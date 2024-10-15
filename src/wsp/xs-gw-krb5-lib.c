#ifdef HL_UNIX
#include <stdarg.h>
#include <hob-unix01.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#ifndef B160501
#ifndef HL_UNIX
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif
#endif
#include "stddef.h"
#include <hob-krb5-defines.h>
#define HAVE_CONFIG_H
#define BUILD_KRB5_LIB
#define BUILD_ROKEN_LIB
#include <hob-krb5-decl.h>
#include "hob-krb5-errortables.h"
#include "gssapi_locl.h"
#ifdef HL_KRB5_WSP_ACTIV
#define TRACEHL1
#define DOMNode void *
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4005)
#ifdef B160501
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#pragma warning(pop)
#endif
#include <hob-netw-01.h>
#include <hob-tcp-sync-01.h>
#include "krb5-protos.h"

#endif
/* Explicit definition instead of alligning hob-xbipgw08-1.h and hob-xbipgw08-2.h */
struct dsd_krb5_kdc_server {                /* definition Kerberos 5 KDC server */
   struct dsd_krb5_kdc_server *adsc_next;   /* next entry in chain     */
   int        imc_len_name;                 /* length of name bytes    */
   int        imc_len_comment;              /* length of Comment bytes */
   struct dsd_bind_ineta_1 dsc_bind_multih;  /* for bind multihomed    */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* KDC INETA         */
   int        imc_port;                     /* Port TCP KDC            */
   int        imc_timeout;                  /* timeout seconds         */
   int        imc_retry_after_error;        /* time retry after error seconds */
   int        imc_conf_max_session;         /* maximum parallel session (TCP) */
   int        imc_max_ticket_size;          /* maximum length of ticket in bytes */
   /* fields for statistics                                            */
   int        imc_cur_session;              /* current sessions        */
   int        imc_max_session;              /* maximum sessions reached */
   int        imc_max_backlog;              /* maximum backlog reached */
   int        imc_l_epoch_max_session;      /* last time / epoch maximum sessions / backlog reached */
   int        imc_no_conn_suc;              /* number of connect successful */
   int        imc_no_conn_fail;             /* number of connect failed */
   int        imc_error_sess;               /* number of sessions abended */
   int        imc_send_packet;              /* number of TCP packets sent */
   HL_LONGLONG ilc_send_data;               /* length of TCP data sent */
   int        imc_recv_packet;              /* number of TCP packets received */
   HL_LONGLONG ilc_recv_data;               /* length of TCP data received */
   int        imc_count_signon_failed;      /* number of times sign-on failed */
   int        imc_count_tgt;                /* number of TGT iussued   */
   int        imc_count_ticket;             /* number of tickets iussued */
};
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__HOB_KRB5_DEFINES) && defined(_WIN32)
#include <hob-krb5-types.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#endif
#include "krb5_locl.h"
#ifdef _WIN32
#include <winsock.h>
#endif
#undef TRACEHL1
#undef DOMNode
#include "config.h"
#ifdef KRB5
#include <krb5-types.h>
#endif
#include <time.h>
#include <errno.h>
#include <hob-krb5-asn1.h>
#include <der.h>
#include <parse_units.h>
#include <stddef.h>
#include <com_right.h>
#include "roken.h"
#include "des.h"
#include "store-int.h"
#if (defined(TIME_WITH_SYS_TIME) || defined(HAVE_SYS_TIME_H))&&(!defined(__HOB_KRB5_DEFINES) || !defined(_WIN32))
#include <sys/time.h>
#endif

#define BACK if (e) return e; p -= l; len -= l; ret += l
#define FORW if(e) {goto fail;} p += l; len -= l; ret += l
#define INIT_FIELD(C, T, E, D, F)					\
    (C)->E = krb5_config_get_ ## T ## _default ((C), NULL, (D), 	\
						"libdefaults", F, NULL)
#define CFXSentByAcceptor	(1 << 0)
#define CFXSealed		(1 << 1)
#define CFXAcceptorSubkey	(1 << 2)
#define CRC_GEN 0xEDB88320L
#define kcrypto_oid_enc(n) { sizeof(n)/sizeof(n[0]), n }
#define CRYPTO_ETYPE(C) ((C)->et->type)
#define F_KEYED		 1
#define F_CPROOF	 2
#define F_DERIVED	 4
#define F_VARIANT	 8
#define F_PSEUDO	16
#define F_SPECIAL	32
#define F_DISABLED	64
#define F_PADCMS	128
#define ENCRYPTION_USAGE(U) (((U) << 8) | 0xAA)
#define INTEGRITY_USAGE(U) (((U) << 8) | 0x55)
#define CHECKSUM_USAGE(U) (((U) << 8) | 0x99)
#define CHECKSUMSIZE(C) ((C)->checksumsize)
#define CHECKSUMTYPE(C) ((C)->type)
#define ERROR_STRING_LEN 256
#define KRB5_FCC_FVNO_1 1
#define KRB5_FCC_FVNO_2 2
#define KRB5_FCC_FVNO_3 3
#define KRB5_FCC_FVNO_4 4
#define FCC_TAG_DELTATIME 1
#define FCACHE(X) ((krb5_fcache*)(X)->data.data)
#define FILENAME(X) (FCACHE(X)->filename)
#define FCC_CURSOR(C) ((struct fcc_cursor*)(C))
#define MAX_PA_COUNTER 3
#define KD_CONFIG		 1
#define KD_SRV_UDP		 2
#define KD_SRV_TCP		 4
#define KD_SRV_HTTP		 8
#define KD_FALLBACK		16
#define KD_CONFIG_EXISTS	32
#define KD_LARGE_MSG		64
#ifndef WITH_OWN_NET_CONNECT
#define HANDLE_CONNECT int fd
#else
#define HANDLE_CONNECT struct dsd_tcpsync_1 *adsp_tcpsync_1
#endif
#ifdef HAVE_RES_SEARCH
#define USE_RESOLVER
#endif
#define princ_num_comp(P) ((P)->name.name_string.len)
#define princ_type(P) ((P)->name.name_type)
#define princ_comp(P) ((P)->name.name_string.val)
#define princ_ncomp(P, N) ((P)->name.name_string.val[(N)])
#define princ_realm(P) ((P)->realm)
#define add_char(BASE, INDEX, LEN, C) do { if((INDEX) < (LEN)) (BASE)[(INDEX)++] = (C); }while(0);
#define zero_long_long(ll) do { ll[0] = ll[1] = 0; } while (0)
#define incr_long_long(ll) do { if (++ll[0] == 0) ++ll[1]; } while (0)
#define set_sequence_number(ll) \
memcpy((char *)(NAME_OF_MAIN_LOC_GLOB_P->sequence_index), (ll), sizeof((NAME_OF_MAIN_LOC_GLOB_P->sequence_index)));
#define ADSL_KRB5_KDC_SERVER ((struct dsd_krb5_kdc_server *) NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context)
#define DEFAULT_JITTER_WINDOW 20
#define BYTEORDER_IS(SP, V) (((SP)->flags & KRB5_STORAGE_BYTEORDER_MASK) == (V))
#define BYTEORDER_IS_LE(SP) BYTEORDER_IS((SP), KRB5_STORAGE_BYTEORDER_LE)
#define BYTEORDER_IS_BE(SP) BYTEORDER_IS((SP), KRB5_STORAGE_BYTEORDER_BE)
#define BYTEORDER_IS_HOST(SP) (BYTEORDER_IS((SP), KRB5_STORAGE_BYTEORDER_HOST) || \
			       krb5_storage_is_flags(NAME_OF_MAIN_LOC_GLOB_P,(SP), KRB5_STORAGE_HOST_BYTEORDER))
#define FD(S) (((fd_storage*)(S)->data)->fd)
#define FUNC(ETEXT, CODE, LEVEL) krb5_error_code ret = 0

extern HL_LONGLONG m_get_epoch_ms( void );
time_t m_mock_time(time_t* ap_time_ptr);

static u_int16_t (*m_bswap16)( u_int16_t) = &m_bswap16_init;
static u_int32_t (*m_bswap32)( u_int32_t) = &m_bswap32_init;
krb5_error_code
gssapi_encode_om_uint32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 n, u_char *p )
{
    p[0] = ( n >> 0 )  & 0xFF;
    p[1] = ( n >> 8 )  & 0xFF;
    p[2] = ( n >> 16 ) & 0xFF;
    p[3] = ( n >> 24 ) & 0xFF;
    return 0;
}
krb5_error_code
gssapi_encode_be_om_uint32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 n, u_char *p )
{
    p[0] = ( n >> 24 ) & 0xFF;
    p[1] = ( n >> 16 ) & 0xFF;
    p[2] = ( n >> 8 )  & 0xFF;
    p[3] = ( n >> 0 )  & 0xFF;
    return 0;
}
krb5_error_code
gssapi_decode_om_uint32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, u_char *p, OM_uint32 *n )
{
    *n = ( p[0] << 0 ) | ( p[1] << 8 ) | ( p[2] << 16 ) | ( p[3] << 24 );
    return 0;
}
krb5_error_code
gssapi_decode_be_om_uint32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, u_char *p, OM_uint32 *n )
{
    *n = ( p[0] <<24 ) | ( p[1] << 16 ) | ( p[2] << 8 ) | ( p[3] << 0 );
    return 0;
}
static krb5_error_code
hash_input_chan_bindings( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const gss_channel_bindings_t b,
                          u_char *p )
{
    u_char num[4];
    MD5_CTX md5;
    MD5_Init( md5 );
    gssapi_encode_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, b->initiator_addrtype, num );
    MD5_Update( md5, num, 0, sizeof( num ) );
    gssapi_encode_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, b->initiator_address.length, num );
    MD5_Update( md5, num, 0, sizeof( num ) );
    if( b->initiator_address.length )
        MD5_Update( md5,
                    b->initiator_address.value,0,
                    b->initiator_address.length );
    gssapi_encode_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, b->acceptor_addrtype, num );
    MD5_Update( md5, num, 0, sizeof( num ) );
    gssapi_encode_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, b->acceptor_address.length, num );
    MD5_Update( md5, num, 0, sizeof( num ) );
    if( b->acceptor_address.length )
        MD5_Update( md5,
                    b->acceptor_address.value, 0,
                    b->acceptor_address.length );
    gssapi_encode_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, b->application_data.length, num );
    MD5_Update( md5, num, 0, sizeof( num ) );
    if( b->application_data.length )
        MD5_Update( md5,
                    b->application_data.value, 0,
                    b->application_data.length );
    MD5_Final( md5, p, 0 );
    return 0;
}
/*
 * create a checksum over the chanel bindings in
 * `input_chan_bindings', `flags' and `fwd_data' and return it in
 * `result'
 */
OM_uint32
gssapi_krb5_create_8003_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 *minor_status,
                                  const gss_channel_bindings_t input_chan_bindings,
                                  OM_uint32 flags,
                                  const krb5_data *fwd_data,
                                  Checksum *result )
{
    u_char *p;
    /*
     * see rfc1964 (section 1.1.1 (Initial Token), and the checksum value
     * field's format) */
    result->cksumtype = CKSUMTYPE_GSSAPI;
    if( fwd_data->length > 0 && ( flags & GSS_C_DELEG_FLAG ) )
        result->checksum.length = 24 + 4 + fwd_data->length;
    else
        result->checksum.length = 24;
    result->checksum.data   =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, result->checksum.length )
        ;
    if( result->checksum.data == NULL ) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    p = result->checksum.data;
    gssapi_encode_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, 16, p );
    p += 4;
    if( input_chan_bindings == GSS_C_NO_CHANNEL_BINDINGS ) {
        memset( p, 0, 16 );
    } else {
        hash_input_chan_bindings(	NAME_OF_MAIN_LOC_GLOB_P, input_chan_bindings, p );
    }
    p += 16;
    gssapi_encode_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, flags, p );
    p += 4;
    if( fwd_data->length > 0 && ( flags & GSS_C_DELEG_FLAG ) ) {
        *p++ = ( 1 >> 0 ) & 0xFF;
        *p++ = ( 1 >> 8 ) & 0xFF;
        *p++ = ( fwd_data->length >> 0 ) & 0xFF;
        *p++ = ( fwd_data->length >> 8 ) & 0xFF;
        memcpy( p, ( unsigned char * ) fwd_data->data, fwd_data->length );
        p += fwd_data->length;
    }
    return GSS_S_COMPLETE;
}
/*
 * verify the checksum in `cksum' over `input_chan_bindings'
 * returning  `flags' and `fwd_data'
 */

void m_free_of_memory_hole( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P );
void m_free_address_memory( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P );
int *m__errno_location_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P
                         )
{
    return &
           NAME_OF_MAIN_LOC_GLOB_P->im_fake_errno_meth_static;
}

char * m_strdup_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const char * ach_org )
{
    char * ach_copy = ( char* )
                      m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, strlen( ach_org ) + 1 )
                      ;
    return strcpy( ach_copy,ach_org );
}
#ifndef O_BINARY
#define O_BINARY 0
#endif
int m_open_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const char * ach_path,int im_flags )
{
    FILE * a_file_pt = NULL;
    char * ach_mode  = NULL;
    int im_file_h    = 1;
#ifndef WITHOUT_FILE
    switch( im_flags ) {
    case O_RDWR                    | O_BINARY:
        ach_mode = "r+b";
        break;
    case O_RDWR | O_CREAT | O_EXCL | O_BINARY:
        ach_mode = "w+b";
        break;
    case O_RDWR | O_CREAT          | O_BINARY:
        ach_mode = "w+b";
        break;
    case O_WRONLY | O_APPEND       | O_BINARY:
        ach_mode = "ab" ;
        break;
    case O_RDONLY                  | O_BINARY:
        ach_mode = "rb" ;
        break;
    case O_WRONLY                  | O_BINARY:
        ach_mode = "wb" ;
        break;
    }
    if( ach_mode != NULL ) {
        a_file_pt = fopen( ach_path,ach_mode );
    } else
        return -1;
    if( a_file_pt == NULL )
        return -1;
    if( NAME_OF_MAIN_LOC_GLOB_P->
            im_counter_array_free_posi >= 0 ) {
        im_file_h =
            NAME_OF_MAIN_LOC_GLOB_P->
            aim_array_free_posi[
                NAME_OF_MAIN_LOC_GLOB_P->
                im_counter_array_free_posi];
        NAME_OF_MAIN_LOC_GLOB_P->
        aim_array_free_posi[
            NAME_OF_MAIN_LOC_GLOB_P->
            im_counter_array_free_posi] = -1;
        NAME_OF_MAIN_LOC_GLOB_P->
        im_counter_array_free_posi =
            NAME_OF_MAIN_LOC_GLOB_P->
            im_counter_array_free_posi - 1;
    } else {
        NAME_OF_MAIN_LOC_GLOB_P->
        im_counter_array_file_pt =
            NAME_OF_MAIN_LOC_GLOB_P->
            im_counter_array_file_pt + 1;
        im_file_h =
            NAME_OF_MAIN_LOC_GLOB_P->
            im_counter_array_file_pt;
        NAME_OF_MAIN_LOC_GLOB_P->
        ads_array_file_pt   = ( dsd_s_file_status * )
                              m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,                                                                          NAME_OF_MAIN_LOC_GLOB_P->
                                      ads_array_file_pt,im_file_h*sizeof( dsd_s_file_status ) )
                              ;
        NAME_OF_MAIN_LOC_GLOB_P->
        aim_array_free_posi = ( int * )
                              m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,                                                            NAME_OF_MAIN_LOC_GLOB_P->
                                      aim_array_free_posi,im_file_h*sizeof( int ) )
                              ;
        if( NAME_OF_MAIN_LOC_GLOB_P->
                ads_array_file_pt == NULL ||
                NAME_OF_MAIN_LOC_GLOB_P->
                aim_array_free_posi == NULL )
            return -1;
    }
    ( *( NAME_OF_MAIN_LOC_GLOB_P->
         ads_array_file_pt + im_file_h - 1 ) ).a_file_pt = a_file_pt;
    ( *( NAME_OF_MAIN_LOC_GLOB_P->
         ads_array_file_pt + im_file_h - 1 ) ).im_status  = 1;
#endif
    return im_file_h;
}
int m_close_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int im_file_desc )
{
#ifndef WITHOUT_FILE
    if( NAME_OF_MAIN_LOC_GLOB_P->
            ads_array_file_pt[im_file_desc - 1].im_status == 0 )
        return 0;
    else {
        if( fclose( NAME_OF_MAIN_LOC_GLOB_P->
                    ads_array_file_pt[im_file_desc - 1].a_file_pt )==0 ) {
            NAME_OF_MAIN_LOC_GLOB_P->
            im_counter_array_free_posi =
                NAME_OF_MAIN_LOC_GLOB_P->
                im_counter_array_free_posi + 1;
            NAME_OF_MAIN_LOC_GLOB_P->
            aim_array_free_posi[
                NAME_OF_MAIN_LOC_GLOB_P->
                im_counter_array_free_posi] = im_file_desc;
            NAME_OF_MAIN_LOC_GLOB_P->
            ads_array_file_pt[im_file_desc - 1].im_status = 0;
            return 0;
        } else
            return -1;
    }
#else
    return 0;
#endif
}
ssize_t m_read_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int im_file_desc,void * a_buffer,size_t im_count )
{
#ifndef WITHOUT_FILE
    ssize_t im_quantity = fread( a_buffer,1,im_count,                                                   NAME_OF_MAIN_LOC_GLOB_P->
                                 ads_array_file_pt[im_file_desc - 1].a_file_pt );
    if( im_quantity == im_count || im_quantity == 0 )
        return im_count;
    else
        return -1;
#else
    return im_count;
#endif
}
ssize_t m_write_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int im_file_desc,const void * a_buffer,size_t im_count )
{
#ifndef WITHOUT_FILE
    ssize_t im_quantity = fwrite( a_buffer,1,im_count,                                                    NAME_OF_MAIN_LOC_GLOB_P->
                                  ads_array_file_pt[im_file_desc - 1].a_file_pt );
    if( im_quantity == im_count )
        return im_count;
    else
        return -1;
#else
    return im_count;
#endif
}
void m_free_arrays_file_h_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P
                            )
{
#ifndef WITHOUT_FILE
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,                        NAME_OF_MAIN_LOC_GLOB_P->
                     ads_array_file_pt )
    ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,                        NAME_OF_MAIN_LOC_GLOB_P->
                     aim_array_free_posi )
    ;
#endif
}
void m_throw_exception(int inp_error_code);

void m_end_exit_abort_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, char ch_art, int im_ret )
{
    if( NAME_OF_MAIN_LOC_GLOB_P->im_re_error_code ) {
        m_throw_exception(NAME_OF_MAIN_LOC_GLOB_P->im_re_error_code);
    } else {
        m_throw_exception(2);
    }
}
void m_init_connect_hl( void * a_ip_address_context )
{
#ifndef HL_KRB5_WSP_ACTIV
#ifdef _WIN32
    WSADATA wsaData;
    WORD    wVersionRequested = 0x0101;
    WSAStartup( wVersionRequested,&wsaData );
#endif
#endif
}
int m_socket_hl( void * a_ip_address_context )
{
    int im_fd;
    int im_familie    = AF_INET;
    int im_sockettype = SOCK_STREAM;
    int im_protokoll  = IPPROTO_TCP;
    return socket( im_familie, im_sockettype, im_protokoll );
}
int m_connect_hl( int im_fd, void * a_ip_address, int im_port, void * a_ip_address_context )
{
    struct sockaddr_in ds_addresse;
    ds_addresse.sin_family      = AF_INET;
    ds_addresse.sin_port        = htons( im_port );
#ifdef HL_KRB5_WSP_ACTIV
    ds_addresse.sin_addr.s_addr = ( *(( unsigned long int* )a_ip_address ) );
#else
    ds_addresse.sin_addr.s_addr = htonl( *(( unsigned long int* )a_ip_address ) );
#endif
    return connect( im_fd, ( struct sockaddr * ) &ds_addresse, sizeof( ds_addresse ) );
}
#ifdef HOB_KERBEROS_CPP
int m_single_accept_hl( int im_fd, int im_port, void * a_ip_address_context )
{
    struct sockaddr_in ds_addresse, ds_adresse_sock;
    int im_adresse_sock_l;
    int im_clien_sock = 0;
    ds_addresse.sin_family      = AF_INET;
    ds_addresse.sin_addr.s_addr = htonl( 0 );
    ds_addresse.sin_port        = htons( im_port );
    if( bind( im_fd, ( struct sockaddr * ) &ds_addresse, sizeof( ds_addresse ) )==-1 )
        if( listen( im_fd,1 )==-1 )
            im_adresse_sock_l = sizeof( ds_adresse_sock );
    im_clien_sock = accept( im_fd,( struct sockaddr* ) &ds_adresse_sock,
                            &im_adresse_sock_l );
    return im_clien_sock;
}
#endif
int m_recv_hl( int im_fd, char * ach_data, int im_numb_bytes, int im_timeout, void * a_ip_address_context )
{
    return  recv( im_fd, ach_data, im_numb_bytes, 0 );
}
int m_send_hl( int im_fd, char const * ach_data, int im_numb_bytes, int im_timeout, void * a_ip_address_context )
{
    return send( im_fd, ach_data, im_numb_bytes, 0 );
}
void m_closesocket_hl( int im_fd, void * a_ip_address_context )
{
#ifdef _WIN32
    closesocket( im_fd );
#else
    close( im_fd );
#endif
}
void m_end_connect_hl( void * a_ip_address_context )
{
#ifndef HL_KRB5_WSP_ACTIV
#ifdef _WIN32
    WSACleanup();
#endif
#endif
}
/*
 * AF_INET - aka IPv4 implementation
 */
/*
 * Are there any addresses that should be considered `uninteresting'?
 */
/*
 * AF_INET6 - aka IPv6 implementation
 */
#ifdef HAVE_IPV6
static krb5_error_code
ipv6_sockaddr2addr( const struct sockaddr *sa, krb5_address *a )
{
    const struct sockaddr_in6 *sin6 = ( const struct sockaddr_in6 * )sa;
    if( IN6_IS_ADDR_V4MAPPED( &sin6->sin6_addr ) ) {
        unsigned char buf[4];
        a->addr_type      = KRB5_ADDRESS_INET;
#ifndef IN6_ADDR_V6_TO_V4
#ifdef IN6_EXTRACT_V4ADDR
#define IN6_ADDR_V6_TO_V4(x) (&IN6_EXTRACT_V4ADDR(x))
#else
#define IN6_ADDR_V6_TO_V4(x) ((const struct in_addr *)&(x)->s6_addr[12])
#endif
#endif
        memcpy( buf, IN6_ADDR_V6_TO_V4( &sin6->sin6_addr ), 4 );
        return krb5_data_copy(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P
                                &a->address, buf, 4 );
    } else {
        a->addr_type = KRB5_ADDRESS_INET6;
        return krb5_data_copy(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P
                                &a->address,
                                &sin6->sin6_addr,
                                sizeof( sin6->sin6_addr ) );
    }
}
static krb5_error_code
ipv6_sockaddr2port( const struct sockaddr *sa, int16_t *port )
{
    const struct sockaddr_in6 *sin6 = ( const struct sockaddr_in6 * )sa;
    *port = sin6->sin6_port;
    return 0;
}
static void
ipv6_addr2sockaddr( const krb5_address *a,
                    struct sockaddr *sa,
                    krb5_socklen_t *sa_size,
                    int port )
{
    struct sockaddr_in6 tmp;
    memset( &tmp, 0, sizeof( tmp ) );
    tmp.sin6_family = AF_INET6;
    memcpy( &tmp.sin6_addr, a->address.data, sizeof( tmp.sin6_addr ) );
    tmp.sin6_port = port;
    memcpy( sa, &tmp, min( sizeof( tmp ), *sa_size ) );
    *sa_size = sizeof( tmp );
}
static void
ipv6_h_addr2sockaddr( const char *addr,
                      struct sockaddr *sa,
                      krb5_socklen_t *sa_size,
                      int port )
{
    struct sockaddr_in6 tmp;
    memset( &tmp, 0, sizeof( tmp ) );
    tmp.sin6_family = AF_INET6;
    tmp.sin6_port   = port;
    tmp.sin6_addr   = *(( const struct in6_addr * )addr );
    memcpy( sa, &tmp, min( sizeof( tmp ), *sa_size ) );
    *sa_size = sizeof( tmp );
}
static krb5_error_code
ipv6_h_addr2addr( const char *addr,
                  krb5_address *a )
{
    a->addr_type = KRB5_ADDRESS_INET6;
    return krb5_data_copy( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P
                           &a->address, addr, sizeof( struct in6_addr ) );
}
/*
 *
 */
static krb5_boolean
ipv6_uninteresting( const struct sockaddr *sa )
{
    const struct sockaddr_in6 *sin6 = ( const struct sockaddr_in6 * )sa;
    const struct in6_addr *in6 = ( const struct in6_addr * )&sin6->sin6_addr;
    return
        IN6_IS_ADDR_LINKLOCAL( in6 )
        || IN6_IS_ADDR_V4COMPAT( in6 );
}
static void
ipv6_anyaddr( struct sockaddr *sa, krb5_socklen_t *sa_size, int port )
{
    struct sockaddr_in6 tmp;
    memset( &tmp, 0, sizeof( tmp ) );
    tmp.sin6_family = AF_INET6;
    tmp.sin6_port   = port;
    tmp.sin6_addr   = in6addr_any;
    *sa_size = sizeof( tmp );
}
static int
ipv6_print_addr( const krb5_address *addr, char *str, size_t len )
{
    char buf[128], buf2[3];
#ifdef HAVE_INET_NTOP
    if( inet_ntop( AF_INET6, addr->address.data, buf, sizeof( buf ) ) == NULL )
#endif
    {
        int i;
        unsigned char *p = addr->address.data;
        buf[0] = '\0';
        for( i = 0; i < addr->address.length; i++ ) {
            snprintf( buf2, sizeof( buf2 ), "%02x", p[i] );
            if( i > 0 && ( i & 1 ) == 0 )
                m_strlcat_hl( buf, ":", sizeof( buf ) );
            m_strlcat_hl( buf, buf2, sizeof( buf ) );
        }
    }
    return snprintf( str, len, "IPv6:%s", buf );
}
static int
ipv6_parse_addr( krb5_context context, const char *address, krb5_address *addr )
{
    int ret;
    struct in6_addr in6;
    const char *p;
    p = strchr( address, ':' );
    if( p ) {
        p++;
        if( strncasecmp( address, "ip6:", p - address ) == 0 ||
                strncasecmp( address, "ipv6:", p - address ) == 0 ||
                strncasecmp( address, "inet6:", p - address ) == 0 )
            address = p;
    }
    ret = inet_pton( AF_INET6, address, &in6.s6_addr );
    if( ret == 1 ) {
        addr->addr_type = KRB5_ADDRESS_INET6;
        ret = krb5_data_alloc( &addr->address, sizeof( in6.s6_addr ) );
        if( ret ) {
            //StSch Trace Point
            return -1;
        }
        memcpy( addr->address.data, in6.s6_addr, sizeof( in6.s6_addr ) );
        return 0;
    }
    return -1;
}
static int
ipv6_mask_boundary( krb5_context context, const krb5_address *inaddr,
                    unsigned long len, krb5_address *low, krb5_address *high )
{
    struct in6_addr addr, laddr, haddr;
    u_int32_t m;
    int i, sub_len;
    if( len > 128 ) {
        krb5_set_error_string( context,"IPv6 prefix too large ()","addr_families.c 1520" )
        ;
        return KRB5_PROG_ATYPE_NOSUPP;
    }
    if( inaddr->address.length != sizeof( addr ) ) {
        krb5_set_error_string( context,"IPv6 addr bad length","addr_families.c 1521" )
        ;
        return KRB5_PROG_ATYPE_NOSUPP;
    }
    memcpy( &addr, inaddr->address.data, inaddr->address.length );
    for( i = 0; i < 16; i++ ) {
        sub_len = min( 8, len );
        m = 0xff << ( 8 - sub_len );
        laddr.s6_addr[i] = addr.s6_addr[i] & m;
        haddr.s6_addr[i] = ( addr.s6_addr[i] & m ) | ~m;
        if( len > 8 )
            len -= 8;
        else
            len = 0;
    }
    low->addr_type = KRB5_ADDRESS_INET6;
    if( krb5_data_alloc( &low->address, sizeof( laddr.s6_addr ) ) != 0 )
        return -1;
    memcpy( low->address.data, laddr.s6_addr, sizeof( laddr.s6_addr ) );
    high->addr_type = KRB5_ADDRESS_INET6;
    if( krb5_data_alloc( &high->address, sizeof( haddr.s6_addr ) ) != 0 ) {
        krb5_free_address( context, low );
        return -1;
    }
    memcpy( high->address.data, haddr.s6_addr, sizeof( haddr.s6_addr ) );
    return 0;
}
#endif
/*
 * table
 */
#define KRB5_ADDRESS_ARANGE	(-100)
struct arange {
    krb5_address low;
    krb5_address high;
};
/*
 * generic functions
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_free_address( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_address *address )
{
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &address->address );
    memset( address, 0, sizeof( *address ) );
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_free_addresses( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     krb5_addresses *addresses )
{
    int i;
    for( i = 0; i < addresses->len; i++ )
        krb5_free_address(	NAME_OF_MAIN_LOC_GLOB_P, context, &addresses->val[i] );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, addresses->val )
    ;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_copy_address( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   const krb5_address *inaddr,
                   krb5_address *outaddr )
{
    outaddr = NULL;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_copy_addresses( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     const krb5_addresses *inaddr,
                     krb5_addresses *outaddr )
{
    int i;
    ALLOC_SEQ( outaddr, inaddr->len );
    if( inaddr->len > 0 && outaddr->val == NULL )
        return ENOMEM;
    for( i = 0; i < inaddr->len; i++ )
        krb5_copy_address(	NAME_OF_MAIN_LOC_GLOB_P, context, &inaddr->val[i], &outaddr->val[i] );
    return 0;
}
/*
 * Create an address of type KRB5_ADDRESS_ADDRPORT from (addr, port)
 */
/*
 * Calculate the boundary addresses of `inaddr'/`prefixlen' and store
 * them in `low' and `high'.
 */
/*
 * Add a specified list of error messages to the et list in context.
 * Call func (probably a comerr-generated function) with a pointer to
 * the current et_list.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_add_et_list( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  void ( *func )(	struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct et_list ** ) )
{
    ( *func )( NAME_OF_MAIN_LOC_GLOB_P, &context->et_list );
    return 0;
}
static krb5_error_code
arcfour_mic_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_keyblock *key,
                 void *cksum_data, size_t cksum_size,
                 void *key6_data, size_t key6_size )
{
    krb5_error_code ret;
    Checksum cksum_k5;
    krb5_keyblock key5;
    char k5_data[16];
    Checksum cksum_k6;
    char T[4];
    memset( T, 0, 4 );
    cksum_k5.checksum.data = k5_data;
    cksum_k5.checksum.length = sizeof( k5_data );
    if( key->keytype == KEYTYPE_ARCFOUR_56 ) {
        char L40[14] = "fortybits";
        memcpy( L40 + 10, T, sizeof( T ) );
        ret = krb5_hmac(	NAME_OF_MAIN_LOC_GLOB_P, context, CKSUMTYPE_RSA_MD5,
                            L40, 14, 0, key, &cksum_k5 );
        memset( &k5_data[7], 0xAB, 9 );
    } else {
        ret = krb5_hmac(	NAME_OF_MAIN_LOC_GLOB_P, context, CKSUMTYPE_RSA_MD5,
                            T, 4, 0, key, &cksum_k5 );
    }
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    key5.keytype = KEYTYPE_ARCFOUR;
    key5.keyvalue = cksum_k5.checksum;
    cksum_k6.checksum.data = key6_data;
    cksum_k6.checksum.length = key6_size;
    return krb5_hmac( NAME_OF_MAIN_LOC_GLOB_P, context, CKSUMTYPE_RSA_MD5,
                      cksum_data, cksum_size, 0, &key5, &cksum_k6 );
}
static krb5_error_code
arcfour_mic_cksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_keyblock *key, unsigned usage,
                   u_char *sgn_cksum, size_t sgn_cksum_sz,
                   const char *v1, size_t l1,
                   const void *v2, size_t l2,
                   const void *v3, size_t l3 )
{
    Checksum CKSUM;
    u_char *ptr;
    size_t len;
    krb5_crypto crypto;
    krb5_error_code ret;
    if( !( sgn_cksum_sz == 8 ) ) {
        //StSch Trace Point
        m_end_exit_abort_hl( NAME_OF_MAIN_LOC_GLOB_P, 'a',0 );
    }
    len = l1 + l2 + l3;
    ptr =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    if( ptr == NULL )
        return ENOMEM;
    memcpy( ptr, v1, l1 );
    memcpy( ptr + l1, v2, l2 );
    memcpy( ptr + l1 + l2, v3, l3 );
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P,                           NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ptr )
        ;
        return ret;
    }
    ret = krb5_create_checksum( NAME_OF_MAIN_LOC_GLOB_P,                               NAME_OF_MAIN_LOC_GLOB_P->
                                gssapi_krb5_context,
                                crypto,
                                usage,
                                0,
                                ptr, len,
                                &CKSUM );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ptr )
    ;
    if( ret == 0 ) {
        memcpy( sgn_cksum, CKSUM.checksum.data, sgn_cksum_sz );
        free_Checksum(	NAME_OF_MAIN_LOC_GLOB_P, &CKSUM );
    }
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P,                        NAME_OF_MAIN_LOC_GLOB_P->
                         gssapi_krb5_context, crypto );
    return ret;
}
OM_uint32
_gssapi_wrap_arcfour( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 * minor_status,
                      const gss_ctx_id_t context_handle,
                      int conf_req_flag,
                      gss_qop_t qop_req,
                      const gss_buffer_t input_message_buffer,
                      int * conf_state,
                      gss_buffer_t output_message_buffer,
                      krb5_keyblock *key )
{
    u_char Klocaldata[16], k6_data[16], *p, *p0;
    size_t len, total_len, datalen;
    krb5_keyblock Klocal;
    krb5_error_code ret;
    int32_t seq_number;
    if( conf_state )
        *conf_state = 0;
    datalen = input_message_buffer->length + 1 ;
    len = datalen + GSS_ARCFOUR_WRAP_TOKEN_SIZE;
    _gssapi_encap_length( NAME_OF_MAIN_LOC_GLOB_P, len, &len, &total_len, ( &( NAME_OF_MAIN_LOC_GLOB_P->
                          gssapi_krb5_context->gss_krb5_mechanism_oid_ ) ) );
    output_message_buffer->length = total_len;
    output_message_buffer->value  =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, total_len )
        ;
    if( output_message_buffer->value == NULL ) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    p0 = _gssapi_make_mech_header( NAME_OF_MAIN_LOC_GLOB_P, output_message_buffer->value,
                                   len, ( &(	NAME_OF_MAIN_LOC_GLOB_P->
                                           gssapi_krb5_context->gss_krb5_mechanism_oid_ ) ) );
    p = p0;
    *p++ = 0x02;
    *p++ = 0x01;
    *p++ = 0x11;
    *p++ = 0x00;
    if( conf_req_flag ) {
        *p++ = 0x10;
        *p++ = 0x00;
    } else {
        *p++ = 0xff;
        *p++ = 0xff;
    }
    *p++ = 0xff;
    *p++ = 0xff;
    p = NULL;
    krb5_auth_con_getlocalseqnumber( NAME_OF_MAIN_LOC_GLOB_P,                                     NAME_OF_MAIN_LOC_GLOB_P->
                                     gssapi_krb5_context,
                                     context_handle->auth_context,
                                     &seq_number );
    gssapi_encode_be_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, seq_number, p0 + 8 );
    krb5_auth_con_setlocalseqnumber( NAME_OF_MAIN_LOC_GLOB_P,                                     NAME_OF_MAIN_LOC_GLOB_P->
                                     gssapi_krb5_context,
                                     context_handle->auth_context,
                                     ++seq_number );
    memset( p0 + 8 + 4,
            ( context_handle->more_flags & LOCAL ) ? 0 : 0xff,
            4 );
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, p0 + 24, 8 );
    p = p0 + GSS_ARCFOUR_WRAP_TOKEN_SIZE;
    memcpy( p, input_message_buffer->value, input_message_buffer->length );
    p[input_message_buffer->length] = 1;
    ret = arcfour_mic_cksum( NAME_OF_MAIN_LOC_GLOB_P, key, KRB5_KU_USAGE_SEAL,
                             p0 + 16, 8,
                             p0, 8,
                             p0 + 24, 8,
                             p0 + GSS_ARCFOUR_WRAP_TOKEN_SIZE,
                             datalen );
    if( ret ) {
        //StSch Trace Point
        *minor_status = ret;
        gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
        return GSS_S_FAILURE;
    }
    {
        int i;
        Klocal.keytype = key->keytype;
        Klocal.keyvalue.data = Klocaldata;
        Klocal.keyvalue.length = sizeof( Klocaldata );
        for( i = 0; i < 16; i++ )
            Klocaldata[i] = (( u_char * )key->keyvalue.data )[i] ^ 0xF0;
    }
    ret = arcfour_mic_key( NAME_OF_MAIN_LOC_GLOB_P,                          NAME_OF_MAIN_LOC_GLOB_P->
                           gssapi_krb5_context, &Klocal,
                           p0 + 8, 4,
                           k6_data, sizeof( k6_data ) );
    memset( Klocaldata, 0, sizeof( Klocaldata ) );
    if( ret ) {
        //StSch Trace Point
        gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    if( conf_req_flag ) {
        RC4_KEY rc4_key;
        RC4_SetKey( rc4_key, k6_data, 0, sizeof( k6_data ) );
        RC4( p0 + 24, 0, 8 + datalen,  p0 + 24, 0, rc4_key );
        memset( rc4_key, 0, RC4_STATE_SIZE );
    }
    memset( k6_data, 0, sizeof( k6_data ) );
    ret = arcfour_mic_key( NAME_OF_MAIN_LOC_GLOB_P,                          NAME_OF_MAIN_LOC_GLOB_P->
                           gssapi_krb5_context, key,
                           p0 + 16, 8,
                           k6_data, sizeof( k6_data ) );
    if( ret ) {
        //StSch Trace Point
        gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    {
        RC4_KEY rc4_key;
        RC4_SetKey( rc4_key, k6_data, 0, sizeof( k6_data ) );
        RC4( p0 + 8, 0, 8,  p0 + 8, 0, rc4_key );
        memset( rc4_key, 0, RC4_STATE_SIZE );
        memset( k6_data, 0, sizeof( k6_data ) );
    }
    if( conf_state )
        *conf_state = conf_req_flag;
    *minor_status = 0;
    return GSS_S_COMPLETE;
}
OM_uint32 _gssapi_unwrap_arcfour( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 *minor_status,
                                  const gss_ctx_id_t context_handle,
                                  const gss_buffer_t input_message_buffer,
                                  gss_buffer_t output_message_buffer,
                                  int *conf_state,
                                  gss_qop_t *qop_state,
                                  krb5_keyblock *key )
{
    u_char Klocaldata[16];
    krb5_keyblock Klocal;
    krb5_error_code ret;
    int32_t seq_number;
    size_t datalen;
    OM_uint32 omret;
    char k6_data[16], SND_SEQ[8], Confounder[8];
    char cksum_data[8];
    u_char *p, *p0;
    int cmp;
    int conf_flag;
    size_t padlen;
    if( conf_state )
        *conf_state = 0;
    if( qop_state )
        *qop_state = 0;
    p0 = input_message_buffer->value;
    omret = _gssapi_verify_mech_header( NAME_OF_MAIN_LOC_GLOB_P, &p0,
                                        input_message_buffer->length, ( &(	NAME_OF_MAIN_LOC_GLOB_P->
                                                gssapi_krb5_context->gss_krb5_mechanism_oid_ ) ) );
    if( omret )
        return omret;
    p = p0;
    datalen = input_message_buffer->length -
              ( p - (( u_char * )input_message_buffer->value ) ) -
              GSS_ARCFOUR_WRAP_TOKEN_SIZE;
    if( memcmp( p, "\x02\x01", 2 ) != 0 )
        return GSS_S_BAD_SIG;
    p += 2;
    if( memcmp( p, "\x11\x00", 2 ) != 0 )
        return GSS_S_BAD_SIG;
    p += 2;
    if( memcmp( p, "\x10\x00", 2 ) == 0 )
        conf_flag = 1;
    else if( memcmp( p, "\xff\xff", 2 ) == 0 )
        conf_flag = 0;
    else
        return GSS_S_BAD_SIG;
    p += 2;
    if( memcmp( p, "\xff\xff", 2 ) != 0 )
        return GSS_S_BAD_MIC;
    p = NULL;
    ret = arcfour_mic_key( NAME_OF_MAIN_LOC_GLOB_P,                          NAME_OF_MAIN_LOC_GLOB_P->
                           gssapi_krb5_context, key,
                           p0 + 16, 8,
                           k6_data, sizeof( k6_data ) );
    if( ret ) {
        //StSch Trace Point
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    {
        RC4_KEY rc4_key;
        RC4_SetKey( rc4_key, k6_data, 0, sizeof( k6_data ) );
        RC4( p0 + 8, 0, 8 + datalen,  SND_SEQ, 0, rc4_key );
        memset( rc4_key, 0, RC4_STATE_SIZE );
        memset( k6_data, 0, sizeof( k6_data ) );
    }
    gssapi_decode_be_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, SND_SEQ, &seq_number );
    if( context_handle->more_flags & LOCAL )
        cmp = memcmp( &SND_SEQ[4], "\xff\xff\xff\xff", 4 );
    else
        cmp = memcmp( &SND_SEQ[4], "\x00\x00\x00\x00", 4 );
    if( cmp != 0 ) {
        *minor_status = 0;
        return GSS_S_BAD_MIC;
    }
    {
        int i;
        Klocal.keytype = key->keytype;
        Klocal.keyvalue.data = Klocaldata;
        Klocal.keyvalue.length = sizeof( Klocaldata );
        for( i = 0; i < 16; i++ )
            Klocaldata[i] = (( u_char * )key->keyvalue.data )[i] ^ 0xF0;
    }
    ret = arcfour_mic_key( NAME_OF_MAIN_LOC_GLOB_P,                          NAME_OF_MAIN_LOC_GLOB_P->
                           gssapi_krb5_context, &Klocal,
                           SND_SEQ, 4,
                           k6_data, sizeof( k6_data ) );
    memset( Klocaldata, 0, sizeof( Klocaldata ) );
    if( ret ) {
        //StSch Trace Point
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    output_message_buffer->value =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, datalen )
        ;
    if( output_message_buffer->value == NULL ) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    output_message_buffer->length = datalen;
    if( conf_flag ) {
        RC4_KEY rc4_key;
        RC4_SetKey( rc4_key, k6_data, 0, sizeof( k6_data ) );
        RC4( p0 + 24, 0, 8, Confounder, 0, rc4_key );
        RC4( p0 + GSS_ARCFOUR_WRAP_TOKEN_SIZE, 0, datalen, output_message_buffer->value, 0, rc4_key );
        memset( rc4_key, 0, RC4_STATE_SIZE );
    } else {
        memcpy( Confounder, p0 + 24, 8 );
        memcpy( output_message_buffer->value,
                p0 + GSS_ARCFOUR_WRAP_TOKEN_SIZE,
                datalen );
    }
    memset( k6_data, 0, sizeof( k6_data ) );
    ret = _gssapi_verify_pad( NAME_OF_MAIN_LOC_GLOB_P, output_message_buffer, datalen, &padlen );
    if( ret ) {
        //StSch Trace Point
        gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
        *minor_status = 0;
        return ret;
    }
    output_message_buffer->length -= padlen;
    ret = arcfour_mic_cksum( NAME_OF_MAIN_LOC_GLOB_P, key, KRB5_KU_USAGE_SEAL,
                             cksum_data, sizeof( cksum_data ),
                             p0, 8,
                             Confounder, sizeof( Confounder ),
                             output_message_buffer->value,
                             output_message_buffer->length + padlen );
    if( ret ) {
        //StSch Trace Point
        gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    cmp = memcmp( cksum_data, p0 + 16, 8 );
    if( cmp ) {
        gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
        *minor_status = 0;
        return GSS_S_BAD_MIC;
    }
    omret = _gssapi_msg_order_check( NAME_OF_MAIN_LOC_GLOB_P, context_handle->order, seq_number );
    if( omret )
        return omret;
    if( conf_state )
        *conf_state = conf_flag;
    *minor_status = 0;
    return GSS_S_COMPLETE;
}
int
encode_AD_IF_RELEVANT( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const AD_IF_RELEVANT *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_AD_IF_RELEVANT( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, AD_IF_RELEVANT *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_AD_IF_RELEVANT( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_AD_IF_RELEVANT( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, AD_IF_RELEVANT *data )
{
    free_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, data );
}
size_t
length_AD_IF_RELEVANT( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const AD_IF_RELEVANT *data )
{
    size_t ret = 0;
    ret += length_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, data );
    return ret;
}
int
encode_APOptions( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const APOptions *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        unsigned char c = 0;
        *p-- = c;
        len--;
        ret++;
        c = 0;
        *p-- = c;
        len--;
        ret++;
        c = 0;
        *p-- = c;
        len--;
        ret++;
        c = 0;
        if( data->mutual_required ) c |= 1<<5;
        if( data->use_session_key ) c |= 1<<6;
        if( data->reserved ) c |= 1<<7;
        *p-- = c;
        *p-- = 0;
        len -= 2;
        ret += 2;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, PRIM,UT_BitString, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_APOptions( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, APOptions *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, PRIM, UT_BitString,&reallen, &l );
    FORW;
    if( len < reallen )
        return ASN1_OVERRUN;
    p++;
    len--;
    reallen--;
    ret++;
    data->reserved = ( *p >> 7 ) & 1;
    data->use_session_key = ( *p >> 6 ) & 1;
    data->mutual_required = ( *p >> 5 ) & 1;
    p += reallen;
    len -= reallen;
    ret += reallen;
    if( size ) *size = ret;
    return 0;
    fail:
    free_APOptions( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_APOptions( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, APOptions *data )
{
}
size_t
length_APOptions( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const APOptions *data )
{
    size_t ret = 0;
    ret += 7;
    return ret;
}
int
encode_AP_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const AP_REP *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->enc_part, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 15, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_AP_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, AP_REP *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 15, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->enc_part, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_AP_REP( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_AP_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, AP_REP *data )
{
    free_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
    free_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( data )->enc_part );
}
size_t
length_AP_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const AP_REP *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->pvno );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( data )->enc_part );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_AP_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const AP_REQ *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->authenticator, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_Ticket( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->ticket, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_APOptions( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->ap_options, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 14, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_AP_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, AP_REQ *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 14, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_APOptions( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->ap_options, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_Ticket( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->ticket, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 4, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->authenticator, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_AP_REQ( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_AP_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, AP_REQ *data )
{
    free_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
    free_APOptions( NAME_OF_MAIN_LOC_GLOB_P, &( data )->ap_options );
    free_Ticket( NAME_OF_MAIN_LOC_GLOB_P, &( data )->ticket );
    free_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( data )->authenticator );
}
size_t
length_AP_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const AP_REQ *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->pvno );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_APOptions( NAME_OF_MAIN_LOC_GLOB_P, &( data )->ap_options );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_Ticket( NAME_OF_MAIN_LOC_GLOB_P, &( data )->ticket );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( data )->authenticator );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
decode_AS_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, AS_REP *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 11, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = decode_KDC_REP( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
        FORW;
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_AS_REP( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_AS_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, AS_REP *data )
{
    free_KDC_REP( NAME_OF_MAIN_LOC_GLOB_P, data );
}
int
encode_AS_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const AS_REQ *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_KDC_REQ( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 10, &l );
    BACK;
    *size = ret;
    return 0;
}
void
free_AS_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, AS_REQ *data )
{
    free_KDC_REQ( NAME_OF_MAIN_LOC_GLOB_P, data );
}
size_t
length_AS_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const AS_REQ *data )
{
    size_t ret = 0;
    ret += length_KDC_REQ( NAME_OF_MAIN_LOC_GLOB_P, data );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_Authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const Authenticator *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    if(( data )->authorization_data ) {
        int oldret = ret;
        ret = 0;
        e = encode_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->authorization_data, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 8, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->seq_number ) {
        int oldret = ret;
        ret = 0;
        e = encode_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->seq_number, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 7, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->subkey ) {
        int oldret = ret;
        ret = 0;
        e = encode_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->subkey, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 6, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->ctime, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cusec, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->cksum ) {
        int oldret = ret;
        ret = 0;
        e = encode_Checksum( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->cksum, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cname, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->crealm, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->authenticator_vno, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 2, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_Authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, Authenticator *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 2, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->authenticator_vno, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->crealm, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cname, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
                if( e )
                    ( data )->cksum = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->cksum =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->cksum ) )
                            ;
                        if(( data )->cksum == NULL ) return ENOMEM;
                        e = decode_Checksum( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->cksum, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 4, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cusec, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 5, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->ctime, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 6, &l );
                if( e )
                    ( data )->subkey = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->subkey =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->subkey ) )
                            ;
                        if(( data )->subkey == NULL ) return ENOMEM;
                        e = decode_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->subkey, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 7, &l );
                if( e )
                    ( data )->seq_number = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->seq_number =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->seq_number ) )
                            ;
                        if(( data )->seq_number == NULL ) return ENOMEM;
                        e = decode_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->seq_number, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 8, &l );
                if( e )
                    ( data )->authorization_data = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->authorization_data =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->authorization_data ) )
                            ;
                        if(( data )->authorization_data == NULL ) return ENOMEM;
                        e = decode_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->authorization_data, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_Authenticator( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_Authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, Authenticator *data )
{
    free_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->crealm );
    free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cname );
    if(( data )->cksum ) {
        free_Checksum( NAME_OF_MAIN_LOC_GLOB_P, ( data )->cksum );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->cksum )
        ;
        ( data )->cksum = NULL;
    }
    free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->ctime );
    if(( data )->subkey ) {
        free_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, ( data )->subkey );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->subkey )
        ;
        ( data )->subkey = NULL;
    }
    if(( data )->seq_number ) {
        free_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, ( data )->seq_number );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->seq_number )
        ;
        ( data )->seq_number = NULL;
    }
    if(( data )->authorization_data ) {
        free_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, ( data )->authorization_data );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->authorization_data )
        ;
        ( data )->authorization_data = NULL;
    }
}
size_t
length_Authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const Authenticator *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->authenticator_vno );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->crealm );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cname );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->cksum ) {
        int oldret = ret;
        ret = 0;
        ret += length_Checksum( NAME_OF_MAIN_LOC_GLOB_P, ( data )->cksum );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cusec );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->ctime );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->subkey ) {
        int oldret = ret;
        ret = 0;
        ret += length_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, ( data )->subkey );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->seq_number ) {
        int oldret = ret;
        ret = 0;
        ret += length_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, ( data )->seq_number );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->authorization_data ) {
        int oldret = ret;
        ret = 0;
        ret += length_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, ( data )->authorization_data );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_AuthorizationData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const AuthorizationData *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    for( i = ( data )->len - 1; i >= 0; --i ) {
        int oldret = ret;
        ret = 0;
        {
            int oldret = ret;
            ret = 0;
            e = encode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( &( data )->val[i] )->ad_data, &l );
            BACK;
            e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
            BACK;
            ret += oldret;
        }
        {
            int oldret = ret;
            ret = 0;
            e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( &( data )->val[i] )->ad_type, &l );
            BACK;
            e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
            BACK;
            ret += oldret;
        }
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_AuthorizationData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, AuthorizationData *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    if( len < reallen )
        return ASN1_OVERRUN;
    len = reallen;
    {
        size_t origlen = len;
        int oldret = ret;
        ret = 0;
        ( data )->len = 0;
        ( data )->val = NULL;
        while( ret < origlen ) {
            ( data )->len++;
            ( data )->val =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val, sizeof( *(( data )->val ) ) * ( data )->len )
                ;
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
            FORW;
            {
                int dce_fix;
                if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                    return ASN1_BAD_FORMAT;
                {
                    size_t newlen, oldlen;
                    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                    if( e )
                        return e;
                    else {
                        p += l;
                        len -= l;
                        ret += l;
                        e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                        FORW;
                        {
                            int dce_fix;
                            oldlen = len;
                            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                            e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( &( data )->val[( data )->len-1] )->ad_type, &l );
                            FORW;
                            if( dce_fix ) {
                                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                                FORW;
                            } else
                                len = oldlen - newlen;
                        }
                    }
                }
                {
                    size_t newlen, oldlen;
                    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                    if( e )
                        return e;
                    else {
                        p += l;
                        len -= l;
                        ret += l;
                        e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                        FORW;
                        {
                            int dce_fix;
                            oldlen = len;
                            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                            e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( &( data )->val[( data )->len-1] )->ad_data, &l );
                            FORW;
                            if( dce_fix ) {
                                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                                FORW;
                            } else
                                len = oldlen - newlen;
                        }
                    }
                }
                if( dce_fix ) {
                    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                    FORW;
                }
            }
            len = origlen - ret;
        }
        ret += oldret;
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_AuthorizationData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, AuthorizationData *data )
{
    while(( data )->len ) {
        free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( &( data )->val[( data )->len-1] )->ad_data );
        ( data )->len--;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val )
    ;
    ( data )->val = NULL;
}
size_t
length_AuthorizationData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const AuthorizationData *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        int i;
        ret = 0;
        for( i = ( data )->len - 1; i >= 0; --i ) {
            int oldret = ret;
            ret = 0;
            {
                int oldret = ret;
                ret = 0;
                ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( &( data )->val[i] )->ad_type );
                ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
            }
            {
                int oldret = ret;
                ret = 0;
                ret += length_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( &( data )->val[i] )->ad_data );
                ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
            }
            ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
            ret += oldret;
        }
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    return ret;
}
int
copy_AuthorizationData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const AuthorizationData *from, AuthorizationData *to )
{
    if((( to )->val =
                m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( from )->len * sizeof( *( to )->val ) )
       ) == NULL && ( from )->len != 0 )
        return ENOMEM;
    for(( to )->len = 0; ( to )->len < ( from )->len; ( to )->len++ ) {
        *( &( &( to )->val[( to )->len] )->ad_type ) = *( &( &( from )->val[( to )->len] )->ad_type );
        if( copy_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( &( from )->val[( to )->len] )->ad_data, &( &( to )->val[( to )->len] )->ad_data ) ) return ENOMEM;
    }
    return 0;
}
int
encode_Checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const Checksum *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->checksum, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_CKSUMTYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cksumtype, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_Checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, Checksum *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_CKSUMTYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cksumtype, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->checksum, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_Checksum( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_Checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, Checksum *data )
{
    free_CKSUMTYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cksumtype );
    free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->checksum );
}
size_t
length_Checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const Checksum *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_CKSUMTYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cksumtype );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->checksum );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_CKSUMTYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const CKSUMTYPE *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( const int* )data, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_CKSUMTYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, CKSUMTYPE *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( int* )data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_CKSUMTYPE( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_CKSUMTYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, CKSUMTYPE *data )
{
}
size_t
length_CKSUMTYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const CKSUMTYPE *data )
{
    size_t ret = 0;
    ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( const int* )data );
    return ret;
}
int
encode_EncAPRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const EncAPRepPart *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    if(( data )->seq_number ) {
        int oldret = ret;
        ret = 0;
        e = encode_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->seq_number, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->subkey ) {
        int oldret = ret;
        ret = 0;
        e = encode_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->subkey, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cusec, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->ctime, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 27, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_EncAPRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, EncAPRepPart *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 27, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->ctime, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cusec, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
                if( e )
                    ( data )->subkey = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->subkey =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->subkey ) )
                            ;
                        if(( data )->subkey == NULL ) return ENOMEM;
                        e = decode_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->subkey, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
                if( e )
                    ( data )->seq_number = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->seq_number =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->seq_number ) )
                            ;
                        if(( data )->seq_number == NULL ) return ENOMEM;
                        e = decode_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->seq_number, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_EncAPRepPart( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_EncAPRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, EncAPRepPart *data )
{
    free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->ctime );
    if(( data )->subkey ) {
        free_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, ( data )->subkey );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->subkey )
        ;
        ( data )->subkey = NULL;
    }
    if(( data )->seq_number ) {
        free_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, ( data )->seq_number );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->seq_number )
        ;
        ( data )->seq_number = NULL;
    }
}
size_t
length_EncAPRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const EncAPRepPart *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->ctime );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cusec );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->subkey ) {
        int oldret = ret;
        ret = 0;
        ret += length_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, ( data )->subkey );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->seq_number ) {
        int oldret = ret;
        ret = 0;
        ret += length_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, ( data )->seq_number );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
decode_EncASRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, EncASRepPart *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 25, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = decode_EncKDCRepPart( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
        FORW;
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_EncASRepPart( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_EncASRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, EncASRepPart *data )
{
    free_EncKDCRepPart( NAME_OF_MAIN_LOC_GLOB_P, data );
}
int
decode_EncKDCRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, EncKDCRepPart *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->key, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_LastReq( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->last_req, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->nonce, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
            if( e )
                ( data )->key_expiration = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->key_expiration =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->key_expiration ) )
                        ;
                    if(( data )->key_expiration == NULL ) return ENOMEM;
                    e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->key_expiration, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 4, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_TicketFlags( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->flags, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 5, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->authtime, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 6, &l );
            if( e )
                ( data )->starttime = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->starttime =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->starttime ) )
                        ;
                    if(( data )->starttime == NULL ) return ENOMEM;
                    e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->starttime, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 7, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->endtime, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 8, &l );
            if( e )
                ( data )->renew_till = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->renew_till =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->renew_till ) )
                        ;
                    if(( data )->renew_till == NULL ) return ENOMEM;
                    e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->renew_till, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 9, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->srealm, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 10, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->sname, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 11, &l );
            if( e )
                ( data )->caddr = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->caddr =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->caddr ) )
                        ;
                    if(( data )->caddr == NULL ) return ENOMEM;
                    e = decode_HostAddresses( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->caddr, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_EncKDCRepPart( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_EncKDCRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, EncKDCRepPart *data )
{
    free_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, &( data )->key );
    free_LastReq( NAME_OF_MAIN_LOC_GLOB_P, &( data )->last_req );
    if(( data )->key_expiration ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->key_expiration );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->key_expiration )
        ;
        ( data )->key_expiration = NULL;
    }
    free_TicketFlags( NAME_OF_MAIN_LOC_GLOB_P, &( data )->flags );
    free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->authtime );
    if(( data )->starttime ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->starttime );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->starttime )
        ;
        ( data )->starttime = NULL;
    }
    free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->endtime );
    if(( data )->renew_till ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->renew_till );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->renew_till )
        ;
        ( data )->renew_till = NULL;
    }
    free_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->srealm );
    free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->sname );
    if(( data )->caddr ) {
        free_HostAddresses( NAME_OF_MAIN_LOC_GLOB_P, ( data )->caddr );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->caddr )
        ;
        ( data )->caddr = NULL;
    }
}
int
encode_EncKrbPrivPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const EncKrbPrivPart *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    if(( data )->r_address ) {
        int oldret = ret;
        ret = 0;
        e = encode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->r_address, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->s_address ) {
        int oldret = ret;
        ret = 0;
        e = encode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->s_address, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->seq_number ) {
        int oldret = ret;
        ret = 0;
        e = encode_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->seq_number, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->usec ) {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->usec, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->timestamp ) {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->timestamp, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->user_data, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 28, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_EncKrbPrivPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, EncKrbPrivPart *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 28, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->user_data, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    ( data )->timestamp = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->timestamp =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->timestamp ) )
                            ;
                        if(( data )->timestamp == NULL ) return ENOMEM;
                        e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->timestamp, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
                if( e )
                    ( data )->usec = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->usec =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->usec ) )
                            ;
                        if(( data )->usec == NULL ) return ENOMEM;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->usec, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
                if( e )
                    ( data )->seq_number = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->seq_number =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->seq_number ) )
                            ;
                        if(( data )->seq_number == NULL ) return ENOMEM;
                        e = decode_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->seq_number, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 4, &l );
                if( e )
                    ( data )->s_address = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->s_address =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->s_address ) )
                            ;
                        if(( data )->s_address == NULL ) return ENOMEM;
                        e = decode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->s_address, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 5, &l );
                if( e )
                    ( data )->r_address = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->r_address =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->r_address ) )
                            ;
                        if(( data )->r_address == NULL ) return ENOMEM;
                        e = decode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->r_address, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_EncKrbPrivPart( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_EncKrbPrivPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, EncKrbPrivPart *data )
{
    free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->user_data );
    if(( data )->timestamp ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->timestamp );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->timestamp )
        ;
        ( data )->timestamp = NULL;
    }
    if(( data )->usec ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->usec )
        ;
        ( data )->usec = NULL;
    }
    if(( data )->seq_number ) {
        free_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, ( data )->seq_number );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->seq_number )
        ;
        ( data )->seq_number = NULL;
    }
    if(( data )->s_address ) {
        free_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, ( data )->s_address );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->s_address )
        ;
        ( data )->s_address = NULL;
    }
    if(( data )->r_address ) {
        free_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, ( data )->r_address );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->r_address )
        ;
        ( data )->r_address = NULL;
    }
}
size_t
length_EncKrbPrivPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const EncKrbPrivPart *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->user_data );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->timestamp ) {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->timestamp );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->usec ) {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( data )->usec );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->seq_number ) {
        int oldret = ret;
        ret = 0;
        ret += length_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, ( data )->seq_number );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->s_address ) {
        int oldret = ret;
        ret = 0;
        ret += length_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, ( data )->s_address );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->r_address ) {
        int oldret = ret;
        ret = 0;
        ret += length_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, ( data )->r_address );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_EncryptedData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const EncryptedData *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cipher, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->kvno ) {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->kvno, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->etype, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_EncryptedData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, EncryptedData *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->etype, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                ( data )->kvno = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->kvno =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->kvno ) )
                        ;
                    if(( data )->kvno == NULL ) return ENOMEM;
                    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->kvno, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cipher, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_EncryptedData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, EncryptedData *data )
{
    free_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->etype );
    if(( data )->kvno ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->kvno )
        ;
        ( data )->kvno = NULL;
    }
    free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cipher );
}
size_t
length_EncryptedData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const EncryptedData *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->etype );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->kvno ) {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( data )->kvno );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cipher );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
copy_EncryptedData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const EncryptedData *from, EncryptedData *to )
{
    if( copy_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, &( from )->etype, &( to )->etype ) ) return ENOMEM;
    if(( from )->kvno ) {
        ( to )->kvno =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( to )->kvno ) )
            ;
        if(( to )->kvno == NULL ) return ENOMEM;
        *(( to )->kvno ) = *(( from )->kvno );
    } else
        ( to )->kvno = NULL;
    if( copy_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( from )->cipher, &( to )->cipher ) ) return ENOMEM;
    return 0;
}
int
encode_EncryptionKey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const EncryptionKey *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->keyvalue, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->keytype, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_EncryptionKey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, EncryptionKey *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->keytype, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->keyvalue, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_EncryptionKey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, EncryptionKey *data )
{
    free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->keyvalue );
}
size_t
length_EncryptionKey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const EncryptionKey *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->keytype );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->keyvalue );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
copy_EncryptionKey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const EncryptionKey *from, EncryptionKey *to )
{
    *( &( to )->keytype ) = *( &( from )->keytype );
    if( copy_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( from )->keyvalue, &( to )->keyvalue ) ) return ENOMEM;
    return 0;
}
int
decode_EncTGSRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, EncTGSRepPart *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 26, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = decode_EncKDCRepPart( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
        FORW;
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_EncTGSRepPart( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_EncTGSRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, EncTGSRepPart *data )
{
    free_EncKDCRepPart( NAME_OF_MAIN_LOC_GLOB_P, data );
}
int
decode_EncTicketPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, EncTicketPart *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 3, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_TicketFlags( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->flags, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->key, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->crealm, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cname, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 4, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_TransitedEncoding( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->transited, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 5, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->authtime, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 6, &l );
                if( e )
                    ( data )->starttime = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->starttime =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->starttime ) )
                            ;
                        if(( data )->starttime == NULL ) return ENOMEM;
                        e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->starttime, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 7, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->endtime, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 8, &l );
                if( e )
                    ( data )->renew_till = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->renew_till =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->renew_till ) )
                            ;
                        if(( data )->renew_till == NULL ) return ENOMEM;
                        e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->renew_till, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 9, &l );
                if( e )
                    ( data )->caddr = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->caddr =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->caddr ) )
                            ;
                        if(( data )->caddr == NULL ) return ENOMEM;
                        e = decode_HostAddresses( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->caddr, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 10, &l );
                if( e )
                    ( data )->authorization_data = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->authorization_data =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->authorization_data ) )
                            ;
                        if(( data )->authorization_data == NULL ) return ENOMEM;
                        e = decode_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->authorization_data, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_EncTicketPart( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_EncTicketPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, EncTicketPart *data )
{
    free_TicketFlags( NAME_OF_MAIN_LOC_GLOB_P, &( data )->flags );
    free_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, &( data )->key );
    free_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->crealm );
    free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cname );
    free_TransitedEncoding( NAME_OF_MAIN_LOC_GLOB_P, &( data )->transited );
    free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->authtime );
    if(( data )->starttime ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->starttime );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->starttime )
        ;
        ( data )->starttime = NULL;
    }
    free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->endtime );
    if(( data )->renew_till ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->renew_till );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->renew_till )
        ;
        ( data )->renew_till = NULL;
    }
    if(( data )->caddr ) {
        free_HostAddresses( NAME_OF_MAIN_LOC_GLOB_P, ( data )->caddr );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->caddr )
        ;
        ( data )->caddr = NULL;
    }
    if(( data )->authorization_data ) {
        free_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, ( data )->authorization_data );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->authorization_data )
        ;
        ( data )->authorization_data = NULL;
    }
}
int
encode_ENCTYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const ENCTYPE *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( const int* )data, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_ENCTYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, ENCTYPE *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( int* )data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_ENCTYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, ENCTYPE *data )
{
}
size_t
length_ENCTYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const ENCTYPE *data )
{
    size_t ret = 0;
    ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( const int* )data );
    return ret;
}
int
copy_ENCTYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const ENCTYPE *from, ENCTYPE *to )
{
    *( to ) = *( from );
    return 0;
}
void initialize_asn1_error_table_r( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct et_list **list )
{
    initialize_error_table_r( NAME_OF_MAIN_LOC_GLOB_P, list, asn1_error_strings, 10, ERROR_TABLE_BASE_asn1 );
}
int
encode_EtypeList( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const EtypeList *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    for( i = ( data )->len - 1; i >= 0; --i ) {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->val[i], &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_EtypeList( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, EtypeList *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    if( len < reallen )
        return ASN1_OVERRUN;
    len = reallen;
    {
        size_t origlen = len;
        int oldret = ret;
        ret = 0;
        ( data )->len = 0;
        ( data )->val = NULL;
        while( ret < origlen ) {
            ( data )->len++;
            ( data )->val =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val, sizeof( *(( data )->val ) ) * ( data )->len )
                ;
            e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->val[( data )->len-1], &l );
            FORW;
            len = origlen - ret;
        }
        ret += oldret;
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_EtypeList( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_EtypeList( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, EtypeList *data )
{
    while(( data )->len ) {
        ( data )->len--;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val )
    ;
    ( data )->val = NULL;
}
size_t
length_EtypeList( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const EtypeList *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        int i;
        ret = 0;
        for( i = ( data )->len - 1; i >= 0; --i ) {
            int oldret = ret;
            ret = 0;
            ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->val[i] );
            ret += oldret;
        }
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    return ret;
}
int
decode_ETYPE_INFO2( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, ETYPE_INFO2 *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    if( len < reallen )
        return ASN1_OVERRUN;
    len = reallen;
    {
        size_t origlen = len;
        int oldret = ret;
        ret = 0;
        ( data )->len = 0;
        ( data )->val = NULL;
        while( ret < origlen ) {
            ( data )->len++;
            ( data )->val =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val, sizeof( *(( data )->val ) ) * ( data )->len )
                ;
            e = decode_ETYPE_INFO2_ENTRY( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->val[( data )->len-1], &l );
            FORW;
            len = origlen - ret;
        }
        ret += oldret;
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_ETYPE_INFO2( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_ETYPE_INFO2( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, ETYPE_INFO2 *data )
{
    while(( data )->len ) {
        free_ETYPE_INFO2_ENTRY( NAME_OF_MAIN_LOC_GLOB_P, &( data )->val[( data )->len-1] );
        ( data )->len--;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val )
    ;
    ( data )->val = NULL;
}
int
decode_ETYPE_INFO2_ENTRY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, ETYPE_INFO2_ENTRY *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->etype, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                ( data )->salt = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->salt =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->salt ) )
                        ;
                    if(( data )->salt == NULL ) return ENOMEM;
                    e = decode_KerberosString( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->salt, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
            if( e )
                ( data )->s2kparams = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->s2kparams =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->s2kparams ) )
                        ;
                    if(( data )->s2kparams == NULL ) return ENOMEM;
                    e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->s2kparams, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_ETYPE_INFO2_ENTRY( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_ETYPE_INFO2_ENTRY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, ETYPE_INFO2_ENTRY *data )
{
    free_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->etype );
    if(( data )->salt ) {
        free_KerberosString( NAME_OF_MAIN_LOC_GLOB_P, ( data )->salt );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->salt )
        ;
        ( data )->salt = NULL;
    }
    if(( data )->s2kparams ) {
        free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, ( data )->s2kparams );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->s2kparams )
        ;
        ( data )->s2kparams = NULL;
    }
}
int
decode_ETYPE_INFO( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, ETYPE_INFO *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    if( len < reallen )
        return ASN1_OVERRUN;
    len = reallen;
    {
        size_t origlen = len;
        int oldret = ret;
        ret = 0;
        ( data )->len = 0;
        ( data )->val = NULL;
        while( ret < origlen ) {
            ( data )->len++;
            ( data )->val =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val, sizeof( *(( data )->val ) ) * ( data )->len )
                ;
            e = decode_ETYPE_INFO_ENTRY( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->val[( data )->len-1], &l );
            FORW;
            len = origlen - ret;
        }
        ret += oldret;
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_ETYPE_INFO( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_ETYPE_INFO( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, ETYPE_INFO *data )
{
    while(( data )->len ) {
        free_ETYPE_INFO_ENTRY( NAME_OF_MAIN_LOC_GLOB_P, &( data )->val[( data )->len-1] );
        ( data )->len--;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val )
    ;
    ( data )->val = NULL;
}
int
decode_ETYPE_INFO_ENTRY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, ETYPE_INFO_ENTRY *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->etype, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                ( data )->salt = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->salt =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->salt ) )
                        ;
                    if(( data )->salt == NULL ) return ENOMEM;
                    e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->salt, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
            if( e )
                ( data )->salttype = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->salttype =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->salttype ) )
                        ;
                    if(( data )->salttype == NULL ) return ENOMEM;
                    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->salttype, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_ETYPE_INFO_ENTRY( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_ETYPE_INFO_ENTRY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, ETYPE_INFO_ENTRY *data )
{
    free_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->etype );
    if(( data )->salt ) {
        free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, ( data )->salt );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->salt )
        ;
        ( data )->salt = NULL;
    }
    if(( data )->salttype ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->salttype )
        ;
        ( data )->salttype = NULL;
    }
}
krb5_error_code KRB5_LIB_FUNCTION
_krb5_principal2principalname( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, PrincipalName *p,
                               const krb5_principal from )
{
    return copy_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &from->name, p );
}
krb5_error_code KRB5_LIB_FUNCTION
_krb5_principalname2krb5_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_principal *principal,
                                    const PrincipalName from,
                                    const Realm realm )
{
    krb5_principal p =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *p ) )
        ;
    copy_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &from, &p->name );
    p->realm = m_strdup_hl( NAME_OF_MAIN_LOC_GLOB_P, realm );
    *principal = p;
    return 0;
}
int
encode_HostAddresses( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const HostAddresses *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    for( i = ( data )->len - 1; i >= 0; --i ) {
        int oldret = ret;
        ret = 0;
        e = encode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->val[i], &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_HostAddresses( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, HostAddresses *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    if( len < reallen )
        return ASN1_OVERRUN;
    len = reallen;
    {
        size_t origlen = len;
        int oldret = ret;
        ret = 0;
        ( data )->len = 0;
        ( data )->val = NULL;
        while( ret < origlen ) {
            ( data )->len++;
            ( data )->val =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val, sizeof( *(( data )->val ) ) * ( data )->len )
                ;
            e = decode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->val[( data )->len-1], &l );
            FORW;
            len = origlen - ret;
        }
        ret += oldret;
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_HostAddresses( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_HostAddresses( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, HostAddresses *data )
{
    while(( data )->len ) {
        free_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, &( data )->val[( data )->len-1] );
        ( data )->len--;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val )
    ;
    ( data )->val = NULL;
}
size_t
length_HostAddresses( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const HostAddresses *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        int i;
        ret = 0;
        for( i = ( data )->len - 1; i >= 0; --i ) {
            int oldret = ret;
            ret = 0;
            ret += length_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, &( data )->val[i] );
            ret += oldret;
        }
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    return ret;
}
int
encode_HostAddress( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const HostAddress *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->address, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->addr_type, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_HostAddress( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, HostAddress *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->addr_type, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->address, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_HostAddress( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, HostAddress *data )
{
    free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->address );
}
size_t
length_HostAddress( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const HostAddress *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->addr_type );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->address );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_KDCOptions( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const KDCOptions *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        unsigned char c = 0;
        if( data->validate ) c |= 1<<0;
        if( data->renew ) c |= 1<<1;
        if( data->enc_tkt_in_skey ) c |= 1<<3;
        if( data->renewable_ok ) c |= 1<<4;
        if( data->disable_transited_check ) c |= 1<<5;
        *p-- = c;
        len--;
        ret++;
        c = 0;
        *p-- = c;
        len--;
        ret++;
        c = 0;
        if( data->canonicalize ) c |= 1<<0;
        if( data->request_anonymous ) c |= 1<<1;
        if( data->unused11 ) c |= 1<<4;
        if( data->unused10 ) c |= 1<<5;
        if( data->unused9 ) c |= 1<<6;
        if( data->renewable ) c |= 1<<7;
        *p-- = c;
        len--;
        ret++;
        c = 0;
        if( data->unused7 ) c |= 1<<0;
        if( data->postdated ) c |= 1<<1;
        if( data->allow_postdate ) c |= 1<<2;
        if( data->proxy ) c |= 1<<3;
        if( data->proxiable ) c |= 1<<4;
        if( data->forwarded ) c |= 1<<5;
        if( data->forwardable ) c |= 1<<6;
        if( data->reserved ) c |= 1<<7;
        *p-- = c;
        *p-- = 0;
        len -= 2;
        ret += 2;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, PRIM,UT_BitString, &l );
    BACK;
    *size = ret;
    return 0;
}
void
free_KDCOptions( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KDCOptions *data )
{
}
size_t
length_KDCOptions( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const KDCOptions *data )
{
    size_t ret = 0;
    ret += 7;
    return ret;
}
int
decode_KDC_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, KDC_REP *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
            if( e )
                ( data )->padata = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->padata =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->padata ) )
                        ;
                    if(( data )->padata == NULL ) return ENOMEM;
                    e = decode_METHOD_DATA( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->padata, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->crealm, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 4, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cname, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 5, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_Ticket( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->ticket, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 6, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->enc_part, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_KDC_REP( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_KDC_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KDC_REP *data )
{
    free_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
    if(( data )->padata ) {
        free_METHOD_DATA( NAME_OF_MAIN_LOC_GLOB_P, ( data )->padata );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->padata )
        ;
        ( data )->padata = NULL;
    }
    free_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->crealm );
    free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cname );
    free_Ticket( NAME_OF_MAIN_LOC_GLOB_P, &( data )->ticket );
    free_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( data )->enc_part );
}
int
encode_KDC_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const KDC_REQ *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_KDC_REQ_BODY( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->req_body, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->padata ) {
        int oldret = ret;
        ret = 0;
        e = encode_METHOD_DATA( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->padata, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
void
free_KDC_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KDC_REQ *data )
{
    free_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
    if(( data )->padata ) {
        free_METHOD_DATA( NAME_OF_MAIN_LOC_GLOB_P, ( data )->padata );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->padata )
        ;
        ( data )->padata = NULL;
    }
    free_KDC_REQ_BODY( NAME_OF_MAIN_LOC_GLOB_P, &( data )->req_body );
}
size_t
length_KDC_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const KDC_REQ *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->pvno );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->padata ) {
        int oldret = ret;
        ret = 0;
        ret += length_METHOD_DATA( NAME_OF_MAIN_LOC_GLOB_P, ( data )->padata );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_KDC_REQ_BODY( NAME_OF_MAIN_LOC_GLOB_P, &( data )->req_body );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_KDC_REQ_BODY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const KDC_REQ_BODY *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    if(( data )->additional_tickets ) {
        int oldret = ret;
        ret = 0;
        for( i = (( data )->additional_tickets )->len - 1; i >= 0; --i ) {
            int oldret = ret;
            ret = 0;
            e = encode_Ticket( NAME_OF_MAIN_LOC_GLOB_P, p, len, &(( data )->additional_tickets )->val[i], &l );
            BACK;
            ret += oldret;
        }
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 11, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->enc_authorization_data ) {
        int oldret = ret;
        ret = 0;
        e = encode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->enc_authorization_data, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 10, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->addresses ) {
        int oldret = ret;
        ret = 0;
        e = encode_HostAddresses( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->addresses, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 9, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        for( i = ( &( data )->etype )->len - 1; i >= 0; --i ) {
            int oldret = ret;
            ret = 0;
            e = encode_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( &( data )->etype )->val[i], &l );
            BACK;
            ret += oldret;
        }
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 8, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->nonce, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 7, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->rtime ) {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->rtime, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 6, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->till ) {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->till, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->from ) {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->from, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->sname ) {
        int oldret = ret;
        ret = 0;
        e = encode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->sname, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->realm, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->cname ) {
        int oldret = ret;
        ret = 0;
        e = encode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->cname, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_KDCOptions( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->kdc_options, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
void
free_KDC_REQ_BODY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KDC_REQ_BODY *data )
{
    free_KDCOptions( NAME_OF_MAIN_LOC_GLOB_P, &( data )->kdc_options );
    if(( data )->cname ) {
        free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, ( data )->cname );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->cname )
        ;
        ( data )->cname = NULL;
    }
    free_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->realm );
    if(( data )->sname ) {
        free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, ( data )->sname );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->sname )
        ;
        ( data )->sname = NULL;
    }
    if(( data )->from ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->from );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->from )
        ;
        ( data )->from = NULL;
    }
    if(( data )->till ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->till );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->till )
        ;
        ( data )->till = NULL;
    }
    if(( data )->rtime ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->rtime );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->rtime )
        ;
        ( data )->rtime = NULL;
    }
    while(( &( data )->etype )->len ) {
        free_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, &( &( data )->etype )->val[( &( data )->etype )->len-1] );
        ( &( data )->etype )->len--;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( &( data )->etype )->val )
    ;
    ( &( data )->etype )->val = NULL;
    if(( data )->addresses ) {
        free_HostAddresses( NAME_OF_MAIN_LOC_GLOB_P, ( data )->addresses );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->addresses )
        ;
        ( data )->addresses = NULL;
    }
    if(( data )->enc_authorization_data ) {
        free_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, ( data )->enc_authorization_data );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->enc_authorization_data )
        ;
        ( data )->enc_authorization_data = NULL;
    }
    if(( data )->additional_tickets ) {
        while((( data )->additional_tickets )->len ) {
            free_Ticket( NAME_OF_MAIN_LOC_GLOB_P, &(( data )->additional_tickets )->val[(( data )->additional_tickets )->len-1] );
            (( data )->additional_tickets )->len--;
        }
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, (( data )->additional_tickets )->val )
        ;
        (( data )->additional_tickets )->val = NULL;
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->additional_tickets )
        ;
        ( data )->additional_tickets = NULL;
    }
}
size_t
length_KDC_REQ_BODY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const KDC_REQ_BODY *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_KDCOptions( NAME_OF_MAIN_LOC_GLOB_P, &( data )->kdc_options );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->cname ) {
        int oldret = ret;
        ret = 0;
        ret += length_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, ( data )->cname );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->realm );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->sname ) {
        int oldret = ret;
        ret = 0;
        ret += length_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, ( data )->sname );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->from ) {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->from );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->till ) {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->till );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->rtime ) {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->rtime );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->nonce );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        {
            int oldret = ret;
            int i;
            ret = 0;
            for( i = ( &( data )->etype )->len - 1; i >= 0; --i ) {
                int oldret = ret;
                ret = 0;
                ret += length_ENCTYPE( NAME_OF_MAIN_LOC_GLOB_P, &( &( data )->etype )->val[i] );
                ret += oldret;
            }
            ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
        }
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->addresses ) {
        int oldret = ret;
        ret = 0;
        ret += length_HostAddresses( NAME_OF_MAIN_LOC_GLOB_P, ( data )->addresses );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->enc_authorization_data ) {
        int oldret = ret;
        ret = 0;
        ret += length_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, ( data )->enc_authorization_data );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->additional_tickets ) {
        int oldret = ret;
        ret = 0;
        {
            int oldret = ret;
            int i;
            ret = 0;
            for( i = (( data )->additional_tickets )->len - 1; i >= 0; --i ) {
                int oldret = ret;
                ret = 0;
                ret += length_Ticket( NAME_OF_MAIN_LOC_GLOB_P, &(( data )->additional_tickets )->val[i] );
                ret += oldret;
            }
            ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
        }
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
decode_KerberosString( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, KerberosString *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_general_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_KerberosString( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_KerberosString( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KerberosString *data )
{
    free_general_string( NAME_OF_MAIN_LOC_GLOB_P, data );
}
int
encode_KerberosTime( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const KerberosTime *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_generalized_time( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_KerberosTime( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, KerberosTime *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_generalized_time( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_KerberosTime( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KerberosTime *data )
{
}
size_t
length_KerberosTime( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const KerberosTime *data )
{
    size_t ret = 0;
    ret += length_generalized_time( NAME_OF_MAIN_LOC_GLOB_P, data );
    return ret;
}
int
encode_KRB_ERROR( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const KRB_ERROR *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    if(( data )->e_data ) {
        int oldret = ret;
        ret = 0;
        e = encode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->e_data, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 12, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->e_text ) {
        int oldret = ret;
        ret = 0;
        e = encode_general_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->e_text, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 11, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->sname, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 10, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->realm, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 9, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->cname ) {
        int oldret = ret;
        ret = 0;
        e = encode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->cname, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 8, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->crealm ) {
        int oldret = ret;
        ret = 0;
        e = encode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->crealm, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 7, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->error_code, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 6, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->susec, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->stime, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->cusec ) {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->cusec, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->ctime ) {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->ctime, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 30, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_KRB_ERROR( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, KRB_ERROR *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 30, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
                if( e )
                    ( data )->ctime = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->ctime =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->ctime ) )
                            ;
                        if(( data )->ctime == NULL ) return ENOMEM;
                        e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->ctime, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
                if( e )
                    ( data )->cusec = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->cusec =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->cusec ) )
                            ;
                        if(( data )->cusec == NULL ) return ENOMEM;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->cusec, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 4, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->stime, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 5, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->susec, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 6, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->error_code, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 7, &l );
                if( e )
                    ( data )->crealm = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->crealm =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->crealm ) )
                            ;
                        if(( data )->crealm == NULL ) return ENOMEM;
                        e = decode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->crealm, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 8, &l );
                if( e )
                    ( data )->cname = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->cname =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->cname ) )
                            ;
                        if(( data )->cname == NULL ) return ENOMEM;
                        e = decode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->cname, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 9, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->realm, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 10, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->sname, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 11, &l );
                if( e )
                    ( data )->e_text = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->e_text =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->e_text ) )
                            ;
                        if(( data )->e_text == NULL ) return ENOMEM;
                        e = decode_general_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->e_text, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 12, &l );
                if( e )
                    ( data )->e_data = NULL;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        ( data )->e_data =
                            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->e_data ) )
                            ;
                        if(( data )->e_data == NULL ) return ENOMEM;
                        e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->e_data, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_KRB_ERROR( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_KRB_ERROR( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KRB_ERROR *data )
{
    free_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
    if(( data )->ctime ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->ctime );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->ctime )
        ;
        ( data )->ctime = NULL;
    }
    if(( data )->cusec ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->cusec )
        ;
        ( data )->cusec = NULL;
    }
    free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->stime );
    if(( data )->crealm ) {
        free_Realm( NAME_OF_MAIN_LOC_GLOB_P, ( data )->crealm );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->crealm )
        ;
        ( data )->crealm = NULL;
    }
    if(( data )->cname ) {
        free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, ( data )->cname );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->cname )
        ;
        ( data )->cname = NULL;
    }
    free_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->realm );
    free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->sname );
    if(( data )->e_text ) {
        free_general_string( NAME_OF_MAIN_LOC_GLOB_P, ( data )->e_text );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->e_text )
        ;
        ( data )->e_text = NULL;
    }
    if(( data )->e_data ) {
        free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, ( data )->e_data );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->e_data )
        ;
        ( data )->e_data = NULL;
    }
}
size_t
length_KRB_ERROR( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const KRB_ERROR *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->pvno );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->ctime ) {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->ctime );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->cusec ) {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( data )->cusec );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->stime );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->susec );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->error_code );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->crealm ) {
        int oldret = ret;
        ret = 0;
        ret += length_Realm( NAME_OF_MAIN_LOC_GLOB_P, ( data )->crealm );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->cname ) {
        int oldret = ret;
        ret = 0;
        ret += length_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, ( data )->cname );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->realm );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->sname );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->e_text ) {
        int oldret = ret;
        ret = 0;
        ret += length_general_string( NAME_OF_MAIN_LOC_GLOB_P, ( data )->e_text );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->e_data ) {
        int oldret = ret;
        ret = 0;
        ret += length_octet_string( NAME_OF_MAIN_LOC_GLOB_P, ( data )->e_data );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_KRB_PRIV( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const KRB_PRIV *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->enc_part, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 21, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_KRB_PRIV( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, KRB_PRIV *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 21, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->enc_part, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_KRB_PRIV( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_KRB_PRIV( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KRB_PRIV *data )
{
    free_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
    free_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( data )->enc_part );
}
size_t
length_KRB_PRIV( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const KRB_PRIV *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->pvno );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( data )->enc_part );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_KRB_SAFE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const KRB_SAFE *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_Checksum( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cksum, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_KRB_SAFE_BODY( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->safe_body, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 20, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_KRB_SAFE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, KRB_SAFE *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 20, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->pvno, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->msg_type, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_KRB_SAFE_BODY( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->safe_body, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_Checksum( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->cksum, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_KRB_SAFE( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_KRB_SAFE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KRB_SAFE *data )
{
    free_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
    free_KRB_SAFE_BODY( NAME_OF_MAIN_LOC_GLOB_P, &( data )->safe_body );
    free_Checksum( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cksum );
}
size_t
length_KRB_SAFE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const KRB_SAFE *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->pvno );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->msg_type );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_KRB_SAFE_BODY( NAME_OF_MAIN_LOC_GLOB_P, &( data )->safe_body );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_Checksum( NAME_OF_MAIN_LOC_GLOB_P, &( data )->cksum );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_KRB_SAFE_BODY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const KRB_SAFE_BODY *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    if(( data )->r_address ) {
        int oldret = ret;
        ret = 0;
        e = encode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->r_address, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->s_address ) {
        int oldret = ret;
        ret = 0;
        e = encode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->s_address, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->seq_number ) {
        int oldret = ret;
        ret = 0;
        e = encode_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->seq_number, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->usec ) {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->usec, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    if(( data )->timestamp ) {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->timestamp, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->user_data, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_KRB_SAFE_BODY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, KRB_SAFE_BODY *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->user_data, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                ( data )->timestamp = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->timestamp =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->timestamp ) )
                        ;
                    if(( data )->timestamp == NULL ) return ENOMEM;
                    e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->timestamp, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
            if( e )
                ( data )->usec = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->usec =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->usec ) )
                        ;
                    if(( data )->usec == NULL ) return ENOMEM;
                    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->usec, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
            if( e )
                ( data )->seq_number = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->seq_number =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->seq_number ) )
                        ;
                    if(( data )->seq_number == NULL ) return ENOMEM;
                    e = decode_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->seq_number, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 4, &l );
            if( e )
                ( data )->s_address = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->s_address =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->s_address ) )
                        ;
                    if(( data )->s_address == NULL ) return ENOMEM;
                    e = decode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->s_address, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 5, &l );
            if( e )
                ( data )->r_address = NULL;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    ( data )->r_address =
                        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *( data )->r_address ) )
                        ;
                    if(( data )->r_address == NULL ) return ENOMEM;
                    e = decode_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->r_address, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_KRB_SAFE_BODY( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_KRB_SAFE_BODY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, KRB_SAFE_BODY *data )
{
    free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->user_data );
    if(( data )->timestamp ) {
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->timestamp );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->timestamp )
        ;
        ( data )->timestamp = NULL;
    }
    if(( data )->usec ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->usec )
        ;
        ( data )->usec = NULL;
    }
    if(( data )->seq_number ) {
        free_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, ( data )->seq_number );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->seq_number )
        ;
        ( data )->seq_number = NULL;
    }
    if(( data )->s_address ) {
        free_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, ( data )->s_address );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->s_address )
        ;
        ( data )->s_address = NULL;
    }
    if(( data )->r_address ) {
        free_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, ( data )->r_address );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->r_address )
        ;
        ( data )->r_address = NULL;
    }
}
size_t
length_KRB_SAFE_BODY( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const KRB_SAFE_BODY *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->user_data );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->timestamp ) {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, ( data )->timestamp );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->usec ) {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( data )->usec );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->seq_number ) {
        int oldret = ret;
        ret = 0;
        ret += length_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, ( data )->seq_number );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->s_address ) {
        int oldret = ret;
        ret = 0;
        ret += length_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, ( data )->s_address );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->r_address ) {
        int oldret = ret;
        ret = 0;
        ret += length_HostAddress( NAME_OF_MAIN_LOC_GLOB_P, ( data )->r_address );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
decode_LastReq( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, LastReq *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    if( len < reallen )
        return ASN1_OVERRUN;
    len = reallen;
    {
        size_t origlen = len;
        int oldret = ret;
        ret = 0;
        ( data )->len = 0;
        ( data )->val = NULL;
        while( ret < origlen ) {
            ( data )->len++;
            ( data )->val =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val, sizeof( *(( data )->val ) ) * ( data )->len )
                ;
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
            FORW;
            {
                int dce_fix;
                if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                    return ASN1_BAD_FORMAT;
                {
                    size_t newlen, oldlen;
                    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                    if( e )
                        return e;
                    else {
                        p += l;
                        len -= l;
                        ret += l;
                        e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                        FORW;
                        {
                            int dce_fix;
                            oldlen = len;
                            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                            e = decode_LR_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( &( data )->val[( data )->len-1] )->lr_type, &l );
                            FORW;
                            if( dce_fix ) {
                                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                                FORW;
                            } else
                                len = oldlen - newlen;
                        }
                    }
                }
                {
                    size_t newlen, oldlen;
                    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                    if( e )
                        return e;
                    else {
                        p += l;
                        len -= l;
                        ret += l;
                        e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                        FORW;
                        {
                            int dce_fix;
                            oldlen = len;
                            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                            e = decode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( &( data )->val[( data )->len-1] )->lr_value, &l );
                            FORW;
                            if( dce_fix ) {
                                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                                FORW;
                            } else
                                len = oldlen - newlen;
                        }
                    }
                }
                if( dce_fix ) {
                    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                    FORW;
                }
            }
            len = origlen - ret;
        }
        ret += oldret;
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_LastReq( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_LastReq( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, LastReq *data )
{
    while(( data )->len ) {
        free_LR_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( &( data )->val[( data )->len-1] )->lr_type );
        free_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( &( data )->val[( data )->len-1] )->lr_value );
        ( data )->len--;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val )
    ;
    ( data )->val = NULL;
}
int
decode_LR_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, LR_TYPE *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( int* )data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_LR_TYPE( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_LR_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, LR_TYPE *data )
{
}
int
encode_MESSAGE_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const MESSAGE_TYPE *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( const int* )data, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_MESSAGE_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, MESSAGE_TYPE *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( int* )data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_MESSAGE_TYPE( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_MESSAGE_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, MESSAGE_TYPE *data )
{
}
size_t
length_MESSAGE_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const MESSAGE_TYPE *data )
{
    size_t ret = 0;
    ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( const int* )data );
    return ret;
}
int
encode_METHOD_DATA( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const METHOD_DATA *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    for( i = ( data )->len - 1; i >= 0; --i ) {
        int oldret = ret;
        ret = 0;
        e = encode_PA_DATA( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->val[i], &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_METHOD_DATA( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, METHOD_DATA *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    if( len < reallen )
        return ASN1_OVERRUN;
    len = reallen;
    {
        size_t origlen = len;
        int oldret = ret;
        ret = 0;
        ( data )->len = 0;
        ( data )->val = NULL;
        while( ret < origlen ) {
            ( data )->len++;
            ( data )->val =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val, sizeof( *(( data )->val ) ) * ( data )->len )
                ;
            e = decode_PA_DATA( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->val[( data )->len-1], &l );
            FORW;
            len = origlen - ret;
        }
        ret += oldret;
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_METHOD_DATA( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_METHOD_DATA( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, METHOD_DATA *data )
{
    while(( data )->len ) {
        free_PA_DATA( NAME_OF_MAIN_LOC_GLOB_P, &( data )->val[( data )->len-1] );
        ( data )->len--;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( data )->val )
    ;
    ( data )->val = NULL;
}
size_t
length_METHOD_DATA( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const METHOD_DATA *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        int i;
        ret = 0;
        for( i = ( data )->len - 1; i >= 0; --i ) {
            int oldret = ret;
            ret = 0;
            ret += length_PA_DATA( NAME_OF_MAIN_LOC_GLOB_P, &( data )->val[i] );
            ret += oldret;
        }
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    return ret;
}
int
encode_NAME_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const NAME_TYPE *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( const int* )data, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_NAME_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, NAME_TYPE *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( int* )data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_NAME_TYPE( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_NAME_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, NAME_TYPE *data )
{
}
size_t
length_NAME_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const NAME_TYPE *data )
{
    size_t ret = 0;
    ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( const int* )data );
    return ret;
}
int
copy_NAME_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const NAME_TYPE *from, NAME_TYPE *to )
{
    *( to ) = *( from );
    return 0;
}
int
encode_PADATA_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const PADATA_TYPE *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( const int* )data, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_PADATA_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, PADATA_TYPE *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( int* )data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_PADATA_TYPE( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_PADATA_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, PADATA_TYPE *data )
{
}
size_t
length_PADATA_TYPE( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const PADATA_TYPE *data )
{
    size_t ret = 0;
    ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( const int* )data );
    return ret;
}
int
encode_PA_DATA( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const PA_DATA *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->padata_value, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_PADATA_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->padata_type, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_PA_DATA( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, PA_DATA *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_PADATA_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->padata_type, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->padata_value, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_PA_DATA( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_PA_DATA( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, PA_DATA *data )
{
    free_PADATA_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->padata_type );
    free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->padata_value );
}
size_t
length_PA_DATA( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const PA_DATA *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_PADATA_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->padata_type );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->padata_value );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_PA_ENC_TS_ENC( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const PA_ENC_TS_ENC *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    if(( data )->pausec ) {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( data )->pausec, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->patimestamp, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
size_t
length_PA_ENC_TS_ENC( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const PA_ENC_TS_ENC *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_KerberosTime( NAME_OF_MAIN_LOC_GLOB_P, &( data )->patimestamp );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    if(( data )->pausec ) {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, ( data )->pausec );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_PA_PAC_REQUEST( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const PA_PAC_REQUEST *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_boolean( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->include_pac, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
size_t
length_PA_PAC_REQUEST( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const PA_PAC_REQUEST *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_boolean( NAME_OF_MAIN_LOC_GLOB_P, &( data )->include_pac );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
encode_PrincipalName( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const PrincipalName *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        for( i = ( &( data )->name_string )->len - 1; i >= 0; --i ) {
            int oldret = ret;
            ret = 0;
            e = encode_general_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( &( data )->name_string )->val[i], &l );
            BACK;
            ret += oldret;
        }
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_NAME_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->name_type, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_PrincipalName( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, PrincipalName *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_NAME_TYPE( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->name_type, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
                    FORW;
                    if( len < reallen )
                        return ASN1_OVERRUN;
                    len = reallen;
                    {
                        size_t origlen = len;
                        int oldret = ret;
                        ret = 0;
                        ( &( data )->name_string )->len = 0;
                        ( &( data )->name_string )->val = NULL;
                        while( ret < origlen ) {
                            ( &( data )->name_string )->len++;
                            ( &( data )->name_string )->val =
                                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( &( data )->name_string )->val, sizeof( *(( &( data )->name_string )->val ) ) * ( &( data )->name_string )->len )
                                ;
                            e = decode_general_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( &( data )->name_string )->val[( &( data )->name_string )->len-1], &l );
                            FORW;
                            len = origlen - ret;
                        }
                        ret += oldret;
                    }
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_PrincipalName( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, PrincipalName *data )
{
    free_NAME_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->name_type );
    while(( &( data )->name_string )->len ) {
        free_general_string( NAME_OF_MAIN_LOC_GLOB_P, &( &( data )->name_string )->val[( &( data )->name_string )->len-1] );
        ( &( data )->name_string )->len--;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( &( data )->name_string )->val )
    ;
    ( &( data )->name_string )->val = NULL;
}
size_t
length_PrincipalName( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const PrincipalName *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_NAME_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( data )->name_type );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        {
            int oldret = ret;
            int i;
            ret = 0;
            for( i = ( &( data )->name_string )->len - 1; i >= 0; --i ) {
                int oldret = ret;
                ret = 0;
                ret += length_general_string( NAME_OF_MAIN_LOC_GLOB_P, &( &( data )->name_string )->val[i] );
                ret += oldret;
            }
            ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
        }
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
copy_PrincipalName( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const PrincipalName *from, PrincipalName *to )
{
    if( copy_NAME_TYPE( NAME_OF_MAIN_LOC_GLOB_P, &( from )->name_type, &( to )->name_type ) ) return ENOMEM;
    if((( &( to )->name_string )->val =
                m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( &( from )->name_string )->len * sizeof( *( &( to )->name_string )->val ) )
       ) == NULL && ( &( from )->name_string )->len != 0 )
        return ENOMEM;
    for(( &( to )->name_string )->len = 0; ( &( to )->name_string )->len < ( &( from )->name_string )->len; ( &( to )->name_string )->len++ ) {
        if( copy_general_string( NAME_OF_MAIN_LOC_GLOB_P, &( &( from )->name_string )->val[( &( to )->name_string )->len], &( &( to )->name_string )->val[( &( to )->name_string )->len] ) ) return ENOMEM;
    }
    return 0;
}
void
free_Principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, Principal *data )
{
    free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->name );
    free_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->realm );
}
int
copy_Principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const Principal *from, Principal *to )
{
    if( copy_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( from )->name, &( to )->name ) ) return ENOMEM;
    if( copy_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( from )->realm, &( to )->realm ) ) return ENOMEM;
    return 0;
}
int
encode_Realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const Realm *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_general_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_Realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, Realm *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_general_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_Realm( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_Realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, Realm *data )
{
    free_general_string( NAME_OF_MAIN_LOC_GLOB_P, data );
}
size_t
length_Realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const Realm *data )
{
    size_t ret = 0;
    ret += length_general_string( NAME_OF_MAIN_LOC_GLOB_P, data );
    return ret;
}
int
copy_Realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const Realm *from, Realm *to )
{
    if( copy_general_string( NAME_OF_MAIN_LOC_GLOB_P, from, to ) ) return ENOMEM;
    return 0;
}
int
decode_TGS_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, TGS_REP *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 13, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = decode_KDC_REP( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
        FORW;
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_TGS_REP( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_TGS_REP( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, TGS_REP *data )
{
    free_KDC_REP( NAME_OF_MAIN_LOC_GLOB_P, data );
}
int
encode_TGS_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const TGS_REQ *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_KDC_REQ( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 12, &l );
    BACK;
    *size = ret;
    return 0;
}
void
free_TGS_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, TGS_REQ *data )
{
    free_KDC_REQ( NAME_OF_MAIN_LOC_GLOB_P, data );
}
size_t
length_TGS_REQ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const TGS_REQ *data )
{
    size_t ret = 0;
    ret += length_KDC_REQ( NAME_OF_MAIN_LOC_GLOB_P, data );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
decode_TicketFlags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, TicketFlags *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, PRIM, UT_BitString,&reallen, &l );
    FORW;
    if( len < reallen )
        return ASN1_OVERRUN;
    p++;
    len--;
    reallen--;
    ret++;
    data->reserved = ( *p >> 7 ) & 1;
    data->forwardable = ( *p >> 6 ) & 1;
    data->forwarded = ( *p >> 5 ) & 1;
    data->proxiable = ( *p >> 4 ) & 1;
    data->proxy = ( *p >> 3 ) & 1;
    data->may_postdate = ( *p >> 2 ) & 1;
    data->postdated = ( *p >> 1 ) & 1;
    data->invalid = ( *p >> 0 ) & 1;
    p++;
    len--;
    reallen--;
    ret++;
    data->renewable = ( *p >> 7 ) & 1;
    data->initial = ( *p >> 6 ) & 1;
    data->pre_authent = ( *p >> 5 ) & 1;
    data->hw_authent = ( *p >> 4 ) & 1;
    data->transited_policy_checked = ( *p >> 3 ) & 1;
    data->ok_as_delegate = ( *p >> 2 ) & 1;
    data->anonymous = ( *p >> 1 ) & 1;
    p += reallen;
    len -= reallen;
    ret += reallen;
    if( size ) *size = ret;
    return 0;
    fail:
    free_TicketFlags( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_TicketFlags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, TicketFlags *data )
{
}
unsigned TicketFlags2int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, TicketFlags f )
{
    unsigned r = 0;
    if( f.reserved ) r |= ( 1U << 0 );
    if( f.forwardable ) r |= ( 1U << 1 );
    if( f.forwarded ) r |= ( 1U << 2 );
    if( f.proxiable ) r |= ( 1U << 3 );
    if( f.proxy ) r |= ( 1U << 4 );
    if( f.may_postdate ) r |= ( 1U << 5 );
    if( f.postdated ) r |= ( 1U << 6 );
    if( f.invalid ) r |= ( 1U << 7 );
    if( f.renewable ) r |= ( 1U << 8 );
    if( f.initial ) r |= ( 1U << 9 );
    if( f.pre_authent ) r |= ( 1U << 10 );
    if( f.hw_authent ) r |= ( 1U << 11 );
    if( f.transited_policy_checked ) r |= ( 1U << 12 );
    if( f.ok_as_delegate ) r |= ( 1U << 13 );
    if( f.anonymous ) r |= ( 1U << 14 );
    return r;
}
int
encode_Ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const Ticket *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    {
        int oldret = ret;
        ret = 0;
        e = encode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->enc_part, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->sname, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->realm, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l );
        BACK;
        ret += oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        e = encode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->tkt_vno, &l );
        BACK;
        e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l );
        BACK;
        ret += oldret;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l );
    BACK;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ret, ASN1_C_APPL, CONS, 1, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_Ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, Ticket *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_APPL, CONS, 1, &reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
        FORW;
        {
            int dce_fix;
            if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
                return ASN1_BAD_FORMAT;
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->tkt_vno, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_Realm( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->realm, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 2, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->sname, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            {
                size_t newlen, oldlen;
                e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 3, &l );
                if( e )
                    return e;
                else {
                    p += l;
                    len -= l;
                    ret += l;
                    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                    FORW;
                    {
                        int dce_fix;
                        oldlen = len;
                        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                        e = decode_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->enc_part, &l );
                        FORW;
                        if( dce_fix ) {
                            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                            FORW;
                        } else
                            len = oldlen - newlen;
                    }
                }
            }
            if( dce_fix ) {
                e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                FORW;
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_Ticket( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_Ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, Ticket *data )
{
    free_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->realm );
    free_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->sname );
    free_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( data )->enc_part );
}
size_t
length_Ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const Ticket *data )
{
    size_t ret = 0;
    {
        int oldret = ret;
        ret = 0;
        ret += length_integer( NAME_OF_MAIN_LOC_GLOB_P, &( data )->tkt_vno );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( data )->realm );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( data )->sname );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    {
        int oldret = ret;
        ret = 0;
        ret += length_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( data )->enc_part );
        ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret ) + oldret;
    }
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    ret += 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, ret );
    return ret;
}
int
copy_Ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const Ticket *from, Ticket *to )
{
    *( &( to )->tkt_vno ) = *( &( from )->tkt_vno );
    if( copy_Realm( NAME_OF_MAIN_LOC_GLOB_P, &( from )->realm, &( to )->realm ) ) return ENOMEM;
    if( copy_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &( from )->sname, &( to )->sname ) ) return ENOMEM;
    if( copy_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &( from )->enc_part, &( to )->enc_part ) ) return ENOMEM;
    return 0;
}
int
decode_TransitedEncoding( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, TransitedEncoding *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, CONS, UT_Sequence,&reallen, &l );
    FORW;
    {
        int dce_fix;
        if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, reallen, &len ) ) < 0 )
            return ASN1_BAD_FORMAT;
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 0, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_integer( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->tr_type, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        {
            size_t newlen, oldlen;
            e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_CONTEXT, CONS, 1, &l );
            if( e )
                return e;
            else {
                p += l;
                len -= l;
                ret += l;
                e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &newlen, &l );
                FORW;
                {
                    int dce_fix;
                    oldlen = len;
                    if(( dce_fix = fix_dce( NAME_OF_MAIN_LOC_GLOB_P, newlen, &len ) ) < 0 )return ASN1_BAD_FORMAT;
                    e = decode_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &( data )->contents, &l );
                    FORW;
                    if( dce_fix ) {
                        e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
                        FORW;
                    } else
                        len = oldlen - newlen;
                }
            }
        }
        if( dce_fix ) {
            e = der_match_tag_and_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, ( Der_class )0, ( Der_type )0, 0, &reallen, &l );
            FORW;
        }
    }
    if( size ) *size = ret;
    return 0;
    fail:
    free_TransitedEncoding( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_TransitedEncoding( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, TransitedEncoding *data )
{
    free_octet_string( NAME_OF_MAIN_LOC_GLOB_P, &( data )->contents );
}
int
encode_UNSIGNED( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const UNSIGNED *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int i, e;
    i = 0;
    e = encode_unsigned( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    BACK;
    *size = ret;
    return 0;
}
int
decode_UNSIGNED( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len, UNSIGNED *data, size_t *size )
{
    size_t ret = 0, reallen;
    size_t l;
    int e;
    memset( data, 0, sizeof( *data ) );
    reallen = 0;
    e = decode_unsigned( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    FORW;
    if( size ) *size = ret;
    return 0;
    fail:
    free_UNSIGNED( NAME_OF_MAIN_LOC_GLOB_P, data );
    return e;
}
void
free_UNSIGNED( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, UNSIGNED *data )
{
}
size_t
length_UNSIGNED( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const UNSIGNED *data )
{
    size_t ret = 0;
    ret += length_unsigned( NAME_OF_MAIN_LOC_GLOB_P, data );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_init( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_auth_context *auth_context )
{
    krb5_auth_context p;
    ALLOC( p, 1 );
    if( !p ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","auth_context.c 1495" )
        ;
        return ENOMEM;
    }
    memset( p, 0, sizeof( *p ) );
    ALLOC( p->authenticator, 1 );
    if( !p->authenticator ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","auth_context.c 1496" )
        ;
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ENOMEM;
    }
    memset( p->authenticator, 0, sizeof( *p->authenticator ) );
    p->flags = KRB5_AUTH_CONTEXT_DO_TIME;
    p->local_address  = NULL;
    p->remote_address = NULL;
    p->local_port     = 0;
    p->remote_port    = 0;
    p->keytype        = KEYTYPE_NULL;
    p->cksumtype      = CKSUMTYPE_NONE;
    *auth_context     = p;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_auth_context auth_context )
{
    if( auth_context != NULL ) {
        krb5_free_authenticator(	NAME_OF_MAIN_LOC_GLOB_P, context, &auth_context->authenticator );
        if( auth_context->local_address ) {
            free_HostAddress(	NAME_OF_MAIN_LOC_GLOB_P, auth_context->local_address );
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, auth_context->local_address )
            ;
        }
        if( auth_context->remote_address ) {
            free_HostAddress(	NAME_OF_MAIN_LOC_GLOB_P, auth_context->remote_address );
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, auth_context->remote_address )
            ;
        }
        krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->keyblock );
        krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->remote_subkey );
        krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->local_subkey );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, auth_context )
        ;
    }
    return 0;
}
static krb5_error_code
copy_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
          krb5_keyblock *in,
          krb5_keyblock **out )
{
    if( in )
        return krb5_copy_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, in, out );
    *out = NULL;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_getkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      krb5_auth_context auth_context,
                      krb5_keyblock **keyblock )
{
    return copy_key( NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->keyblock, keyblock );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_getlocalsubkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                              krb5_auth_context auth_context,
                              krb5_keyblock **keyblock )
{
    return copy_key( NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->local_subkey, keyblock );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_getremotesubkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                               krb5_auth_context auth_context,
                               krb5_keyblock **keyblock )
{
    return copy_key( NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->remote_subkey, keyblock );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_generatelocalsubkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                   krb5_auth_context auth_context,
                                   krb5_keyblock *key )
{
    krb5_error_code ret;
    krb5_keyblock *subkey;
    ret = krb5_generate_subkey_extended( NAME_OF_MAIN_LOC_GLOB_P, context, key,
                                         auth_context->keytype,
                                         &subkey );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( auth_context->local_subkey )
        krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->local_subkey );
    auth_context->local_subkey = subkey;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_setremotesubkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                               krb5_auth_context auth_context,
                               krb5_keyblock *keyblock )
{
    if( auth_context->remote_subkey )
        krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->remote_subkey );
    return copy_key( NAME_OF_MAIN_LOC_GLOB_P, context, keyblock, &auth_context->remote_subkey );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_getlocalseqnumber( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                 krb5_auth_context auth_context,
                                 int32_t *seqnumber )
{
    *seqnumber = auth_context->local_seqnumber;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_setlocalseqnumber( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                 krb5_auth_context auth_context,
                                 int32_t seqnumber )
{
    auth_context->local_seqnumber = seqnumber;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_setremoteseqnumber( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                  krb5_auth_context auth_context,
                                  int32_t seqnumber )
{
    auth_context->remote_seqnumber = seqnumber;
    return 0;
}
void KRB5_LIB_FUNCTION
krb5_free_authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                         krb5_authenticator *authenticator )
{
    free_Authenticator( NAME_OF_MAIN_LOC_GLOB_P, *authenticator );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *authenticator )
    ;
    *authenticator = NULL;
}
#ifndef HAVE_BSWAP32
unsigned int ROKEN_LIB_FUNCTION
bswap32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned int val )
{
    return ( val & 0xff ) << 24 |
           ( val & 0xff00 ) << 8 |
           ( val & 0xff0000 ) >> 8 |
           ( val & 0xff000000 ) >> 24;
}
#endif
#ifndef HAVE_BSWAP16
unsigned short ROKEN_LIB_FUNCTION
bswap16( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned short val )
{
    return ( val & 0xff ) << 8 |
           ( val & 0xff00 ) >> 8;
}
#endif
krb5_error_code KRB5_LIB_FUNCTION
krb5_build_ap_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_enctype enctype,
                   krb5_creds *cred,
                   krb5_flags ap_options,
                   krb5_data authenticator,
                   krb5_data *retdata )
{
    krb5_error_code ret = 0;
    AP_REQ ap;
    Ticket t;
    size_t len;
    ap.pvno = 5;
    ap.msg_type = krb_ap_req;
    memset( &ap.ap_options, 0, sizeof( ap.ap_options ) );
    ap.ap_options.use_session_key = ( ap_options & AP_OPTS_USE_SESSION_KEY ) > 0;
    ap.ap_options.mutual_required = ( ap_options & AP_OPTS_MUTUAL_REQUIRED ) > 0;
    ap.ticket.tkt_vno = 5;
    copy_Realm( NAME_OF_MAIN_LOC_GLOB_P, &cred->server->realm, &ap.ticket.realm );
    copy_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &cred->server->name, &ap.ticket.sname );
    decode_Ticket( NAME_OF_MAIN_LOC_GLOB_P, cred->ticket.data, cred->ticket.length, &t, &len );
    copy_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &t.enc_part, &ap.ticket.enc_part );
    free_Ticket( NAME_OF_MAIN_LOC_GLOB_P, &t );
    ap.authenticator.etype = enctype;
    ap.authenticator.kvno  = NULL;
    ap.authenticator.cipher = authenticator;
    ASN1_MALLOC_ENCODE( AP_REQ, retdata->data, retdata->length,
                        &ap, &len, ret );
    //StSch Trace Point 6001
    if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
        void* a_temp_memory=0;
        struct dsd_memory_traces* adsl_trace;
        unsigned int un_kvno=0;
        unsigned int un_akvno=0;
        int in_ap_opt=0;
        char* achl_sname=( char* )0;
        char* achl_trace_format="AP-REQ: pvno=%i, msg-type=%i, ap-opt=%i, tkt-vno=%i, realm=%s, sname=%s, "
                                "etype=%i, kvno=%u, a-etype=%i, a-kvno=%u";
        m_aux_stor_start( &a_temp_memory );
        adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
        if( ap.ap_options.use_session_key ) {
            in_ap_opt+=1;
        }
        if( ap.ap_options.mutual_required ) {
            in_ap_opt+=2;
        }
        if( ap.ticket.enc_part.kvno!=NULL ) {
            un_kvno=*ap.ticket.enc_part.kvno;
        }
        if( ap.authenticator.kvno!=NULL ) {
            un_akvno=*ap.authenticator.kvno;
        }
        achl_sname=m_krb5_principalname2string( &a_temp_memory, achl_sname, &ap.ticket.sname );
        m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',6001,
                     adsl_trace,&a_temp_memory, achl_trace_format, ap.pvno, ap.msg_type, in_ap_opt,
                     ap.ticket.tkt_vno, ap.ticket.realm, achl_sname, ap.ticket.enc_part.etype,
                     un_kvno, ap.authenticator.etype, un_akvno );
        m_aux_stor_end( &a_temp_memory );
    }
    if( ret == 0 && retdata->length != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"build_ap_req.c 10030: internal error in ASN.1 encoder" );
    free_AP_REQ( NAME_OF_MAIN_LOC_GLOB_P, &ap );
    return ret;
}
static krb5_error_code
make_etypelist( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_authdata **auth_data )
{
    EtypeList etypes;
    krb5_error_code ret;
    krb5_authdata ad;
    u_char *buf;
    size_t len;
    size_t buf_size;
    ret = krb5_init_etype( NAME_OF_MAIN_LOC_GLOB_P, context, &etypes.len, &etypes.val, NULL );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ASN1_MALLOC_ENCODE( EtypeList, buf, buf_size, &etypes, &len, ret );
    if( ret ) {
        //StSch Trace Point
        free_EtypeList(	NAME_OF_MAIN_LOC_GLOB_P, &etypes );
        return ret;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"build_auth.c 10023: internal error in ASN.1 encoder" );
    free_EtypeList( NAME_OF_MAIN_LOC_GLOB_P, &etypes );
    ALLOC_SEQ( &ad, 1 );
    if( ad.val == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","build_auth.c 1257" )
        ;
        return ENOMEM;
    }
    ad.val[0].ad_type = KRB5_AUTHDATA_GSS_API_ETYPE_NEGOTIATION;
    ad.val[0].ad_data.length = len;
    ad.val[0].ad_data.data = buf;
    ASN1_MALLOC_ENCODE( AD_IF_RELEVANT, buf, buf_size, &ad, &len, ret );
    if( ret ) {
        //StSch Trace Point
        free_AuthorizationData(	NAME_OF_MAIN_LOC_GLOB_P, &ad );
        return ret;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"build_auth.c 10024: internal error in ASN.1 encoder" );
    free_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, &ad );
    ALLOC( *auth_data, 1 );
    if( *auth_data == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","build_auth.c 1258" )
        ;
        return ENOMEM;
    }
    ALLOC_SEQ( *auth_data, 1 );
    if(( *auth_data )->val == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","build_auth.c 1259" )
        ;
        return ENOMEM;
    }
    ( *auth_data )->val[0].ad_type = KRB5_AUTHDATA_IF_RELEVANT;
    ( *auth_data )->val[0].ad_data.length = len;
    ( *auth_data )->val[0].ad_data.data = buf;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_build_authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          krb5_auth_context auth_context,
                          krb5_enctype enctype,
                          krb5_creds *cred,
                          Checksum *cksum,
                          Authenticator **auth_result,
                          krb5_data *result,
                          krb5_key_usage usage )
{
    Authenticator *auth;
    u_char *buf = NULL;
    size_t buf_size;
    size_t len;
    krb5_error_code ret;
    krb5_crypto crypto;
    auth =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *auth ) )
        ;
    if( auth == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","build_auth.c 1260" )
        ;
        return ENOMEM;
    }
    memset( auth, 0, sizeof( *auth ) );
    auth->authenticator_vno = 5;
    copy_Realm( NAME_OF_MAIN_LOC_GLOB_P, &cred->client->realm, &auth->crealm );
    copy_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &cred->client->name, &auth->cname );
    krb5_us_timeofday( NAME_OF_MAIN_LOC_GLOB_P, context, &auth->ctime, &auth->cusec );
    ret = krb5_auth_con_getlocalsubkey( NAME_OF_MAIN_LOC_GLOB_P, context, auth_context, &auth->subkey );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE ) {
        if( auth_context->local_seqnumber == 0 )
            krb5_generate_seq_number(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                        &cred->session,
                                        &auth_context->local_seqnumber );
        ALLOC( auth->seq_number, 1 );
        if( auth->seq_number == NULL ) {
            //StSch Trace Point
            ret = ENOMEM;
            goto fail;
        }
        *auth->seq_number = auth_context->local_seqnumber;
    } else
        auth->seq_number = NULL;
    auth->authorization_data = NULL;
    auth->cksum = cksum;
    if( cksum != NULL && cksum->cksumtype == CKSUMTYPE_GSSAPI ) {
        /*
         * This is not GSS-API specific, we only enable it for
         * GSS for now
         */
        ret = make_etypelist(	NAME_OF_MAIN_LOC_GLOB_P, context, &auth->authorization_data );
        if( ret ) {
            //StSch Trace Point
            goto fail;
        }
    }
    if( auth_context ) {
        auth_context->authenticator->ctime = auth->ctime;
        auth_context->authenticator->cusec = auth->cusec;
    }
    ASN1_MALLOC_ENCODE( Authenticator, buf, buf_size, auth, &len, ret );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"build_auth.c 10025: internal error in ASN.1 encoder" );
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, &cred->session, enctype, &crypto );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    ret = krb5_encrypt( NAME_OF_MAIN_LOC_GLOB_P, context,
                        crypto,
                        usage ,
                        buf + buf_size - len,
                        len,
                        result );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    if( auth_result )
        *auth_result = auth;
    else {
        auth->cksum = NULL;
        free_Authenticator(	NAME_OF_MAIN_LOC_GLOB_P, auth );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, auth )
        ;
    }
    return ret;
    fail:
    free_Authenticator( NAME_OF_MAIN_LOC_GLOB_P, auth );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, auth )
    ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    return ret;
}
/*
 * Add a new ccache type with operations `ops', overwriting any
 * existing one if `override'.
 * Return an error code or 0.
 */
/*
 * Allocate memory for a new ccache in `id' with operations `ops'
 * and name `residual'.
 * Return 0 or an error code.
 */
static krb5_error_code
allocate_ccache( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 const krb5_cc_ops *ops,
                 const char *residual,
                 krb5_ccache *id )
{
    krb5_error_code ret;
    krb5_ccache p;
    p =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *p ) )
        ;
    if( p == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","cache.c 1547" )
        ;
        return KRB5_CC_NOMEM;
    }
    p->ops = ops;
    *id = p;
    ret = p->ops->resolve( NAME_OF_MAIN_LOC_GLOB_P, context, id, residual );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
    }
    return ret;
}
/*
 * Find and allocate a ccache in `id' from the specification in `residual'.
 * If the ccache name doesn't contain any colon, interpret it as a file name.
 * Return 0 or an error code.
 */

const krb5_cc_ops krb5_fcc_ops = {
    "FILE",
    fcc_get_name,
    fcc_resolve,
    fcc_gen_new,
    fcc_initialize,
    fcc_destroy,
    fcc_close,
    fcc_store_cred,
    (( void * )0 ),
    fcc_get_principal,
    fcc_get_first,
    fcc_get_next,
    fcc_end_get,
    fcc_remove_cred,
    fcc_set_flags,
    fcc_get_version
};
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_resolve( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 const char *name,
                 krb5_ccache *id )
{
    return allocate_ccache( NAME_OF_MAIN_LOC_GLOB_P, context, & krb5_fcc_ops, name, id );
}
/*
 * Generate a new ccache of type `ops' in `id'.
 * Return 0 or an error code.
 */
/*
 * Generates a new unique ccache of `type` in `id'. If `type' is NULL,
 * the library chooses the default credential cache type. The supplied
 * `hint' (that can be NULL) is a string that the credential cache
 * type can use to base the name of the credential on, this is to make
 * its easier for the user to differentiate the credentials.
 *
 *  Returns 0 or an error code.
 */
/*
 * Return the name of the ccache `id'
 */
/*
 * Return the type of the ccache `id'.
 */
/*
 * Return krb5_cc_ops of a the ccache `id'.
 */
/*
 * Expand variables in `str' into `res'
 */
/*
 * Set the default cc name for `context' to `name'.
 */
/*
 * Return a pointer to a context static string containing the default
 * ccache name.
 */
/*
 * Open the default ccache in `id'.
 * Return 0 or an error code.
 */
/*
 * Create a new ccache in `id' for `primary_principal'.
 * Return 0 or an error code.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_initialize( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_ccache id,
                    krb5_principal primary_principal )
{
    return id->ops->init( NAME_OF_MAIN_LOC_GLOB_P, context, id, primary_principal );
}
/*
 * Remove the ccache `id'.
 * Return 0 or an error code.
 */
/*
 * Stop using the ccache `id' and free the related resources.
 * Return 0 or an error code.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_close( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               krb5_ccache id )
{
    krb5_error_code ret;
    ret = id->ops->close( NAME_OF_MAIN_LOC_GLOB_P, context, id );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, id )
    ;
    return ret;
}
/*
 * Store `creds' in the ccache `id'.
 * Return 0 or an error code.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_store_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_ccache id,
                    krb5_creds *creds )
{
    return id->ops->store( NAME_OF_MAIN_LOC_GLOB_P, context, id, creds );
}
/*
 * Retrieve the credential identified by `mcreds' (and `whichfields')
 * from `id' in `creds'.
 * Return 0 or an error code.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_retrieve_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       krb5_ccache id,
                       krb5_flags whichfields,
                       const krb5_creds *mcreds,
                       krb5_creds *creds )
{
    krb5_error_code ret;
    krb5_cc_cursor cursor;
    if( id->ops->retrieve != NULL ) {
        return id->ops->retrieve(	NAME_OF_MAIN_LOC_GLOB_P, context, id, whichfields,
                                    mcreds, creds );
    }
    krb5_cc_start_seq_get( NAME_OF_MAIN_LOC_GLOB_P, context, id, &cursor );
    while(( ret = krb5_cc_next_cred( NAME_OF_MAIN_LOC_GLOB_P, context, id, &cursor, creds ) ) == 0 ) {
        if( krb5_compare_creds(	NAME_OF_MAIN_LOC_GLOB_P, context, whichfields, mcreds, creds ) ) {
            ret = 0;
            break;
        }
        krb5_free_cred_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, creds );
    }
    krb5_cc_end_seq_get( NAME_OF_MAIN_LOC_GLOB_P, context, id, &cursor );
    return ret;
}
/*
 * Return the principal of `id' in `principal'.
 * Return 0 or an error code.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_get_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       krb5_ccache id,
                       krb5_principal *principal )
{
    return id->ops->get_princ( NAME_OF_MAIN_LOC_GLOB_P, context, id, principal );
}
/*
 * Start iterating over `id', `cursor' is initialized to the
 * beginning.
 * Return 0 or an error code.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_start_seq_get( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       const krb5_ccache id,
                       krb5_cc_cursor *cursor )
{
    return id->ops->get_first( NAME_OF_MAIN_LOC_GLOB_P, context, id, cursor );
}
/*
 * Retrieve the next cred pointed to by (`id', `cursor') in `creds'
 * and advance `cursor'.
 * Return 0 or an error code.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_next_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   const krb5_ccache id,
                   krb5_cc_cursor *cursor,
                   krb5_creds *creds )
{
    return id->ops->get_next( NAME_OF_MAIN_LOC_GLOB_P, context, id, cursor, creds );
}
/*
 * Destroy the cursor `cursor'.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_end_seq_get( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     const krb5_ccache id,
                     krb5_cc_cursor *cursor )
{
    return id->ops->end_get( NAME_OF_MAIN_LOC_GLOB_P, context, id, cursor );
}
/*
 * Remove the credential identified by `cred', `which' from `id'.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_cc_remove_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     krb5_ccache id,
                     krb5_flags which,
                     krb5_creds *cred )
{
    if( id->ops->remove_cred == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"ccache  does not support remove_cred","cache.c 1557" )
        ;
        return EACCES;
    }
    return ( *id->ops->remove_cred )( NAME_OF_MAIN_LOC_GLOB_P, context, id, which, cred );
}
/*
 * Set the flags of `id' to `flags'.
 */

/*
 * Copy the contents of `from' to `to'.
 */
/*
 * Return the version of `id'.
 */
/*
 * Clear `mcreds' so it can be used with krb5_cc_retrieve_cred
 */
void KRB5_LIB_FUNCTION
krb5_cc_clear_mcred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_creds *mcred )
{
    memset( mcred, 0, sizeof( *mcred ) );
}
/*
 * Get the cc ops that is registered in `context' to handle the
 * `prefix'. Returns NULL if ops not found.
 */
/*
 * Implementation of draft-ietf-krb-wg-gssapi-cfx-06.txt
 */
static krb5_error_code
wrap_length_cfx( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_crypto crypto,
                 int conf_req_flag,
                 size_t input_length,
                 size_t *output_length,
                 size_t *cksumsize,
                 u_int16_t *padlength )
{
    krb5_error_code ret;
    krb5_cksumtype type;
    *output_length = sizeof( gss_cfx_wrap_token_desc );
    *padlength = 0;
    ret = krb5_crypto_get_checksum_type( NAME_OF_MAIN_LOC_GLOB_P,                                        NAME_OF_MAIN_LOC_GLOB_P->
                                         gssapi_krb5_context, crypto, &type );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_checksumsize( NAME_OF_MAIN_LOC_GLOB_P,                            NAME_OF_MAIN_LOC_GLOB_P->
                             gssapi_krb5_context, type, cksumsize );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( conf_req_flag ) {
        size_t padsize;
        input_length += sizeof( gss_cfx_wrap_token_desc );
        ret = krb5_crypto_getpadsize(	NAME_OF_MAIN_LOC_GLOB_P,                             	NAME_OF_MAIN_LOC_GLOB_P->
                                        gssapi_krb5_context, crypto, &padsize );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
        if( padsize > 1 ) {
            *padlength = padsize - ( input_length % padsize );
        }
        input_length += *padlength;
        *output_length += krb5_get_wrapped_length(	NAME_OF_MAIN_LOC_GLOB_P,                                          	NAME_OF_MAIN_LOC_GLOB_P->
                          gssapi_krb5_context,
                          crypto, input_length );
    } else {
        *output_length += input_length + *cksumsize;
    }
    if( !( *output_length > input_length ) ) {
        //StSch Trace Point
        m_end_exit_abort_hl( NAME_OF_MAIN_LOC_GLOB_P, 'a',0 );
    }
    return 0;
}
/*
 * Rotate "rrc" bytes to the front or back
 */
static krb5_error_code
rrc_rotate( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, void *data, size_t len, u_int16_t rrc, krb5_boolean unrotate )
{
    u_char *tmp;
    size_t left;
    char buf[256];
    if( len == 0 )
        return 0;
    rrc %= len;
    if( rrc == 0 )
        return 0;
    left = len - rrc;
    if( rrc <= sizeof( buf ) ) {
        tmp = buf;
    } else {
        tmp =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, rrc )
            ;
        if( tmp == NULL )
            return ENOMEM;
    }
    if( unrotate ) {
        memcpy( tmp, data, rrc );
        memmove( data, ( u_char * )data + rrc, left );
        memcpy(( u_char * )data + left, tmp, rrc );
    } else {
        memcpy( tmp, ( u_char * )data + left, rrc );
        memmove(( u_char * )data + rrc, data, left );
        memcpy( data, tmp, rrc );
    }
    if( rrc > sizeof( buf ) )
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tmp )
        ;
    return 0;
}
OM_uint32 _gssapi_wrap_cfx( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 *minor_status,
                            const gss_ctx_id_t context_handle,
                            int conf_req_flag,
                            gss_qop_t qop_req,
                            const gss_buffer_t input_message_buffer,
                            int *conf_state,
                            gss_buffer_t output_message_buffer,
                            krb5_keyblock *key )
{
    krb5_crypto crypto;
    gss_cfx_wrap_token token;
    krb5_error_code ret;
    unsigned usage;
    krb5_data cipher;
    size_t wrapped_len, cksumsize;
    u_int16_t padlength, rrc = 0;
    OM_uint32 seq_number;
    u_char *p;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P,                           NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, key, 0, &crypto );
    if( ret != 0 ) {
        gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    ret = wrap_length_cfx( NAME_OF_MAIN_LOC_GLOB_P, crypto, conf_req_flag,
                           input_message_buffer->length,
                           &wrapped_len, &cksumsize, &padlength );
    if( ret != 0 ) {
        gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
        *minor_status = ret;
        krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                    	NAME_OF_MAIN_LOC_GLOB_P->
                                gssapi_krb5_context, crypto );
        return GSS_S_FAILURE;
    }
    rrc = ( conf_req_flag ? sizeof( *token ) : 0 ) + ( u_int16_t )cksumsize;
    output_message_buffer->length = wrapped_len;
    output_message_buffer->value =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, output_message_buffer->length )
        ;
    if( output_message_buffer->value == NULL ) {
        *minor_status = ENOMEM;
        krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                    	NAME_OF_MAIN_LOC_GLOB_P->
                                gssapi_krb5_context, crypto );
        return GSS_S_FAILURE;
    }
    p = output_message_buffer->value;
    token = ( gss_cfx_wrap_token )p;
    token->TOK_ID[0] = 0x05;
    token->TOK_ID[1] = 0x04;
    token->Flags     = 0;
    token->Filler    = 0xFF;
    if(( context_handle->more_flags & LOCAL ) == 0 )
        token->Flags |= CFXSentByAcceptor;
    if( context_handle->more_flags & ACCEPTOR_SUBKEY )
        token->Flags |= CFXAcceptorSubkey;
    if( conf_req_flag ) {
        /*
         * In Wrap tokens with confidentiality, the EC field is
         * used to encode the size (in bytes) of the random filler.
         */
        token->Flags |= CFXSealed;
        token->EC[0] = ( padlength >> 8 ) & 0xFF;
        token->EC[1] = ( padlength >> 0 ) & 0xFF;
    } else {
        /*
         * In Wrap tokens without confidentiality, the EC field is
         * used to encode the size (in bytes) of the trailing
         * checksum.
         *
         * This is not used in the checksum calcuation itself,
         * because the checksum length could potentially vary
         * depending on the data length.
         */
        token->EC[0] = 0;
        token->EC[1] = 0;
    }
    /*
     * In Wrap tokens that provide for confidentiality, the RRC
     * field in the header contains the hex value 00 00 before
     * encryption.
     *
     * In Wrap tokens that do not provide for confidentiality,
     * both the EC and RRC fields in the appended checksum
     * contain the hex value 00 00 for the purpose of calculating
     * the checksum.
     */
    token->RRC[0] = 0;
    token->RRC[1] = 0;
    krb5_auth_con_getlocalseqnumber( NAME_OF_MAIN_LOC_GLOB_P,                                    NAME_OF_MAIN_LOC_GLOB_P->
                                     gssapi_krb5_context,
                                     context_handle->auth_context,
                                     &seq_number );
    gssapi_encode_be_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, 0,          &token->SND_SEQ[0] );
    gssapi_encode_be_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, seq_number, &token->SND_SEQ[4] );
    krb5_auth_con_setlocalseqnumber( NAME_OF_MAIN_LOC_GLOB_P,                                    NAME_OF_MAIN_LOC_GLOB_P->
                                     gssapi_krb5_context,
                                     context_handle->auth_context,
                                     ++seq_number );
    /*
     * If confidentiality is requested, the token header is
     * appended to the plaintext before encryption; the resulting
     * token is {"header" | encrypt(plaintext | pad | "header")}.
     *
     * If no confidentiality is requested, the checksum is
     * calculated over the plaintext concatenated with the
     * token header.
     */
    if( context_handle->more_flags & LOCAL ) {
        usage = KRB5_KU_USAGE_INITIATOR_SEAL;
    } else {
        usage = KRB5_KU_USAGE_ACCEPTOR_SEAL;
    }
    if( conf_req_flag ) {
        /*
         * Any necessary padding is added here to ensure that the
         * encrypted token header is always at the end of the
         * ciphertext.
         *
         * The specification does not require that the padding
         * bytes are initialized.
         */
        p += sizeof( *token );
        memcpy( p, input_message_buffer->value, input_message_buffer->length );
        memset( p + input_message_buffer->length, 0xFF, padlength );
        memcpy( p + input_message_buffer->length + padlength,
                token, sizeof( *token ) );
        ret = krb5_encrypt(	NAME_OF_MAIN_LOC_GLOB_P,                   	NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, crypto,
                            usage, p,
                            input_message_buffer->length + padlength +
                            sizeof( *token ),
                            &cipher );
        if( ret != 0 ) {
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            *minor_status = ret;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
            return GSS_S_FAILURE;
        }
        if( !( sizeof( *token ) + cipher.length == wrapped_len ) ) {
            //StSch Trace Point
            m_end_exit_abort_hl(	NAME_OF_MAIN_LOC_GLOB_P, 'a',0 );
        }
        token->RRC[0] = ( rrc >> 8 ) & 0xFF;
        token->RRC[1] = ( rrc >> 0 ) & 0xFF;
        ret = rrc_rotate(	NAME_OF_MAIN_LOC_GLOB_P, cipher.data, cipher.length, rrc, FALSE );
        if( ret != 0 ) {
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            *minor_status = ret;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
            return GSS_S_FAILURE;
        }
        memcpy( p, cipher.data, cipher.length );
        krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &cipher );
    } else {
        char *buf;
        Checksum cksum;
        buf =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, input_message_buffer->length + sizeof( *token ) )
            ;
        if( buf == NULL ) {
            *minor_status = ENOMEM;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
            return GSS_S_FAILURE;
        }
        memcpy( buf, input_message_buffer->value, input_message_buffer->length );
        memcpy( buf + input_message_buffer->length, token, sizeof( *token ) );
        ret = krb5_create_checksum(	NAME_OF_MAIN_LOC_GLOB_P,                           	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto,
                                    usage, 0, buf,
                                    input_message_buffer->length +
                                    sizeof( *token ),
                                    &cksum );
        if( ret != 0 ) {
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            *minor_status = ret;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
            ;
            return GSS_S_FAILURE;
        }
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        if( !( cksum.checksum.length == cksumsize ) ) {
            //StSch Trace Point
            m_end_exit_abort_hl(	NAME_OF_MAIN_LOC_GLOB_P, 'a',0 );
        }
        token->EC[0] = ( cksum.checksum.length >> 8 ) & 0xFF;
        token->EC[1] = ( cksum.checksum.length >> 0 ) & 0xFF;
        token->RRC[0] = ( rrc >> 8 ) & 0xFF;
        token->RRC[1] = ( rrc >> 0 ) & 0xFF;
        p += sizeof( *token );
        memcpy( p, input_message_buffer->value, input_message_buffer->length );
        memcpy( p + input_message_buffer->length,
                cksum.checksum.data, cksum.checksum.length );
        ret = rrc_rotate(	NAME_OF_MAIN_LOC_GLOB_P, p,
                            input_message_buffer->length + cksum.checksum.length, rrc, FALSE );
        if( ret != 0 ) {
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            *minor_status = ret;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
            free_Checksum(	NAME_OF_MAIN_LOC_GLOB_P, &cksum );
            return GSS_S_FAILURE;
        }
        free_Checksum(	NAME_OF_MAIN_LOC_GLOB_P, &cksum );
    }
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P,                        NAME_OF_MAIN_LOC_GLOB_P->
                         gssapi_krb5_context, crypto );
    if( conf_state != NULL ) {
        *conf_state = conf_req_flag;
    }
    *minor_status = 0;
    return GSS_S_COMPLETE;
}
OM_uint32 _gssapi_unwrap_cfx( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 *minor_status,
                              const gss_ctx_id_t context_handle,
                              const gss_buffer_t input_message_buffer,
                              gss_buffer_t output_message_buffer,
                              int *conf_state,
                              gss_qop_t *qop_state,
                              krb5_keyblock *key )
{
    krb5_crypto crypto;
    gss_cfx_wrap_token token;
    u_char token_flags;
    krb5_error_code ret;
    unsigned usage;
    krb5_data data;
    u_int16_t ec, rrc;
    OM_uint32 seq_number_lo, seq_number_hi;
    size_t len;
    u_char *p;
    *minor_status = 0;
    if( input_message_buffer->length < sizeof( *token ) ) {
        return GSS_S_DEFECTIVE_TOKEN;
    }
    p = input_message_buffer->value;
    token = ( gss_cfx_wrap_token )p;
    if( token->TOK_ID[0] != 0x05 || token->TOK_ID[1] != 0x04 ) {
        return GSS_S_DEFECTIVE_TOKEN;
    }
    token_flags = token->Flags &
                  ( CFXSentByAcceptor | CFXSealed | CFXAcceptorSubkey );
    if( token_flags & CFXSentByAcceptor ) {
        if(( context_handle->more_flags & LOCAL ) == 0 )
            return GSS_S_DEFECTIVE_TOKEN;
    }
    if( token->Filler != 0xFF ) {
        return GSS_S_DEFECTIVE_TOKEN;
    }
    if( conf_state != NULL ) {
        *conf_state = ( token_flags & CFXSealed ) ? 1 : 0;
    }
    ec  = ( token->EC[0]  << 8 ) | token->EC[1];
    rrc = ( token->RRC[0] << 8 ) | token->RRC[1];
    /*
     * Check sequence number
     */
    gssapi_decode_be_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, &token->SND_SEQ[0], &seq_number_hi );
    gssapi_decode_be_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, &token->SND_SEQ[4], &seq_number_lo );
    if( seq_number_hi ) {
        *minor_status = ERANGE;
        return GSS_S_UNSEQ_TOKEN;
    }
    ret = _gssapi_msg_order_check( NAME_OF_MAIN_LOC_GLOB_P, context_handle->order, seq_number_lo );
    if( ret != 0 ) {
        *minor_status = 0;
        gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
        return ret;
    }
    /*
     * Decrypt and/or verify checksum
     */
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P,                           NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, key, 0, &crypto );
    if( ret != 0 ) {
        gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    if( context_handle->more_flags & LOCAL ) {
        usage = KRB5_KU_USAGE_ACCEPTOR_SEAL;
    } else {
        usage = KRB5_KU_USAGE_INITIATOR_SEAL;
    }
    p += sizeof( *token );
    len = input_message_buffer->length;
    len -= ( p - ( u_char * )input_message_buffer->value );
    *minor_status = rrc_rotate( NAME_OF_MAIN_LOC_GLOB_P, p, len, rrc, TRUE );
    if( *minor_status != 0 ) {
        krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                    	NAME_OF_MAIN_LOC_GLOB_P->
                                gssapi_krb5_context, crypto );
        return GSS_S_FAILURE;
    }
    if( token_flags & CFXSealed ) {
        ret = krb5_decrypt(	NAME_OF_MAIN_LOC_GLOB_P,                   	NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, crypto, usage,
                            p, len, &data );
        if( ret != 0 ) {
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            *minor_status = ret;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            return GSS_S_BAD_MIC;
        }
        if( data.length < ec + sizeof( *token ) ) {
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &data );
            return GSS_S_DEFECTIVE_TOKEN;
        }
        p = data.data;
        p += data.length - sizeof( *token );
        (( gss_cfx_wrap_token )p )->RRC[0] = token->RRC[0];
        (( gss_cfx_wrap_token )p )->RRC[1] = token->RRC[1];
        if( memcmp( p, token, sizeof( *token ) ) != 0 ) {
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &data );
            return GSS_S_BAD_MIC;
        }
        output_message_buffer->value = data.data;
        output_message_buffer->length = data.length - ec - sizeof( *token );
    } else {
        Checksum cksum;
        ret = krb5_crypto_get_checksum_type(	NAME_OF_MAIN_LOC_GLOB_P,                                    	NAME_OF_MAIN_LOC_GLOB_P->
                                                gssapi_krb5_context,
                                                crypto, &cksum.cksumtype );
        if( ret != 0 ) {
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            *minor_status = ret;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            return GSS_S_FAILURE;
        }
        cksum.checksum.length = ec;
        if( len < cksum.checksum.length ) {
            *minor_status = ERANGE;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            return GSS_S_BAD_MIC;
        }
        len -= cksum.checksum.length;
        cksum.checksum.data = p + len;
        output_message_buffer->length = len;
        output_message_buffer->value =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len + sizeof( *token ) )
            ;
        if( output_message_buffer->value == NULL ) {
            *minor_status = ENOMEM;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            return GSS_S_FAILURE;
        }
        memcpy( output_message_buffer->value, p, len );
        memcpy(( u_char * )output_message_buffer->value + len,
               token, sizeof( *token ) );
        token = ( gss_cfx_wrap_token )(( u_char * )output_message_buffer->value +
                                       len );
        token->EC[0]  = 0;
        token->EC[1]  = 0;
        token->RRC[0] = 0;
        token->RRC[1] = 0;
        ret = krb5_verify_checksum(	NAME_OF_MAIN_LOC_GLOB_P,                           	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto,
                                    usage,
                                    output_message_buffer->value,
                                    len + sizeof( *token ),
                                    &cksum );
        if( ret != 0 ) {
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            *minor_status = ret;
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P,                        	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context, crypto );
            gss_release_buffer(	NAME_OF_MAIN_LOC_GLOB_P, minor_status, output_message_buffer );
            return GSS_S_BAD_MIC;
        }
    }
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P,                        NAME_OF_MAIN_LOC_GLOB_P->
                         gssapi_krb5_context, crypto );
    if( qop_state != NULL ) {
        *qop_state = GSS_C_QOP_DEFAULT;
    }
    *minor_status = 0;
    return GSS_S_COMPLETE;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decode_EncTicketPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                           const void *data,
                           size_t length,
                           EncTicketPart *t,
                           size_t *len )
{
    return decode_EncTicketPart( NAME_OF_MAIN_LOC_GLOB_P, data, length, t, len );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decode_EncASRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          const void *data,
                          size_t length,
                          EncASRepPart *t,
                          size_t *len )
{
    return decode_EncASRepPart( NAME_OF_MAIN_LOC_GLOB_P, data, length, t, len );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decode_EncTGSRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                           const void *data,
                           size_t length,
                           EncTGSRepPart *t,
                           size_t *len )
{
    return decode_EncTGSRepPart( NAME_OF_MAIN_LOC_GLOB_P, data, length, t, len );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decode_EncAPRepPart( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          const void *data,
                          size_t length,
                          EncAPRepPart *t,
                          size_t *len )
{
    return decode_EncAPRepPart( NAME_OF_MAIN_LOC_GLOB_P, data, length, t, len );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decode_Authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                           const void *data,
                           size_t length,
                           Authenticator *t,
                           size_t *len )
{
    return decode_Authenticator( NAME_OF_MAIN_LOC_GLOB_P, data, length, t, len );
}
#ifndef HAVE_NETINFO
struct fileptr {
    const char *s;
    FILE *f;
};
static krb5_error_code parse_section( char *p, krb5_config_section **s,
                                      krb5_config_section **res,
                                      const char **error_message );
static krb5_error_code parse_binding( struct fileptr *f, unsigned *lineno, char *p,
                                      krb5_config_binding **b,
                                      krb5_config_binding **parent,
                                      const char **error_message );
static krb5_error_code parse_list( struct fileptr *f, unsigned *lineno,
                                   krb5_config_binding **parent,
                                   const char **error_message );
/*
 * Parse a section:
 *
 * [section]
 *	foo = bar
 *	b = {
 *		a
 *	    }
 * ...
 *
 * starting at the line in `p', storing the resulting structure in
 * `s' and hooking it into `parent'.
 * Store the error message in `error_message'.
 */
/*
 * Parse a brace-enclosed list from `f', hooking in the structure at
 * `parent'.
 * Store the error message in `error_message'.
 */
/*
 *
 */
/*
 * Parse the config file `fname', generating the structures into `res'
 * returning error messages in `error_message'
 */
#endif
static void
free_binding( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_config_binding *b )
{
    krb5_config_binding *next_b;
    while( b ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, b->name )
        ;
        if( b->type == krb5_config_string )
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, b->u.string )
            ;
        else if( b->type == krb5_config_list )
            free_binding(	NAME_OF_MAIN_LOC_GLOB_P, context, b->u.list );
        else
            //StSch Trace Point
            krb5_abortx(	NAME_OF_MAIN_LOC_GLOB_P, context,"config_file.c 10022: unknown binding type (%d) in free_binding" );
        next_b = b->next;
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, b )
        ;
        b = next_b;
    }
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_config_file_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_config_section *s )
{
    free_binding( NAME_OF_MAIN_LOC_GLOB_P, context, s );
    return 0;
}
/*
 * Set the list of etypes `ret_etypes' from the configuration variable
 * `name'
 */
/*
 * read variables from the configuration file and set in `context'
 */
static krb5_error_code
init_context_from_config_file( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context )
{
    krb5_error_code ret;
    const char * tmp;
    krb5_enctype *tmptypes;
    context->extra_addresses         = NULL;
    context->ignore_addresses        = NULL;
    ( context )->http_proxy            = NULL;
    context->mutex                   = NULL;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->etypes )
    ;
    context->etypes                  = NULL;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->etypes_des )
    ;
    context->etypes_des              = NULL;
    context->default_realms          = NULL;
    context->max_skew                = 0;
    context->max_retries             = 0;
    context->kdc_sec_offset          = 0;
    context->kdc_usec_offset         = 0;
    context->cf                      = NULL;
    context->et_list                 = NULL;
    context->warn_dest               = NULL;
    context->use_admin_kdc           = FALSE;
    context->srv_try_txt             = FALSE;
    context->pkinit_flags            = 0;
    ( context )->default_keytab        = NULL;
    ( context )->default_keytab_modify = NULL;
    ( context )->time_fmt              = "%Y-%m-%dT%H:%M:%S";
    ( context )->date_fmt              = "%Y-%m-%d";
    ( context )->log_utc               = 0;
    ( context )->scan_interfaces       = FALSE;
    ( context )->fcache_vno            = 0;
    ( context )->srv_lookup            = FALSE;
    context->default_cc_name         = NULL;
    context->cc_ops                  = NULL;
    context->num_cc_ops              = 0;
    context->num_kt_types            = 0;
    context->kt_types                = NULL;
    context->forwardable_flag        = 0;
    context->proxiable_flag          = 0;
    context->anonymous_flag          = 0;
    context->kdc_timeout             = 3;
    context->large_msg_size          = 6000;
    context->client_server           = 0;
    context->kdc_port                = 0;
    context->kdc_ip_address          = 0;
    context->renew_life              = 0;
    context->start_time              = 0;
    context->max_ticket_size         = 0;
    context->server                  = NULL;
    context->passwd                  = NULL;
    context->add_serv_realms         = NULL;
    context->number_add_ser_rea      = 0;
    context->c_opt                   = NULL;
    context->gss_krb5_mechanism_oid_.length   = 9;
    context->gss_krb5_mechanism_oid_.elements = ( void * )"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
#ifdef WITHOUT_FILE
    context->tgt                     = NULL;
    context->length_tgt              = 0;
#endif
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_init_context( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context *context )
{
    krb5_context p;
    krb5_error_code ret;
    *context = NULL;
    p =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( *p ) ) ),'\0',( 1 ) * ( sizeof( *p ) ) )
        ;
    if( !p )
        return ENOMEM;
    p->mutex = NULL;
    krb5_config_file_free( NAME_OF_MAIN_LOC_GLOB_P, p, p->cf );
    p->cf = NULL;
    ret = init_context_from_config_file( NAME_OF_MAIN_LOC_GLOB_P, p );
    krb5_init_ets( NAME_OF_MAIN_LOC_GLOB_P, p );
    if( ret ) {
        //StSch Trace Point
        krb5_free_context( NAME_OF_MAIN_LOC_GLOB_P, p );
        p = NULL;
    }
    *context = p;
    return ret;
}
void KRB5_LIB_FUNCTION
krb5_free_context( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context )
{
    if( context->default_cc_name )
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->default_cc_name )
        ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->etypes )
    ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->etypes_des )
    ;
    krb5_free_host_realm( NAME_OF_MAIN_LOC_GLOB_P, context, context->default_realms );
    krb5_config_file_free( NAME_OF_MAIN_LOC_GLOB_P, context, context->cf );
    free_error_table( NAME_OF_MAIN_LOC_GLOB_P, context->et_list );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->cc_ops )
    ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->kt_types )
    ;
    krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
    if( context->server ) {
        memset( context->server, 0, strlen( context->server )+1 );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->server )
        ;
        context->server = NULL;
    }
    if( context->passwd ) {
        memset( context->passwd, 0, strlen( context->passwd )+1 );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->passwd )
        ;
        context->passwd = NULL;
    }
#ifdef WITHOUT_FILE
    if( context->tgt ) {
        memset( context->tgt, 0, context->length_tgt );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->tgt )
        ;
        context->tgt = NULL;
        context->length_tgt = 0;
    }
#endif
    memset( context, 0, sizeof( *context ) );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context )
    ;
}
/*
 *  `pq' isn't free, its up the the caller
 */
/*
 * set `etype' to a malloced list of the default enctypes
 */
static krb5_error_code
default_etypes( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_enctype **etype )
{
    krb5_enctype p[] = {
        ETYPE_AES256_CTS_HMAC_SHA1_96,
        ETYPE_AES128_CTS_HMAC_SHA1_96,
        ETYPE_DES3_CBC_SHA1,
        ETYPE_DES3_CBC_MD5,
        ETYPE_ARCFOUR_HMAC_MD5,
        ETYPE_DES_CBC_MD5,
        ETYPE_DES_CBC_MD4,
        ETYPE_DES_CBC_CRC
    };
    krb5_enctype *e = NULL, *ep;
    int i, n = 0;
    for( i = 0; i < sizeof( p )/sizeof( p[0] ); i++ ) {
        if( krb5_enctype_valid(	NAME_OF_MAIN_LOC_GLOB_P, context, p[i] ) != 0 )
            continue;
        ep =
            m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, e, ( n + 2 ) * sizeof( *e ) )
            ;
        if( ep == NULL ) {
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, e )
            ;
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","context.c 1309" )
            ;
            return ENOMEM;
        }
        e = ep;
        e[n] = p[i];
        e[n + 1] = ETYPE_NULL;
        n++;
    }
    *etype = e;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_default_in_tkt_etypes( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                krb5_enctype **etypes )
{
    krb5_enctype *p;
    int i;
    krb5_error_code ret;
    if( context->etypes ) {
        for( i = 0; context->etypes[i]; i++ );
        ++i;
        ALLOC( p, i );
        if( !p ) {
            krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","context.c 1311" )
            ;
            return ENOMEM;
        }
        memmove( p, context->etypes, i * sizeof( krb5_enctype ) );
    } else {
        ret = default_etypes( NAME_OF_MAIN_LOC_GLOB_P, context, &p );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
    }
    *etypes = p;
    return 0;
}
const char* KRB5_LIB_FUNCTION
krb5_get_err_text( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_error_code code )
{
    const char *p = NULL;
    if( context != NULL )
        p = com_right(	NAME_OF_MAIN_LOC_GLOB_P, context->et_list, code );
    if( p == NULL )
        p = m_strerror_hl(	NAME_OF_MAIN_LOC_GLOB_P, code );
    if( p == NULL )
        p = "Unknown error";
    return p;
}
void KRB5_LIB_FUNCTION
krb5_init_ets( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context )
{
    if( context->et_list == NULL ) {
        krb5_add_et_list(	NAME_OF_MAIN_LOC_GLOB_P, context, initialize_krb5_error_table_r );
        krb5_add_et_list(	NAME_OF_MAIN_LOC_GLOB_P, context, initialize_asn1_error_table_r );
        krb5_add_et_list(	NAME_OF_MAIN_LOC_GLOB_P, context, initialize_heim_error_table_r );
    }
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_set_fcache_version( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, int version )
{
    context->fcache_vno = version;
    return 0;
}

static u_long table[256];

void
_krb5_crc_init_table( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P
                    )
{
    static int flag = 0;
    unsigned long crc, poly;
    int     i, j;
    if( flag )
        return;
    m_enter_cs();
    if( !flag ) {
        poly = CRC_GEN;
        for( i = 0; i < 256; i++ ) {
            crc = i;
            for( j = 8; j > 0; j-- ) {
                if( crc & 1 ) {
                    crc = ( crc >> 1 ) ^ poly;
                } else {
                    crc >>= 1;
                }
            }
            table[i] = crc;
        }
        flag
        = 1;
    }
    m_leave_cs();
}
u_int32_t
_krb5_crc_update( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const char *p, size_t len, u_int32_t res )
{
    while( len-- )
        res =
            table[( res ^ *p++ ) & 0xFF] ^( res >> 8 );
    return res & 0xFFFFFFFF;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_free_cred_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_creds *c )
{
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, c->client );
    c->client = NULL;
    c->server = NULL;
    krb5_free_keyblock_contents( NAME_OF_MAIN_LOC_GLOB_P, context, &c->session );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &c->ticket );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &c->second_ticket );
    free_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, &c->authdata );
    krb5_free_addresses( NAME_OF_MAIN_LOC_GLOB_P, context, &c->addresses );
    memset( c, 0, sizeof( *c ) );
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_copy_creds_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          const krb5_creds *incred,
                          krb5_creds *c )
{
    krb5_error_code ret;
    memset( c, 0, sizeof( *c ) );
    ret = krb5_copy_principal( NAME_OF_MAIN_LOC_GLOB_P, context, incred->client, &c->client );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    ret = krb5_copy_principal( NAME_OF_MAIN_LOC_GLOB_P, context, incred->server, &c->server );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    ret = krb5_copy_keyblock_contents( NAME_OF_MAIN_LOC_GLOB_P, context, &incred->session, &c->session );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    c->times = incred->times;
    ret = krb5_data_copy( NAME_OF_MAIN_LOC_GLOB_P, &c->ticket,
                          incred->ticket.data,
                          incred->ticket.length );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    ret = krb5_data_copy( NAME_OF_MAIN_LOC_GLOB_P, &c->second_ticket,
                          incred->second_ticket.data,
                          incred->second_ticket.length );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    ret = copy_AuthorizationData( NAME_OF_MAIN_LOC_GLOB_P, &incred->authdata, &c->authdata );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    ret = krb5_copy_addresses( NAME_OF_MAIN_LOC_GLOB_P, context,
                               &incred->addresses,
                               &c->addresses );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    c->flags = incred->flags;
    return 0;
    fail:
    krb5_free_cred_contents( NAME_OF_MAIN_LOC_GLOB_P, context, c );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_copy_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 const krb5_creds *incred,
                 krb5_creds **outcred )
{
    krb5_creds *c;
    c =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *c ) )
        ;
    if( c == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","creds.c 1124" )
        ;
        return ENOMEM;
    }
    memset( c, 0, sizeof( *c ) );
    *outcred = c;
    return krb5_copy_creds_contents( NAME_OF_MAIN_LOC_GLOB_P, context, incred, c );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_free_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_creds *c )
{
    krb5_free_cred_contents( NAME_OF_MAIN_LOC_GLOB_P, context, c );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, c )
    ;
    return 0;
}
static krb5_boolean
krb5_data_equal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const krb5_data *a, const krb5_data *b )
{
    if( a->length != b->length )
        return FALSE;
    return memcmp( a->data, b->data, a->length ) == 0;
}
static krb5_boolean
krb5_times_equal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const krb5_times *a, const krb5_times *b )
{
    return a->starttime == b->starttime &&
           a->authtime == b->authtime &&
           a->endtime == b->endtime &&
           a->renew_till == b->renew_till;
}
/*
 * Return TRUE if `mcreds' and `creds' are equal (`whichfields'
 * determines what equal means).
 */
krb5_boolean KRB5_LIB_FUNCTION
krb5_compare_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_flags whichfields,
                    const krb5_creds * mcreds, const krb5_creds * creds )
{
    krb5_boolean match = TRUE;
    if( match && mcreds->server ) {
        if( whichfields & ( KRB5_TC_DONT_MATCH_REALM | KRB5_TC_MATCH_SRV_NAMEONLY ) )
            match = krb5_principal_compare_any_realm(	NAME_OF_MAIN_LOC_GLOB_P, context, mcreds->server,
                    creds->server );
        else
            match = krb5_principal_compare(	NAME_OF_MAIN_LOC_GLOB_P, context, mcreds->server,
                                            creds->server );
    }
    if( match && mcreds->client ) {
        if( whichfields & KRB5_TC_DONT_MATCH_REALM )
            match = krb5_principal_compare_any_realm(	NAME_OF_MAIN_LOC_GLOB_P, context, mcreds->client,
                    creds->client );
        else
            match = krb5_principal_compare(	NAME_OF_MAIN_LOC_GLOB_P, context, mcreds->client,
                                            creds->client );
    }
    if( match && ( whichfields & KRB5_TC_MATCH_KEYTYPE ) )
        match = krb5_enctypes_compatible_keys(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                                mcreds->session.keytype,
                                                creds->session.keytype );
    if( match && ( whichfields & KRB5_TC_MATCH_FLAGS_EXACT ) )
        match = mcreds->flags.i == creds->flags.i;
    if( match && ( whichfields & KRB5_TC_MATCH_FLAGS ) )
        match = ( creds->flags.i & mcreds->flags.i ) == mcreds->flags.i;
    if( match && ( whichfields & KRB5_TC_MATCH_TIMES_EXACT ) )
        match = krb5_times_equal(	NAME_OF_MAIN_LOC_GLOB_P, &mcreds->times, &creds->times );
    if( match && ( whichfields & KRB5_TC_MATCH_TIMES ) )
        match = ( mcreds->times.renew_till <= creds->times.renew_till ) &&
                ( mcreds->times.endtime <= creds->times.endtime );
    if( match && ( whichfields & KRB5_TC_MATCH_AUTHDATA ) ) {
        unsigned int i;
        if( mcreds->authdata.len != creds->authdata.len )
            match = FALSE;
        else
            for( i = 0; match && i < mcreds->authdata.len; i++ )
                match = ( mcreds->authdata.val[i].ad_type ==
                          creds->authdata.val[i].ad_type ) &&
                        krb5_data_equal(	NAME_OF_MAIN_LOC_GLOB_P, &mcreds->authdata.val[i].ad_data,
                                            &creds->authdata.val[i].ad_data );
    }
    if( match && ( whichfields & KRB5_TC_MATCH_2ND_TKT ) )
        match = krb5_data_equal(	NAME_OF_MAIN_LOC_GLOB_P, &mcreds->second_ticket, &creds->second_ticket );
    if( match && ( whichfields & KRB5_TC_MATCH_IS_SKEY ) )
        match = (( mcreds->second_ticket.length == 0 ) ==
                 ( creds->second_ticket.length == 0 ) );
    return match;
}
void _krb5_n_fold( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const void *str, size_t len, void *key, size_t size );
struct key_usage {
    unsigned usage;
    struct key_data key;
};
struct krb5_crypto_data {
    struct encryption_type *et;
    struct key_data key;
    int num_key_usage;
    struct key_usage *key_usage;
    void *params;
};
static struct checksum_type *_find_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_cksumtype type );
static struct encryption_type *_find_enctype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_enctype type );
static struct key_type *_find_keytype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_keytype type );
static krb5_error_code _get_derived_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context, krb5_crypto,
        unsigned, struct key_data** );
static struct key_data *_new_derived_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_crypto crypto, unsigned usage );
static krb5_error_code derive_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                   struct encryption_type *et,
                                   struct key_data *key,
                                   const void *constant,
                                   size_t len );
krb5_error_code hmac( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      struct checksum_type *cm,
                      const void *data,
                      size_t len,
                      unsigned usage,
                      struct key_data *keyblock,
                      Checksum *result );
static void free_key_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, struct key_data *key );
static krb5_error_code usage2arcfour( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context, unsigned * );
static void xor( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock *, const unsigned char * );
/************************************************************
 *                                                          *
 ************************************************************/
/* This defines the Andrew string_to_key function.  It accepts a password
 * string as input and converts its via a one-way encryption algorithm to a DES
 * encryption key.  It is compatible with the original Andrew authentication
 * service password database.
 */
/*
 * Short passwords, i.e 8 characters or less.
 */
/*
 * Long passwords, i.e 9 characters or more.
 */
/*
 *
 */
void
DES3_random_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 krb5_keyblock *key )
{
    DES_cblock *k = key->keyvalue.data;
    do {
        krb5_generate_random_block(	NAME_OF_MAIN_LOC_GLOB_P, k, 3 * sizeof( DES_cblock ) );
        DES_set_odd_parity(	NAME_OF_MAIN_LOC_GLOB_P, &k[0] );
        DES_set_odd_parity(	NAME_OF_MAIN_LOC_GLOB_P, &k[1] );
        DES_set_odd_parity(	NAME_OF_MAIN_LOC_GLOB_P, &k[2] );
    } while( DES_is_weak_key( NAME_OF_MAIN_LOC_GLOB_P, &k[0] ) ||
             DES_is_weak_key(	NAME_OF_MAIN_LOC_GLOB_P, &k[1] ) ||
             DES_is_weak_key(	NAME_OF_MAIN_LOC_GLOB_P, &k[2] ) );
}
void
DES3_schedule( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               struct key_data *key,
               const void *params )
{
    DES_cblock *k = key->key->keyvalue.data;
    DES_key_schedule *s = key->schedule->data;
    GenDESSubKeys( &k[0], &s[0] );
    GenDESSubKeys( &k[1], &s[1] );
    GenDESSubKeys( &k[2], &s[2] );
}
/*
 * A = A xor B. A & B are 8 bytes.
 */
static void
xor( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock *key, const unsigned char *b )
{
    unsigned char *a = ( unsigned char* )key;
    a[0] ^= b[0];
    a[1] ^= b[1];
    a[2] ^= b[2];
    a[3] ^= b[3];
    a[4] ^= b[4];
    a[5] ^= b[5];
    a[6] ^= b[6];
    a[7] ^= b[7];
}
krb5_error_code
DES3_string_to_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_enctype enctype,
                    krb5_data password,
                    krb5_salt salt,
                    krb5_data opaque,
                    krb5_keyblock *key )
{
    char *str;
    size_t len;
    unsigned char tmp[24];
    DES_cblock keys[3];
    len = password.length + salt.saltvalue.length;
    str =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    if( len != 0 && str == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1133" )
        ;
        return ENOMEM;
    }
    memcpy( str, password.data, password.length );
    memcpy( str + password.length, salt.saltvalue.data, salt.saltvalue.length );
    {
        DES_cblock ivec;
        DES_key_schedule s[3];
        int i;
        _krb5_n_fold(	NAME_OF_MAIN_LOC_GLOB_P, str, len, tmp, 24 );
        for( i = 0; i < 3; i++ ) {
            memcpy( keys + i, tmp + i * 8, sizeof( keys[i] ) );
            DES_set_odd_parity(	NAME_OF_MAIN_LOC_GLOB_P, keys + i );
            if( DES_is_weak_key(	NAME_OF_MAIN_LOC_GLOB_P, keys + i ) )
                xor(	NAME_OF_MAIN_LOC_GLOB_P, keys + i, ( const unsigned char* )"\0\0\0\0\0\0\0\xf0" );
            GenDESSubKeys( keys + i, &s[i] );
        }
        memset( &ivec, 0, sizeof( ivec ) );
        DES3_ede_cbc_encrypt_decrypt(tmp, tmp, &s[0], &s[1], &s[2], sizeof( tmp )/8, &ivec, DES_ENCRYPT);
        memset( s, 0, sizeof( s ) );
        memset( &ivec, 0, sizeof( ivec ) );
        for( i = 0; i < 3; i++ ) {
            memcpy( keys + i, tmp + i * 8, sizeof( keys[i] ) );
            DES_set_odd_parity(	NAME_OF_MAIN_LOC_GLOB_P, keys + i );
            if( DES_is_weak_key(	NAME_OF_MAIN_LOC_GLOB_P, keys + i ) )
                xor(	NAME_OF_MAIN_LOC_GLOB_P, keys + i, ( const unsigned char* )"\0\0\0\0\0\0\0\xf0" );
        }
        memset( tmp, 0, sizeof( tmp ) );
    }
    key->keytype = enctype;
    krb5_data_copy( NAME_OF_MAIN_LOC_GLOB_P, &key->keyvalue, keys, sizeof( keys ) );
    memset( keys, 0, sizeof( keys ) );
    memset( str, 0, len );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, str )
    ;
    return 0;
}
krb5_error_code
DES3_string_to_key_derived( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                            krb5_enctype enctype,
                            krb5_data password,
                            krb5_salt salt,
                            krb5_data opaque,
                            krb5_keyblock *key )
{
    krb5_error_code ret;
    size_t len = password.length + salt.saltvalue.length;
    char *s;
    s =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    if( len != 0 && s == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1134" )
        ;
        return ENOMEM;
    }
    memcpy( s, password.data, password.length );
    memcpy( s + password.length, salt.saltvalue.data, salt.saltvalue.length );
    ret = krb5_string_to_key_derived( NAME_OF_MAIN_LOC_GLOB_P, context,
                                      s,
                                      len,
                                      enctype,
                                      key );
    memset( s, 0, len );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, s )
    ;
    return ret;
}
void
DES3_random_to_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_keyblock *key,
                    const void *data,
                    size_t size )
{
    unsigned char *x = key->keyvalue.data;
    const u_char *q = data;
    DES_cblock *k;
    int i, j;
    memset( x, 0, sizeof( x ) );
    for( i = 0; i < 3; ++i ) {
        unsigned char foo;
        for( j = 0; j < 7; ++j ) {
            unsigned char b = q[7 * i + j];
            x[8 * i + j] = b;
        }
        foo = 0;
        for( j = 6; j >= 0; --j ) {
            foo |= q[7 * i + j] & 1;
            foo <<= 1;
        }
        x[8 * i + 7] = foo;
    }
    k = key->keyvalue.data;
    for( i = 0; i < 3; i++ ) {
        DES_set_odd_parity(	NAME_OF_MAIN_LOC_GLOB_P, &k[i] );
        if( DES_is_weak_key(	NAME_OF_MAIN_LOC_GLOB_P, &k[i] ) )
            xor(	NAME_OF_MAIN_LOC_GLOB_P, &k[i], ( const unsigned char* )"\0\0\0\0\0\0\0\xf0" );
    }
}
/*
 * ARCFOUR
 */
void
ARCFOUR_schedule( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  struct key_data *kd,
                  const void *params )
{
    RC4_SetKey( kd->schedule->data,kd->key->keyvalue.data,
                 0, kd->key->keyvalue.length );
}
krb5_error_code
ARCFOUR_string_to_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       krb5_enctype enctype,
                       krb5_data password,
                       krb5_salt salt,
                       krb5_data opaque,
                       krb5_keyblock *key )
{
    char *s, *p;
    size_t len;
    int i;
    MD4_CTX m;
    len = 2 * password.length;
    s =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    if( len != 0 && s == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1135" )
        ;
        return ENOMEM;
    }
    for( p = s, i = 0; i < password.length; ++i ) {
        *p++ = (( char * )password.data )[i];
        *p++ = 0;
    }
    MD4_Init( m );
    MD4_Update( m, s, 0, len );
    key->keytype = enctype;
    krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, &key->keyvalue, 16 );
    MD4_Final( m, key->keyvalue.data, 0 );
    memset( s, 0, len );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, s )
    ;
    return 0;
}
/*
 * AES
 */
krb5_error_code KRB5_LIB_FUNCTION
_krb5_PKCS5_PBKDF2( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_cksumtype cktype,
                    krb5_data password, krb5_salt salt, u_int32_t iter,
                    krb5_keytype type, krb5_keyblock *key )
{
    struct checksum_type *c = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, cktype );
    struct key_type *kt;
    size_t datalen, leftofkey;
    krb5_error_code ret;
    u_int32_t keypart;
    struct key_data ksign;
    krb5_keyblock kb;
    Checksum result;
    char *data, *tmpcksum;
    int i, j;
    char *p;
    if( c == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"checksum  not supported","crypto.c 1136" )
        ;
        return KRB5_PROG_KEYTYPE_NOSUPP;
    }
    kt = _find_keytype( NAME_OF_MAIN_LOC_GLOB_P, type );
    if( kt == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"key type  not supported","crypto.c 1137" )
        ;
        return KRB5_PROG_KEYTYPE_NOSUPP;
    }
    key->keytype = type;
    ret = krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, &key->keyvalue, kt->bits / 8 );
    if( ret ) {
        //StSch Trace Point
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1138" )
        ;
        return ret;
    }
    ret = krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, &result.checksum, c->checksumsize );
    if( ret ) {
        //StSch Trace Point
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1139" )
        ;
        krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &key->keyvalue );
        return ret;
    }
    tmpcksum =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, c->checksumsize )
        ;
    if( tmpcksum == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1140" )
        ;
        krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &key->keyvalue );
        krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &result.checksum );
        return ENOMEM;
    }
    datalen = salt.saltvalue.length + 4;
    data =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, datalen )
        ;
    if( data == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1141" )
        ;
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tmpcksum )
        ;
        krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &key->keyvalue );
        krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &result.checksum );
        return ENOMEM;
    }
    kb.keyvalue = password;
    ksign.key = &kb;
    memcpy( data, salt.saltvalue.data, salt.saltvalue.length );
    keypart = 1;
    leftofkey = key->keyvalue.length;
    p = key->keyvalue.data;
    while( leftofkey ) {
        int len;
        if( leftofkey > c->checksumsize )
            len = c->checksumsize;
        else
            len = leftofkey;
        _krb5_put_int(	NAME_OF_MAIN_LOC_GLOB_P, data + datalen - 4, keypart, 4 );
        ret = hmac(	NAME_OF_MAIN_LOC_GLOB_P, context, c, data, datalen, 0, &ksign, &result );
        if( ret )
            //StSch Trace Point
            krb5_abortx(	NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10005: hmac failed" );
        memcpy( p, result.checksum.data, len );
        memcpy( tmpcksum, result.checksum.data, result.checksum.length );
        for( i = 0; i < iter; i++ ) {
            ret = hmac(	NAME_OF_MAIN_LOC_GLOB_P, context, c, tmpcksum, result.checksum.length,
                        0, &ksign, &result );
            if( ret )
                //StSch Trace Point
                krb5_abortx(	NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10006: hmac failed" );
            memcpy( tmpcksum, result.checksum.data, result.checksum.length );
            for( j = 0; j < len; j++ )
                p[j] ^= tmpcksum[j];
        }
        p += len;
        leftofkey -= len;
        keypart++;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, data )
    ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tmpcksum )
    ;
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &result.checksum );
    return 0;
}
krb5_error_code
AES_string_to_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_enctype enctype,
                   krb5_data password,
                   krb5_salt salt,
                   krb5_data opaque,
                   krb5_keyblock *key )
{
    krb5_error_code ret;
    u_int32_t iter;
    struct encryption_type *et;
    struct key_data kd;
    if( opaque.length == 0 )
        iter =
            NAME_OF_MAIN_LOC_GLOB_P->
            _krb5_AES_string_to_default_iterator - 1;
    else if( opaque.length == 4 ) {
        unsigned long v;
        _krb5_get_int(	NAME_OF_MAIN_LOC_GLOB_P, opaque.data, &v, 4 );
        iter = (( u_int32_t )v ) - 1;
    } else
        return KRB5_PROG_KEYTYPE_NOSUPP;
    et = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, enctype );
    if( et == NULL )
        return KRB5_PROG_KEYTYPE_NOSUPP;
    ret = _krb5_PKCS5_PBKDF2( NAME_OF_MAIN_LOC_GLOB_P, context, CKSUMTYPE_SHA1, password, salt,
                              iter, enctype, key );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_copy_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, key, &kd.key );
    kd.schedule = NULL;
    ret = derive_key( NAME_OF_MAIN_LOC_GLOB_P, context, et, &kd, "kerberos", strlen( "kerberos" ) );
    krb5_free_keyblock_contents( NAME_OF_MAIN_LOC_GLOB_P, context, key );
    if( ret == 0 ) {
        ret = krb5_copy_keyblock_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, kd.key, key );
        free_key_data(	NAME_OF_MAIN_LOC_GLOB_P, context, &kd );
    }
    return ret;
}
void
AES_schedule( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              struct key_data *kd,
              const void *params )
{
    struct krb5_aes_schedule *key = kd->schedule->data;
    int inl_32bit_blocks = kd->key->keyvalue.length /4;
    memset( key, 0, sizeof( *key ) );
    m_gen_aes_encrypt_keys( kd->key->keyvalue.data, inl_32bit_blocks, &key->ekey);
    m_gen_aes_decrypt_keys( kd->key->keyvalue.data, inl_32bit_blocks, &key->dkey);
}
/*
 *
 */
/*
 *
 */
static struct salt_type des3_salt[2]= {
    {
        KRB5_PW_SALT,
        "pw-salt",
        DES3_string_to_key
    },
    { 0 }
};

static struct salt_type des3_salt_derived[2]= {
    {
        KRB5_PW_SALT,
        "pw-salt",
        DES3_string_to_key_derived
    },
    { 0 }
};
static struct salt_type AES_salt[2]= {
    {
        KRB5_PW_SALT,
        "pw-salt",
        AES_string_to_key
    },
    { 0 }
};
static struct salt_type arcfour_salt[2]= {
    {
        KRB5_PW_SALT,
        "pw-salt",
        ARCFOUR_string_to_key
    },
    { 0 }
};
static struct key_type keytype_null= {
    KEYTYPE_NULL,
    "null",
    0,
    0,
    0,
    0,
    (( void * )0 ),
    (( void * )0 ),
    (( void * )0 )
};
static struct key_type keytype_des3= {
    KEYTYPE_DES3,
    "des3",
    168,
    3 * sizeof( DES_cblock ),
    3 * sizeof( DES_cblock ),
    3 * sizeof( DES_key_schedule ),
    DES3_random_key,
    DES3_schedule,
    des3_salt,
    DES3_random_to_key
};
static struct key_type keytype_des3_derived= {
    KEYTYPE_DES3,
    "des3",
    168,
    3 * DES_BLOCK_SIZE,
    3 * DES_BLOCK_SIZE,
    3 * DES_SUBKEY_ARRAY_SIZE * 4,
    DES3_random_key,
    DES3_schedule,
    des3_salt_derived,
    DES3_random_to_key
};
static struct key_type keytype_aes128= {
    KEYTYPE_AES128,
    "aes-128",
    128,
    16,
    16,
    sizeof( struct krb5_aes_schedule ),
    (( void * )0 ),
    AES_schedule,
    AES_salt
};
static struct key_type keytype_aes192= {
    KEYTYPE_AES192,
    "aes-192",
    192,
    24,
    24,
    sizeof( struct krb5_aes_schedule ),
    (( void * )0 ),
    AES_schedule,
    AES_salt
};
static struct key_type keytype_aes256= {
    KEYTYPE_AES256,
    "aes-256",
    256,
    32,
    32,
    sizeof( struct krb5_aes_schedule ),
    (( void * )0 ),
    AES_schedule,
    AES_salt
};
static struct key_type keytype_arcfour= {
    KEYTYPE_ARCFOUR,
    "arcfour",
    128,
    16,
    16,
    RC4_STATE_SIZE,
    (( void * )0 ),
    ARCFOUR_schedule,
    arcfour_salt
};
static struct key_type *keytypes[7]= {
    &keytype_null,
    &keytype_des3_derived,
    &keytype_des3,
    &keytype_aes128,
    &keytype_aes192,
    &keytype_aes256,
    &keytype_arcfour
};
static int num_keytypes=sizeof( keytypes ) / sizeof( keytypes[0] );

static struct key_type *
_find_keytype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_keytype type ) {
    int i;
    for( i = 0; i < num_keytypes; i++ )
        if( keytypes[i]->type == type )
            return keytypes[i];
    return NULL;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_pw_salt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  krb5_const_principal principal,
                  krb5_salt *salt )
{
    size_t len;
    int i;
    krb5_error_code ret;
    char *p;
    salt->salttype = KRB5_PW_SALT;
    len = strlen( principal->realm );
    for( i = 0; i < principal->name.name_string.len; ++i )
        len += strlen( principal->name.name_string.val[i] );
    ret = krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, &salt->saltvalue, len );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    p = salt->saltvalue.data;
    memcpy( p, principal->realm, strlen( principal->realm ) );
    p += strlen( principal->realm );
    for( i = 0; i < principal->name.name_string.len; ++i ) {
        memcpy( p,
                principal->name.name_string.val[i],
                strlen( principal->name.name_string.val[i] ) );
        p += strlen( principal->name.name_string.val[i] );
    }
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_free_salt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_salt salt )
{
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &salt.saltvalue );
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_string_to_key_data_salt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                              krb5_enctype enctype,
                              krb5_data password,
                              krb5_salt salt,
                              krb5_keyblock *key )
{
    krb5_data opaque;
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &opaque );
    return krb5_string_to_key_data_salt_opaque( NAME_OF_MAIN_LOC_GLOB_P, context, enctype, password,
            salt, opaque, key );
}
/*
 * Do a string -> key for encryption type `enctype' operation on
 * `password' (with salt `salt' and the enctype specific data string
 * `opaque'), returning the resulting key in `key'
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_string_to_key_data_salt_opaque( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                     krb5_enctype enctype,
                                     krb5_data password,
                                     krb5_salt salt,
                                     krb5_data opaque,
                                     krb5_keyblock *key )
{
    struct encryption_type *et =_find_enctype( NAME_OF_MAIN_LOC_GLOB_P, enctype );
    struct salt_type *st;
    if( et == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"encryption type  not supported","crypto.c 1149" )
        ;
        return KRB5_PROG_ETYPE_NOSUPP;
    }
    for( st = et->keytype->string_to_key; st && st->type; st++ )
        if( st->type == salt.salttype )
            return ( *st->string_to_key )(	NAME_OF_MAIN_LOC_GLOB_P, context, enctype, password,
                                            salt, opaque, key );
    krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P, context,"salt type  not supported","crypto.c 1150" )
    ;
    return HEIM_ERR_SALTTYPE_NOSUPP;
}
/*
 * Do a string -> key for encryption type `enctype' operation on the
 * string `password' (with salt `salt'), returning the resulting key
 * in `key'
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_string_to_key_salt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                         krb5_enctype enctype,
                         const char *password,
                         krb5_salt salt,
                         krb5_keyblock *key )
{
    krb5_data pw;
    pw.data = ( void* )password;
    pw.length = strlen( password );
    return krb5_string_to_key_data_salt( NAME_OF_MAIN_LOC_GLOB_P, context, enctype, pw, salt, key );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_generate_random_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                               krb5_enctype type,
                               krb5_keyblock *key )
{
    krb5_error_code ret;
    struct encryption_type *et = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, type );
    if( et == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"encryption type  not supported","crypto.c 1155" )
        ;
        return KRB5_PROG_ETYPE_NOSUPP;
    }
    ret = krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, &key->keyvalue, et->keytype->size );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    key->keytype = type;
    if( et->keytype->random_key )
        (	NAME_OF_MAIN_LOC_GLOB_P, *et->keytype->random_key )( NAME_OF_MAIN_LOC_GLOB_P, context, key );
    else
        krb5_generate_random_block(	NAME_OF_MAIN_LOC_GLOB_P, key->keyvalue.data,
                                    key->keyvalue.length );
    return 0;
}
static krb5_error_code
_key_schedule( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               struct key_data *key,
               const void *params )
{
    krb5_error_code ret;
    struct encryption_type *et = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, key->key->keytype );
    struct key_type *kt = et->keytype;
    if( kt->schedule == NULL )
        return 0;
    if( key->schedule != NULL )
        return 0;
    ALLOC( key->schedule, 1 );
    if( key->schedule == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1156" )
        ;
        return ENOMEM;
    }
    ret = krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, key->schedule, kt->schedule_size );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, key->schedule )
        ;
        key->schedule = NULL;
        return ret;
    }
    ( *kt->schedule )( NAME_OF_MAIN_LOC_GLOB_P, context, key, params );
    return 0;
}
/************************************************************
 *                                                          *
 ************************************************************/
void
NONE_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               struct key_data *key,
               const void *data,
               size_t len,
               unsigned usage,
               Checksum *C )
{
}
void
CRC32_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                struct key_data *key,
                const void *data,
                size_t len,
                unsigned usage,
                Checksum *C )
{
    u_int32_t crc;
    unsigned char *r = C->checksum.data;
    _krb5_crc_init_table( NAME_OF_MAIN_LOC_GLOB_P );
    crc = _krb5_crc_update( NAME_OF_MAIN_LOC_GLOB_P, data, len, 0 );
    r[0] = crc & 0xff;
    r[1] = ( crc >> 8 )  & 0xff;
    r[2] = ( crc >> 16 ) & 0xff;
    r[3] = ( crc >> 24 ) & 0xff;
}
void
RSA_MD4_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  struct key_data *key,
                  const void *data,
                  size_t len,
                  unsigned usage,
                  Checksum *C )
{
    MD4_CTX m;
    MD4_Init( m );
    MD4_Update( m, data, 0, len );
    MD4_Final( m, C->checksum.data, 0 );
}
void
RSA_MD4_DES_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      struct key_data *key,
                      const void *data,
                      size_t len,
                      unsigned usage,
                      Checksum *cksum )
{
    MD4_CTX md4;
    DES_cblock ivec;
    unsigned char *p = cksum->checksum.data;
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, p, 8 );
    MD4_Init( md4 );
    MD4_Update( md4, p, 0, 8 );
    MD4_Update( md4, data, 0, len );
    MD4_Final( md4, p + 8, 0 );
    memset( &ivec, 0, sizeof( ivec ) );
    DES_cbc_encrypt_decrypt(p,
        p,
        (unsigned int *) key->schedule->data,
        3,
        &ivec,
        DES_ENCRYPT);
}
krb5_error_code
RSA_MD4_DES_verify( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    struct key_data *key,
                    const void *data,
                    size_t len,
                    unsigned usage,
                    Checksum *C )
{
    MD4_CTX md4;
    unsigned char tmp[24];
    unsigned char res[16];
    DES_cblock ivec;
    krb5_error_code ret = 0;
    memset( &ivec, 0, sizeof( ivec ) );
    DES_cbc_encrypt_decrypt((unsigned char*) C->checksum.data,
        tmp,
        (unsigned int *) key->schedule->data,
        C->checksum.length/8,
        &ivec,
        DES_DECRYPT);
    MD4_Init( md4 );
    MD4_Update( md4, tmp, 0, 8 );
    MD4_Update( md4, data, 0, len );
    MD4_Final( md4, res, 0 );
    if( memcmp( res, tmp + 8, sizeof( res ) ) != 0 ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    memset( tmp, 0, sizeof( tmp ) );
    memset( res, 0, sizeof( res ) );
    return ret;
}
void
RSA_MD5_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  struct key_data *key,
                  const void *data,
                  size_t len,
                  unsigned usage,
                  Checksum *C )
{
    MD5_CTX inr_md5_ctx;
    MD5_Init( inr_md5_ctx );
    MD5_Update( inr_md5_ctx, data, 0, len );
    MD5_Final( inr_md5_ctx, C->checksum.data, 0 );
}
void
RSA_MD5_DES_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      struct key_data *key,
                      const void *data,
                      size_t len,
                      unsigned usage,
                      Checksum *C )
{
    MD5_CTX inr_md5_ctx;
    DES_cblock ivec;
    unsigned char *p = C->checksum.data;
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, p, 8 );
    MD5_Init( inr_md5_ctx );
    MD5_Update( inr_md5_ctx, p, 0, 8 );
    MD5_Update( inr_md5_ctx, data, 0, len );
    MD5_Final( inr_md5_ctx, p + 8, 0 );
    memset( &ivec, 0, sizeof( ivec ) );
    DES_cbc_encrypt_decrypt(p,
        p,
        (unsigned int *) key->schedule->data,
        3,
        &ivec,
        DES_ENCRYPT);
}
krb5_error_code
RSA_MD5_DES_verify( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    struct key_data *key,
                    const void *data,
                    size_t len,
                    unsigned usage,
                    Checksum *C )
{
    MD5_CTX inr_md5_ctx;
    unsigned char tmp[24];
    unsigned char res[16];
    DES_cblock ivec;
    DES_key_schedule *sched = key->schedule->data;
    krb5_error_code ret = 0;
    memset( &ivec, 0, sizeof( ivec ) );
    DES_cbc_encrypt_decrypt((unsigned char*) C->checksum.data,
        tmp,
        &sched[0],
        C->checksum.length/8,
        &ivec,
        DES_DECRYPT);
    MD5_Init( inr_md5_ctx );
    MD5_Update( inr_md5_ctx, tmp, 0, 8 );
    MD5_Update( inr_md5_ctx, data, 0, len );
    MD5_Final( inr_md5_ctx, res, 0 );
    if( memcmp( res, tmp + 8, sizeof( res ) ) != 0 ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    memset( tmp, 0, sizeof( tmp ) );
    memset( res, 0, sizeof( res ) );
    return ret;
}
void
RSA_MD5_DES3_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       struct key_data *key,
                       const void *data,
                       size_t len,
                       unsigned usage,
                       Checksum *C )
{
    MD5_CTX inr_md5_ctx;
    DES_cblock ivec;
    unsigned char *p = C->checksum.data;
    DES_key_schedule *sched = key->schedule->data;
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, p, 8 );
    MD5_Init( inr_md5_ctx );
    MD5_Update( inr_md5_ctx, p, 0, 8 );
    MD5_Update( inr_md5_ctx, data, 0, len );
    MD5_Final( inr_md5_ctx, p + 8, 0 );
    memset( &ivec, 0, sizeof( ivec ) );
    DES3_ede_cbc_encrypt_decrypt(p, p, &sched[0], &sched[1], &sched[2],
                           3, &ivec, DES_ENCRYPT);
}
krb5_error_code
RSA_MD5_DES3_verify( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     struct key_data *key,
                     const void *data,
                     size_t len,
                     unsigned usage,
                     Checksum *C )
{
    MD5_CTX inr_md5_ctx;
    unsigned char tmp[24];
    unsigned char res[16];
    DES_cblock ivec;
    DES_key_schedule *sched = key->schedule->data;
    krb5_error_code ret = 0;
    memset( &ivec, 0, sizeof( ivec ) );
    DES3_ede_cbc_encrypt_decrypt((unsigned char*)C->checksum.data, tmp, &sched[0], &sched[1], &sched[2],
                           C->checksum.length/8, &ivec, DES_DECRYPT);
    MD5_Init( inr_md5_ctx );
    MD5_Update( inr_md5_ctx, tmp, 0, 8 );
    MD5_Update( inr_md5_ctx, data, 0, len );
    MD5_Final( inr_md5_ctx, res, 0 );
    if( memcmp( res, tmp + 8, sizeof( res ) ) != 0 ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    memset( tmp, 0, sizeof( tmp ) );
    memset( res, 0, sizeof( res ) );
    return ret;
}
void
SHA1_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               struct key_data *key,
               const void *data,
               size_t len,
               unsigned usage,
               Checksum *C )
{
    SHA1_CTX inr_sha_ctx;
    SHA1_Init( inr_sha_ctx );
    SHA1_Update( inr_sha_ctx, (char*)data,0, len );
    SHA1_Final( inr_sha_ctx, C->checksum.data, 0 );
}
krb5_error_code
hmac( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
      struct checksum_type *cm,
      const void *data,
      size_t len,
      unsigned usage,
      struct key_data *keyblock,
      Checksum *result )
{
    int inl_hash_type;
    int inl_len = HMAC_MAX_DIGEST_LEN;
    char chr_dest_array[HMAC_MAX_DIGEST_LEN];
    int inl_ret;
    switch(cm->type) {
        case CKSUMTYPE_RSA_MD5:
            inl_hash_type = HMAC_MD5_ID;
            break;
        case CKSUMTYPE_SHA1:
            inl_hash_type = HMAC_SHA1_ID;
            break;
        default:
            return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    inl_ret= GenHMAC(keyblock->key->keyvalue.data, 0,
	        keyblock->key->keyvalue.length, (char*) data, 0, len,
	        inl_hash_type, chr_dest_array, 0, &inl_len);
	memcpy(result->checksum.data,chr_dest_array, result->checksum.length);
	return inl_ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_hmac( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
           krb5_cksumtype cktype,
           const void *data,
           size_t len,
           unsigned usage,
           krb5_keyblock *key,
           Checksum *result )
{
    struct checksum_type *c = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, cktype );
    struct key_data kd;
    krb5_error_code ret;
    if( c == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"checksum type  not supported","crypto.c 1157" )
        ;
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    kd.key = key;
    kd.schedule = NULL;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, context, c, data, len, usage, &kd, result );
    if( kd.schedule )
        krb5_free_data(	NAME_OF_MAIN_LOC_GLOB_P, context, kd.schedule );
    return ret;
}
void
SP_HMAC_SHA1_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       struct key_data *key,
                       const void *data,
                       size_t len,
                       unsigned usage,
                       Checksum *result )
{
    struct checksum_type *c = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, CKSUMTYPE_SHA1 );
    Checksum res;
    char sha1_data[20];
    krb5_error_code ret;
    res.checksum.data = sha1_data;
    res.checksum.length = sizeof( sha1_data );
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, context, c, data, len, usage, key, &res );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10008: hmac failed" );
    memcpy( result->checksum.data, res.checksum.data, result->checksum.length );
}
/*
 * checksum according to section 5. of draft-brezak-win2k-krb-rc4-hmac-03.txt
 */
void
HMAC_MD5_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   struct key_data *key,
                   const void *data,
                   size_t len,
                   unsigned usage,
                   Checksum *result )
{
    MD5_CTX inr_md5_ctx;
    struct checksum_type *c = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, CKSUMTYPE_RSA_MD5 );
    const char signature[] = "signaturekey";
    Checksum ksign_c;
    struct key_data ksign;
    krb5_keyblock kb;
    unsigned char t[4];
    unsigned char tmp[16];
    unsigned char ksign_c_data[16];
    krb5_error_code ret;
    ksign_c.checksum.length = sizeof( ksign_c_data );
    ksign_c.checksum.data   = ksign_c_data;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, context, c, signature, sizeof( signature ), 0, key, &ksign_c );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10009: hmac failed" );
    ksign.key = &kb;
    kb.keyvalue = ksign_c.checksum;
    MD5_Init( inr_md5_ctx );
    t[0] = ( usage >>  0 ) & 0xFF;
    t[1] = ( usage >>  8 ) & 0xFF;
    t[2] = ( usage >> 16 ) & 0xFF;
    t[3] = ( usage >> 24 ) & 0xFF;
    MD5_Update( inr_md5_ctx, t, 0, 4 );
    MD5_Update( inr_md5_ctx, data, 0, len );
    MD5_Final( inr_md5_ctx, tmp, 0 );
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, context, c, tmp, sizeof( tmp ), 0, &ksign, result );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10010: hmac failed" );
}
/*
 * same as previous but being used while encrypting.
 */
void
HMAC_MD5_checksum_enc( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       struct key_data *key,
                       const void *data,
                       size_t len,
                       unsigned usage,
                       Checksum *result )
{
    struct checksum_type *c = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, CKSUMTYPE_RSA_MD5 );
    Checksum ksign_c;
    struct key_data ksign;
    krb5_keyblock kb;
    unsigned char t[4];
    unsigned char ksign_c_data[16];
    krb5_error_code ret;
    t[0] = ( usage >>  0 ) & 0xFF;
    t[1] = ( usage >>  8 ) & 0xFF;
    t[2] = ( usage >> 16 ) & 0xFF;
    t[3] = ( usage >> 24 ) & 0xFF;
    ksign_c.checksum.length = sizeof( ksign_c_data );
    ksign_c.checksum.data   = ksign_c_data;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, context, c, t, sizeof( t ), 0, key, &ksign_c );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10011: hmac failed" );
    ksign.key = &kb;
    kb.keyvalue = ksign_c.checksum;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, context, c, data, len, 0, &ksign, result );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10012: hmac failed" );
}

static struct checksum_type checksum_none= {
    CKSUMTYPE_NONE,
    "none",
    1,
    0,
    0,
    NONE_checksum,
    (( void * )0 )
};
static struct checksum_type checksum_crc32= {
    CKSUMTYPE_CRC32,
    "crc32",
    1,
    4,
    0,
    CRC32_checksum,
    (( void * )0 )
};
static struct checksum_type checksum_rsa_md4= {
    CKSUMTYPE_RSA_MD4,
    "rsa-md4",
    64,
    16,
    2,
    RSA_MD4_checksum,
    (( void * )0 )
};
static struct checksum_type checksum_rsa_md4_des= {
    CKSUMTYPE_RSA_MD4_DES,
    "rsa-md4-des",
    64,
    24,
    1 | 2 | 8,
    RSA_MD4_DES_checksum,
    RSA_MD4_DES_verify
};
static struct checksum_type checksum_rsa_md5= {
    CKSUMTYPE_RSA_MD5,
    "rsa-md5",
    64,
    16,
    2,
    RSA_MD5_checksum,
    (( void * )0 )
};
static struct checksum_type checksum_rsa_md5_des= {
    CKSUMTYPE_RSA_MD5_DES,
    "rsa-md5-des",
    64,
    24,
    1 | 2 | 8,
    RSA_MD5_DES_checksum,
    RSA_MD5_DES_verify
};
static struct checksum_type checksum_rsa_md5_des3= {
    CKSUMTYPE_RSA_MD5_DES3,
    "rsa-md5-des3",
    64,
    24,
    1 | 2 | 8,
    RSA_MD5_DES3_checksum,
    RSA_MD5_DES3_verify
};
static struct checksum_type checksum_sha1= {
    CKSUMTYPE_SHA1,
    "sha1",
    64,
    20,
    2,
    SHA1_checksum,
    (( void * )0 )
};
static struct checksum_type checksum_hmac_sha1_des3= {
    CKSUMTYPE_HMAC_SHA1_DES3,
    "hmac-sha1-des3",
    64,
    20,
    1 | 2 | 4,
    SP_HMAC_SHA1_checksum,
    (( void * )0 )
};
static struct checksum_type checksum_hmac_sha1_aes128= {
    CKSUMTYPE_HMAC_SHA1_96_AES_128,
    "hmac-sha1-96-aes128",
    64,
    12,
    1 | 2 | 4,
    SP_HMAC_SHA1_checksum,
    (( void * )0 )
};
static struct checksum_type checksum_hmac_sha1_aes256= {
    CKSUMTYPE_HMAC_SHA1_96_AES_256,
    "hmac-sha1-96-aes256",
    64,
    12,
    1 | 2 | 4,
    SP_HMAC_SHA1_checksum,
    (( void * )0 )
};
static struct checksum_type checksum_hmac_md5= {
    CKSUMTYPE_HMAC_MD5,
    "hmac-md5",
    64,
    16,
    1 | 2,
    HMAC_MD5_checksum,
    (( void * )0 )
};
static struct checksum_type checksum_hmac_md5_enc= {
    CKSUMTYPE_HMAC_MD5_ENC,
    "hmac-md5-enc",
    64,
    16,
    1 | 2 | 16,
    HMAC_MD5_checksum_enc,
    (( void * )0 )
};
static struct checksum_type *checksum_types[]= {
    &checksum_none,
    &checksum_crc32,
    &checksum_rsa_md4,
    &checksum_rsa_md4_des,

    &checksum_rsa_md5,
    &checksum_rsa_md5_des,
    &checksum_rsa_md5_des3,
    &checksum_sha1,
    &checksum_hmac_sha1_des3,
    &checksum_hmac_sha1_aes128,
    &checksum_hmac_sha1_aes256,
    &checksum_hmac_md5,
    &checksum_hmac_md5_enc
};
static int num_checksums=sizeof( checksum_types ) / sizeof( checksum_types[0] );

static struct checksum_type *
_find_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_cksumtype type ) {
    int i;
    for( i = 0; i < num_checksums; i++ )
        if( checksum_types[i]->type == type )
            return checksum_types[i];
    return NULL;
}
static krb5_error_code
get_checksum_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  krb5_crypto crypto,
                  unsigned usage,
                  struct checksum_type *ct,
                  struct key_data **key )
{
    krb5_error_code ret = 0;
    if( ct->flags & F_DERIVED )
        ret = _get_derived_key(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage, key );
    else if( ct->flags & F_VARIANT ) {
        int i;
        *key = _new_derived_key(	NAME_OF_MAIN_LOC_GLOB_P, crypto, 0xff );
        if( *key == NULL ) {
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1158" )
            ;
            return ENOMEM;
        }
        ret = krb5_copy_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto->key.key, &( *key )->key );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
        for( i = 0; i < ( *key )->key->keyvalue.length; i++ )
            (( unsigned char* )( *key )->key->keyvalue.data )[i] ^= 0xF0;
    } else {
        *key = &crypto->key;
    }
    if( ret == 0 )
        ret = _key_schedule(	NAME_OF_MAIN_LOC_GLOB_P, context, *key, crypto->params );
    return ret;
}
static krb5_error_code
create_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 struct checksum_type *ct,
                 krb5_crypto crypto,
                 unsigned usage,
                 void *data,
                 size_t len,
                 Checksum *result )
{
    krb5_error_code ret;
    struct key_data *dkey;
    int keyed_checksum;
    if( ct->flags & F_DISABLED ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    keyed_checksum = ( ct->flags & F_KEYED ) != 0;
    if( keyed_checksum && crypto == NULL ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    if( keyed_checksum ) {
        ret = get_checksum_key(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage, ct, &dkey );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
    } else
        dkey = NULL;
    result->cksumtype = ct->type;
    krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, &result->checksum, ct->checksumsize );
    ( *ct->checksum )( NAME_OF_MAIN_LOC_GLOB_P, context, dkey, data, len, usage, result );
    return 0;
}
static int
arcfour_checksum_p( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct checksum_type *ct, krb5_crypto crypto )
{
    return ( ct->type == CKSUMTYPE_HMAC_MD5 ) &&
           ( crypto->key.key->keytype == KEYTYPE_ARCFOUR );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_create_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      krb5_crypto crypto,
                      krb5_key_usage usage,
                      int type,
                      void *data,
                      size_t len,
                      Checksum *result )
{
    struct checksum_type *ct = NULL;
    unsigned keyusage;
    if( type ) {
        ct = _find_checksum(	NAME_OF_MAIN_LOC_GLOB_P, type );
    } else if( crypto ) {
        ct = crypto->et->keyed_checksum;
        if( ct == NULL )
            ct = crypto->et->checksum;
    }
    if( ct == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"checksum type  not supported","crypto.c 1159" )
        ;
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    if( arcfour_checksum_p( NAME_OF_MAIN_LOC_GLOB_P, ct, crypto ) ) {
        keyusage = usage;
        usage2arcfour(	NAME_OF_MAIN_LOC_GLOB_P, context, &keyusage );
    } else
        keyusage = CHECKSUM_USAGE( usage );
    return create_checksum( NAME_OF_MAIN_LOC_GLOB_P, context, ct, crypto, keyusage,
                            data, len, result );
}
static krb5_error_code
verify_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 krb5_crypto crypto,
                 unsigned usage,
                 void *data,
                 size_t len,
                 Checksum *cksum )
{
    krb5_error_code ret;
    struct key_data *dkey;
    int keyed_checksum;
    Checksum c;
    struct checksum_type *ct;
    ct = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, cksum->cksumtype );
    if( ct == NULL || ( ct->flags & F_DISABLED ) ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"checksum type  not supported","crypto.c 1160" )
        ;
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    if( ct->checksumsize != cksum->checksum.length ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    keyed_checksum = ( ct->flags & F_KEYED ) != 0;
    if( keyed_checksum && crypto == NULL ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    if( keyed_checksum )
        ret = get_checksum_key(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage, ct, &dkey );
    else
        dkey = NULL;
    if( ct->verify )
        return ( *ct->verify )(	NAME_OF_MAIN_LOC_GLOB_P, context, dkey, data, len, usage, cksum );
    ret = krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, &c.checksum, ct->checksumsize );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ( *ct->checksum )( NAME_OF_MAIN_LOC_GLOB_P, context, dkey, data, len, usage, &c );
    if( NAME_OF_MAIN_LOC_GLOB_P->im_control_5 ) {
        if( c.checksum.length != cksum->checksum.length ||
                memcmp( c.checksum.data, cksum->checksum.data, c.checksum.length ) ) {
            krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
            ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
        } else {
            ret = 0;
        }
    } else
        ret = 0;
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &c.checksum );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_verify_checksum( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      krb5_crypto crypto,
                      krb5_key_usage usage,
                      void *data,
                      size_t len,
                      Checksum *cksum )
{
    struct checksum_type *ct;
    unsigned keyusage;
    ct = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, cksum->cksumtype );
    if( ct == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"checksum type  not supported","crypto.c 1161" )
        ;
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    if( arcfour_checksum_p( NAME_OF_MAIN_LOC_GLOB_P, ct, crypto ) ) {
        keyusage = usage;
        usage2arcfour(	NAME_OF_MAIN_LOC_GLOB_P, context, &keyusage );
    } else
        keyusage = CHECKSUM_USAGE( usage );
    return verify_checksum( NAME_OF_MAIN_LOC_GLOB_P, context, crypto, keyusage,
                            data, len, cksum );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_crypto_get_checksum_type( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                               krb5_crypto crypto,
                               krb5_cksumtype *type )
{
    struct checksum_type *ct = NULL;
    if( crypto != NULL ) {
        ct = crypto->et->keyed_checksum;
        if( ct == NULL )
            ct = crypto->et->checksum;
    }
    if( ct == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"checksum type not found","crypto.c 1162" )
        ;
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    *type = ct->type;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_checksumsize( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_cksumtype type,
                   size_t *size )
{
    struct checksum_type *ct = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, type );
    if( ct == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"checksum type  not supported","crypto.c 1163" )
        ;
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    *size = ct->checksumsize;
    return 0;
}
krb5_boolean KRB5_LIB_FUNCTION
krb5_checksum_is_keyed( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                        krb5_cksumtype type )
{
    struct checksum_type *ct = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, type );
    if( ct == NULL ) {
        if( context )
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"checksum type  not supported","crypto.c 1164" )
            ;
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    return ct->flags & F_KEYED;
}
krb5_boolean KRB5_LIB_FUNCTION
krb5_checksum_is_collision_proof( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                  krb5_cksumtype type )
{
    struct checksum_type *ct = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, type );
    if( ct == NULL ) {
        if( context )
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"checksum type  not supported","crypto.c 1165" )
            ;
        return KRB5_PROG_SUMTYPE_NOSUPP;
    }
    return ct->flags & F_CPROOF;
}
/************************************************************
 *                                                          *
 ************************************************************/
krb5_error_code
NULL_encrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              struct key_data *key,
              void *data,
              size_t len,
              krb5_boolean encrypt,
              int usage,
              void *ivec )
{
    return 0;
}
krb5_error_code
DES3_CBC_encrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  struct key_data *key,
                  void *data,
                  size_t len,
                  krb5_boolean encrypt,
                  int usage,
                  void *ivec )
{
    DES_cblock local_ivec;
    DES_key_schedule *s = key->schedule->data;
    if( ivec == NULL ) {
        ivec = &local_ivec;
        memset( local_ivec, 0, sizeof( local_ivec ) );
    }
    DES3_ede_cbc_encrypt_decrypt((unsigned char *) data,
					 (unsigned char *) data,
                                         &s[0], &s[1], &s[2],
                                         len/DES_BLOCK_SIZE,
                                         (unsigned char *) ivec,
                                         encrypt ? DES_ENCRYPT : DES_DECRYPT);
    return 0;
}
/*
 * AES draft-raeburn-krb-rijndael-krb-02
 */
krb5_error_code
AES_CTS_encrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 struct key_data *key,
                 void *data,
                 size_t len,
                 krb5_boolean encrypt,
                 int usage,
                 void *ivec )
 {
     struct krb5_aes_schedule *aeskey = key->schedule->data;
     unsigned char local_ivec[AES_BLOCK_SIZE];
     ds_aes_key *k;
     int inl_rounds = (key->key->keyvalue.length /4)+6;
     if( encrypt )
         k = &aeskey->ekey;
     else
         k = &aeskey->dkey;
     if( len < AES_BLOCK_SIZE )
         //StSch Trace Point
         krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10013: invalid use of AES_CTS_encrypt" );
     if( len == AES_BLOCK_SIZE ) {
         if( encrypt )
             AES_Fast_ecb_encrypt((unsigned char *) data, (unsigned char *) data, k, 1, inl_rounds);
         else
             AES_Fast_ecb_decrypt((unsigned char *) data, (unsigned char *) data, k, 1, inl_rounds);
     } else {
         unsigned char * aucl_current_block = (unsigned char*)data;
         unsigned char aucl_temp_block[AES_BLOCK_SIZE];
         int inl_block_cnt_cbc = ( len - 1 ) / AES_BLOCK_SIZE ;
         int inl_last_cbc_offset = (inl_block_cnt_cbc * AES_BLOCK_SIZE);
         int inl_temp;
         if( ivec == NULL ) {
             memset( local_ivec, 0, sizeof( local_ivec ) );
             ivec = local_ivec;
         }
         if( encrypt ) {

             AES_Fast_cbc_encrypt(aucl_current_block,
                 aucl_current_block,
                 k,
                 inl_block_cnt_cbc,
                 (unsigned char *) ivec,
                 inl_rounds);
             aucl_current_block += inl_last_cbc_offset - AES_BLOCK_SIZE;
             len -= inl_last_cbc_offset;
             memcpy( aucl_temp_block, aucl_current_block, AES_BLOCK_SIZE );
             for( inl_last_cbc_offset = 0; inl_last_cbc_offset < len; inl_last_cbc_offset++ )
                 aucl_current_block[inl_last_cbc_offset] = aucl_current_block[inl_last_cbc_offset + AES_BLOCK_SIZE] ^ aucl_temp_block[inl_last_cbc_offset];
             AES_Fast_ecb_encrypt(aucl_current_block, aucl_current_block, k, 1, inl_rounds);
             memcpy(aucl_current_block+AES_BLOCK_SIZE, aucl_temp_block, len);
             /*if( ivec )
             memcpy( ivec, aucl_current_block, blocksize );*/ /** @todo Check ivec return */
         }
         else {
             aucl_current_block += inl_last_cbc_offset-AES_BLOCK_SIZE;
             AES_Fast_ecb_decrypt(aucl_current_block, aucl_temp_block, k, 1, inl_rounds);
             len -= inl_last_cbc_offset;
             memcpy(aucl_current_block,aucl_current_block+AES_BLOCK_SIZE, len);
             memcpy(aucl_current_block+len,aucl_temp_block+len,AES_BLOCK_SIZE-len);
             for( inl_last_cbc_offset = 0; inl_last_cbc_offset < len; inl_last_cbc_offset++ )
                 aucl_current_block[inl_last_cbc_offset + AES_BLOCK_SIZE] = aucl_current_block[inl_last_cbc_offset] ^ aucl_temp_block[inl_last_cbc_offset];
             AES_Fast_cbc_decrypt((unsigned char *) data,
                 (unsigned char *) data,
                 k,
                 inl_block_cnt_cbc,
                 (unsigned char *) ivec,
                 inl_rounds);
         }
     }
     return 0;
 }
krb5_error_code
AES_CBC_encrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 struct key_data *key,
                 void *data,
                 size_t len,
                 krb5_boolean encrypt,
                 int usage,
                 void *ivec )
 {
     struct krb5_aes_schedule *aeskey = key->schedule->data;
     char local_ivec[AES_BLOCK_SIZE];
     int inl_rounds = (key->key->keyvalue.length /4)+6;
     ds_aes_key *k;
     if( ivec == NULL ) {
         ivec = &local_ivec;
         memset( local_ivec, 0, sizeof( local_ivec ) );
     }
     if( encrypt ) {
         k = &aeskey->ekey;
         AES_Fast_cbc_encrypt((unsigned char *) data,
             (unsigned char *) data,
             k,
             len/AES_BLOCK_SIZE,
             (unsigned char *) ivec,
             inl_rounds);
     } else {
         k = &aeskey->dkey;
         AES_Fast_cbc_decrypt((unsigned char *) data,
             (unsigned char *) data,
             k,
             len/16,
             (unsigned char *) ivec,
             inl_rounds);
     }
     return 0;
 }
/*
 * RC2
 */
/*
 * section 6 of draft-brezak-win2k-krb-rc4-hmac-03
 *
 * warning: not for small children
 */
static krb5_error_code
ARCFOUR_subencrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    struct key_data *key,
                    void *data,
                    size_t len,
                    unsigned usage,
                    void *ivec )
{
    struct checksum_type *c = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, CKSUMTYPE_RSA_MD5 );
    Checksum k1_c, k2_c, k3_c, cksum;
    struct key_data ke;
    krb5_keyblock kb;
    unsigned char t[4];
    RC4_KEY rc4_key;
    unsigned char *cdata = data;
    unsigned char k1_c_data[16], k2_c_data[16], k3_c_data[16];
    krb5_error_code ret;
    t[0] = ( usage >>  0 ) & 0xFF;
    t[1] = ( usage >>  8 ) & 0xFF;
    t[2] = ( usage >> 16 ) & 0xFF;
    t[3] = ( usage >> 24 ) & 0xFF;
    k1_c.checksum.length = sizeof( k1_c_data );
    k1_c.checksum.data   = k1_c_data;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, NULL, c, t, sizeof( t ), 0, key, &k1_c );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10014: hmac failed" );
    memcpy( k2_c_data, k1_c_data, sizeof( k1_c_data ) );
    k2_c.checksum.length = sizeof( k2_c_data );
    k2_c.checksum.data   = k2_c_data;
    ke.key = &kb;
    kb.keyvalue = k2_c.checksum;
    cksum.checksum.length = 16;
    cksum.checksum.data   = data;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, NULL, c, cdata + 16, len - 16, 0, &ke, &cksum );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10015: hmac failed" );
    ke.key = &kb;
    kb.keyvalue = k1_c.checksum;
    k3_c.checksum.length = sizeof( k3_c_data );
    k3_c.checksum.data   = k3_c_data;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, NULL, c, data, 16, 0, &ke, &k3_c );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10016: hmac failed" );
    RC4_SetKey( rc4_key, k3_c.checksum.data, 0, k3_c.checksum.length );
    RC4( cdata + 16, 0, len - 16, cdata + 16, 0, rc4_key );
    memset( k1_c_data, 0, sizeof( k1_c_data ) );
    memset( k2_c_data, 0, sizeof( k2_c_data ) );
    memset( k3_c_data, 0, sizeof( k3_c_data ) );
    return 0;
}
static krb5_error_code
ARCFOUR_subdecrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    struct key_data *key,
                    void *data,
                    size_t len,
                    unsigned usage,
                    void *ivec )
{
    struct checksum_type *c = _find_checksum( NAME_OF_MAIN_LOC_GLOB_P, CKSUMTYPE_RSA_MD5 );
    Checksum k1_c, k2_c, k3_c, cksum;
    struct key_data ke;
    krb5_keyblock kb;
    unsigned char t[4];
    RC4_KEY rc4_key;
    unsigned char *cdata = data;
    unsigned char k1_c_data[16], k2_c_data[16], k3_c_data[16];
    unsigned char cksum_data[16];
    krb5_error_code ret;
    t[0] = ( usage >>  0 ) & 0xFF;
    t[1] = ( usage >>  8 ) & 0xFF;
    t[2] = ( usage >> 16 ) & 0xFF;
    t[3] = ( usage >> 24 ) & 0xFF;
    k1_c.checksum.length = sizeof( k1_c_data );
    k1_c.checksum.data   = k1_c_data;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, NULL, c, t, sizeof( t ), 0, key, &k1_c );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10017: hmac failed" );
    memcpy( k2_c_data, k1_c_data, sizeof( k1_c_data ) );
    k2_c.checksum.length = sizeof( k2_c_data );
    k2_c.checksum.data   = k2_c_data;
    ke.key = &kb;
    kb.keyvalue = k1_c.checksum;
    k3_c.checksum.length = sizeof( k3_c_data );
    k3_c.checksum.data   = k3_c_data;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, NULL, c, cdata, 16, 0, &ke, &k3_c );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10018: hmac failed" );
    RC4_SetKey( rc4_key, k3_c.checksum.data, 0, k3_c.checksum.length );
    RC4( cdata + 16, 0, len - 16, cdata + 16, 0, rc4_key );
    ke.key = &kb;
    kb.keyvalue = k2_c.checksum;
    cksum.checksum.length = 16;
    cksum.checksum.data   = cksum_data;
    ret = hmac( NAME_OF_MAIN_LOC_GLOB_P, NULL, c, cdata + 16, len - 16, 0, &ke, &cksum );
    if( ret )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"crypto.c 10019: hmac failed" );
    memset( k1_c_data, 0, sizeof( k1_c_data ) );
    memset( k2_c_data, 0, sizeof( k2_c_data ) );
    memset( k3_c_data, 0, sizeof( k3_c_data ) );
    if( memcmp( cksum.checksum.data, data, 16 ) != 0 ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5KRB_AP_ERR_BAD_INTEGRITY;
    } else {
        return 0;
    }
}
/*
 * convert the usage numbers used in
 * draft-ietf-cat-kerb-key-derivation-00.txt to the ones in
 * draft-brezak-win2k-krb-rc4-hmac-04.txt
 */
static krb5_error_code
usage2arcfour( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, unsigned *usage )
{
    switch( *usage ) {
    case KRB5_KU_AS_REP_ENC_PART :
        case KRB5_KU_TGS_REP_ENC_PART_SUB_KEY :
                *usage = 8;
        return 0;
    case KRB5_KU_USAGE_SEAL :
            *usage = 13;
        return 0;
    case KRB5_KU_USAGE_SIGN :
            *usage = 15;
        return 0;
    case KRB5_KU_USAGE_SEQ:
            *usage = 0;
        return 0;
    default :
            return 0;
    }
}
krb5_error_code
ARCFOUR_encrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 struct key_data *key,
                 void *data,
                 size_t len,
                 krb5_boolean encrypt,
                 int usage,
                 void *ivec )
{
    krb5_error_code ret;
    unsigned keyusage = usage;
    if(( ret = usage2arcfour( NAME_OF_MAIN_LOC_GLOB_P, context, &keyusage ) ) != 0 )
        return ret;
    if( encrypt )
        return ARCFOUR_subencrypt(	NAME_OF_MAIN_LOC_GLOB_P, context, key, data, len, keyusage, ivec );
    else
        return ARCFOUR_subdecrypt(	NAME_OF_MAIN_LOC_GLOB_P, context, key, data, len, keyusage, ivec );
}
/*
 * these should currently be in reverse preference order.
 * (only relevant for !F_PSEUDO) */


struct encryption_type enctype_null= {
    ETYPE_NULL,
    "null",
    (( void * )0 ),
    1,
    1,
    0,
    &keytype_null,
    &checksum_none,
    (( void * )0 ),
    64,
    NULL_encrypt,
};
struct encryption_type enctype_arcfour_hmac_md5= {
    ETYPE_ARCFOUR_HMAC_MD5,
    "arcfour-hmac-md5",
    (( void * )0 ),
    1,
    1,
    8,
    &keytype_arcfour,
    &checksum_hmac_md5,
    (( void * )0 ),
    32,
    ARCFOUR_encrypt
};
struct encryption_type enctype_des3_cbc_sha1= {
    ETYPE_DES3_CBC_SHA1,
    "des3-cbc-sha1",
    (( void * )0 ),
    8,
    8,
    8,
    &keytype_des3_derived,
    &checksum_sha1,
    &checksum_hmac_sha1_des3,
    4,
    DES3_CBC_encrypt,
};
struct encryption_type enctype_aes128_cts_hmac_sha1= {
    ETYPE_AES128_CTS_HMAC_SHA1_96,
    "aes128-cts-hmac-sha1-96",
    (( void * )0 ),
    16,
    1,
    16,
    &keytype_aes128,
    &checksum_sha1,
    &checksum_hmac_sha1_aes128,
    4,
    AES_CTS_encrypt,
};
struct encryption_type enctype_aes256_cts_hmac_sha1= {
    ETYPE_AES256_CTS_HMAC_SHA1_96,
    "aes256-cts-hmac-sha1-96",
    (( void * )0 ),
    16,
    1,
    16,
    &keytype_aes256,
    &checksum_sha1,
    &checksum_hmac_sha1_aes256,
    4,
    AES_CTS_encrypt,
};
unsigned aes_128_cbc_num[9]= { 2, 16, 840, 1, 101, 3, 4, 1, 2 };
heim_oid aes_128_cbc_oid= { sizeof( aes_128_cbc_num )/sizeof( aes_128_cbc_num[0] ), aes_128_cbc_num };
struct encryption_type enctype_aes128_cbc_none= {
    ETYPE_AES128_CBC_NONE,
    "aes128-cbc-none",
    &aes_128_cbc_oid,
    16,
    16,
    16,
    &keytype_aes128,
    &checksum_none,
    (( void * )0 ),
    16|128,
    AES_CBC_encrypt,
};
unsigned aes_192_cbc_num[9]= { 2, 16, 840, 1, 101, 3, 4, 1, 22 };
heim_oid aes_192_cbc_oid= { sizeof( aes_192_cbc_num )/sizeof( aes_192_cbc_num[0] ), aes_192_cbc_num };
struct encryption_type enctype_aes192_cbc_none= {
    ETYPE_AES192_CBC_NONE,
    "aes192-cbc-none",
    &aes_192_cbc_oid,
    16,
    16,
    16,
    &keytype_aes192,
    &checksum_none,
    (( void * )0 ),
    16|128,
    AES_CBC_encrypt,
};
unsigned aes_256_cbc_num[9]= { 2, 16, 840, 1, 101, 3, 4, 1, 42 };
heim_oid aes_256_cbc_oid= { sizeof( aes_256_cbc_num )/sizeof( aes_256_cbc_num[0] ), aes_256_cbc_num };
struct encryption_type enctype_aes256_cbc_none= {
    ETYPE_AES256_CBC_NONE,
    "aes256-cbc-none",
    &aes_256_cbc_oid,
    16,
    16,
    16,
    &keytype_aes256,
    &checksum_none,
    (( void * )0 ),
    16|128,
    AES_CBC_encrypt,
};
struct encryption_type *etypes[8]= {
    &enctype_null,
    &enctype_des3_cbc_sha1,
    &enctype_aes128_cts_hmac_sha1,
    &enctype_aes256_cts_hmac_sha1,
    &enctype_aes128_cbc_none,
    &enctype_aes192_cbc_none,
    &enctype_aes256_cbc_none,
    &enctype_arcfour_hmac_md5
};
unsigned num_etypes=sizeof( etypes ) / sizeof( etypes[0] );

static struct encryption_type *
_find_enctype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_enctype type ) {
    int i;
    for( i = 0; i < num_etypes; i++ )
        if( etypes[i]->type == type )
            return etypes[i];
    return NULL;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_string_to_enctype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                        const char *string,
                        krb5_enctype *etype )
{
    int i;
    for( i = 0; i < num_etypes; i++ )
        if( strcmp( etypes[i]->name, string ) == 0 ) {
            *etype = etypes[i]->type;
            return 0;
        }
    krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P, context,"encryption type  not supported","crypto.c 1169" )
    ;
    return KRB5_PROG_ETYPE_NOSUPP;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_enctype_to_keytype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                         krb5_enctype etype,
                         krb5_keytype *keytype )
{
    struct encryption_type *e = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, etype );
    if( e == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"encryption type  not supported","crypto.c 1173" )
        ;
        return KRB5_PROG_ETYPE_NOSUPP;
    }
    *keytype = e->keytype->type;
    return 0;
}
/*
 * First take the configured list of etypes for `keytype' if available,
 * else, do `krb5_keytype_to_enctypes'.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_enctype_valid( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_enctype etype )
{
    struct encryption_type *e = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, etype );
    if( e == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"encryption type  not supported","crypto.c 1176" )
        ;
        return KRB5_PROG_ETYPE_NOSUPP;
    }
    if( e->flags & F_DISABLED ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"encryption type  is disabled","crypto.c 1177" )
        ;
        return KRB5_PROG_ETYPE_NOSUPP;
    }
    return 0;
}
krb5_boolean KRB5_LIB_FUNCTION
krb5_enctypes_compatible_keys( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                               krb5_enctype etype1,
                               krb5_enctype etype2 )
{
    struct encryption_type *e1 = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, etype1 );
    struct encryption_type *e2 = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, etype2 );
    return e1 != NULL && e2 != NULL && e1->keytype == e2->keytype;
}
static krb5_boolean
derived_crypto( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_crypto crypto )
{
    return ( crypto->et->flags & F_DERIVED ) != 0;
}
static krb5_boolean
special_crypto( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_crypto crypto )
{
    return ( crypto->et->flags & F_SPECIAL ) != 0;
}
static krb5_error_code
encrypt_internal_derived( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          krb5_crypto crypto,
                          unsigned usage,
                          void *data,
                          size_t len,
                          krb5_data *result,
                          void *ivec )
{
    size_t sz, block_sz, checksum_sz, total_sz;
    Checksum cksum;
    unsigned char *p, *q;
    krb5_error_code ret;
    struct key_data *dkey;
    const struct encryption_type *et = crypto->et;
    checksum_sz = CHECKSUMSIZE( et->keyed_checksum );
    sz = et->confoundersize + len;
    block_sz = ( sz + et->padsize - 1 ) &~( et->padsize - 1 );
    total_sz = block_sz + checksum_sz;
    p =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( total_sz ) ),'\0',( 1 ) * ( total_sz ) )
        ;
    if( p == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1180" )
        ;
        return ENOMEM;
    }
    q = p;
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, q, et->confoundersize );
    q += et->confoundersize;
    memcpy( q, data, len );
    ret = create_checksum( NAME_OF_MAIN_LOC_GLOB_P, context,
                           et->keyed_checksum,
                           crypto,
                           INTEGRITY_USAGE( usage ),
                           p,
                           block_sz,
                           &cksum );
    if( ret == 0 && cksum.checksum.length != checksum_sz ) {
        free_Checksum(	NAME_OF_MAIN_LOC_GLOB_P, &cksum );
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5_CRYPTO_INTERNAL;
    }
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    memcpy( p + block_sz, cksum.checksum.data, cksum.checksum.length );
    free_Checksum( NAME_OF_MAIN_LOC_GLOB_P, &cksum );
    ret = _get_derived_key( NAME_OF_MAIN_LOC_GLOB_P, context, crypto, ENCRYPTION_USAGE( usage ), &dkey );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    ret = _key_schedule( NAME_OF_MAIN_LOC_GLOB_P, context, dkey, crypto->params );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
#ifdef CRYPTO_DEBUG
    krb5_crypto_debug( context, 1, block_sz, dkey->key );
#endif
    ret = ( *et->encrypt )( NAME_OF_MAIN_LOC_GLOB_P, context, dkey, p, block_sz, 1, usage, ivec );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    result->data = p;
    result->length = total_sz;
    return 0;
    fail:
    memset( p, 0, total_sz );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
    ;
    return ret;
}
static krb5_error_code
encrypt_internal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  krb5_crypto crypto,
                  void *data,
                  size_t len,
                  krb5_data *result,
                  void *ivec )
{
    size_t sz, block_sz, checksum_sz, padsize = 0;
    Checksum cksum;
    unsigned char *p, *q;
    krb5_error_code ret;
    const struct encryption_type *et = crypto->et;
    checksum_sz = CHECKSUMSIZE( et->checksum );
    sz = et->confoundersize + checksum_sz + len;
    block_sz = ( sz + et->padsize - 1 ) &~( et->padsize - 1 );
    if(( et->flags & F_PADCMS ) && et->padsize != 1 ) {
        padsize = et->padsize - ( sz % et->padsize );
        if( padsize == et->padsize )
            block_sz += et->padsize;
    }
    p =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( block_sz ) ),'\0',( 1 ) * ( block_sz ) )
        ;
    if( p == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1181" )
        ;
        return ENOMEM;
    }
    q = p;
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, q, et->confoundersize );
    q += et->confoundersize;
    memset( q, 0, checksum_sz );
    q += checksum_sz;
    memcpy( q, data, len );
    ret = create_checksum( NAME_OF_MAIN_LOC_GLOB_P, context,
                           et->checksum,
                           crypto,
                           0,
                           p,
                           block_sz,
                           &cksum );
    if( ret == 0 && cksum.checksum.length != checksum_sz ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        free_Checksum(	NAME_OF_MAIN_LOC_GLOB_P, &cksum );
        ret = KRB5_CRYPTO_INTERNAL;
    }
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    memcpy( p + et->confoundersize, cksum.checksum.data, cksum.checksum.length );
    free_Checksum( NAME_OF_MAIN_LOC_GLOB_P, &cksum );
    ret = _key_schedule( NAME_OF_MAIN_LOC_GLOB_P, context, &crypto->key, crypto->params );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    if( et->flags & F_PADCMS ) {
        int i;
        q = p + len + checksum_sz + et->confoundersize;
        for( i = 0; i < padsize; i++ )
            q[i] = padsize;
    }
#ifdef CRYPTO_DEBUG
    krb5_crypto_debug( context, 1, block_sz, crypto->key.key );
#endif
    ret = ( *et->encrypt )( NAME_OF_MAIN_LOC_GLOB_P, context, &crypto->key, p, block_sz, 1, 0, ivec );
    if( ret ) {
        //StSch Trace Point
        memset( p, 0, block_sz );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    result->data = p;
    result->length = block_sz;
    return 0;
    fail:
    memset( p, 0, block_sz );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
    ;
    return ret;
}
static krb5_error_code
encrypt_internal_special( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          krb5_crypto crypto,
                          int usage,
                          void *data,
                          size_t len,
                          krb5_data *result,
                          void *ivec )
{
    struct encryption_type *et = crypto->et;
    size_t cksum_sz = CHECKSUMSIZE( et->checksum );
    size_t sz = len + cksum_sz + et->confoundersize;
    char *tmp, *p;
    krb5_error_code ret;
    tmp =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sz )
        ;
    if( tmp == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1182" )
        ;
        return ENOMEM;
    }
    p = tmp;
    memset( p, 0, cksum_sz );
    p += cksum_sz;
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, p, et->confoundersize );
    p += et->confoundersize;
    memcpy( p, data, len );
    ret = ( *et->encrypt )( NAME_OF_MAIN_LOC_GLOB_P, context, &crypto->key, tmp, sz, TRUE, usage, ivec );
    if( ret ) {
        //StSch Trace Point
        memset( tmp, 0, sz );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tmp )
        ;
        return ret;
    }
    result->data   = tmp;
    result->length = sz;
    return 0;
}
static krb5_error_code
decrypt_internal_derived( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          krb5_crypto crypto,
                          unsigned usage,
                          void *data,
                          size_t len,
                          krb5_data *result,
                          void *ivec )
{
    size_t checksum_sz;
    Checksum cksum;
    unsigned char *p;
    krb5_error_code ret;
    struct key_data *dkey;
    struct encryption_type *et = crypto->et;
    unsigned long l;
    checksum_sz = CHECKSUMSIZE( et->keyed_checksum );
    if( len < checksum_sz ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return EINVAL;
    }
    if((( len - checksum_sz ) % et->padsize ) != 0 ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5_BAD_MSIZE;
    }
    p =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    if( len != 0 && p == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1183" )
        ;
        return ENOMEM;
    }
    memcpy( p, data, len );
    len -= checksum_sz;
    ret = _get_derived_key( NAME_OF_MAIN_LOC_GLOB_P, context, crypto, ENCRYPTION_USAGE( usage ), &dkey );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    ret = _key_schedule( NAME_OF_MAIN_LOC_GLOB_P, context, dkey, crypto->params );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
#ifdef CRYPTO_DEBUG
    krb5_crypto_debug( context, 0, len, dkey->key );
#endif
    ret = ( *et->encrypt )( NAME_OF_MAIN_LOC_GLOB_P, context, dkey, p, len, 0, usage, ivec );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    cksum.checksum.data   = p + len;
    cksum.checksum.length = checksum_sz;
    cksum.cksumtype       = CHECKSUMTYPE( et->keyed_checksum );
    ret = verify_checksum( NAME_OF_MAIN_LOC_GLOB_P, context,
                           crypto,
                           INTEGRITY_USAGE( usage ),
                           p,
                           len,
                           &cksum );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    l = len - et->confoundersize;
    memmove( p, p + et->confoundersize, l );
    result->data =
        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p, l )
        ;
    if( result->data == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1184" )
        ;
        return ENOMEM;
    }
    result->length = l;
    return 0;
}
static krb5_error_code
decrypt_internal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  krb5_crypto crypto,
                  void *data,
                  size_t len,
                  krb5_data *result,
                  void *ivec )
{
    krb5_error_code ret;
    unsigned char *p;
    Checksum cksum;
    size_t checksum_sz, l;
    struct encryption_type *et = crypto->et;
    if(( len % et->padsize ) != 0 ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5_BAD_MSIZE;
    }
    checksum_sz = CHECKSUMSIZE( et->checksum );
    p =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    if( len != 0 && p == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1185" )
        ;
        return ENOMEM;
    }
    memcpy( p, data, len );
    ret = _key_schedule( NAME_OF_MAIN_LOC_GLOB_P, context, &crypto->key, crypto->params );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
#ifdef CRYPTO_DEBUG
    krb5_crypto_debug( context, 0, len, crypto->key.key );
#endif
    ret = ( *et->encrypt )( NAME_OF_MAIN_LOC_GLOB_P, context, &crypto->key, p, len, 0, 0, ivec );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    ret = krb5_data_copy( NAME_OF_MAIN_LOC_GLOB_P, &cksum.checksum, p + et->confoundersize, checksum_sz );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    memset( p + et->confoundersize, 0, checksum_sz );
    cksum.cksumtype = CHECKSUMTYPE( et->checksum );
    ret = verify_checksum( NAME_OF_MAIN_LOC_GLOB_P, context, NULL, 0, p, len, &cksum );
    free_Checksum( NAME_OF_MAIN_LOC_GLOB_P, &cksum );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    l = len - et->confoundersize - checksum_sz;
    memmove( p, p + et->confoundersize + checksum_sz, l );
    result->data =
        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p, l )
        ;
    if( result->data == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1186" )
        ;
        return ENOMEM;
    }
    result->length = l;
    return 0;
}
static krb5_error_code
decrypt_internal_special( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          krb5_crypto crypto,
                          int usage,
                          void *data,
                          size_t len,
                          krb5_data *result,
                          void *ivec )
{
    struct encryption_type *et = crypto->et;
    size_t cksum_sz = CHECKSUMSIZE( et->checksum );
    size_t sz = len - cksum_sz - et->confoundersize;
    unsigned char *p;
    krb5_error_code ret;
    if(( len % et->padsize ) != 0 ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5_BAD_MSIZE;
    }
    p =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    if( p == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1187" )
        ;
        return ENOMEM;
    }
    memcpy( p, data, len );
    ret = ( *et->encrypt )( NAME_OF_MAIN_LOC_GLOB_P, context, &crypto->key, p, len, FALSE, usage, ivec );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    memmove( p, p + cksum_sz + et->confoundersize, sz );
    result->data =
        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p, sz )
        ;
    if( result->data == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1188" )
        ;
        return ENOMEM;
    }
    result->length = sz;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_encrypt_ivec( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_crypto crypto,
                   unsigned usage,
                   void *data,
                   size_t len,
                   krb5_data *result,
                   void *ivec )
{
    if( derived_crypto( NAME_OF_MAIN_LOC_GLOB_P, context, crypto ) )
        return encrypt_internal_derived(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage,
                                            data, len, result, ivec );
    else if( special_crypto( NAME_OF_MAIN_LOC_GLOB_P, context, crypto ) )
        return encrypt_internal_special(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage,
                                            data, len, result, ivec );
    else
        return encrypt_internal(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, data, len, result, ivec );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_encrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_crypto crypto,
              unsigned usage,
              void *data,
              size_t len,
              krb5_data *result )
{
    return krb5_encrypt_ivec( NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage, data, len, result, NULL );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_encrypt_EncryptedData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                            krb5_crypto crypto,
                            unsigned usage,
                            void *data,
                            size_t len,
                            int kvno,
                            EncryptedData *result )
{
    result->etype = CRYPTO_ETYPE( crypto );
    if( kvno ) {
        ALLOC( result->kvno, 1 );
        *result->kvno = kvno;
    } else
        result->kvno = NULL;
    return krb5_encrypt( NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage, data, len, &result->cipher );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decrypt_ivec( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_crypto crypto,
                   unsigned usage,
                   void *data,
                   size_t len,
                   krb5_data *result,
                   void *ivec )
{
    if( derived_crypto( NAME_OF_MAIN_LOC_GLOB_P, context, crypto ) )
        return decrypt_internal_derived(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage,
                                            data, len, result, ivec );
    else if( special_crypto( NAME_OF_MAIN_LOC_GLOB_P, context, crypto ) )
        return decrypt_internal_special(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage,
                                            data, len, result, ivec );
    else
        return decrypt_internal(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, data, len, result, ivec );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decrypt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_crypto crypto,
              unsigned usage,
              void *data,
              size_t len,
              krb5_data *result )
{
    return krb5_decrypt_ivec( NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage, data, len, result,
                              NULL );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decrypt_EncryptedData( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                            krb5_crypto crypto,
                            unsigned usage,
                            const EncryptedData *e,
                            krb5_data *result )
{
    return krb5_decrypt( NAME_OF_MAIN_LOC_GLOB_P, context, crypto, usage,
                         e->cipher.data, e->cipher.length, result );
}
/************************************************************
 *                                                          *
 ************************************************************/
#ifdef HAVE_OPENSSL
#include <openssl/rand.h>
#define ENTROPY_NEEDED 20
static int
seed_something( void )
{
    char buf[1024], seedfile[256];
    /* If there is a seed file, load it. But such a file cannot be trusted,
       so use 0 for the entropy estimate */
    if( RAND_file_name( seedfile, sizeof( seedfile ) ) ) {
        int fd;
        fd = open( seedfile, O_RDONLY );
        if( fd >= 0 ) {
            ssize_t ret;
            ret = read( fd, buf, sizeof( buf ) );
            if( ret > 0 )
                RAND_add( buf, ret, 0.0 );
            close( fd );
        } else
            seedfile[0] = '\0';
    } else
        seedfile[0] = '\0';
    /* Calling RAND_status() will try to use /dev/urandom if it exists so
       we do not have to deal with it. */
    if( RAND_status() != 1 ) {
        krb5_context context;
        const char *p;
        if( !krb5_init_context( &context ) ) {
            p = krb5_config_get_string( context, NULL, "libdefaults",
                                        "egd_socket", NULL );
            if( p != NULL )
                RAND_egd_bytes( p, ENTROPY_NEEDED );
            krb5_free_context( context );
        }
    }
    if( RAND_status() == 1 )	{
        if( seedfile[0] )
            RAND_write_file( seedfile );
        return 0;
    } else
        return -1;
}
void KRB5_LIB_FUNCTION
krb5_generate_random_block( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, void *buf, size_t len )
{
    if( !rng_initialized ) {
        if( seed_something() )
            //StSch Trace Point
            krb5_abortx(	NAME_OF_MAIN_LOC_GLOB_P, NULL,"crypto.c 10020: Fatal: could not seed the random number generator" );
        rng_initialized = 1;
    }
    RAND_bytes( buf, len );
}
#else
#ifndef HOB_KRB5_UNIT_TEST
void KRB5_LIB_FUNCTION
krb5_generate_random_block( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, void *buf, size_t len )
{
   // Just use the HOB DRBG
   if(m_secdrbg_randbytes((char*)buf, len) != 0){
      // DRBG not initialized, throw external error nr.
      m_throw_exception(5);
   }
}
#endif
#endif
static void
DES3_postproc( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               unsigned char *k, size_t len, struct key_data *key )
{
    DES3_random_to_key( NAME_OF_MAIN_LOC_GLOB_P, context, key->key, k, len );
    if( key->schedule ) {
        krb5_free_data(	NAME_OF_MAIN_LOC_GLOB_P, context, key->schedule );
        key->schedule = NULL;
    }
}
static krb5_error_code
derive_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
            struct encryption_type *et,
            struct key_data *key,
            const void *constant,
            size_t len )
{
    unsigned char *k;
    unsigned int nblocks = 0, i;
    krb5_error_code ret = 0;
    struct key_type *kt = et->keytype;
    /* since RC2 is only the weird crypto alg with parameter and this
     * function not defined with work with RC2, this is ok */
    ret = _key_schedule( NAME_OF_MAIN_LOC_GLOB_P, context, key, NULL );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( et->blocksize * 8 < kt->bits ||
            len != et->blocksize ) {
        nblocks = ( kt->bits + et->blocksize * 8 - 1 ) / ( et->blocksize * 8 );
        k =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, nblocks * et->blocksize )
            ;
        if( k == NULL ) {
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1189" )
            ;
            return ENOMEM;
        }
        _krb5_n_fold(	NAME_OF_MAIN_LOC_GLOB_P, constant, len, k, et->blocksize );
        for( i = 0; i < nblocks; i++ ) {
            if( i > 0 )
                memcpy( k + i * et->blocksize,
                        k + ( i - 1 ) * et->blocksize,
                        et->blocksize );
            ( *et->encrypt )(	NAME_OF_MAIN_LOC_GLOB_P, context, key, k + i * et->blocksize, et->blocksize,
                                1, 0, NULL );
        }
    } else {
        void *c =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
            ;
        size_t res_len = ( kt->bits + 7 ) / 8;
        if( len != 0 && c == NULL ) {
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1190" )
            ;
            return ENOMEM;
        }
        memcpy( c, constant, len );
        ( *et->encrypt )(	NAME_OF_MAIN_LOC_GLOB_P, context, key, c, len, 1, 0, NULL );
        k =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, res_len )
            ;
        if( res_len != 0 && k == NULL ) {
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, c )
            ;
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1191" )
            ;
            return ENOMEM;
        }
        _krb5_n_fold(	NAME_OF_MAIN_LOC_GLOB_P, c, len, k, res_len );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, c )
        ;
    }
    switch( kt->type ) {
    case KEYTYPE_DES3:
            DES3_postproc(	NAME_OF_MAIN_LOC_GLOB_P, context, k, nblocks * et->blocksize, key );
        break;
    case KEYTYPE_AES128:
        case KEYTYPE_AES256:
                memcpy( key->key->keyvalue.data, k, key->key->keyvalue.length );
        break;
    default:
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"derive_key() called with unknown keytype ()","crypto.c 1192" )
            ;
        ret = KRB5_CRYPTO_INTERNAL;
        break;
    }
    if( key->schedule ) {
        krb5_free_data(	NAME_OF_MAIN_LOC_GLOB_P, context, key->schedule );
        key->schedule = NULL;
    }
    memset( k, 0, nblocks * et->blocksize );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, k )
    ;
    return ret;
}
static struct key_data *
_new_derived_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_crypto crypto, unsigned usage ) {
    struct key_usage *d = crypto->key_usage;
    d =

        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, d, ( crypto->num_key_usage + 1 ) * sizeof( *d ) )
        ;
    if( d == NULL )
        return NULL;
    crypto->key_usage = d;
    d += crypto->num_key_usage++;
    memset( d, 0, sizeof( *d ) );
    d->usage = usage;
    return &d->key;
}
static krb5_error_code
_get_derived_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  krb5_crypto crypto,
                  unsigned usage,
                  struct key_data **key )
{
    int i;
    struct key_data *d;
    unsigned char constant[5];
    for( i = 0; i < crypto->num_key_usage; i++ )
        if( crypto->key_usage[i].usage == usage ) {
            *key = &crypto->key_usage[i].key;
            return 0;
        }
    d = _new_derived_key( NAME_OF_MAIN_LOC_GLOB_P, crypto, usage );
    if( d == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1194" )
        ;
        return ENOMEM;
    }
    krb5_copy_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, crypto->key.key, &d->key );
    _krb5_put_int( NAME_OF_MAIN_LOC_GLOB_P, constant, usage, 5 );
    derive_key( NAME_OF_MAIN_LOC_GLOB_P, context, crypto->et, d, constant, sizeof( constant ) );
    *key = d;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_crypto_init( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  const krb5_keyblock *key,
                  krb5_enctype etype,
                  krb5_crypto *crypto )
{
    krb5_error_code ret;
    ALLOC( *crypto, 1 );
    if( *crypto == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1195" )
        ;
        return ENOMEM;
    }
    if( etype == ETYPE_NULL )
        etype = key->keytype;
    ( *crypto )->et = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, etype );
    if(( *crypto )->et == NULL || (( *crypto )->et->flags & F_DISABLED ) ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *crypto )
        ;
        *crypto = NULL;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"encryption type  not supported","crypto.c 1196" )
        ;
        return KRB5_PROG_ETYPE_NOSUPP;
    }
    if(( *crypto )->et->keytype->minsize > key->keyvalue.length ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *crypto )
        ;
        *crypto = NULL;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"encryption key has bad length","crypto.c 1197" )
        ;
        return KRB5_BAD_KEYSIZE;
    }
    ret = krb5_copy_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, key, &( *crypto )->key.key );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *crypto )
        ;
        *crypto = NULL;
        return ret;
    }
    ( *crypto )->key.schedule = NULL;
    ( *crypto )->num_key_usage = 0;
    ( *crypto )->key_usage = NULL;
    ( *crypto )->params = NULL;
    return 0;
}
static void
free_key_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, struct key_data *key )
{
    krb5_free_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, key->key );
    if( key->schedule ) {
        memset( key->schedule->data, 0, key->schedule->length );
        krb5_free_data(	NAME_OF_MAIN_LOC_GLOB_P, context, key->schedule );
    }
}
static void
free_key_usage( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, struct key_usage *ku )
{
    free_key_data( NAME_OF_MAIN_LOC_GLOB_P, context, &ku->key );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_crypto_destroy( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     krb5_crypto crypto )
{
    int i;
    for( i = 0; i < crypto->num_key_usage; i++ )
        free_key_usage(	NAME_OF_MAIN_LOC_GLOB_P, context, &crypto->key_usage[i] );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, crypto->key_usage )
    ;
    free_key_data( NAME_OF_MAIN_LOC_GLOB_P, context, &crypto->key );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, crypto->params )
    ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, crypto )
    ;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_crypto_getpadsize( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                        krb5_crypto crypto,
                        size_t *padsize )
{
    *padsize = crypto->et->padsize;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_string_to_key_derived( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                            const void *str,
                            size_t len,
                            krb5_enctype etype,
                            krb5_keyblock *key )
{
    struct encryption_type *et = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, etype );
    krb5_error_code ret;
    struct key_data kd;
    size_t keylen = et->keytype->bits / 8;
    u_char *tmp;
    if( et == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"encryption type  not supported","crypto.c 1202" )
        ;
        return KRB5_PROG_ETYPE_NOSUPP;
    }
    ALLOC( kd.key, 1 );
    if( kd.key == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1203" )
        ;
        return ENOMEM;
    }
    ret = krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, &kd.key->keyvalue, et->keytype->size );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, kd.key )
        ;
        return ret;
    }
    kd.key->keytype = etype;
    tmp =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, keylen )
        ;
    if( tmp == NULL ) {
        krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, kd.key );
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","crypto.c 1204" )
        ;
        return ENOMEM;
    }
    _krb5_n_fold( NAME_OF_MAIN_LOC_GLOB_P, str, len, tmp, keylen );
    kd.schedule = NULL;
    DES3_postproc( NAME_OF_MAIN_LOC_GLOB_P, context, tmp, keylen, &kd );
    memset( tmp, 0, keylen );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tmp )
    ;
    ret = derive_key( NAME_OF_MAIN_LOC_GLOB_P, context,
                      et,
                      &kd,
                      "kerberos",
                      strlen( "kerberos" ) );
    ret = krb5_copy_keyblock_contents( NAME_OF_MAIN_LOC_GLOB_P, context, kd.key, key );
    free_key_data( NAME_OF_MAIN_LOC_GLOB_P, context, &kd );
    return ret;
}
static size_t
wrapped_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_crypto  crypto,
                size_t       data_len )
{
    struct encryption_type *et = crypto->et;
    size_t padsize = et->padsize;
    size_t checksumsize = CHECKSUMSIZE( et->checksum );
    size_t res;
    res =  et->confoundersize + checksumsize + data_len;
    res = ( res + padsize - 1 ) / padsize * padsize;
    return res;
}
static size_t
wrapped_length_dervied( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                        krb5_crypto  crypto,
                        size_t       data_len )
{
    struct encryption_type *et = crypto->et;
    size_t padsize = et->padsize;
    size_t res;
    res =  et->confoundersize + data_len;
    res = ( res + padsize - 1 ) / padsize * padsize;
    if( et->keyed_checksum )
        res += et->keyed_checksum->checksumsize;
    else
        res += et->checksum->checksumsize;
    return res;
}
/*
 * Return the size of an encrypted packet of length `data_len'
 */
size_t
krb5_get_wrapped_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                         krb5_crypto  crypto,
                         size_t       data_len )
{
    if( derived_crypto( NAME_OF_MAIN_LOC_GLOB_P, context, crypto ) )
        return wrapped_length_dervied(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, data_len );
    else
        return wrapped_length(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto, data_len );
}
#ifdef CRYPTO_DEBUG
static krb5_error_code
krb5_get_keyid( krb5_context context,
                krb5_keyblock *key,
                u_int32_t *keyid )
{
    MD5_CTX inr_md5_ctx;
    unsigned char tmp[16];
    MD5_Init( &md5 );
    MD5_Update( &md5, key->keyvalue.data, key->keyvalue.length );
    MD5_Final( tmp, &md5 );
    *keyid = ( tmp[12] << 24 ) | ( tmp[13] << 16 ) | ( tmp[14] << 8 ) | tmp[15];
    return 0;
}
static void
krb5_crypto_debug( krb5_context context,
                   int encrypt,
                   size_t len,
                   krb5_keyblock *key )
{
    u_int32_t keyid;
    char *kt;
    krb5_get_keyid( context, key, &keyid );
    krb5_enctype_to_string( context, key->keytype, &kt );
    krb5_warnx( context, "%s %lu bytes with key-id %#x (%s)",
                encrypt ? "encrypting" : "decrypting",
                ( unsigned long )len,
                keyid,
                kt );
    m_stor_free_hl( kt );
}
#endif
void KRB5_LIB_FUNCTION
krb5_data_zero( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data *p )
{
    p->length = 0;
    p->data   = NULL;
}
void KRB5_LIB_FUNCTION
krb5_data_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data *p )
{
    if( p->data != NULL )
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p->data )
        ;
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, p );
}
void KRB5_LIB_FUNCTION
krb5_free_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_data *p )
{
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, p );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_data_alloc( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data *p, int len )
{
    p->data =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    if( len && p->data == NULL )
        return ENOMEM;
    p->length = len;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_data_copy( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data *p, const void *data, size_t len )
{
    if( len ) {
        if( krb5_data_alloc(	NAME_OF_MAIN_LOC_GLOB_P, p, len ) )
            return ENOMEM;
        memmove( p->data, data, len );
    } else
        p->data = NULL;
    p->length = len;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_copy_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                const krb5_data *indata,
                krb5_data **outdata )
{
    krb5_error_code ret;
    ALLOC( *outdata, 1 );
    if( *outdata == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","data.c 1336" )
        ;
        return ENOMEM;
    }
    ret = copy_octet_string( NAME_OF_MAIN_LOC_GLOB_P, indata, *outdata );
    if( ret ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *outdata )
        ;
    }
    return ret;
}
/*
 * return the length of the mechanism in token or -1
 * (which implies that the token was bad - GSS_S_DEFECTIVE_TOKEN
 */
ssize_t
gssapi_krb5_get_mech( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const u_char *ptr,
                      size_t total_len,
                      const u_char **mech_ret )
{
    size_t len, len_len, mech_len, foo;
    const u_char *p = ptr;
    int e;
    if( total_len < 1 )
        return -1;
    if( *p++ != 0x60 )
        return -1;
    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, total_len - 1, &len, &len_len );
    if( e || 1 + len_len + len != total_len )
        return -1;
    p += len_len;
    if( *p++ != 0x06 )
        return -1;
    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, total_len - 1 - len_len - 1,
                        &mech_len, &foo );
    if( e )
        return -1;
    p += foo;
    *mech_ret = p;
    return mech_len;
}
OM_uint32
_gssapi_verify_mech_header( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, u_char **str,
                            size_t total_len,
                            gss_OID mech )
{
    const u_char *p;
    ssize_t mech_len;
    mech_len = gssapi_krb5_get_mech( NAME_OF_MAIN_LOC_GLOB_P, *str, total_len, &p );
    if( mech_len < 0 )
        return GSS_S_DEFECTIVE_TOKEN;
    if( mech_len != mech->length )
        return GSS_S_BAD_MECH;
    if( memcmp( p,
                mech->elements,
                mech->length ) != 0 )
        return GSS_S_BAD_MECH;
    p += mech_len;
    *str = ( char * )p;
    return GSS_S_COMPLETE;
}
OM_uint32
gssapi_krb5_verify_header( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, u_char **str,
                           size_t total_len,
                           u_char *type,
                           gss_OID oid )
{
    OM_uint32 ret;
    size_t len;
    u_char *p = *str;
    ret = _gssapi_verify_mech_header( NAME_OF_MAIN_LOC_GLOB_P, str, total_len, oid );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    len = total_len - ( *str - p );
    if( len < 2 )
        return GSS_S_DEFECTIVE_TOKEN;
    if( memcmp( *str, type, 2 ) != 0 )
        return GSS_S_DEFECTIVE_TOKEN;
    *str += 2;
    return 0;
}
/*
 * Remove the GSS-API wrapping from `in_token' giving `out_data.
 * Does not copy data, so just free `in_token'.
 */
/*
 * Remove the GSS-API wrapping from `in_token' giving `out_data.
 * Does not copy data, so just free `in_token'.
 */
OM_uint32
gssapi_krb5_decapsulate( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 *minor_status,
                         gss_buffer_t input_token_buffer,
                         krb5_data *out_data,
                         char *type,
                         gss_OID oid )
{
    u_char *p;
    OM_uint32 ret;
    p = input_token_buffer->value;
    ret = gssapi_krb5_verify_header( NAME_OF_MAIN_LOC_GLOB_P, &p,
                                     input_token_buffer->length,
                                     type,
                                     oid );
    if( ret ) {
        //StSch Trace Point
        *minor_status = 0;
        return ret;
    }
    out_data->length = input_token_buffer->length -
                       ( p - ( u_char * )input_token_buffer->value );
    out_data->data   = p;
    return GSS_S_COMPLETE;
}
/*
 * Verify padding of a gss wrapped message and return its length.
 */
OM_uint32
_gssapi_verify_pad( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, gss_buffer_t wrapped_token,
                    size_t datalen,
                    size_t *padlen )
{
    u_char *pad;
    size_t padlength;
    int i;
    pad = ( u_char * )wrapped_token->value + wrapped_token->length - 1;
    padlength = *pad;
    if( padlength > datalen )
        return GSS_S_BAD_MECH;
    for( i = padlength; i > 0 && *pad == padlength; i--, pad-- )
        ;
    if( i != 0 )
        return GSS_S_BAD_MIC;
    *padlen = padlength;
    return 0;
}
int
copy_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const heim_general_string *from, heim_general_string *to )
{
    *to = m_strdup_hl( NAME_OF_MAIN_LOC_GLOB_P, *from );
    if( *to == NULL )
        return ENOMEM;
    return 0;
}
int
copy_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const heim_octet_string *from, heim_octet_string *to )
{
    to->length = from->length;
    to->data   =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, to->length )
        ;
    if( to->length != 0 && to->data == NULL )
        return ENOMEM;
    memcpy( to->data, from->data, to->length );
    return 0;
}
void
free_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, heim_general_string *str )
{
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *str )
    ;
    *str = NULL;
}
void
free_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, heim_octet_string *k )
{
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, k->data )
    ;
    k->data = NULL;
}
/*
 * All decoding functions take a pointer `p' to first position in
 * which to read, from the left, `len' which means the maximum number
 * of characters we are able to read, `ret' were the value will be
 * returned and `size' where the number of used bytes is stored.
 * Either 0 or an error code is returned.
 */
static int
der_get_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                  unsigned *ret, size_t *size )
{
    unsigned val = 0;
    size_t oldlen = len;
    while( len-- )
        val = val * 256 + *p++;
    *ret = val;
    if( size ) *size = oldlen;
    return 0;
}
int
der_get_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
             int *ret, size_t *size )
{
    int val = 0;
    size_t oldlen = len;
    if( len > 0 ) {
        val = ( signed char )*p++;
        while( --len )
            val = val * 256 + *p++;
    }
    *ret = val;
    if( size ) *size = oldlen;
    return 0;
}
int
der_get_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                size_t *val, size_t *size )
{
    size_t v;
    if( len <= 0 )
        return ASN1_OVERRUN;
    --len;
    v = *p++;
    if( v < 128 ) {
        *val = v;
        if( size ) *size = 1;
    } else {
        int e;
        size_t l;
        unsigned tmp;
        if( v == 0x80 ) {
            *val = ASN1_INDEFINITE;
            if( size ) *size = 1;
            return 0;
        }
        v &= 0x7F;
        if( len < v )
            return ASN1_OVERRUN;
        e = der_get_unsigned(	NAME_OF_MAIN_LOC_GLOB_P, p, v, &tmp, &l );
        if( e ) return e;
        *val = tmp;
        if( size ) *size = l + 1;
    }
    return 0;
}
int
der_get_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                        heim_general_string *str, size_t *size )
{
    char *s;
    s =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len + 1 )
        ;
    if( s == NULL )
        return ENOMEM;
    memcpy( s, p, len );
    s[len] = '\0';
    *str = s;
    if( size ) *size = len;
    return 0;
}
int
der_get_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                      heim_octet_string *data, size_t *size )
{
    data->length = len;
    data->data =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    if( data->data == NULL && data->length != 0 )
        return ENOMEM;
    memcpy( data->data, p, len );
    if( size ) *size = len;
    return 0;
}
int
der_get_tag( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
             Der_class *class, Der_type *type,
             int *tag, size_t *size )
{
    if( len < 1 )
        return ASN1_OVERRUN;
    *class = ( Der_class )((( *p ) >> 6 ) & 0x03 );
    *type = ( Der_type )((( *p ) >> 5 ) & 0x01 );
    *tag = ( *p ) & 0x1F;
    if( size ) *size = 1;
    return 0;
}
int
der_match_tag( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
               Der_class class, Der_type type,
               int tag, size_t *size )
{
    size_t l;
    Der_class thisclass;
    Der_type thistype;
    int thistag;
    int e;
    e = der_get_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, &thisclass, &thistype, &thistag, &l );
    if( e ) return e;
    if( class != thisclass || type != thistype )
        return ASN1_BAD_ID;
    if( tag > thistag )
        return ASN1_MISPLACED_FIELD;
    if( tag < thistag )
        return ASN1_MISSING_FIELD;
    if( size ) *size = l;
    return 0;
}
int
der_match_tag_and_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                          Der_class class, Der_type type, int tag,
                          size_t *length_ret, size_t *size )
{
    size_t l, ret = 0;
    int e;
    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, class, type, tag, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, length_ret, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( size ) *size = ret;
    return 0;
}
int
decode_integer( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                int *num, size_t *size )
{
    size_t ret = 0;
    size_t l, reallen;
    int e;
    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, PRIM, UT_Integer, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &reallen, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( reallen > len )
        return ASN1_OVERRUN;
    e = der_get_int( NAME_OF_MAIN_LOC_GLOB_P, p, reallen, num, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( size ) *size = ret;
    return 0;
}
int
decode_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                 unsigned *num, size_t *size )
{
    size_t ret = 0;
    size_t l, reallen;
    int e;
    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, PRIM, UT_Integer, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &reallen, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( reallen > len )
        return ASN1_OVERRUN;
    e = der_get_unsigned( NAME_OF_MAIN_LOC_GLOB_P, p, reallen, num, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( size ) *size = ret;
    return 0;
}
int
decode_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                       heim_general_string *str, size_t *size )
{
    size_t ret = 0;
    size_t l, reallen;
    int e;
    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, PRIM, UT_GeneralString, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &reallen, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( len < reallen )
        return ASN1_OVERRUN;
    e = der_get_general_string( NAME_OF_MAIN_LOC_GLOB_P, p, reallen, str, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( size ) *size = ret;
    return 0;
}
int
decode_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                     heim_octet_string *k, size_t *size )
{
    size_t ret = 0;
    size_t l, reallen;
    int e;
    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, PRIM, UT_OctetString, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &reallen, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( len < reallen )
        return ASN1_OVERRUN;
    e = der_get_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, reallen, k, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( size ) *size = ret;
    return 0;
}
static void
generalizedtime2time( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const char *s, time_t *t )
{
    struct tm tm;
    memset( &tm, 0, sizeof( tm ) );
    sscanf( s, "%04d%02d%02d%02d%02d%02dZ",
            &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
            &tm.tm_min, &tm.tm_sec );
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    *t = m_timegm_hl( NAME_OF_MAIN_LOC_GLOB_P, &tm );
}
int
decode_generalized_time( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned char *p, size_t len,
                         time_t *t, size_t *size )
{
    heim_octet_string k;
    char *times;
    size_t ret = 0;
    size_t l, reallen;
    int e;
    e = der_match_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, ASN1_C_UNIV, PRIM, UT_GeneralizedTime, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    e = der_get_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, &reallen, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    if( len < reallen )
        return ASN1_OVERRUN;
    e = der_get_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, reallen, &k, &l );
    if( e ) return e;
    p += l;
    len -= l;
    ret += l;
    times =
        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, k.data, k.length + 1 )
        ;
    if( times == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, k.data )
        ;
        return ENOMEM;
    }
    times[k.length] = 0;
    generalizedtime2time( NAME_OF_MAIN_LOC_GLOB_P, times, t );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, times )
    ;
    if( size ) *size = ret;
    return 0;
}
int
fix_dce( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, size_t reallen, size_t *len )
{
    if( reallen == ASN1_INDEFINITE )
        return 1;
    if( *len < reallen )
        return -1;
    *len = reallen;
    return 0;
}
size_t
_heim_len_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned val )
{
    size_t ret = 0;
    do {
        ++ret;
        val /= 256;
    } while( val );
    return ret;
}
size_t
_heim_len_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int val )
{
    unsigned char q;
    size_t ret = 0;
    if( val >= 0 ) {
        do {
            q = val % 256;
            ret++;
            val /= 256;
        } while( val );
        if( q >= 128 )
            ret++;
    } else {
        val = ~val;
        do {
            q = ~( val % 256 );
            ret++;
            val /= 256;
        } while( val );
        if( q < 128 )
            ret++;
    }
    return ret;
}
size_t
length_len( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, size_t len )
{
    if( len < 128 )
        return 1;
    else
        return _heim_len_unsigned(	NAME_OF_MAIN_LOC_GLOB_P, len ) + 1;
}
size_t
length_boolean( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const int *data )
{
    return 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, 1 ) + 1;
}
size_t
length_integer( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const int *data )
{
    size_t len = _heim_len_int( NAME_OF_MAIN_LOC_GLOB_P, *data );
    return 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, len ) + len;
}
size_t
length_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const unsigned *data )
{
    unsigned val = *data;
    size_t len = 0;
    while( val > 255 ) {
        ++len;
        val /= 256;
    }
    len++;
    if( val >= 128 )
        len++;
    return 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, len ) + len;
}
size_t
length_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const heim_general_string *data )
{
    char *str = *data;
    size_t len = strlen( str );
    return 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, len ) + len;
}
size_t
length_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const heim_octet_string *k )
{
    return 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, k->length ) + k->length;
}
size_t
length_generalized_time( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const time_t *t )
{
    heim_octet_string k;
    size_t ret;
    time2generalizedtime( NAME_OF_MAIN_LOC_GLOB_P, *t, &k );
    ret = 1 + length_len( NAME_OF_MAIN_LOC_GLOB_P, k.length ) + k.length;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, k.data )
    ;
    return ret;
}
void int_to_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int im_number,char * ach_buffer );
/*
 * All encoding functions take a pointer `p' to first position in
 * which to write, from the right, `len' which means the maximum
 * number of characters we are able to write.  The function returns
 * the number of characters written in `size' (if non-NULL).
 * The return value is 0 or an error.
 */
static int
der_put_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, unsigned val, size_t *size )
{
    unsigned char *base = p;
    if( val ) {
        while( len > 0 && val ) {
            *p-- = val % 256;
            val /= 256;
            --len;
        }
        if( val != 0 )
            return ASN1_OVERFLOW;
        else {
            *size = base - p;
            return 0;
        }
    } else if( len < 1 )
        return ASN1_OVERFLOW;
    else {
        *p    = 0;
        *size = 1;
        return 0;
    }
}
int
der_put_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, int val, size_t *size )
{
    unsigned char *base = p;
    if( val >= 0 ) {
        do {
            if( len < 1 )
                return ASN1_OVERFLOW;
            *p-- = val % 256;
            len--;
            val /= 256;
        } while( val );
        if( p[1] >= 128 ) {
            if( len < 1 )
                return ASN1_OVERFLOW;
            *p-- = 0;
            len--;
        }
    } else {
        val = ~val;
        do {
            if( len < 1 )
                return ASN1_OVERFLOW;
            *p-- = ~( val % 256 );
            len--;
            val /= 256;
        } while( val );
        if( p[1] < 128 ) {
            if( len < 1 )
                return ASN1_OVERFLOW;
            *p-- = 0xff;
            len--;
        }
    }
    *size = base - p;
    return 0;
}
int
der_put_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, size_t val, size_t *size )
{
    if( len < 1 )
        return ASN1_OVERFLOW;
    if( val < 128 ) {
        *p = val;
        *size = 1;
        return 0;
    } else {
        size_t l;
        int e;
        e = der_put_unsigned(	NAME_OF_MAIN_LOC_GLOB_P, p, len - 1, val, &l );
        if( e )
            return e;
        p -= l;
        *p = 0x80 | l;
        *size = l + 1;
        return 0;
    }
}
int
der_put_boolean( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const int *data, size_t *size )
{
    if( len < 1 )
        return ASN1_OVERFLOW;
    if( *data != 0 )
        *p = 0xff;
    else
        *p = 0;
    *size = 1;
    return 0;
}
int
der_put_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                        const heim_general_string *str, size_t *size )
{
    size_t slen = strlen( *str );
    if( len < slen )
        return ASN1_OVERFLOW;
    p -= slen;
    len -= slen;
    memcpy( p+1, *str, slen );
    *size = slen;
    return 0;
}
int
der_put_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                      const heim_octet_string *data, size_t *size )
{
    if( len < data->length )
        return ASN1_OVERFLOW;
    p -= data->length;
    len -= data->length;
    memcpy( p+1, data->data, data->length );
    *size = data->length;
    return 0;
}
int
der_put_tag( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, Der_class class, Der_type type,
             int tag, size_t *size )
{
    if( len < 1 )
        return ASN1_OVERFLOW;
    *p = ( class << 6 ) | ( type << 5 ) | tag;
    *size = 1;
    return 0;
}
int
der_put_length_and_tag( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, size_t len_val,
                        Der_class class, Der_type type, int tag, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int e;
    e = der_put_length( NAME_OF_MAIN_LOC_GLOB_P, p, len, len_val, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, class, type, tag, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}
int
encode_boolean( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const int *data,
                size_t *size )
{
    size_t ret = 0;
    size_t l;
    int e;
    e = der_put_boolean( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, l, ASN1_C_UNIV, PRIM, UT_Boolean, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}
int
encode_integer( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const int *data, size_t *size )
{
    int num = *data;
    size_t ret = 0;
    size_t l;
    int e;
    e = der_put_int( NAME_OF_MAIN_LOC_GLOB_P, p, len, num, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, l, ASN1_C_UNIV, PRIM, UT_Integer, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}
int
encode_unsigned( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len, const unsigned *data,
                 size_t *size )
{
    unsigned num = *data;
    size_t ret = 0;
    size_t l;
    int e;
    e = der_put_unsigned( NAME_OF_MAIN_LOC_GLOB_P, p, len, num, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    if( p[1] >= 128 ) {
        if( len == 0 )
            return ASN1_OVERFLOW;
        *p-- = 0;
        len--;
        ret++;
        l++;
    }
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, l, ASN1_C_UNIV, PRIM, UT_Integer, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}
int
encode_general_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                       const heim_general_string *data, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int e;
    e = der_put_general_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, data, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, l, ASN1_C_UNIV, PRIM, UT_GeneralString, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}
int
encode_octet_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                     const heim_octet_string *k, size_t *size )
{
    size_t ret = 0;
    size_t l;
    int e;
    e = der_put_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, k, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, l, ASN1_C_UNIV, PRIM, UT_OctetString, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}
int
time2generalizedtime( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, time_t t, heim_octet_string *s )
{
    struct tm *tm;
    size_t len;
    char * temp;
    len = 15;
    s->data =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len + 1 )
        ;
    if( s->data == NULL )
        return ENOMEM;
    s->length = len;
    tm = gmtime( &t );
    temp = ( char* )s->data;
    int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_year + 1900,temp );
    temp = temp+4;
    if( tm->tm_mon + 1 < 10 ) {
        *temp = '0';
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_mon + 1,temp+1 );
    } else {
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_mon + 1,temp );
    }
    temp = temp+2;
    if( tm->tm_mday < 10 ) {
        *temp = '0';
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_mday,temp+1 );
    } else {
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_mday,temp );
    }
    temp = temp+2;
    if( tm->tm_hour < 10 ) {
        *temp = '0';
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_hour,temp+1 );
    } else {
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_hour,temp );
    }
    temp = temp+2;
    if( tm->tm_min < 10 ) {
        *temp = '0';
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_min,temp+1 );
    } else {
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_min,temp );
    }
    temp = temp+2;
    if( tm->tm_sec < 10 ) {
        *temp = '0';
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_sec,temp+1 );
    } else {
        int_to_string( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_sec,temp );
    }
    temp = temp+2;
    *temp = 'Z';
    return 0;
}
int
encode_generalized_time( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, size_t len,
                         const time_t *t, size_t *size )
{
    size_t ret = 0;
    size_t l;
    heim_octet_string k;
    int e;
    e = time2generalizedtime( NAME_OF_MAIN_LOC_GLOB_P, *t, &k );
    if( e )
        return e;
    e = der_put_octet_string( NAME_OF_MAIN_LOC_GLOB_P, p, len, &k, &l );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, k.data )
    ;
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    e = der_put_length_and_tag( NAME_OF_MAIN_LOC_GLOB_P, p, len, k.length, ASN1_C_UNIV, PRIM,
                                UT_GeneralizedTime, &l );
    if( e )
        return e;
    p -= l;
    len -= l;
    ret += l;
    *size = ret;
    return 0;
}
/*
 * The document that got me started for real was "Efficient
 * Implementation of the Data Encryption Standard" by Dag Arne Osvik.
 * I never got to the PC1 transformation was working, instead I used
 * table-lookup was used for all key schedule setup. The document was
 * very useful since it de-mystified other implementations for me.
 *
 * The core DES function (SBOX + P transformation) is from Richard
 * Outerbridge public domain DES implementation. My sanity is saved
 * thanks to his work. Thank you Richard.
 */

static unsigned char odd_parity[256] = {
    1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
    112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
    128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
    145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
    161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
    176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
    193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
    208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
    224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
    241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254,
};

int
DES_set_odd_parity( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock *key )
{
    int i;
    for( i = 0; i < DES_CBLOCK_LEN; i++ )
        ( *key )[i] = odd_parity[( *key )[i]];
    return 0;
}
/*
 *
 */

static DES_cblock weak_keys[16]= {
    {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
    {0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE},
    {0x1F,0x1F,0x1F,0x1F,0x0E,0x0E,0x0E,0x0E},
    {0xE0,0xE0,0xE0,0xE0,0xF1,0xF1,0xF1,0xF1},
    {0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE},
    {0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01},
    {0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1},
    {0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E},
    {0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1},
    {0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01},
    {0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE},
    {0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E},
    {0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E},
    {0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01},
    {0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
    {0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1}
};

int
DES_is_weak_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock *key )
{
    int i;
    for( i = 0; i < sizeof( weak_keys )/sizeof( weak_keys[0] ); i++ ) {
        if( memcmp(	weak_keys[i], key, DES_CBLOCK_LEN ) == 0 )
            return 1;
    }
    return 0;
}

/* D3DES (V5.09) -
 *
 * A portable, public domain, version of the Data Encryption Standard.
 *
 * Written with Symantec's THINK (Lightspeed) C by Richard Outerbridge.
 * Thanks to: Dan Hoey for his excellent Initial and Inverse permutation
 * code;  Jim Gillogly & Phil Karn for the DES key schedule code; Dennis
 * Ferguson, Eric Young and Dana How for comparing notes; and Ray Lau,
 * for humouring me on.
 *
 * Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.
 * (GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1992.
 */
void
gssapi_krb5_set_error_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P
                            )
{
}
void
_gssapi_encap_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, size_t data_len,
                      size_t *len,
                      size_t *total_len,
                      const gss_OID mech )
{
    size_t len_len;
    *len = 1 + 1 + mech->length + data_len;
    len_len = length_len( NAME_OF_MAIN_LOC_GLOB_P, *len );
    *total_len = 1 + len_len + *len;
}
void
gssapi_krb5_encap_length( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, size_t data_len,
                          size_t *len,
                          size_t *total_len,
                          const gss_OID mech )
{
    _gssapi_encap_length( NAME_OF_MAIN_LOC_GLOB_P, data_len + 2, len, total_len, mech );
}
u_char *
gssapi_krb5_make_header( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, u_char *p,
                         size_t len,
                         const u_char *type,
                         const gss_OID mech )
{
    p = _gssapi_make_mech_header( NAME_OF_MAIN_LOC_GLOB_P, p, len, mech );
    memcpy( p, type, 2 );
    p += 2;
    return p;
}
u_char *
_gssapi_make_mech_header( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, u_char *p,
                          size_t len,
                          const gss_OID mech )
{
    int e;
    size_t len_len, foo;
    *p++ = 0x60;
    len_len = length_len( NAME_OF_MAIN_LOC_GLOB_P, len );
    e = der_put_length( NAME_OF_MAIN_LOC_GLOB_P, p + len_len - 1, len_len, len, &foo );
    if( e || foo != len_len )
        //StSch Trace Point
        m_end_exit_abort_hl(	NAME_OF_MAIN_LOC_GLOB_P, 'a',0 )
        ;
    p += len_len;
    *p++ = 0x06;
    *p++ = mech->length;
    memcpy( p, mech->elements, mech->length );
    p += mech->length;
    return p;
}
/*
 * Give it a krb5_data and it will encapsulate with extra GSS-API krb5
 * wrappings.
 */
OM_uint32
gssapi_krb5_encapsulate( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 *minor_status,
                         const krb5_data *in_data,
                         gss_buffer_t output_token,
                         const u_char *type,
                         const gss_OID mech
                       )
{
    size_t len, outer_len;
    u_char *p;
    gssapi_krb5_encap_length( NAME_OF_MAIN_LOC_GLOB_P, in_data->length, &len, &outer_len, mech );
    output_token->length = outer_len;
    output_token->value  =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, outer_len )
        ;
    if( output_token->value == NULL ) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    p = gssapi_krb5_make_header( NAME_OF_MAIN_LOC_GLOB_P, output_token->value, len, type, mech );
    memcpy( p, in_data->data, in_data->length );
    return GSS_S_COMPLETE;
}
const char *
com_right( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct et_list *list, long code )
{
    struct et_list *p;
    for( p = list; p; p = p->next ) {
        if( code >= p->table->base && code < p->table->base + p->table->n_msgs )
            return p->table->msgs[code - p->table->base];
    }
    return NULL;
}
struct foobar {
    struct et_list etl;
    struct error_table et;
};
void
initialize_error_table_r( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct et_list **list,
                          const char **messages,
                          int num_errors,
                          long base )
{
    struct et_list *et, **end;
    struct foobar *f;
    for( end = list, et = *list; et; end = &et->next, et = et->next )
        if( et->table->msgs == messages )
            return;
    f =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *f ) )
        ;
    if( f == NULL )
        return;
    et = &f->etl;
    et->table = &f->et;
    et->table->msgs = messages;
    et->table->n_msgs = num_errors;
    et->table->base = base;
    et->next = NULL;
    *end = et;
}

void
free_error_table( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct et_list *et )
{
    while( et ) {
        struct et_list *p = et;
        et = et->next;
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
    }
}
void KRB5_LIB_FUNCTION
krb5_clear_error_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context )
{
    /*memset( NAME_OF_MAIN_LOC_GLOB_P->
            error_string,'\0',ERROR_STRING_LEN );*/
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_set_error_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, const char *fmt, const char *file )
{
    krb5_error_code ret = 0;
    /*m_strlcat_hl( NAME_OF_MAIN_LOC_GLOB_P,                   NAME_OF_MAIN_LOC_GLOB_P->
                  error_string,file,sizeof( NAME_OF_MAIN_LOC_GLOB_P->
                                            error_string ) );
    m_strlcat_hl( NAME_OF_MAIN_LOC_GLOB_P,                   NAME_OF_MAIN_LOC_GLOB_P->
                  error_string,": ",sizeof( NAME_OF_MAIN_LOC_GLOB_P->
                                            error_string ) );
    m_strlcat_hl( NAME_OF_MAIN_LOC_GLOB_P,                   NAME_OF_MAIN_LOC_GLOB_P->
                  error_string,fmt,sizeof( NAME_OF_MAIN_LOC_GLOB_P->
                                           error_string ) );*/
    return ret;
}
char * KRB5_LIB_FUNCTION
krb5_get_error_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context )
{
    char *ret;
    if( krb5_have_error_string( NAME_OF_MAIN_LOC_GLOB_P, context ) ) {
        /*ret = ( char* )
              memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( ERROR_STRING_LEN ) * ( sizeof( char ) ) ),'\0',( ERROR_STRING_LEN ) * ( sizeof( char ) ) )
              ;
        ret = memcpy( ret,                          NAME_OF_MAIN_LOC_GLOB_P->
                      error_string,ERROR_STRING_LEN );
        memset( NAME_OF_MAIN_LOC_GLOB_P->
                error_string,'\0',ERROR_STRING_LEN );*/
    } else
        ret = NULL;
    return ret;
}
krb5_boolean KRB5_LIB_FUNCTION
krb5_have_error_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context )
{
   /* return strcmp( "",                       NAME_OF_MAIN_LOC_GLOB_P->
                   error_string ) != 0;*/
      return FALSE;
}
typedef struct krb5_fcache {
    char *filename;
    int version;
} krb5_fcache;
struct fcc_cursor {
    int fd;
    krb5_storage *sp;
};
const char*
fcc_get_name( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_ccache id )
{
    return FILENAME( id );
}
static krb5_error_code
fcc_lock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_ccache id,
          int fd, krb5_boolean exclusive )
{
    return 0;
}
static krb5_error_code
fcc_unlock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, int fd )
{
    return 0;
}
krb5_error_code
fcc_resolve( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_ccache *id, const char *res )
{
    krb5_fcache *f;
    f =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *f ) )
        ;
    if( f == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","fcache.c 1284" )
        ;
        return KRB5_CC_NOMEM;
    }
    f->filename = m_strdup_hl( NAME_OF_MAIN_LOC_GLOB_P, res );
    if( f->filename == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, f )
        ;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","fcache.c 1285" )
        ;
        return KRB5_CC_NOMEM;
    }
    f->version = 0;
    ( *id )->data.data = f;
    ( *id )->data.length = sizeof( *f );
    return 0;
}
krb5_error_code
fcc_gen_new( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_ccache *id )
{
    ( *id )->data.data   = NULL;
    ( *id )->data.length = 0;
    return 0;
}
static void
storage_set_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_storage *sp, int vno )
{
    int flags = 0;
    switch( vno ) {
    case KRB5_FCC_FVNO_1:
            flags |= KRB5_STORAGE_PRINCIPAL_WRONG_NUM_COMPONENTS;
        flags |= KRB5_STORAGE_PRINCIPAL_NO_NAME_TYPE;
        flags |= KRB5_STORAGE_HOST_BYTEORDER;
        break;
    case KRB5_FCC_FVNO_2:
            flags |= KRB5_STORAGE_HOST_BYTEORDER;
        break;
    case KRB5_FCC_FVNO_3:
            flags |= KRB5_STORAGE_KEYBLOCK_KEYTYPE_TWICE;
        break;
    case KRB5_FCC_FVNO_4:
            break;
    default:
            //StSch Trace Point
            krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"fcache.c 10031: storage_set_flags called with bad vno (%x)" );
    }
    krb5_storage_set_flags( NAME_OF_MAIN_LOC_GLOB_P, sp, flags );
}
static krb5_error_code
fcc_open( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
          krb5_ccache id,
          int *fd_ret,
          int flags,
          mode_t mode )
{
    krb5_boolean exclusive = (( flags | O_WRONLY ) == flags ||
                              ( flags | O_RDWR ) == flags );
    krb5_error_code ret;
    const char *filename = FILENAME( id );
    int fd;
    fd = m_open_hl( NAME_OF_MAIN_LOC_GLOB_P, filename, flags );
    if( fd < 0 ) {
        ret = ( int )m__errno_location_hl(	NAME_OF_MAIN_LOC_GLOB_P );
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"open(): ","fcache.c 1289" )
        ;
        return ret;
    }
    if(( ret = fcc_lock( NAME_OF_MAIN_LOC_GLOB_P, context, id, fd, exclusive ) ) != 0 ) {
        m_close_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )fd );
        return ret;
    }
    *fd_ret = fd;
    return 0;
}
krb5_error_code
fcc_initialize( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_ccache id,
                krb5_principal primary_principal )
{
    krb5_fcache *f = FCACHE( id );
    int ret = 0;
    int fd;
    char *filename = f->filename;
    ret = fcc_open( NAME_OF_MAIN_LOC_GLOB_P, context, id, &fd, O_RDWR | O_CREAT | O_BINARY, 0600 );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    {
        krb5_storage *sp;
        sp = krb5_storage_from_fd( NAME_OF_MAIN_LOC_GLOB_P, fd );
#ifdef WITHOUT_FILE
        sp->ticket_in = context->tgt;
        sp->length_ticket_in = context->length_tgt;
        sp->position_ticket_in = 0;
#endif
        krb5_storage_set_eof_code(	NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_CC_END );
        if( context->fcache_vno != 0 )
            f->version = context->fcache_vno;
        else
            f->version = KRB5_FCC_FVNO_4;
        ret |= krb5_store_int8(	NAME_OF_MAIN_LOC_GLOB_P, sp, 5 );
        ret |= krb5_store_int8(	NAME_OF_MAIN_LOC_GLOB_P, sp, f->version );
        storage_set_flags(	NAME_OF_MAIN_LOC_GLOB_P, context, sp, f->version );
        if( f->version == KRB5_FCC_FVNO_4 && ret == 0 ) {
            if( context->kdc_sec_offset ) {
                ret |= krb5_store_int16(	NAME_OF_MAIN_LOC_GLOB_P, sp, 12 );
                ret |= krb5_store_int16(	NAME_OF_MAIN_LOC_GLOB_P, sp, FCC_TAG_DELTATIME );
                ret |= krb5_store_int16(	NAME_OF_MAIN_LOC_GLOB_P, sp, 8 );
                ret |= krb5_store_int32(	NAME_OF_MAIN_LOC_GLOB_P, sp, context->kdc_sec_offset );
                ret |= krb5_store_int32(	NAME_OF_MAIN_LOC_GLOB_P, sp, context->kdc_usec_offset );
            } else {
                ret |= krb5_store_int16(	NAME_OF_MAIN_LOC_GLOB_P, sp, 0 );
            }
        }
        ret |= krb5_store_principal(	NAME_OF_MAIN_LOC_GLOB_P, sp, primary_principal );
#ifdef WITHOUT_FILE
        {
            void * tgt     = NULL;
            int length_tgt = 0;
            if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
                tgt        = context->tgt;
                length_tgt = context->length_tgt;
            } else {
                if( NAME_OF_MAIN_LOC_GLOB_P->im_control_3 ) {
                    NAME_OF_MAIN_LOC_GLOB_P->im_control_3 = 0;
                    tgt        = NULL;
                    length_tgt = 0;
                } else {
                    tgt        = NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT;
                    length_tgt = NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT;
                }
            }
            if( tgt ) {
                tgt =
                    m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tgt,length_tgt + sp->length_ticket_out )
                    ;
            } else {
                tgt =
                    m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sp->length_ticket_out )
                    ;
            }
            memcpy((( char * )( tgt ) ) + length_tgt,sp->ticket_out,sp->length_ticket_out );
            length_tgt = sp->length_ticket_out + length_tgt;
            if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
                context->tgt = tgt;
                context->length_tgt = length_tgt;
            } else {
                NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT         = tgt;
                NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT = length_tgt;
            }
        }
#endif
        krb5_storage_free( NAME_OF_MAIN_LOC_GLOB_P, sp );
    }
    fcc_unlock( NAME_OF_MAIN_LOC_GLOB_P, context, fd );
    m_close_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )fd );
    return ret;
}
krb5_error_code
fcc_close( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
           krb5_ccache id )
{
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, FILENAME( id ) )
    ;
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &id->data );
    return 0;
}
krb5_error_code
fcc_destroy( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
             krb5_ccache id )
{
    FILE * handle;
#ifdef WITHOUT_FILE
    if( context->tgt )
        memset( context->tgt,'\0',context->length_tgt );
#endif
    handle = ( FILE * )m_open_hl( NAME_OF_MAIN_LOC_GLOB_P, FILENAME( id ),O_WRONLY | O_BINARY );
    m_close_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )handle );
    return 0;
}
krb5_error_code
fcc_store_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_ccache id,
                krb5_creds *creds )
{
    int ret;
    int fd;
    ret = fcc_open( NAME_OF_MAIN_LOC_GLOB_P, context, id, &fd, O_WRONLY | O_APPEND | O_BINARY, 0 );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    {
        krb5_storage *sp;
        sp = krb5_storage_from_fd( NAME_OF_MAIN_LOC_GLOB_P, fd );
#ifdef WITHOUT_FILE
        sp->ticket_in = context->tgt;
        sp->length_ticket_in = context->length_tgt;
        sp->position_ticket_in = 0;
#endif
        krb5_storage_set_eof_code(	NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_CC_END );
        storage_set_flags(	NAME_OF_MAIN_LOC_GLOB_P, context, sp, FCACHE( id )->version );
        krb5_storage_set_flags( NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_STORAGE_CREDS_FLAGS_WRONG_BITORDER );
        ret = krb5_store_creds(	NAME_OF_MAIN_LOC_GLOB_P, sp, creds );
#ifdef WITHOUT_FILE
        {
            void * tgt     = NULL;
            int length_tgt = 0;
            if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
                tgt        = context->tgt;
                length_tgt = context->length_tgt;
            } else {
                if( NAME_OF_MAIN_LOC_GLOB_P->im_control_3 ) {
                    NAME_OF_MAIN_LOC_GLOB_P->im_control_3 = 0;
                    tgt        = NULL;
                    length_tgt = 0;
                } else {
                    tgt        = NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT;
                    length_tgt = NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT;
                }
            }
            if( tgt ) {
                tgt =
                    m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tgt,length_tgt + sp->length_ticket_out )
                    ;
            } else {
                tgt =
                    m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sp->length_ticket_out )
                    ;
            }
            memcpy((( char * )( tgt ) ) + length_tgt,sp->ticket_out,sp->length_ticket_out );
            length_tgt = sp->length_ticket_out + length_tgt;
            if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
                context->tgt = tgt;
                context->length_tgt = length_tgt;
            } else {
                NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT         = tgt;
                NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT = length_tgt;
            }
        }
#endif
        krb5_storage_free( NAME_OF_MAIN_LOC_GLOB_P, sp );
    }
    fcc_unlock( NAME_OF_MAIN_LOC_GLOB_P, context, fd );
    m_close_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )fd );
    return ret;
}
static krb5_error_code
init_fcc( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
          krb5_ccache id,
          krb5_storage **ret_sp,
          int *ret_fd )
{
    int fd;
    int8_t pvno, tag;
    krb5_storage *sp;
    krb5_error_code ret;
    ret = fcc_open( NAME_OF_MAIN_LOC_GLOB_P, context, id, &fd, O_RDONLY | O_BINARY, 0 );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    sp = krb5_storage_from_fd( NAME_OF_MAIN_LOC_GLOB_P, fd );
#ifdef WITHOUT_FILE
    sp->ticket_in = context->tgt;
    sp->length_ticket_in = context->length_tgt;
    sp->position_ticket_in = 0;
#endif
    if( sp == NULL ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = ENOMEM;
        goto out;
    }
    krb5_storage_set_eof_code( NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_CC_END );
    ret = krb5_ret_int8( NAME_OF_MAIN_LOC_GLOB_P, sp, &pvno );
    if( ret != 0 ) {
        //StSch Trace Point
        if( ret == KRB5_CC_END )
            ret = ENOENT;
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        goto out;
    }
    if( pvno != 5 ) {
        //StSch Trace Point
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"Bad version number in credential cache file: ","fcache.c 1292" )
        ;
        ret = KRB5_CCACHE_BADVNO;
        goto out;
    }
    ret = krb5_ret_int8( NAME_OF_MAIN_LOC_GLOB_P, sp, &tag );
    if( ret != 0 ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5_CC_FORMAT;
        goto out;
    }
    FCACHE( id )->version = tag;
    storage_set_flags( NAME_OF_MAIN_LOC_GLOB_P, context, sp, FCACHE( id )->version );
    switch( tag ) {
    case KRB5_FCC_FVNO_4: {
            int16_t length;
            ret = krb5_ret_int16(	NAME_OF_MAIN_LOC_GLOB_P, sp, &length );
        if( ret ) {
        //StSch Trace Point
        ret = KRB5_CC_FORMAT;
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            goto out;
        }
    while( length > 0 ) {
    int16_t tag, data_len;
    int i;
    int8_t dummy;
    ret = krb5_ret_int16(	NAME_OF_MAIN_LOC_GLOB_P, sp, &tag );
        if( ret ) {
            //StSch Trace Point
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            ret = KRB5_CC_FORMAT;
            goto out;
        }
        ret = krb5_ret_int16(	NAME_OF_MAIN_LOC_GLOB_P, sp, &data_len );
        if( ret ) {
            //StSch Trace Point
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            ret = KRB5_CC_FORMAT;
            goto out;
        }
        switch( tag ) {
        case FCC_TAG_DELTATIME :
                ret = krb5_ret_int32(	NAME_OF_MAIN_LOC_GLOB_P, sp, &context->kdc_sec_offset );
            if( ret ) {
                //StSch Trace Point
                krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
                ret = KRB5_CC_FORMAT;
                goto out;
            }
            ret = krb5_ret_int32(	NAME_OF_MAIN_LOC_GLOB_P, sp, &context->kdc_usec_offset );
            if( ret ) {
                //StSch Trace Point
                krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
                ret = KRB5_CC_FORMAT;
                goto out;
            }
            break;
        default :
                for( i = 0; i < data_len; ++i ) {
                    ret = krb5_ret_int8(	NAME_OF_MAIN_LOC_GLOB_P, sp, &dummy );
                    if( ret ) {
                        //StSch Trace Point
                        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
                        ret = KRB5_CC_FORMAT;
                        goto out;
                    }
                }
            break;
        }
        length -= 4 + data_len;
    }
    break;
    }
    case KRB5_FCC_FVNO_3:
        case KRB5_FCC_FVNO_2:
            case KRB5_FCC_FVNO_1:
                    break;
    default :
            ret = KRB5_CCACHE_BADVNO;
        //StSch Trace Point
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"Unknown version number () in credential cache file: ","fcache.c 1293" )
        ;
        goto out;
    }
    *ret_sp = sp;
    *ret_fd = fd;
    return 0;
    out:
    if( sp != NULL )
#ifdef WITHOUT_FILE
    {
        void * tgt     = NULL;
        int length_tgt = 0;
        if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
            tgt        = context->tgt;
            length_tgt = context->length_tgt;
        } else {
            if( NAME_OF_MAIN_LOC_GLOB_P->im_control_3 ) {
                NAME_OF_MAIN_LOC_GLOB_P->im_control_3 = 0;
                tgt        = NULL;
                length_tgt = 0;
            } else {
                tgt        = NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT;
                length_tgt = NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT;
            }
        }
        if( tgt ) {
            tgt =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tgt,length_tgt + sp->length_ticket_out )
                ;
        } else {
            tgt =
                m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sp->length_ticket_out )
                ;
        }
        memcpy((( char * )( tgt ) ) + length_tgt,sp->ticket_out,sp->length_ticket_out );
        length_tgt = sp->length_ticket_out + length_tgt;
        if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
            context->tgt = tgt;
            context->length_tgt = length_tgt;
        } else {
            NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT         = tgt;
            NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT = length_tgt;
        }
    }
#endif
    krb5_storage_free( NAME_OF_MAIN_LOC_GLOB_P, sp );
    fcc_unlock( NAME_OF_MAIN_LOC_GLOB_P, context, fd );
    m_close_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )fd );
    return ret;
}
krb5_error_code
fcc_get_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_ccache id,
                   krb5_principal *principal )
{
    krb5_error_code ret;
    int fd;
    krb5_storage *sp;
    ret = init_fcc( NAME_OF_MAIN_LOC_GLOB_P, context, id, &sp, &fd );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_ret_principal( NAME_OF_MAIN_LOC_GLOB_P, sp, principal );
    if( ret ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
    }
#ifdef WITHOUT_FILE
    {
        void * tgt     = NULL;
        int length_tgt = 0;
        if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
            tgt        = context->tgt;
            length_tgt = context->length_tgt;
        } else {
            if( NAME_OF_MAIN_LOC_GLOB_P->im_control_3 ) {
                NAME_OF_MAIN_LOC_GLOB_P->im_control_3 = 0;
                tgt        = NULL;
                length_tgt = 0;
            } else {
                tgt        = NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT;
                length_tgt = NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT;
            }
        }
        if( tgt ) {
            tgt =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tgt,length_tgt + sp->length_ticket_out )
                ;
        } else {
            tgt =
                m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sp->length_ticket_out )
                ;
        }
        memcpy((( char * )( tgt ) ) + length_tgt,sp->ticket_out,sp->length_ticket_out );
        length_tgt = sp->length_ticket_out + length_tgt;
        if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
            context->tgt = tgt;
            context->length_tgt = length_tgt;
        } else {
            NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT         = tgt;
            NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT = length_tgt;
        }
    }
#endif
    krb5_storage_free( NAME_OF_MAIN_LOC_GLOB_P, sp );
    fcc_unlock( NAME_OF_MAIN_LOC_GLOB_P, context, fd );
    m_close_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )fd );
    return ret;
}
krb5_error_code
fcc_end_get( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
             krb5_ccache id,
             krb5_cc_cursor *cursor );
krb5_error_code
fcc_get_first( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               krb5_ccache id,
               krb5_cc_cursor *cursor )
{
    krb5_error_code ret;
    krb5_principal principal;
    *cursor =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( struct fcc_cursor ) )
        ;
    if( *cursor == NULL ) {
        krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","fcache.c 1294" )
        ;
        return ENOMEM;
    }
    memset( *cursor, 0, sizeof( struct fcc_cursor ) );
    ret = init_fcc( NAME_OF_MAIN_LOC_GLOB_P, context, id, &FCC_CURSOR( *cursor )->sp,
                    &FCC_CURSOR( *cursor )->fd );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *cursor )
        ;
        *cursor = NULL;
        return ret;
    }
    ret = krb5_ret_principal( NAME_OF_MAIN_LOC_GLOB_P, FCC_CURSOR( *cursor )->sp, &principal );
    if( ret ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        fcc_end_get(	NAME_OF_MAIN_LOC_GLOB_P, context, id, cursor );
        return ret;
    }
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, principal );
    fcc_unlock( NAME_OF_MAIN_LOC_GLOB_P, context, FCC_CURSOR( *cursor )->fd );
    return 0;
}
krb5_error_code
fcc_get_next( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_ccache id,
              krb5_cc_cursor *cursor,
              krb5_creds *creds )
{
    krb5_error_code ret;
    if(( ret = fcc_lock( NAME_OF_MAIN_LOC_GLOB_P, context, id, FCC_CURSOR( *cursor )->fd, FALSE ) ) != 0 )
        return ret;
    ret = krb5_ret_creds( NAME_OF_MAIN_LOC_GLOB_P, FCC_CURSOR( *cursor )->sp, creds );
    if( ret ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
    }
    fcc_unlock( NAME_OF_MAIN_LOC_GLOB_P, context, FCC_CURSOR( *cursor )->fd );
    return ret;
}
krb5_error_code
fcc_end_get( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
             krb5_ccache id,
             krb5_cc_cursor *cursor )
{
#ifdef WITHOUT_FILE
    {
        void * tgt     = NULL;
        int length_tgt = 0;
        if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
            tgt        = context->tgt;
            length_tgt = context->length_tgt;
        } else
        {
            if( NAME_OF_MAIN_LOC_GLOB_P->im_control_3 ) {
                NAME_OF_MAIN_LOC_GLOB_P->im_control_3 = 0;
                tgt        = NULL;
                length_tgt = 0;
            } else
            {
                tgt        = NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT;
                length_tgt = NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT;
            }
        }
        if( tgt ) {
            tgt =
                m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tgt,length_tgt + FCC_CURSOR( *cursor )->sp->length_ticket_out )
                ;
        } else
        {
            tgt =

            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, FCC_CURSOR( *cursor )->sp->length_ticket_out )
            ;
        }
        memcpy((( char * )( tgt ) ) + length_tgt, FCC_CURSOR( *cursor )->sp->ticket_out, FCC_CURSOR( *cursor )->sp->length_ticket_out );
        length_tgt = FCC_CURSOR( *cursor )->sp->length_ticket_out + length_tgt;
        if( NAME_OF_MAIN_LOC_GLOB_P->im_control_2 ) {
            context->tgt = tgt;
            context->length_tgt = length_tgt;
        } else
        {
            NAME_OF_MAIN_LOC_GLOB_P->a_renew_TGT        = tgt;
            NAME_OF_MAIN_LOC_GLOB_P->im_length_renew_TGT = length_tgt;
        }
    }
#endif
    krb5_storage_free( NAME_OF_MAIN_LOC_GLOB_P, FCC_CURSOR( *cursor )->sp );
    m_close_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )( FCC_CURSOR( *cursor )->fd ) );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *cursor )
    ;
    *cursor = NULL;
    return 0;
}
krb5_error_code
fcc_remove_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 krb5_ccache id,
                 krb5_flags which,
                 krb5_creds *cred )
{
    return 0;
}
krb5_error_code
fcc_set_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               krb5_ccache id,
               krb5_flags flags )
{
    return 0;
}
krb5_error_code
fcc_get_version( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 krb5_ccache id )
{
    return FCACHE( id )->version;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_free_kdc_rep( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_kdc_rep *rep )
{
    free_KDC_REP( NAME_OF_MAIN_LOC_GLOB_P, &rep->kdc_rep );
    free_EncTGSRepPart( NAME_OF_MAIN_LOC_GLOB_P, &rep->enc_part );
    free_KRB_ERROR( NAME_OF_MAIN_LOC_GLOB_P, &rep->error );
    memset( rep, 0, sizeof( *rep ) );
    return 0;
}
/*
 * Free all memory allocated by `realmlist'
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_free_host_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      krb5_realm *realmlist )
{
    krb5_realm *p;
    if( realmlist == NULL )
        return 0;
    for( p = realmlist; *p; ++p )
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *p )
        ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, realmlist )
    ;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_generate_seq_number( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          const krb5_keyblock *key,
                          u_int32_t *seqno )
{
    krb5_error_code ret;
    krb5_keyblock *subkey;
    u_int32_t q;
    u_char *p;
    int i;
    ret = krb5_generate_subkey( NAME_OF_MAIN_LOC_GLOB_P, context, key, &subkey );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    q = 0;
    for( p = ( u_char * )subkey->keyvalue.data, i = 0;
            i < subkey->keyvalue.length;
            ++i, ++p )
        q = ( q << 8 ) | *p;
    q &= 0xffffffff;
    *seqno = q;
    krb5_free_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, subkey );
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_generate_subkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      const krb5_keyblock *key,
                      krb5_keyblock **subkey )
{
    return krb5_generate_subkey_extended( NAME_OF_MAIN_LOC_GLOB_P, context, key, key->keytype, subkey );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_generate_subkey_extended( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                               const krb5_keyblock *key,
                               krb5_enctype etype,
                               krb5_keyblock **subkey )
{
    krb5_error_code ret;
    ALLOC( *subkey, 1 );
    if( *subkey == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","generate_subkey.c 1505" )
        ;
        return ENOMEM;
    }
    if( etype == ETYPE_NULL )
        etype = key->keytype;
    ret = krb5_generate_random_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, etype, *subkey );
    if( ret != 0 ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *subkey )
        ;
        *subkey = NULL;
    }
    return ret;
}
#if !(defined HAVE_GETTIMEOFDAY) && !(defined HOB_KRB5_UNIT_TEST)
/*
 * Simple m_gettimeofday_hl that only returns seconds.
 */
int ROKEN_LIB_FUNCTION
m_gettimeofday_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct timeval *tp, void *ignore )
{
    time_t t;
    t = time( NULL );
    //StSch Trace Point Always
    tp->tv_sec  = t;
    tp->tv_usec = 0;
    return 0;
}
#endif
#ifdef __osf__
struct rtentry;
struct mbuf;
#endif

enum {
    LOOP            = 1,
    LOOP_IF_NONE    = 2,
    EXTRA_ADDRESSES = 4,
    SCAN_INTERFACES = 8
};
/*
 * Try to get all addresses, but return the one corresponding to
 * `hostname' if we fail.
 *
 * Only include loopback address if there are no other.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_all_client_addrs( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_addresses *res )
{
    res->val = ( void* )0;
    res->len = 0;
    return 0;
}
/*
 * Try to get all local addresses that a server should listen to.
 * If that fails, we return the address corresponding to `hostname'.
 */
krb5_error_code
_krb5_mk_req_internal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       krb5_auth_context *auth_context,
                       const krb5_flags ap_req_options,
                       krb5_data *in_data,
                       krb5_creds *in_creds,
                       krb5_data *outbuf,
                       krb5_key_usage checksum_usage,
                       krb5_key_usage encrypt_usage );
/*
 * Take the `body' and encode it into `padata' using the credentials
 * in `creds'.
 */
static krb5_error_code
make_pa_tgs_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 krb5_auth_context ac,
                 KDC_REQ_BODY *body,
                 PA_DATA *padata,
                 krb5_creds *creds,
                 krb5_key_usage usage )
{
    u_char *buf;
    size_t buf_size;
    size_t len;
    krb5_data in_data;
    krb5_error_code ret;
    ASN1_MALLOC_ENCODE( KDC_REQ_BODY, buf, buf_size, body, &len, ret );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"get_cred.c 10027: internal error in ASN.1 encoder" );
    in_data.length = len;
    in_data.data   = buf;
    ret = _krb5_mk_req_internal( NAME_OF_MAIN_LOC_GLOB_P, context, &ac, 0, &in_data, creds,
                                 &padata->padata_value,
                                 KRB5_KU_TGS_REQ_AUTH_CKSUM,
                                 usage
                               );
    out:
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    padata->padata_type = KRB5_PADATA_TGS_REQ;
    return 0;
}
/*
 * Set the `enc-authorization-data' in `req_body' based on `authdata'
 */
static krb5_error_code
set_auth_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               KDC_REQ_BODY *req_body,
               krb5_authdata *authdata,
               krb5_keyblock *key )
{
    if( authdata->len ) {
        size_t len, buf_size;
        unsigned char *buf;
        krb5_crypto crypto;
        krb5_error_code ret;
        ASN1_MALLOC_ENCODE( AuthorizationData, buf, buf_size, authdata,
                            &len, ret );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
        if( buf_size != len )
            //StSch Trace Point
            krb5_abortx(	NAME_OF_MAIN_LOC_GLOB_P, context,"get_cred.c 10028: internal error in ASN.1 encoder" );
        ALLOC( req_body->enc_authorization_data, 1 );
        if( req_body->enc_authorization_data == NULL ) {
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
            ;
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1265" )
            ;
            return ENOMEM;
        }
        ret = krb5_crypto_init(	NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
        if( ret ) {
            //StSch Trace Point
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
            ;
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, req_body->enc_authorization_data )
            ;
            req_body->enc_authorization_data = NULL;
            return ret;
        }
        krb5_encrypt_EncryptedData(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                    crypto,
                                    KRB5_KU_TGS_REQ_AUTH_DAT_SUBKEY,
                                    buf,
                                    len,
                                    0,
                                    req_body->enc_authorization_data );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    } else {
        req_body->enc_authorization_data = NULL;
    }
    return 0;
}
/*
 * Create a tgs-req in `t' with `addresses', `flags', `second_ticket'
 * (if not-NULL), `in_creds', `krbtgt', and returning the generated
 * subkey in `subkey'.
 */
static krb5_error_code
init_tgs_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_ccache ccache,
              krb5_addresses *addresses,
              krb5_kdc_flags flags,
              Ticket *second_ticket,
              krb5_creds *in_creds,
              krb5_creds *krbtgt,
              unsigned nonce,
              krb5_keyblock **subkey,
              TGS_REQ *t,
              krb5_key_usage usage )
{
    krb5_error_code ret = 0;
    memset( t, 0, sizeof( *t ) );
    t->pvno = 5;
    t->msg_type = krb_tgs_req;
    if( in_creds->session.keytype ) {
        ALLOC_SEQ( &t->req_body.etype, 1 );
        if( t->req_body.etype.val == NULL ) {
            //StSch Trace Point
            ret = ENOMEM;
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1266" )
            ;
            goto fail;
        }
        t->req_body.etype.val[0] = in_creds->session.keytype;
    } else {
        ret = krb5_init_etype(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                &t->req_body.etype.len,
                                &t->req_body.etype.val,
                                NULL );
    }
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    t->req_body.addresses = addresses;
    t->req_body.kdc_options = flags.b;
    ret = copy_Realm( NAME_OF_MAIN_LOC_GLOB_P, &in_creds->server->realm, &t->req_body.realm );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    ALLOC( t->req_body.sname, 1 );
    if( t->req_body.sname == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1267" )
        ;
        goto fail;
    }
    /* some versions of some code might require that the client be
       present in TGS-REQs, but this is clearly against the spec */
    ret = copy_PrincipalName( NAME_OF_MAIN_LOC_GLOB_P, &in_creds->server->name, t->req_body.sname );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    /* req_body.till should be NULL if there is no endtime specified,
       but old MIT code (like DCE secd) doesn't like that */
    ALLOC( t->req_body.till, 1 );
    if( t->req_body.till == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1268" )
        ;
        goto fail;
    }
    *t->req_body.till = in_creds->times.endtime;
    t->req_body.nonce = nonce;
    if( second_ticket ) {
        ALLOC( t->req_body.additional_tickets, 1 );
        if( t->req_body.additional_tickets == NULL ) {
            //StSch Trace Point
            ret = ENOMEM;
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1269" )
            ;
            goto fail;
        }
        ALLOC_SEQ( t->req_body.additional_tickets, 1 );
        if( t->req_body.additional_tickets->val == NULL ) {
            //StSch Trace Point
            ret = ENOMEM;
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1270" )
            ;
            goto fail;
        }
        ret = copy_Ticket(	NAME_OF_MAIN_LOC_GLOB_P, second_ticket, t->req_body.additional_tickets->val );
        if( ret ) {
            //StSch Trace Point
            goto fail;
        }
    }
    ALLOC( t->padata, 1 );
    if( t->padata == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1271" )
        ;
        goto fail;
    }
    ALLOC_SEQ( t->padata, 1 );
    if( t->padata->val == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1272" )
        ;
        goto fail;
    }
    {
        krb5_auth_context ac;
        krb5_keyblock *key = NULL;
        ret = krb5_auth_con_init(	NAME_OF_MAIN_LOC_GLOB_P, context, &ac );
        if( ret ) {
            //StSch Trace Point
            goto fail;
        }
        ret = set_auth_data(	NAME_OF_MAIN_LOC_GLOB_P, context, &t->req_body, &in_creds->authdata,
                                key ? key : &krbtgt->session );
        if( ret ) {
            //StSch Trace Point
            if( key )
                krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, key );
            krb5_auth_con_free(	NAME_OF_MAIN_LOC_GLOB_P, context, ac );
            goto fail;
        }
        ret = make_pa_tgs_req(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                ac,
                                &t->req_body,
                                t->padata->val,
                                krbtgt,
                                usage );
        if( ret ) {
            //StSch Trace Point
            if( key )
                krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, key );
            krb5_auth_con_free(	NAME_OF_MAIN_LOC_GLOB_P, context, ac );
            goto fail;
        }
        *subkey = key;
        krb5_auth_con_free(	NAME_OF_MAIN_LOC_GLOB_P, context, ac );
    }
    fail:
    if( ret ) {
        //StSch Trace Point
        t->req_body.addresses = NULL;
        free_TGS_REQ(	NAME_OF_MAIN_LOC_GLOB_P, t );
    }
    return ret;
}
krb5_error_code
_krb5_get_krbtgt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  krb5_ccache  id,
                  krb5_realm realm,
                  krb5_creds **cred )
{
    krb5_error_code ret;
    krb5_creds tmp_cred;
    memset( &tmp_cred, 0, sizeof( tmp_cred ) );
    ret = krb5_cc_get_principal( NAME_OF_MAIN_LOC_GLOB_P, context, id, &tmp_cred.client );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_make_principal( NAME_OF_MAIN_LOC_GLOB_P, context,
                               &tmp_cred.server,
                               realm,
                               KRB5_TGS_NAME,
                               realm );
    if( ret ) {
        //StSch Trace Point
        krb5_free_principal(	NAME_OF_MAIN_LOC_GLOB_P, context, tmp_cred.client );
        return ret;
    }
    ret = krb5_get_credentials( NAME_OF_MAIN_LOC_GLOB_P, context,
                                KRB5_GC_CACHED,
                                id,
                                &tmp_cred,
                                cred );
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_cred.client );
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_cred.server );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    return 0;
}
static krb5_error_code
decrypt_tkt_with_subkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                         krb5_keyblock *key,
                         krb5_key_usage usage,
                         krb5_const_pointer subkey,
                         krb5_kdc_rep *dec_rep )
{
    krb5_error_code ret;
    krb5_data data;
    size_t size;
    krb5_crypto crypto;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_decrypt_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, context,
                                      crypto,
                                      usage,
                                      &dec_rep->kdc_rep.enc_part,
                                      &data );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret && subkey ) {
        ret = krb5_crypto_init(	NAME_OF_MAIN_LOC_GLOB_P, context, ( krb5_keyblock* )subkey, 0, &crypto );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
        ret = krb5_decrypt_EncryptedData(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                            crypto,
                                            KRB5_KU_TGS_REP_ENC_PART_SUB_KEY,
                                            &dec_rep->kdc_rep.enc_part,
                                            &data );
        krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    }
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_decode_EncASRepPart( NAME_OF_MAIN_LOC_GLOB_P, context,
                                    data.data,
                                    data.length,
                                    &dec_rep->enc_part,
                                    &size );
    if( ret ) {
        //StSch Trace Point
        ret = krb5_decode_EncTGSRepPart(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                            data.data,
                                            data.length,
                                            &dec_rep->enc_part,
                                            &size );
    }
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &data );
    return ret;
}
static krb5_error_code
get_cred_kdc_usage( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_ccache id,
                    krb5_kdc_flags flags,
                    krb5_addresses *addresses,
                    krb5_creds *in_creds,
                    krb5_creds *krbtgt,
                    krb5_creds *out_creds,
                    krb5_key_usage usage )
{
    TGS_REQ req;
    krb5_data enc;
    krb5_data resp;
    krb5_kdc_rep rep;
    KRB_ERROR error;
    krb5_error_code ret;
    unsigned nonce;
    krb5_keyblock *subkey = NULL;
    size_t len;
    Ticket second_ticket;
    int send_to_kdc_flags = 0;
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &resp );
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &enc );
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, &nonce, sizeof( nonce ) );
    nonce &= 0xffffffff;
    if( flags.b.enc_tkt_in_skey ) {
        ret = decode_Ticket(	NAME_OF_MAIN_LOC_GLOB_P, in_creds->second_ticket.data,
                                in_creds->second_ticket.length,
                                &second_ticket, &len );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
    }
    ret = init_tgs_req( NAME_OF_MAIN_LOC_GLOB_P, context,
                        id,
                        addresses,
                        flags,
                        flags.b.enc_tkt_in_skey ? &second_ticket : NULL,
                        in_creds,
                        krbtgt,
                        nonce,
                        &subkey,
                        &req,
                        usage );
    if( flags.b.enc_tkt_in_skey )
        free_Ticket(	NAME_OF_MAIN_LOC_GLOB_P, &second_ticket );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    ASN1_MALLOC_ENCODE( TGS_REQ, enc.data, enc.length, &req, &len, ret );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    //StSch Trace Point 6002
    if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
        void* a_temp_memory=0;
        struct dsd_memory_traces* adsl_trace;
        KDC_REQ_BODY ads_req_body= req.req_body;
        char* achl_cname=0;
        char* achl_sname=0;
        long long ill_from=0;
        long long ill_rtime=0;
        char* achl_trace_format="TGS-REQ: pvno=%i, msg-type=%i, flags=%i, cname=%s, realm=%s, sname=%s, "
                                "from=%lli, till=%lli, rtime=%lli, nonce=%u";
        m_aux_stor_start( &a_temp_memory );
        adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
        achl_cname=m_krb5_principalname2string( &a_temp_memory,achl_cname,ads_req_body.cname );
        achl_sname=m_krb5_principalname2string( &a_temp_memory,achl_sname,ads_req_body.sname );
        if( req.padata!=NULL ) {
            int inl_in1=0;
            for( ; inl_in1<req.padata->len; inl_in1++ ) {
                m_krb5_trace_memcat( &a_temp_memory, adsl_trace,req.padata->val+inl_in1,
                                     sizeof( PA_DATA ),"PA-DATA:" );
            }
        }
        if( ads_req_body.from!=NULL ) {
            ill_from=*ads_req_body.from;
        }
        if( ads_req_body.rtime!=NULL ) {
            ill_rtime=*ads_req_body.rtime;
        }
        m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',6002,
                     adsl_trace, &a_temp_memory, achl_trace_format,req.pvno, req.msg_type,flags.i,
                     achl_cname,ads_req_body.realm, achl_sname,ill_from, *ads_req_body.till, ill_rtime, ads_req_body.nonce );
        m_aux_stor_end( &a_temp_memory );
    }
    if( enc.length != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"get_cred.c 10029: internal error in ASN.1 encoder" );
    req.req_body.addresses = NULL;
    free_TGS_REQ( NAME_OF_MAIN_LOC_GLOB_P, &req );
    /*
     * Send and receive
     */
    again:
    //StSch Trace Point Always
    ret = krb5_sendto_kdc_flags( NAME_OF_MAIN_LOC_GLOB_P, context, &enc,
                                 &krbtgt->server->name.name_string.val[1],
                                 &resp,
                                 send_to_kdc_flags );
    //StSch Trace Point Always
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    memset( &rep, 0, sizeof( rep ) );
    if( decode_TGS_REP( NAME_OF_MAIN_LOC_GLOB_P, resp.data, resp.length, &rep.kdc_rep, &len ) == 0 ) {
        //StSch Trace Point 6003
        if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
            void* a_temp_memory=0;
            struct dsd_memory_traces* adsl_trace;
            char* achl_cname=0;
            char* achl_sname=0;
            int inl_kvno=0;
            KDC_REP ads_rep=rep.kdc_rep;
            char* achl_msg_format="TGS-REP: pvno=%i, msg-type=%i, crealm=%s, cname=%s, tkt-vno=%i, "
                                  "realm=%s, sname=%s, etype=%i, kvno=%i";
            m_aux_stor_start( &a_temp_memory );
            adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
            if( ads_rep.padata!=NULL ) {
                int inl_in1=0;
                for( ; inl_in1<ads_rep.padata->len; inl_in1++ ) {
                    m_krb5_trace_memcat( &a_temp_memory, adsl_trace,ads_rep.padata->val+inl_in1,
                                         sizeof( PA_DATA ),"PA-DATA:" );
                }
            }
            if( ads_rep.enc_part.kvno!=NULL ) {
                inl_kvno=*ads_rep.enc_part.kvno;
            }
            achl_cname=m_krb5_principalname2string( &a_temp_memory, achl_cname, &ads_rep.cname );
            achl_sname=m_krb5_principalname2string( &a_temp_memory, achl_sname, &ads_rep.ticket.sname );
            m_krb5_trace(( struct krb5_tracer* )NAME_OF_MAIN_LOC_GLOB_P->a_tracer,'T',6003,
                         adsl_trace,&a_temp_memory, achl_msg_format, ads_rep.pvno, ads_rep.msg_type,ads_rep.crealm,achl_cname,
                         ads_rep.ticket.tkt_vno,ads_rep.ticket.realm,achl_sname, ads_rep.enc_part.etype,inl_kvno );
            m_aux_stor_end( &a_temp_memory );
        }
        ret = krb5_copy_principal(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                    in_creds->client,
                                    &out_creds->client );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
        ret = krb5_copy_principal(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                    in_creds->server,
                                    &out_creds->server );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
        out_creds->times.endtime = in_creds->times.endtime;
        ret = _krb5_extract_ticket(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                    &rep,
                                    out_creds,
                                    &krbtgt->session,
                                    NULL,
                                    KRB5_KU_TGS_REP_ENC_PART_SESSION,
                                    &krbtgt->addresses,
                                    nonce,
                                    TRUE,
                                    flags.b.request_anonymous,
                                    decrypt_tkt_with_subkey,
                                    subkey );
        krb5_free_kdc_rep(	NAME_OF_MAIN_LOC_GLOB_P, context, &rep );
    } else if( krb5_rd_error( NAME_OF_MAIN_LOC_GLOB_P, context, &resp, &error ) == 0 ) {
        //StSch Trace Point 6004
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
            achl_cname=m_krb5_principalname2string( &a_temp_memory, achl_cname, error.cname );
            achl_sname=m_krb5_principalname2string( &a_temp_memory, achl_sname, &error.sname );
            if( error.crealm!=NULL ) {
                achl_crealm=*error.crealm;
            }
            if( error.ctime!=NULL ) {
                ill_ctime=*error.ctime;
            }
            if( error.cusec!=NULL ) {
                inl_cusec=*error.cusec;
            }
            m_krb5_trace(( struct krb5_tracer* )NAME_OF_MAIN_LOC_GLOB_P->a_tracer,'T',6004,
                         adsl_trace,&a_temp_memory, achl_msg_format, error.pvno,error.msg_type,ill_ctime,
                         inl_cusec,error.stime,error.susec, error.error_code, achl_crealm,achl_cname,
                         error.realm,achl_sname );
            m_aux_stor_end( &a_temp_memory );
        }
        ret = krb5_error_from_rd_error(	NAME_OF_MAIN_LOC_GLOB_P, context, &error, in_creds );
        krb5_free_error_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, &error );
        if( ret == KRB5KRB_ERR_RESPONSE_TOO_BIG && !( send_to_kdc_flags & KRB5_KRBHST_FLAGS_LARGE_MSG ) ) {
            send_to_kdc_flags |= KRB5_KRBHST_FLAGS_LARGE_MSG;
            krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &resp );
            goto again;
        }
    } else if( resp.data && (( char* )resp.data )[0] == 4 ) {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_V4_REPLY;
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
    } else {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_MSG_TYPE;
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
    }
    out:
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &resp );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &enc );
    if( subkey ) {
        krb5_free_keyblock_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, subkey );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, subkey )
        ;
    }
    return ret;
}
static krb5_error_code
get_cred_kdc( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_ccache id,
              krb5_kdc_flags flags,
              krb5_addresses *addresses,
              krb5_creds *in_creds,
              krb5_creds *krbtgt,
              krb5_creds *out_creds )
{
    krb5_error_code ret;
    ret = get_cred_kdc_usage( NAME_OF_MAIN_LOC_GLOB_P, context, id, flags, addresses, in_creds,
                              krbtgt, out_creds, KRB5_KU_TGS_REQ_AUTH );
    if( ret == KRB5KRB_AP_ERR_BAD_INTEGRITY ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = get_cred_kdc_usage(	NAME_OF_MAIN_LOC_GLOB_P, context, id, flags, addresses, in_creds,
                                    krbtgt, out_creds, KRB5_KU_AP_REQ_AUTH );
    }
    return ret;
}
static krb5_error_code
get_cred_kdc_la( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_ccache id, krb5_kdc_flags flags,
                 krb5_creds *in_creds, krb5_creds *krbtgt,
                 krb5_creds *out_creds )
{
    krb5_error_code ret;
    krb5_addresses addresses, *addrs = &addresses;
    krb5_get_all_client_addrs( NAME_OF_MAIN_LOC_GLOB_P, context, &addresses );
    if( addresses.len == 0 )
        addrs = NULL;
    ret = get_cred_kdc( NAME_OF_MAIN_LOC_GLOB_P, context, id, flags, addrs,
                        in_creds, krbtgt, out_creds );
    krb5_free_addresses( NAME_OF_MAIN_LOC_GLOB_P, context, &addresses );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_kdc_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_ccache id,
                   krb5_kdc_flags flags,
                   krb5_addresses *addresses,
                   Ticket  *second_ticket,
                   krb5_creds *in_creds,
                   krb5_creds **out_creds
                 )
{
    krb5_error_code ret;
    krb5_creds *krbtgt;
    *out_creds =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( **out_creds ) ) ),'\0',( 1 ) * ( sizeof( **out_creds ) ) )
        ;
    if( *out_creds == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1273" )
        ;
        return ENOMEM;
    }
    ret = _krb5_get_krbtgt( NAME_OF_MAIN_LOC_GLOB_P, context,
                            id,
                            in_creds->server->realm,
                            &krbtgt );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *out_creds )
        ;
        return ret;
    }
    ret = get_cred_kdc( NAME_OF_MAIN_LOC_GLOB_P, context, id, flags, addresses,
                        in_creds, krbtgt, *out_creds );
    krb5_free_creds( NAME_OF_MAIN_LOC_GLOB_P, context, krbtgt );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *out_creds )
        ;
    }
    return ret;
}
static krb5_error_code
find_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
           krb5_ccache id,
           krb5_principal server,
           krb5_creds **tgts,
           krb5_creds *out_creds )
{
    krb5_error_code ret;
    krb5_creds mcreds;
    krb5_cc_clear_mcred( NAME_OF_MAIN_LOC_GLOB_P, &mcreds );
    mcreds.server = server;
    ret = krb5_cc_retrieve_cred( NAME_OF_MAIN_LOC_GLOB_P, context, id, KRB5_TC_DONT_MATCH_REALM,
                                 &mcreds, out_creds );
    if( ret == 0 )
        return 0;
    while( tgts && *tgts ) {
        if( krb5_compare_creds(	NAME_OF_MAIN_LOC_GLOB_P, context, KRB5_TC_DONT_MATCH_REALM,
                                &mcreds, *tgts ) ) {
            ret = krb5_copy_creds_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, *tgts, out_creds );
            return ret;
        }
        tgts++;
    }
    krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
    return KRB5_CC_NOTFOUND;
}
static krb5_error_code
add_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_creds ***tgts, krb5_creds *tkt )
{
    int i;
    krb5_error_code ret;
    krb5_creds **tmp = *tgts;
    for( i = 0; tmp && tmp[i]; i++ );
    tmp =
        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tmp, ( i+2 )*sizeof( *tmp ) )
        ;
    if( tmp == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1274" )
        ;
        return ENOMEM;
    }
    *tgts = tmp;
    ret = krb5_copy_creds( NAME_OF_MAIN_LOC_GLOB_P, context, tkt, &tmp[i] );
    tmp[i+1] = NULL;
    return ret;
}
krb5_error_code
get_cred_from_kdc_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                         krb5_kdc_flags flags,
                         krb5_ccache ccache,
                         krb5_creds *in_creds,
                         krb5_creds **out_creds,
                         krb5_creds ***ret_tgts )
{
    krb5_error_code ret;
    krb5_creds *tgt, tmp_creds;
    krb5_const_realm client_realm, server_realm, try_realm;
    *out_creds = NULL;
    client_realm = krb5_principal_get_realm( NAME_OF_MAIN_LOC_GLOB_P, context, in_creds->client );
    server_realm = krb5_principal_get_realm( NAME_OF_MAIN_LOC_GLOB_P, context, in_creds->server );
    memset( &tmp_creds, 0, sizeof( tmp_creds ) );
    ret = krb5_copy_principal( NAME_OF_MAIN_LOC_GLOB_P, context, in_creds->client, &tmp_creds.client );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    try_realm = client_realm;
    ret = krb5_make_principal( NAME_OF_MAIN_LOC_GLOB_P, context,
                               &tmp_creds.server,
                               try_realm,
                               KRB5_TGS_NAME,
                               server_realm );
    if( ret ) {
        //StSch Trace Point
        krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.client );
        return ret;
    }
    {
        krb5_creds tgts;
        ret = find_cred( NAME_OF_MAIN_LOC_GLOB_P, context, ccache, tmp_creds.server,
                         *ret_tgts, &tgts );
        if( ret == 0 ) {
            *out_creds =
                memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( **out_creds ) ) ),'\0',( 1 ) * ( sizeof( **out_creds ) ) )
                ;
            if( *out_creds == NULL ) {
                krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1277" )
                ;
                ret = ENOMEM;
            } else {
                ret = get_cred_kdc_la( NAME_OF_MAIN_LOC_GLOB_P, context, ccache, flags,
                                       in_creds, &tgts, *out_creds );
                if( ret ) {
                    //StSch Trace Point
                    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *out_creds )
                    ;
                    *out_creds = NULL;
                }
            }
            krb5_free_cred_contents( NAME_OF_MAIN_LOC_GLOB_P, context, &tgts );
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.server );
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.client );
            return ret;
        }
    }
    if( krb5_realm_compare( NAME_OF_MAIN_LOC_GLOB_P, context, in_creds->client, in_creds->server ) ) {
        krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5_CC_NOTFOUND;
    }
    while( 1 ) {
        heim_general_string tgt_inst;
        ret = get_cred_from_kdc_flags( NAME_OF_MAIN_LOC_GLOB_P, context, flags, ccache, &tmp_creds,
                                       &tgt, ret_tgts );
        if( ret ) {
            //StSch Trace Point
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.server );
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.client );
            return ret;
        }
        ret = add_cred( NAME_OF_MAIN_LOC_GLOB_P, context, ret_tgts, tgt );
        if( ret ) {
            //StSch Trace Point
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.server );
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.client );
            return ret;
        }
        tgt_inst = tgt->server->name.name_string.val[1];
        if( strcmp( tgt_inst, server_realm ) == 0 )
            break;
        krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.server );
        ret = krb5_make_principal( NAME_OF_MAIN_LOC_GLOB_P, context, &tmp_creds.server,
                                   tgt_inst, KRB5_TGS_NAME, server_realm );
        if( ret ) {
            //StSch Trace Point
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.server );
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.client );
            return ret;
        }
        ret = krb5_free_creds( NAME_OF_MAIN_LOC_GLOB_P, context, tgt );
        if( ret ) {
            //StSch Trace Point
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.server );
            krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.client );
            return ret;
        }
    }
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.server );
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, tmp_creds.client );
    *out_creds =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( **out_creds ) ) ),'\0',( 1 ) * ( sizeof( **out_creds ) ) )
        ;
    if( *out_creds == NULL ) {
        krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1278" )
        ;
        ret = ENOMEM;
    } else {
        ret = get_cred_kdc_la( NAME_OF_MAIN_LOC_GLOB_P, context, ccache, flags,
                               in_creds, tgt, *out_creds );
        if( ret ) {
            //StSch Trace Point
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *out_creds )
            ;
            *out_creds = NULL;
        }
    }
    krb5_free_creds( NAME_OF_MAIN_LOC_GLOB_P, context, tgt );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_credentials_with_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                 krb5_flags options,
                                 krb5_kdc_flags flags,
                                 krb5_ccache ccache,
                                 krb5_creds *in_creds,
                                 krb5_creds **out_creds )
{
    krb5_error_code ret;
    krb5_creds **tgts;
    krb5_creds *res_creds;
    int i;
    *out_creds = NULL;
    res_creds =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( *res_creds ) ) ),'\0',( 1 ) * ( sizeof( *res_creds ) ) )
        ;
    if( res_creds == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_cred.c 1279" )
        ;
        return ENOMEM;
    }
    if( in_creds->session.keytype )
        options |= KRB5_TC_MATCH_KEYTYPE;
    if( NAME_OF_MAIN_LOC_GLOB_P->im_control_1 ) {
        /*
          * If we got a credential, check if credential is expired before
          * returning it.
          */
        ret = krb5_cc_retrieve_cred( NAME_OF_MAIN_LOC_GLOB_P, context,
                                     ccache,
                                     in_creds->session.keytype ?
                                     KRB5_TC_MATCH_KEYTYPE : 0,
                                     in_creds, res_creds );
        /*
         * If we got a credential, check if credential is expired before
         * returning it, but only if KRB5_GC_EXPIRED_OK is not set.
         */
        if( ret == 0 ) {
            krb5_timestamp timeret;
            if( options & KRB5_GC_EXPIRED_OK ) {
                *out_creds = res_creds;
                return 0;
            }
            krb5_timeofday( NAME_OF_MAIN_LOC_GLOB_P, context, &timeret );
            if( res_creds->times.endtime > timeret ) {
                *out_creds = res_creds;
                return 0;
            } else if( context->client_server )
                //StSch Trace Point
                krb5_err( NAME_OF_MAIN_LOC_GLOB_P, context, 1, KRB5KRB_AP_ERR_TKT_EXPIRED,"Ticket expired!" )
                ;
            if( options & KRB5_GC_CACHED )
                krb5_cc_remove_cred( NAME_OF_MAIN_LOC_GLOB_P, context, ccache, 0, res_creds );
        } else if( ret != KRB5_CC_END ) {
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, res_creds )
            ;
            return ret;
        }
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, res_creds )
        ;
        if( options & KRB5_GC_CACHED ) {
            krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
            return KRB5_CC_NOTFOUND;
        }
        if( options & KRB5_GC_USER_USER )
            flags.b.enc_tkt_in_skey = 1;
    }
    tgts = NULL;
    if( !context->client_server )
        ret = get_cred_from_kdc_flags( NAME_OF_MAIN_LOC_GLOB_P, context, flags, ccache,
                                       in_creds, out_creds, &tgts );
    else
        //StSch Trace Point
        krb5_err( NAME_OF_MAIN_LOC_GLOB_P, context, 1, ret,"No appropriate ticket in CCache!" )
        ;
    for( i = 0; tgts && tgts[i]; i++ ) {
        krb5_cc_store_cred(	NAME_OF_MAIN_LOC_GLOB_P, context, ccache, tgts[i] );
        krb5_free_creds(	NAME_OF_MAIN_LOC_GLOB_P, context, tgts[i] );
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tgts )
    ;
    if( ret == 0 && flags.b.enc_tkt_in_skey == 0 )
        krb5_cc_store_cred(	NAME_OF_MAIN_LOC_GLOB_P, context, ccache, *out_creds );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_credentials( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      krb5_flags options,
                      krb5_ccache ccache,
                      krb5_creds *in_creds,
                      krb5_creds **out_creds )
{
    krb5_kdc_flags flags;
    flags.i = 0;
    return krb5_get_credentials_with_flags( NAME_OF_MAIN_LOC_GLOB_P, context, options, flags,
                                            ccache, in_creds, out_creds );
}
/*
 * Return the first default realm.  For compatibility.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_default_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                        krb5_realm *realm )
{
    krb5_error_code ret;
    char *res;
    if( context->default_realms == NULL
            || context->default_realms[0] == NULL ) {
        krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P, context,"No default realm available!","get_default_realm.c 1263" )
        ;
        return KRB5_CONFIG_NODEFREALM;
    }
    //for(res=context->default_realms[0]; *res!='\0';res++)
    //{
    //
    //}
    res = m_strdup_hl( NAME_OF_MAIN_LOC_GLOB_P, context->default_realms[0] );
    if( res == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_default_realm.c 1264" )
        ;
        return ENOMEM;
    }
    *realm = res;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_init_etype( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 unsigned *len,
                 krb5_enctype **val,
                 const krb5_enctype *etypes )
{
    int i;
    krb5_error_code ret;
    krb5_enctype *tmp = NULL;
    ret = 0;
    if( etypes == NULL ) {
        ret = krb5_get_default_in_tkt_etypes(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                                &tmp );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
        etypes = tmp;
    }
    for( i = 0; etypes[i]; ++i )
        ;
    *len = i;
    *val =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, i * sizeof( **val ) )
        ;
    if( i != 0 && *val == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_in_tkt.c 1359" )
        ;
        goto cleanup;
    }
    memmove( *val,
             etypes,
             i * sizeof( *tmp ) );
    cleanup:
    if( tmp != NULL )
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tmp )
        ;
    return ret;
}
static krb5_error_code
decrypt_tkt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
             krb5_keyblock *key,
             krb5_key_usage usage,
             krb5_const_pointer decrypt_arg,
             krb5_kdc_rep *dec_rep )
{
    krb5_error_code ret;
    krb5_data data;
    size_t size;
    krb5_crypto crypto;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_decrypt_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, context,
                                      crypto,
                                      usage,
                                      &dec_rep->kdc_rep.enc_part,
                                      &data );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_decode_EncASRepPart( NAME_OF_MAIN_LOC_GLOB_P, context,
                                    data.data,
                                    data.length,
                                    &dec_rep->enc_part,
                                    &size );
    if( ret ) {
        //StSch Trace Point
        ret = krb5_decode_EncTGSRepPart(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                            data.data,
                                            data.length,
                                            &dec_rep->enc_part,
                                            &size );
    }
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &data );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    return 0;
}
int
_krb5_extract_ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      krb5_kdc_rep *rep,
                      krb5_creds *creds,
                      krb5_keyblock *key,
                      krb5_const_pointer keyseed,
                      krb5_key_usage key_usage,
                      krb5_addresses *addrs,
                      unsigned nonce,
                      krb5_boolean allow_server_mismatch,
                      krb5_boolean ignore_cname,
                      krb5_decrypt_proc decrypt_proc,
                      krb5_const_pointer decryptarg )
{
    krb5_error_code ret;
    krb5_principal tmp_principal;
    int tmp;
    size_t len;
    time_t tmp_time;
    krb5_timestamp sec_now;
    ret = _krb5_principalname2krb5_principal( NAME_OF_MAIN_LOC_GLOB_P, &tmp_principal,
            rep->kdc_rep.cname,
            rep->kdc_rep.crealm );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    if( !ignore_cname ) {
        tmp = krb5_principal_compare(	NAME_OF_MAIN_LOC_GLOB_P, context, tmp_principal, creds->client );
        if( !tmp ) {
            //StSch Trace Point
            krb5_free_principal(	NAME_OF_MAIN_LOC_GLOB_P, context, tmp_principal );
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            ret = KRB5KRB_AP_ERR_MODIFIED;
            goto out;
        }
    }
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, creds->client );
    creds->client = tmp_principal;
    ASN1_MALLOC_ENCODE( Ticket, creds->ticket.data, creds->ticket.length,
                        &rep->kdc_rep.ticket, &len, ret );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    if( creds->ticket.length != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"get_in_tkt.c 10041: internal error in ASN.1 encoder" );
    creds->second_ticket.length = 0;
    creds->second_ticket.data   = NULL;
    ret = _krb5_principalname2krb5_principal( NAME_OF_MAIN_LOC_GLOB_P, &tmp_principal,
            rep->kdc_rep.ticket.sname,
            rep->kdc_rep.ticket.realm );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    if( allow_server_mismatch ) {
        krb5_free_principal(	NAME_OF_MAIN_LOC_GLOB_P, context, creds->server );
        creds->server = tmp_principal;
        tmp_principal = NULL;
    } else {
        tmp = krb5_principal_compare(	NAME_OF_MAIN_LOC_GLOB_P, context, tmp_principal, creds->server );
        krb5_free_principal(	NAME_OF_MAIN_LOC_GLOB_P, context, tmp_principal );
        if( !tmp ) {
            //StSch Trace Point
            ret = KRB5KRB_AP_ERR_MODIFIED;
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            goto out;
        }
    }
    if( decrypt_proc == NULL )
        decrypt_proc = decrypt_tkt;
    ret = ( *decrypt_proc )( NAME_OF_MAIN_LOC_GLOB_P, context, key, key_usage, decryptarg, rep );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
#if 0
    ret = krb5_decode_keyblock( context, &rep->enc_part.key, 1 );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
#endif
    if( nonce != rep->enc_part.nonce ) {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_MODIFIED;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","get_in_tkt.c 1360" )
        ;
        goto out;
    }
    krb5_timeofday( NAME_OF_MAIN_LOC_GLOB_P, context, &sec_now );                   //org_JF
    if( rep->enc_part.flags.initial
            && context->kdc_sec_offset == 0 ) {
        context->kdc_sec_offset = rep->enc_part.authtime - sec_now;
        krb5_timeofday( NAME_OF_MAIN_LOC_GLOB_P, context, &sec_now );
    };
    if( rep->enc_part.starttime ) {
        tmp_time = *rep->enc_part.starttime;
    } else
        tmp_time = rep->enc_part.authtime;
    if( creds->times.starttime == 0
            && abs( tmp_time - sec_now ) > context->max_skew ) {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_SKEW;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"time skew () larger than max ()","get_in_tkt.c 1361" )
        ;
        goto out;
    }
    if( creds->times.starttime != 0
            && tmp_time != creds->times.starttime ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5KRB_AP_ERR_MODIFIED;
        goto out;
    }
    creds->times.starttime = tmp_time;
    if( rep->enc_part.renew_till ) {
        tmp_time = *rep->enc_part.renew_till;
    } else
        tmp_time = 0;
    if( creds->times.renew_till != 0
            && tmp_time > creds->times.renew_till ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5KRB_AP_ERR_MODIFIED;
        goto out;
    }
    creds->times.renew_till = tmp_time;
    creds->times.authtime = rep->enc_part.authtime;
    if( creds->times.endtime != 0
            && rep->enc_part.endtime > creds->times.endtime ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5KRB_AP_ERR_MODIFIED;
        goto out;
    }
    creds->times.endtime  = rep->enc_part.endtime;
    if( rep->enc_part.caddr )
        krb5_copy_addresses(	NAME_OF_MAIN_LOC_GLOB_P, context, rep->enc_part.caddr, &creds->addresses );
    else if( addrs )
        krb5_copy_addresses(	NAME_OF_MAIN_LOC_GLOB_P, context, addrs, &creds->addresses );
    else {
        creds->addresses.len = 0;
        creds->addresses.val = NULL;
    }
    creds->flags.b = rep->enc_part.flags;
    creds->authdata.len = 0;
    creds->authdata.val = NULL;
    creds->session.keyvalue.length = 0;
    creds->session.keyvalue.data   = NULL;
    creds->session.keytype = rep->enc_part.key.keytype;
    ret = krb5_data_copy( NAME_OF_MAIN_LOC_GLOB_P, &creds->session.keyvalue,
                          rep->enc_part.key.keyvalue.data,
                          rep->enc_part.key.keyvalue.length );
    out:
    memset( rep->enc_part.key.keyvalue.data, 0,
            rep->enc_part.key.keyvalue.length );
    return ret;
}
void initialize_heim_error_table_r( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct et_list **list )
{
    initialize_error_table_r( NAME_OF_MAIN_LOC_GLOB_P, list, heim_error_strings, 140, ERROR_TABLE_BASE_heim );
}
void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_init( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *opt )
{
    memset( opt, 0, sizeof( *opt ) );
    opt->flags = 0;
    opt->opt_private = NULL;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_alloc( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                               krb5_get_init_creds_opt **opt )
{
    krb5_get_init_creds_opt *o;
    *opt = NULL;
    o =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( *o ) ) ),'\0',( 1 ) * ( sizeof( *o ) ) )
        ;
    if( o == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"out of memory","init_creds.c 1295" )
        ;
        return ENOMEM;
    }
    krb5_get_init_creds_opt_init( NAME_OF_MAIN_LOC_GLOB_P, o );
    o->opt_private =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( *o->opt_private ) ) ),'\0',( 1 ) * ( sizeof( *o->opt_private ) ) )
        ;
    if( o->opt_private == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"out of memory","init_creds.c 1296" )
        ;
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, o )
        ;
        return ENOMEM;
    }
    o->opt_private->refcount = 1;
    *opt = o;
    return 0;
}
krb5_error_code
_krb5_get_init_creds_opt_copy( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                               const krb5_get_init_creds_opt *in,
                               krb5_get_init_creds_opt **out )
{
    krb5_get_init_creds_opt *opt;
    *out = NULL;
    opt =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *opt ) )
        ;
    if( opt == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"out of memory","init_creds.c 1297" )
        ;
        return ENOMEM;
    }
    if( in )
        *opt = *in;
    if( opt->opt_private == NULL ) {
        opt->opt_private =
            memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( *opt->opt_private ) ) ),'\0',( 1 ) * ( sizeof( *opt->opt_private ) ) )
            ;
        if( opt->opt_private == NULL ) {
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"out of memory","init_creds.c 1298" )
            ;
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, opt )
            ;
            return ENOMEM;
        }
        opt->opt_private->refcount = 1;
    } else
        opt->opt_private->refcount++;
    *out = opt;
    return 0;
}
void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *opt )
{
    if( opt->opt_private == NULL )
        return;
    if( opt->opt_private->refcount < 1 )
        return;
    if( --opt->opt_private->refcount == 0 ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, opt->opt_private )
        ;
    }
    memset( opt, 0, sizeof( *opt ) );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, opt )
    ;
}
void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_tkt_life( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *opt,
                                      krb5_deltat tkt_life )
{
    opt->flags |= KRB5_GET_INIT_CREDS_OPT_TKT_LIFE;
    opt->tkt_life = tkt_life;
}
void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_renew_life( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *opt,
                                        krb5_deltat renew_life )
{
    opt->flags |= KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE;
    opt->renew_life = renew_life;
}
void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_forwardable( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *opt,
        int forwardable )
{
    opt->flags |= KRB5_GET_INIT_CREDS_OPT_FORWARDABLE;
    opt->forwardable = forwardable;
}
void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_proxiable( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *opt,
                                       int proxiable )
{
    opt->flags |= KRB5_GET_INIT_CREDS_OPT_PROXIABLE;
    opt->proxiable = proxiable;
}
void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_etype_list( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *opt,
                                        krb5_enctype *etype_list,
                                        int etype_list_length )
{
    opt->flags |= KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST;
    opt->etype_list = etype_list;
    opt->etype_list_length = etype_list_length;
}
void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_address_list( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *opt,
        krb5_addresses *addresses )
{
    opt->flags |= KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST;
    opt->address_list = addresses;
}
void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_anonymous( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_get_init_creds_opt *opt,
                                       int anonymous )
{
    opt->flags |= KRB5_GET_INIT_CREDS_OPT_ANONYMOUS;
    opt->anonymous = anonymous;
}
static krb5_error_code
require_ext_opt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 krb5_get_init_creds_opt *opt,
                 const char *type )
{
    if( opt->opt_private == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context," on non extendable opt","init_creds.c 1299" )
        ;
        return EINVAL;
    }
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_pa_password( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
        krb5_get_init_creds_opt *opt,
        const char *password,
        krb5_s2k_proc key_proc )
{
    krb5_error_code ret;
    ret = require_ext_opt( NAME_OF_MAIN_LOC_GLOB_P, context, opt, "init_creds_opt_set_pa_password" );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    opt->opt_private->password = password;
    opt->opt_private->key_proc = key_proc;
    return 0;
}
typedef struct krb5_get_init_creds_ctx {
    krb5_kdc_flags flags;
    krb5_creds cred;
    krb5_addresses *addrs;
    krb5_enctype *etypes;
    krb5_preauthtype *pre_auth_types;
    const char *in_tkt_service;
    unsigned nonce;
    unsigned pk_nonce;
    AS_REQ as_req;
    int pa_counter;
    const char *password;
    krb5_s2k_proc key_proc;
    krb5_get_init_creds_req_pac req_pac;
    krb5_pk_init_ctx pk_init_ctx;
} krb5_get_init_creds_ctx;
static krb5_error_code
default_s2k_func( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_enctype type,
                  krb5_const_pointer keyseed,
                  krb5_salt salt, krb5_data *s2kparms,
                  krb5_keyblock **key )
{
    krb5_error_code ret;
    krb5_data password;
    krb5_data opaque;
    password.data = ( void * )keyseed;
    password.length = strlen( keyseed );
    if( s2kparms )
        opaque = *s2kparms;
    else
        krb5_data_zero(	NAME_OF_MAIN_LOC_GLOB_P, &opaque );
    *key =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( **key ) )
        ;
    if( *key == NULL )
        return ENOMEM;
    ret = krb5_string_to_key_data_salt_opaque( NAME_OF_MAIN_LOC_GLOB_P, context, type, password,
            salt, opaque, *key );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *key )
        ;
    }
    return ret;
}
static void
free_init_creds_ctx( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_get_init_creds_ctx *ctx )
{
    if( ctx->etypes )
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ctx->etypes )
        ;
    if( ctx->pre_auth_types )
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ctx->pre_auth_types )
        ;
    free_AS_REQ( NAME_OF_MAIN_LOC_GLOB_P, &ctx->as_req );
    memset( &ctx->as_req, 0, sizeof( ctx->as_req ) );
}
static krb5_error_code
init_cred( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
           krb5_creds *cred,
           krb5_principal client,
           krb5_deltat start_time,
           const char *in_tkt_service,
           krb5_get_init_creds_opt *options )
{
    krb5_error_code ret;
    krb5_const_realm client_realm;
    int tmp;
    krb5_timestamp now;
    krb5_timeofday( NAME_OF_MAIN_LOC_GLOB_P, context, &now );
    memset( cred, 0, sizeof( *cred ) );
    if( client )
        krb5_copy_principal( NAME_OF_MAIN_LOC_GLOB_P, context, client, &cred->client );
    else {
        //StSch Trace Point
        ret = 1;
        goto out;
    }
    client_realm = krb5_principal_get_realm( NAME_OF_MAIN_LOC_GLOB_P, context, cred->client );
    if( start_time )
        cred->times.starttime  = now + start_time;
    if( options->flags & KRB5_GET_INIT_CREDS_OPT_TKT_LIFE )
        tmp = options->tkt_life;
    else
        tmp = 10 * 60 * 60;
    cred->times.endtime = now + tmp;
    if(( options->flags & KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE ) &&
            options->renew_life > 0 ) {
        cred->times.renew_till = now + options->renew_life;
    }
    if( in_tkt_service ) {
        krb5_realm server_realm;
        ret = krb5_parse_name( NAME_OF_MAIN_LOC_GLOB_P, context, in_tkt_service, &cred->server );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
        server_realm = m_strdup_hl( NAME_OF_MAIN_LOC_GLOB_P, client_realm );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *krb5_princ_realm( NAME_OF_MAIN_LOC_GLOB_P, context, cred->server ) )
        ;
        krb5_princ_set_realm( NAME_OF_MAIN_LOC_GLOB_P, context, cred->server, &server_realm );
    } else {
        //StSch Trace Point
        ret = 1;
        goto out;
    }
    return 0;
    out:
    krb5_free_cred_contents( NAME_OF_MAIN_LOC_GLOB_P, context, cred );
    return ret;
}
static krb5_error_code
get_init_creds_common( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       krb5_creds *creds,
                       krb5_principal client,
                       krb5_deltat start_time,
                       const char *in_tkt_service,
                       krb5_get_init_creds_opt *options,
                       krb5_get_init_creds_ctx *ctx )
{
    krb5_get_init_creds_opt default_opt;
    krb5_error_code ret;
    krb5_enctype *etypes;
    krb5_preauthtype *pre_auth_types;
    memset( ctx, 0, sizeof( *ctx ) );
    if( options == NULL ) {
        krb5_get_init_creds_opt_init(	NAME_OF_MAIN_LOC_GLOB_P, &default_opt );
        options = &default_opt;
    }
    if( options->opt_private ) {
        ctx->password = options->opt_private->password;
        ctx->key_proc = options->opt_private->key_proc;
        ctx->req_pac = options->opt_private->req_pac;
        ctx->pk_init_ctx = options->opt_private->pk_init_ctx;
    } else
        ctx->req_pac = KRB5_PA_PAC_DONT_CARE;
    if( ctx->key_proc == NULL )
        ctx->key_proc = default_s2k_func;
    ctx->pre_auth_types = NULL;
    ctx->flags.i = 0;
    ctx->addrs = NULL;
    ctx->etypes = NULL;
    ctx->pre_auth_types = NULL;
    ctx->in_tkt_service = in_tkt_service;
    ret = init_cred( NAME_OF_MAIN_LOC_GLOB_P, context, &ctx->cred, client, start_time,
                     in_tkt_service, options );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ctx->flags.i = 0;
    if( options->flags & KRB5_GET_INIT_CREDS_OPT_FORWARDABLE )
        ctx->flags.b.forwardable = options->forwardable;
    if( options->flags & KRB5_GET_INIT_CREDS_OPT_PROXIABLE )
        ctx->flags.b.proxiable = options->proxiable;
    if( start_time )
        ctx->flags.b.postdated = 1;
    if( ctx->cred.times.renew_till )
        ctx->flags.b.renewable = 1;
    if( options->flags & KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST )
        ctx->addrs = options->address_list;
    if( options->flags & KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST ) {
        etypes =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( options->etype_list_length + 1 )
                              * sizeof( krb5_enctype ) )
            ;
        if( etypes == NULL ) {
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","init_creds_pw.c 1342" )
            ;
            return ENOMEM;
        }
        memcpy( etypes, options->etype_list,
                options->etype_list_length * sizeof( krb5_enctype ) );
        etypes[options->etype_list_length] = ETYPE_NULL;
        ctx->etypes = etypes;
    }
    if( options->flags & KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST ) {
        pre_auth_types =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( options->preauth_list_length + 1 )
                              * sizeof( krb5_preauthtype ) )
            ;
        if( pre_auth_types == NULL ) {
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","init_creds_pw.c 1343" )
            ;
            return ENOMEM;
        }
        memcpy( pre_auth_types, options->preauth_list,
                options->preauth_list_length * sizeof( krb5_preauthtype ) );
        pre_auth_types[options->preauth_list_length] = KRB5_PADATA_NONE;
        ctx->pre_auth_types = pre_auth_types;
    }
    if( options->flags & KRB5_GET_INIT_CREDS_OPT_SALT )
        ;
    if( options->flags & KRB5_GET_INIT_CREDS_OPT_ANONYMOUS )
        ctx->flags.b.request_anonymous = options->anonymous;
    return 0;
}
static krb5_error_code
init_creds_init_as_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                        krb5_kdc_flags opts,
                        const krb5_creds *creds,
                        const krb5_addresses *addrs,
                        const krb5_enctype *etypes,
                        AS_REQ *a )
{
    krb5_error_code ret;
    memset( a, 0, sizeof( *a ) );
    a->pvno = 5;
    a->msg_type = krb_as_req;
    a->req_body.kdc_options = opts.b;
    a->req_body.cname =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *a->req_body.cname ) )
        ;
    if( a->req_body.cname == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","init_creds_pw.c 1346" )
        ;
        goto fail;
    }
    a->req_body.sname =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *a->req_body.sname ) )
        ;
    if( a->req_body.sname == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","init_creds_pw.c 1347" )
        ;
        goto fail;
    }
    if( creds->client ) {
        ret = _krb5_principal2principalname(	NAME_OF_MAIN_LOC_GLOB_P, a->req_body.cname, creds->client );
        if( ret ) {
            //StSch Trace Point
            goto fail;
        }
        ret = copy_Realm(	NAME_OF_MAIN_LOC_GLOB_P, &creds->client->realm, &a->req_body.realm );
        if( ret ) {
            //StSch Trace Point
            goto fail;
        }
    } else {
        krb5_realm realm;
        a->req_body.cname = NULL;
        ret = krb5_get_default_realm(	NAME_OF_MAIN_LOC_GLOB_P, context, &realm );
        if( ret ) {
            //StSch Trace Point
            goto fail;
        }
        ret = copy_Realm(	NAME_OF_MAIN_LOC_GLOB_P, &realm, &a->req_body.realm );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, realm )
        ;
    }
    ret = _krb5_principal2principalname( NAME_OF_MAIN_LOC_GLOB_P, a->req_body.sname, creds->server );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    if( creds->times.starttime ) {
        a->req_body.from =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *a->req_body.from ) )
            ;
        if( a->req_body.from == NULL ) {
            //StSch Trace Point
            ret = ENOMEM;
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","init_creds_pw.c 1348" )
            ;
            goto fail;
        }
        *a->req_body.from = creds->times.starttime;
    }
    if( creds->times.endtime ) {
        ALLOC( a->req_body.till, 1 );
        *a->req_body.till = creds->times.endtime;
    }
    if( creds->times.renew_till ) {
        a->req_body.rtime =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *a->req_body.rtime ) )
            ;
        if( a->req_body.rtime == NULL ) {
            //StSch Trace Point
            ret = ENOMEM;
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","init_creds_pw.c 1349" )
            ;
            goto fail;
        }
        *a->req_body.rtime = creds->times.renew_till;
    }
    a->req_body.nonce = 0;
    ret = krb5_init_etype( NAME_OF_MAIN_LOC_GLOB_P, context,
                           &a->req_body.etype.len,
                           &a->req_body.etype.val,
                           etypes );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    /*
     * This means no addresses
     */
    if( addrs && addrs->len == 0 ) {
        a->req_body.addresses = NULL;
    } else {
        a->req_body.addresses =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *a->req_body.addresses ) )
            ;
        if( a->req_body.addresses == NULL ) {
            //StSch Trace Point
            ret = ENOMEM;
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","init_creds_pw.c 1350" )
            ;
            goto fail;
        }
        if( addrs )
            ret = krb5_copy_addresses(	NAME_OF_MAIN_LOC_GLOB_P, context, addrs, a->req_body.addresses );
        else {
            ret = krb5_get_all_client_addrs(	NAME_OF_MAIN_LOC_GLOB_P, context, a->req_body.addresses );
            if( ret == 0 && a->req_body.addresses->len == 0 ) {
                m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, a->req_body.addresses )
                ;
                a->req_body.addresses = NULL;
            }
        }
        if( ret ) {
            //StSch Trace Point
            goto fail;
        }
    }
    a->req_body.enc_authorization_data = NULL;
    a->req_body.additional_tickets = NULL;
    a->padata = NULL;
    return 0;
    fail:
    free_AS_REQ( NAME_OF_MAIN_LOC_GLOB_P, a );
    memset( a, 0, sizeof( *a ) );
    return ret;
}
static void
free_paid( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, struct pa_info_data *ppaid )
{
    krb5_free_salt( NAME_OF_MAIN_LOC_GLOB_P, context, ppaid->salt );
    if( ppaid->s2kparams )
        krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, ppaid->s2kparams );
}
static krb5_error_code
set_paid( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct pa_info_data *paid, krb5_context context,
          krb5_enctype etype,
          krb5_salttype salttype, void *salt_string, size_t salt_len,
          krb5_data *s2kparams )
{
    paid->etype = etype;
    paid->salt.salttype = salttype;
    paid->salt.saltvalue.data =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, salt_len + 1 )
        ;
    if( paid->salt.saltvalue.data == NULL ) {
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return ENOMEM;
    }
    memcpy( paid->salt.saltvalue.data, salt_string, salt_len );
    (( char * )paid->salt.saltvalue.data )[salt_len] = '\0';
    paid->salt.saltvalue.length = salt_len;
    if( s2kparams ) {
        krb5_error_code ret;
        ret = krb5_copy_data(	NAME_OF_MAIN_LOC_GLOB_P, context, s2kparams, &paid->s2kparams );
        if( ret ) {
            //StSch Trace Point
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            krb5_free_salt(	NAME_OF_MAIN_LOC_GLOB_P, context, paid->salt );
            return ret;
        }
    } else
        paid->s2kparams = NULL;
    return 0;
}
struct pa_info_data *
pa_etype_info2( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                const krb5_principal client,
                const AS_REQ *asreq,
                struct pa_info_data *paid,
                heim_octet_string *data ) {
    krb5_error_code ret;
    ETYPE_INFO2 e;
    size_t sz;
    int i, j;
    memset( &e, 0, sizeof( e ) );
    ret = decode_ETYPE_INFO2( NAME_OF_MAIN_LOC_GLOB_P, data->data, data->length, &e, &sz );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    if( e.len == 0 )
        //StSch Trace Point
        goto out;
    for( j = 0; j < asreq->req_body.etype.len; j++ ) {
        for( i = 0; i < e.len; i++ ) {
            if( asreq->req_body.etype.val[j] == e.val[i].etype ) {
                krb5_salt salt;
                if( e.val[i].salt == NULL )
                    ret = krb5_get_pw_salt(	NAME_OF_MAIN_LOC_GLOB_P, context, client, &salt );
                else {
                    salt.saltvalue.data = *e.val[i].salt;
                    salt.saltvalue.length = strlen( *e.val[i].salt );
                    ret = 0;
                }
                if( ret == 0 )
                    ret = set_paid(	NAME_OF_MAIN_LOC_GLOB_P, paid, context, e.val[i].etype,
                                    KRB5_PW_SALT,
                                    salt.saltvalue.data,
                                    salt.saltvalue.length,
                                    e.val[i].s2kparams );
                if( e.val[i].salt == NULL )
                    krb5_free_salt(	NAME_OF_MAIN_LOC_GLOB_P, context, salt );
                if( ret == 0 ) {
                    free_ETYPE_INFO2(	NAME_OF_MAIN_LOC_GLOB_P, &e );
                    return paid;
                }
            }
        }
    }
    out:
    free_ETYPE_INFO2( NAME_OF_MAIN_LOC_GLOB_P, &e );
    return NULL;
}
struct pa_info_data *
pa_etype_info( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               const krb5_principal client,
               const AS_REQ *asreq,
               struct pa_info_data *paid,
               heim_octet_string *data ) {
    krb5_error_code ret;
    ETYPE_INFO e;
    size_t sz;
    int i, j;
    memset( &e, 0, sizeof( e ) );
    ret = decode_ETYPE_INFO( NAME_OF_MAIN_LOC_GLOB_P, data->data, data->length, &e, &sz );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    if( e.len == 0 )
        //StSch Trace Point
        goto out;
    for( j = 0; j < asreq->req_body.etype.len; j++ ) {
        for( i = 0; i < e.len; i++ ) {
            if( asreq->req_body.etype.val[j] == e.val[i].etype ) {
                krb5_salt salt;
                salt.salttype = KRB5_PW_SALT;
                if( e.val[i].salt == NULL )
                    ret = krb5_get_pw_salt(	NAME_OF_MAIN_LOC_GLOB_P, context, client, &salt );
                else {
                    salt.saltvalue = *e.val[i].salt;
                    ret = 0;
                }
                if( e.val[i].salttype )
                    salt.salttype = *e.val[i].salttype;
                if( ret == 0 ) {
                    ret = set_paid(	NAME_OF_MAIN_LOC_GLOB_P, paid, context, e.val[i].etype,
                                    salt.salttype,
                                    salt.saltvalue.data,
                                    salt.saltvalue.length,
                                    NULL );
                    if( e.val[i].salt == NULL )
                        krb5_free_salt(	NAME_OF_MAIN_LOC_GLOB_P, context, salt );
                }
                if( ret == 0 ) {
                    free_ETYPE_INFO(	NAME_OF_MAIN_LOC_GLOB_P, &e );
                    return paid;
                }
            }
        }
    }
    out:
    free_ETYPE_INFO( NAME_OF_MAIN_LOC_GLOB_P, &e );
    return NULL;
}
struct pa_info_data *
pa_pw_or_afs3_salt( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    const krb5_principal client,
                    const AS_REQ *asreq,
                    struct pa_info_data *paid,
                    heim_octet_string *data ) {
    krb5_error_code ret;
    if( paid->etype == ENCTYPE_NULL )
        return NULL;
    ret = set_paid( NAME_OF_MAIN_LOC_GLOB_P, paid, context,
                    paid->etype,
                    paid->salt.salttype,
                    data->data,
                    data->length,
                    NULL );
    if( ret ) {
        //StSch Trace Point
        return NULL;
    }
    return paid;
}

static struct pa_info pa_prefs[] = {
    { KRB5_PADATA_ETYPE_INFO2, pa_etype_info2 },
    { KRB5_PADATA_ETYPE_INFO, pa_etype_info },
    { KRB5_PADATA_PW_SALT, pa_pw_or_afs3_salt },
    { KRB5_PADATA_AFS3_SALT, pa_pw_or_afs3_salt }
};

static PA_DATA *
find_pa_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const METHOD_DATA *md, int type )
{
    int i;
    for( i = 0; i < md->len; i++ )
        if( md->val[i].padata_type == type )
            return &md->val[i];
    return NULL;
}
static struct pa_info_data *
process_pa_info( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 const krb5_principal client,
                 const AS_REQ *asreq,
                 struct pa_info_data *paid,
                 METHOD_DATA *md ) {
    struct pa_info_data *p = NULL;
    int i;
    for( i = 0; p == NULL && i < sizeof( pa_prefs )/sizeof( pa_prefs[0] ); i++ ) {
        PA_DATA *pa = find_pa_data(	NAME_OF_MAIN_LOC_GLOB_P, md, pa_prefs[i].type );
        if( pa == NULL )
            continue;
        paid->salt.salttype = pa_prefs[i].type;
        p = ( * pa_prefs[i].salt_info )(	NAME_OF_MAIN_LOC_GLOB_P, context, client, asreq,
                                            paid, &pa->padata_value );
    }
    return p;
}
static krb5_error_code
make_pa_enc_timestamp( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, METHOD_DATA *md,
                       krb5_enctype etype, krb5_keyblock *key )
{
    PA_ENC_TS_ENC p;
    unsigned char *buf;
    size_t buf_size;
    size_t len;
    EncryptedData encdata;
    krb5_error_code ret;
    int32_t usec;
    int usec2;
    krb5_crypto crypto;
    krb5_us_timeofday( NAME_OF_MAIN_LOC_GLOB_P, context, &p.patimestamp, &usec );
    usec2         = usec;
    p.pausec      = &usec2;
    ASN1_MALLOC_ENCODE( PA_ENC_TS_ENC, buf, buf_size, &p, &len, ret );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"init_creds_pw.c 10036: internal error in ASN.1 encoder" );
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        return ret;
    }
    ret = krb5_encrypt_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, context,
                                      crypto,
                                      KRB5_KU_PA_ENC_TIMESTAMP,
                                      buf,
                                      len,
                                      0,
                                      &encdata );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ASN1_MALLOC_ENCODE( EncryptedData, buf, buf_size, &encdata, &len, ret );
    free_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, &encdata );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"init_creds_pw.c 10037: internal error in ASN.1 encoder" );
    ret = krb5_padata_add( NAME_OF_MAIN_LOC_GLOB_P, context, md, KRB5_PADATA_ENC_TIMESTAMP, buf, len );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
    }
    return ret;
}
static krb5_error_code
add_enc_ts_padata( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   METHOD_DATA *md,
                   krb5_principal client,
                   krb5_s2k_proc key_proc,
                   krb5_const_pointer keyseed,
                   krb5_enctype *enctypes,
                   unsigned netypes,
                   krb5_salt *salt,
                   krb5_data *s2kparams )
{
    krb5_error_code ret;
    krb5_salt salt2;
    krb5_enctype *ep;
    int i;
    if( salt == NULL ) {
        ret = krb5_get_pw_salt(	NAME_OF_MAIN_LOC_GLOB_P, context, client, &salt2 );
        salt = &salt2;
    }
    if( !enctypes ) {
        enctypes = context->etypes;
        netypes = 0;
        for( ep = enctypes; *ep != ETYPE_NULL; ep++ )
            netypes++;
    }
    for( i = 0; i < netypes; ++i ) {
        krb5_keyblock *key;
        ret = ( *key_proc )(	NAME_OF_MAIN_LOC_GLOB_P, context, enctypes[i], keyseed,
                                *salt, s2kparams, &key );
        if( ret ) {
            //StSch Trace Point
            continue;
        }
        ret = make_pa_enc_timestamp(	NAME_OF_MAIN_LOC_GLOB_P, context, md, enctypes[i], key );
        krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, key );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
    }
    if( salt == &salt2 )
        krb5_free_salt(	NAME_OF_MAIN_LOC_GLOB_P, context, salt2 );
    return 0;
}
static krb5_error_code
pa_data_to_md_ts_enc( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      const AS_REQ *a,
                      const krb5_principal client,
                      krb5_get_init_creds_ctx *ctx,
                      struct pa_info_data *ppaid,
                      METHOD_DATA *md )
{
    if( ctx->key_proc == NULL || ctx->password == NULL )
        return 0;
    if( ppaid ) {
        add_enc_ts_padata(	NAME_OF_MAIN_LOC_GLOB_P, context, md, client,
                            ctx->key_proc, ctx->password,
                            &ppaid->etype, 1,
                            &ppaid->salt, ppaid->s2kparams );
    } else {
        krb5_salt salt;
        add_enc_ts_padata(	NAME_OF_MAIN_LOC_GLOB_P, context, md, client,
                            ctx->key_proc, ctx->password,
                            a->req_body.etype.val, a->req_body.etype.len,
                            NULL, NULL );
        salt.salttype = KRB5_PW_SALT;
        krb5_data_zero(	NAME_OF_MAIN_LOC_GLOB_P, &salt.saltvalue );
        add_enc_ts_padata(	NAME_OF_MAIN_LOC_GLOB_P, context, md, client,
                            ctx->key_proc, ctx->password,
                            a->req_body.etype.val, a->req_body.etype.len,
                            &salt, NULL );
    }
    return 0;
}
static krb5_error_code
pa_data_to_key_plain( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      const krb5_principal client,
                      krb5_get_init_creds_ctx *ctx,
                      krb5_salt salt,
                      krb5_data *s2kparams,
                      krb5_enctype etype,
                      krb5_keyblock **key )
{
    krb5_error_code ret;
    ret = ( *ctx->key_proc )( NAME_OF_MAIN_LOC_GLOB_P, context, etype, ctx->password,
                              salt, s2kparams, key );
    return ret;
}
static krb5_error_code
pa_data_to_md_pkinit( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      const AS_REQ *a,
                      const krb5_principal client,
                      krb5_get_init_creds_ctx *ctx,
                      METHOD_DATA *md )
{
    if( ctx->pk_init_ctx == NULL )
        return 0;
#ifdef PKINIT
    return _krb5_pk_mk_padata( context,
                               ctx->pk_init_ctx,
                               &a->req_body,
                               ctx->pk_nonce,
                               md );
#else
    krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P, context,"no support for PKINIT compiled in","init_creds_pw.c 1351" )
    ;
    return EINVAL;
#endif
}
static krb5_error_code
pa_data_add_pac_request( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                         krb5_get_init_creds_ctx *ctx,
                         METHOD_DATA *md )
{
    size_t len, length;
    krb5_error_code ret;
    PA_PAC_REQUEST req;
    void *buf;
    switch( ctx->req_pac ) {
    case KRB5_PA_PAC_DONT_CARE:
            return 0;
    case KRB5_PA_PAC_REQ_TRUE:
            req.include_pac = 1;
        break;
    case KRB5_PA_PAC_REQ_FALSE:
            req.include_pac = 0;
    }
    ASN1_MALLOC_ENCODE( PA_PAC_REQUEST, buf, length,
                        &req, &len, ret );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( len != length )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"init_creds_pw.c 10038: internal error in ASN.1 encoder" );
    ret = krb5_padata_add( NAME_OF_MAIN_LOC_GLOB_P, context, md, KRB5_PADATA_PA_PAC_REQUEST, buf, len );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
    }
    return 0;
}
/*
 * Assumes caller always will free `out_md', even on error.
 */
static krb5_error_code
process_pa_data_to_md( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       const krb5_creds *creds,
                       const AS_REQ *a,
                       krb5_get_init_creds_ctx *ctx,
                       METHOD_DATA *in_md,
                       METHOD_DATA **out_md,
                       krb5_prompter_fct prompter,
                       void *prompter_data )
{
    krb5_error_code ret;
    ALLOC( *out_md, 1 );
    if( *out_md == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","init_creds_pw.c 1352" )
        ;
        return ENOMEM;
    }
    ( *out_md )->len = 0;
    ( *out_md )->val = NULL;
    if( in_md->len != 0 ) {
        struct pa_info_data paid, *ppaid;
        memset( &paid, 0, sizeof( paid ) );
        paid.etype = ENCTYPE_NULL;
        ppaid = process_pa_info(	NAME_OF_MAIN_LOC_GLOB_P, context, creds->client, a, &paid, in_md );
        pa_data_to_md_ts_enc(	NAME_OF_MAIN_LOC_GLOB_P, context, a, creds->client, ctx, ppaid, *out_md );
        if( ppaid )
            free_paid(	NAME_OF_MAIN_LOC_GLOB_P, context, ppaid );
    }
    pa_data_add_pac_request( NAME_OF_MAIN_LOC_GLOB_P, context, ctx, *out_md );
    ret = pa_data_to_md_pkinit( NAME_OF_MAIN_LOC_GLOB_P, context, a, creds->client, ctx, *out_md );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if(( *out_md )->len == 0 ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, *out_md )
        ;
        *out_md = NULL;
    }
    return 0;
}
static krb5_error_code
process_pa_data_to_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                        krb5_get_init_creds_ctx *ctx,
                        krb5_creds *creds,
                        AS_REQ *a,
                        krb5_kdc_rep *rep,
                        krb5_keyblock **key )
{
    struct pa_info_data paid, *ppaid = NULL;
    krb5_error_code ret;
    krb5_enctype etype;
    PA_DATA *pa;
    int index;
    memset( &paid, 0, sizeof( paid ) );
    etype = rep->kdc_rep.enc_part.etype;
    if( rep->kdc_rep.padata ) {
        paid.etype = etype;
        ppaid = process_pa_info(	NAME_OF_MAIN_LOC_GLOB_P, context, creds->client, a, &paid,
                                    rep->kdc_rep.padata );
    }
    if( ppaid == NULL ) {
        ret = krb5_get_pw_salt(	NAME_OF_MAIN_LOC_GLOB_P, context, creds->client, &paid.salt );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
        paid.etype = etype;
        paid.s2kparams = NULL;
    }
    pa = NULL;
    if( rep->kdc_rep.padata ) {
        index = 0;
        pa = krb5_find_padata(	NAME_OF_MAIN_LOC_GLOB_P, rep->kdc_rep.padata->val,
                                rep->kdc_rep.padata->len,
                                KRB5_PADATA_PK_AS_REP,
                                &index );
        if( pa == NULL ) {
            index = 0;
            pa = krb5_find_padata(	NAME_OF_MAIN_LOC_GLOB_P, rep->kdc_rep.padata->val,
                                    rep->kdc_rep.padata->len,
                                    KRB5_PADATA_PK_AS_REP_19,
                                    &index );
        }
    }
    if( pa && ctx->pk_init_ctx ) {
#ifdef PKINIT
        ret = _krb5_pk_rd_pa_reply( context,
                                    ctx->pk_init_ctx,
                                    etype,
                                    ctx->pk_nonce,
                                    pa,
                                    key );
#else
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"no support for PKINIT compiled in","init_creds_pw.c 1353" )
        ;
        ret = EINVAL;
#endif
    } else if( ctx->password )
        ret = pa_data_to_key_plain(	NAME_OF_MAIN_LOC_GLOB_P, context, creds->client, ctx,
                                    paid.salt, paid.s2kparams, etype, key );
    else {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"No usable pa data type","init_creds_pw.c 1354" )
        ;
        ret = EINVAL;
    }
    free_paid( NAME_OF_MAIN_LOC_GLOB_P, context, &paid );
    return ret;
}
static krb5_error_code
init_cred_loop( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                const krb5_get_init_creds_opt *init_cred_opts,
                const krb5_prompter_fct prompter,
                void *prompter_data,
                krb5_get_init_creds_ctx *ctx,
                krb5_creds *creds,
                krb5_kdc_rep *ret_as_reply )
{
    krb5_error_code ret;
    krb5_kdc_rep rep;
    METHOD_DATA md;
    krb5_data resp;
    size_t len;
    size_t size;
    int send_to_kdc_flags = 0;
    memset( &md, 0, sizeof( md ) );
    memset( &rep, 0, sizeof( rep ) );
    if( ret_as_reply )
        memset( ret_as_reply, 0, sizeof( *ret_as_reply ) );
    ret = init_creds_init_as_req( NAME_OF_MAIN_LOC_GLOB_P, context, ctx->flags, creds,
                                  ctx->addrs, ctx->etypes, &ctx->as_req );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, &ctx->nonce, sizeof( ctx->nonce ) );
    ctx->nonce &= 0xffffffff;
    ctx->pk_nonce = ctx->nonce;
    /*
     * Increase counter when we want other pre-auth types then
     * KRB5_PA_ENC_TIMESTAMP.
     */
    ctx->pa_counter = 0;
    while( ctx->pa_counter < MAX_PA_COUNTER ) {
        krb5_data req;
        ctx->pa_counter++;
        if( ctx->as_req.padata ) {
            free_METHOD_DATA(	NAME_OF_MAIN_LOC_GLOB_P, ctx->as_req.padata );
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ctx->as_req.padata )
            ;
            ctx->as_req.padata = NULL;
        }
        ctx->as_req.req_body.nonce = ctx->nonce;
        ret = process_pa_data_to_md(	NAME_OF_MAIN_LOC_GLOB_P, context, creds, &ctx->as_req, ctx,
                                        &md, &ctx->as_req.padata,
                                        prompter, prompter_data );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
        ASN1_MALLOC_ENCODE( AS_REQ, req.data, req.length,
                            &ctx->as_req, &len, ret );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
        if( len != req.length )
            //StSch Trace Point
            krb5_abortx(	NAME_OF_MAIN_LOC_GLOB_P, context,"init_creds_pw.c 10039: internal error in ASN.1 encoder" );
        //StSch Trace Point 6005
        if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
            void* a_temp_memory=0;
            struct dsd_memory_traces* adsl_trace;
            KDC_REQ_BODY ads_req_body= ctx->as_req.req_body;
            char* achl_cname=0;
            char* achl_sname=0;
            long long ill_from=0;
            long long ill_rtime=0;
            char* achl_trace_format="AS-REQ: pvno=%i, msg-type=%i, flags=%i, cname=%s, realm=%s, sname=%s, "
                                    "from=%lli, till=%lli, rtime=%lli, nonce=%u";
            m_aux_stor_start( &a_temp_memory );
            adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
            achl_cname=m_krb5_principalname2string( &a_temp_memory,achl_cname,ads_req_body.cname );
            achl_sname=m_krb5_principalname2string( &a_temp_memory,achl_sname,ads_req_body.sname );
            if( ctx->as_req.padata!=NULL ) {
                int inl_in1=0;
                for( ; inl_in1<ctx->as_req.padata->len; inl_in1++ ) {
                    m_krb5_trace_memcat( &a_temp_memory, adsl_trace,ctx->as_req.padata->val+inl_in1,
                                         sizeof( PA_DATA ),"PA-DATA:" );
                }
            }
            if( ads_req_body.from!=NULL ) {
                ill_from=*ads_req_body.from;
            }
            if( ads_req_body.rtime!=NULL ) {
                ill_rtime=*ads_req_body.rtime;
            }
            m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',6005,
                         adsl_trace, &a_temp_memory, achl_trace_format,ctx->as_req.pvno, ctx->as_req.msg_type,ctx->flags.i,
                         achl_cname,ads_req_body.realm, achl_sname,ill_from, *ads_req_body.till, ill_rtime, ads_req_body.nonce );
            m_aux_stor_end( &a_temp_memory );
        }
        ret = krb5_sendto_kdc_flags(	NAME_OF_MAIN_LOC_GLOB_P, context, &req,
                                        &creds->client->realm, &resp,
                                        send_to_kdc_flags );
        krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &req );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
        memset( &rep, 0, sizeof( rep ) );
        ret = decode_AS_REP(	NAME_OF_MAIN_LOC_GLOB_P, resp.data, resp.length, &rep.kdc_rep, &size );
        if( ret == 0 ) {
            //StSch Trace Point 6006
            if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
                void* a_temp_memory=0;
                struct dsd_memory_traces* adsl_trace;
                char* achl_cname=0;
                char* achl_sname=0;
                int inl_kvno=0;
                KDC_REP ads_rep=rep.kdc_rep;
                char* achl_msg_format="AS-REP: pvno=%i, msg-type=%i, crealm=%s, cname=%s, tkt-vno=%i, "
                                      "realm=%s, sname=%s, etype=%i, kvno=%i";
                m_aux_stor_start( &a_temp_memory );
                adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
                if( ads_rep.padata!=NULL ) {
                    int inl_in1=0;
                    for( ; inl_in1<ads_rep.padata->len; inl_in1++ ) {
                        m_krb5_trace_memcat( &a_temp_memory, adsl_trace,ads_rep.padata->val+inl_in1,
                                             sizeof( PA_DATA ),"PA-DATA:" );
                    }
                }
                if( ads_rep.enc_part.kvno!=NULL ) {
                    inl_kvno=*ads_rep.enc_part.kvno;
                }
                achl_cname=m_krb5_principalname2string( &a_temp_memory, achl_cname, &ads_rep.cname );
                achl_sname=m_krb5_principalname2string( &a_temp_memory, achl_sname, &ads_rep.ticket.sname );
                m_krb5_trace(( struct krb5_tracer* )NAME_OF_MAIN_LOC_GLOB_P->a_tracer,'T',6006,
                             adsl_trace,&a_temp_memory, achl_msg_format, ads_rep.pvno, ads_rep.msg_type,ads_rep.crealm,achl_cname,
                             ads_rep.ticket.tkt_vno,ads_rep.ticket.realm,achl_sname, ads_rep.enc_part.etype,inl_kvno );
                m_aux_stor_end( &a_temp_memory );
            }
            krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &resp );
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            break;
        } else {
            KRB_ERROR error;
            ret = krb5_rd_error(	NAME_OF_MAIN_LOC_GLOB_P, context, &resp, &error );
            //StSch Trace Point 6007
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
                achl_cname=m_krb5_principalname2string( &a_temp_memory, achl_cname, error.cname );
                achl_sname=m_krb5_principalname2string( &a_temp_memory, achl_sname, &error.sname );
                if( error.crealm!=NULL ) {
                    achl_crealm=*error.crealm;
                }
                if( error.ctime!=NULL ) {
                    ill_ctime=*error.ctime;
                }
                if( error.cusec!=NULL ) {
                    inl_cusec=*error.cusec;
                }
                m_krb5_trace(( struct krb5_tracer* )NAME_OF_MAIN_LOC_GLOB_P->a_tracer,'T',6007,
                             adsl_trace,&a_temp_memory, achl_msg_format, error.pvno,error.msg_type,ill_ctime,inl_cusec,error.stime,
                             error.susec, error.error_code, achl_crealm,achl_cname,error.realm,achl_sname );
                m_aux_stor_end( &a_temp_memory );
            }
            if( ret && resp.data && (( char* )resp.data )[0] == 4 )
                ret = KRB5KRB_AP_ERR_V4_REPLY;
            krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &resp );
            if( ret ) {
                //StSch Trace Point
                goto out;
            }
            ret = krb5_error_from_rd_error(	NAME_OF_MAIN_LOC_GLOB_P, context, &error, creds );
            /*
             * If no preauth was set and KDC requires it, give it one
             * more try.
             */
            if( ret == KRB5KDC_ERR_PREAUTH_REQUIRED ) {
                free_METHOD_DATA(	NAME_OF_MAIN_LOC_GLOB_P, &md );
                memset( &md, 0, sizeof( md ) );
                if( error.e_data ) {
                    ret = decode_METHOD_DATA(	NAME_OF_MAIN_LOC_GLOB_P, error.e_data->data,
                                                error.e_data->length,
                                                &md,
                                                NULL );
                    if( ret ) {
                        //StSch Trace Point
                        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"failed to decode METHOD DATA","init_creds_pw.c 1355" )
                        ;
                    }
                } else {
                }
                krb5_free_error_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, &error );
                if( ret ) {
                    //StSch Trace Point
                    goto out;
                }
            } else if( ret == KRB5KRB_ERR_RESPONSE_TOO_BIG ) {
                if( send_to_kdc_flags & KRB5_KRBHST_FLAGS_LARGE_MSG ) {
                    //StSch Trace Point
                    if( ret_as_reply )
                        rep.error = error;
                    else
                        krb5_free_error_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, &error );
                    goto out;
                }
                krb5_free_error_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, &error );
                send_to_kdc_flags |= KRB5_KRBHST_FLAGS_LARGE_MSG;
            } else {
                //StSch Trace Point
                if( ret_as_reply )
                    rep.error = error;
                else
                    krb5_free_error_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, &error );
                goto out;
            }
        }
    }
    {
        krb5_keyblock *key = NULL;
        ret = process_pa_data_to_key(	NAME_OF_MAIN_LOC_GLOB_P, context, ctx, creds,
                                        &ctx->as_req, &rep, &key );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
        ret = _krb5_extract_ticket(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                    &rep,
                                    creds,
                                    key,
                                    NULL,
                                    KRB5_KU_AS_REP_ENC_PART,
                                    NULL,
                                    ctx->nonce,
                                    FALSE,
                                    ctx->flags.b.request_anonymous,
                                    NULL,
                                    NULL );
        krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, key );
    }
    out:
    free_METHOD_DATA( NAME_OF_MAIN_LOC_GLOB_P, &md );
    memset( &md, 0, sizeof( md ) );
    if( ret == 0 && ret_as_reply )
        *ret_as_reply = rep;
    else
        krb5_free_kdc_rep(	NAME_OF_MAIN_LOC_GLOB_P, context, &rep );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_init_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     krb5_creds *creds,
                     krb5_principal client,
                     krb5_prompter_fct prompter,
                     void *data,
                     krb5_deltat start_time,
                     const char *in_tkt_service,
                     krb5_get_init_creds_opt *options )
{
    krb5_get_init_creds_ctx ctx;
    krb5_kdc_rep kdc_reply;
    krb5_error_code ret;
    char buf[BUFSIZ];
    int done;
    memset( &kdc_reply, 0, sizeof( kdc_reply ) );
    ret = get_init_creds_common( NAME_OF_MAIN_LOC_GLOB_P, context, creds, client, start_time,
                                 in_tkt_service, options, &ctx );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    done = 0;
    while( !done ) {
        memset( &kdc_reply, 0, sizeof( kdc_reply ) );
        ret = init_cred_loop( NAME_OF_MAIN_LOC_GLOB_P, context,
                              options,
                              prompter,
                              data,
                              &ctx,
                              &ctx.cred,
                              &kdc_reply );
        switch( ret ) {
        case 0 :
                done = 1;
            break;
        case KRB5KDC_ERR_KEY_EXPIRED :
                //StSch Trace Point
                if( prompter == NULL || ctx.password == NULL )
                    goto out;
            krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
            if( ctx.in_tkt_service != NULL
                    && strcmp( ctx.in_tkt_service, "kadmin/changepw" ) == 0 )
                goto out;
            goto out;
        default:
                //StSch Trace Point
                goto out;
        }
    }
    out:
    memset( buf, 0, sizeof( buf ) );
    free_init_creds_ctx( NAME_OF_MAIN_LOC_GLOB_P, context, &ctx );
    krb5_free_kdc_rep( NAME_OF_MAIN_LOC_GLOB_P, context, &kdc_reply );
    if( ret == 0 )
        *creds = ctx.cred;
    else
        krb5_free_cred_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, &ctx.cred );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_init_creds_password( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                              krb5_creds *creds,
                              krb5_principal client,
                              const char *password,
                              krb5_prompter_fct prompter,
                              void *data,
                              krb5_deltat start_time,
                              const char *in_tkt_service,
                              krb5_get_init_creds_opt *in_options )
{
    krb5_get_init_creds_opt *options;
    char buf[BUFSIZ];
    krb5_error_code ret;
    if( in_options == NULL )
        ret = krb5_get_init_creds_opt_alloc(	NAME_OF_MAIN_LOC_GLOB_P, context, &options );
    else
        ret = _krb5_get_init_creds_opt_copy(	NAME_OF_MAIN_LOC_GLOB_P, context, in_options, &options );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( options->opt_private->password == NULL ) {
        ret = krb5_get_init_creds_opt_set_pa_password(	NAME_OF_MAIN_LOC_GLOB_P, context, options,
                password, NULL );
        if( ret ) {
            //StSch Trace Point
            krb5_get_init_creds_opt_free(	NAME_OF_MAIN_LOC_GLOB_P, options );
            memset( buf, 0, sizeof( buf ) );
            return ret;
        }
    }
    ret = krb5_get_init_creds( NAME_OF_MAIN_LOC_GLOB_P, context, creds, client, prompter,
                               data, start_time, in_tkt_service, options );
    krb5_get_init_creds_opt_free( NAME_OF_MAIN_LOC_GLOB_P, options );
    memset( buf, 0, sizeof( buf ) );
    return ret;
}
void KRB5_LIB_FUNCTION
krb5_free_keyblock_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                             krb5_keyblock *keyblock )
{
    if( keyblock ) {
        if( keyblock->keyvalue.data != NULL )
            memset( keyblock->keyvalue.data, 0, keyblock->keyvalue.length );
        krb5_data_free(	NAME_OF_MAIN_LOC_GLOB_P, &keyblock->keyvalue );
        keyblock->keytype = ENCTYPE_NULL;
    }
}
void KRB5_LIB_FUNCTION
krb5_free_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_keyblock *keyblock )
{
    if( keyblock ) {
        krb5_free_keyblock_contents(	NAME_OF_MAIN_LOC_GLOB_P, context, keyblock );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, keyblock )
        ;
    }
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_copy_keyblock_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                             const krb5_keyblock *inblock,
                             krb5_keyblock *to )
{
    return copy_EncryptionKey( NAME_OF_MAIN_LOC_GLOB_P, inblock, to );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_copy_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    const krb5_keyblock *inblock,
                    krb5_keyblock **to )
{
    krb5_keyblock *k;
    k =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *k ) )
        ;
    if( k == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","keyblock.c 1558" )
        ;
        return ENOMEM;
    }
    *to = k;
    return krb5_copy_keyblock_contents( NAME_OF_MAIN_LOC_GLOB_P, context, inblock, k );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_kt_copy_entry_contents_mod( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context,krb5_keytab_entry*,krb5_const_principal,krb5_enctype );
krb5_error_code KRB5_LIB_FUNCTION
krb5_kt_get_entry( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_keytab id,
                   krb5_const_principal principal,
                   krb5_kvno kvno,
                   krb5_enctype enctype,
                   krb5_keytab_entry *entry )
{
    return krb5_kt_copy_entry_contents_mod( NAME_OF_MAIN_LOC_GLOB_P, context, entry, principal, enctype );
}
/*
 * Copy the contents of `in' into `out'.
 * Return 0 or an error.  */
krb5_error_code KRB5_LIB_FUNCTION
krb5_kt_copy_entry_contents_mod( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                 krb5_keytab_entry *out,
                                 krb5_const_principal princ,
                                 krb5_enctype enctype )
{
    krb5_error_code ret;
    krb5_salt salt;
    krb5_keyblock key;
    krb5_get_pw_salt( NAME_OF_MAIN_LOC_GLOB_P, context, princ, &salt );
    krb5_string_to_key_salt( NAME_OF_MAIN_LOC_GLOB_P, context, enctype, context->passwd, salt, &key );
    memset( out, 0, sizeof( *out ) );
    out->vno = 0;
    ret = krb5_copy_principal( NAME_OF_MAIN_LOC_GLOB_P, context, princ, &out->principal );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    ret = krb5_copy_keyblock_contents( NAME_OF_MAIN_LOC_GLOB_P, context,
                                       &key,
                                       &out->keyblock );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    memset( context->passwd,0,strlen( context->passwd ) );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, context->passwd )
    ;
    context->passwd = NULL;
    out->timestamp = 0;
    return 0;
    fail:
    krb5_kt_free_entry( NAME_OF_MAIN_LOC_GLOB_P, context, out );
    return ret;
}
/*
* Free the contents of `entry'.
*/
krb5_error_code KRB5_LIB_FUNCTION
krb5_kt_free_entry( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_keytab_entry *entry )
{
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, entry->principal );
    krb5_free_keyblock_contents( NAME_OF_MAIN_LOC_GLOB_P, context, &entry->keyblock );
    memset( entry, 0, sizeof( *entry ) );
    return 0;
}
void initialize_krb5_error_table_r( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct et_list **list )
{
    initialize_error_table_r( NAME_OF_MAIN_LOC_GLOB_P, list, krb5_error_strings, 249, ERROR_TABLE_BASE_krb5 );
}
struct krb5_krbhst_data {
    char *realm;
    unsigned int flags;
    int def_port;
    int port;
    krb5_error_code( *get_next )( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context, struct krb5_krbhst_data *,
                                  krb5_krbhst_info** );
    unsigned int fallback_count;
    struct krb5_krbhst_info *hosts, **index, **end;
};
static void
free_krbhst_info( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_krbhst_info *hi )
{
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, hi )
    ;
}
/*
 * as a fallback, look for `serv_string.kd->realm' (typically
 * kerberos.REALM, kerberos-1.REALM, ...
 * `port' is the default port for the service, and `proto' the
 * protocol
 */
static struct krb5_krbhst_data*
common_init( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
             const char *realm,
             int flags ) {
    struct krb5_krbhst_data *kd;
    if(( kd =

                memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( *kd ) ) ),'\0',( 1 ) * ( sizeof( *kd ) ) )
       ) == NULL )
        return NULL;
    if(( kd->realm = m_strdup_hl( NAME_OF_MAIN_LOC_GLOB_P, realm ) ) == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, kd )
        ;
        return NULL;
    }
    if( flags & KRB5_KRBHST_FLAGS_LARGE_MSG )
        kd->flags |= KD_LARGE_MSG;
    kd->end = kd->index = &kd->hosts;
    return kd;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_krbhst_init_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                        const char *realm,
                        unsigned int type,
                        int flags,
                        krb5_krbhst_handle *handle )
{
    struct krb5_krbhst_data *kd;
    if(( kd = common_init( NAME_OF_MAIN_LOC_GLOB_P, context, realm, flags ) ) == NULL )
        return ENOMEM;
    kd->get_next = NULL;
    kd->def_port = 0;
    *handle = kd;
    return 0;
}
void KRB5_LIB_FUNCTION
krb5_krbhst_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_krbhst_handle handle )
{
    krb5_krbhst_info *h, *next;
    if( handle == NULL )
        return;
    for( h = handle->hosts; h != NULL; h = next ) {
        next = h->next;
        free_krbhst_info(	NAME_OF_MAIN_LOC_GLOB_P, h );
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, handle->realm )
    ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, handle );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_mk_error( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               krb5_error_code error_code,
               const char *e_text,
               const krb5_data *e_data,
               const krb5_principal client,
               const krb5_principal server,
               time_t *client_time,
               int *client_usec,
               krb5_data *reply )
{
    KRB_ERROR msg;
    krb5_timestamp sec;
    int32_t usec;
    size_t len;
    krb5_error_code ret = 0;
    krb5_us_timeofday( NAME_OF_MAIN_LOC_GLOB_P, context, &sec, &usec );
    memset( &msg, 0, sizeof( msg ) );
    msg.pvno     = 5;
    msg.msg_type = krb_error;
    msg.stime    = sec;
    msg.susec    = usec;
    msg.ctime    = client_time;
    msg.cusec    = client_usec;
    if( error_code < KRB5KDC_ERR_NONE || error_code >= KRB5_ERR_RCSID ) {
        if( e_text == NULL )
            e_text = krb5_get_err_text(	NAME_OF_MAIN_LOC_GLOB_P, context, error_code );
        error_code = KRB5KRB_ERR_GENERIC;
    }
    msg.error_code = error_code - KRB5KDC_ERR_NONE;
    if( e_text )
        msg.e_text = ( heim_general_string* )&e_text;
    if( e_data )
        msg.e_data = ( heim_octet_string* )e_data;
    if( server ) {
        msg.realm = server->realm;
        msg.sname = server->name;
    } else {
        msg.realm = "<unspecified realm>";
    }
    if( client ) {
        msg.crealm = &client->realm;
        msg.cname = &client->name;
    }
    if(msg.realm==NULL){
       msg.realm = "<unspecified realm>";
    }
    ASN1_MALLOC_ENCODE( KRB_ERROR, reply->data, reply->length, &msg, &len, ret );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( reply->length != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"mk_error.c 10040: internal error in ASN.1 encoder" );
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_mk_priv( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_auth_context auth_context,
              const krb5_data *userdata,
              krb5_data *outbuf,
              krb5_replay_data *outdata )
{
    krb5_error_code ret;
    KRB_PRIV s;
    EncKrbPrivPart part;
    u_char *buf = NULL;
    size_t buf_size;
    size_t len;
    krb5_crypto crypto;
    krb5_keyblock *key;
    krb5_replay_data rdata;
    if(( auth_context->flags &
            ( KRB5_AUTH_CONTEXT_RET_TIME | KRB5_AUTH_CONTEXT_RET_SEQUENCE ) ) &&
            outdata == NULL )
        return KRB5_RC_REQUIRED;
    if( auth_context->local_subkey )
        key = auth_context->local_subkey;
    else if( auth_context->remote_subkey )
        key = auth_context->remote_subkey;
    else
        key = auth_context->keyblock;
    memset( &rdata, 0, sizeof( rdata ) );
    part.user_data = *userdata;
    krb5_us_timeofday( NAME_OF_MAIN_LOC_GLOB_P, context, &rdata.timestamp, &rdata.usec );
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_TIME ) {
        part.timestamp = &rdata.timestamp;
        part.usec      = &rdata.usec;
    } else {
        part.timestamp = NULL;
        part.usec      = NULL;
    }
    if( auth_context->flags & KRB5_AUTH_CONTEXT_RET_TIME ) {
        outdata->timestamp = rdata.timestamp;
        outdata->usec = rdata.usec;
    }
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE ) {
        rdata.seq = auth_context->local_seqnumber;
        part.seq_number = &rdata.seq;
    } else
        part.seq_number = NULL;
    if( auth_context->flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE )
        outdata->seq = auth_context->local_seqnumber;
    part.s_address = auth_context->local_address;
    part.r_address = auth_context->remote_address;
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &s.enc_part.cipher );
    ASN1_MALLOC_ENCODE( EncKrbPrivPart, buf, buf_size, &part, &len, ret );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"mk_priv.c 10032: internal error in ASN.1 encoder" );
    s.pvno = 5;
    s.msg_type = krb_priv;
    s.enc_part.etype = key->keytype;
    s.enc_part.kvno = NULL;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        return ret;
    }
    ret = krb5_encrypt( NAME_OF_MAIN_LOC_GLOB_P, context,
                        crypto,
                        KRB5_KU_KRB_PRIV,
                        buf + buf_size - len,
                        len,
                        &s.enc_part.cipher );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        return ret;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    ASN1_MALLOC_ENCODE( KRB_PRIV, buf, buf_size, &s, &len, ret );
    if( ret ) {
        //StSch Trace Point
        goto fail;
    }
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &s.enc_part.cipher );
    ret = krb5_data_copy( NAME_OF_MAIN_LOC_GLOB_P, outbuf, buf + buf_size - len, len );
    if( ret ) {
        //StSch Trace Point
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","mk_priv.c 1337" )
        ;
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        return ENOMEM;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE )
        auth_context->local_seqnumber =
            ( auth_context->local_seqnumber + 1 ) & 0xFFFFFFFF;
    return 0;
    fail:
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &s.enc_part.cipher );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_mk_rep( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
             krb5_auth_context auth_context,
             krb5_data *outbuf )
{
    krb5_error_code ret;
    AP_REP ap;
    EncAPRepPart body;
    u_char *buf = NULL;
    size_t buf_size;
    size_t len;
    krb5_crypto crypto;
    ap.pvno = 5;
    ap.msg_type = krb_ap_rep;
    memset( &body, 0, sizeof( body ) );
    body.ctime = auth_context->authenticator->ctime;
    body.cusec = auth_context->authenticator->cusec;
    if( auth_context->flags & KRB5_AUTH_CONTEXT_USE_SUBKEY ) {
        if( auth_context->local_subkey == NULL ) {
            ret = krb5_auth_con_generatelocalsubkey(	NAME_OF_MAIN_LOC_GLOB_P, context,
                    auth_context,
                    auth_context->keyblock );
            if( ret ) {
                //StSch Trace Point
                krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"krb5_mk_rep: generating subkey","mk_rep.c 1374" )
                ;
                free_EncAPRepPart(	NAME_OF_MAIN_LOC_GLOB_P, &body );
                return ret;
            }
        }
        ret = krb5_copy_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->local_subkey,
                                    &body.subkey );
        if( ret ) {
            //StSch Trace Point
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"krb5_copy_keyblock: out of memory","mk_rep.c 1375" )
            ;
            free_EncAPRepPart(	NAME_OF_MAIN_LOC_GLOB_P, &body );
            return ENOMEM;
        }
    } else
        body.subkey = NULL;
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE ) {
        if( auth_context->local_seqnumber == 0 )
            krb5_generate_seq_number(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                        auth_context->keyblock,
                                        &auth_context->local_seqnumber );
        ALLOC( body.seq_number, 1 );
        if( body.seq_number == NULL ) {
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","mk_rep.c 1376" )
            ;
            free_EncAPRepPart(	NAME_OF_MAIN_LOC_GLOB_P, &body );
            return ENOMEM;
        }
        *( body.seq_number ) = auth_context->local_seqnumber;
    } else
        body.seq_number = NULL;
    ap.enc_part.etype = auth_context->keyblock->keytype;
    ap.enc_part.kvno  = NULL;
    ASN1_MALLOC_ENCODE( EncAPRepPart, buf, buf_size, &body, &len, ret );
    free_EncAPRepPart( NAME_OF_MAIN_LOC_GLOB_P, &body );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"mk_rep.c 10045: internal error in ASN.1 encoder" );
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->keyblock,
                            0 , &crypto );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        return ret;
    }
    ret = krb5_encrypt( NAME_OF_MAIN_LOC_GLOB_P, context,
                        crypto,
                        KRB5_KU_AP_REQ_ENC_PART,
                        buf + buf_size - len,
                        len,
                        &ap.enc_part.cipher );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ASN1_MALLOC_ENCODE( AP_REP, outbuf->data, outbuf->length, &ap, &len, ret );
    if( ret == 0 && outbuf->length != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"mk_rep.c 10046: internal error in ASN.1 encoder" );
    free_AP_REP( NAME_OF_MAIN_LOC_GLOB_P, &ap );
    return ret;
}
krb5_error_code
_krb5_mk_req_internal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       krb5_auth_context *auth_context,
                       const krb5_flags ap_req_options,
                       krb5_data *in_data,
                       krb5_creds *in_creds,
                       krb5_data *outbuf,
                       krb5_key_usage checksum_usage,
                       krb5_key_usage encrypt_usage )
{
    krb5_error_code ret;
    krb5_data authenticator;
    Checksum c;
    Checksum *c_opt;
    krb5_auth_context ac;
    if( auth_context ) {
        if( *auth_context == NULL )
            ret = krb5_auth_con_init(	NAME_OF_MAIN_LOC_GLOB_P, context, auth_context );
        else
            ret = 0;
        ac = *auth_context;
    } else
        ret = krb5_auth_con_init( NAME_OF_MAIN_LOC_GLOB_P, context, &ac );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( ac->local_subkey == NULL && ( ap_req_options & AP_OPTS_USE_SUBKEY ) ) {
        ret = krb5_auth_con_generatelocalsubkey( NAME_OF_MAIN_LOC_GLOB_P, context, ac, &in_creds->session );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
    }
    krb5_free_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, ac->keyblock );
    krb5_copy_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, &in_creds->session, &ac->keyblock );
    /* it's unclear what type of checksum we can use.  try the best one, except:
     * a) if it's configured differently for the current realm, or
     * b) if the session key is des-cbc-crc
     */
    if( in_data ) {
        if( ac->keyblock->keytype == ETYPE_DES_CBC_CRC ) {
            ret = krb5_create_checksum(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                        NULL,
                                        0,
                                        CKSUMTYPE_RSA_MD4,
                                        in_data->data,
                                        in_data->length,
                                        &c );
        } else if( ac->keyblock->keytype == ETYPE_ARCFOUR_HMAC_MD5 ||
                   ac->keyblock->keytype == ETYPE_ARCFOUR_HMAC_MD5_56 ) {
            ret = krb5_create_checksum(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                        NULL,
                                        0,
                                        CKSUMTYPE_RSA_MD5,
                                        in_data->data,
                                        in_data->length,
                                        &c );
        } else {
            krb5_crypto crypto;
            ret = krb5_crypto_init(	NAME_OF_MAIN_LOC_GLOB_P, context, ac->keyblock, 0, &crypto );
            if( ret ) {
                //StSch Trace Point
                return ret;
            }
            ret = krb5_create_checksum(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                        crypto,
                                        checksum_usage,
                                        0,
                                        in_data->data,
                                        in_data->length,
                                        &c );
            krb5_crypto_destroy(	NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
        }
        c_opt = &c;
    } else {
        c_opt = ( Checksum* )( context->c_opt );
    }
    ret = krb5_build_authenticator( NAME_OF_MAIN_LOC_GLOB_P, context,
                                    ac,
                                    ac->keyblock->keytype,
                                    in_creds,
                                    c_opt,
                                    NULL,
                                    &authenticator,
                                    encrypt_usage );
    if( c_opt )
        free_Checksum( NAME_OF_MAIN_LOC_GLOB_P, c_opt );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_build_ap_req( NAME_OF_MAIN_LOC_GLOB_P, context, ac->keyblock->keytype,
                             in_creds, ap_req_options, authenticator, outbuf );
    if( auth_context == NULL )
        krb5_auth_con_free( NAME_OF_MAIN_LOC_GLOB_P, context, ac );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_mk_req_extended( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      krb5_auth_context *auth_context,
                      const krb5_flags ap_req_options,
                      krb5_data *in_data,
                      krb5_creds *in_creds,
                      krb5_data *outbuf )
{
    return _krb5_mk_req_internal( NAME_OF_MAIN_LOC_GLOB_P, context,
                                  auth_context,
                                  ap_req_options,
                                  in_data,
                                  in_creds,
                                  outbuf,
                                  KRB5_KU_AP_REQ_AUTH_CKSUM,
                                  KRB5_KU_AP_REQ_AUTH );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_mk_safe( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_auth_context auth_context,
              const krb5_data *userdata,
              krb5_data *outbuf,
              krb5_replay_data *outdata )
{
    krb5_error_code ret;
    KRB_SAFE s;
    u_char *buf = NULL;
    size_t buf_size;
    size_t len;
    krb5_crypto crypto;
    krb5_keyblock *key;
    krb5_replay_data rdata;
    if(( auth_context->flags &
            ( KRB5_AUTH_CONTEXT_RET_TIME | KRB5_AUTH_CONTEXT_RET_SEQUENCE ) ) &&
            outdata == NULL )
        return KRB5_RC_REQUIRED;
    if( auth_context->local_subkey )
        key = auth_context->local_subkey;
    else if( auth_context->remote_subkey )
        key = auth_context->remote_subkey;
    else
        key = auth_context->keyblock;
    s.pvno = 5;
    s.msg_type = krb_safe;
    memset( &rdata, 0, sizeof( rdata ) );
    s.safe_body.user_data = *userdata;
    krb5_us_timeofday( NAME_OF_MAIN_LOC_GLOB_P, context, &rdata.timestamp, &rdata.usec );
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_TIME ) {
        s.safe_body.timestamp  = &rdata.timestamp;
        s.safe_body.usec       = &rdata.usec;
    } else {
        s.safe_body.timestamp  = NULL;
        s.safe_body.usec       = NULL;
    }
    if( auth_context->flags & KRB5_AUTH_CONTEXT_RET_TIME ) {
        outdata->timestamp = rdata.timestamp;
        outdata->usec = rdata.usec;
    }
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE ) {
        rdata.seq = auth_context->local_seqnumber;
        s.safe_body.seq_number = &rdata.seq;
    } else
        s.safe_body.seq_number = NULL;
    if( auth_context->flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE )
        outdata->seq = auth_context->local_seqnumber;
    s.safe_body.s_address = auth_context->local_address;
    s.safe_body.r_address = auth_context->remote_address;
    s.cksum.cksumtype       = 0;
    s.cksum.checksum.data   = NULL;
    s.cksum.checksum.length = 0;
    ASN1_MALLOC_ENCODE( KRB_SAFE, buf, buf_size, &s, &len, ret );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"mk_safe.c 10033: internal error in ASN.1 encoder" );
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        return ret;
    }
    ret = krb5_create_checksum( NAME_OF_MAIN_LOC_GLOB_P, context,
                                crypto,
                                KRB5_KU_KRB_SAFE_CKSUM,
                                0,
                                buf,
                                len,
                                &s.cksum );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
        ;
        return ret;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    ASN1_MALLOC_ENCODE( KRB_SAFE, buf, buf_size, &s, &len, ret );
    free_Checksum( NAME_OF_MAIN_LOC_GLOB_P, &s.cksum );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"mk_safe.c 10034: internal error in ASN.1 encoder" );
    outbuf->length = len;
    outbuf->data   = buf;
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE )
        auth_context->local_seqnumber =
            ( auth_context->local_seqnumber + 1 ) & 0xFFFFFFFF;
    return 0;
}
static void
rr13( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *buf, size_t len )
{
    unsigned char *tmp;
    int bytes = ( len + 7 ) / 8;
    int i;
    if( len == 0 )
        return;
    {
        const int bits = 13 % len;
        const int lbit = len % 8;
        tmp =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, bytes )
            ;
        memcpy( tmp, buf, bytes );
        if( lbit ) {
            tmp[bytes - 1] &= 0xff << ( 8 - lbit );
            for( i = lbit; i < 8; i += len )
                tmp[bytes - 1] |= buf[0] >> i;
        }
        for( i = 0; i < bytes; i++ ) {
            int bb;
            int b1, s1, b2, s2;
            bb = 8 * i - bits;
            while( bb < 0 )
                bb += len;
            b1 = bb / 8;
            s1 = bb % 8;
            if( bb + 8 > bytes * 8 )
                s2 = ( len + 8 - s1 ) % 8;
            else
                s2 = 8 - s1;
            b2 = ( b1 + 1 ) % bytes;
            buf[i] = ( tmp[b1] << s1 ) | ( tmp[b2] >> s2 );
        }
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tmp )
        ;
    }
}
static void
add1( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *a, unsigned char *b, size_t len )
{
    int i;
    int carry = 0;
    for( i = len - 1; i >= 0; i-- ) {
        int x = a[i] + b[i] + carry;
        carry = x > 0xff;
        a[i] = x & 0xff;
    }
    for( i = len - 1; carry && i >= 0; i-- ) {
        int x = a[i] + carry;
        carry = x > 0xff;
        a[i] = x & 0xff;
    }
}
void KRB5_LIB_FUNCTION
_krb5_n_fold( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const void *str, size_t len, void *key, size_t size )
{
    /* if len < size we need at most N * len bytes, ie < 2 * size;
       if len > size we need at most 2 * len */
    size_t maxlen = 2 * max( size, len );
    size_t l = 0;
    unsigned char *tmp =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, maxlen )
        ;
    unsigned char *buf =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, len )
        ;
    memcpy( buf, str, len );
    memset( key, 0, size );
    do {
        memcpy( tmp + l, buf, len );
        l += len;
        rr13(	NAME_OF_MAIN_LOC_GLOB_P, buf, len * 8 );
        while( l >= size ) {
            add1(	NAME_OF_MAIN_LOC_GLOB_P, key, tmp, size );
            l -= size;
            if( l == 0 )
                break;
            memmove( tmp, tmp + size, l );
        }
    } while( l != 0 );
    memset( buf, 0, len );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    memset( tmp, 0, maxlen );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, tmp );
}
/*
 * Like read but never return partial data.
 */
ssize_t ROKEN_LIB_FUNCTION
net_read( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int fd, void *buf, size_t nbytes )
{
    char *cbuf = ( char * )buf;
    ssize_t count;
    size_t rem = nbytes;
    while( rem > 0 ) {
#ifdef WIN32
        count = recv( fd, cbuf, rem, 0 );
#else
        count = read( fd, cbuf, rem );
#endif
        if( count < 0 ) {
            if(( int )m__errno_location_hl(	NAME_OF_MAIN_LOC_GLOB_P
                                          ) == EINTR )
                continue;
            else
                return count;
        } else if( count == 0 ) {
            return count;
        }
        cbuf += count;
        rem -= count;
    }
    return nbytes;
}
/*
 * Like write but never return partial data.
 */
ssize_t ROKEN_LIB_FUNCTION
net_write( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, HANDLE_CONNECT,
           const void *buf, size_t nbytes )
{
    char *cbuf = ( char * )buf;
    ssize_t count;
    size_t rem = nbytes;
    while( rem > 0 ) {
        //IGNORE_INTERFACE_CHANGE_begin
        {
            int im_time_out;
#ifdef WITH_OWN_NET_CONNECT
            int iml_error;
#endif
            if( NAME_OF_MAIN_LOC_GLOB_P->a_generic_obj )
                im_time_out = *(( int* )( NAME_OF_MAIN_LOC_GLOB_P->a_generic_obj ) );
            else
#ifndef WITH_OWN_NET_CONNECT
                im_time_out = -1;
#else
                im_time_out = 10;
#endif
#ifndef WITH_OWN_NET_CONNECT
            count = m_send_hl( fd, cbuf, rem, im_time_out, NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context );
#else
            count = m_tcpsync_send_single( &iml_error, adsp_tcpsync_1, cbuf, rem, im_time_out * 1000 );
#endif
        }
        //IGNORE_INTERFACE_CHANGE_end
        if( count < 0 ) {
            if(( int )m__errno_location_hl( NAME_OF_MAIN_LOC_GLOB_P
                                          ) == EINTR )
                continue;
            else
                return count;
        }
        cbuf += count;
        rem -= count;
    }
    return nbytes;
}
PA_DATA *
krb5_find_padata( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, PA_DATA *val, unsigned len, int type, int *index )
{
    for( ; *index < len; ( *index )++ )
        if( val[*index].padata_type == type )
            return val + *index;
    return NULL;
}
int KRB5_LIB_FUNCTION
krb5_padata_add( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, METHOD_DATA *md,
                 int type, void *buf, size_t len )
{
    PA_DATA *pa;
    pa =
        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, md->val, ( md->len + 1 ) * sizeof( *md->val ) )
        ;
    if( pa == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","padata.c 1248" )
        ;
        return ENOMEM;
    }
    md->val = pa;
    pa[md->len].padata_type = type;
    pa[md->len].padata_value.length = len;
    pa[md->len].padata_value.data = buf;
    md->len++;
    return 0;
}
void KRB5_LIB_FUNCTION
krb5_free_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     krb5_principal p )
{
    if( p ) {
        free_Principal(	NAME_OF_MAIN_LOC_GLOB_P, p );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
    }
}
const char* KRB5_LIB_FUNCTION
krb5_principal_get_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          krb5_principal principal )
{
    return princ_realm( principal );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_parse_name( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 const char *name,
                 krb5_principal *principal )
{
    krb5_error_code ret;
    heim_general_string *comp;
    heim_general_string realm;
    int ncomp;
    const char *p;
    char *q;
    char *s;
    char *start;
    int n;
    char c;
    int got_realm = 0;
    ncomp = 1;
    for( p = name; *p; p++ ) {
        if( *p=='\\' ) {
            if( !p[1] ) {
                krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"trailing \\ in principal name","principal.c 1087" )
                ;
                return KRB5_PARSE_MALFORMED;
            }
            p++;
        } else if( *p == '/' )
            ncomp++;
    }
    comp =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( ncomp ) * ( sizeof( *comp ) ) ),'\0',( ncomp ) * ( sizeof( *comp ) ) )
        ;
    if( comp == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1088" )
        ;
        return ENOMEM;
    }
    n = 0;
    p = start = q = s = m_strdup_hl( NAME_OF_MAIN_LOC_GLOB_P, name );
    if( start == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, comp )
        ;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1089" )
        ;
        return ENOMEM;
    }
    while( *p ) {
        c = *p++;
        if( c == '\\' ) {
            c = *p++;
            if( c == 'n' )
                c = '\n';
            else if( c == 't' )
                c = '\t';
            else if( c == 'b' )
                c = '\b';
            else if( c == '0' )
                c = '\0';
            else if( c == '\0' ) {
                //StSch Trace Point
                krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"trailing \\ in principal name","principal.c 1090" )
                ;
                ret = KRB5_PARSE_MALFORMED;
                goto exit;
            }
        } else if( c == '/' || c == '@' ) {
            if( got_realm ) {
                //StSch Trace Point
                krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"part after realm in principal name","principal.c 1091" )
                ;
                ret = KRB5_PARSE_MALFORMED;
                goto exit;
            } else {
                comp[n] =
                    m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, q - start + 1 )
                    ;
                if( comp[n] == NULL ) {
                    //StSch Trace Point
                    krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1092" )
                    ;
                    ret = ENOMEM;
                    goto exit;
                }
                memcpy( comp[n], start, q - start );
                comp[n][q - start] = 0;
                n++;
            }
            if( c == '@' )
                got_realm = 1;
            start = q;
            continue;
        }
        if( got_realm && ( c == ':' || c == '/' || c == '\0' ) ) {
            //StSch Trace Point
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"part after realm in principal name","principal.c 1093" )
            ;
            ret = KRB5_PARSE_MALFORMED;
            goto exit;
        }
        *q++ = c;
    }
    if( got_realm ) {
        realm =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, q - start + 1 )
            ;
        if( realm == NULL ) {
            //StSch Trace Point
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1094" )
            ;
            ret = ENOMEM;
            goto exit;
        }
        memcpy( realm, start, q - start );
        realm[q - start] = 0;
    } else {
        ret = krb5_get_default_realm(	NAME_OF_MAIN_LOC_GLOB_P, context, &realm );
        if( ret ) {
            //StSch Trace Point
            goto exit;
        }
        comp[n] =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, q - start + 1 )
            ;
        if( comp[n] == NULL ) {
            //StSch Trace Point
            krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1095" )
            ;
            ret = ENOMEM;
            goto exit;
        }
        memcpy( comp[n], start, q - start );
        comp[n][q - start] = 0;
        n++;
    }
    *principal =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( **principal ) )
        ;
    if( *principal == NULL ) {
        //StSch Trace Point
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1096" )
        ;
        ret = ENOMEM;
        goto exit;
    }
    ( *principal )->name.name_type = KRB5_NT_PRINCIPAL;
    ( *principal )->name.name_string.val = comp;
    princ_num_comp( *principal ) = n;
    ( *principal )->realm = realm;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, s )
    ;
    return 0;
    exit:
    while( n>0 ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, comp[--n] )
        ;
    }
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, comp )
    ;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, s )
    ;
    return ret;
}
const static char* quotable_chars= " \n\t\b\\/@";
const static char* replace_chars= " ntb\\/@";

static size_t
quote_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const char *s, char *out, size_t index, size_t len )
{
    const char *p, *q;
    char ch_temp;
    for( p = s; *p && index < len; p++ ) {
        if(( q = strchr( quotable_chars, *p ) ) ) {
            add_char( out, index, len, '\\' );
            ch_temp =
                replace_chars[q -
                              quotable_chars];
            add_char( out, index, len, ch_temp );
        } else
            add_char( out, index, len, *p );
    }
    if( index < len )
        out[index] = '\0';
    return index;
}
static krb5_error_code
unparse_name_fixed( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_const_principal principal,
                    char *name,
                    size_t len,
                    krb5_boolean short_form )
{
    size_t index = 0;
    int i;
    for( i = 0; i < princ_num_comp( principal ); i++ ) {
        if( i )
            add_char( name, index, len, '/' );
        index = quote_string(	NAME_OF_MAIN_LOC_GLOB_P, princ_ncomp( principal, i ), name, index, len );
        if( index == len )
            return ERANGE;
    }
    if( short_form ) {
        krb5_realm r;
        krb5_error_code ret;
        ret = krb5_get_default_realm(	NAME_OF_MAIN_LOC_GLOB_P, context, &r );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
        if( strcmp( princ_realm( principal ), r ) != 0 )
            short_form = 0;
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, r )
        ;
    }
    if( !short_form ) {
        add_char( name, index, len, '@' );
        index = quote_string(	NAME_OF_MAIN_LOC_GLOB_P, princ_realm( principal ), name, index, len );
        if( index == len )
            return ERANGE;
    }
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_unparse_name_fixed( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                         krb5_const_principal principal,
                         char *name,
                         size_t len )
{
    return unparse_name_fixed( NAME_OF_MAIN_LOC_GLOB_P, context, principal, name, len, FALSE );
}
krb5_realm*
krb5_princ_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  krb5_principal principal )
{
    return &princ_realm( principal );
}
void KRB5_LIB_FUNCTION
krb5_princ_set_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      krb5_principal principal,
                      krb5_realm *realm )
{
    princ_realm( principal ) = *realm;
}

static krb5_error_code
append_component( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_principal p,
                  const char *comp,
                  size_t comp_len )
{
    heim_general_string *tmp;
    size_t len = princ_num_comp( p );
    tmp =
        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, princ_comp( p ), ( len + 1 ) * sizeof( *tmp ) )
        ;
    if( tmp == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1098" )
        ;
        return ENOMEM;
    }
    princ_comp( p ) = tmp;
    princ_ncomp( p, len ) =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, comp_len + 1 )
        ;
    if( princ_ncomp( p, len ) == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1099" )
        ;
        return ENOMEM;
    }
    memcpy( princ_ncomp( p, len ), comp, comp_len );
    princ_ncomp( p, len )[comp_len] = '\0';
    princ_num_comp( p )++;
    return 0;
}
static void
va_princ( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, krb5_principal p, const char *krb5_tgs_name, const char *server_realm )
{
    append_component( NAME_OF_MAIN_LOC_GLOB_P, context, p, krb5_tgs_name, strlen( krb5_tgs_name ) );
    append_component( NAME_OF_MAIN_LOC_GLOB_P, context, p, server_realm,  strlen( server_realm ) );
    if( context->add_serv_realms ) {
        int i;
        for( i=0; i<context->number_add_ser_rea; i++ )
            append_component( NAME_OF_MAIN_LOC_GLOB_P, context, p, ( context->add_serv_realms )[i],  strlen(( context->add_serv_realms )[i] ) );
    }
}
static krb5_error_code
build_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                 krb5_principal *principal,
                 int rlen,
                 krb5_const_realm realm,    void ( *func )( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context, krb5_principal, const char *, const char * ),
                 const char * krb5_tgs_name,
                 const char * server_realm
               )
{
    krb5_principal p;
    p =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( *p ) ) ),'\0',( 1 ) * ( sizeof( *p ) ) )
        ;
    if( p == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1100" )
        ;
        return ENOMEM;
    }
    princ_type( p ) = KRB5_NT_PRINCIPAL;
    princ_realm( p ) = m_strdup_hl( NAME_OF_MAIN_LOC_GLOB_P, realm );
    if( p->realm == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1101" )
        ;
        return ENOMEM;
    }
    ( *func )( NAME_OF_MAIN_LOC_GLOB_P, context, p, krb5_tgs_name, server_realm );
    *principal = p;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_make_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     krb5_principal *principal,
                     krb5_const_realm realm,
                     const char * krb5_tgs_name,
                     const char * server_realm )
{
    krb5_error_code ret;
    krb5_realm r = NULL;
    if( realm == NULL ) {
        ret = krb5_get_default_realm( NAME_OF_MAIN_LOC_GLOB_P, context, &r );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
        realm = r;
    }
    ret = krb5_build_principal_va( NAME_OF_MAIN_LOC_GLOB_P, context, principal, strlen( realm ), realm, krb5_tgs_name,server_realm );
    if( r )
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, r )
        ;
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_build_principal_va( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                         krb5_principal *principal,
                         int rlen,
                         krb5_const_realm realm,
                         const char * krb5_tgs_name,
                         const char * server_realm )
{
    return build_principal( NAME_OF_MAIN_LOC_GLOB_P, context, principal, rlen, realm, va_princ, krb5_tgs_name,server_realm );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_copy_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     krb5_const_principal inprinc,
                     krb5_principal *outprinc )
{
    krb5_principal p =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *p ) )
        ;
    if( p == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1102" )
        ;
        return ENOMEM;
    }
    if( copy_Principal( NAME_OF_MAIN_LOC_GLOB_P, inprinc, p ) ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","principal.c 1103" )
        ;
        return ENOMEM;
    }
    *outprinc = p;
    return 0;
}
/*
 * return TRUE iff princ1 == princ2 (without considering the realm)
 */
krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_compare_any_realm( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                                  krb5_const_principal princ1,
                                  krb5_const_principal princ2 )
{
    int i;
    if( princ_num_comp( princ1 ) != princ_num_comp( princ2 ) )
        return FALSE;
    for( i = 0; i < princ_num_comp( princ1 ); i++ ) {
        if( strcmp( princ_ncomp( princ1, i ), princ_ncomp( princ2, i ) ) != 0 )
            return FALSE;
    }
    return TRUE;
}
/*
 * return TRUE iff princ1 == princ2
 */
krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_compare( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                        krb5_const_principal princ1,
                        krb5_const_principal princ2 )
{
    if( !krb5_realm_compare( NAME_OF_MAIN_LOC_GLOB_P, context, princ1, princ2 ) )
        return FALSE;
    return krb5_principal_compare_any_realm( NAME_OF_MAIN_LOC_GLOB_P, context, princ1, princ2 );
}
/*
 * return TRUE iff realm(princ1) == realm(princ2)
 */
krb5_boolean KRB5_LIB_FUNCTION
krb5_realm_compare( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_const_principal princ1,
                    krb5_const_principal princ2 )
{
    return strcmp( princ_realm( princ1 ), princ_realm( princ2 ) ) == 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_rd_error( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
               krb5_data *msg,
               KRB_ERROR *result )
{
    size_t len;
    krb5_error_code ret;
    ret = decode_KRB_ERROR( NAME_OF_MAIN_LOC_GLOB_P, msg->data, msg->length, result, &len );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    result->error_code += KRB5KDC_ERR_NONE;
    return 0;
}
void KRB5_LIB_FUNCTION
krb5_free_error_contents( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          krb5_error *error )
{
    free_KRB_ERROR( NAME_OF_MAIN_LOC_GLOB_P, error );
    memset( error, 0, sizeof( *error ) );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_error_from_rd_error( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                          const krb5_error *error,
                          const krb5_creds *creds )
{
    krb5_error_code ret;
    ret = error->error_code;
    if( error->e_text != NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"","rd_error.c 1566" )
        ;
    } else {
        char clientname[256], servername[256];
        if( creds != NULL ) {
            krb5_unparse_name_fixed(	NAME_OF_MAIN_LOC_GLOB_P, context, creds->client,
                                        clientname, sizeof( clientname ) );
            krb5_unparse_name_fixed(	NAME_OF_MAIN_LOC_GLOB_P, context, creds->server,
                                        servername, sizeof( servername ) );
        }
        switch( ret ) {
        case KRB5KDC_ERR_NAME_EXP :
                krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"Client  expired","rd_error.c 1567" )
                ;
            break;
        case KRB5KDC_ERR_SERVICE_EXP :
                krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"Server  expired","rd_error.c 1568" )
                ;
            break;
        case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN :
                krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"Client  unknown","rd_error.c 1569" )
                ;
            break;
        case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN :
                krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"Server  unknown","rd_error.c 1570" )
                ;
            break;
        default :
                krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            break;
        }
    }
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_rd_priv( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_auth_context auth_context,
              const krb5_data *inbuf,
              krb5_data *outbuf,
              krb5_replay_data *outdata )
{
    krb5_error_code ret;
    KRB_PRIV priv;
    EncKrbPrivPart part;
    size_t len;
    krb5_data plain;
    krb5_keyblock *key;
    krb5_crypto crypto;
    if(( auth_context->flags &
            ( KRB5_AUTH_CONTEXT_RET_TIME | KRB5_AUTH_CONTEXT_RET_SEQUENCE ) ) &&
            outdata == NULL )
        return KRB5_RC_REQUIRED;
    memset( &priv, 0, sizeof( priv ) );
    ret = decode_KRB_PRIV( NAME_OF_MAIN_LOC_GLOB_P, inbuf->data, inbuf->length, &priv, &len );
    if( ret ) {
        //StSch Trace Point
        goto failure;
    }
    if( priv.pvno != 5 ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5KRB_AP_ERR_BADVERSION;
        goto failure;
    }
    if( priv.msg_type != krb_priv ) {
        //StSch Trace Point
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        ret = KRB5KRB_AP_ERR_MSG_TYPE;
        goto failure;
    }
    if( auth_context->remote_subkey )
        key = auth_context->remote_subkey;
    else if( auth_context->local_subkey )
        key = auth_context->local_subkey;
    else
        key = auth_context->keyblock;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        goto failure;
    }
    ret = krb5_decrypt_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, context,
                                      crypto,
                                      KRB5_KU_KRB_PRIV,
                                      &priv.enc_part,
                                      &plain );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret ) {
        //StSch Trace Point
        goto failure;
    }
    ret = decode_EncKrbPrivPart( NAME_OF_MAIN_LOC_GLOB_P, plain.data, plain.length, &part, &len );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &plain );
    if( ret ) {
        //StSch Trace Point
        goto failure;
    }
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_TIME ) {
        krb5_timestamp sec;
        krb5_timeofday(	NAME_OF_MAIN_LOC_GLOB_P, context, &sec );
        if( part.timestamp == NULL ||
                part.usec      == NULL ||
                abs( *part.timestamp - sec ) > context->max_skew ) {
            //StSch Trace Point
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            ret = KRB5KRB_AP_ERR_SKEW;
            goto failure_part;
        }
    }
    /* check sequence number. since MIT krb5 cannot generate a sequence
       number of zero but instead generates no sequence number, we accept that
    */
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE ) {
        if(( part.seq_number == NULL
                && auth_context->remote_seqnumber != 0 )
                || ( part.seq_number != NULL
                     && *part.seq_number != auth_context->remote_seqnumber ) ) {
            //StSch Trace Point
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            ret = KRB5KRB_AP_ERR_BADORDER;
            goto failure_part;
        }
        auth_context->remote_seqnumber++;
    }
    ret = krb5_data_copy( NAME_OF_MAIN_LOC_GLOB_P, outbuf, part.user_data.data, part.user_data.length );
    if( ret ) {
        //StSch Trace Point
        goto failure_part;
    }
    if(( auth_context->flags &
            ( KRB5_AUTH_CONTEXT_RET_TIME | KRB5_AUTH_CONTEXT_RET_SEQUENCE ) ) ) {
        /* if these fields are not present in the priv-part, silently
               return zero */
        memset( outdata, 0, sizeof( *outdata ) );
        if( part.timestamp )
            outdata->timestamp = *part.timestamp;
        if( part.usec )
            outdata->usec = *part.usec;
        if( part.seq_number )
            outdata->seq = *part.seq_number;
    }
    failure_part:
    free_EncKrbPrivPart( NAME_OF_MAIN_LOC_GLOB_P, &part );
    failure:
    free_KRB_PRIV( NAME_OF_MAIN_LOC_GLOB_P, &priv );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_rd_rep( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
             krb5_auth_context auth_context,
             const krb5_data *inbuf,
             krb5_ap_rep_enc_part **repl )
{
    krb5_error_code ret;
    AP_REP ap_rep;
    size_t len;
    krb5_data data;
    krb5_crypto crypto;
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, &data );
    ret = 0;
    ret = decode_AP_REP( NAME_OF_MAIN_LOC_GLOB_P, inbuf->data, inbuf->length, &ap_rep, &len );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( ap_rep.pvno != 5 ) {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_BADVERSION;
        krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
        goto out;
    }
    if( ap_rep.msg_type != krb_ap_rep ) {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_MSG_TYPE;
        krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
        goto out;
    }
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, auth_context->keyblock, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    ret = krb5_decrypt_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, context,
                                      crypto,
                                      KRB5_KU_AP_REQ_ENC_PART,
                                      &ap_rep.enc_part,
                                      &data );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    *repl =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( **repl ) )
        ;
    if( *repl == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","rd_rep.c 1508" )
        ;
        goto out;
    }
    ret = krb5_decode_EncAPRepPart( NAME_OF_MAIN_LOC_GLOB_P, context,
                                    data.data,
                                    data.length,
                                    *repl,
                                    &len );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if(( *repl )->ctime != auth_context->authenticator->ctime ||
            ( *repl )->cusec != auth_context->authenticator->cusec ) {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_MUT_FAIL;
        krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
        goto out;
    }
    if(( *repl )->seq_number )
        krb5_auth_con_setremoteseqnumber( NAME_OF_MAIN_LOC_GLOB_P, context, auth_context,
                                          *(( *repl )->seq_number ) );
    if(( *repl )->subkey )
        krb5_auth_con_setremotesubkey( NAME_OF_MAIN_LOC_GLOB_P, context, auth_context, ( *repl )->subkey );
    out:
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &data );
    free_AP_REP( NAME_OF_MAIN_LOC_GLOB_P, &ap_rep );
    return ret;
}
void KRB5_LIB_FUNCTION
krb5_free_ap_rep_enc_part( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                           krb5_ap_rep_enc_part *val )
{
    free_EncAPRepPart( NAME_OF_MAIN_LOC_GLOB_P, val );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, val );
}
static krb5_error_code
decrypt_tkt_enc_part( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                      krb5_keyblock *key,
                      EncryptedData *enc_part,
                      EncTicketPart *decr_part )
{
    krb5_error_code ret;
    krb5_data plain;
    size_t len;
    krb5_crypto crypto;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_decrypt_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, context,
                                      crypto,
                                      KRB5_KU_TICKET,
                                      enc_part,
                                      &plain );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_decode_EncTicketPart( NAME_OF_MAIN_LOC_GLOB_P, context, plain.data, plain.length,
                                     decr_part, &len );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &plain );
    return ret;
}
static krb5_error_code
decrypt_authenticator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       EncryptionKey *key,
                       EncryptedData *enc_part,
                       Authenticator *authenticator,
                       krb5_key_usage usage )
{
    krb5_error_code ret;
    krb5_data plain;
    size_t len;
    krb5_crypto crypto;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_decrypt_EncryptedData( NAME_OF_MAIN_LOC_GLOB_P, context,
                                      crypto,
                                      usage ,
                                      enc_part,
                                      &plain );
    if( ret && usage == KRB5_KU_TGS_REQ_AUTH )
        ret = krb5_decrypt_EncryptedData(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                            crypto,
                                            KRB5_KU_AP_REQ_AUTH,
                                            enc_part,
                                            &plain );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    NAME_OF_MAIN_LOC_GLOB_P->a_krb5_auth_hash=m_aux_stor_alloc(
        NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,20);
    m_krb5_sha1(plain.data,plain.length,NAME_OF_MAIN_LOC_GLOB_P->a_krb5_auth_hash,
        NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area); //Todo: make optional
    ret = krb5_decode_Authenticator( NAME_OF_MAIN_LOC_GLOB_P, context, plain.data, plain.length,
                                     authenticator, &len );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &plain );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decode_ap_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    const krb5_data *inbuf,
                    krb5_ap_req *ap_req )
{
    krb5_error_code ret;
    size_t len;
    ret = decode_AP_REQ( NAME_OF_MAIN_LOC_GLOB_P, inbuf->data, inbuf->length, ap_req, &len );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( ap_req->pvno != 5 ) {
        free_AP_REQ(	NAME_OF_MAIN_LOC_GLOB_P, ap_req );
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5KRB_AP_ERR_BADVERSION;
    }
    if( ap_req->msg_type != krb_ap_req ) {
        free_AP_REQ(	NAME_OF_MAIN_LOC_GLOB_P, ap_req );
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5KRB_AP_ERR_MSG_TYPE;
    }
    if( ap_req->ticket.tkt_vno != 5 ) {
        free_AP_REQ(	NAME_OF_MAIN_LOC_GLOB_P, ap_req );
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        return KRB5KRB_AP_ERR_BADVERSION;
    }
    return 0;
}
static krb5_error_code
find_etypelist( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_auth_context auth_context,
                EtypeList *etypes )
{
    krb5_error_code ret;
    krb5_authdata *ad;
    krb5_authdata adIfRelevant;
    unsigned i;
    adIfRelevant.len = 0;
    etypes->len = 0;
    etypes->val = NULL;
    ad = auth_context->authenticator->authorization_data;
    if( ad == NULL )
        return 0;
    for( i = 0; i < ad->len; i++ ) {
        if( ad->val[i].ad_type == KRB5_AUTHDATA_IF_RELEVANT ) {
            ret = decode_AD_IF_RELEVANT(	NAME_OF_MAIN_LOC_GLOB_P, ad->val[i].ad_data.data,
                                            ad->val[i].ad_data.length,
                                            &adIfRelevant,
                                            NULL );
            if( ret ) {
                //StSch Trace Point
                return ret;
            }
            if( adIfRelevant.len == 1 &&
                    adIfRelevant.val[0].ad_type ==
                    KRB5_AUTHDATA_GSS_API_ETYPE_NEGOTIATION ) {
                break;
            }
            free_AD_IF_RELEVANT(	NAME_OF_MAIN_LOC_GLOB_P, &adIfRelevant );
            adIfRelevant.len = 0;
        }
    }
    if( adIfRelevant.len == 0 )
        return 0;
    ret = decode_EtypeList( NAME_OF_MAIN_LOC_GLOB_P, adIfRelevant.val[0].ad_data.data,
                            adIfRelevant.val[0].ad_data.length,
                            etypes,
                            NULL );
    free_AD_IF_RELEVANT( NAME_OF_MAIN_LOC_GLOB_P, &adIfRelevant );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_decrypt_ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     Ticket *ticket,
                     krb5_keyblock *key,
                     EncTicketPart *out,
                     krb5_flags flags )
{
    EncTicketPart t;
    krb5_error_code ret;
    ret = decrypt_tkt_enc_part( NAME_OF_MAIN_LOC_GLOB_P, context, key, &ticket->enc_part, &t );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    {
        krb5_timestamp now;
        time_t start = t.authtime;
        krb5_timeofday(	NAME_OF_MAIN_LOC_GLOB_P, context, &now );
        if( t.starttime )
            start = *t.starttime;
        if( start - now > context->max_skew
                || ( t.flags.invalid
                     && !( flags & KRB5_VERIFY_AP_REQ_IGNORE_INVALID ) ) ) {
            free_EncTicketPart(	NAME_OF_MAIN_LOC_GLOB_P, &t );
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            return KRB5KRB_AP_ERR_TKT_NYV;
        }
        if( now - t.endtime > context->max_skew ) {
            free_EncTicketPart(	NAME_OF_MAIN_LOC_GLOB_P, &t );
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            return KRB5KRB_AP_ERR_TKT_EXPIRED;
        }
    }
    if( out )
        *out = t;
    else
        free_EncTicketPart(	NAME_OF_MAIN_LOC_GLOB_P, &t );
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_verify_ap_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                    krb5_auth_context *auth_context,
                    krb5_ap_req *ap_req,
                    krb5_const_principal server,
                    krb5_keyblock *keyblock,
                    krb5_flags flags,
                    krb5_flags *ap_req_options,
                    krb5_ticket **ticket )
{
    return krb5_verify_ap_req2( NAME_OF_MAIN_LOC_GLOB_P, context,
                                auth_context,
                                ap_req,
                                server,
                                keyblock,
                                flags,
                                ap_req_options,
                                ticket,
                                KRB5_KU_AP_REQ_AUTH );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_verify_ap_req2( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     krb5_auth_context *auth_context,
                     krb5_ap_req *ap_req,
                     krb5_const_principal server,
                     krb5_keyblock *keyblock,
                     krb5_flags flags,
                     krb5_flags *ap_req_options,
                     krb5_ticket **ticket,
                     krb5_key_usage usage )
{
    krb5_ticket *t;
    krb5_auth_context ac;
    krb5_error_code ret;
    EtypeList etypes;
    if( auth_context && *auth_context ) {
        ac = *auth_context;
    } else {
        ret = krb5_auth_con_init(	NAME_OF_MAIN_LOC_GLOB_P, context, &ac );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
    }
    t =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( *t ) )
        ;
    if( t == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        goto out;
    }
    memset( t, 0, sizeof( *t ) );
    if( ap_req->ap_options.use_session_key && ac->keyblock ) {
        ret = krb5_decrypt_ticket(	NAME_OF_MAIN_LOC_GLOB_P, context, &ap_req->ticket,
                                    ac->keyblock,
                                    &t->ticket,
                                    flags );
        krb5_free_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context, ac->keyblock );
        ac->keyblock = NULL;
    } else
        ret = krb5_decrypt_ticket(	NAME_OF_MAIN_LOC_GLOB_P, context, &ap_req->ticket,
                                    keyblock,
                                    &t->ticket,
                                    flags );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    _krb5_principalname2krb5_principal( NAME_OF_MAIN_LOC_GLOB_P, &t->server, ap_req->ticket.sname,
                                        ap_req->ticket.realm );
    _krb5_principalname2krb5_principal( NAME_OF_MAIN_LOC_GLOB_P, &t->client, t->ticket.cname,
                                        t->ticket.crealm );
    krb5_copy_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, &t->ticket.key, &ac->keyblock );
    ret = decrypt_authenticator( NAME_OF_MAIN_LOC_GLOB_P, context,
                                 &t->ticket.key,
                                 &ap_req->authenticator,
                                 ac->authenticator,
                                 usage );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    {
        krb5_principal p1, p2;
        krb5_boolean res;
        _krb5_principalname2krb5_principal(	NAME_OF_MAIN_LOC_GLOB_P, &p1,
                                            ac->authenticator->cname,
                                            ac->authenticator->crealm );
        _krb5_principalname2krb5_principal(	NAME_OF_MAIN_LOC_GLOB_P, &p2,
                                            t->ticket.cname,
                                            t->ticket.crealm );
        res = krb5_principal_compare(	NAME_OF_MAIN_LOC_GLOB_P, context, p1, p2 );
        krb5_free_principal(	NAME_OF_MAIN_LOC_GLOB_P, context, p1 );
        krb5_free_principal(	NAME_OF_MAIN_LOC_GLOB_P, context, p2 );
        if( !res ) {
            //StSch Trace Point
            ret = KRB5KRB_AP_ERR_BADMATCH;
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            goto out;
        }
    }
    {
        krb5_timestamp now;
        krb5_timeofday(	NAME_OF_MAIN_LOC_GLOB_P, context, &now );
        if( abs( ac->authenticator->ctime - now ) > context->max_skew ) {
            //StSch Trace Point
            ret = KRB5KRB_AP_ERR_SKEW;
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            goto out;
        }
    }
    if( ac->authenticator->seq_number )
        krb5_auth_con_setremoteseqnumber(	NAME_OF_MAIN_LOC_GLOB_P, context, ac,
                                            *ac->authenticator->seq_number );
    if( ac->authenticator->subkey ) {
        ret = krb5_auth_con_setremotesubkey(	NAME_OF_MAIN_LOC_GLOB_P, context, ac,
                                                ac->authenticator->subkey );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
    //m_krb5_hash_authenticator( NAME_OF_MAIN_LOC_GLOB_P,   //Todo: make optional
    //                           ac->authenticator);
    }
    ret = find_etypelist( NAME_OF_MAIN_LOC_GLOB_P, context, ac, &etypes );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    ac->keytype = ETYPE_NULL;
    if( etypes.val ) {
        int i;
        for( i = 0; i < etypes.len; i++ ) {
            if( krb5_enctype_valid(	NAME_OF_MAIN_LOC_GLOB_P, context, etypes.val[i] ) == 0 ) {
                ac->keytype = etypes.val[i];
                break;
            }
        }
    }
    if( ap_req_options ) {
        *ap_req_options = 0;
        if( ac->keytype != ETYPE_NULL )
            *ap_req_options |= AP_OPTS_USE_SUBKEY;
        if( ap_req->ap_options.use_session_key )
            *ap_req_options |= AP_OPTS_USE_SESSION_KEY;
        if( ap_req->ap_options.mutual_required )
            *ap_req_options |= AP_OPTS_MUTUAL_REQUIRED;
    }
    if( ticket )
        *ticket = t;
    else
        krb5_free_ticket(	NAME_OF_MAIN_LOC_GLOB_P, context, t );
    if( auth_context ) {
        if( *auth_context == NULL )
            *auth_context = ac;
    } else
        krb5_auth_con_free(	NAME_OF_MAIN_LOC_GLOB_P, context, ac );
    free_EtypeList( NAME_OF_MAIN_LOC_GLOB_P, &etypes );
    return 0;
    out:
    if( t )
        krb5_free_ticket(	NAME_OF_MAIN_LOC_GLOB_P, context, t );
    if( auth_context == NULL || *auth_context == NULL )
        krb5_auth_con_free(	NAME_OF_MAIN_LOC_GLOB_P, context, ac );
    return ret;
}
static krb5_error_code
get_key_from_keytab( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                     krb5_auth_context *auth_context,
                     krb5_ap_req *ap_req,
                     krb5_const_principal server,
                     krb5_keytab keytab,
                     krb5_keyblock **out_key )
{
    krb5_error_code ill_ret = KRB5KRB_AP_ERR_NOKEY;
    struct encryption_type * adsl_target_enc_type = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P, ap_req->ticket.enc_part.etype );

    *out_key = (krb5_keyblock*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,sizeof(krb5_keyblock));
    (*out_key)->keytype = adsl_target_enc_type->keytype->type;
    (*out_key)->keyvalue.length = adsl_target_enc_type->keytype->size;
    (*out_key)->keyvalue.data = NULL;

    if(*(context->default_keytab)==0x05 && *(context->default_keytab+1)==0x02){
        ill_ret = m_krb5_search_AD_keytab(NAME_OF_MAIN_LOC_GLOB_P, context, ap_req, server,out_key);
    } else {
        ill_ret = m_krb5_search_heimdal_keytab(NAME_OF_MAIN_LOC_GLOB_P, context, ap_req, server,out_key);
    }

    if(ill_ret){
      m_aux_stor_free(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,(*out_key)->keyvalue.data);
      m_aux_stor_free(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,*out_key);
      *out_key = NULL;
    }
    return ill_ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_rd_req( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
             krb5_auth_context *auth_context,
             const krb5_data *inbuf,
             krb5_const_principal server,
             krb5_keytab keytab,
             krb5_flags *ap_req_options,
             krb5_ticket **ticket )
{
    krb5_error_code ret;
    krb5_ap_req ap_req;
    krb5_keyblock *keyblock = NULL;
    krb5_principal service = NULL;
    if( *auth_context == NULL ) {
        ret = krb5_auth_con_init(	NAME_OF_MAIN_LOC_GLOB_P, context, auth_context );
        if( ret ) {
            //StSch Trace Point
            return ret;
        }
    }
    ret = krb5_decode_ap_req( NAME_OF_MAIN_LOC_GLOB_P, context, inbuf, &ap_req );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    /* Service Principal will always be extracted from the request! */
    _krb5_principalname2krb5_principal(	NAME_OF_MAIN_LOC_GLOB_P, &server,
                                        ap_req.ticket.sname,
                                        ap_req.ticket.realm );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if(context->default_realms[0] == NULL) {
       context->default_realms[0] = server->realm;
    }
    if( ap_req.ap_options.use_session_key &&
            ( *auth_context )->keyblock == NULL ) {
        //StSch Trace Point
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"krb5_rd_req: user to user auth without session key given","rd_req.c 1509" )
        ;
        ret = KRB5KRB_AP_ERR_NOKEY;
        goto out;
    }
    if(( *auth_context )->keyblock == NULL ) {
        ret = get_key_from_keytab(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                    auth_context,
                                    &ap_req,
                                    server,
                                    keytab,
                                    &keyblock );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
    } else {
        ret = krb5_copy_keyblock(	NAME_OF_MAIN_LOC_GLOB_P, context,
                                    ( *auth_context )->keyblock,
                                    &keyblock );
        if( ret ) {
            //StSch Trace Point
            goto out;
        }
    }
    ret = krb5_verify_ap_req( NAME_OF_MAIN_LOC_GLOB_P, context,
                              auth_context,
                              &ap_req,
                              server,
                              keyblock,
                              0,
                              ap_req_options,
                              ticket );
    krb5_free_keyblock( NAME_OF_MAIN_LOC_GLOB_P, context, keyblock );
    out:
    free_AP_REQ( NAME_OF_MAIN_LOC_GLOB_P, &ap_req );
    if( service )
        krb5_free_principal(	NAME_OF_MAIN_LOC_GLOB_P, context, service );
    return ret;
}
static krb5_error_code
verify_checksum_2( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_auth_context auth_context,
                   KRB_SAFE *safe )
{
    krb5_error_code ret;
    u_char *buf;
    size_t buf_size;
    size_t len;
    Checksum c;
    krb5_crypto crypto;
    krb5_keyblock *key;
    c = safe->cksum;
    safe->cksum.cksumtype       = 0;
    safe->cksum.checksum.data   = NULL;
    safe->cksum.checksum.length = 0;
    ASN1_MALLOC_ENCODE( KRB_SAFE, buf, buf_size, safe, &len, ret );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( buf_size != len )
        //StSch Trace Point
        krb5_abortx( NAME_OF_MAIN_LOC_GLOB_P, context,"rd_safe.c 10026: internal error in ASN.1 encoder" );
    if( auth_context->remote_subkey )
        key = auth_context->remote_subkey;
    else if( auth_context->local_subkey )
        key = auth_context->local_subkey;
    else
        key = auth_context->keyblock;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P, context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        goto out;
    }
    ret = krb5_verify_checksum( NAME_OF_MAIN_LOC_GLOB_P, context,
                                crypto,
                                KRB5_KU_KRB_SAFE_CKSUM,
                                buf + buf_size - len,
                                len,
                                &c );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P, context, crypto );
    out:
    safe->cksum = c;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buf )
    ;
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_rd_safe( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
              krb5_auth_context auth_context,
              const krb5_data *inbuf,
              krb5_data *outbuf,
              krb5_replay_data *outdata )
{
    krb5_error_code ret;
    KRB_SAFE safe;
    size_t len;
    if(( auth_context->flags &
            ( KRB5_AUTH_CONTEXT_RET_TIME | KRB5_AUTH_CONTEXT_RET_SEQUENCE ) ) &&
            outdata == NULL ) {
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"rd_safe: need outdata to return data","rd_safe.c 1261" )
        ;
        return KRB5_RC_REQUIRED;
    }
    ret = decode_KRB_SAFE( NAME_OF_MAIN_LOC_GLOB_P, inbuf->data, inbuf->length, &safe, &len );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( safe.pvno != 5 ) {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_BADVERSION;
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        goto failure;
    }
    if( safe.msg_type != krb_safe ) {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_MSG_TYPE;
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        goto failure;
    }
    if( !krb5_checksum_is_keyed( NAME_OF_MAIN_LOC_GLOB_P, context, safe.cksum.cksumtype )
            || !krb5_checksum_is_collision_proof(	NAME_OF_MAIN_LOC_GLOB_P, context, safe.cksum.cksumtype ) ) {
        //StSch Trace Point
        ret = KRB5KRB_AP_ERR_INAPP_CKSUM;
        krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
        goto failure;
    }
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_TIME ) {
        krb5_timestamp sec;
        krb5_timeofday(	NAME_OF_MAIN_LOC_GLOB_P, context, &sec );
        if( safe.safe_body.timestamp == NULL ||
                safe.safe_body.usec      == NULL ||
                abs( *safe.safe_body.timestamp - sec ) > context->max_skew ) {
            //StSch Trace Point
            ret = KRB5KRB_AP_ERR_SKEW;
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            goto failure;
        }
    }
    /* check sequence number. since MIT krb5 cannot generate a sequence
       number of zero but instead generates no sequence number, we accept that
    */
    if( auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE ) {
        if(( safe.safe_body.seq_number == NULL
                && auth_context->remote_seqnumber != 0 )
                || ( safe.safe_body.seq_number != NULL
                     && *safe.safe_body.seq_number !=
                     auth_context->remote_seqnumber ) ) {
            //StSch Trace Point
            ret = KRB5KRB_AP_ERR_BADORDER;
            krb5_clear_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context );
            goto failure;
        }
        auth_context->remote_seqnumber++;
    }
    ret = verify_checksum_2( NAME_OF_MAIN_LOC_GLOB_P, context, auth_context, &safe );
    if( ret ) {
        //StSch Trace Point
        goto failure;
    }
    outbuf->length = safe.safe_body.user_data.length;
    outbuf->data   =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, outbuf->length )
        ;
    if( outbuf->data == NULL ) {
        //StSch Trace Point
        ret = ENOMEM;
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"malloc: out of memory","rd_safe.c 1262" )
        ;
        goto failure;
    }
    memcpy( outbuf->data, safe.safe_body.user_data.data, outbuf->length );
    if(( auth_context->flags &
            ( KRB5_AUTH_CONTEXT_RET_TIME | KRB5_AUTH_CONTEXT_RET_SEQUENCE ) ) ) {
        /* if these fields are not present in the safe-part, silently
               return zero */
        memset( outdata, 0, sizeof( *outdata ) );
        if( safe.safe_body.timestamp )
            outdata->timestamp = *safe.safe_body.timestamp;
        if( safe.safe_body.usec )
            outdata->usec = *safe.safe_body.usec;
        if( safe.safe_body.seq_number )
            outdata->seq = *safe.safe_body.seq_number;
    }
    failure:
    free_KRB_SAFE( NAME_OF_MAIN_LOC_GLOB_P, &safe );
    return ret;
}
OM_uint32 gss_release_buffer
( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 * minor_status,
  gss_buffer_t buffer
)
{
    *minor_status = 0;
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, buffer->value )
    ;
    buffer->value  = NULL;
    buffer->length = 0;
    return GSS_S_COMPLETE;
}
#define WIN32  /** @todo check, what this is supposed to do!!! */
/*
 * Random number generator based on ideas from truerand in cryptolib
 * as described on page 424 in Applied Cryptography 2 ed. by Bruce
 * Schneier.
 */
#if !defined(WIN32) && !defined(__EMX__) && !defined(__OS2__) && !defined(__CYGWIN32__)
static
RETSIGTYPE
sigALRM( int sig )
{
    if( igdata < gsize )
        gdata[igdata++] ^= counter & 0xff;
#ifndef HAVE_SIGACTION
    signal( SIGALRM, sigALRM );
#endif
    SIGRETURN( 0 );
}
#endif
#if !defined(HAVE_RANDOM) && defined(HAVE_RAND)
#ifndef srandom
#define srandom srand
#endif
#ifndef random
#define random rand
#endif
#endif
#if !defined(HAVE_SETITIMER) || defined(WIN32) || defined(__EMX__) || defined(__OS2__) || defined(__CYGWIN32__)
static void
des_not_rand_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *data, int size )
{
    int i;
    srandom( time( NULL ) );
    for( i = 0; i < size; ++i )
        data[i] ^= random() % 0x100;
}
#endif
#if !defined(WIN32) && !defined(__EMX__) && !defined(__OS2__) && !defined(__CYGWIN32__)
#ifndef HAVE_SETITIMER
static void
pacemaker( struct timeval *tv )
{
    fd_set fds;
    pid_t pid;
    pid = getppid();
    while( 1 ) {
        FD_ZERO( &fds );
        FD_SET( 0, &fds );
        select( 1, &fds, NULL, NULL, tv );
        kill( pid, SIGALRM );
    }
}
#endif
#ifdef HAVE_SIGACTION
static RETSIGTYPE
( *fake_signal( int sig, RETSIGTYPE( *f )( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int ) ) )( int )
{
    struct sigaction sa, osa;
    sa.sa_handler = f;
    sa.sa_flags = 0;
    sigemptyset( &sa.sa_mask );
    sigaction( sig, &sa, &osa );
    return osa.sa_handler;
}
#define signal(S, F) fake_signal((S), (F))
#endif
/*
 * Generate size bytes of "random" data using timed interrupts.
 * It takes about 40ms/byte random data.
 * It's not neccessary to be root to run it.
 */
void
DES_rand_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *data, int size )
{
    struct itimerval tv, otv;
    RETSIGTYPE( *osa )( NAME_OF_MAIN_LOC_GLOB_P, int );
    int i, j;
#ifndef HAVE_SETITIMER
    RETSIGTYPE( *ochld )( NAME_OF_MAIN_LOC_GLOB_P, int );
    pid_t pid;
#endif
    char *rnd_devices[] = {"/dev/random",
                           "/dev/srandom",
                           "/dev/urandom",
                           "/dev/arandom",
                           NULL
                          };
    char **p;
    for( p = rnd_devices; *p; p++ ) {
        int fd = open( *p, O_RDONLY | O_NDELAY );
        if( fd >= 0 && read( fd, data, size ) == size ) {
            close( fd );
            return;
        }
        close( fd );
    }
    if( size >= 8 )
        sumFile( "/dev/mem", ( 1024*1024*2 ), data );
    gdata = data;
    gsize = size;
    igdata = 0;
    osa = signal( SIGALRM, sigALRM );
    tv.it_value.tv_sec = 0;
    tv.it_value.tv_usec = 10 * 1000;
    tv.it_interval = tv.it_value;
#ifdef HAVE_SETITIMER
    setitimer( ITIMER_REAL, &tv, &otv );
#else
    ochld = signal( SIGCHLD, SIG_IGN );
    pid = fork();
    if( pid == -1 ) {
        signal( SIGCHLD, ochld != SIG_ERR ? ochld : SIG_DFL );
        des_not_rand_data(	NAME_OF_MAIN_LOC_GLOB_P, data, size );
        return;
    }
    if( pid == 0 )
        pacemaker( &tv.it_interval );
#endif
    for( i = 0; i < 4; i++ ) {
        for( igdata = 0; igdata < size; )
            counter++;
        for( j = 0; j < size; j++ )
            gdata[j] = ( gdata[j]>>2 ) | ( gdata[j]<<6 );
    }
#ifdef HAVE_SETITIMER
    setitimer( ITIMER_REAL, &otv, 0 );
#else
    kill( pid, SIGKILL );
    while( waitpid( pid, NULL, 0 ) != pid );
    signal( SIGCHLD, ochld != SIG_ERR ? ochld : SIG_DFL );
#endif
    signal( SIGALRM, osa != SIG_ERR ? osa : SIG_DFL );
}
#else
void
DES_rand_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned char *p, int s )
{
    des_not_rand_data( NAME_OF_MAIN_LOC_GLOB_P, p, s );
}
#endif
void
DES_generate_random_block( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock *block )
{
    DES_rand_data( NAME_OF_MAIN_LOC_GLOB_P, ( unsigned char * )block, sizeof( *block ) );
}
/*
 * In case the generator does not get initialized use this as fallback.
 */
static void
do_initialize( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P
             )
{
    DES_cblock default_seed;
    do {
        DES_generate_random_block(	NAME_OF_MAIN_LOC_GLOB_P, &default_seed );
        DES_set_odd_parity(	NAME_OF_MAIN_LOC_GLOB_P, &default_seed );
    } while( DES_is_weak_key( NAME_OF_MAIN_LOC_GLOB_P, &default_seed ) );
    DES_init_random_number_generator( NAME_OF_MAIN_LOC_GLOB_P, &default_seed );
}
/*
 * Set the generator seed and reset the sequence number to 0.
 */
void
DES_set_random_generator_seed( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock *seed )
{
    GenDESSubKeys( seed, &
                 NAME_OF_MAIN_LOC_GLOB_P->
                 sequence_seed );
    do {
        NAME_OF_MAIN_LOC_GLOB_P->
        sequence_index[0] =
            NAME_OF_MAIN_LOC_GLOB_P->
            sequence_index[1] = 0;
    } while( 0 );
    NAME_OF_MAIN_LOC_GLOB_P->
    initialized = 1;
}
/*
 * Generate a sequence of random des keys
 * using the random block sequence, fixup
 * parity and skip weak keys.
 */
int
DES_new_random_key( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock *key )
{
    if( !
            NAME_OF_MAIN_LOC_GLOB_P->
            initialized )
        do_initialize(	NAME_OF_MAIN_LOC_GLOB_P );
    do {
        DES_ecb_encrypt_decrypt(( DES_cblock * ) NAME_OF_MAIN_LOC_GLOB_P->sequence_index,
            key, NAME_OF_MAIN_LOC_GLOB_P->sequence_seed, 1, DES_ENCRYPT);
        do {
            if( ++
                    NAME_OF_MAIN_LOC_GLOB_P->
                    sequence_index[0] == 0 ) ++
                NAME_OF_MAIN_LOC_GLOB_P->
                sequence_index[1];
        } while( 0 );
        DES_set_odd_parity(	NAME_OF_MAIN_LOC_GLOB_P, key );
    } while( DES_is_weak_key( NAME_OF_MAIN_LOC_GLOB_P, key ) );
    return( 0 );
}
/*
 * des_init_random_number_generator:
 *
 * Initialize the sequence of random 64 bit blocks.  The input seed
 * can be a secret key since it should be well hidden and is also not
 * kept.
 *
 */
void
DES_init_random_number_generator( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, DES_cblock *seed )
{
    struct timeval now;
    DES_cblock uniq;
    DES_cblock new_key;
    m_gettimeofday_hl( NAME_OF_MAIN_LOC_GLOB_P, &now, ( struct timezone * )0 );
    DES_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, &uniq );
    DES_set_random_generator_seed( NAME_OF_MAIN_LOC_GLOB_P, seed );
    set_sequence_number(( unsigned char * )&uniq );
    DES_new_random_key( NAME_OF_MAIN_LOC_GLOB_P, &new_key );
    DES_set_random_generator_seed( NAME_OF_MAIN_LOC_GLOB_P, &new_key );
    set_sequence_number(( unsigned char * )&now );
    DES_new_random_key( NAME_OF_MAIN_LOC_GLOB_P, &new_key );
    DES_set_random_generator_seed( NAME_OF_MAIN_LOC_GLOB_P, &new_key );
}

#undef WIN32
static int
recv_loop( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, HANDLE_CONNECT,
           time_t tmout,
           int udp,
           size_t limit,
           krb5_data *rep )
{
    int ret;
#ifdef WITH_OWN_NET_CONNECT
    int iml_error;
#endif
    krb5_data_zero( NAME_OF_MAIN_LOC_GLOB_P, rep );
    rep->data =
        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, rep->data, limit )
        ;
    if( rep->data == NULL ) {
        krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, rep );
        return -1;
    }
#ifndef WITH_OWN_NET_CONNECT
    //IGNORE_INTERFACE_CHANGE_begin
    ret = m_recv_hl( fd, ( char* )rep->data, limit, tmout, NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context );
    //IGNORE_INTERFACE_CHANGE_end
    if( ret < 0 )
#else
    ret = m_tcpsync_recv( &iml_error, adsp_tcpsync_1, ( char* )rep->data, limit, tmout * 1000 );
    if( ret <= 0 )
#endif
    {
        krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, rep );
        return -1;
    }
    rep->length = limit;
    return 0;
}
/*
 * `send_and_recv' for a TCP (or any other stream) socket.
 * Since there are no record limits on a stream socket the protocol here
 * is to prepend the request with 4 bytes of its length and the reply
 * is similarly encoded.
 */

static int
send_and_recv_tcp( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   HANDLE_CONNECT,
                   time_t tmout,
                   const krb5_data *req,
                   krb5_data *rep )
{
#ifdef WITH_OWN_NET_CONNECT
#define fd adsp_tcpsync_1
#endif
    unsigned char len[4];
    unsigned long rep_len;
    krb5_data len_data;
    _krb5_put_int( NAME_OF_MAIN_LOC_GLOB_P, len, req->length, 4 );
    if( net_write( NAME_OF_MAIN_LOC_GLOB_P, fd, len, sizeof( len ) ) < 0 )
        return -1;
    if( net_write( NAME_OF_MAIN_LOC_GLOB_P, fd, req->data, req->length ) < 0 )
        return -1;
    if( recv_loop( NAME_OF_MAIN_LOC_GLOB_P, fd, tmout, 0, 4, &len_data ) < 0 )
        return -1;
    if( len_data.length != 4 ) {
        krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &len_data );
        return -1;
    }
    _krb5_get_int( NAME_OF_MAIN_LOC_GLOB_P, len_data.data, &rep_len, 4 );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &len_data );
    if( rep_len <= context->max_ticket_size ) {
        if( recv_loop( NAME_OF_MAIN_LOC_GLOB_P, fd, tmout, 0, rep_len, rep ) < 0 )
            return -1;
        if( rep->length != rep_len ) {
            krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, rep );
            return -1;
        }
    } else {
        //StSch Trace Point
        krb5_err( NAME_OF_MAIN_LOC_GLOB_P, context, 1, 1,"ticket size larger than max_ticket_size" )
        ;
    }
    return 0;
#ifdef WITH_OWN_NET_CONNECT
#undef fd
#endif
}
/*
 * Send the data `send' to one host from `handle` and get back the reply
 * in `receive'.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_sendto( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
             const krb5_data *send_data,
             krb5_krbhst_handle handle,
             krb5_data *receive )
{
    krb5_error_code ret = 0;
#ifndef WITH_OWN_NET_CONNECT
    int fd;
    int i;
#else
    BOOL     bol1;
    int      iml_w1;
    int      iml_error;
    struct dsd_tcpsync_1 dsl_tcpsync_1;
#endif
#ifndef WITH_OWN_NET_CONNECT
    //IGNORE_INTERFACE_CHANGE_begin
    m_init_connect_hl( NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context );
    //IGNORE_INTERFACE_CHANGE_end
    for( i = 0; i < context->max_retries; ++i ) {
        //IGNORE_INTERFACE_CHANGE_begin
        fd = m_socket_hl( NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context );
        //IGNORE_INTERFACE_CHANGE_end
        if( fd < 0 )
            continue;
        //IGNORE_INTERFACE_CHANGE_begin
        if( m_connect_hl( fd, context->kdc_ip_address, context->kdc_port, NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context ) < 0 ) {
            m_closesocket_hl( fd, NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context );
            //IGNORE_INTERFACE_CHANGE_end
            continue;
        }
        NAME_OF_MAIN_LOC_GLOB_P->a_generic_obj = &context->kdc_timeout;
        ret = send_and_recv_tcp( NAME_OF_MAIN_LOC_GLOB_P, context, fd, context->kdc_timeout,
                                 send_data, receive );
        NAME_OF_MAIN_LOC_GLOB_P->a_generic_obj = ( void* )0;
        //IGNORE_INTERFACE_CHANGE_begin
        m_closesocket_hl( fd, NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context );
        //IGNORE_INTERFACE_CHANGE_end
        if( ret == 0 && receive->length != 0 )
            goto out;
    }
#else
    bol1 = m_tcpsync_connect( &iml_error, &dsl_tcpsync_1,
                              &ADSL_KRB5_KDC_SERVER->dsc_bind_multih,
                              ADSL_KRB5_KDC_SERVER->adsc_server_ineta,
                              ADSL_KRB5_KDC_SERVER->imc_port );
    if( bol1 ) {
        NAME_OF_MAIN_LOC_GLOB_P->a_generic_obj = &context->kdc_timeout;
        ret = send_and_recv_tcp( NAME_OF_MAIN_LOC_GLOB_P, context, &dsl_tcpsync_1, context->kdc_timeout,
                                 send_data, receive );
        NAME_OF_MAIN_LOC_GLOB_P->a_generic_obj = ( void* )0;
        iml_w1 = m_tcpsync_close( &iml_error, &dsl_tcpsync_1 );
        if(( iml_w1 == 0 ) && ( receive->length > 0 ) ) goto out;
    }
#endif
    //StSch Trace Point
    krb5_clear_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
    ret = KRB5_KDC_UNREACH;
    out:
    //IGNORE_INTERFACE_CHANGE_begin
    m_end_connect_hl( NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context );
    //IGNORE_INTERFACE_CHANGE_end
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_sendto_kdc_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                       const krb5_data *send_data,
                       const krb5_realm *realm,
                       krb5_data *receive,
                       int flags )
{
    krb5_error_code ret;
    krb5_krbhst_handle handle;
    int type;
    if(( flags & KRB5_KRBHST_FLAGS_MASTER ) || context->use_admin_kdc )
        type = KRB5_KRBHST_ADMIN;
    else
        type = KRB5_KRBHST_KDC;
    if( send_data->length > context->large_msg_size )
        flags |= KRB5_KRBHST_FLAGS_LARGE_MSG;
    ret = krb5_krbhst_init_flags( NAME_OF_MAIN_LOC_GLOB_P, context, *realm, type, flags, &handle );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_sendto( NAME_OF_MAIN_LOC_GLOB_P, context, send_data, handle, receive );
    krb5_krbhst_free( NAME_OF_MAIN_LOC_GLOB_P, context, handle );
    if( ret == KRB5_KDC_UNREACH )
        krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P, context,"unable to reach any KDC in realm ","send_to_kdc.c 1373" )
        ;
    return ret;
}
#undef fd
struct gss_msg_order {
    OM_uint32 flags;
    OM_uint32 start;
    OM_uint32 length;
    OM_uint32 jitter_window;
    OM_uint32 first_seq;
    OM_uint32 elem[1];
};
static void
elem_set( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct gss_msg_order *o, unsigned int slot, OM_uint32 val )
{
    o->elem[slot % o->jitter_window] = val;
}
static void
elem_insert( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct gss_msg_order *o,
             unsigned int after_slot,
             OM_uint32 seq_num )
{
    if( !( o->jitter_window > after_slot ) ) {
        //StSch Trace Point
        m_end_exit_abort_hl( NAME_OF_MAIN_LOC_GLOB_P, 'a',0 );
    }
    if( o->length > after_slot )
        memmove( &o->elem[after_slot + 1], &o->elem[after_slot],
                 ( o->length - after_slot - 1 ) * sizeof( o->elem[0] ) );
    elem_set( NAME_OF_MAIN_LOC_GLOB_P, o, after_slot, seq_num );
    if( o->length < o->jitter_window )
        o->length++;
}
OM_uint32
_gssapi_msg_order_check( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct gss_msg_order *o, OM_uint32 seq_num )
{
    OM_uint32 r;
    int i;
    if( o == NULL )
        return GSS_S_COMPLETE;
    if(( o->flags & ( GSS_C_REPLAY_FLAG|GSS_C_SEQUENCE_FLAG ) ) == 0 )
        return GSS_S_COMPLETE;
    if( o->elem[0] == seq_num - 1 ) {
        elem_insert(	NAME_OF_MAIN_LOC_GLOB_P, o, 0, seq_num );
        return GSS_S_COMPLETE;
    }
    r = ( o->flags & ( GSS_C_REPLAY_FLAG|GSS_C_SEQUENCE_FLAG ) )==GSS_C_REPLAY_FLAG;
    /* sequence number larger then largest sequence number
     * or smaller then the first sequence number */
    if( seq_num > o->elem[0]
            || seq_num < o->first_seq
            || o->length == 0 ) {
        elem_insert(	NAME_OF_MAIN_LOC_GLOB_P, o, 0, seq_num );
        if( r ) {
            return GSS_S_COMPLETE;
        } else {
            return GSS_S_GAP_TOKEN;
        }
    }
    if( !( o->length > 0 ) ) {
        //StSch Trace Point
        m_end_exit_abort_hl( NAME_OF_MAIN_LOC_GLOB_P, 'a',0 );
    }
    if( seq_num < o->elem[o->length - 1] ) {
        if( r )
            return( GSS_S_OLD_TOKEN );
        else
            return( GSS_S_UNSEQ_TOKEN );
    }
    if( seq_num == o->elem[o->length - 1] ) {
        return GSS_S_DUPLICATE_TOKEN;
    }
    for( i = 0; i < o->length - 1; i++ ) {
        if( o->elem[i] == seq_num )
            return GSS_S_DUPLICATE_TOKEN;
        if( o->elem[i + 1] < seq_num && o->elem[i] < seq_num ) {
            elem_insert(	NAME_OF_MAIN_LOC_GLOB_P, o, i, seq_num );
            if( r )
                return GSS_S_COMPLETE;
            else
                return GSS_S_UNSEQ_TOKEN;
        }
    }
    return GSS_S_FAILURE;
}
void KRB5_LIB_FUNCTION
krb5_storage_set_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_flags flags )
{
    sp->flags |= flags;
}
krb5_boolean KRB5_LIB_FUNCTION
krb5_storage_is_flags( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_flags flags )
{
    return ( sp->flags & flags ) == flags;
}
void KRB5_LIB_FUNCTION
krb5_storage_set_eof_code( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, int code )
{
    sp->eof_code = code;
}
krb5_ssize_t KRB5_LIB_FUNCTION
_krb5_put_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, void *buffer, unsigned long value, size_t size )
{
    unsigned char *p = buffer;
    int i;
    for( i = size - 1; i >= 0; i-- ) {
        p[i] = value & 0xff;
        value >>= 8;
    }
    return size;
}
krb5_ssize_t KRB5_LIB_FUNCTION
_krb5_get_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, void *buffer, unsigned long *value, size_t size )
{
    unsigned char *p = buffer;
    unsigned long v = 0;
    int i;
    for( i = 0; i < size; i++ )
        v = ( v << 8 ) + p[i];
    *value = v;
    return size;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_storage_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp )
{
    if( sp->free )
        ( NAME_OF_MAIN_LOC_GLOB_P, *sp->free )( NAME_OF_MAIN_LOC_GLOB_P, sp );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sp->data )
    ;
#ifdef WITHOUT_FILE
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sp->ticket_out )
    ;
#endif
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sp )
    ;
    return 0;
}
static krb5_error_code
krb5_store_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                int32_t value,
                size_t len )
{
    int ret;
    unsigned char v[16];
    if( len > sizeof( v ) )
        return EINVAL;
    _krb5_put_int( NAME_OF_MAIN_LOC_GLOB_P, v, value, len );
    ret = sp->store( NAME_OF_MAIN_LOC_GLOB_P, sp, v, len );
    if( ret != len )
        return ( ret<0 )?( int )m__errno_location_hl(	NAME_OF_MAIN_LOC_GLOB_P
                                                    ):sp->eof_code;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_int32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                  int32_t value )
{
    if( BYTEORDER_IS_HOST( sp ) )
        value = htonl( value );
    else if( BYTEORDER_IS_LE( sp ) )
        value = bswap32(	NAME_OF_MAIN_LOC_GLOB_P, value );
    return krb5_store_int( NAME_OF_MAIN_LOC_GLOB_P, sp, value, 4 );
}
static krb5_error_code
krb5_ret_int( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
              int32_t *value,
              size_t len )
{
    int ret;
    unsigned char v[4];
    unsigned long w;
    ret = sp->fetch( NAME_OF_MAIN_LOC_GLOB_P, sp, v, len );
    if( ret != len )
        return ( ret<0 )?( int )m__errno_location_hl(	NAME_OF_MAIN_LOC_GLOB_P
                                                    ):sp->eof_code;
    _krb5_get_int( NAME_OF_MAIN_LOC_GLOB_P, v, &w, len );
    *value = w;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_int32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                int32_t *value )
{
    krb5_error_code ret = krb5_ret_int( NAME_OF_MAIN_LOC_GLOB_P, sp, value, 4 );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( BYTEORDER_IS_HOST( sp ) )
        *value = htonl( *value );
    else if( BYTEORDER_IS_LE( sp ) )
        *value = bswap32(	NAME_OF_MAIN_LOC_GLOB_P, *value );
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_int16( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                  int16_t value )
{
    if( BYTEORDER_IS_HOST( sp ) )
        value = htons( value );
    else if( BYTEORDER_IS_LE( sp ) )
        value = bswap16(	NAME_OF_MAIN_LOC_GLOB_P, value );
    return krb5_store_int( NAME_OF_MAIN_LOC_GLOB_P, sp, value, 2 );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_int16( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                int16_t *value )
{
    int32_t v;
    int ret;
    ret = krb5_ret_int( NAME_OF_MAIN_LOC_GLOB_P, sp, &v, 2 );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    *value = v;
    if( BYTEORDER_IS_HOST( sp ) )
        *value = htons( *value );
    else if( BYTEORDER_IS_LE( sp ) )
        *value = bswap16(	NAME_OF_MAIN_LOC_GLOB_P, *value );
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_int8( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                 int8_t value )
{
    int ret;
    ret = sp->store( NAME_OF_MAIN_LOC_GLOB_P, sp, &value, sizeof( value ) );
    if( ret != sizeof( value ) )
        return ( ret<0 )?( int )m__errno_location_hl(	NAME_OF_MAIN_LOC_GLOB_P
                                                    ):sp->eof_code;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_int8( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
               int8_t *value )
{
    int ret;
    ret = sp->fetch( NAME_OF_MAIN_LOC_GLOB_P, sp, value, sizeof( *value ) );
    if( ret != sizeof( *value ) )
        return ( ret<0 )?( int )m__errno_location_hl(	NAME_OF_MAIN_LOC_GLOB_P
                                                    ):sp->eof_code;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                 krb5_data data )
{
    int ret;
    ret = krb5_store_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, data.length );
    if( ret < 0 )
        return ret;
    ret = sp->store( NAME_OF_MAIN_LOC_GLOB_P, sp, data.data, data.length );
    if( ret != data.length ) {
        if( ret < 0 )
            return ( int )m__errno_location_hl(	NAME_OF_MAIN_LOC_GLOB_P );
        return sp->eof_code;
    }
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_data( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
               krb5_data *data )
{
    int ret;
    int32_t size;
    ret = krb5_ret_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, &size );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_data_alloc( NAME_OF_MAIN_LOC_GLOB_P, data, size );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( size ) {
        ret = sp->fetch(	NAME_OF_MAIN_LOC_GLOB_P, sp, data->data, size );
        if( ret != size )
            return ( ret < 0 )? ( int )m__errno_location_hl(	NAME_OF_MAIN_LOC_GLOB_P
                                                           ) : sp->eof_code;
    }
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, const char *s )
{
    krb5_data data;
    data.length = strlen( s );
    data.data = ( void* )s;
    return krb5_store_data( NAME_OF_MAIN_LOC_GLOB_P, sp, data );
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                 char **string )
{
    int ret;
    krb5_data data;
    ret = krb5_ret_data( NAME_OF_MAIN_LOC_GLOB_P, sp, &data );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    *string =
        m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, data.data, data.length + 1 )
        ;
    if( *string == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, data.data )
        ;
        return ENOMEM;
    }
    ( *string )[data.length] = 0;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                      krb5_principal p )
{
    int i;
    int ret;
    if( !krb5_storage_is_flags( NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_STORAGE_PRINCIPAL_NO_NAME_TYPE ) ) {
        ret = krb5_store_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, p->name.name_type );
        if( ret ) { //StSch Trace Point
            return ret;
        }
    }
    if( krb5_storage_is_flags( NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_STORAGE_PRINCIPAL_WRONG_NUM_COMPONENTS ) )
        ret = krb5_store_int32(	NAME_OF_MAIN_LOC_GLOB_P, sp, p->name.name_string.len + 1 );
    else
        ret = krb5_store_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, p->name.name_string.len );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    ret = krb5_store_string( NAME_OF_MAIN_LOC_GLOB_P, sp, p->realm );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    for( i = 0; i < p->name.name_string.len; i++ ) {
        ret = krb5_store_string(	NAME_OF_MAIN_LOC_GLOB_P, sp, p->name.name_string.val[i] );
        if( ret ) { //StSch Trace Point
            return ret;
        }
    }
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_principal( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp,
                    krb5_principal *princ )
{
    int i;
    int ret;
    krb5_principal p;
    int32_t type;
    int32_t ncomp;
    p =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( 1 ) * ( sizeof( *p ) ) ),'\0',( 1 ) * ( sizeof( *p ) ) )
        ;
    if( p == NULL )
        return ENOMEM;
    if( krb5_storage_is_flags( NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_STORAGE_PRINCIPAL_NO_NAME_TYPE ) )
        type = KRB5_NT_UNKNOWN;
    else 	if(( ret = krb5_ret_int32(	NAME_OF_MAIN_LOC_GLOB_P, sp, &type ) ) ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    if(( ret = krb5_ret_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, &ncomp ) ) ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p )
        ;
        return ret;
    }
    if( krb5_storage_is_flags( NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_STORAGE_PRINCIPAL_WRONG_NUM_COMPONENTS ) )
        ncomp--;
    p->name.name_type = type;
    p->name.name_string.len = ncomp;
    ret = krb5_ret_string( NAME_OF_MAIN_LOC_GLOB_P, sp, &p->realm );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    p->name.name_string.val =
        memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( ncomp ) * ( sizeof( *p->name.name_string.val ) ) ),'\0',( ncomp ) * ( sizeof( *p->name.name_string.val ) ) )
        ;
    if( p->name.name_string.val == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, p->realm )
        ;
        return ENOMEM;
    }
    for( i = 0; i < ncomp; i++ ) {
        ret = krb5_ret_string(	NAME_OF_MAIN_LOC_GLOB_P, sp, &p->name.name_string.val[i] );
        if( ret ) { //StSch Trace Point
            return ret;
        }
    }
    *princ = p;
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_keyblock p )
{
    int ret;
    ret = krb5_store_int16( NAME_OF_MAIN_LOC_GLOB_P, sp, p.keytype );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    if( krb5_storage_is_flags( NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_STORAGE_KEYBLOCK_KEYTYPE_TWICE ) ) {
        /* this should really be enctype, but it is the same as
               keytype nowadays */
        ret = krb5_store_int16( NAME_OF_MAIN_LOC_GLOB_P, sp, p.keytype );
        if( ret ) { //StSch Trace Point
            return ret;
        }
    }
    ret = krb5_store_data( NAME_OF_MAIN_LOC_GLOB_P, sp, p.keyvalue );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_keyblock( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_keyblock *p )
{
    int ret;
    int16_t tmp;
    ret = krb5_ret_int16( NAME_OF_MAIN_LOC_GLOB_P, sp, &tmp );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    p->keytype = tmp;
    if( krb5_storage_is_flags( NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_STORAGE_KEYBLOCK_KEYTYPE_TWICE ) ) {
        ret = krb5_ret_int16( NAME_OF_MAIN_LOC_GLOB_P, sp, &tmp );
        if( ret ) { //StSch Trace Point
            return ret;
        }
    }
    ret = krb5_ret_data( NAME_OF_MAIN_LOC_GLOB_P, sp, &p->keyvalue );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_times( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_times times )
{
    int ret;
    ret = krb5_store_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, times.authtime );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    ret = krb5_store_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, times.starttime );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    ret = krb5_store_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, times.endtime );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    ret = krb5_store_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, times.renew_till );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_times( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_times *times )
{
    int ret;
    int32_t tmp;
    ret = krb5_ret_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, &tmp );
    times->authtime = tmp;
    if( ret ) { //StSch Trace Point
        return ret;
    }
    ret = krb5_ret_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, &tmp );
    times->starttime = tmp;
    if( ret ) { //StSch Trace Point
        return ret;
    }
    ret = krb5_ret_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, &tmp );
    times->endtime = tmp;
    if( ret ) { //StSch Trace Point
        return ret;
    }
    ret = krb5_ret_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, &tmp );
    times->renew_till = tmp;
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_address( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_address p )
{
    int ret;
    ret = krb5_store_int16( NAME_OF_MAIN_LOC_GLOB_P, sp, p.addr_type );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    ret = krb5_store_data( NAME_OF_MAIN_LOC_GLOB_P, sp, p.address );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_address( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_address *adr )
{
    int16_t t;
    int ret;
    ret = krb5_ret_int16( NAME_OF_MAIN_LOC_GLOB_P, sp, &t );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    adr->addr_type = t;
    ret = krb5_ret_data( NAME_OF_MAIN_LOC_GLOB_P, sp, &adr->address );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_addrs( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_addresses p )
{
    int i;
    int ret;
    ret = krb5_store_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, p.len );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    for( i = 0; i<p.len; i++ ) {
        ret = krb5_store_address(	NAME_OF_MAIN_LOC_GLOB_P, sp, p.val[i] );
        if( ret ) { //StSch Trace Point
            break;
        }
    }
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_addrs( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_addresses *adr )
{
    int i;
    int ret;
    int32_t tmp;
    ret = krb5_ret_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, &tmp );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    adr->len = tmp;
    ALLOC( adr->val, adr->len );
    if( adr->val == NULL && adr->len != 0 )
        return ENOMEM;
    for( i = 0; i < adr->len; i++ ) {
        ret = krb5_ret_address(	NAME_OF_MAIN_LOC_GLOB_P, sp, &adr->val[i] );
        if( ret ) { //StSch Trace Point
            break;
        }
    }
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_authdata( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_authdata auth )
{
    krb5_error_code ret;
    int i;
    ret = krb5_store_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, auth.len );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    for( i = 0; i < auth.len; i++ ) {
        ret = krb5_store_int16(	NAME_OF_MAIN_LOC_GLOB_P, sp, auth.val[i].ad_type );
        if( ret ) { //StSch Trace Point
            break;
        }
        ret = krb5_store_data(	NAME_OF_MAIN_LOC_GLOB_P, sp, auth.val[i].ad_data );
        if( ret ) { //StSch Trace Point
            break;
        }
    }
    return 0;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_authdata( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_authdata *auth )
{
    krb5_error_code ret;
    int32_t tmp;
    int16_t tmp2;
    int i;
    ret = krb5_ret_int32( NAME_OF_MAIN_LOC_GLOB_P, sp, &tmp );
    if( ret ) { //StSch Trace Point
        return ret;
    }
    ALLOC_SEQ( auth, tmp );
    if( auth->val == NULL && tmp != 0 )
        return ENOMEM;
    for( i = 0; i < tmp; i++ ) {
        ret = krb5_ret_int16(	NAME_OF_MAIN_LOC_GLOB_P, sp, &tmp2 );
        if( ret ) { //StSch Trace Point
            break;
        }
        auth->val[i].ad_type = tmp2;
        ret = krb5_ret_data(	NAME_OF_MAIN_LOC_GLOB_P, sp, &auth->val[i].ad_data );
        if( ret ) { //StSch Trace Point
            break;
        }
    }
    return ret;
}
static int32_t
bitswap32( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int32_t b )
{
    int32_t r = 0;
    int i;
    for( i = 0; i < 32; i++ ) {
        r = r << 1 | ( b & 1 );
        b = b >> 1;
    }
    return r;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_store_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_creds *creds )
{
    int ret;
    ret = krb5_store_principal( NAME_OF_MAIN_LOC_GLOB_P, sp, creds->client );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_store_principal( NAME_OF_MAIN_LOC_GLOB_P, sp, creds->server );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_store_keyblock( NAME_OF_MAIN_LOC_GLOB_P, sp, creds->session );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_store_times( NAME_OF_MAIN_LOC_GLOB_P, sp, creds->times );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_store_int8( NAME_OF_MAIN_LOC_GLOB_P, sp, creds->second_ticket.length != 0 );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( krb5_storage_is_flags( NAME_OF_MAIN_LOC_GLOB_P, sp, KRB5_STORAGE_CREDS_FLAGS_WRONG_BITORDER ) )
        ret = krb5_store_int32(	NAME_OF_MAIN_LOC_GLOB_P, sp, creds->flags.i );
    else
        ret = krb5_store_int32(	NAME_OF_MAIN_LOC_GLOB_P, sp, bitswap32(	NAME_OF_MAIN_LOC_GLOB_P, TicketFlags2int(	NAME_OF_MAIN_LOC_GLOB_P, creds->flags.b ) ) );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_store_addrs( NAME_OF_MAIN_LOC_GLOB_P, sp, creds->addresses );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_store_authdata( NAME_OF_MAIN_LOC_GLOB_P, sp, creds->authdata );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_store_data( NAME_OF_MAIN_LOC_GLOB_P, sp, creds->ticket );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    ret = krb5_store_data( NAME_OF_MAIN_LOC_GLOB_P, sp, creds->second_ticket );
    return ret;
}
krb5_error_code KRB5_LIB_FUNCTION
krb5_ret_creds( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage *sp, krb5_creds *creds )
{
    krb5_error_code ret;
    int8_t dummy8;
    int32_t dummy32;
    memset( creds, 0, sizeof( *creds ) );
    ret = krb5_ret_principal( NAME_OF_MAIN_LOC_GLOB_P, sp,  &creds->client );
    if( ret ) { //StSch Trace Point
        goto cleanup;
    }
    ret = krb5_ret_principal( NAME_OF_MAIN_LOC_GLOB_P, sp,  &creds->server );
    if( ret ) { //StSch Trace Point
        goto cleanup;
    }
    ret = krb5_ret_keyblock( NAME_OF_MAIN_LOC_GLOB_P, sp,  &creds->session );
    if( ret ) { //StSch Trace Point
        goto cleanup;
    }
    ret = krb5_ret_times( NAME_OF_MAIN_LOC_GLOB_P, sp,  &creds->times );
    if( ret ) { //StSch Trace Point
        goto cleanup;
    }
    ret = krb5_ret_int8( NAME_OF_MAIN_LOC_GLOB_P, sp,  &dummy8 );
    if( ret ) { //StSch Trace Point
        goto cleanup;
    }
    ret = krb5_ret_int32( NAME_OF_MAIN_LOC_GLOB_P, sp,  &dummy32 );
    if( ret ) { //StSch Trace Point
        goto cleanup;
    }
    /*
     * Runtime detect the what is the higher bits of the bitfield. If
     * any of the higher bits are set in the input data, its either a
     * new ticket flag (and this code need to be removed), or its a
     * MIT cache (or new Heimdal cache), lets change it to our current
     * format.
     */
    {
        u_int32_t mask = 0xffff0000;
        creds->flags.i = 0;
        creds->flags.b.anonymous = 1;
        if( creds->flags.i & mask )
            mask = ~mask;
        if( dummy32 & mask )
            dummy32 = bitswap32(	NAME_OF_MAIN_LOC_GLOB_P, dummy32 );
    }
    creds->flags.i = dummy32;
    ret = krb5_ret_addrs( NAME_OF_MAIN_LOC_GLOB_P, sp,  &creds->addresses );
    if( ret ) { //StSch Trace Point
        goto cleanup;
    }
    ret = krb5_ret_authdata( NAME_OF_MAIN_LOC_GLOB_P, sp,  &creds->authdata );
    if( ret ) { //StSch Trace Point
        goto cleanup;
    }
    ret = krb5_ret_data( NAME_OF_MAIN_LOC_GLOB_P, sp,  &creds->ticket );
    if( ret ) { //StSch Trace Point
        goto cleanup;
    }
    ret = krb5_ret_data( NAME_OF_MAIN_LOC_GLOB_P, sp,  &creds->second_ticket );
    cleanup:
    return ret;
}
typedef struct fd_storage {
    int fd;
} fd_storage;
static ssize_t
fd_fetch( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage * sp, void *data, size_t size )
{
#ifdef WITHOUT_FILE
    if( sp->ticket_in && sp->length_ticket_in >= sp->position_ticket_in + size ) {
        char * csp_ticket_in = ( char * )( sp->ticket_in );
        char * cdata         = ( char * )data;
        memcpy( cdata,csp_ticket_in + sp->position_ticket_in,size );
        sp->position_ticket_in = sp->position_ticket_in + size;
        return m_read_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )( FD( sp ) ), data, size );
    } else {
        return 0;
    }
#else
    return m_read_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )( FD( sp ) ), data, size );
#endif
}
static ssize_t
fd_store( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage * sp, const void *data, size_t size )
{
#ifdef WITHOUT_FILE
    if( sp->ticket_out ) {
        sp->ticket_out =
            m_aux_stor_realloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sp->ticket_out,sp->length_ticket_out + size )
            ;
    } else {
        sp->ticket_out =
            m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, size )
            ;
    }
    memcpy((( char * )( sp->ticket_out ) ) + sp->length_ticket_out,data,size );
    sp->length_ticket_out = sp->length_ticket_out + size;
    return m_write_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )( FD( sp ) ), data, size );
#else
    return m_write_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )( FD( sp ) ), data, size );
#endif
}
static off_t
fd_seek( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage * sp, off_t offset, int whence )
{
    return ( off_t ) 0;
}
static void
fd_free( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_storage * sp )
{
    m_close_hl( NAME_OF_MAIN_LOC_GLOB_P, ( int )FD( sp ) );
}
krb5_storage * KRB5_LIB_FUNCTION
krb5_storage_from_fd( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int fd )
{
    krb5_storage *sp;
    if( fd < 0 )
        return NULL;
    sp =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( krb5_storage ) )
        ;
#ifdef WITHOUT_FILE
    sp->ticket_out        = NULL;
    sp->length_ticket_out = 0;
#endif
    if( sp == NULL )
        return NULL;
    sp->data =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sizeof( fd_storage ) )
        ;
    if( sp->data == NULL ) {
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, sp )
        ;
        return NULL;
    }
    sp->flags = 0;
    sp->eof_code = HEIM_ERR_EOF;
    FD( sp ) = fd;
    sp->fetch = fd_fetch;
    sp->store = fd_store;
    sp->seek = fd_seek;
    sp->free = fd_free;
    return sp;
}
void int_to_string( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int im_number,char * ach_buffer )
{
    char chr_tmp[1024];
    int im_counter = 0;
    int im_i;
    if( im_number > 0 ) {
        int im_digit;
        while( im_number > 0 ) {
            im_digit  = im_number % 10;
            switch( im_digit ) {
            case 0 :
                    chr_tmp[im_counter] = '0';
                break;
            case 1 :
                    chr_tmp[im_counter] = '1';
                break;
            case 2 :
                    chr_tmp[im_counter] = '2';
                break;
            case 3 :
                    chr_tmp[im_counter] = '3';
                break;
            case 4 :
                    chr_tmp[im_counter] = '4';
                break;
            case 5 :
                    chr_tmp[im_counter] = '5';
                break;
            case 6 :
                    chr_tmp[im_counter] = '6';
                break;
            case 7 :
                    chr_tmp[im_counter] = '7';
                break;
            case 8 :
                    chr_tmp[im_counter] = '8';
                break;
            case 9 :
                    chr_tmp[im_counter] = '9';
                break;
            default:
                    ach_buffer[0]       = '\0';
                return;
            }
            im_number     = im_number / 10;
            im_counter++;
        }
        for( im_i=im_counter-1; im_i>=0; im_i-- ) {
            ach_buffer[im_counter-1-im_i] = chr_tmp[im_i];
        }
        ach_buffer[im_counter] = '\0';
    } else {
        if( im_number == 0 ) {
            ach_buffer[0] = '0';
            ach_buffer[1] = '\0';
        } else {
            ach_buffer[0] = '-';
            int_to_string( NAME_OF_MAIN_LOC_GLOB_P, im_number*( -1 ),ach_buffer + 1 );
        }
    }
}
char* ROKEN_LIB_FUNCTION
m_strerror_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, int eno )
{
    char error_int[100];
    char * strl_error_string= (char*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ERROR_STRING_LEN);
    *strl_error_string = '\0';
    m_strlcat_hl( NAME_OF_MAIN_LOC_GLOB_P, strl_error_string, "Error occurred: ",sizeof( strl_error_string ) );
    int_to_string( NAME_OF_MAIN_LOC_GLOB_P, eno,error_int );
    m_strlcat_hl( NAME_OF_MAIN_LOC_GLOB_P, strl_error_string, error_int,sizeof( strl_error_string ) );
    return
        strl_error_string;
}
#ifndef HAVE_STRLCAT
size_t ROKEN_LIB_FUNCTION
m_strlcat_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, char *dst, const char *src, size_t dst_sz )
{
    size_t len = strlen( dst );
    if( dst_sz < len )
        /* the total size of dst is less than the string it contains;
               this could be considered bad input, but we might as well
               handle it */
        return len + strlen( src );
    return len + m_strlcpy_hl( NAME_OF_MAIN_LOC_GLOB_P, dst + len, src, dst_sz - len );
}
#endif
#ifndef HAVE_STRLCPY
size_t ROKEN_LIB_FUNCTION
m_strlcpy_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, char *dst, const char *src, size_t dst_sz )
{
    size_t n;
    for( n = 0; n < dst_sz; n++ ) {
        if(( *dst++ = *src++ ) == '\0' )
            break;
    }
    if( n < dst_sz )
        return n;
    if( n > 0 )
        *( dst - 1 ) = '\0';
    return n + strlen( src );
}
#endif
krb5_error_code KRB5_LIB_FUNCTION
krb5_free_ticket( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                  krb5_ticket *ticket )
{
    free_EncTicketPart( NAME_OF_MAIN_LOC_GLOB_P, &ticket->ticket );
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, ticket->client );
    krb5_free_principal( NAME_OF_MAIN_LOC_GLOB_P, context, ticket->server );
    m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ticket )
    ;
    return 0;
}
static int
is_leap( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, unsigned y )
{
    y += 1900;
    return ( y % 4 ) == 0 && (( y % 100 ) != 0 || ( y % 400 ) == 0 );
}
#ifndef HAVE_TIMEGM
time_t
m_timegm_hl( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, struct tm *tm )
{
    static const unsigned ndays[2][12] = {
        {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
        {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
    };
    time_t res = 0;
    unsigned i;
    for( i = 70; i < tm->tm_year; ++i )
        res += is_leap( NAME_OF_MAIN_LOC_GLOB_P, i ) ? 366 : 365;
    for( i = 0; i < tm->tm_mon; ++i )
        res += ndays[is_leap( NAME_OF_MAIN_LOC_GLOB_P, tm->tm_year )][i];
    res += tm->tm_mday - 1;
    res *= 24;
    res += tm->tm_hour;
    res *= 60;
    res += tm->tm_min;
    res *= 60;
    res += tm->tm_sec;
    return res;
}
#endif

#ifndef HOB_KRB5_UNIT_TEST
time_t m_mock_time(time_t* ap_time_ptr)
{
   return time(ap_time_ptr);
}
#endif
/*
 * return ``corrected'' time in `timeret'.
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_timeofday( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                krb5_timestamp *timeret )
{
    *timeret = m_mock_time( NULL ) + context->kdc_sec_offset;
    //StSch Trace Point Always
    return 0;
}
/*
 * like m_gettimeofday_hl but with time correction to the KDC
 */
krb5_error_code KRB5_LIB_FUNCTION
krb5_us_timeofday( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
                   krb5_timestamp *sec,
                   int32_t *usec )
{
    struct timeval tv;
    m_gettimeofday_hl( NAME_OF_MAIN_LOC_GLOB_P, &tv, NULL );
    *sec  = tv.tv_sec + context->kdc_sec_offset;
    *usec = tv.tv_usec;
    return 0;
}
static OM_uint32
unwrap_des3
( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 * minor_status,
  const gss_ctx_id_t context_handle,
  const gss_buffer_t input_message_buffer,
  gss_buffer_t output_message_buffer,
  int * conf_state,
  gss_qop_t * qop_state,
  krb5_keyblock *key
)
{
    u_char *p;
    size_t len;
    u_char *seq;
    krb5_data seq_data;
    u_char cksum[20];
    int32_t seq_number;
    size_t padlength;
    OM_uint32 ret;
    int cstate;
    krb5_crypto crypto;
    Checksum csum;
    int cmp;
    p = input_message_buffer->value;
    ret = gssapi_krb5_verify_header( NAME_OF_MAIN_LOC_GLOB_P, &p,
                                     input_message_buffer->length,
                                     "\x02\x01", ( &(	NAME_OF_MAIN_LOC_GLOB_P->
                                             gssapi_krb5_context->gss_krb5_mechanism_oid_ ) ) );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    if( memcmp( p, "\x04\x00", 2 ) != 0 )
        return GSS_S_BAD_SIG;
    p += 2;
    if( memcmp( p, "\x02\x00", 2 ) == 0 ) {
        cstate = 1;
    } else if( memcmp( p, "\xff\xff", 2 ) == 0 ) {
        cstate = 0;
    } else
        return GSS_S_BAD_MIC;
    p += 2;
    if( conf_state != NULL )
        *conf_state = cstate;
    if( memcmp( p, "\xff\xff", 2 ) != 0 )
        return GSS_S_DEFECTIVE_TOKEN;
    p += 2;
    p += 28;
    len = p - ( u_char * )input_message_buffer->value;
    if( cstate ) {
        krb5_data tmp;
        ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P,                             NAME_OF_MAIN_LOC_GLOB_P->
                                gssapi_krb5_context, key,
                                ETYPE_DES3_CBC_NONE, &crypto );
        if( ret ) {
            //StSch Trace Point
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            *minor_status = ret;
            return GSS_S_FAILURE;
        }
        ret = krb5_decrypt( NAME_OF_MAIN_LOC_GLOB_P,                         NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, crypto, KRB5_KU_USAGE_SEAL,
                            p, input_message_buffer->length - len, &tmp );
        krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P,                          NAME_OF_MAIN_LOC_GLOB_P->
                             gssapi_krb5_context, crypto );
        if( ret ) {
            //StSch Trace Point
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            *minor_status = ret;
            return GSS_S_FAILURE;
        }
        if( !( tmp.length == input_message_buffer->length - len ) ) {
            //StSch Trace Point
            m_end_exit_abort_hl( NAME_OF_MAIN_LOC_GLOB_P, 'a',0 );
        }
        memcpy( p, tmp.data, tmp.length );
        krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &tmp );
    }
    ret = _gssapi_verify_pad( NAME_OF_MAIN_LOC_GLOB_P, input_message_buffer,
                              input_message_buffer->length - len,
                              &padlength );
    if( ret ) {
        //StSch Trace Point
        return ret;
    }
    p -= 28;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P,                         NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, key,
                            ETYPE_DES3_CBC_NONE, &crypto );
    if( ret ) {
        //StSch Trace Point
        gssapi_krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    {
        DES_cblock ivec;
        memcpy( &ivec, p + 8, 8 );
        ret = krb5_decrypt_ivec( NAME_OF_MAIN_LOC_GLOB_P,                               NAME_OF_MAIN_LOC_GLOB_P->
                                 gssapi_krb5_context,
                                 crypto,
                                 KRB5_KU_USAGE_SEQ,
                                 p, 8, &seq_data,
                                 &ivec );
    }
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P,                       NAME_OF_MAIN_LOC_GLOB_P->
                         gssapi_krb5_context, crypto );
    if( ret ) {
        //StSch Trace Point
        gssapi_krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    if( seq_data.length != 8 ) {
        krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &seq_data );
        *minor_status = 0;
        return GSS_S_BAD_MIC;
    }
    seq = seq_data.data;
    gssapi_decode_om_uint32( NAME_OF_MAIN_LOC_GLOB_P, seq, &seq_number );
    if( context_handle->more_flags & LOCAL )
        cmp = memcmp( &seq[4], "\xff\xff\xff\xff", 4 );
    else
        cmp = memcmp( &seq[4], "\x00\x00\x00\x00", 4 );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &seq_data );
    if( cmp != 0 ) {
        *minor_status = 0;
        return GSS_S_BAD_MIC;
    }
    ret = _gssapi_msg_order_check( NAME_OF_MAIN_LOC_GLOB_P, context_handle->order, seq_number );
    if( ret ) {
        //StSch Trace Point
        *minor_status = 0;
        return ret;
    }
    memcpy( cksum, p + 8, 20 );
    memcpy( p + 20, p - 8, 8 );
    csum.cksumtype = CKSUMTYPE_HMAC_SHA1_DES3;
    csum.checksum.length = 20;
    csum.checksum.data   = cksum;
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P,                         NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        gssapi_krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    ret = krb5_verify_checksum( NAME_OF_MAIN_LOC_GLOB_P,                              NAME_OF_MAIN_LOC_GLOB_P->
                                gssapi_krb5_context, crypto,
                                KRB5_KU_USAGE_SIGN,
                                p + 20,
                                input_message_buffer->length - len + 8,
                                &csum );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P,                       NAME_OF_MAIN_LOC_GLOB_P->
                         gssapi_krb5_context, crypto );
    if( ret ) {
        //StSch Trace Point
        gssapi_krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    output_message_buffer->length = input_message_buffer->length
                                    - len - padlength - 8;
    output_message_buffer->value  =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, output_message_buffer->length )
        ;
    if( output_message_buffer->length != 0 && output_message_buffer->value == NULL )
        return GSS_S_FAILURE;
    memcpy( output_message_buffer->value,
            p + 36,
            output_message_buffer->length );
    return GSS_S_COMPLETE;
}
OM_uint32 gss_unwrap
( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 * minor_status,
  const gss_ctx_id_t context_handle,
  const gss_buffer_t input_message_buffer,
  gss_buffer_t output_message_buffer,
  int * conf_state,
  gss_qop_t * qop_state
)
{
    krb5_keyblock *key;
    OM_uint32 ret;
    krb5_keytype keytype;
    output_message_buffer->value = NULL;
    output_message_buffer->length = 0;
    if( qop_state != NULL )
        *qop_state = GSS_C_QOP_DEFAULT;
    ret = gss_krb5_get_subkey( NAME_OF_MAIN_LOC_GLOB_P, context_handle, &key );
    if( ret ) {
        //StSch Trace Point
        gssapi_krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    krb5_enctype_to_keytype( NAME_OF_MAIN_LOC_GLOB_P,                           NAME_OF_MAIN_LOC_GLOB_P->
                             gssapi_krb5_context, key->keytype, &keytype );
    *minor_status = 0;
    //StSch Trace Point 6008
    if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
        void * a_temp_memory;
        struct dsd_memory_traces* adsl_trace;
        char* achl_trace_format="etype:%i";
        void* a_key_hash;
        m_aux_stor_start( &a_temp_memory );
        a_key_hash=m_aux_stor_alloc( &a_temp_memory,20 );
        adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
        m_krb5_sha1( key->keyvalue.data,key->keyvalue.length,a_key_hash, &a_temp_memory );
        m_krb5_trace_memcat( &a_temp_memory, adsl_trace,a_key_hash,20,"K-Hash:" );
        m_krb5_trace_memcat( &a_temp_memory, adsl_trace,input_message_buffer->value,16,"GSS Header:" );
        m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',6008,
                     adsl_trace, &a_temp_memory, achl_trace_format, key->keytype );
        m_aux_stor_end( &a_temp_memory );
    }
    switch( keytype ) {
    case KEYTYPE_DES3 :
            ret = unwrap_des3( NAME_OF_MAIN_LOC_GLOB_P, minor_status, context_handle,
                               input_message_buffer, output_message_buffer,
                               conf_state, qop_state, key );
        break;
    case KEYTYPE_ARCFOUR:
        case KEYTYPE_ARCFOUR_56:
                ret = _gssapi_unwrap_arcfour( NAME_OF_MAIN_LOC_GLOB_P, minor_status, context_handle,
                                              input_message_buffer, output_message_buffer,
                                              conf_state, qop_state, key );
        break;
    default :
            ret = _gssapi_unwrap_cfx( NAME_OF_MAIN_LOC_GLOB_P, minor_status, context_handle,
                                      input_message_buffer, output_message_buffer,
                                      conf_state, qop_state, key );
        break;
    }
    krb5_free_keyblock( NAME_OF_MAIN_LOC_GLOB_P,                      NAME_OF_MAIN_LOC_GLOB_P->
                        gssapi_krb5_context, key );
    return ret;
}
static krb5_error_code
_warnerr( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, int do_errtext,
          krb5_error_code code, int level, const char *fmt )
{
    const char *args[2] = {NULL,NULL};
    const char **arg;
    char *msg = NULL;
    char *err_str = NULL;
    arg = args;
    if( fmt ) {
        msg = ( char* )
              memset( m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, ( strlen( fmt )+1 ) * ( sizeof( char ) ) ),'\0',( strlen( fmt )+1 ) * ( sizeof( char ) ) )
              ;
        if( msg == NULL )
            return ENOMEM;
        else
            memcpy( msg,fmt,strlen( fmt )+1 );
        *arg++ = msg;
    }
    if( context && do_errtext ) {
        const char *err_msg;
        err_str = krb5_get_error_string( NAME_OF_MAIN_LOC_GLOB_P, context );
        if( err_str != NULL ) {
            *arg++ = err_str;
        } else {
            err_msg = krb5_get_err_text( NAME_OF_MAIN_LOC_GLOB_P, context, code );
            if( err_msg )
                *arg++ = err_msg;
            else
                *arg++ = "<unknown error>";
        }
    }
    NAME_OF_MAIN_LOC_GLOB_P->im_re_error_code = code;
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_err( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, int eval, krb5_error_code code,
          const char *fmt )
{
    _warnerr( NAME_OF_MAIN_LOC_GLOB_P, context, 1, code, 0, fmt );
    m_end_exit_abort_hl( NAME_OF_MAIN_LOC_GLOB_P, 'x',eval )
    ;
}


krb5_error_code KRB5_LIB_FUNCTION
krb5_abortx( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context, const char *fmt )
{
    _warnerr( NAME_OF_MAIN_LOC_GLOB_P, context, 0, 1, 0, fmt );
    //StSch Trace Point
    m_end_exit_abort_hl( NAME_OF_MAIN_LOC_GLOB_P, 'a',0 )
    ;
}
OM_uint32
gss_krb5_get_subkey( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const gss_ctx_id_t context_handle,
                     krb5_keyblock **key )
{
    krb5_keyblock *skey = NULL;
    if( context_handle->more_flags & LOCAL ) {
        krb5_auth_con_getremotesubkey(	NAME_OF_MAIN_LOC_GLOB_P,                              	NAME_OF_MAIN_LOC_GLOB_P->
                                        gssapi_krb5_context,
                                        context_handle->auth_context,
                                        &skey );
    } else {
        krb5_auth_con_getlocalsubkey(	NAME_OF_MAIN_LOC_GLOB_P,                             	NAME_OF_MAIN_LOC_GLOB_P->
                                        gssapi_krb5_context,
                                        context_handle->auth_context,
                                        &skey );
    }
    /*
     * Only use the initiator subkey or ticket session key if
     * an acceptor subkey was not required.
     */
    if( skey == NULL &&
            ( context_handle->more_flags & ACCEPTOR_SUBKEY ) == 0 ) {
        if( context_handle->more_flags & LOCAL ) {
            krb5_auth_con_getlocalsubkey(	NAME_OF_MAIN_LOC_GLOB_P,                                 	NAME_OF_MAIN_LOC_GLOB_P->
                                            gssapi_krb5_context,
                                            context_handle->auth_context,
                                            &skey );
        } else {
            krb5_auth_con_getremotesubkey(	NAME_OF_MAIN_LOC_GLOB_P,                                  	NAME_OF_MAIN_LOC_GLOB_P->
                                            gssapi_krb5_context,
                                            context_handle->auth_context,
                                            &skey );
        }
        if( skey == NULL )
            krb5_auth_con_getkey(	NAME_OF_MAIN_LOC_GLOB_P,                         	NAME_OF_MAIN_LOC_GLOB_P->
                                    gssapi_krb5_context,
                                    context_handle->auth_context,
                                    &skey );
    }
    if( skey == NULL )
        return GSS_KRB5_S_KG_NO_SUBKEY;
    *key = skey;
    return 0;
}
static OM_uint32
wrap_des3
( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 * minor_status,
  const gss_ctx_id_t context_handle,
  int conf_req_flag,
  gss_qop_t qop_req,
  const gss_buffer_t input_message_buffer,
  int * conf_state,
  gss_buffer_t output_message_buffer,
  krb5_keyblock *key
)
{
    u_char *p;
    u_char seq[8];
    int32_t seq_number;
    size_t len, total_len, padlength, datalen;
    u_int32_t ret;
    krb5_crypto crypto;
    Checksum cksum;
    krb5_data encdata;
    padlength = 8 - ( input_message_buffer->length % 8 );
    datalen = input_message_buffer->length + padlength + 8;
    len = datalen + 34;
    gssapi_krb5_encap_length( NAME_OF_MAIN_LOC_GLOB_P, len, &len, &total_len, ( &( NAME_OF_MAIN_LOC_GLOB_P->
                              gssapi_krb5_context->gss_krb5_mechanism_oid_ ) ) );
    output_message_buffer->length = total_len;
    output_message_buffer->value  =
        m_aux_stor_alloc( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, total_len )
        ;
    if( output_message_buffer->value == NULL ) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    p = gssapi_krb5_make_header( NAME_OF_MAIN_LOC_GLOB_P, output_message_buffer->value,
                                 len,
                                 "\x02\x01", ( &(	NAME_OF_MAIN_LOC_GLOB_P->
                                         gssapi_krb5_context->gss_krb5_mechanism_oid_ ) ) );
    memcpy( p, "\x04\x00", 2 );
    p += 2;
    if( conf_req_flag )
        memcpy( p, "\x02\x00", 2 );
    else
        memcpy( p, "\xff\xff", 2 );
    p += 2;
    memcpy( p, "\xff\xff", 2 );
    p += 2;
    memcpy( p + 20, p - 8, 8 );
    krb5_generate_random_block( NAME_OF_MAIN_LOC_GLOB_P, p + 28, 8 );
    memcpy( p + 28 + 8, input_message_buffer->value,
            input_message_buffer->length );
    memset( p + 28 + 8 + input_message_buffer->length, padlength, padlength );
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P,                         NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, key, 0, &crypto );
    if( ret ) {
        //StSch Trace Point
        gssapi_krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, output_message_buffer->value )
        ;
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    ret = krb5_create_checksum( NAME_OF_MAIN_LOC_GLOB_P,                              NAME_OF_MAIN_LOC_GLOB_P->
                                gssapi_krb5_context,
                                crypto,
                                KRB5_KU_USAGE_SIGN,
                                0,
                                p + 20,
                                datalen + 8,
                                &cksum );
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P,                       NAME_OF_MAIN_LOC_GLOB_P->
                         gssapi_krb5_context, crypto );
    if( ret ) {
        //StSch Trace Point
        gssapi_krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, output_message_buffer->value )
        ;
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    memset( p, 0, 28 );
    memcpy( p + 8, cksum.checksum.data, cksum.checksum.length );
    free_Checksum( NAME_OF_MAIN_LOC_GLOB_P, &cksum );
    krb5_auth_con_getlocalseqnumber( NAME_OF_MAIN_LOC_GLOB_P,                                   NAME_OF_MAIN_LOC_GLOB_P->
                                     gssapi_krb5_context,
                                     context_handle->auth_context,
                                     &seq_number );
    seq[0] = ( seq_number >> 0 )  & 0xFF;
    seq[1] = ( seq_number >> 8 )  & 0xFF;
    seq[2] = ( seq_number >> 16 ) & 0xFF;
    seq[3] = ( seq_number >> 24 ) & 0xFF;
    memset( seq + 4,
            ( context_handle->more_flags & LOCAL ) ? 0 : 0xFF,
            4 );
    ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P,                         NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, key, ETYPE_DES3_CBC_NONE,
                            &crypto );
    if( ret ) {
        //StSch Trace Point
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, output_message_buffer->value )
        ;
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    {
        DES_cblock ivec;
        memcpy( &ivec, p + 8, 8 );
        ret = krb5_encrypt_ivec( NAME_OF_MAIN_LOC_GLOB_P,                               NAME_OF_MAIN_LOC_GLOB_P->
                                 gssapi_krb5_context,
                                 crypto,
                                 KRB5_KU_USAGE_SEQ,
                                 seq, 8, &encdata,
                                 &ivec );
    }
    krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P,                       NAME_OF_MAIN_LOC_GLOB_P->
                         gssapi_krb5_context, crypto );
    if( ret ) {
        //StSch Trace Point
        gssapi_krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P );
        m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, output_message_buffer->value )
        ;
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    if( !( encdata.length == 8 ) ) {
        //StSch Trace Point
        m_end_exit_abort_hl( NAME_OF_MAIN_LOC_GLOB_P, 'a',0 );
    }
    memcpy( p, encdata.data, encdata.length );
    krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &encdata );
    krb5_auth_con_setlocalseqnumber( NAME_OF_MAIN_LOC_GLOB_P,                                   NAME_OF_MAIN_LOC_GLOB_P->
                                     gssapi_krb5_context,
                                     context_handle->auth_context,
                                     ++seq_number );
    p += 28;
    if( conf_req_flag ) {
        krb5_data tmp;
        ret = krb5_crypto_init( NAME_OF_MAIN_LOC_GLOB_P,                             NAME_OF_MAIN_LOC_GLOB_P->
                                gssapi_krb5_context, key,
                                ETYPE_DES3_CBC_NONE, &crypto );
        if( ret ) {
            //StSch Trace Point
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, output_message_buffer->value )
            ;
            *minor_status = ret;
            return GSS_S_FAILURE;
        }
        ret = krb5_encrypt( NAME_OF_MAIN_LOC_GLOB_P,                         NAME_OF_MAIN_LOC_GLOB_P->
                            gssapi_krb5_context, crypto, KRB5_KU_USAGE_SEAL,
                            p, datalen, &tmp );
        krb5_crypto_destroy( NAME_OF_MAIN_LOC_GLOB_P,                          NAME_OF_MAIN_LOC_GLOB_P->
                             gssapi_krb5_context, crypto );
        if( ret ) {
            //StSch Trace Point
            gssapi_krb5_set_error_string(	NAME_OF_MAIN_LOC_GLOB_P );
            m_aux_stor_free( NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, output_message_buffer->value )
            ;
            *minor_status = ret;
            return GSS_S_FAILURE;
        }
        if( !( tmp.length == datalen ) ) {
            //StSch Trace Point
            m_end_exit_abort_hl( NAME_OF_MAIN_LOC_GLOB_P, 'a',0 );
        }
        memcpy( p, tmp.data, datalen );
        krb5_data_free( NAME_OF_MAIN_LOC_GLOB_P, &tmp );
    }
    if( conf_state != NULL )
        *conf_state = conf_req_flag;
    *minor_status = 0;
    return GSS_S_COMPLETE;
}
OM_uint32 gss_wrap
( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, OM_uint32 * minor_status,
  const gss_ctx_id_t context_handle,
  int conf_req_flag,
  gss_qop_t qop_req,
  const gss_buffer_t input_message_buffer,
  int * conf_state,
  gss_buffer_t output_message_buffer
)
{
    krb5_keyblock *key;
    OM_uint32 ret;
    krb5_keytype keytype;
    ret = gss_krb5_get_subkey( NAME_OF_MAIN_LOC_GLOB_P, context_handle, &key );
    if( ret ) {
        //StSch Trace Point
        gssapi_krb5_set_error_string( NAME_OF_MAIN_LOC_GLOB_P );
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    krb5_enctype_to_keytype( NAME_OF_MAIN_LOC_GLOB_P,                           NAME_OF_MAIN_LOC_GLOB_P->
                             gssapi_krb5_context, key->keytype, &keytype );
    //StSch Trace Point 6009
    if( NAME_OF_MAIN_LOC_GLOB_P->in_trace_lvl>=2 ) {
        void * a_temp_memory;
        struct dsd_memory_traces* adsl_trace;
        char* achl_trace_format="etype:%i";
        void* a_key_hash;
        m_aux_stor_start( &a_temp_memory );
        a_key_hash=m_aux_stor_alloc( &a_temp_memory,20 );
        adsl_trace=m_init_krb5_mem_trace( &a_temp_memory );
        m_krb5_sha1( key->keyvalue.data,key->keyvalue.length,a_key_hash, &a_temp_memory );
        m_krb5_trace_memcat( &a_temp_memory, adsl_trace,a_key_hash,20,"K-Hash:" );
        m_krb5_trace(( struct krb5_tracer* )( NAME_OF_MAIN_LOC_GLOB_P->a_tracer ),'T',6009,
                     adsl_trace, &a_temp_memory, achl_trace_format, key->keytype );
        m_aux_stor_end( &a_temp_memory );
    }
    switch( keytype ) {
    case KEYTYPE_DES3 :
            ret = wrap_des3( NAME_OF_MAIN_LOC_GLOB_P, minor_status, context_handle, conf_req_flag,
                             qop_req, input_message_buffer, conf_state,
                             output_message_buffer, key );
        break;
    case KEYTYPE_ARCFOUR:
        case KEYTYPE_ARCFOUR_56:
                ret = _gssapi_wrap_arcfour( NAME_OF_MAIN_LOC_GLOB_P, minor_status, context_handle, conf_req_flag,
                                            qop_req, input_message_buffer, conf_state,
                                            output_message_buffer, key );
        break;
    default :
            ret = _gssapi_wrap_cfx( NAME_OF_MAIN_LOC_GLOB_P, minor_status, context_handle, conf_req_flag,
                                    qop_req, input_message_buffer, conf_state,
                                    output_message_buffer, key );
        break;
    }
    krb5_free_keyblock( NAME_OF_MAIN_LOC_GLOB_P,                      NAME_OF_MAIN_LOC_GLOB_P->
                        gssapi_krb5_context, key );
    return ret;
}

void KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_preauth_list(krb5_get_init_creds_opt *opt,
					 krb5_preauthtype *preauth_list,
					 int preauth_list_length)
{
    opt->flags |= KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST;
    opt->preauth_list_length = preauth_list_length;
    opt->preauth_list = preauth_list;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_auth_con_setflags(krb5_context context,
		       krb5_auth_context auth_context,
		       int32_t flags)
{
    auth_context->flags = flags;
    return 0;
}

krb5_error_code
change_password (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
         krb5_context context,
		 krb5_principal client,
		 const char *password,
		 char *newpw,
		 size_t newpw_sz,
		 int inp_kdc_change_pw_port,
		 void *data,
		 krb5_get_init_creds_opt *old_options)
{
    /* no frees are called, the Memory Container is discarded right after this function */
    krb5_error_code ret;
    krb5_creds cpw_cred;
    int result_code;
    krb5_data result_code_string;
    krb5_data result_string;
    char *p;
    krb5_get_init_creds_opt options;

    memset (&cpw_cred, 0, sizeof(cpw_cred));

    krb5_get_init_creds_opt_init (NAME_OF_MAIN_LOC_GLOB_P, &options);
    krb5_get_init_creds_opt_set_tkt_life (NAME_OF_MAIN_LOC_GLOB_P, &options, 60);
    krb5_get_init_creds_opt_set_forwardable (NAME_OF_MAIN_LOC_GLOB_P, &options, FALSE);
    krb5_get_init_creds_opt_set_proxiable (NAME_OF_MAIN_LOC_GLOB_P, &options, FALSE);
    if (old_options && old_options->flags & KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST)
	krb5_get_init_creds_opt_set_preauth_list (&options,
						  old_options->preauth_list,
						  old_options->preauth_list_length);					
	krb5_get_init_creds_opt_set_etype_list(NAME_OF_MAIN_LOC_GLOB_P, &options,
	                      old_options->etype_list,
	                      old_options->etype_list_length);
    krb5_data_zero (NAME_OF_MAIN_LOC_GLOB_P, &result_code_string);
    krb5_data_zero (NAME_OF_MAIN_LOC_GLOB_P, &result_string);

    ret = krb5_get_init_creds_password (NAME_OF_MAIN_LOC_GLOB_P,
                    context,
					&cpw_cred,
					client,
					password,
					NULL,
					data,
					0,
					"kadmin/changepw",
					&options);
    if (ret)
	goto out;

    context->kdc_port=inp_kdc_change_pw_port;
    ret = krb5_change_password (NAME_OF_MAIN_LOC_GLOB_P, context,
				&cpw_cred,
				newpw,
				&result_code,
				&result_code_string,
				&result_string);
    if (ret)
	goto out;
    if (result_code == 0) {
	ret = 0;
    } else {
	krb5_set_error_string (NAME_OF_MAIN_LOC_GLOB_P, context, "failed changing password","xs-gw-krb5-lib.c");
	ret = ENOTTY;
    }

out:
    return ret;
}

/*
 *  changepw.c
 *  No frees are called, since change password is using only short-lived memory in a memory container, which is freed after the exchange
 */

static void
str2data (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data *d,
	  const char *fmt,
	  ...);

static void
str2data (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_data *d,
	  const char *fmt,
	  ...)
{
    va_list args;

    va_start(args, fmt);
    d->length = strlen(fmt);
    d->data=m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, d->length);
    memcpy(d->data, fmt, d->length);
    va_end(args);
}
/*
 * Change password protocol defined by
 * draft-ietf-cat-kerb-chg-password-02.txt
 *
 * Share the response part of the protocol with MS set password
 * (RFC3244)
 */

static krb5_error_code
chgpw_send_request (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
            krb5_context context,
		    krb5_auth_context *auth_context,
		    krb5_creds *creds,
		    krb5_principal targprinc,
		    int is_stream,
		    struct dsd_tcpsync_1 * sock,
		    krb5_data *reply_buffer,
			char *passwd,
		    const char *host)
{
    krb5_error_code ret;
    krb5_data ap_req_data;
    krb5_data krb_priv_data;
    krb5_data passwd_data;
    krb5_data *send_data;
    size_t len;
    u_char header[6];
    u_char *p;

    if (is_stream)
	return KRB5_KPASSWD_MALFORMED;

    if (targprinc &&
	krb5_principal_compare(NAME_OF_MAIN_LOC_GLOB_P, context, creds->client, targprinc) != TRUE)
	return KRB5_KPASSWD_MALFORMED;

    krb5_data_zero (NAME_OF_MAIN_LOC_GLOB_P, &ap_req_data);

    ret = krb5_mk_req_extended (NAME_OF_MAIN_LOC_GLOB_P, context,
				auth_context,
				AP_OPTS_MUTUAL_REQUIRED | AP_OPTS_USE_SUBKEY,
				NULL, /* in_data */
				creds,
				&ap_req_data);
    if (ret)
	return ret;

    passwd_data.data   = passwd;
    passwd_data.length = strlen(passwd);

    krb5_data_zero (NAME_OF_MAIN_LOC_GLOB_P, &krb_priv_data);

    ret = krb5_mk_priv (NAME_OF_MAIN_LOC_GLOB_P, context,
			*auth_context,
			&passwd_data,
			&krb_priv_data,
			NULL);
    if (ret)
	goto out2;

    len = 6 + ap_req_data.length + krb_priv_data.length;
    p = header;
    *p++ = (len >> 8) & 0xFF;
    *p++ = (len >> 0) & 0xFF;
    *p++ = 0;
    *p++ = 1;
    *p++ = (ap_req_data.length >> 8) & 0xFF;
    *p++ = (ap_req_data.length >> 0) & 0xFF;

    send_data=(krb5_data*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,sizeof(krb5_data));
    send_data->data=m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,len);
    send_data->length=len;
    memcpy(send_data->data,header,6);
    memcpy(((char*)send_data->data)+6,ap_req_data.data,ap_req_data.length);
    memcpy(((char*)send_data->data)+6+ap_req_data.length,krb_priv_data.data,krb_priv_data.length);

    ret = send_and_recv_tcp( NAME_OF_MAIN_LOC_GLOB_P, context, sock, context->kdc_timeout,
            send_data, reply_buffer );
        NAME_OF_MAIN_LOC_GLOB_P->a_generic_obj = ( void* )0;

out2:
    return ret;
}

static krb5_error_code
process_reply (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context context,
	       krb5_auth_context auth_context,
	       int is_stream,
	       struct dsd_tcpsync_1 * sock,
	       krb5_data *reply_buffer,
	       int *result_code,
	       krb5_data *result_code_string,
	       krb5_data *result_string,
	       const char *host)
{
    krb5_error_code ret;
    u_char *reply;
    ssize_t len;
    u_int16_t pkt_len, pkt_ver;
    krb5_data ap_rep_data;
    int save_errno;

    len = reply_buffer->length;
    reply=(u_char*)(reply_buffer->data);

    if (len < 6) {
        str2data (NAME_OF_MAIN_LOC_GLOB_P, result_string, "server %s sent to too short message "
            "(%ld bytes)", host, (long)len);
        *result_code = KRB5_KPASSWD_MALFORMED;
        return 0;
    }

    pkt_len = (reply[0] << 8) | (reply[1]);
    pkt_ver = (reply[2] << 8) | (reply[3]);

    if ((pkt_len != len) || (reply[1] == 0x7e || reply[1] == 0x5e)) {
        KRB_ERROR error;
        size_t size;
        u_char *p;

        memset(&error, 0, sizeof(error));

        ret = decode_KRB_ERROR(NAME_OF_MAIN_LOC_GLOB_P, reply, len, &error, &size);
        if (ret)
            return ret;

        if (error.e_data->length < 2) {
            str2data(NAME_OF_MAIN_LOC_GLOB_P, result_string, "server %s sent too short "
                "e_data to print anything usable", host);
            *result_code = KRB5_KPASSWD_MALFORMED;
            return 0;
        }

        p = error.e_data->data;
        *result_code = (p[0] << 8) | p[1];
        if (error.e_data->length == 2)
            str2data(NAME_OF_MAIN_LOC_GLOB_P, result_string, "server only sent error code");
        else
            krb5_data_copy (NAME_OF_MAIN_LOC_GLOB_P, result_string,
            p + 2,
            error.e_data->length - 2);
        return 0;
    }

    if (pkt_len != len) {
        str2data (NAME_OF_MAIN_LOC_GLOB_P, result_string, "client: wrong len in reply");
        *result_code = KRB5_KPASSWD_MALFORMED;
        return 0;
    }
    if (pkt_ver != KRB5_KPASSWD_VERS_CHANGEPW) {
        str2data (NAME_OF_MAIN_LOC_GLOB_P, result_string,
            "client: wrong version number (%d)", pkt_ver);
        *result_code = KRB5_KPASSWD_MALFORMED;
        return 0;
    }

    ap_rep_data.data = reply + 6;
    ap_rep_data.length  = (reply[4] << 8) | (reply[5]);

    if (reply + len < (u_char *)ap_rep_data.data + ap_rep_data.length) {
        str2data (NAME_OF_MAIN_LOC_GLOB_P, result_string, "client: wrong AP len in reply");
        *result_code = KRB5_KPASSWD_MALFORMED;
        return 0;
    }

    if (ap_rep_data.length) {
        krb5_ap_rep_enc_part *ap_rep;
        krb5_data priv_data;
        u_char *p;

        priv_data.data   = (u_char*)ap_rep_data.data + ap_rep_data.length;
        priv_data.length = len - ap_rep_data.length - 6;

        ret = krb5_rd_rep (NAME_OF_MAIN_LOC_GLOB_P,
            context,
            auth_context,
            &ap_rep_data,
            &ap_rep);
        if (ret)
            return ret;

        ret = krb5_rd_priv (NAME_OF_MAIN_LOC_GLOB_P,
            context,
            auth_context,
            &priv_data,
            result_code_string,
            NULL);
        if (ret) {
            return ret;
        }

        if (result_code_string->length < 2) {
            *result_code = KRB5_KPASSWD_MALFORMED;
            str2data (NAME_OF_MAIN_LOC_GLOB_P, result_string,
                "client: bad length in result");
            return 0;
        }

        p = result_code_string->data;

        *result_code = (p[0] << 8) | p[1];
        krb5_data_copy (NAME_OF_MAIN_LOC_GLOB_P, result_string,
            (unsigned char*)result_code_string->data + 2,
            result_code_string->length - 2);
        return 0;
    } else {
        KRB_ERROR error;
        size_t size;
        u_char *p;

        ret = decode_KRB_ERROR(NAME_OF_MAIN_LOC_GLOB_P, reply + 6, len - 6, &error, &size);
        if (ret) {
            return ret;
        }
        if (error.e_data->length < 2) {
            return 1;		/* XXX */
        }

        p = error.e_data->data;
        *result_code = (p[0] << 8) | p[1];
        krb5_data_copy (NAME_OF_MAIN_LOC_GLOB_P, result_string,
            p + 2,
            error.e_data->length - 2);
        return 0;
    }
}


/*
 * change the password using the credentials in `creds' (for the
 * principal indicated in them) to `newpw', storing the result of
 * the operation in `result_*' and an error code or 0.
 */

typedef krb5_error_code (*kpwd_send_request) (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context,
					      krb5_auth_context *,
					      krb5_creds *,
					      krb5_principal,
					      int,
					      struct dsd_tcpsync_1 *,
					      krb5_data *,
					      char *,
					      const char *);
typedef krb5_error_code (*kpwd_process_reply) (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context,
					       krb5_auth_context,
					       int,
					       struct dsd_tcpsync_1 *,
					       krb5_data *,
					       int *,
					       krb5_data *,
					       krb5_data *,
					       const char *);

static struct kpwd_proc {
    const char *name;
    int flags;
#define SUPPORT_TCP	1
#define SUPPORT_UDP	2
    kpwd_send_request send_req;
    kpwd_process_reply process_rep;
} procs[] = {
    {
	"change password",
	SUPPORT_UDP,
	chgpw_send_request,
	process_reply
    },
    { NULL }
};

static struct kpwd_proc *
find_chpw_proto(const char *name)
{
    struct kpwd_proc *p;
    for (p = procs; p->name != NULL; p++) {
	if (strcmp(p->name, name) == 0)
	    return p;
    }
    return NULL;
}

/*
 *
 */

static krb5_error_code
change_password_loop (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context	context,
                      krb5_creds	*creds,
                      krb5_principal	targprinc,
                      char		*newpw,
                      int		*result_code,
                      krb5_data		*result_code_string,
                      krb5_data		*result_string,
struct kpwd_proc	*proc)
{
    krb5_error_code ret;
    krb5_auth_context auth_context = NULL;
    int sock;
    int i;
    int done = 0;
    krb5_realm realm = creds->client->realm;
    krb5_address dsl_local_addr;
    struct sockaddr* adsl_local_address = m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,sizeof(struct sockaddr_in6));
    int inl_addr_len = sizeof(struct sockaddr_in6);

    BOOL     bol1;
    int      iml_w1;
    int      iml_error;
    struct dsd_tcpsync_1 dsl_tcpsync_1;
    krb5_data *reply_buffer;
    int replied = 0;
    reply_buffer=(krb5_data*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,sizeof(krb5_data));
    ret = krb5_auth_con_init (NAME_OF_MAIN_LOC_GLOB_P, context, &auth_context);
    if (ret)
        return ret;

    krb5_auth_con_setflags (context, auth_context,
        KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    auth_context->local_address = &dsl_local_addr;
    bol1 = m_tcpsync_connect( &iml_error, &dsl_tcpsync_1,
        &ADSL_KRB5_KDC_SERVER->dsc_bind_multih,
        ADSL_KRB5_KDC_SERVER->adsc_server_ineta,
        context->kdc_port );
    /* Read the host address (required!) */
    if(!getsockname(dsl_tcpsync_1.imc_socket, adsl_local_address,&inl_addr_len)){
       if(adsl_local_address->sa_family == AF_INET) {
          dsl_local_addr.addr_type = KRB5_ADDRESS_INET;
          dsl_local_addr.address.length = 4;
          dsl_local_addr.address.data = m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, 4);
          memcpy(dsl_local_addr.address.data, &((struct sockaddr_in*)adsl_local_address)->sin_addr,4);
       } else if(adsl_local_address->sa_family == AF_INET6) {
          dsl_local_addr.addr_type = KRB5_ADDRESS_INET6;
          dsl_local_addr.address.length = 16;
          dsl_local_addr.address.data = m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, 16);
          memcpy(dsl_local_addr.address.data, &((struct sockaddr_in6*)adsl_local_address)->sin6_addr,16);
       } else {
          bol1 = FALSE;
       }
    } else {
       bol1 = FALSE;
    }
    if( bol1 ) {
        NAME_OF_MAIN_LOC_GLOB_P->a_generic_obj = &context->kdc_timeout;
        if (!replied) {
            replied = 0;
            ret = (*proc->send_req) (NAME_OF_MAIN_LOC_GLOB_P, context,
                &auth_context,
                creds,
                targprinc,
                0,
                &dsl_tcpsync_1,
                reply_buffer,
                newpw,
                "WSP PW Change");
            iml_w1 = m_tcpsync_close( &iml_error, &dsl_tcpsync_1 );
            if (ret || iml_w1!=0) {
                ret = KRB5_KDC_UNREACH;
                goto out;
            }
        }

        ret = (*proc->process_rep) (NAME_OF_MAIN_LOC_GLOB_P, context,
            auth_context,
            0,
            &dsl_tcpsync_1,
            reply_buffer,
            result_code,
            result_code_string,
            result_string,
            "WSP PW Change");
    } else {
        ret = KRB5_KDC_UNREACH;
    }
out:
    m_end_connect_hl( NAME_OF_MAIN_LOC_GLOB_P->a_ip_address_context );
        if (ret == KRB5_KDC_UNREACH) {
            krb5_set_error_string(NAME_OF_MAIN_LOC_GLOB_P, context,
                "unable to reach any changepw server "
                " in realm %s", realm);
            *result_code = KRB5_KPASSWD_HARDERROR;
        }
        return ret;
}


/*
 * change the password using the credentials in `creds' (for the
 * principal indicated in them) to `newpw', storing the result of
 * the operation in `result_*' and an error code or 0.
 */

krb5_error_code KRB5_LIB_FUNCTION
krb5_change_password (struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
              krb5_context	context,
		      krb5_creds	*creds,
		      char		*newpw,
		      int		*result_code,
		      krb5_data		*result_code_string,
		      krb5_data		*result_string)
{
    struct kpwd_proc *p = find_chpw_proto("change password");

    *result_code = KRB5_KPASSWD_MALFORMED;
    result_code_string->data = result_string->data = NULL;
    result_code_string->length = result_string->length = 0;

    if (p == NULL)
	return KRB5_KPASSWD_MALFORMED;

    return change_password_loop(NAME_OF_MAIN_LOC_GLOB_P, context, creds, NULL, newpw,
				result_code, result_code_string,
				result_string, p);
}

HL_LONGLONG
m_krb5_date_to_timestamp( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const char *achp_tm )
{
    struct tm dscl_time; //temporary variable
    char achl_work[5]; //Working variable
    static const unsigned ndays[2][12] = {
        {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
        {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
    };
    HL_LONGLONG ill_res = 0;
    int i; //counter variable
    /* read date to struct */
    memset(achl_work,0,5);
    memcpy(achl_work,achp_tm,4);
    dscl_time.tm_year = atoi(achl_work);
    memcpy(achl_work,achp_tm+4,2);
    achl_work[3] = '\0';
    dscl_time.tm_mon = atoi(achl_work);
    memcpy(achl_work,achp_tm+6,2);
    dscl_time.tm_mday = atoi(achl_work);
    memcpy(achl_work,achp_tm+8,2);
    dscl_time.tm_hour = atoi(achl_work);
    memcpy(achl_work,achp_tm+10,2);
    dscl_time.tm_min = atoi(achl_work);
    memcpy(achl_work,achp_tm+12,2);
    dscl_time.tm_sec = atoi(achl_work);

    for( i = 70; i < dscl_time.tm_year; ++i )
        ill_res += is_leap( NAME_OF_MAIN_LOC_GLOB_P, i ) ? 366 : 365;
    for( i = 0; i < dscl_time.tm_mon; ++i )
        ill_res += ndays[is_leap( NAME_OF_MAIN_LOC_GLOB_P, dscl_time.tm_year )][i];
    ill_res += dscl_time.tm_mday - 1;
    ill_res *= 24;
    ill_res += dscl_time.tm_hour;
    ill_res *= 60;
    ill_res += dscl_time.tm_min;
    ill_res *= 60;
    ill_res += dscl_time.tm_sec;
    return ill_res;
}

static inline void m_read_hex(struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, const char* achp_string, EncryptionKey* adsp_key){
    unsigned char* aucl_dest_buf = (unsigned char*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, adsp_key->keyvalue.length);
    int inl_counter=0;
    int inl_temp= 0;
    const char* achl_string=achp_string+4;
    for(;inl_counter < adsp_key->keyvalue.length; ++inl_counter) {
        sscanf(achl_string,"%02x",&inl_temp);
        *aucl_dest_buf = (unsigned char)inl_temp;
        ++aucl_dest_buf;
        achl_string +=2;
    }
    aucl_dest_buf -=adsp_key->keyvalue.length;
    adsp_key->keyvalue.data=aucl_dest_buf;
}

/**
*   Routine for searching a Heimdal key tab dump for a key/principal combination.
*
*   This rountine searches a given Heimdal keytab dump for a key of a specified etype
*   belonging to a specified principal. Valid from, valid untill and cnaceled dates are
*   checked using the current time. If a date is not given, it is assumed to be acceptable.
*   etype is extracted from the AP REQ. The keytab is contained in the context struct.
*   It is assumed, that the Keyblock is initialized and large enough to hold the key.
*
*   Note, that the key tab MUST be /0 terminated!
*
*   @param  NAME_OF_MAIN_LOC_GLOB_P Pointer to global/static variable struct.
*   @param  adsp_context            Heimdal context structure.
*   @param  adsp_ap_req             Pointer to AP REQ.
*   @param  adsp_server             Tareget service principal for AP REQ.
*   @param  aadsp_keyblock          Return pointer for the key.
*
*   @return 0, if key was found, error code (<0) otherwise.
*/
krb5_error_code m_krb5_search_heimdal_keytab(struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
                krb5_context adsp_context,
                krb5_ap_req     *adsp_ap_req,
                krb5_const_principal   adsp_server,
                krb5_keyblock  **aadsp_keyblock) {
    int ill_ret = KRB5KRB_AP_ERR_NOKEY;                     //keeps return values
    char* achl_principal_name = (char*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,adsp_context->client_server); //stores the target principal name
    const char* achl_keytab = adsp_context->default_keytab; //the actual keytab
    const char* achl_current_entry = achl_keytab;           //work pointer to start of current keytab entry
    const char* achl_target_key_start= NULL;                //pointer to start of the target key
    const char* achl_target_key_end = NULL;                 //pointer  to position one beyond(!) the end of target key
    int inl_princ_len;                                      //length of full principal name
    int inl_enc_type = 0;                                   //temp variable for etype. 0 means none found.
    HL_LONGLONG ill_current_time = m_get_epoch_ms()/1000;   //current time
    HL_LONGLONG ill_temp_timestamp;                         //temp for timestamps in key tab

    if(*(achl_keytab+(adsp_context->client_server)-1) != 0){
        return ill_ret;
    }
    inl_princ_len = krb5_unparse_name_fixed(NAME_OF_MAIN_LOC_GLOB_P, adsp_context, adsp_server, achl_principal_name, adsp_context->client_server);
    if(inl_princ_len){
        return inl_princ_len;
    }
    inl_princ_len = strlen(achl_principal_name);

    for(;;){
        achl_current_entry = strstr(achl_current_entry,achl_principal_name);
        if(achl_current_entry == NULL) {
            break;
        }
        if( ( achl_current_entry != achl_keytab || *(achl_current_entry-1) == ':' )
            && *(achl_current_entry+inl_princ_len) != ' ' ) {
                achl_current_entry++;
                continue;
            }
        /* Found target principal entry */
        achl_current_entry = strchr(achl_current_entry,' ');
        achl_target_key_start = ++achl_current_entry;
        achl_current_entry = strchr(achl_current_entry,' ');
        achl_target_key_start = strchr(++achl_target_key_start, ':');
        while( achl_target_key_start < achl_current_entry ) {
            /* Search key list */
            achl_target_key_start = strchr(++achl_target_key_start, ':');
            ++achl_target_key_start;
            while(*achl_target_key_start != ':') {
                inl_enc_type *= 10;
                inl_enc_type += (*achl_target_key_start)- 0x30;
                ++achl_target_key_start;
            }
            if( inl_enc_type == adsp_ap_req->ticket.enc_part.etype ){
                achl_target_key_end = strchr(++achl_target_key_start, ':');
                break;
            }
            inl_enc_type = 0;
            achl_target_key_start = strchr(++achl_target_key_start, ':');
            achl_target_key_start = strchr(++achl_target_key_start, ':');
        }
        if(!inl_enc_type){
            continue;
        }
        /* Check, if entry is valid */
        achl_current_entry = strchr(++achl_current_entry,' ');
        achl_current_entry = strchr(++achl_current_entry,' ');
        ++achl_current_entry;
        if(*achl_current_entry != '-') {
            ill_temp_timestamp = m_krb5_date_to_timestamp(NAME_OF_MAIN_LOC_GLOB_P, achl_current_entry);
            if(ill_temp_timestamp > ill_current_time){
                continue;
            }
        }
        achl_current_entry = strchr(achl_current_entry,' ');
        ++achl_current_entry;
        if(*achl_current_entry != '-') {
            ill_temp_timestamp = m_krb5_date_to_timestamp(NAME_OF_MAIN_LOC_GLOB_P, achl_current_entry);
            if(ill_temp_timestamp < ill_current_time){
                continue;
            }
        }
        achl_current_entry = strchr(achl_current_entry,' ');
        ++achl_current_entry;
        if(*achl_current_entry != '-') {
            ill_temp_timestamp = m_krb5_date_to_timestamp(NAME_OF_MAIN_LOC_GLOB_P, achl_current_entry);
            if(ill_temp_timestamp < ill_current_time){
                continue;
            }
        }
        /* Valid entry found */
        if( inl_enc_type && achl_target_key_end > achl_target_key_start) {
            m_read_hex( NAME_OF_MAIN_LOC_GLOB_P, achl_target_key_start-4, (*aadsp_keyblock));
            ill_ret = 0;
            }
        break;
    }

    m_aux_stor_free(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,achl_principal_name);
    return ill_ret;
}//krb5_error_code m_krb5_search_heimdal_keytab(struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context adsp_context, krb5_ap_req *adsp_ap_req, krb5_principal adsp_server, krb5_keyblock  **aadsp_keyblock);


/**
*   Routine for searching an Active Directory key tab dump for a key/principal combination.
*
*   This rountine searches a given Active Directory keytab dump for a key of a specified etype
*   belonging to a specified principal. Valid from, valid untill and cnaceled dates are
*   checked using the current time. If a date is not given, it is assumed to be acceptable.
*   etype is extracted from the AP REQ. The keytab is contained in the context struct.
*   It is assumed, that the Keyblock is initialized and large enough to hold the key.
*
*   It is expected, that the key tab is NOT /0 terminated.
*
*   @param  NAME_OF_MAIN_LOC_GLOB_P Pointer to global/static variable struct.
*   @param  adsp_context            Heimdal context structure.
*   @param  adsp_ap_req             Pointer to AP REQ.
*   @param  adsp_server             Tareget service principal for AP REQ.
*   @param  aadsp_keyblock          Return pointer for the key.
*
*   @return 0, if key was found, error code (<0) otherwise.
*/
krb5_error_code m_krb5_search_AD_keytab(struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
                krb5_context adsp_context,
                krb5_ap_req     *adsp_ap_req,
                krb5_const_principal   adsp_server,
                krb5_keyblock  **aadsp_keyblock) {
    int inl_entry_len = 0;                                              //length of current entry
    unsigned int unl_name_len=4;                                                 //length of full principal, including num_components and realm
    unsigned int unl_counter;                                                    //counter for loops
    const char * achl_current_entry = adsp_context->default_keytab+2;   //work pointer
    const char* const achl_end_keytab = achl_current_entry+adsp_context->client_server-3;    //pointer to the end of the keytab
    char* achl_principal;                                               //target principal as in AD dump
    char* achl_work;                                                    //work pointer
    krb5_error_code inl_ret = KRB5KRB_AP_ERR_NOKEY;                     //return code
    u_int16_t usl_work;                                                 //work variable
#ifndef B120516
    char      chrl_trans_1[ 512 ];
    char      chrl_trans_2[ 512 ];
#endif

    /* generate principal name in AD syntax */
    unl_name_len+= adsp_server->name.name_string.len*2;
    for(unl_counter = 0; unl_counter < adsp_server->name.name_string.len; ++unl_counter){
        unl_name_len += strlen(*(adsp_server->name.name_string.val+unl_counter));
    }
    unl_name_len += strlen(adsp_server->realm);
    achl_principal = (char*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, unl_name_len);
    memset(achl_principal, 0,unl_name_len);
    usl_work = adsp_server->name.name_string.len;
    usl_work = m_bswap16(usl_work);
    memcpy(achl_principal,(char*)(&usl_work),2);
    achl_work = achl_principal+2;
    usl_work = strlen(adsp_server->realm);
    memcpy(achl_work+2,adsp_server->realm, usl_work);
    usl_work = m_bswap16(usl_work);
    memcpy(achl_work,(char*)(&usl_work),2);
    achl_work +=2;
    for(unl_counter = 0; unl_counter < adsp_server->name.name_string.len; ++unl_counter){
        usl_work = strlen(*(adsp_server->name.name_string.val+unl_counter));
        achl_work = strchr(achl_work,'\0');
        memcpy(achl_work+2,*(adsp_server->name.name_string.val+unl_counter), usl_work);
        usl_work = m_bswap16(usl_work);
        memcpy(achl_work,(char*)(&usl_work),2);
        achl_work +=2;
    }
    /* search keytab */
    for(;;){
        if(achl_end_keytab < achl_current_entry){
            break;
        }
        inl_entry_len = (int)m_bswap32(*((u_int32_t*)(achl_current_entry)));
        if(inl_entry_len <=0) {
            achl_current_entry -= inl_entry_len;
            continue;
        }
        achl_work = (char*)achl_current_entry+4;
        achl_current_entry += inl_entry_len+4;
        if(memcmp(achl_work,achl_principal,unl_name_len)!=0){
            continue;
        }
        achl_work += unl_name_len+9;
        usl_work = m_bswap16( *((u_int16_t*)(achl_work)));
        if ( usl_work == adsp_ap_req->ticket.enc_part.etype ){
            usl_work = m_bswap16( *((u_int16_t*)(achl_work+2)));
            (*aadsp_keyblock)->keyvalue.data = m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, usl_work);
            memcpy((*aadsp_keyblock)->keyvalue.data,achl_work+4,usl_work);
            inl_ret = 0;
            break;
        }
    }
    m_aux_stor_free(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area, achl_principal);
    return inl_ret;
}//krb5_error_code m_krb5_search_AD_keytab(struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P, krb5_context adsp_context, krb5_ap_req *adsp_ap_req, krb5_principal adsp_server, krb5_keyblock  **aadsp_keyblock);

static inline u_int16_t  m_bswap16_le( u_int16_t x )
{ return ((x & (u_int16_t)0x00ffU) << 8 | (x & (u_int16_t)0xff00U) >> 8); }

static inline u_int16_t  m_bswap16_be( u_int16_t x )
{ return x; }

static inline u_int16_t m_bswap16_init( u_int16_t usp_in ){
    u_int16_t inl_int_val = 1;
    char* achl_char_ptr= (char*)&inl_int_val;
    if(*achl_char_ptr) {
        m_bswap16 = &m_bswap16_le;
    } else {
        m_bswap16 = &m_bswap16_be;
    }
    return m_bswap16(usp_in);
}

static inline u_int32_t  m_bswap32_le( u_int32_t x )
{ return ((x & (u_int32_t)0x000000ffUL) << 24 | (x & (u_int32_t)0x0000ff00UL) <<  8 | \
 	      (x & (u_int32_t)0x00ff0000UL) >>  8 | (x & (u_int32_t)0xff000000UL) >> 24); }
 	
static inline u_int32_t  m_bswap32_be( u_int32_t x )
{ return x; }

static inline u_int32_t m_bswap32_init( u_int32_t unp_in ){
    u_int16_t inl_int_val = 1;
    char* achl_char_ptr= (char*)&inl_int_val;
    if(*achl_char_ptr) {
        m_bswap32 = &m_bswap32_le;
    } else {
        m_bswap32 = &m_bswap32_be;
    }
    return m_bswap32(unp_in);
}


static const char* const achg_delimiter = " \t\n";

static inline char* m_next_token( const char* achp_string, const char* achp_delimiters, int inp_jump_count ){
    int inl_counter=0;
    char * achl_ret_string = achp_string;
    for(; inl_counter < inp_jump_count; ++inl_counter){
        achl_ret_string = strpbrk(achl_ret_string, achp_delimiters);
	    ++achl_ret_string;
	}
	return achl_ret_string;
}

static dsd_heimdal_keytab_entry_t* m_read_mit_dump( struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P,
                            const char *achp_keytab) {
    dsd_heimdal_keytab_entry_t dsl_keytab_start;        //starting point for entry list
    dsd_heimdal_keytab_entry_t *adsl_current_entry = &dsl_keytab_start; //current entry
    const char* achl_mit_keytab_ptr = achp_keytab;      //current position in the MIT keytab
    int inl_dump_ver=0;                                 //version of the dump file
	int inl_num_tl_data= 0;                             //number of tl data in current entry
	int inl_extra_data_len;                             //length of extra data
	int inl_work1= 0,inl_work2;     //work integer
	char* achl_work;
	int inl_kvno= 0;
	int inl_key_data_ver= 0;
	int inl_high_kvno= -1;
	
	memset(&dsl_keytab_start,0,sizeof(dsd_heimdal_keytab_entry_t));
	achl_mit_keytab_ptr = strstr(achl_mit_keytab_ptr,"kdb5_util load_dump version ");
	if(achl_mit_keytab_ptr == NULL){
	    return NULL;
	}
	achl_mit_keytab_ptr += 28;
	inl_dump_ver = (*achl_mit_keytab_ptr)- 0x30;
	if(inl_dump_ver < 4 || inl_dump_ver >6){
	    return NULL;
	}
	achl_mit_keytab_ptr = strstr(achl_mit_keytab_ptr, "princ");
	while(achl_mit_keytab_ptr){
	    achl_mit_keytab_ptr = m_next_token(achl_mit_keytab_ptr, achg_delimiter,1);
	    if(adsl_current_entry->adsc_next_entry != NULL ){
	        return NULL;
	    }
	    adsl_current_entry->adsc_next_entry = (dsd_heimdal_keytab_entry_t *)m_aux_stor_alloc(
	                                                    NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,
	                                                    sizeof(dsd_heimdal_keytab_entry_t));
	    adsl_current_entry = adsl_current_entry->adsc_next_entry;
	    memset(adsl_current_entry,0 , sizeof(dsd_heimdal_keytab_entry_t));
	    inl_work2 = sscanf(achl_mit_keytab_ptr, "%i\t%i\t%i\t%i\t%i\t", &inl_work1,
	                &adsl_current_entry->inc_princ_len,
	                &inl_num_tl_data,
	                &adsl_current_entry->inc_key_count,
	                &inl_extra_data_len);
	    if(inl_work1 != 38 || inl_work2 != 5 || adsl_current_entry->inc_key_count <= 0){
	        return NULL;
	    }
	    achl_mit_keytab_ptr = m_next_token(achl_mit_keytab_ptr, achg_delimiter, inl_work2);
	    adsl_current_entry->achc_princ_name = (char*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,
	                                                                  adsl_current_entry->inc_princ_len);
        memcpy(adsl_current_entry->achc_princ_name, achl_mit_keytab_ptr, adsl_current_entry->inc_princ_len);
	    achl_work =achl_mit_keytab_ptr+adsl_current_entry->inc_princ_len+1;
	    achl_mit_keytab_ptr = m_next_token(achl_mit_keytab_ptr, achg_delimiter, 1);
	    if(achl_work != achl_mit_keytab_ptr){
	        return NULL;
	    }
	    inl_work1 = sscanf(achl_mit_keytab_ptr, "%i\t%i\t%i\t%i\t%i\t",
	                            &adsl_current_entry->inc_attributes,
                                &adsl_current_entry->inc_tkt_lifetime,
                                &adsl_current_entry->inc_renew_life,
                                &adsl_current_entry->inc_valid_until,
                                &adsl_current_entry->inc_pw_expired);
        if(inl_work1 !=5){
	        return NULL;
	    }
	    achl_mit_keytab_ptr = m_next_token(achl_mit_keytab_ptr, achg_delimiter,8+(3*inl_num_tl_data));
	
	    adsl_current_entry->asdc_key_list = (EncryptionKey*)m_aux_stor_alloc(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,
	                                            sizeof(EncryptionKey)*adsl_current_entry->inc_key_count);
        memset(adsl_current_entry->asdc_key_list,0,sizeof(EncryptionKey)*adsl_current_entry->inc_key_count);
        inl_work1 = sscanf(achl_mit_keytab_ptr, "%i\t%i\t", &inl_key_data_ver,&inl_high_kvno);
        if(inl_work1 !=2){
	        return NULL;
	    }
	    for(inl_work1 = 0; inl_work1 < adsl_current_entry->inc_key_count; ++inl_work1){
	        inl_work2 = sscanf(achl_mit_keytab_ptr, "%i\t%i\t%i\t%i\t", &inl_key_data_ver,
	                            &inl_kvno,
	                            &(adsl_current_entry->asdc_key_list+inl_work1)->keytype,
	                            &(adsl_current_entry->asdc_key_list+inl_work1)->keyvalue.length);
            if(inl_kvno > inl_high_kvno || inl_work2 != 4) {
	        return NULL;
            }
            (adsl_current_entry->asdc_key_list+inl_work1)->keyvalue.length -=2;
	        achl_mit_keytab_ptr = m_next_token(achl_mit_keytab_ptr, achg_delimiter,4);
	        if(inl_kvno == inl_high_kvno){
	                m_read_hex( NAME_OF_MAIN_LOC_GLOB_P, achl_mit_keytab_ptr, (adsl_current_entry->asdc_key_list+inl_work1));
	            }
	        achl_mit_keytab_ptr = m_next_token(achl_mit_keytab_ptr, achg_delimiter,1+(3*(inl_key_data_ver-1)));
	    }
	    achl_mit_keytab_ptr = strstr(achl_mit_keytab_ptr, "princ");
	}
     return dsl_keytab_start.adsc_next_entry;
}

static int m_write_hex(const unsigned char* aucp_data, size_t szp_data_len, char* achp_dest)
{
    int inl_ret=0;
    for(;szp_data_len>0;--szp_data_len){
        achp_dest+= sprintf(achp_dest,"%02x",*aucp_data);
        inl_ret+=2;
        ++aucp_data;
    }
    return inl_ret;
}

int mit_prop_dump(  const char *achp_keytab,
                    const char *achp_pw_salt,
                    const char *achp_pw,
                    char *achp_dest_buf,
                    size_t szp_dest_len,
                    void **aavop_mem_ptr)
{
   struct dsd_global_and_static* NAME_OF_MAIN_LOC_GLOB_P = NULL;
   dsd_heimdal_keytab_entry_t *adsl_entry_ancor = NULL; //current entry
    krb5_data dsl_password;
	krb5_salt dsl_salt;
	krb5_data dsl_opaque;
	krb5_keyblock dsl_key;
	struct key_data dsl_kd;
	struct krb5_aes_schedule dsl_schedule;
	struct krb5_crypto_data dsl_crypto;
	krb5_data dsl_result;
	EncryptionKey* adsl_key_pointer=NULL;
	int inl_res=0;
	int inl_work=0, inl_work2=0;
	struct encryption_type * adsl_etype;
	
   NAME_OF_MAIN_LOC_GLOB_P = (struct dsd_global_and_static*)m_aux_stor_alloc(aavop_mem_ptr, sizeof(struct dsd_global_and_static));
   memset(NAME_OF_MAIN_LOC_GLOB_P, 0, sizeof(struct dsd_global_and_static));
   NAME_OF_MAIN_LOC_GLOB_P->aa_memory_area = aavop_mem_ptr;
   NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area = aavop_mem_ptr;
   NAME_OF_MAIN_LOC_GLOB_P->_krb5_AES_string_to_default_iterator = 4096;
   NAME_OF_MAIN_LOC_GLOB_P->im_counter_array_free_posi = -1;
   NAME_OF_MAIN_LOC_GLOB_P->im_control_5 = 1;

	adsl_entry_ancor = m_read_mit_dump( NAME_OF_MAIN_LOC_GLOB_P,
                                        achp_keytab);
	if(adsl_entry_ancor == NULL){
	    return -2;
	}
	dsl_password.data = achp_pw;
    dsl_password.length = strlen(achp_pw);
    dsl_salt.salttype = KRB5_PW_SALT;
    dsl_salt.saltvalue.data = achp_pw_salt;
    dsl_salt.saltvalue.length = strlen(achp_pw_salt);
    memset(&dsl_opaque,0,sizeof(krb5_data));
    memset(&dsl_key,0,sizeof(krb5_keyblock));
    memset(&dsl_kd,0,sizeof(struct key_data));
    memset(&dsl_result,0,sizeof(krb5_data));

    inl_res= AES_string_to_key( NAME_OF_MAIN_LOC_GLOB_P, NULL,
        ETYPE_AES128_CTS_HMAC_SHA1_96,
        dsl_password,
        dsl_salt,
        dsl_opaque,
        &dsl_key );
    dsl_kd.key = &dsl_key;
    dsl_kd.schedule = &dsl_opaque;
    dsl_kd.schedule->data = &dsl_schedule;
    AES_schedule( NAME_OF_MAIN_LOC_GLOB_P, NULL,
        &dsl_kd, NULL );
    dsl_crypto.et = &enctype_aes128_cts_hmac_sha1;
    dsl_crypto.key = dsl_kd;
    dsl_crypto.key_usage = NULL;
    dsl_crypto.num_key_usage = 0;
    dsl_crypto.params = NULL;
    inl_res =szp_dest_len;
    for(;;){
        /* Calculate length */
        inl_res -= (adsl_entry_ancor->inc_princ_len+21);
        if(adsl_entry_ancor->inc_pw_expired) {
            inl_res -= (adsl_entry_ancor->inc_princ_len+14);
        }
        for(inl_work = 0; inl_work <adsl_entry_ancor->inc_key_count ;++inl_work){
            adsl_etype = _find_enctype( NAME_OF_MAIN_LOC_GLOB_P,
                                        (adsl_entry_ancor->asdc_key_list+inl_work)->keytype );
            if(adsl_etype){
               inl_res -= adsl_etype->keytype->size*2 +7;
            } else {
               (adsl_entry_ancor->asdc_key_list+inl_work)->keytype = ETYPE_NULL;
            }
        }
        if(inl_res <=0){
            return 0;
        }
        memcpy(achp_dest_buf,adsl_entry_ancor->achc_princ_name,
            adsl_entry_ancor->inc_princ_len);
        achp_dest_buf += adsl_entry_ancor->inc_princ_len;
        *(achp_dest_buf++) = ' ';
        *(achp_dest_buf++) = '1';
        adsl_key_pointer = adsl_entry_ancor->asdc_key_list;
        for(inl_work = adsl_entry_ancor->inc_key_count; inl_work >0 ;--inl_work){
           if( adsl_key_pointer->keytype == ETYPE_NULL){
              continue;
           }
           *(achp_dest_buf++) = ':';
            *(achp_dest_buf++) = ':';
            if(sprintf(achp_dest_buf,"%i",adsl_key_pointer->keytype) !=2){
                return -2;
            }
            achp_dest_buf += 2;
            *(achp_dest_buf++) = ':';
            inl_work2 = decrypt_internal_derived( NAME_OF_MAIN_LOC_GLOB_P, NULL,
                &dsl_crypto,
                0,
                adsl_key_pointer->keyvalue.data,
                adsl_key_pointer->keyvalue.length,
                &dsl_result,
                NULL);
            if(inl_work2){
                return -1;
            }
            achp_dest_buf += m_write_hex((unsigned char*)dsl_result.data,dsl_result.length,achp_dest_buf);
            *(achp_dest_buf++) = ':';
            *(achp_dest_buf++) = '-';
            ++adsl_key_pointer;
        }
        memcpy(achp_dest_buf, " - - - - - - - - - ",20);
        achp_dest_buf +=19;
        if(adsl_entry_ancor->adsc_next_entry == NULL){
            return szp_dest_len-inl_res+1;
        }
        adsl_entry_ancor = adsl_entry_ancor->adsc_next_entry;
    }
}
