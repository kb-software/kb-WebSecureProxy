/**
 * PROJECT:  xs-gw-udp-gate-srtp.cpp
 *
 * This project implements a complete SRTP-interface with UDP.
 *
 * Required programs:
 * MS Visual Studio .NET 2005 or later
 * MS Linker
 *
 * Copyright (C) HOB Germany 2010
 * Copyright (C) HOB Germany 2011
 *
 * @version 1.01
 * @author  Varshawskyy, others, Juergen-Lorenz Lauenstein
 * @date    2011/05/09   (code review)
 *
 */
/*+-----------------------------------------------------------------------------------+*/
/*| Defines                                                                           |*/
/*+-----------------------------------------------------------------------------------+*/
#define HL_KEY_LENGTH   16
#define HL_SALT_LENGTH  14
#define HL_AUTH_LENGTH  20
#define HL_AES_LEN      16
#define HL_MAX_SEQNO    (unsigned int)0x8000

/*+-----------------------------------------------------------------------------------+*/
/*| Typedefs                                                                          |*/
/*+-----------------------------------------------------------------------------------+*/
#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

/*+-----------------------------------------------------------------------------------+*/
/*| Includes                                                                          |*/
/*+-----------------------------------------------------------------------------------+*/
#ifndef HL_UNIX
#include <windows.h>
#include <stdio.h>

#ifdef B110912
#include "hobaes.h"
#include "hsha.h"
#endif
#ifndef B160501
#include <stdint.h>
#endif
#include <hob-encry-1.h>
#else
#include <string.h>
#ifndef B160501
#include <stdint.h>
#endif
#include <arpa/inet.h>
#include <hob-unix01.h>
#include <hob-encry-1.h>
#endif

/*+-----------------------------------------------------------------------------------+*/
/*| Structures                                                                        |*/
/*+-----------------------------------------------------------------------------------+*/
struct dsd_keys
{
   unsigned char uchrc_master_key[HL_KEY_LENGTH];   // master key (local, remote)
   unsigned char uchrc_master_salt[HL_SALT_LENGTH]; // master salt (local, remote)
   unsigned char uchrc_encr_key[HL_KEY_LENGTH];     // encryption key (local, remote)
   unsigned char uchrc_auth_key[HL_AUTH_LENGTH];    // authentication key (local, remote)
   unsigned char uchrc_salting_key[HL_SALT_LENGTH]; // salting key (local, remote)
   unsigned      uinc_roc;                          // rollover counter for the local or the remote paket
   unsigned      uinc_seqno;                        // sequence number of the local or the remote paket
};

/*+-----------------------------------------------------------------------------------+*/
/*| Global variables and statics                                                      |*/
/*+-----------------------------------------------------------------------------------+*/
static const char chrs_enc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char ucrs_decr[128] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,   // 0x00 - 0x0F
                                     -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,   // 0x10 - 0x1F
                                     -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,   // 0x20 - 0x2F
                                     52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,   // 0x30 - 0x3F
                                     -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,   // 0x40 - 0x4F
                                     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,   // 0x50 - 0x5F
                                     -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,   // 0x60 - 0x6F
                                     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1 }; // 0x70 - 0x7F

/*+-----------------------------------------------------------------------------------+*/
/*| Prototypes                                                                        |*/
/*+-----------------------------------------------------------------------------------+*/
static void m_decode_base64( char*, struct dsd_keys * );
static void m_encrypt( unsigned long, int, int, unsigned char *, int, struct dsd_keys *, unsigned char * );
static void m_make_auth_tag( unsigned char*, int, unsigned, unsigned char *, unsigned char * );
static int  m_to_roc( char *, char *, int, unsigned char *, int, struct dsd_keys * );

/*+-----------------------------------------------------------------------------------+*/
/*| Functions                                                                         |*/
/*+-----------------------------------------------------------------------------------+*/
extern PTYPE BOOL m_udp_gate_encry_init( char *achp_keys,
                                         char *achp_encode/*server*/,
                                         char *achp_decode/*client*/ )
{
   // check input parameters (to do: return different error numbers)
   if (achp_keys == NULL || achp_encode == NULL || achp_decode == NULL)
     return FALSE;

   // check whether all master characters are Base64 characters
   int in_k = 0;
   do
   {  // check for base64 characters...
      if (!memchr( (void *)chrs_enc, achp_keys[in_k], sizeof(chrs_enc) - 1 ))
      { // check for the pad-character '='
        if (achp_keys[in_k] != '=')
          // masters are not base64 coded, return with error
          return FALSE;
      }
      in_k++;  // next character
   } while( in_k < 80);

   // 'achp_encode' and 'achp_decode' contain the key information, roc and seqno
   // generate corresponding keys for each base64-string
   m_decode_base64( achp_keys + 40, (struct dsd_keys *)achp_encode/*server*/ );
   m_decode_base64( achp_keys, (struct dsd_keys *)achp_decode/*client*/ );

   return TRUE;

}; // BOOL m_udp_gate_encry_init( char *, char *, char * )


extern PTYPE int m_udp_gate_encry_encode( char *achp_out, int imp_len_out,
                                          char *achp_inp, int imp_len_inp,
                                          char *achp_encode )
{
   // both payloads begin at the 13th Byte of the paket
   unsigned char *aucrl_payload     = (unsigned char *)(achp_inp + 12);
   unsigned char *aucrl_enc_payload = (unsigned char *)(achp_out + 12);

   unsigned char uchrl_roc[4] = { 0, 0, 0, 0 };
   unsigned char uchrl_auth_tag[10];
   unsigned char *auchrl_auth_part;
   struct dsd_keys *adsl_local = (struct dsd_keys *)achp_encode;  // set adsl_local from the achp_encode
   int iml_c = 0;
   int iml_length = imp_len_inp - 12; // im_length is here the payload length


   // check input parameters...
   if (achp_inp == NULL || imp_len_inp == 0 ||
       achp_out == NULL || imp_len_out < imp_len_inp + 10 ||
       achp_encode == NULL)
     return -1;

   unsigned uinl_seqno = ntohs( *(unsigned short *)(achp_inp + 2) );
   // when the seqno is zero and the previous storied value is not zero, the roc has to be incremented
   if (uinl_seqno == 0 && adsl_local->uinc_seqno)
     adsl_local->uinc_roc++;

   adsl_local->uinc_seqno = uinl_seqno;  //the seqno has to be updated
   // compute the index
   unsigned long long uinl_index = (unsigned long long)adsl_local->uinc_roc * (unsigned int)(1 << 16) + uinl_seqno;

   // compute the roc as an unsigned char array
   unsigned uinl_roc = adsl_local->uinc_roc;
   while (uinl_roc / 256 > 0)
   {
       uchrl_roc[3 - iml_c] = (unsigned char)(uinl_roc % 256);
       iml_c++;
       uinl_roc /= 256;
   }
   uchrl_roc[3 - iml_c] = (unsigned char)(uinl_index % 256);

   // do encryption
   m_encrypt( (unsigned long)ntohl( *(unsigned int *)(achp_inp + 8) ) /*ssrc*/,
              adsl_local->uinc_roc,
              uinl_seqno,
              aucrl_payload,
              iml_length,
              adsl_local,
              aucrl_enc_payload );
   // copy the header from the input to the output
   memcpy( achp_out, achp_inp, 12 );

   auchrl_auth_part = (unsigned char *)achp_out; // the auth. part begins with the beginning of the paket
   // compute the auth. tag
   m_make_auth_tag( auchrl_auth_part, imp_len_inp, adsl_local->uinc_roc, adsl_local->uchrc_auth_key, uchrl_auth_tag );
   // copy the computed auth. tag after the encoded payload
   memcpy( auchrl_auth_part + imp_len_inp, uchrl_auth_tag, 10 );

   return imp_len_inp + 10; // returns the length of the created packet

}; // int m_udp_gate_encry_encode( char *, int, char *, int, char * )


extern PTYPE int m_udp_gate_encry_decode( char *achp_out, int imp_len_out,
                                          char *achp_inp, int imp_len_inp,
                                          char *achp_decode )
{

   // check for valid parameters...
   if (achp_inp == NULL || imp_len_inp == 0 ||
       achp_out == NULL || imp_len_out < imp_len_inp - 10 ||
       achp_decode == NULL)
     return -1;

     //set the seqno
     unsigned uinl_seqno = ntohs( *(unsigned short *)(achp_inp + 2) );

     int            iml_payload_length = imp_len_inp - 12;                  // payload length is the length of the auth. tag
     unsigned char *aucrl_payload      = (unsigned char *)(achp_inp + 12);  // payload begins after the header
     unsigned char *aucrl_dec_payload  = (unsigned char *)(achp_out + 12);  // decr. payload begins after the header

     // if the authentication fails, it is nothing else to do, just ignore
     struct dsd_keys *adsl_remote = (struct dsd_keys *)achp_decode;

     if (m_to_roc( achp_inp, achp_out, imp_len_inp, aucrl_payload, iml_payload_length, adsl_remote ) == -1)
       return -1;

     // encrypt here is the same as decrypt. Decrypt the real payload, not the tag
     m_encrypt( ntohl( *(unsigned int *)(achp_inp + 8) ) /*ssrc*/,
                adsl_remote->uinc_roc,
                uinl_seqno,
                aucrl_payload,
                iml_payload_length - 10,
                adsl_remote,
                aucrl_dec_payload );

     memcpy( achp_out, achp_inp, 12 );                                    // copy the header from the input into the output
     memcpy( achp_out + 12, aucrl_dec_payload, iml_payload_length - 10 ); // copy the decrypted payload into
     // return the number of bytes of the created rtp paket
     return imp_len_inp - 10;

}; // int m_udp_gate_encry_decode( char *, int, char *, int, char * )


static void m_derive_session_keys( unsigned char    ucp_label,
                                   int              imp_counter,
                                   struct dsd_keys *adsp_keys,
                                   unsigned char   *auchrp_help1 )
{
      unsigned char ucrl_iv[HL_KEY_LENGTH];
      unsigned char ucrl_key_id[HL_SALT_LENGTH];
      unsigned char ucrl_x[HL_SALT_LENGTH];
      unsigned char ucrl_ivector[HL_AES_LEN];


      memset( ucrl_ivector, 0, sizeof(ucrl_ivector) );
      memset( ucrl_key_id, 0, sizeof(ucrl_key_id) );
      ucrl_key_id[7] = ucp_label;

      int iml_1;
      for (iml_1 = 0; iml_1 < HL_SALT_LENGTH; iml_1++)
         ucrl_x[iml_1] = (unsigned char)(ucrl_key_id[iml_1] ^ adsp_keys->uchrc_master_salt[iml_1]);

      struct ds_aes_key_t  aimrl_enckeybyte;
#ifndef HL_UNIX
#ifdef B110912
      m_aes_set_encrypt_key( adsp_keys->uchrc_master_key, 4, (unsigned int *)&aimrl_enckeybyte );
#else
      m_aes_set_encrypt_key( adsp_keys->uchrc_master_key, 4, (ds_aes_key *) &aimrl_enckeybyte );
#endif
#else
      m_aes_set_encrypt_key( adsp_keys->uchrc_master_key, 4, (ds_aes_key *) &aimrl_enckeybyte );
#endif

      memcpy( ucrl_iv, ucrl_x, HL_SALT_LENGTH );
      memset( ucrl_iv + HL_SALT_LENGTH, 0, HL_KEY_LENGTH - HL_SALT_LENGTH );
      unsigned int uml_carry = imp_counter;

      for (iml_1 = HL_KEY_LENGTH - 1; iml_1 > -1; iml_1--)
      {
          uml_carry    = (unsigned int)ucrl_iv[iml_1] + uml_carry;
          ucrl_iv[iml_1] = (unsigned char)uml_carry;
          uml_carry >>= 8;
      }

#ifndef HL_UNIX
#ifdef B110912
      m_aes_cbc_encrypt( ucrl_iv, auchrp_help1, (unsigned int *)&aimrl_enckeybyte, 1, ucrl_ivector, 10 );
#else
      m_aes_cbc_encrypt( ucrl_iv, auchrp_help1, (ds_aes_key *) &aimrl_enckeybyte, 1, ucrl_ivector, 10 );
#endif
#else
      m_aes_cbc_encrypt( ucrl_iv, auchrp_help1, (ds_aes_key *) &aimrl_enckeybyte, 1, ucrl_ivector, 10 );
#endif

}; // void m_derive_session_keys( unsigned char, int, struct dsd_keys *, unsigned char * )


/**
* Generates a key stream segment
*
* @param im_counter   counter to generate a keystream segment session encryption key
* param aucr_index    paket index
* param aucr_ssrc     paket ssrc
* param auchr_help3   generated keystream segment
*/
static void m_generate_keystream_segment( int imp_counter,
                                          unsigned char *aucrp_index, unsigned char *aucrp_ssrc, struct dsd_keys *adsp_keys,
                                          unsigned char *auchrp_help3 )
{
    unsigned char uchrl_term1[16], uchrl_term2[16], uchrl_term3[16];
    unsigned char uchrl_help2[16], uchrl_ivector[16];
    struct ds_aes_key_t  imrl_enckeybyte;


    memcpy( uchrl_term1, adsp_keys->uchrc_salting_key, HL_SALT_LENGTH );
	uchrl_term1[HL_SALT_LENGTH] = uchrl_term1[HL_SALT_LENGTH + 1] = 0;

	memcpy( uchrl_term2, aucrp_index, HL_SALT_LENGTH );
	uchrl_term2[HL_SALT_LENGTH] = uchrl_term2[HL_SALT_LENGTH + 1] = 0;

	memcpy( uchrl_term3, aucrp_ssrc, 8 );
    memset( uchrl_term3 + 8, 0, sizeof(uchrl_term3) - 8 );

    int iml_1;
    for (iml_1 = 0; iml_1 < HL_KEY_LENGTH; iml_1++)
       uchrl_help2[iml_1] = (unsigned char)(uchrl_term1[iml_1] ^ uchrl_term2[iml_1] ^ uchrl_term3[iml_1]);

    unsigned int uml_carry = imp_counter;
    for (iml_1 = HL_KEY_LENGTH - 1; iml_1 > -1; iml_1--)
    {
        uml_carry          = (unsigned int)uchrl_help2[iml_1] + uml_carry;
        uchrl_help2[iml_1] = (unsigned char)uml_carry;
        uml_carry >>= 8;
    }

#ifndef HL_UNIX
#ifdef B110912
    m_aes_set_encrypt_key( adsp_keys->uchrc_encr_key, 4, (unsigned int *)&imrl_enckeybyte );
#else
    m_aes_set_encrypt_key( adsp_keys->uchrc_encr_key, 4, (ds_aes_key *) &imrl_enckeybyte );
#endif
#else
    m_aes_set_encrypt_key( adsp_keys->uchrc_encr_key, 4, (ds_aes_key *) &imrl_enckeybyte );
#endif

	memset( uchrl_ivector, 0, sizeof(uchrl_ivector) );
#ifndef HL_UNIX
#ifdef B110912
    m_aes_cbc_encrypt( uchrl_help2, auchrp_help3, (unsigned int *)&imrl_enckeybyte, 1, uchrl_ivector, 10 );
#else
    m_aes_cbc_encrypt( uchrl_help2, auchrp_help3, (ds_aes_key *) &imrl_enckeybyte, 1, uchrl_ivector, 10 );
#endif
#else
    m_aes_cbc_encrypt( uchrl_help2, auchrp_help3, (ds_aes_key *) &imrl_enckeybyte, 1, uchrl_ivector, 10 );
#endif

}; // void m_generate_keystream_segment( int, unsigned char*, unsigned char*, struct dsd_keys *, unsigned char * )


static void m_encrypt( unsigned long    uinp_ssrc,
                       int              imp_roc,
                       int              imp_seqno,
                       unsigned char   *auchrp_payload,
                       int              imp_length,
                       struct dsd_keys *adsp_keys,
                       unsigned char   *auchrp_enc_payload )
{
    // derivation of session keys is done earlier
    // derivation of the keystream
    int iml_payload_len = imp_length;
    int iml_end         = imp_length % 16;
    int iml_segments    = iml_payload_len / 16;
    unsigned char uchrl_index[14], uchrl_ssrc[8], uchrl_keysegm[16];


    memset( uchrl_index, 0, sizeof(uchrl_index) );
    memset( uchrl_ssrc, 0, sizeof(uchrl_ssrc) );

    //compute the index as unsigned char array
    long long ill_index = imp_roc * (unsigned int)(1 << 16) + imp_seqno;

    int iml_1 = 0;
    while (ill_index / 256 > 0)
    {
       uchrl_index[13 - iml_1] = (unsigned char)(ill_index % 256);
       iml_1++;
       ill_index /= 256;
    }
    uchrl_index[13  - iml_1] = (unsigned char)(ill_index % 256);

    //compute the ssrc as unsigned char array
    iml_1 = 0;
    while (uinp_ssrc / 256 > 0)
    {
       uchrl_ssrc[7 - iml_1] = (unsigned char)(uinp_ssrc % 256);
       iml_1++;
       uinp_ssrc /= 256;
    }
    uchrl_ssrc[7 - iml_1] = (unsigned char)(uinp_ssrc % 256);


    for (iml_1 = 0; iml_1 < iml_segments ; iml_1++)
    {  // compute the current stream segment and add it to the key stream
       m_generate_keystream_segment( iml_1, uchrl_index, uchrl_ssrc, adsp_keys, uchrl_keysegm );

       for (int iml_2 = 0; iml_2 < HL_KEY_LENGTH; iml_2++)
          auchrp_enc_payload[iml_1 * HL_KEY_LENGTH + iml_2] = (unsigned char)(uchrl_keysegm[iml_2] ^ auchrp_payload[iml_1 * HL_KEY_LENGTH +  iml_2]);
    }

    //If payload fits in 1 segment we still have to generate the key segment
    //If payload size % 16 != 0 we have to generate an extra key segment (to encrpyt the additional bytes)
    if (iml_end != 0)
    {
        m_generate_keystream_segment( iml_1, uchrl_index, uchrl_ssrc, adsp_keys, uchrl_keysegm );
    }

    //encrypt the remaining bytes (imp_length % 16)
    for (iml_1 = 0; iml_1 < iml_end; iml_1++)
       auchrp_enc_payload[iml_segments * HL_KEY_LENGTH + iml_1] = (unsigned char)(uchrl_keysegm[iml_1] ^ auchrp_payload[iml_segments * HL_KEY_LENGTH + iml_1]);

} // void m_encrypt( unsigned long, int, int, unsigned char *,int, struct dsd_keys *, unsigned char * )


static void m_decode_base64( char* achrp_masters, struct dsd_keys *adsp_keys )
{
    // in accordance with rfc4568
    unsigned char uchrl_masters[HL_KEY_LENGTH + HL_SALT_LENGTH];
    unsigned char uchrl_help1[16];


	// decode base64-characters...
	// shorten the length, if we find pad-characters...
    int iml_len_masters = 40;
	while (achrp_masters[iml_len_masters - 1] == '=')
        iml_len_masters--;

    // step through all characters...
    int iml_in = 0, iml_out = 0;
    int imrl_in[4];
    while (iml_in <= iml_len_masters - 4)
    {
        imrl_in[0] = achrp_masters[iml_in++];  imrl_in[1] = achrp_masters[iml_in++];
        imrl_in[2] = achrp_masters[iml_in++];  imrl_in[3] = achrp_masters[iml_in++];

        uchrl_masters[iml_out++] = ucrs_decr[imrl_in[0]] << 2         | ucrs_decr[imrl_in[1]] >> 4;
        uchrl_masters[iml_out++] = (ucrs_decr[imrl_in[1]] & 0xf) << 4 | ucrs_decr[imrl_in[2]] >> 2;
        uchrl_masters[iml_out++] = (ucrs_decr[imrl_in[2]] & 0x3) << 6 | ucrs_decr[imrl_in[3]];
    }; // while()

    // check the remaining rest of the input string
    if (iml_in < iml_len_masters)
    {
      imrl_in[0] = achrp_masters[iml_in++];  imrl_in[1] = achrp_masters[iml_in++];
      uchrl_masters[iml_out++] = ucrs_decr[imrl_in[0]] << 2 | ucrs_decr[imrl_in[1]] >> 4;

      if (iml_in < iml_len_masters)
      {
        imrl_in[2] = achrp_masters[iml_in];
        uchrl_masters[iml_out] = (ucrs_decr[imrl_in[1]] & 0xf) << 4 | ucrs_decr[imrl_in[2]] >> 2;
      }
    }

    memcpy( adsp_keys->uchrc_master_key, uchrl_masters, HL_KEY_LENGTH );
    memcpy( adsp_keys->uchrc_master_salt, uchrl_masters + HL_KEY_LENGTH, HL_SALT_LENGTH );

    // the needed new derivation of the session keys with the received masters
    // derivation of session keys and of the encryption key
    m_derive_session_keys( 0, 0, adsp_keys, uchrl_help1 );
    memcpy( adsp_keys->uchrc_encr_key, uchrl_help1, HL_KEY_LENGTH );

    // derivation of the auth. key
    m_derive_session_keys( 1, 0, adsp_keys, uchrl_help1 );  //this is only temporary with help1 and so on further
    memcpy( adsp_keys->uchrc_auth_key, uchrl_help1, HL_KEY_LENGTH );

    // generation of the bytes 17-20
    m_derive_session_keys( 1, 1, adsp_keys, uchrl_help1 );
    memcpy( adsp_keys->uchrc_auth_key + HL_KEY_LENGTH, uchrl_help1, 4 );

    // derivation of the salting key
    m_derive_session_keys( 2, 0, adsp_keys, uchrl_help1 );
    memcpy( adsp_keys->uchrc_salting_key, uchrl_help1, HL_SALT_LENGTH );

    adsp_keys->uinc_roc = 0;
    adsp_keys->uinc_seqno = 0;

}; // m_decodebase64_masters( char *, struct dsd_keys * )


static int m_to_roc( char            *achp_inp,
                     char            *achp_out,
                     int              imp_packet_len,
                     unsigned char   *auchrp_payload,
                     int              imp_payload_length,
                     struct dsd_keys *adsp_keys )
{
    unsigned char uchrl_auth_tag[10];
    unsigned char uchrl_auth_mtag[10];
    int iml_auth_tag_length = sizeof(uchrl_auth_tag);


    // hold the auth. tag from the incoming paket
    memcpy( uchrl_auth_tag,
            auchrp_payload + imp_payload_length - sizeof(uchrl_auth_tag),
            sizeof(uchrl_auth_tag) );
    // The last ten bytes belong to auth.tag, so they are not in the authenticated part
    int iml_auth_part_length = imp_packet_len - sizeof(uchrl_auth_tag);

    // set the seqno for the next assignment
    unsigned short uinl_seqno = ntohs( *(unsigned short *)(achp_inp + 2) );

    memcpy( achp_out, achp_inp, iml_auth_part_length );
    unsigned char *auchrl_auth_part = (unsigned char *)achp_out;
    iml_auth_part_length = imp_packet_len - iml_auth_tag_length;

    // set the roc to the guessed value and check the authentication
    unsigned int uml_v = 0;
    if (adsp_keys->uinc_seqno == 0 && adsp_keys->uinc_roc == 0)
    {
      m_make_auth_tag( auchrl_auth_part, iml_auth_part_length, adsp_keys->uinc_roc,
                       adsp_keys->uchrc_auth_key, uchrl_auth_mtag );

      if (memcmp( uchrl_auth_mtag, uchrl_auth_tag, sizeof(uchrl_auth_tag) ) != 0)
        // server error: authentication fault
        return -1;
      else
        adsp_keys->uinc_seqno = uinl_seqno;  // for the first received message
    }
    else
    { // default value
      uml_v = adsp_keys->uinc_roc;
      // test only if new is below uim_range
      if (uinl_seqno < HL_MAX_SEQNO)
      { // if old number is larger and difference is more than range: rollover, else
        // the rollover has happened before
        if (adsp_keys->uinc_seqno > uinl_seqno && adsp_keys->uinc_seqno - uinl_seqno > HL_MAX_SEQNO)
          uml_v = adsp_keys->uinc_roc + 1;
      }
      else
      { if (adsp_keys->uinc_seqno < uinl_seqno && uinl_seqno - adsp_keys->uinc_seqno > HL_MAX_SEQNO)
           uml_v = adsp_keys->uinc_roc - 1;
      }

      m_make_auth_tag( auchrl_auth_part, iml_auth_part_length, uml_v,
                       adsp_keys->uchrc_auth_key, uchrl_auth_mtag );

      if (memcmp( uchrl_auth_mtag, uchrl_auth_tag, sizeof(uchrl_auth_tag) ) != 0)
        // server error: authentication fault
        return -1;
      else
      { if (adsp_keys->uinc_roc == uml_v && adsp_keys->uinc_seqno < uinl_seqno)
          adsp_keys->uinc_seqno = uinl_seqno;
        else
        { if (adsp_keys->uinc_roc + 1 == uml_v)
          { adsp_keys->uinc_roc++;
            adsp_keys->uinc_seqno = uinl_seqno;
          }
        }
      }
    }

    return 0;

} // m_to_roc( char *, char *, int, unsigned char *, int, dsd_keys * )


static void m_make_auth_tag( unsigned char* auchrp_auth_part,
                             int            imp_len_authpart,
                             unsigned int   uinp_roc,
                             unsigned char* auchrp_auth_key,
                             unsigned char* auchrp_auth_tag )
{
    // append zeroes to k
    unsigned char uchrl_k64_auth[64], uchrl_xor[64];
    unsigned char uchrl_digest_in[20], uchrl_digest_out[20];
    unsigned char uchrl_roc[4] = { 0, 0, 0, 0 };
    int imrl_sha[24];
    int iml_1;


    // making the padding for the roc as unsigned char array
    iml_1 = 0;
    while (uinp_roc / 256 > 0)
    {
        uchrl_roc[3 - iml_1] = (unsigned char)(uinp_roc % 256);
        iml_1++;
        uinp_roc /= 256;
    }
    uchrl_roc[3 - iml_1] = (unsigned char)(uinp_roc % 256);

    //add roc array to auth.part
    memcpy( auchrp_auth_part + imp_len_authpart, uchrl_roc, imp_len_authpart );
    memcpy( uchrl_k64_auth, auchrp_auth_key, 20 );
    memset( uchrl_k64_auth + 20, 0, sizeof(uchrl_k64_auth) - 20 );

    // make xor(k64_auth, ipad)
    for (iml_1 = 0; iml_1 < 64; iml_1++)
       uchrl_xor[iml_1] = uchrl_k64_auth[iml_1] ^ (unsigned char)0x36;

    SHA1_Init( imrl_sha );
#ifndef HL_UNIX
#ifdef B110912
    SHA1_Update( (unsigned int *)imrl_sha, (char *)uchrl_xor, 0, 64 );
    SHA1_Update( (unsigned int *)imrl_sha, (char*)auchrp_auth_part, 0, imp_len_authpart + 4 );
    SHA1_Final( (unsigned int *)imrl_sha, (char*)uchrl_digest_in, 0 );
#else
    SHA1_Update( imrl_sha, (char *)uchrl_xor, 0, 64 );
    SHA1_Update( imrl_sha, (char*)auchrp_auth_part, 0, imp_len_authpart + 4 );
    SHA1_Final( imrl_sha, (char*)uchrl_digest_in, 0 );
#endif
#else
    SHA1_Update( imrl_sha, (char *)uchrl_xor, 0, 64 );
    SHA1_Update( imrl_sha, (char*)auchrp_auth_part, 0, imp_len_authpart + 4 );
    SHA1_Final( imrl_sha, (char*)uchrl_digest_in, 0 );
#endif

    // make xor(k64_auth, opad)
    for (iml_1 = 0; iml_1 < 64; iml_1++)
       uchrl_xor[iml_1] = uchrl_k64_auth[iml_1] ^ (unsigned char)0x5c;

    SHA1_Init( imrl_sha );
#ifndef HL_UNIX
#ifdef B110912
    SHA1_Update( (unsigned int *)imrl_sha, (char *)uchrl_xor, 0, 64 );
    SHA1_Update( (unsigned int *)imrl_sha, (char *)uchrl_digest_in, 0, 20 );
    SHA1_Final( (unsigned int *)imrl_sha, (char*)uchrl_digest_out, 0 );
#else
    SHA1_Update( imrl_sha, (char *)uchrl_xor, 0, 64 );
    SHA1_Update( imrl_sha, (char *)uchrl_digest_in, 0, 20 );
    SHA1_Final( imrl_sha, (char*)uchrl_digest_out, 0 );
#endif
#else
    SHA1_Update( imrl_sha, (char *)uchrl_xor, 0, 64 );
    SHA1_Update( imrl_sha, (char *)uchrl_digest_in, 0, 20 );
    SHA1_Final( imrl_sha, (char*)uchrl_digest_out, 0 );
#endif

    // the authentication tag has to be 80 bits long, so it has to be
    // truncated to the 80 left-most bits = 10 left-most bytes
    memcpy( auchrp_auth_tag, uchrl_digest_out, 10 );

}; // void m_make_auth_tag( unsigned char *, int, unsigned int, unsigned char *, unsigned char * )
