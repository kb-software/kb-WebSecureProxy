//**********************************************************
//
// AES - EAX mode module
// For AES 128/192/256
//
//**********************************************************
#include <hob-encry-1.h>
#include "hobeax.h"
#include <memory.h>


#define EAX_BLOCK_SIZE      AES_BLOCK_SIZE
#define EAX_BLOCK_MASK      (EAX_BLOCK_SIZE-1)



// Increment the CTR counter
static void m_increment_counter(unsigned char * abyrp_count)
{
  int iml_i;

  iml_i = EAX_BLOCK_SIZE-1;
  while(iml_i >= 0)
  {
    abyrp_count[iml_i]++;
    if(abyrp_count[iml_i] != 0)
      return;
    iml_i--;
  }  
}
//==========================================================================
// Initialize context and set the AES key/rounds
//
// Input parameters:  unsigned char * abyrp_key		key buffer
//                    unsigned int    uimp_key_len	size of key in bytes
//		      dsd_eax_ctx *   adsp_ctx		context structure
// Returns: nothing
//==========================================================================
void m_eax_init_ctx(unsigned char * abyrp_key, unsigned int uimp_key_len,
	            dsd_eax_ctx * adsp_ctx)
{
  static unsigned char byrg_omac_pad_xor_array[4] = {0x00,0x87,0x0E,0x89};
  unsigned char uchl_c, *abyrl_p;
  unsigned int uiml_i;

  // clear context
  memset(adsp_ctx, 0, sizeof(dsd_eax_ctx));

  // setup AES key
  m_aes_set_encrypt_key(abyrp_key,uimp_key_len/4,adsp_ctx->dsd_aes);

  if(uimp_key_len == 16)
    adsp_ctx->uimd_rounds = 10;
  else if(uimp_key_len == 24)
    adsp_ctx->uimd_rounds = 12;
  else
    adsp_ctx->uimd_rounds = 14;

  // generate E(0) for OMAC padding
  m_aes_ecb_encrypt(adsp_ctx->byrd_pad_buf,adsp_ctx->byrd_pad_buf,
                    adsp_ctx->dsd_aes,1,adsp_ctx->uimd_rounds);

  // compute 2 * E(0) and 4 * E(0)
  // over GF(2^128) mod x^128 + x^7 + x^2 + x + 1
  abyrl_p = adsp_ctx->byrd_pad_buf;
  uchl_c = *abyrl_p >> 6;

  for(uiml_i = 0;uiml_i < EAX_BLOCK_SIZE-1;uiml_i++)
  {
    *(abyrl_p + 16) = (*abyrl_p << 2) | (*(abyrl_p + 1) >> 6);
    *abyrl_p        = (*abyrl_p << 1) | (*(abyrl_p + 1) >> 7);
    abyrl_p++;
  }
  *(abyrl_p + 16) = (*abyrl_p << 2) ^ byrg_omac_pad_xor_array[uchl_c];
  uchl_c >>= 1;
  *(abyrl_p + 15) ^= uchl_c;
  *abyrl_p = (*abyrl_p << 1) ^ byrg_omac_pad_xor_array[uchl_c];
}
//=======================================================================
// Initialize context for a new message
//
// Input parameters: unsigned char *  abyrp_nonce	nonce buffer
//		     unsigned int     uimp_nonce_len	size of nonce
//		     dsd_eax_ctx      adsp_ctx		context structure
// Returns: nothing
//=======================================================================
void m_eax_init_msg(unsigned char * abyrp_nonce,
	            unsigned int uimp_nonce_len,
	            dsd_eax_ctx * adsp_ctx)
{
  unsigned int uiml_i = 0, uiml_index = 0;
  unsigned char * abyrl_p;

  // Clear nonce, header and message buffers
  memset(adsp_ctx->byrd_nonce_buf, 0, EAX_BLOCK_SIZE);
  memset(adsp_ctx->byrd_header_buf, 0, EAX_BLOCK_SIZE);
  memset(adsp_ctx->byrd_message_buf, 0, EAX_BLOCK_SIZE);

  // Set header OMAC start values
  adsp_ctx->uimd_header_count = 0;
  adsp_ctx->byrd_header_buf[EAX_BLOCK_SIZE-1] = 1;

  // Set message OMAC start values
  adsp_ctx->uimd_msg_ecount = 0;		// encryption data count
  adsp_ctx->uimd_msg_acount = 0;		// authentication data count
  adsp_ctx->byrd_message_buf[EAX_BLOCK_SIZE-1] = 2;

  if(uimp_nonce_len != 0)
  {
    uiml_index = EAX_BLOCK_SIZE;

    // update the OMAC for the nonce
    uiml_i = 0;
    while(uiml_i < uimp_nonce_len)
    {
      if(uiml_index == EAX_BLOCK_SIZE)
      {
        m_aes_ecb_encrypt(adsp_ctx->byrd_nonce_buf,adsp_ctx->byrd_nonce_buf,
		          adsp_ctx->dsd_aes,1,adsp_ctx->uimd_rounds);
        uiml_index = 0;
      }
      adsp_ctx->byrd_nonce_buf[uiml_index++] ^= abyrp_nonce[uiml_i++];
    }

    // pad OMAC for the nonce
    abyrl_p = adsp_ctx->byrd_pad_buf;
    if(uiml_index < EAX_BLOCK_SIZE)
    {
      adsp_ctx->byrd_nonce_buf[uiml_index] ^= 0x80;
      abyrl_p += 16;
    }
    for(uiml_i=0;uiml_i < EAX_BLOCK_SIZE;uiml_i++)
      adsp_ctx->byrd_nonce_buf[uiml_i] ^= abyrl_p[uiml_i];
  }
  else
    memcpy(adsp_ctx->byrd_nonce_buf,adsp_ctx->byrd_pad_buf,EAX_BLOCK_SIZE);

  // generate final OMAC of nonce
  m_aes_ecb_encrypt(adsp_ctx->byrd_nonce_buf,adsp_ctx->byrd_nonce_buf,
                    adsp_ctx->dsd_aes,1,adsp_ctx->uimd_rounds);

  // copy result to counter for AES-CTR mode
  memcpy(adsp_ctx->byrd_counter,adsp_ctx->byrd_nonce_buf,EAX_BLOCK_SIZE);
}
//=======================================================================
// Update header OMAC
// Final OMAC is done in m_eax_generate_tag
//
// Input parameters: unsigned char *  abyrp_header	header data
//		     unsigned int     uimp_header_len	size of data
//		     dsd_eax_ctx *    adsp_ctx		context structure
// Returns: nothing
//=======================================================================
void m_eax_update_header_omac(unsigned char * abyrp_header,
                              unsigned int uimp_header_len,
                              dsd_eax_ctx * adsp_ctx)
{
  unsigned int uiml_count = 0, uiml_index;

  if(uimp_header_len == 0)
    return;

  uiml_index = adsp_ctx->uimd_header_count & EAX_BLOCK_MASK;
  if(uiml_index != 0)
  {
    while(uiml_count < uimp_header_len && uiml_index < EAX_BLOCK_SIZE)
    {
      adsp_ctx->byrd_header_buf[uiml_index] ^= abyrp_header[uiml_count];
      uiml_count++;
      uiml_index++;
    }
  }

  while(uiml_count < uimp_header_len)
  {
    if(uiml_index == EAX_BLOCK_SIZE || uiml_index == 0)
    {
      m_aes_ecb_encrypt(adsp_ctx->byrd_header_buf,adsp_ctx->byrd_header_buf,
                        adsp_ctx->dsd_aes,1,adsp_ctx->uimd_rounds);
      uiml_index = 0;
    }
    adsp_ctx->byrd_header_buf[uiml_index++] ^= abyrp_header[uiml_count++];
  }
  adsp_ctx->uimd_header_count += uiml_count;
}
//=======================================================================
// Update ciphertext OMAC
// Final OMAC is done in m_eax_generate_tag
//
// Input parameters: unsigned char * abyrp_data		ciphertext
//		     unsigned int    uimp_data_len	size of data
//		     dsd_eax_ctx *   adsp_ctx		context structure
// Returns: nothing
//=======================================================================
void m_eax_update_ciphertext_omac(unsigned char * abyrp_data,
                                  unsigned int uimp_data_len,
                                  dsd_eax_ctx * adsp_ctx)
{
  unsigned int uiml_count = 0, uiml_index;

  if(uimp_data_len == 0)
    return;

  uiml_index = adsp_ctx->uimd_msg_acount & EAX_BLOCK_MASK;
  if(uiml_index != 0)
  {
    while(uiml_count < uimp_data_len && uiml_index < EAX_BLOCK_SIZE)
      adsp_ctx->byrd_message_buf[uiml_index++] ^= abyrp_data[uiml_count++];
  }

  while(uiml_count < uimp_data_len)
  {
    if(uiml_index == EAX_BLOCK_SIZE || uiml_index == 0)
    {
      m_aes_ecb_encrypt(adsp_ctx->byrd_message_buf,adsp_ctx->byrd_message_buf,
                        adsp_ctx->dsd_aes,1,adsp_ctx->uimd_rounds);
      uiml_index = 0;
    }
    adsp_ctx->byrd_message_buf[uiml_index++] ^= abyrp_data[uiml_count++];
  }
  adsp_ctx->uimd_msg_acount += uiml_count;
}
//=======================================================================
// Encrypt/Decrypt message data
//
// Input parameters: unsigned char *  abyrp_message	message in/out
//                   unsigned int     uimp_message_len	size of message
//                   dsd_eax_ctx *    adsp_ctx		context structure
// Returns: nothing
//=======================================================================
void m_eax_crypt_data(unsigned char * abyrp_message,
	              unsigned int uimp_message_len,
                      dsd_eax_ctx * adsp_ctx)
{
  unsigned int uiml_count = 0, uiml_index;

  if(uimp_message_len == 0)
    return;

  uiml_index = adsp_ctx->uimd_msg_ecount & EAX_BLOCK_MASK;
  if(uiml_index != 0)
  {
    while(uiml_count < uimp_message_len && uiml_index < EAX_BLOCK_SIZE)
      abyrp_message[uiml_count++] ^= adsp_ctx->byrd_enc_counter[uiml_index++];
  }

  while(uiml_count < uimp_message_len)
  {
    if(uiml_index == EAX_BLOCK_SIZE || uiml_index == 0)
    {
      m_aes_ecb_encrypt(adsp_ctx->byrd_counter,adsp_ctx->byrd_enc_counter,
                        adsp_ctx->dsd_aes,1,adsp_ctx->uimd_rounds);
      m_increment_counter(adsp_ctx->byrd_counter);
      uiml_index = 0;
    }
    abyrp_message[uiml_count++] ^= adsp_ctx->byrd_enc_counter[uiml_index++];
  }
  adsp_ctx->uimd_msg_ecount += uiml_count;
}
//=======================================================================
// Generate the authentication tag
// Finalizes header and cipher/message OMAC
//
// Input parameters: unsigned char * abyrp_tag		destination buffer
//		     unsigned int    uimp_tag_len	size of buffer
//		     dsd_eax_ctx *   adsp_ctx		context structure
// Returns: int Status - 0 o.k., else error/warning occured
//=======================================================================
int m_eax_generate_tag(unsigned char * abyrp_tag,
                       unsigned int uimp_tag_len,
                       dsd_eax_ctx * adsp_ctx)
{
  unsigned int uiml_i;
  unsigned char * abyrl_p;

  if(adsp_ctx->uimd_msg_ecount > 0 &&
     adsp_ctx->uimd_msg_acount != adsp_ctx->uimd_msg_ecount)
    return(-1);

  // final pad OMAC of header
  uiml_i = adsp_ctx->uimd_header_count & EAX_BLOCK_MASK;
  abyrl_p = adsp_ctx->byrd_pad_buf;
  if(uiml_i != 0)
  {
    adsp_ctx->byrd_header_buf[uiml_i] ^= 0x80;
    abyrl_p += 16;
  }
  for(uiml_i = 0;uiml_i < EAX_BLOCK_SIZE; uiml_i++)
    adsp_ctx->byrd_header_buf[uiml_i] ^= abyrl_p[uiml_i];
  m_aes_ecb_encrypt(adsp_ctx->byrd_header_buf, adsp_ctx->byrd_header_buf,
                    adsp_ctx->dsd_aes,1,adsp_ctx->uimd_rounds);

  // final pad OMAC of ciphertext
  uiml_i = adsp_ctx->uimd_msg_acount & EAX_BLOCK_MASK;
  abyrl_p = adsp_ctx->byrd_pad_buf;
  if(uiml_i != 0)
  {
    adsp_ctx->byrd_message_buf[uiml_i] ^= 0x80;
    abyrl_p += 16;
  }
  for(uiml_i = 0;uiml_i < EAX_BLOCK_SIZE; uiml_i++)
    adsp_ctx->byrd_message_buf[uiml_i] ^= abyrl_p[uiml_i];
  m_aes_ecb_encrypt(adsp_ctx->byrd_message_buf,adsp_ctx->byrd_message_buf,
                    adsp_ctx->dsd_aes,1,adsp_ctx->uimd_rounds);

  // generate final authentication tag
  for(uiml_i = 0; uiml_i < uimp_tag_len; uiml_i++)
    abyrp_tag[uiml_i] = adsp_ctx->byrd_nonce_buf[uiml_i] ^
                        adsp_ctx->byrd_message_buf[uiml_i] ^
                        adsp_ctx->byrd_header_buf[uiml_i];

  if(adsp_ctx->uimd_msg_ecount == adsp_ctx->uimd_msg_acount)
    return(0);
  else
    return(1);				// issue warning, not same length!!
}
//===============================================================
// End EAX processing, clear the context
//
// Input parameters: dsd_eax_ctx *   adsp_ctx	context structure
// Returns: nothing
//===============================================================
void m_eax_cleanup(dsd_eax_ctx * adsp_ctx)
{
  memset(adsp_ctx, 0, sizeof(dsd_eax_ctx));
}
//=======================================================================
// Encrypt message and generate authentication OMAC
//
// Input parameters: unsigned char * abyrp_data		message
//		     unsigned int    uimp_data_len	size of message
//		     dsd_eax_ctx *   adsp_ctx		context structure
// Returns: nothing
//=======================================================================
void m_eax_encrypt(unsigned char * abyrp_data,
                   unsigned int uimp_data_len,
                   dsd_eax_ctx * adsp_ctx)
{
  m_eax_crypt_data(abyrp_data, uimp_data_len, adsp_ctx);
  m_eax_update_ciphertext_omac(abyrp_data, uimp_data_len, adsp_ctx);
}
//=======================================================================
// Decrypt message and generate authentication OMAC
//
// Input parameters: unsigned char * abyrp_data		cipher text
//		     unsigned int    uimp_data_len	size of text
//		     dsd_eax_ctx *   adsp_ctx		context structure
// Returns: nothing
//=======================================================================
void m_eax_decrypt(unsigned char * abyrp_data,
                   unsigned int uimp_data_len,
                   dsd_eax_ctx * adsp_ctx)
{
  m_eax_update_ciphertext_omac(abyrp_data, uimp_data_len, adsp_ctx);
  m_eax_crypt_data(abyrp_data, uimp_data_len, adsp_ctx);
}
//=========================================================================
// Encrypt a full message with nonce and header data
//
// Input parameters: unsigned char * abyrp_nonce	the nonce data
//		     unsigned int    uimp_nonce_len	size of nonce
//		     unsigned char * abyrp_message	the message data
//		     unsigned int    uimp_message_len	size of message
//		     unsigned char * abyrp_header	header data/NULL
//		     unsigned int    uimp_header_len	size of header/0
//		     unsigned char * abyrp_tag		destination for tag
//		     unsigned int    uimp_tag_len	size of tag buffer
//		     dsd_eax_ctx *   adsp_ctx		context structure
// Returns: int Status - 0 o.k., else error occured
//=========================================================================
int eax_encrypt_message(unsigned char * abyrp_nonce,
		        unsigned int uimp_nonce_len,
		        unsigned char * abyrp_message,
		        unsigned int uimp_message_len,
		        unsigned char * abyrp_header,
		        unsigned int uimp_header_len,
                        unsigned char * abyrp_tag,
                        unsigned int uimp_tag_len,
                        dsd_eax_ctx * adsp_ctx)
{
  int iml_retcode;

  m_eax_init_msg(abyrp_nonce,uimp_nonce_len,adsp_ctx);
  m_eax_update_header_omac(abyrp_header,uimp_header_len,adsp_ctx);
  m_eax_encrypt(abyrp_message,uimp_message_len,adsp_ctx);
  iml_retcode = m_eax_generate_tag(abyrp_tag,uimp_tag_len,adsp_ctx);
  if(iml_retcode != 0)
    return(-1);
  return(0);
}
//=========================================================================
// Decrypt a full message with nonce and header data
//
// Input parameters: unsigned char * abyrp_nonce	the nonce data
//		     unsigned int    uimp_nonce_len	size of nonce
//		     unsigned char * abyrp_message	the message data
//		     unsigned int    uimp_message_len	size of message
//		     unsigned char * abyrp_header	header data/NULL
//		     unsigned int    uimp_header_len	size of header/0
//		     unsigned char * abyrp_tag		source of tag
//		     unsigned int    uimp_tag_len	size of tag
//		     dsd_eax_ctx *   adsp_ctx		context structure
// Returns: int Status - 0 o.k., else error occured
//=========================================================================
int eax_decrypt_message(unsigned char * abyrp_nonce,
                        unsigned int uimp_nonce_len,
                        unsigned char * abyrp_message,
                        unsigned int uimp_message_len,
                        unsigned char * abyrp_header,
                        unsigned int uimp_header_len,
                        unsigned char * abyrp_tag,
                        unsigned int uimp_tag_len,
                        dsd_eax_ctx * adsp_ctx)
{
  unsigned char byrl_temp_tag[EAX_BLOCK_SIZE];
  int iml_retcode;

  m_eax_init_msg(abyrp_nonce,uimp_nonce_len,adsp_ctx);
  m_eax_update_header_omac(abyrp_header,uimp_header_len,adsp_ctx);
  m_eax_decrypt(abyrp_message,uimp_message_len,adsp_ctx);
  iml_retcode = m_eax_generate_tag(byrl_temp_tag,uimp_tag_len,adsp_ctx);
  if(iml_retcode != 0)
    return(-1);
  if(memcmp(abyrp_tag,byrl_temp_tag,uimp_tag_len) != 0)
    return(-1);
  return(0);
}
