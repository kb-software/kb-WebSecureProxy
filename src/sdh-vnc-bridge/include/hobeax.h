#ifndef _EAX_HEADER_
#define _EAX_HEADER_

/* The EAX-AES  context  */
#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    unsigned char  byrd_header_buf[AES_BLOCK_SIZE];  // Header OMAC buffer
    unsigned char  byrd_message_buf[AES_BLOCK_SIZE]; // Message OMAC buffer
    unsigned char  byrd_nonce_buf[AES_BLOCK_SIZE];   // Nonce OMAC buffer
    unsigned char  byrd_pad_buf[AES_BLOCK_SIZE*2];   // OMAC padding data
    unsigned char  byrd_counter[AES_BLOCK_SIZE];     // CTR counter
    unsigned char  byrd_enc_counter[AES_BLOCK_SIZE]; // encrypted CTR
    unsigned int   uimd_header_count;		// Header data count
    unsigned int   uimd_msg_ecount;		// Encryption data count
    unsigned int   uimd_msg_acount;		// Authentication data count
    unsigned int   uimd_rounds;			// AES rounds count
    ds_aes_key     dsd_aes[1];			// AES context
} dsd_eax_ctx;


extern void m_eax_init_ctx(unsigned char * abyrp_key, unsigned int uimp_key_len,
	                   dsd_eax_ctx * adsp_ctx);

extern void m_eax_init_msg(unsigned char * abyrp_nonce,
	                   unsigned int uimp_nonce_len,
	                   dsd_eax_ctx * adsp_ctx);

extern void m_eax_update_header_omac(unsigned char * abyrp_header,
		                     unsigned int uimp_header_len,
		                     dsd_eax_ctx * adsp_ctx);

extern void m_eax_update_ciphertext_omac(unsigned char * abyrp_data,
                                         unsigned int uimp_data_len,
                                         dsd_eax_ctx * adsp_ctx);

extern void m_eax_crypt_data(unsigned char * abyrp_data,
	                     unsigned int uimp_data_len,
                             dsd_eax_ctx * adsp_ctx);

extern int m_eax_generate_tag(unsigned char * abyrp_tag,
                              unsigned int uimp_tag_len,
                              dsd_eax_ctx * adsp_ctx);

extern void m_eax_cleanup(dsd_eax_ctx * adsp_ctx);

extern void m_eax_encrypt(unsigned char * abyrp_data,
                          unsigned int uimp_data_len,
                          dsd_eax_ctx * adsp_ctx);

extern void m_eax_decrypt(unsigned char * abyrp_data,
                          unsigned int uimp_data_len,
                          dsd_eax_ctx * adsp_ctx);

extern int eax_encrypt_message(unsigned char * abyrp_nonce,
	                       unsigned int uimp_nonce_len,
                               unsigned char * abyrp_message,
                               unsigned int uimp_message_len,
                               unsigned char * abyrp_header,
                               unsigned int uimp_header_len,
                               unsigned char * abyrp_tag,
                               unsigned int uimp_tag_len,
                               dsd_eax_ctx * adsp_ctx);

extern int eax_decrypt_message(unsigned char * abyrp_nonce,
                               unsigned int uimp_nonce_len,
                               unsigned char * abyrp_message,
                               unsigned int uimp_message_len,
                               unsigned char * abyrp_header,
                               unsigned int uimp_header_len,
                               unsigned char * abyrp_tag,
                               unsigned int uimp_tag_len,
                               dsd_eax_ctx * adsp_ctx);

#ifdef __cplusplus
}
#endif

#endif
