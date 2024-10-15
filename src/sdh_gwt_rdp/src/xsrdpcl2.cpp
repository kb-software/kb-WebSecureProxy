#include <hob-rdpclient2.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <xs-tk-gather-tools-01.cpp>

#define SM_MINIFY_WORKAREAS 0

#define SM_TRACE_RDP_CLIENT		0
#define SM_TRACE_RDP_TRAFFIC		0
#define MS_TRACE_RDP_TRAFFIC_SIZEONLY		0
#define MS_TRACE_RDP_TRAFFIC_MAXLEN		128
#define SM_TRACE_CREDSSP_TRAFFIC	0
#define SM_TRACE_SSL_BUG			0
#define SM_TRACE_NTLM_TRAFFIC		0

#define HL_AUX_SSL_FUNCTION(context, function) context->function
#if HL_USE_AUX_SSL_FUNCTIONS
#define HL_FromASN1CertToCertStruc adsl_client->adsc_aux_ssl_functions->FromASN1CertToCertStruc
#define HL_FromASN1_DNCommonNameToString adsl_client->adsc_aux_ssl_functions->FromASN1_DNCommonNameToString
#define HL_FreeCertStruc adsp_client->adsc_aux_ssl_functions->FreeCertStruc
#else
#define HL_FromASN1CertToCertStruc FromASN1CertToCertStruc
#define HL_FromASN1_DNCommonNameToString FromASN1_DNCommonNameToString
#define HL_FreeCertStruc FreeCertStruc
#endif

static BOOL m_unicode_string_empty(struct dsd_unicode_string* adsp_ucs) {
	if(adsp_ucs->imc_len_str > 0)
		return FALSE;
	if(adsp_ucs->imc_len_str == 0)
		return TRUE;
	int inl_res = m_len_bytes_ucs(adsp_ucs);
	if(inl_res <= 0)
		return TRUE;
	return FALSE;
}

#if 0
static BOOL m_subaux_rdpclient_2( void * vpp_userfld, int imp_func, void * ap_param, int imp_length ) {
   char       *achl1;                       /* working-variable        */
   int        iml1;                         /* working-variable        */
   struct dsd_workarea_1 *adsl_workarea_1_w1;  /* work area            */

   struct dsd_call_rdpclient_2* ADSL_CONN_1_G = ((struct dsd_call_rdpclient_2 *) vpp_userfld);
   switch (imp_func) {                      /* depend on function      */
     case DEF_AUX_GET_WORKAREA:             /* get additional work area */
     {
       if (imp_length != sizeof(struct dsd_aux_get_workarea)) return FALSE;
	   adsl_workarea_1_w1 = (struct dsd_workarea_1 *) m_aux_procalloc(ADSL_CONN_1_G->dsc_aux.amc_aux, ADSL_CONN_1_G->dsc_aux.vpc_userfld, 4096);
       adsl_workarea_1_w1->adsc_next = ADSL_CONN_1_G->adsc_workarea_1;
       ADSL_CONN_1_G->adsc_workarea_1 = adsl_workarea_1_w1;  /* set new chain */
       dsd_aux_get_workarea* ADSL_AUX_GET_WORKAREA = ((struct dsd_aux_get_workarea *) ap_param);
       ADSL_AUX_GET_WORKAREA->achc_work_area = (char *) (ADSL_CONN_1_G->adsc_workarea_1 + 1);
       ADSL_AUX_GET_WORKAREA->imc_len_work_area = 4096 - sizeof(struct dsd_workarea_1);
       return TRUE;                         /* all done                */
	 }
   }
   return ADSL_CONN_1_G->dsc_aux.amc_aux(ADSL_CONN_1_G->dsc_aux.vpc_userfld, imp_func, ap_param, imp_length);
} /* end m_subaux_rdpclient_2() */
#endif


#define HMACT64_BLOCK_LENGTH 64
#define HMACT64_STATE_IPAD_OFF  0
#define HMACT64_STATE_OPAD_OFF  HMACT64_BLOCK_LENGTH
#define HMACT64_IPAD 0x36
#define HMACT64_OPAD 0x5c
#define HMACT64_STATE_SIZE (HMACT64_BLOCK_LENGTH + HMACT64_BLOCK_LENGTH)

struct dsd_hmact64 {
	char chrc_state[HMACT64_STATE_SIZE];
	int inc_md5_state[MD5_ARRAY_SIZE];
};

/**
 * Initializes the HMACT64 digest.
 *
 * @param byr_hmac_state HMAC state handle.
 * @param ds_md5 MD5 state handle.
 * @param byr_key The key.
 * @param im_keyoff Start of the key.
 * @param im_keylen Length of the key.
 */
static void HMACT64_init(struct dsd_hmact64* adsp_hmac, const char* achp_key, int inp_keylen) {
	int length = HL_MIN(inp_keylen, HMACT64_BLOCK_LENGTH);
	int im_keyoff = 0;
	for(int i = 0; i < length; i++, im_keyoff++) {
		adsp_hmac->chrc_state[HMACT64_STATE_IPAD_OFF + i] = (char) (achp_key[im_keyoff] ^ HMACT64_IPAD);
		adsp_hmac->chrc_state[HMACT64_STATE_OPAD_OFF + i] = (char) (achp_key[im_keyoff] ^ HMACT64_OPAD);
	}
	for(int i = length; i < HMACT64_BLOCK_LENGTH; i++) {
		adsp_hmac->chrc_state[HMACT64_STATE_IPAD_OFF + i] = HMACT64_IPAD;
		adsp_hmac->chrc_state[HMACT64_STATE_OPAD_OFF + i] = HMACT64_OPAD;
	}
	MD5_Init(adsp_hmac->inc_md5_state);
	MD5_Update(adsp_hmac->inc_md5_state, adsp_hmac->chrc_state, HMACT64_STATE_IPAD_OFF, HMACT64_BLOCK_LENGTH);
}

/**
 * Updates digest with the specified data.
 *
 * @param ds_md5 MD5 state handle.
 * @param byr_data The data.
 * @param im_off Start offset.
 * @param im_len Length of data.
 */
static void HMACT64_update(struct dsd_hmact64* adsp_hmac, const char* achp_data, int inp_len) {
	MD5_Update(adsp_hmac->inc_md5_state, achp_data, 0, inp_len);
}

/**
 * Writes a digest.
 *
 * @param byr_hmac_state HMAC state handle.
 * @param ds_md5 MD5 state handle.
 * @param byr_digest Receives digest.
 * @param im_off Start offset.
 */
static void HMACT64_final(struct dsd_hmact64* adsp_hmac, char* achp_digest) {
	char chrl_temp[16];
	MD5_Final(adsp_hmac->inc_md5_state, chrl_temp, 0);
	MD5_Init(adsp_hmac->inc_md5_state);
	MD5_Update(adsp_hmac->inc_md5_state, adsp_hmac->chrc_state, HMACT64_STATE_OPAD_OFF, HMACT64_BLOCK_LENGTH);
	MD5_Update(adsp_hmac->inc_md5_state, chrl_temp, 0, 16);
	MD5_Final(adsp_hmac->inc_md5_state, achp_digest, 0);
}

static BOOL m_sub_get_epoch( void * ap_sub_call_1, HL_LONGLONG *ailp_epoch ) {
	struct dsd_aux_helper* adsl_aux = (struct dsd_aux_helper*)ap_sub_call_1;
	return adsl_aux->amc_aux(adsl_aux->vpc_userfld, DEF_AUX_GET_T_MSEC, ailp_epoch, sizeof(*ailp_epoch));
}

static BOOL m_sub_get_random( void* ap_sub_call_1, char *achp_random, int imp_len_random ) {
	struct dsd_aux_helper* adsl_aux = (struct dsd_aux_helper*)ap_sub_call_1;
	memset(achp_random, 0, imp_len_random);
	return adsl_aux->amc_aux(adsl_aux->vpc_userfld, DEF_AUX_RANDOM_VISIBLE, achp_random, imp_len_random);
}

void m_gssapi_ntlm_01(struct dsd_gssapi_01_call* adsp_call) {
	struct dsd_gssapi_ntlm_01* adsl_context = (struct dsd_gssapi_ntlm_01*)adsp_call->adsc_context;
	char byrl_work1[ 2048 ];           /* work area               */
	switch(adsp_call->inc_func) {
	case IM_GSSAPI_FUNC_START:
		adsl_context->dsc_base.boc_initialized = FALSE;
		adsl_context->iec_state = ied_ntlmf_invalid;
		adsp_call->inc_return = DEF_IRET_NORMAL;
		return;
	case IM_GSSAPI_FUNC_INITIALIZE_CONTEXT:
		break;
	case IM_GSSAPI_FUNC_WRAP: {
#if 0
		if(adsl_context->umc_client_seqnum == 1) {
			memset(adsl_context->chrc_client_sign_key, 0, sizeof(adsl_context->chrc_client_sign_key));
			memset(adsl_context->chrc_client_handle, 0, sizeof(adsl_context->chrc_client_handle));
		}
#endif
		char byr_msg_signature[16];
		/* Set NTLMSSP_MESSAGE_SIGNATURE.Version */
		m_write_uint32_le(byr_msg_signature, 0x00000001);
		struct dsd_hmact64 dsl_hmact64;
		HMACT64_init(&dsl_hmact64, adsl_context->chrc_client_sign_key, sizeof(adsl_context->chrc_client_sign_key));
		/* Set NTLMSSP_MESSAGE_SIGNATURE.SeqNum */
		m_write_uint32_le(byr_msg_signature+12, adsl_context->umc_client_seqnum++);
		HMACT64_update(&dsl_hmact64, byr_msg_signature+12, 4);

		struct dsd_gather_i_1_fifo dsl_fifo2;
		m_gather_fifo_init(&dsl_fifo2);
		dsd_gather_i_1* adsl_gather_tmp = adsp_call->adsc_gather_in;
		while(adsl_gather_tmp != NULL) {
			int inl_len = m_gather1_copy(&adsl_gather_tmp, byrl_work1, byrl_work1+sizeof(byrl_work1));
			HMACT64_update(&dsl_hmact64, byrl_work1, inl_len);
#if SM_TRACE_NTLM_TRAFFIC
			printf("IM_GSSAPI_FUNC_WRAP: data=%d\n", inl_len);
			m_aux_console_out(adsp_call->adsc_wa_alloc1->adsc_aux, byrl_work1, inl_len);
#endif
			RC4(byrl_work1, 0, inl_len, byrl_work1, 0, adsl_context->chrc_client_handle);
			if(!m_gather2_copy(adsp_call->adsc_wa_alloc1, byrl_work1, inl_len, &dsl_fifo2)) {
				adsp_call->inc_return = DEF_IRET_ERRAU;
				return;
			}
		}

		char chrl_hmac_md5[MD5_DIGEST_LEN];
		HMACT64_final(&dsl_hmact64, chrl_hmac_md5);
		/* Set NTLMSSP_MESSAGE_SIGNATURE.CheckSum */
		RC4(chrl_hmac_md5, 0, 8, byr_msg_signature, 4, adsl_context->chrc_client_handle);
#if SM_TRACE_NTLM_TRAFFIC
		printf("IM_GSSAPI_FUNC_WRAP: inl_out=%d\n", sizeof(byr_msg_signature));
		m_aux_console_out(adsp_call->adsc_wa_alloc1->adsc_aux, byr_msg_signature, sizeof(byr_msg_signature));
#endif
		if(!m_gather2_copy(adsp_call->adsc_wa_alloc1, byr_msg_signature, sizeof(byr_msg_signature), &adsp_call->dsc_gather_out)) {
			adsp_call->inc_return = DEF_IRET_ERRAU;
			return;
		}
		m_gather_fifo_append_list(&adsp_call->dsc_gather_out, &dsl_fifo2);
#if SM_TRACE_NTLM_TRAFFIC
		int inl_out = m_gather_i_1_count_data_len(adsp_call->dsc_gather_out.adsc_first);
		printf("IM_GSSAPI_FUNC_WRAP: inl_out=%d\n", inl_out);
		m_aux_dump_gather(adsp_call->adsc_wa_alloc1->adsc_aux, adsp_call->dsc_gather_out.adsc_first, -1);
#endif
		adsp_call->inc_return = DEF_IRET_NORMAL;
		return;
	}
    case IM_GSSAPI_FUNC_UNWRAP: {
		dsd_gather_i_1* adsl_gather_tmp = adsp_call->adsc_gather_in;
		char byr_server_msg_signature[16];
		int inl_len = m_gather1_copy(&adsl_gather_tmp, byr_server_msg_signature, byr_server_msg_signature+sizeof(byr_server_msg_signature));
		if(inl_len != sizeof(byr_server_msg_signature)) {
			adsp_call->inc_return = DEF_IRET_ERRAU;
			return;
		}

		char byr_msg_signature[16];
		/* Set NTLMSSP_MESSAGE_SIGNATURE.Version */
		m_write_uint32_le(byr_msg_signature, 0x00000001);
		struct dsd_hmact64 dsl_hmact64;
		HMACT64_init(&dsl_hmact64, adsl_context->chrc_server_sign_key, sizeof(adsl_context->chrc_server_sign_key));
		/* Set NTLMSSP_MESSAGE_SIGNATURE.SeqNum */
		m_write_uint32_le(byr_msg_signature+12, adsl_context->umc_server_seqnum++);
		HMACT64_update(&dsl_hmact64, byr_msg_signature+12, 4);

		while(adsl_gather_tmp != NULL) {
			inl_len = m_gather1_copy(&adsl_gather_tmp, byrl_work1, byrl_work1+sizeof(byrl_work1));
			RC4(byrl_work1, 0, inl_len, byrl_work1, 0, adsl_context->chrc_server_handle);
			HMACT64_update(&dsl_hmact64, byrl_work1, inl_len);
#if SM_TRACE_NTLM_TRAFFIC
			printf("IM_GSSAPI_FUNC_UNWRAP: data=%d\n", inl_len);
			m_aux_console_out(adsp_call->adsc_wa_alloc1->adsc_aux, byrl_work1, inl_len);
#endif
			if(!m_gather2_copy(adsp_call->adsc_wa_alloc1, byrl_work1, inl_len, &adsp_call->dsc_gather_out)) {
				adsp_call->inc_return = DEF_IRET_ERRAU;
				return;
			}
		}

		char chrl_hmac_md5[MD5_DIGEST_LEN];
		HMACT64_final(&dsl_hmact64, chrl_hmac_md5);
		/* Set NTLMSSP_MESSAGE_SIGNATURE.CheckSum */
		RC4(chrl_hmac_md5, 0, 8, byr_msg_signature, 4, adsl_context->chrc_server_handle);
		if(memcmp(byr_msg_signature, byr_server_msg_signature, sizeof(byr_msg_signature)) != 0) {
			adsp_call->inc_return = DEF_IRET_ERRAU;
			return;
		}

		adsp_call->inc_return = DEF_IRET_NORMAL;
		return;
	}
	case IM_GSSAPI_FUNC_CLOSE:
		adsp_call->inc_return = DEF_IRET_NORMAL;
		adsl_context->iec_state = ied_ntlmf_invalid;

		memset(adsl_context->chrc_client_sign_key, 0, sizeof(adsl_context->chrc_client_sign_key));
		memset(adsl_context->chrc_client_handle, 0, sizeof(adsl_context->chrc_client_handle));
		memset(adsl_context->chrc_server_sign_key, 0, sizeof(adsl_context->chrc_server_sign_key));
		memset(adsl_context->chrc_server_handle, 0, sizeof(adsl_context->chrc_server_handle));
		return;
	default:
		adsp_call->inc_return = DEF_IRET_INT_ERROR;
		return;
	}
	switch(adsl_context->iec_state) {
	case ied_ntlmf_invalid: {
		dsd_ntlm_req dsl_ntlm_req;
		memset(&dsl_ntlm_req, 0, sizeof(dsl_ntlm_req));
		dsl_ntlm_req.iec_ntlmf = ied_ntlmf_neg_gen;
		// dsl_ntlm_req.vpc_userfld = &dsl_sub_call_1;
		// dsl_ntlm_req.amc_get_epoch = &m_sub_get_epoch;  /* callback get epoch */
		// dsl_ntlm_req.amc_get_random = &m_sub_get_random;  /* callback get random */
		dsl_ntlm_req.achc_negotiate = byrl_work1;  /* address of packet NTLMSSP_NEGOTIATE */
		dsl_ntlm_req.imc_len_negotiate = sizeof(byrl_work1);  /* length of packet NTLMSSP_NEGOTIATE */
		dsl_ntlm_req.iec_ntlmf = ied_ntlmf_neg_gen;  /* generate NTLMSSP_NEGOTIATE */
		
		struct dsd_gssapi_ntlm_params_01* adsl_params = adsl_context->adsc_params;
		dsl_ntlm_req.dsc_ucs_domain = adsl_params->dsc_ucs_domain;
		//dsl_ntlm_req.dsc_ucs_domain.imc_len_str = 0;
		//dsl_ntlm_req.dsc_ucs_userid = adsl_context->dsc_ucs_userid;
		//dsl_ntlm_req.dsc_ucs_password = adsl_context->dsc_ucs_password;
		dsl_ntlm_req.dsc_ucs_workstation = adsl_params->dsc_ucs_workstation;
		//dsl_ntlm_req.dsc_ucs_workstation.imc_len_str = 0;
		//dsl_ntlm_req.dsc_ucs_prot_target.iec_chs_str = ied_chs_utf_8;
		
		if(!m_proc_ntlm_req(&dsl_ntlm_req)) {
			adsp_call->inc_return = DEF_IRET_ERRAU;
			return;
		}
		if(!m_gather2_copy(adsp_call->adsc_wa_alloc1,
			dsl_ntlm_req.achc_negotiate, dsl_ntlm_req.imc_len_negotiate, &adsp_call->dsc_gather_out)) {
			adsp_call->inc_return = DEF_IRET_ERRAU;
			return;
		}
		adsp_call->inc_return = DEF_IRET_NORMAL;
		adsl_context->iec_state = ied_ntlmf_neg_gen;
		return;
	}
	case ied_ntlmf_neg_gen: {
		dsd_ntlm_req dsl_ntlm_req;
		dsd_gather_i_1* adsl_gather_tmp = adsp_call->adsc_gather_in;
		int inl_len = m_gather1_copy(&adsl_gather_tmp, byrl_work1, byrl_work1+sizeof(byrl_work1));
		if(inl_len <= 0 || adsl_gather_tmp != NULL) {
			adsp_call->inc_return = DEF_IRET_NORMAL;
			return;
		}
		char byrl_work2[ 2048 ];           /* work area               */
		memset(&dsl_ntlm_req, 0, sizeof(dsl_ntlm_req));
		dsl_ntlm_req.achc_challenge = byrl_work1;  /* address of packet NTLMSSP_CHALLENGE */
		dsl_ntlm_req.imc_len_challenge = inl_len;  /* length of packet NTLMSSP_CHALLENGE */
		dsl_ntlm_req.achc_auth = byrl_work2;  /* address of packet NTLMSSP_AUTH */
		dsl_ntlm_req.imc_len_auth = sizeof(byrl_work2);  /* length of packet NTLMSSP_AUTH */
		dsl_ntlm_req.iec_ntlmf = ied_ntlmf_auth_gen;  /* generate NTLMSSP_NEGOTIATE */
		struct dsd_gssapi_ntlm_params_01* adsl_params = adsl_context->adsc_params;
		dsl_ntlm_req.dsc_ucs_domain = adsl_params->dsc_ucs_domain;
		dsl_ntlm_req.dsc_ucs_userid = adsl_params->dsc_ucs_userid;
		dsl_ntlm_req.dsc_ucs_password = adsl_params->dsc_ucs_password;
		dsl_ntlm_req.dsc_ucs_workstation = adsl_params->dsc_ucs_workstation;
		dsl_ntlm_req.dsc_ucs_prot_target.iec_chs_str = ied_chs_utf_8;
		dsl_ntlm_req.vpc_userfld = adsp_call->adsc_wa_alloc1->adsc_aux;
		dsl_ntlm_req.amc_get_epoch = &m_sub_get_epoch;  /* callback get epoch */
		dsl_ntlm_req.amc_get_random = &m_sub_get_random;  /* callback get random */
		dsl_ntlm_req.boc_gssapi = FALSE;
		char chrl_ntlm_client_seal_key[LEN_NTLM_SEAL_KEY];
		char chrl_ntlm_server_seal_key[LEN_NTLM_SEAL_KEY];
		dsl_ntlm_req.achc_ntlm_client_sign_key = adsl_context->chrc_client_sign_key;
		dsl_ntlm_req.achc_ntlm_client_seal_key = chrl_ntlm_client_seal_key;
		dsl_ntlm_req.achc_ntlm_server_sign_key = adsl_context->chrc_server_sign_key;
		dsl_ntlm_req.achc_ntlm_server_seal_key = chrl_ntlm_server_seal_key;
		if(!m_proc_ntlm_req(&dsl_ntlm_req)) {
			adsp_call->inc_return = DEF_IRET_ERRAU;
			return;
		}
		//memset(dsl_ntlm_req.achc_ntlm_client_sign_key, 0, LEN_NTLM_SIGN_KEY);
		//memset(dsl_ntlm_req.achc_ntlm_client_seal_key, 0, LEN_NTLM_SEAL_KEY);
		RC4_SetKey(adsl_context->chrc_client_handle, chrl_ntlm_client_seal_key, 0, sizeof(chrl_ntlm_client_seal_key));
		adsl_context->umc_client_seqnum = 0;
		RC4_SetKey(adsl_context->chrc_server_handle, chrl_ntlm_server_seal_key, 0, sizeof(chrl_ntlm_server_seal_key));
		adsl_context->umc_server_seqnum = 0;
		if(!m_gather2_copy(adsp_call->adsc_wa_alloc1,
			dsl_ntlm_req.achc_auth, dsl_ntlm_req.imc_len_auth, &adsp_call->dsc_gather_out)) {
			adsp_call->inc_return = DEF_IRET_ERRAU;
			return;
		}
		adsp_call->inc_return = DEF_IRET_NORMAL;
		adsl_context->iec_state = ied_ntlmf_auth_gen;
		adsl_context->dsc_base.boc_initialized = TRUE;
		return;
	}
	case ied_ntlmf_auth_gen: {
		adsp_call->inc_return = DEF_IRET_INT_ERROR;
		return;
	}
	default:
		adsp_call->inc_return = DEF_IRET_INT_ERROR;
		return;
	}
}


static const int IM_ASN1_OCTECT_STRING = 0x04;
static const int IM_ASN1_SEQUENCE = 0x30;

/**
	* version field in TSRequest.
	*/
static const int IM_TSREQ_VERSION = 0xa0;
/**
	* negoTokens field in TSRequest.
	*/
static const int IM_TSREQ_NEGOTOKENS = 0xa1;
/**
	* authInfo field in TSRequest.
	*/
static const int IM_TSREQ_AUTHINFO = 0xa2;
/**
	* pubKeyAuth field in TSRequest.
	*/
static const int IM_TSREQ_PUBAUTHKEY = 0xa3;
/**
	* errorCode field in TSRequest.
	*/
static const int IM_TSREQ_ERRORCODE = 0xa4;

/**
	* credType field in TSCredentials.
	*/
static const int IM_TSCREDS_CREDTYPE = 0xa0;
/**
	* credentials field in TSCredentials.
	*/
static const int IM_TSCREDS_CREDENTIALS = 0xa1;

/**
	* domainName field in TSPasswordCreds.
	*/
static const int IM_TSPWDCREDS_DOMAINNAME = 0xa0;
/**
	* userName field in TSPasswordCreds.
	*/
static const int IM_TSPWDCREDS_USERNAME = 0xa1;
/**
	* password field in TSPasswordCreds.
	*/
static const int IM_TSPWDCREDS_PASSWORD = 0xa2;

static const int IM_NEGO_TOKEN_INIT_MECHTYPES = 0xa0;

/**
 * Prepends an ASN.1 sequence (0x30).
 */
static BOOL m_prepend_sequence(struct dsd_gather_writer* adsp_gw, int im_end) {
	if(!m_gw_prepend_asn1_length(adsp_gw, im_end - m_gw_get_abs_pos(adsp_gw)))
		return FALSE;
	return m_gw_prepend_byte(adsp_gw, (char) IM_ASN1_SEQUENCE);
}

/**
 * Prepends an ASN.1 sequence (0x04).
 */
static BOOL m_prepend_octet_string(struct dsd_gather_writer* adsp_gw, int im_end) {
	if(!m_gw_prepend_asn1_length(adsp_gw, im_end - m_gw_get_abs_pos(adsp_gw)))
		return FALSE;
	return m_gw_prepend_byte(adsp_gw, (char) IM_ASN1_OCTECT_STRING);
}

/**
 * Prepends an ASN.1 encoded sequence field.
 */
static BOOL m_prepend_seq_field(struct dsd_gather_writer* adsp_gw, int im_field, int im_end) {
	if(!m_gw_prepend_asn1_length(adsp_gw, im_end - m_gw_get_abs_pos(adsp_gw)))
		return FALSE;
	return m_gw_prepend_byte(adsp_gw, (char) im_field);
}

/**
 * Prepends an ASN.1 encoded TSRequest.version sequence field (0xa0).
 */
static BOOL m_prepend_tsrequest_version(struct dsd_gather_writer* adsp_gw) {
	int im_end = m_gw_get_abs_pos(adsp_gw);
	if(!m_gw_prepend_asn1_int(adsp_gw, 3))
		return FALSE;
	return m_prepend_seq_field(adsp_gw, IM_TSREQ_VERSION, im_end);
}

/**
 * Prepends an ASN.1 octet string with UTF-16 (LE).
 */
static BOOL m_prepend_unicode_octet_string(struct dsd_gather_writer* adsp_gw, const struct dsd_unicode_string* adsp_val) {
	int im_end = m_gw_get_abs_pos(adsp_gw);
	if(!m_gw_prepend_utf16_string(adsp_gw, adsp_val))
		return FALSE;
	return m_prepend_octet_string(adsp_gw, im_end);
}

/**
 * Reads an ASN.1 sequence (0x30).
 */
static BOOL m_read_asn1_sequence(struct dsd_gather_reader* adsp_gr, unsigned int* aunp_length) {
	uint8_t im_val;
	if(!m_gr_read_uint8(adsp_gr, &im_val))
		return FALSE;
	if(im_val != IM_ASN1_SEQUENCE) {
		// TODO:
		//throw new dsd_hob_error("invalid ASN1 type 0x" + Integer.toHexString(im_val));
		return FALSE;
	}
	return m_gr_read_asn1_length(adsp_gr, aunp_length);
}

/**
 * Reads an ASN.1 octet string (0x04).
 */
static BOOL m_read_asn1_octet_string(struct dsd_gather_reader* adsp_gr, unsigned int* aunp_length) {
	uint8_t im_val;
	if(!m_gr_read_uint8(adsp_gr, &im_val))
		return FALSE;
	if(im_val != IM_ASN1_OCTECT_STRING) {
		// TODO:
		//throw new dsd_hob_error("invalid ASN1 type 0x" + Integer.toHexString(im_val));
		return FALSE;
	}
	return m_gr_read_asn1_length(adsp_gr, aunp_length);
}

#define HL_GR_RET_FALSE(call) if(!(call)) return FALSE
#define HL_GR_RET_GOTO(call, lbl) if(!(call)) goto lbl

static BOOL m_credssp_init_sec_context(struct dsd_gssapi_01_call* adsp_call, struct dsd_gather_i_1* adsp_gather_in) {
	struct dsd_credssp_01* adsl_context = (struct dsd_credssp_01*)adsp_call->adsc_context;

	// Set the default error value
	adsp_call->inc_return = DEF_IRET_ERRAU;

	struct dsd_gssapi_01_call dsl_mech_call;
	dsl_mech_call.inc_func = IM_GSSAPI_FUNC_INITIALIZE_CONTEXT;
	dsl_mech_call.adsc_context = adsl_context->adsc_mech;
	dsl_mech_call.adsc_gather_in = adsp_gather_in;
	dsl_mech_call.adsc_wa_alloc1 = adsp_call->adsc_wa_alloc1;
	m_gather_fifo_init(&dsl_mech_call.dsc_gather_out);
	dsl_mech_call.adsc_context->amc_gssapi(&dsl_mech_call);
	if(dsl_mech_call.inc_return != DEF_IRET_NORMAL) {
		adsp_call->inc_return = dsl_mech_call.inc_return;
		return FALSE;
	}

	struct dsd_gather_writer dsl_gw;
	m_gw_init(&dsl_gw, adsp_call->adsc_wa_alloc1);
	
	//struct dsd_gather_writer_pos dsl_mech1;
	HL_GR_RET_FALSE(m_gw_mark_end(&dsl_gw));
	int inl_mech_len = m_gather_i_1_count_data_len(dsl_mech_call.dsc_gather_out.adsc_first);
#if SM_TRACE_CREDSSP_TRAFFIC
	printf("IM_TSREQ_NEGOTOKENS: len=%d\n", inl_mech_len);
	m_aux_dump_gather(adsp_call->adsc_wa_alloc1->adsc_aux, dsl_mech_call.dsc_gather_out.adsc_first, -1);
#endif
	//m_gw_get_position(&dsl_gw, &dsl_mech1);
	/* Add the whole header. */
	//int im_end = dsl_mech1.inc_abs_pos + inl_mech_len;
	int im_end = m_gw_get_abs_pos(&dsl_gw);
	if(adsl_context->adsc_mech->boc_initialized) {
		struct dsd_gssapi_01_call dsl_mech_call2;
		dsl_mech_call2.inc_func = IM_GSSAPI_FUNC_WRAP;
		dsl_mech_call2.adsc_context = adsl_context->adsc_mech;
		struct dsd_gssapi_credssp_params_01* adsl_params = adsl_context->adsc_params;
		struct dsd_gather_i_1 dsl_gather_wrap;
		dsl_gather_wrap.achc_ginp_cur = (char*)adsl_params->achc_subject_public_key;
		dsl_gather_wrap.achc_ginp_end = (char*)adsl_params->achc_subject_public_key + adsl_params->inc_subject_public_key_len;
		dsl_gather_wrap.adsc_next = NULL;
		dsl_mech_call2.adsc_gather_in = &dsl_gather_wrap;
		dsl_mech_call2.adsc_wa_alloc1 = adsp_call->adsc_wa_alloc1;
		m_gather_fifo_init(&dsl_mech_call2.dsc_gather_out);
		dsl_mech_call.adsc_context->amc_gssapi(&dsl_mech_call2);
		if(dsl_mech_call2.inc_return != DEF_IRET_NORMAL) {
			adsp_call->inc_return = dsl_mech_call2.inc_return;
			return FALSE;
		}
		/* pubKeyAuth */
		int im_end_pubauthkey = m_gw_get_abs_pos(&dsl_gw);
		// TODO: Add data without copying!
		HL_GR_RET_FALSE(m_gw_prepend_gather_list(&dsl_gw, dsl_mech_call2.dsc_gather_out.adsc_first));
		/* pubKeyAuth OCTET STRING */
		HL_GR_RET_FALSE(m_prepend_octet_string(&dsl_gw, im_end_pubauthkey));
		/* TSRequest::pubKeyAuth. */
		HL_GR_RET_FALSE(m_prepend_seq_field(&dsl_gw, IM_TSREQ_PUBAUTHKEY, im_end_pubauthkey));
		int im_start_pubauthkey = m_gw_get_abs_pos(&dsl_gw);
#if SM_TRACE_CREDSSP_TRAFFIC
		printf("IM_TSREQ_PUBAUTHKEY: len=%d\n", im_start_pubauthkey-im_end_pubauthkey);
		m_aux_console_out(adsp_call->adsc_wa_alloc1->adsc_aux, dsl_gw.achc_cur, dsl_gw.achc_upper-dsl_gw.achc_cur);
#endif
	}
	if(inl_mech_len > 0) {
		int im_end_mech = m_gw_get_abs_pos(&dsl_gw);
		// TODO: Add data without copying!
		HL_GR_RET_FALSE(m_gw_prepend_gather_list(&dsl_gw, dsl_mech_call.dsc_gather_out.adsc_first));
		/* MechTypesList OCTET STRING */
		HL_GR_RET_FALSE(m_prepend_octet_string(&dsl_gw, im_end_mech));
		/* NegoTokenInit::MechTypes */
		HL_GR_RET_FALSE(m_prepend_seq_field(&dsl_gw, IM_NEGO_TOKEN_INIT_MECHTYPES, im_end_mech));
		/* NegotiationToken::NegoTokenInit */
		HL_GR_RET_FALSE(m_prepend_sequence(&dsl_gw, im_end_mech));
		/* NegoData::NegotiationToken */
		HL_GR_RET_FALSE(m_prepend_sequence(&dsl_gw, im_end_mech));
		/* TSRequest::negoTokens. */
		HL_GR_RET_FALSE(m_prepend_seq_field(&dsl_gw, IM_TSREQ_NEGOTOKENS, im_end_mech));
	}
	/* TSRequest::version. */
	HL_GR_RET_FALSE(m_prepend_tsrequest_version(&dsl_gw));
	/* TSRequest. */
	HL_GR_RET_FALSE(m_prepend_sequence(&dsl_gw, im_end));
	HL_GR_RET_FALSE(m_gw_mark_start(&dsl_gw));
	m_gather3_list_release(&dsl_gw.dsc_fifo, &adsp_call->dsc_gather_out);
	m_gw_destroy(&dsl_gw);

	adsp_call->inc_return = DEF_IRET_NORMAL;
	return TRUE;
}

/**
 * Processes the TSRequest.negoTokens sequence field.
 */
static BOOL m_credssp_process_negotiation_token(struct dsd_gssapi_01_call* adsp_call, struct dsd_gather_reader* adsp_gr, int imp_len) {
	// Set the default error value
	adsp_call->inc_return = DEF_IRET_ERRAU;

	int imp_end = m_gr_get_abs_position(adsp_gr) + imp_len;
	while(m_gr_get_abs_position(adsp_gr) < imp_end) {
		uint8_t im_seqfield;
		HL_GR_RET_FALSE(m_gr_read_uint8(adsp_gr, &im_seqfield));
		unsigned int im_seqfieldlen;
		HL_GR_RET_FALSE(m_gr_read_asn1_length(adsp_gr, &im_seqfieldlen));
		int im_end = m_gr_get_abs_position(adsp_gr) + im_seqfieldlen;
		switch(im_seqfield) {
		case IM_NEGO_TOKEN_INIT_MECHTYPES: {
			while(m_gr_get_abs_position(adsp_gr) < im_end) {
				unsigned int im_mtlen;
				HL_GR_RET_FALSE(m_read_asn1_octet_string(adsp_gr, &im_mtlen));
				int im_mtend = m_gr_get_abs_position(adsp_gr) + im_mtlen;
				struct dsd_gather_i_1 dsrl_tuple[2];
				HL_GR_RET_FALSE(m_gr_extract_gathers(adsp_gr, im_mtlen, dsrl_tuple));
				/* Process the mechtype. */
				if(!m_credssp_init_sec_context(adsp_call, &dsrl_tuple[0]))
					return FALSE;
				HL_GR_RET_FALSE(m_gr_seek(adsp_gr, im_mtend));
			}
			break;
		}
		default:
			//throw new c_errorcode_exception(dsd_errorcodes.IM_ERR_CREDSSP_NEGTOKENINIT,
			//	"unsupported NegTokenInit field 0x" + Integer.toHexString(im_seqfield));
			return FALSE;
		}
		HL_GR_RET_FALSE(m_gr_seek(adsp_gr, im_end));
	}

	adsp_call->inc_return = DEF_IRET_NORMAL;
	return TRUE;
}

/**
 * Processes the TSRequest.pubKeyAuth sequence field.
 */
static BOOL m_credssp_process_pubauthkey_token(struct dsd_gssapi_01_call* adsp_call, struct dsd_gather_i_1* adsp_gather_in) {
	struct dsd_credssp_01* adsl_context = (struct dsd_credssp_01*)adsp_call->adsc_context;

	// Set the default error value
	adsp_call->inc_return = DEF_IRET_ERRAU;

	struct dsd_gssapi_01_call dsl_mech_call2;
	dsl_mech_call2.inc_func = IM_GSSAPI_FUNC_UNWRAP;
	dsl_mech_call2.adsc_context = adsl_context->adsc_mech;
	dsl_mech_call2.adsc_gather_in = adsp_gather_in;
	dsl_mech_call2.adsc_wa_alloc1 = adsp_call->adsc_wa_alloc1;
	m_gather_fifo_init(&dsl_mech_call2.dsc_gather_out);
	dsl_mech_call2.adsc_context->amc_gssapi(&dsl_mech_call2);
	if(dsl_mech_call2.inc_return != DEF_IRET_NORMAL) {
		adsp_call->inc_return = dsl_mech_call2.inc_return;
		return FALSE;
	}
	char byr_pubkey[4096];
	struct dsd_gather_i_1* adsl_tmp = dsl_mech_call2.dsc_gather_out.adsc_first;
	int im_pubkey_len = m_gather1_copy(&adsl_tmp, byr_pubkey, byr_pubkey+sizeof(byr_pubkey));
	if(im_pubkey_len < 0) {
		adsp_call->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}
	struct dsd_gssapi_credssp_params_01* adsl_params = adsl_context->adsc_params;
	/* Specified in [MS-CSSP] 3.5.4 */
	byr_pubkey[0]--;
	if(adsl_params->inc_subject_public_key_len != im_pubkey_len
		|| memcmp(adsl_params->achc_subject_public_key, byr_pubkey, im_pubkey_len) != 0) {
		//throw new c_errorcode_exception(dsd_errorcodes.IM_ERR_CREDSSP_PUBKEY, "CredSSP invalid public key token");
		adsp_call->inc_return = DEF_IRET_ERRAU;
		return FALSE;
	}

	//dsd_gssapi_ntlm_01* adsl_tmp_mech = (dsd_gssapi_ntlm_01*)adsl_context->adsc_mech;
	struct dsd_gather_writer dsl_gw1;
	m_gw_init(&dsl_gw1, adsp_call->adsc_wa_alloc1);
	HL_GR_RET_FALSE(m_gw_mark_end(&dsl_gw1));
	int inl_end = m_gw_get_abs_pos(&dsl_gw1);
	/* TSPasswordCreds->password OCTET STRING */
	HL_GR_RET_FALSE(m_prepend_unicode_octet_string(&dsl_gw1, &adsl_params->dsc_ucs_password));
	HL_GR_RET_FALSE(m_prepend_seq_field(&dsl_gw1, IM_TSPWDCREDS_PASSWORD, inl_end));
	/* TSPasswordCreds->userName OCTET STRING */
	int inl_end2 = m_gw_get_abs_pos(&dsl_gw1);
	HL_GR_RET_FALSE(m_prepend_unicode_octet_string(&dsl_gw1, &adsl_params->dsc_ucs_userid));
	HL_GR_RET_FALSE(m_prepend_seq_field(&dsl_gw1, IM_TSPWDCREDS_USERNAME, inl_end2));
	/* TSPasswordCreds->domainName OCTET STRING */
	inl_end2 = m_gw_get_abs_pos(&dsl_gw1);
	HL_GR_RET_FALSE(m_prepend_unicode_octet_string(&dsl_gw1, &adsl_params->dsc_ucs_domain));
	HL_GR_RET_FALSE(m_prepend_seq_field(&dsl_gw1, IM_TSPWDCREDS_DOMAINNAME, inl_end2));
	HL_GR_RET_FALSE(m_prepend_sequence(&dsl_gw1, inl_end));
	/* OCTET STRING TSPasswordCreds */
	HL_GR_RET_FALSE(m_prepend_octet_string(&dsl_gw1, inl_end));
	/* TSCredentials->credentials */
	HL_GR_RET_FALSE(m_prepend_seq_field(&dsl_gw1, IM_TSCREDS_CREDENTIALS, inl_end));
	inl_end2 = m_gw_get_abs_pos(&dsl_gw1);
	/* credType */
	HL_GR_RET_FALSE(m_gw_prepend_asn1_int(&dsl_gw1, 1));
	/* TSCredentials->credType */
	HL_GR_RET_FALSE(m_prepend_seq_field(&dsl_gw1, IM_TSCREDS_CREDTYPE, inl_end2));
	/* TSCredentials */
	HL_GR_RET_FALSE(m_prepend_sequence(&dsl_gw1, inl_end));
	HL_GR_RET_FALSE(m_gw_mark_start(&dsl_gw1));

	struct dsd_gather_i_1_fifo_aux dsl_fifo1;
	m_gather_fifo_init(&dsl_fifo1.dsc_base);
	dsl_fifo1.dsc_base.amp_free_cb = &m_gather_fifo_aux_free;
	dsl_fifo1.adsc_aux = dsl_gw1.adsc_wa_alloc->adsc_aux;
	m_gather3_list_release(&dsl_gw1.dsc_fifo, &dsl_fifo1.dsc_base);
	m_gw_destroy(&dsl_gw1);

#if SM_TRACE_CREDSSP_TRAFFIC
	printf("TSCredentials: len=%d\n", m_gather_i_1_count_data_len(dsl_fifo1.dsc_base.adsc_first));
	m_aux_dump_gather(adsp_call->adsc_wa_alloc1->adsc_aux, dsl_fifo1.dsc_base.adsc_first, -1);
#endif
	//struct dsd_gssapi_01_call dsl_mech_call2;
	dsl_mech_call2.inc_func = IM_GSSAPI_FUNC_WRAP;
	dsl_mech_call2.adsc_context = adsl_context->adsc_mech;
	dsl_mech_call2.adsc_gather_in = dsl_fifo1.dsc_base.adsc_first;
	dsl_mech_call2.adsc_wa_alloc1 = adsp_call->adsc_wa_alloc1;
	m_gather_fifo_init(&dsl_mech_call2.dsc_gather_out);
	dsl_mech_call2.adsc_context->amc_gssapi(&dsl_mech_call2);
	if(dsl_mech_call2.inc_return != DEF_IRET_NORMAL) {
		adsp_call->inc_return = dsl_mech_call2.inc_return;
		return FALSE;
	}

	struct dsd_gather_writer dsl_gw2;
	m_gw_init(&dsl_gw2, adsp_call->adsc_wa_alloc1);
	HL_GR_RET_FALSE(m_gw_mark_end(&dsl_gw2));
	inl_end = m_gw_get_abs_pos(&dsl_gw2);
	/* TSPasswordCreds */
	// TODO: Add data without copying!
	HL_GR_RET_FALSE(m_gw_prepend_gather_list(&dsl_gw2, dsl_mech_call2.dsc_gather_out.adsc_first));
	/* authInfo OCTET STRING */
	HL_GR_RET_FALSE(m_prepend_octet_string(&dsl_gw2, inl_end));
	/* TSRequest::authInfo */
	HL_GR_RET_FALSE(m_prepend_seq_field(&dsl_gw2, IM_TSREQ_AUTHINFO, inl_end));
	/* TSRequest::version */
	HL_GR_RET_FALSE(m_prepend_tsrequest_version(&dsl_gw2));
	/* TSRequest */
	HL_GR_RET_FALSE(m_prepend_sequence(&dsl_gw2, inl_end));
	HL_GR_RET_FALSE(m_gw_mark_start(&dsl_gw2));
	m_gather3_list_release(&dsl_gw2.dsc_fifo, &adsp_call->dsc_gather_out);
	m_gw_destroy(&dsl_gw2);

#if SM_TRACE_CREDSSP_TRAFFIC
	printf("TSRequest: len=%d\n", m_gather_i_1_count_data_len(adsp_call->dsc_gather_out.adsc_first));
	m_aux_dump_gather(adsp_call->adsc_wa_alloc1->adsc_aux, adsp_call->dsc_gather_out.adsc_first, -1);
#endif

	adsl_context->dsc_base.boc_initialized = TRUE;
	adsp_call->inc_return = DEF_IRET_NORMAL;
	return TRUE;
}

void m_gssapi_credssp_01(struct dsd_gssapi_01_call* adsp_call) {
	struct dsd_credssp_01* adsl_context = (struct dsd_credssp_01*)adsp_call->adsc_context;
	switch(adsp_call->inc_func) {
	case IM_GSSAPI_FUNC_START: {
		adsl_context->dsc_base.boc_initialized = FALSE;
		adsl_context->iec_state = iec_credssp_state_start;
		adsl_context->unc_error_code = 0;
		adsl_context->inc_last_seqfield = 0;
		adsl_context->inc_server_version = -1;
		adsl_context->adsc_mech = adsl_context->adsc_params->adsc_mech;
		adsp_call->inc_return = DEF_IRET_NORMAL;

		struct dsd_gssapi_01_call dsl_mech_call;
		dsl_mech_call.inc_func = IM_GSSAPI_FUNC_START;
		dsl_mech_call.adsc_context = adsl_context->adsc_mech;
		dsl_mech_call.adsc_gather_in = NULL;
		dsl_mech_call.adsc_wa_alloc1 = adsp_call->adsc_wa_alloc1;
		m_gather_fifo_init(&dsl_mech_call.dsc_gather_out);
		dsl_mech_call.adsc_context->amc_gssapi(&dsl_mech_call);
		return;
	}
	case IM_GSSAPI_FUNC_INITIALIZE_CONTEXT:
		break;
	case IM_GSSAPI_FUNC_CLOSE: {
		struct dsd_gssapi_01_call dsl_mech_call;
		dsl_mech_call.inc_func = IM_GSSAPI_FUNC_CLOSE;
		dsl_mech_call.adsc_context = adsl_context->adsc_mech;
		dsl_mech_call.adsc_gather_in = NULL;
		dsl_mech_call.adsc_wa_alloc1 = adsp_call->adsc_wa_alloc1;
		m_gather_fifo_init(&dsl_mech_call.dsc_gather_out);
		dsl_mech_call.adsc_context->amc_gssapi(&dsl_mech_call);
		
		adsp_call->inc_return = DEF_IRET_NORMAL;
		return;
	}
	default:
		adsp_call->inc_return = DEF_IRET_INT_ERROR;
		return;
	}


	switch(adsl_context->iec_state) {
	case iec_credssp_state_start: {
		if(!m_credssp_init_sec_context(adsp_call, NULL)) {
			return;
		}
		adsl_context->iec_state = iec_credssp_state_mech;
		adsp_call->inc_return = DEF_IRET_NORMAL;
		return;
	}
	case iec_credssp_state_mech: {
		int inl_data_len = m_gather_i_1_count_data_len(adsp_call->adsc_gather_in);
		if(inl_data_len <= 0) {
			adsp_call->inc_return = DEF_IRET_NORMAL;
			return;
		}
		adsp_call->inc_return = DEF_IRET_ERRAU;
		struct dsd_gather_i_1_fifo dsl_fifo;
		m_gather_fifo_init(&dsl_fifo);
		m_gather_fifo_append_list2(&dsl_fifo, adsp_call->adsc_gather_in);
		struct dsd_gather_reader dsl_gather_reader;
		m_gr_init(&dsl_gather_reader, &dsl_fifo);
		struct dsd_gather_i_1_pos dsl_lookahead_pos;
		// Start lookahead mode
		HL_GR_RET_GOTO(m_gr_begin_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);
		unsigned int unl_packet_len;
		// Try to parse the top-level header to determine the total length of the packet
		if(!m_read_asn1_sequence(&dsl_gather_reader, &unl_packet_len)) {
			adsp_call->inc_return = DEF_IRET_NORMAL;
			return;
		}
		int inl_abs_pos = m_gr_get_abs_position(&dsl_gather_reader);
		// Is the packet complete?
		if((inl_data_len-inl_abs_pos) < (int)unl_packet_len) {
			adsp_call->inc_return = DEF_IRET_NORMAL;
			return;
		}
		// End lookahead mode
		HL_GR_RET_GOTO(m_gr_end_lookahead(&dsl_gather_reader, &dsl_lookahead_pos), LBL_FAILED);

		while(m_gr_has_more(&dsl_gather_reader)) {
			uint8_t im_seqfield;
			HL_GR_RET_GOTO(m_gr_read_uint8(&dsl_gather_reader, &im_seqfield), LBL_FAILED);
			unsigned int im_seqfieldlen;
			HL_GR_RET_GOTO(m_gr_read_asn1_length(&dsl_gather_reader, &im_seqfieldlen), LBL_FAILED);
			int im_end = m_gr_get_abs_position(&dsl_gather_reader) + im_seqfieldlen;
			switch(im_seqfield) {
			case IM_TSREQ_VERSION: {
				// Note: Workaround for ticket #31027 even though that protocol version is not documented.
				unsigned int im_version;
				HL_GR_RET_GOTO(m_gr_read_asn1_integer(&dsl_gather_reader, &im_version), LBL_FAILED);
				adsl_context->inc_server_version = im_version;
#if 0
				// Version check is not used at the moment
				switch(im_version) {
				case 2: // e.g. Windows Server 2008 R2
				case 3: // e.g. Windows Server 2012 R2
				case 4: // e.g. Windows 10 SP1
					break;
				default:
					//throw new c_errorcode_exception(dsd_errorcodes.IM_ERR_CREDSSP_TSVERSION,
					//	"unsupported TsRequest version " + im_version);
					adsp_call->inc_return = DEF_IRET_ERRAU;
					return;
				}
#endif
				break;
			}
			case IM_TSREQ_NEGOTOKENS: {
				/* NegoData::NegotiationToken */
				unsigned int inl_token;
				HL_GR_RET_GOTO(m_read_asn1_sequence(&dsl_gather_reader, &inl_token), LBL_FAILED);
				/* NegotiationToken::NegoTokenInit */
				unsigned int inl_init;
				HL_GR_RET_GOTO(m_read_asn1_sequence(&dsl_gather_reader, &inl_init), LBL_FAILED);
				if(!m_credssp_process_negotiation_token(adsp_call, &dsl_gather_reader, inl_init)) {
					return;
				}
				break;
			}
			case IM_TSREQ_PUBAUTHKEY: {
				/* Read the octet string. */
				unsigned int im_paklen;
				HL_GR_RET_GOTO(m_read_asn1_octet_string(&dsl_gather_reader, &im_paklen), LBL_FAILED);
				struct dsd_gather_i_1 dsrl_tuple[2];
				HL_GR_RET_GOTO(m_gr_extract_gathers(&dsl_gather_reader, im_paklen, dsrl_tuple), LBL_FAILED);
				if(!m_credssp_process_pubauthkey_token(adsp_call, &dsrl_tuple[0])) {
					return;
				}
				break;
			}
			case IM_TSREQ_ERRORCODE: {
				HL_GR_RET_GOTO(m_gr_read_asn1_integer(&dsl_gather_reader, &adsl_context->unc_error_code), LBL_FAILED);
				adsp_call->inc_return = DEF_IRET_ERR_EXTENDED;
				return;
			}
			default:
				//throw new c_errorcode_exception(dsd_errorcodes.IM_ERR_CREDSSP_TSREQUEST, "unsupported TsRequest field 0x"
				//	+ Integer.toHexString(im_seqfield));
				adsp_call->inc_return = DEF_IRET_INT_ERROR;
				return;
			}
			HL_GR_RET_GOTO(m_gr_seek(&dsl_gather_reader, im_end), LBL_FAILED);
			adsl_context->inc_last_seqfield = im_seqfield;
		}
		adsp_call->inc_return = DEF_IRET_NORMAL;
		return;
	}
	default:
		adsp_call->inc_return = DEF_IRET_INT_ERROR;
		return;
	}
LBL_FAILED:
	// TODO: Error logging
	adsp_call->inc_return = DEF_IRET_ERRAU;
	return;
}

static void m_rdpclient_free_gather_i_2(struct dsd_gather_i_1_fifo* adsp_list, struct dsd_gather_i_1* adsp_g) {
	struct dsd_gather_i_2* adsl_g2 = (struct dsd_gather_i_2*)adsp_g;
	if(adsl_g2->adsc_owner == NULL)
		return;
	struct dsd_call_rdpclient_2* adsl_client = HL_UPCAST(struct dsd_call_rdpclient_2, dsc_to_rdpacc, adsp_list);
#ifdef HL_RDP_WEBTERM
	struct dsd_aux_helper* adsl_aux_helper = &adsl_client->dsc_wa_aux2;
#else
	struct dsd_aux_helper* adsl_aux_helper = &adsl_client->dsc_wa_aux1;
#endif
	m_free_gather_i_2(adsl_g2, adsl_aux_helper);
}

static BOOL m_subaux_rdpclient_ssl(void * vpp_userfld, int imp_func, void * ap_param, int imp_length ) {
	struct dsd_call_rdpclient_2* adsl_client = (struct dsd_call_rdpclient_2*)vpp_userfld;
#if SM_TRACE_SSL_BUG
	switch(imp_func) {
	case DEF_AUX_MEMGET:
		if(!adsl_client->dsc_aux.amc_aux(adsl_client->dsc_aux.vpc_userfld, imp_func, ap_param, imp_length))
			return FALSE;
		printf("m_subaux_rdpclient_ssl: DEF_AUX_MEMGET ptr=%p length=%d\n", *(void**)ap_param, imp_length);
		return TRUE;
	case DEF_AUX_MEMFREE:
		printf("m_subaux_rdpclient_ssl: DEF_AUX_MEMFREE ptr=%p\n", *(void**)ap_param);
		return adsl_client->dsc_aux.amc_aux(adsl_client->dsc_aux.vpc_userfld, imp_func, ap_param, imp_length);
	}
#endif
	return adsl_client->dsc_aux.amc_aux(adsl_client->dsc_aux.vpc_userfld, imp_func, ap_param, imp_length);
}

static void m_ssl_conn_callback(struct dsd_hl_ssl_ccb_1* adsp_ccb) {
	struct dsd_call_rdpclient_2* adsl_client = (struct dsd_call_rdpclient_2*)adsp_ccb->vpc_userfld;
	adsl_client->boc_ssl_initialized = TRUE;
#if SM_TRACE_RDP_CLIENT
	printf("#m_ssl_conn_callback adsp_ccb=%p\n", adsp_ccb);
#endif
#if SM_TRACE_SSL_BUG
	printf("m_ssl_conn_callback: Before FromASN1CertToCertStruc\n");
#endif
	X509CERT* adsl_cert;
	int inl_ret = HL_FromASN1CertToCertStruc(
#ifdef XH_INTERFACE
		&adsl_client->dsc_ssl_hmem_context,
#endif
		adsp_ccb->achc_certificate, 0, adsp_ccb->inc_len_certificate,
        0, 0, NULL, 0, &adsl_cert);
#if SM_TRACE_SSL_BUG
	printf("m_ssl_conn_callback: After FromASN1CertToCertStruc\n");
#endif
	if(inl_ret != 0)
		return;
	adsl_client->adsc_end_cert = adsl_cert;
#if 0
	IDATPARR* adsl_subjectpubkey = adsl_cert->PubKeyValueOcsp;
	char* achl_common_name = NULL;
#if SM_TRACE_SSL_BUG
	printf("m_ssl_conn_callback: Before FromASN1_DNCommonNameToString\n");
#endif
	inl_ret = HL_FromASN1_DNCommonNameToString(
#ifdef XH_INTERFACE
		&adsl_client->dsc_ssl_hmem_context,
#endif
		adsl_cert->Subject, &achl_common_name);
#if SM_TRACE_SSL_BUG
	printf("m_ssl_conn_callback: Before FromASN1_DNCommonNameToString\n");
#endif
	if(inl_ret != 0)
		return;
#if 0	
	for(int i=0; i<adsl_cert->PubKeyValueOcsp->Cnt; i++) {
		IDATA* adsl_idata = adsl_cert->PubKeyValueOcsp->ppArr[i];
		char* achl_pos = adsl_idata->Base + adsl_idata->Off;
		int inl_len = adsl_idata->Len;
		m_aux_console_out(&adsl_client->dsc_aux, achl_pos, inl_len);
	}
#endif
#endif
}

static void m_rdp_client_2_cleanup_ssl(struct dsd_call_rdpclient_2* adsp_client) {
	switch(adsp_client->iec_rdp_state) {
	case iec_state_rdp_tls_init:
	case iec_state_rdp_tls_credssp:
	case iec_state_rdp_tls_rdp:
	{
		break;
	}
	default:
		return;
	}
	if(adsp_client->adsc_end_cert != NULL) {
#if SM_TRACE_SSL_BUG
		printf("m_rdpclient_2: Before FreeCertStruc\n");
#endif
		HL_FreeCertStruc(
#ifdef XH_INTERFACE
			&adsp_client->dsc_ssl_hmem_context,
#endif
			adsp_client->adsc_end_cert);
#if SM_TRACE_SSL_BUG
		printf("m_rdpclient_2: After FreeCertStruc\n");
#endif
		adsp_client->adsc_end_cert = NULL;
	}

	struct dsd_hl_ssl_c_1& dsl_ssl_client = adsp_client->dsc_ssl_client;
	if(dsl_ssl_client.vpc_ext) {
		dsl_ssl_client.boc_eof_client = TRUE;
		dsl_ssl_client.boc_eof_server = TRUE;
		dsl_ssl_client.achc_out_cl_cur = NULL;
		dsl_ssl_client.achc_out_cl_end = NULL;
		dsl_ssl_client.achc_out_se_cur = NULL;
		dsl_ssl_client.achc_out_se_end = NULL;
		dsl_ssl_client.adsc_gai1_in_cl = NULL;
		dsl_ssl_client.adsc_gai1_in_se = NULL;
#if HL_USE_AUX_SSL_FUNCTIONS
		adsp_client->adsc_aux_ssl_functions->m_hlcl01(&dsl_ssl_client);
#else
		m_hlcl01(&dsl_ssl_client);
#endif
	}
}

#ifdef HL_RDP_WEBTERM
void m_wt_rdp_client_2(struct dsd_call_rdpclient_2* adsp_client)
#else
void m_rdpclient_2(struct dsd_call_rdpclient_2* adsp_client)
#endif
{
#if 0
	struct dsd_workarea_allocator dsl_wa_alloc3;
	m_wa_allocator_init(&dsl_wa_alloc3);
	dsl_wa_alloc3.adsc_aux = &adsp_client->dsc_aux;

	struct dsd_workarea_chain dsc_wa_chain1;
	dsc_wa_chain1.adsc_aux = &adsp_client->dsc_aux;
	dsc_wa_chain1.adsc_workarea_1 = NULL;
	struct dsd_aux_helper dsl_aux_helper;
	dsl_aux_helper.amc_aux = &m_subaux_wa_allocator_intern;
	dsl_aux_helper.vpc_userfld = &dsc_wa_chain1;
	dsl_wa_alloc3.adsc_aux = &dsl_aux_helper;
	
	struct dsd_gather_i_1_fifo dsl_fifo2;
	m_gather_fifo_init(&dsl_fifo2);
	m_gather2_copy(&dsl_wa_alloc3, "A", 1, &dsl_fifo2);
	m_gather2_copy(&dsl_wa_alloc3, "B", 1, &dsl_fifo2);
	m_gather2_copy(&dsl_wa_alloc3, "C", 1, &dsl_fifo2);
	m_gather2_copy(&dsl_wa_alloc3, "D", 1, &dsl_fifo2);
	m_gather2_copy(&dsl_wa_alloc3, "E", 1, &dsl_fifo2);
	m_gather2_copy(&dsl_wa_alloc3, "F", 1, &dsl_fifo2);
	m_gather2_copy(&dsl_wa_alloc3, "G", 1, &dsl_fifo2);

	struct dsd_gather_writer dsl_gw;
	m_gw_init(&dsl_gw, &dsl_wa_alloc3);

	m_gw_prepend_gather_list(&dsl_gw, dsl_fifo2.adsc_first);

	struct dsd_gather_writer_pos dsl_pos1;
	m_gw_get_position(&dsl_gw, &dsl_pos1);
	m_gw_set_position(&dsl_gw, &dsl_pos1);
	struct dsd_unicode_string dsl_tmp;
	dsl_tmp.ac_str = "\x44\x61\x73\x20\x69\x73\x74\x20\x65\x69\x6E\x20\x74\x6F\x6C\x6C\x65\x72\x20\xC3\x9C\x62\x65\x72\x66\x61\x6C\x6C\x20\x61\x75\x66\x20\x64\x69\x65\x20\xC3\x84\xC3\x9C\x2E\x20";
	dsl_tmp.imc_len_str = strlen((const char*)dsl_tmp.ac_str);
	dsl_tmp.iec_chs_str = ied_chs_utf_8;
	m_gw_prepend_utf16_string(&dsl_gw, &dsl_tmp);
	m_gw_prepend_uint32_le(&dsl_gw, 0xaabbccdd);
	m_gw_mark_start(&dsl_gw);
	struct dsd_gather_writer_pos dsl_pos2;
	m_gw_get_position(&dsl_gw, &dsl_pos2);
	m_gw_write_uint32_le(&dsl_gw, 123456);
	m_gw_mark_end(&dsl_gw);
	m_gw_set_position(&dsl_gw, &dsl_pos1);
	m_gw_write_uint32_le(&dsl_gw, 123456);
	m_gw_write_uint32_le(&dsl_gw, 789);
	m_gw_mark_end(&dsl_gw);
	struct dsd_gather_i_3_itr dsl_first;
	m_gather3_list_get_first(&dsl_gw.dsc_fifo, &dsl_first);
	m_gather3_list_release(&dsl_gw.dsc_fifo);
	m_gw_destroy(&dsl_gw);
#endif
	struct dsd_workarea_allocator dsl_wa_alloc2;
	struct dsd_workarea_allocator* adsl_cur_wa_alloc;
	//struct dsd_aux_helper dsl_aux_helper_ext;
	//dsl_aux_helper_ext.amc_aux = adsp_client->amc_aux;
	//dsl_aux_helper_ext.vpc_userfld = adsp_client->vpc_userfld;

	bool bol_ssl_changed = false;
	dsd_gather_i_1* adsc_gather_i_1_in = m_gather_i_1_skip_processed(adsp_client->adsc_gather_i_1_in);
	dsd_gather_i_1_fifo dsl_gai1_out_to_server;
	m_gather_fifo_init(&dsl_gai1_out_to_server);

	adsp_client->dsc_rdpacc.inc_func = adsp_client->inc_func;
	adsp_client->dsc_rdpacc.adsc_cc_co1_ch = adsp_client->adsc_cc_co1_ch;
	adsp_client->dsc_rdpacc.adsc_se_co1_ch = adsp_client->adsc_se_co1_ch;

	adsp_client->dsc_rdpacc.boc_callagain = adsp_client->boc_callagain;
#if SM_MINIFY_WORKAREAS
	if(adsp_client->inc_len_work_area > 64)
		adsp_client->inc_len_work_area = 64;
#endif
	dsl_wa_alloc2.adsc_aux = &adsp_client->dsc_wa_aux2;
	dsl_wa_alloc2.adsc_wa_cur = NULL;
	dsl_wa_alloc2.achc_lower = adsp_client->achc_work_area;
	dsl_wa_alloc2.achc_upper = adsp_client->achc_work_area + adsp_client->inc_len_work_area;
	adsl_cur_wa_alloc = &dsl_wa_alloc2;

#ifdef HL_RDP_WEBTERM
	struct dsd_wt_record_1 **aadsc_wtr1_out_fifo = &adsp_client->adsc_wtr1_out;
#endif

#if SM_TRACE_RDP_CLIENT
	if(adsp_client->inc_call_count == 11) {
		int a = 0;
	}

	printf("#m_rdpclient_2[%d] adsc_cc_co1_ch=%p adsc_se_co1_ch=%p adsc_gather_i_1_in=%p (bytes %d)\n",
		adsp_client->inc_call_count++,
		adsp_client->adsc_cc_co1_ch, adsp_client->adsc_se_co1_ch,
		adsc_gather_i_1_in, m_gather_i_1_count_data_len(adsc_gather_i_1_in));
#endif
	//HeapValidate(GetProcessHeap(), 0, NULL);
	switch(adsp_client->inc_func) {
	case DEF_IFUNC_START:
		adsp_client->dsc_rdpacc.vpc_userfld = adsp_client->dsc_aux.vpc_userfld;
		adsp_client->dsc_rdpacc.amc_aux = adsp_client->dsc_aux.amc_aux;  /* pointer to subroutine */
		adsp_client->dsc_wa_chain1.adsc_aux = &adsp_client->dsc_aux;
		adsp_client->dsc_wa_chain1.adsc_workarea_1 = NULL;
		adsp_client->dsc_wa_aux1.amc_aux = &m_subaux_wa_allocator_intern;
		adsp_client->dsc_wa_aux1.vpc_userfld = &adsp_client->dsc_wa_chain1;
		m_wa_allocator_init(&adsp_client->dsc_wa_alloc1);
		adsp_client->dsc_wa_alloc1.adsc_aux = &adsp_client->dsc_wa_aux1;
		m_gather_fifo_init(&adsp_client->dsc_to_rdpacc);
		adsp_client->dsc_to_rdpacc.amp_free_cb = &m_rdpclient_free_gather_i_2;

		adsp_client->dsc_wa_chain2.adsc_aux = &adsp_client->dsc_aux;
		adsp_client->dsc_wa_chain2.adsc_workarea_1 = NULL;
		adsp_client->dsc_wa_aux2.amc_aux = &m_subaux_wa_allocator_extern;
		adsp_client->dsc_wa_aux2.vpc_userfld = &adsp_client->dsc_wa_chain2;

		adsp_client->dsc_rdpacc.achc_work_area = dsl_wa_alloc2.achc_lower;
		adsp_client->dsc_rdpacc.inc_len_work_area = dsl_wa_alloc2.achc_upper - dsl_wa_alloc2.achc_lower;
#ifdef HL_RDP_WEBTERM
		m_wt_rdp_client_1(&adsp_client->dsc_rdpacc);
#else
		m_rdpclient_1(&adsp_client->dsc_rdpacc);
#endif
		adsp_client->iec_rdp_state = iec_state_rdp_negotiate;
		adsl_cur_wa_alloc->achc_lower = adsp_client->dsc_rdpacc.achc_work_area;
		adsl_cur_wa_alloc->achc_upper = adsp_client->dsc_rdpacc.achc_work_area + adsp_client->dsc_rdpacc.inc_len_work_area;

		m_fifo_init(&adsp_client->dsc_to_ssl_cl);
		adsp_client->dsc_to_ssl_cl.amp_free_cb = &m_free_data_block;
#if 1		
		struct dsd_call_credssp_01 dsl_credssp_call;
		dsl_credssp_call.dsc_base.inc_func = IM_GSSAPI_FUNC_START;
		dsl_credssp_call.dsc_base.adsc_context = &adsp_client->dsc_credssp.dsc_base;
		dsl_credssp_call.dsc_base.adsc_gather_in = NULL;
		dsl_credssp_call.dsc_base.adsc_wa_alloc1 = &adsp_client->dsc_wa_alloc1;
		m_gather_fifo_init(&dsl_credssp_call.dsc_base.dsc_gather_out);
		m_gssapi_credssp_01(&dsl_credssp_call.dsc_base);
#endif
		adsp_client->adsc_end_cert = NULL;
		goto LBL_SYNC_PARAMS;
	case DEF_IFUNC_REFLECT:
		switch(adsp_client->iec_rdp_state) {
		case iec_state_rdp_negotiate:
			break;
		case iec_state_rdp_negotiate2:
			break;
      case iec_state_rdp_pure:
			if(adsp_client->adsc_cc_co1_ch != NULL && adsp_client->adsc_cc_co1_ch->iec_cc_command == ied_ccc_reconnect) {
				m_gather_fifo_reset(&adsp_client->dsc_to_rdpacc);
				adsp_client->iec_rdp_state = iec_state_rdp_negotiate;
			}
         break;
		case iec_state_rdp_tls_init:
		case iec_state_rdp_tls_credssp:
		case iec_state_rdp_tls_rdp:
		{
#ifdef HL_RDP_WEBTERM
			// Unmark all remaining gathers
			m_gather_fifo_foreach(&adsp_client->dsc_to_rdpacc, &m_gather_i_2_ref_dec, &adsp_client->dsc_aux);
#endif
			if(adsp_client->adsc_cc_co1_ch != NULL && adsp_client->adsc_cc_co1_ch->iec_cc_command == ied_ccc_reconnect) {
				// Reset the CredSSP context
				struct dsd_call_credssp_01 dsl_credssp_call;
				dsl_credssp_call.dsc_base.inc_func = IM_GSSAPI_FUNC_CLOSE;
				dsl_credssp_call.dsc_base.adsc_context = &adsp_client->dsc_credssp.dsc_base;
				dsl_credssp_call.dsc_base.adsc_gather_in = NULL;
				dsl_credssp_call.dsc_base.adsc_wa_alloc1 = &adsp_client->dsc_wa_alloc1;
				m_gather_fifo_init(&dsl_credssp_call.dsc_base.dsc_gather_out);
				m_gssapi_credssp_01(&dsl_credssp_call.dsc_base);
				dsl_credssp_call.dsc_base.inc_func = IM_GSSAPI_FUNC_START;
				m_gssapi_credssp_01(&dsl_credssp_call.dsc_base);

				m_rdp_client_2_cleanup_ssl(adsp_client);
				m_fifo_reset(&adsp_client->dsc_to_ssl_cl,  adsp_client->dsc_wa_alloc1.adsc_aux);
				m_gather_fifo_reset(&adsp_client->dsc_to_rdpacc);
				adsp_client->iec_rdp_state = iec_state_rdp_negotiate;
			}
			struct dsd_hl_ssl_c_1& dsl_ssl_client = adsp_client->dsc_ssl_client;
			if(dsl_ssl_client.adsc_gai1_in_se != NULL) {
				adsp_client->inc_return = DEF_IRET_INT_ERROR;
				return;
         }
			if(adsp_client->dsc_rdpacc.adsc_cc_co1_ch != NULL) {
				//adsp_client->dsc_wa_chain1.adsc_workarea_1 = NULL;
				adsl_cur_wa_alloc = &adsp_client->dsc_wa_alloc1;
				adsp_client->dsc_rdpacc.amc_aux = adsl_cur_wa_alloc->adsc_aux->amc_aux;
				adsp_client->dsc_rdpacc.vpc_userfld = adsl_cur_wa_alloc->adsc_aux->vpc_userfld;
				goto LBL_PROCESS_RDP;
			}
			//dsl_ssl_client.adsc_gai1_in_se = &adsl_received_data->dsc_data_gather;
			if(dsl_ssl_client.adsc_gai1_in_cl != NULL) {
				goto LBL_PROCESS_SSL;
			}
			dsl_ssl_client.adsc_gai1_in_se = adsc_gather_i_1_in;
			goto LBL_PROCESS_SSL;
		}
		default:
			adsp_client->inc_return = DEF_IRET_INT_ERROR;
			return;
		}

		adsp_client->dsc_rdpacc.adsc_gather_i_1_in = adsc_gather_i_1_in;
		//adsp_client->dsc_rdpacc.adsc_gai1_out_to_server = adsp_client->adsc_gai1_out_to_server;
    	adsp_client->dsc_rdpacc.vpc_userfld = adsp_client->dsc_aux.vpc_userfld;
		adsp_client->dsc_rdpacc.amc_aux = adsp_client->dsc_aux.amc_aux;  /* pointer to subroutine */
#if SM_TRACE_RDP_TRAFFIC
		if(adsc_gather_i_1_in != NULL) {
            int iml_len = m_gather_i_1_count_data_len(adsc_gather_i_1_in);
            printf("RDP DATA FROM SERVER length: %d Bytes:\n",iml_len);
#if !MS_TRACE_RDP_TRAFFIC_SIZEONLY
#if MS_TRACE_RDP_TRAFFIC_MAXLEN
            if (iml_len <= MS_TRACE_RDP_TRAFFIC_MAXLEN)
#endif
			    m_aux_dump_gather(&adsp_client->dsc_aux, adsc_gather_i_1_in, -1);

#endif
		}
#endif
		goto LBL_PROCESS_RDP;
	case DEF_IFUNC_CLOSE: {
#if 0
		struct dsd_call_credssp_01 dsl_credssp_call;
		dsl_credssp_call.dsc_base.inc_func = IM_GSSAPI_FUNC_CLOSE;
		dsl_credssp_call.dsc_base.adsc_context = &adsp_client->dsc_credssp.dsc_base;
		dsl_credssp_call.dsc_base.adsc_gather_in = NULL;
		dsl_credssp_call.dsc_base.adsc_wa_alloc1 = &adsp_client->dsc_wa_alloc1;
		m_gather_fifo_init(&dsl_credssp_call.dsc_base.dsc_gather_out);
		m_gssapi_credssp_01(&dsl_credssp_call.dsc_base);

		if(adsp_client->adsc_end_cert != NULL) {
			ds__hmem dsl_new_struct;
			memset(&dsl_new_struct, 0, sizeof(ds__hmem));
			dsl_new_struct.in__aux_up_version = 1;
			dsl_new_struct.am__aux2 = adsp_client->dsc_aux.amc_aux;
			dsl_new_struct.in__flags = 0;
			dsl_new_struct.vp__context = adsp_client->dsc_aux.vpc_userfld;
			FreeCertStruc(&dsl_new_struct, adsp_client->adsc_end_cert);
			adsp_client->adsc_end_cert = NULL;
		}
		/*adsp_client->dsc_rdpacc.achc_work_area = dsl_wa_alloc2.achc_lower;
		adsp_client->dsc_rdpacc.inc_len_work_area = dsl_wa_alloc2.achc_upper - dsl_wa_alloc2.achc_lower;
		m_rdpclient_1(&adsp_client->dsc_rdpacc);
		adsl_cur_wa_alloc->achc_lower = adsp_client->dsc_rdpacc.achc_work_area;
		adsl_cur_wa_alloc->achc_upper = adsp_client->dsc_rdpacc.achc_work_area + adsp_client->dsc_rdpacc.inc_len_work_area;*/
		switch(adsp_client->iec_rdp_state) {
		case iec_state_rdp_tls_init:
		case iec_state_rdp_tls_credssp:
		case iec_state_rdp_tls_rdp:
		{
			struct dsd_hl_ssl_c_1& dsl_ssl_client = adsp_client->dsc_ssl_client;
			dsl_ssl_client.boc_eof_client = TRUE;
			goto LBL_PROCESS_SSL;
		}
		}
		goto LBL_PROCESS_RDP;
#endif
		goto LBL_CLEANUP;
	}
	}
LBL_PROCESS_SSL: {
	struct dsd_hl_ssl_c_1& dsl_ssl_client = adsp_client->dsc_ssl_client;
	if(dsl_ssl_client.inc_return == DEF_IRET_END)
		goto LBL_SYNC_PARAMS;
	dsd_data_block* adsl_data_block = NULL;
	dsl_ssl_client.adsc_gai1_in_cl = NULL;
	if(adsp_client->dsc_to_ssl_cl.adsc_first != NULL) {
		adsl_data_block = HL_UPCAST(dsd_data_block, dsc_slist_elem, adsp_client->dsc_to_ssl_cl.adsc_first);
		dsl_ssl_client.adsc_gai1_in_cl = adsl_data_block->adsc_data;
	}
	dsd_gather_i_1_pos dsl_in_cl1 = m_make_gather_pos(dsl_ssl_client.adsc_gai1_in_cl);
	dsd_gather_i_1_pos dsl_in_se1 = m_make_gather_pos(dsl_ssl_client.adsc_gai1_in_se);

	struct dsd_gather_i_1* adsl_out_se = (struct dsd_gather_i_1*)m_wa_allocator_reserve_lower(&dsl_wa_alloc2, sizeof(dsd_gather_i_1)+1, HL_ALIGNOF(dsd_gather_i_1));
	if(adsl_out_se == NULL) {
		adsp_client->inc_return = DEF_IRET_ERRAU;
		goto LBL_SYNC_PARAMS;
	}
	//dsl_wa_alloc2.adsc_wa_cur = NULL;
	//adsl_out_se->adsc_owner = dsl_wa_alloc2.adsc_wa_cur;
	char* achl_out_se_start = (char*)(adsl_out_se+1);
	dsl_ssl_client.achc_out_se_cur = achl_out_se_start;
	dsl_ssl_client.achc_out_se_end = dsl_wa_alloc2.achc_upper;
	
#ifdef HL_RDP_WEBTERM
	struct dsd_workarea_allocator* adsl_wa_alloc_out_cl = &dsl_wa_alloc2;
#else
	struct dsd_workarea_allocator* adsl_wa_alloc_out_cl = &adsp_client->dsc_wa_alloc1;
#endif
	struct dsd_gather_i_2* adsl_out_cl = (struct dsd_gather_i_2*)m_wa_allocator_reserve_lower(adsl_wa_alloc_out_cl, sizeof(dsd_gather_i_2)+1, HL_ALIGNOF(dsd_gather_i_2));
	if(adsl_out_cl == NULL) {
		adsp_client->inc_return = DEF_IRET_ERRAU;
		goto LBL_SYNC_PARAMS;
	}
	adsl_out_cl->adsc_owner = NULL;//m_wa_allocator_share_inc(adsl_wa_alloc_out_cl);
	char* achl_out_cl_start = (char*)(adsl_out_cl+1);
	dsl_ssl_client.achc_out_cl_cur = achl_out_cl_start;
	dsl_ssl_client.achc_out_cl_end = adsl_wa_alloc_out_cl->achc_upper;

#if SM_TRACE_RDP_CLIENT
	printf("#PROCESS-SSL: adsc_gai1_in_cl=%d adsc_gai1_in_se=%d out-cl=%d out-se=%d\n",
		m_gather_i_1_count_data_len(dsl_ssl_client.adsc_gai1_in_cl),
		m_gather_i_1_count_data_len(dsl_ssl_client.adsc_gai1_in_se),
		dsl_ssl_client.achc_out_cl_end-achl_out_cl_start,
		dsl_ssl_client.achc_out_se_end-achl_out_se_start);
#endif

#if HL_USE_AUX_SSL_FUNCTIONS
	adsp_client->adsc_aux_ssl_functions->m_hlcl01(&dsl_ssl_client);
#else
	m_hlcl01(&dsl_ssl_client);
#endif
	dsl_ssl_client.adsc_gai1_in_cl = m_gather_i_1_skip_processed(dsl_ssl_client.adsc_gai1_in_cl);
    dsl_ssl_client.adsc_gai1_in_se = m_gather_i_1_skip_processed(dsl_ssl_client.adsc_gai1_in_se);
	dsd_gather_i_1_pos dsl_in_cl2 = m_make_gather_pos(dsl_ssl_client.adsc_gai1_in_cl);
	dsd_gather_i_1_pos dsl_in_se2 = m_make_gather_pos(dsl_ssl_client.adsc_gai1_in_se);
	bol_ssl_changed = false;
	if(adsl_data_block != NULL && !m_cmp_gather_pos(&dsl_in_cl1, &dsl_in_cl2)) {
		adsl_data_block->adsc_data = dsl_ssl_client.adsc_gai1_in_cl;
		if(adsl_data_block->adsc_data == NULL) {
			m_fifo_remove_first(&adsp_client->dsc_to_ssl_cl);
			m_free_data_block(&adsl_data_block->dsc_slist_elem, adsp_client->dsc_wa_alloc1.adsc_aux);
		}
		bol_ssl_changed = true;
	}
	if(!m_cmp_gather_pos(&dsl_in_se1, &dsl_in_se2)) {
		adsc_gather_i_1_in = dsl_ssl_client.adsc_gai1_in_se;
		bol_ssl_changed = true;
	}

#if SM_TRACE_RDP_CLIENT
	printf("#PROCESS-SSL: ret=%d out-cl=%d out-se=%d\n",
		dsl_ssl_client.inc_return,
		dsl_ssl_client.achc_out_cl_cur-achl_out_cl_start,
		dsl_ssl_client.achc_out_se_cur-achl_out_se_start);
#endif

	if(achl_out_cl_start < dsl_ssl_client.achc_out_cl_cur) {
		adsl_out_cl->dsc_base.achc_ginp_cur = achl_out_cl_start;
		adsl_out_cl->dsc_base.achc_ginp_end = dsl_ssl_client.achc_out_cl_cur;
		adsl_out_cl->dsc_base.adsc_next = NULL;
		//m_gather_i_2_ref_inc(adsl_out_cl, adsl_wa_alloc_out_cl->adsc_aux);
		m_wa_allocator_commit_lower(adsl_wa_alloc_out_cl, adsl_out_cl->dsc_base.achc_ginp_end);
		adsl_out_cl->adsc_owner = m_wa_allocator_share_inc(adsl_wa_alloc_out_cl);
		m_gather_fifo_append(&adsp_client->dsc_to_rdpacc, &adsl_out_cl->dsc_base);
#if SM_TRACE_RDP_TRAFFIC
		printf("RDP DATA FROM SERVER Bytes:\n");
        printf("adsl_client->adsc_gai1_from_server:\tachc_ginp_cur=0x%X\tachc_ginp_end=0x%X\n",
			adsl_out_cl->dsc_base.achc_ginp_cur,
            adsl_out_cl->dsc_base.achc_ginp_end);
		m_aux_dump_gather(&adsp_client->dsc_aux, &adsl_out_cl->dsc_base, -1);
#endif
		bol_ssl_changed = true;
		struct dsd_workarea_chain* adsc_wa_chain = &adsp_client->dsc_wa_chain1;
		if(adsc_wa_chain != NULL && adsc_wa_chain->adsc_workarea_1 != NULL) {
			adsc_wa_chain->adsc_workarea_1->adsc_next = NULL;
		}
	}

	int iml_out_se = dsl_ssl_client.achc_out_se_cur-achl_out_se_start;
	if(iml_out_se > 0) {
#if 0
LBL_AGAIN:
		char* p1 = dsl_ssl_client.achc_out_se_cur;
		m_hlcl01(&dsl_ssl_client);
		if(dsl_ssl_client.inc_return != DEF_IRET_NORMAL){
			adsp_client->inc_return = DEF_IRET_SSL_FAILED;
			goto LBL_SYNC_PARAMS;
		}
#if 0
		char* p2 = dsl_ssl_client.achc_out_se_cur;
		if(p1 != p2) {
			goto LBL_AGAIN;
		}

#endif
#endif
		adsl_out_se->achc_ginp_cur = achl_out_se_start;
		adsl_out_se->achc_ginp_end = dsl_ssl_client.achc_out_se_cur;
		adsl_out_se->adsc_next = NULL;
		m_wa_allocator_commit_lower(&dsl_wa_alloc2, adsl_out_se->achc_ginp_end);
		m_gather_fifo_append(&dsl_gai1_out_to_server, adsl_out_se);
		bol_ssl_changed = true;
		//goto LBL_SYNC_PARAMS;
	}
	switch(dsl_ssl_client.inc_return) {
	case DEF_IRET_NORMAL:
		break;
	case DEF_IRET_END:
		if(adsp_client->dsc_rdpacc.inc_return != DEF_IRET_END)
			goto LBL_PROCESS_RDP;
		adsp_client->inc_return = DEF_IRET_END;
		goto LBL_SYNC_PARAMS;
	default:
		adsp_client->iec_extended_result = iec_rdpclient_extended_ssl_failed;
		adsp_client->inc_return = DEF_IRET_ERR_EXTENDED;
		goto LBL_SYNC_PARAMS;
	}
	//HeapValidate(GetProcessHeap(), 0, NULL);
	if(dsl_ssl_client.adsc_gai1_in_cl != NULL)
		goto LBL_PROCESS_SSL;
	adsl_cur_wa_alloc = &dsl_wa_alloc2;
	adsp_client->dsc_rdpacc.vpc_userfld = adsp_client->dsc_aux.vpc_userfld;
	adsp_client->dsc_rdpacc.amc_aux = adsp_client->dsc_aux.amc_aux;  /* pointer to subroutine */
	switch(adsp_client->iec_rdp_state) {
	case iec_state_rdp_tls_init:
		if(adsp_client->boc_ssl_initialized) {
			adsp_client->dsc_continue_after_ext.adsc_next = NULL;
			adsp_client->dsc_continue_after_ext.iec_cc_command = ied_ccc_continue_after_ext;
#if SM_TRACE_RDP_CLIENT
			printf("#iec_state_rdp_tls_init 1\n");
#endif
			if(adsp_client->dsc_rdpacc.adsc_cc_co1_ch != NULL) {
				adsp_client->inc_return = DEF_IRET_INT_ERROR;
				goto LBL_SYNC_PARAMS;
			}
#if SM_TRACE_RDP_CLIENT
			printf("#iec_state_rdp_tls_init 2 initialized credssp=%d\n", adsp_client->dsc_credssp.dsc_base.boc_initialized);
#endif
			if(adsp_client->dsc_credssp.dsc_base.boc_initialized) {
				adsp_client->dsc_rdpacc.adsc_cc_co1_ch = &adsp_client->dsc_continue_after_ext;
				adsp_client->iec_rdp_state = iec_state_rdp_tls_rdp;
				goto LBL_PROCESS_RDP;
			}
#if SM_TRACE_RDP_CLIENT
			printf("#iec_state_rdp_tls_init 3 user=%d pwd=%d\n",
				adsp_client->dsc_credssp.adsc_params->dsc_ucs_userid.imc_len_str,
				adsp_client->dsc_credssp.adsc_params->dsc_ucs_password.imc_len_str);
#endif
			if(m_unicode_string_empty(&adsp_client->dsc_credssp.adsc_params->dsc_ucs_userid)
				|| m_unicode_string_empty(&adsp_client->dsc_credssp.adsc_params->dsc_ucs_password))
			{
				adsp_client->inc_return = DEF_IRET_ERR_EXTENDED;
				adsp_client->iec_extended_result = iec_rdpclient_extended_credssp_no_credentials;
				goto LBL_SYNC_PARAMS;
			}
#if SM_TRACE_RDP_CLIENT
			printf("#iec_state_rdp_tls_init 4 adsp_client->adsc_end_cert=%p\n", adsp_client->adsc_end_cert);
#endif
			if(adsp_client->adsc_end_cert == NULL) {
				// TODO: Error
				adsp_client->inc_return = DEF_IRET_INT_ERROR;
				goto LBL_SYNC_PARAMS;
			}
			IDATPARR* adsl_subjectpubkey = adsp_client->adsc_end_cert->PubKeyValueOcsp;
			if(adsl_subjectpubkey == NULL || adsl_subjectpubkey->Cnt != 1) {
				// TODO: Error
				adsp_client->inc_return = DEF_IRET_INT_ERROR;
				goto LBL_SYNC_PARAMS;
			}
			IDATA* adsl_idata = adsl_subjectpubkey->ppArr[0];
			adsp_client->dsc_credssp.adsc_params->achc_subject_public_key = adsl_idata->Base + adsl_idata->Off;
			adsp_client->dsc_credssp.adsc_params->inc_subject_public_key_len = adsl_idata->Len;
			adsp_client->iec_rdp_state = iec_state_rdp_tls_credssp;
#if SM_TRACE_RDP_CLIENT
			printf("#iec_state_rdp_tls_init 5\n");
#endif
			goto LBL_PROCESS_CREDSSP;
		}
		if(bol_ssl_changed)
			goto LBL_PROCESS_SSL;
		adsp_client->inc_return = DEF_IRET_NORMAL;
		goto LBL_SYNC_PARAMS;
	case iec_state_rdp_tls_credssp:
		goto LBL_PROCESS_CREDSSP;
	case iec_state_rdp_tls_rdp:
		adsp_client->dsc_rdpacc.adsc_gather_i_1_in = adsp_client->dsc_to_rdpacc.adsc_first;
		goto LBL_PROCESS_RDP;
	}
	} /*end of LBL_PROCESS_SSL */
LBL_PROCESS_CREDSSP: {
	struct dsd_workarea_chain* adsc_wa_chain = (struct dsd_workarea_chain*)adsp_client->dsc_wa_alloc1.adsc_aux->vpc_userfld;
	struct dsd_workarea_chain dsl_rdp_wa_chain = *adsc_wa_chain;
	dsl_rdp_wa_chain.adsc_workarea_1 = NULL;
	adsp_client->dsc_wa_alloc1.adsc_aux->vpc_userfld = &dsl_rdp_wa_chain;
	
	dsd_call_credssp_01 dsl_call;
	dsl_call.dsc_base.inc_func = IM_GSSAPI_FUNC_INITIALIZE_CONTEXT;
	dsl_call.dsc_base.adsc_context = &adsp_client->dsc_credssp.dsc_base;
	dsl_call.dsc_base.adsc_gather_in = adsp_client->dsc_to_rdpacc.adsc_first;
	dsl_call.dsc_base.adsc_wa_alloc1 = &adsp_client->dsc_wa_alloc1;
	m_gather_fifo_init(&dsl_call.dsc_base.dsc_gather_out);
	m_gssapi_credssp_01(&dsl_call.dsc_base);
	adsp_client->dsc_wa_alloc1.adsc_aux->vpc_userfld = adsc_wa_chain;
	adsp_client->dsc_rdpacc.adsc_gather_i_1_in = m_gather_fifo_free_processed(&adsp_client->dsc_to_rdpacc);
	if(dsl_call.dsc_base.inc_return != DEF_IRET_NORMAL) {
		adsp_client->iec_extended_result = iec_rdpclient_extended_credssp_failed;
		adsp_client->inc_return = dsl_call.dsc_base.inc_return;
		goto LBL_SYNC_PARAMS;
	}
	if(dsl_call.dsc_base.dsc_gather_out.adsc_first == NULL) {
		if(bol_ssl_changed)
			goto LBL_PROCESS_SSL;
		adsp_client->inc_return = DEF_IRET_NORMAL;
		goto LBL_SYNC_PARAMS;
	}
	struct dsd_data_block* adsl_data_block = (struct dsd_data_block*)m_wa_allocator_alloc_lower(
		&adsp_client->dsc_wa_alloc1, sizeof(dsd_data_block), HL_ALIGNOF(dsd_data_block));
	if(adsl_data_block == NULL) {
		adsp_client->inc_return = DEF_IRET_ERRAU;
		goto LBL_SYNC_PARAMS;
	}
	// TODO: Free workareas
	adsl_data_block->adsc_wa1 = NULL;
	adsl_data_block->adsc_wa2 = m_wa_allocator_share_inc(&adsp_client->dsc_wa_alloc1);
	adsl_data_block->adsc_data = dsl_call.dsc_base.dsc_gather_out.adsc_first;
	adsl_data_block->dsc_workareas = dsl_rdp_wa_chain;
	//adsl_data_block->adsc_wa_aux = adsl_cur_wa_alloc->adsc_aux;
	//adsp_client->dsc_to_ssl_cl
	//dsl_ssl_client.adsc_gai1_in_cl = adsp_client->dsc_rdpacc.adsc_gai1_out_to_server;
	adsp_client->dsc_rdpacc.adsc_gai1_out_to_server = NULL;
#if SM_TRACE_RDP_TRAFFIC
	printf("RDP DATA TO SERVER Bytes:\n");
	m_aux_dump_gather(&adsp_client->dsc_aux, adsl_data_block->adsc_data, -1);
#endif
	m_fifo_append(&adsp_client->dsc_to_ssl_cl, &adsl_data_block->dsc_slist_elem);
	if(!adsp_client->dsc_credssp.dsc_base.boc_initialized)
		goto LBL_PROCESS_SSL;
	adsp_client->dsc_rdpacc.adsc_cc_co1_ch = &adsp_client->dsc_continue_after_ext;
	adsp_client->iec_rdp_state = iec_state_rdp_tls_rdp;
	goto LBL_PROCESS_SSL;
	} /*end of LBL_PROCESS_CREDSSP */
LBL_PROCESS_RDP: {
	struct dsd_workarea_chain* adsc_wa_chain = (struct dsd_workarea_chain*)adsl_cur_wa_alloc->adsc_aux->vpc_userfld;
	struct dsd_workarea_chain dsl_rdp_wa_chain;
	dsl_rdp_wa_chain.adsc_aux = adsc_wa_chain->adsc_aux;
	dsl_rdp_wa_chain.adsc_workarea_1 = NULL;
	adsl_cur_wa_alloc->adsc_aux->vpc_userfld = &dsl_rdp_wa_chain;
	adsp_client->dsc_rdpacc.achc_work_area = adsl_cur_wa_alloc->achc_lower;
	adsp_client->dsc_rdpacc.inc_len_work_area = adsl_cur_wa_alloc->achc_upper - adsl_cur_wa_alloc->achc_lower;
#if SM_MINIFY_WORKAREAS
	if(adsp_client->dsc_rdpacc.inc_len_work_area > 64)
		adsp_client->dsc_rdpacc.inc_len_work_area = 64;
#endif

	//HeapValidate(GetProcessHeap(), 0, NULL);
#ifdef HL_RDP_WEBTERM
	m_wt_rdp_client_1(&adsp_client->dsc_rdpacc);
#else
	m_rdpclient_1(&adsp_client->dsc_rdpacc);
#endif
	//HeapValidate(GetProcessHeap(), 0, NULL);
	adsl_cur_wa_alloc->adsc_aux->vpc_userfld = adsc_wa_chain;
	adsl_cur_wa_alloc->achc_lower = adsp_client->dsc_rdpacc.achc_work_area;
	adsl_cur_wa_alloc->achc_upper = adsp_client->dsc_rdpacc.achc_work_area + adsp_client->dsc_rdpacc.inc_len_work_area;
	char* achl_p = (char*)adsp_client->dsc_rdpacc.adsc_gai1_out_to_server;
	char* achl_managed_wa = NULL;
	if(achl_p != NULL && achl_p >= adsl_cur_wa_alloc->achc_lower && achl_p < adsl_cur_wa_alloc->achc_upper) {
		achl_managed_wa = adsl_cur_wa_alloc->adsc_wa_cur;
		adsl_cur_wa_alloc->adsc_wa_cur = NULL;
		adsl_cur_wa_alloc->achc_lower = NULL;
		adsl_cur_wa_alloc->achc_upper = NULL;
		//adsc_wa_chain->adsc_workarea_1 = NULL;
		//adsl_managed_wa = NULL;
	}
#ifdef HL_RDP_WEBTERM
	achl_p = (char*)adsp_client->dsc_rdpacc.adsc_wtr1_out;
	if(achl_p != NULL && achl_p >= adsl_cur_wa_alloc->achc_lower && achl_p < adsl_cur_wa_alloc->achc_upper) {
		achl_managed_wa = adsl_cur_wa_alloc->adsc_wa_cur;
		adsl_cur_wa_alloc->adsc_wa_cur = NULL;
		adsl_cur_wa_alloc->achc_lower = NULL;
		adsl_cur_wa_alloc->achc_upper = NULL;
		//adsc_wa_chain->adsc_workarea_1 = NULL;
		//adsl_managed_wa = NULL;
	}
	struct dsd_wt_record_1* adsl_wtr1_out2 = adsp_client->dsc_rdpacc.adsc_wtr1_out;
	if(adsl_wtr1_out2 != NULL) {
		if(adsl_cur_wa_alloc != &dsl_wa_alloc2) {
			int a = 0;
		}
		*aadsc_wtr1_out_fifo = adsl_wtr1_out2;
		while(adsl_wtr1_out2 != NULL) {
			if(adsl_wtr1_out2->adsc_next == NULL)
				break;
			adsl_wtr1_out2 = adsl_wtr1_out2->adsc_next;
		}
		aadsc_wtr1_out_fifo = &adsl_wtr1_out2->adsc_next;
		adsp_client->dsc_rdpacc.adsc_wtr1_out = NULL;
	}
#endif
#if 0
	if(adsp_client->dsc_rdpacc.inc_return != DEF_IRET_NORMAL) {
		if(adsp_client->dsc_rdpacc.inc_func == DEF_IFUNC_CLOSE) {
			
		}
		goto LBL_SYNC_PARAMS2;
	}
#endif
#if SM_TRACE_RDP_TRAFFIC
	if(adsp_client->dsc_rdpacc.adsc_gai1_out_to_server != NULL) {
		printf("RDP DATA TO SERVER Bytes:\n");
		m_aux_dump_gather(&adsp_client->dsc_aux, adsp_client->dsc_rdpacc.adsc_gai1_out_to_server, -1);
	}
#endif
	switch(adsp_client->iec_rdp_state) {
	case iec_state_rdp_negotiate:
		if(m_gather_i_1_skip_processed(adsp_client->dsc_rdpacc.adsc_gai1_out_to_server) == NULL)
			break;
		adsp_client->iec_rdp_state = iec_state_rdp_negotiate2;
		break;
    case iec_state_rdp_negotiate2: {
		struct dsd_se_co1 *adsl_se_co1_ch = adsp_client->dsc_rdpacc.adsc_se_co1_ch;
		struct dsd_se_co1 **adsl_se_co1_last = &adsp_client->dsc_rdpacc.adsc_se_co1_ch;
		while(adsl_se_co1_ch != NULL) {
			if(adsl_se_co1_ch->iec_se_command == ied_sec_rdp_neg_resp) {
				*adsl_se_co1_last = adsl_se_co1_ch->adsc_next;
				goto LBL_RDP_NEG_RESP;
			}
			adsl_se_co1_last = &adsl_se_co1_ch->adsc_next;
			adsl_se_co1_ch = adsl_se_co1_ch->adsc_next;
		}
		break;
LBL_RDP_NEG_RESP:
		struct dsd_rdp_neg_resp* adsl_rdp_neg_resp = (struct dsd_rdp_neg_resp*)(adsl_se_co1_ch + 1);
		adsp_client->dsc_rdp_neg_resp = *adsl_rdp_neg_resp;
		switch(adsl_rdp_neg_resp->usc_type) {
		case 0x02:
			break;
		case 0x03:
			adsp_client->inc_return = DEF_IRET_ERR_EXTENDED;
			adsp_client->iec_extended_result = iec_rdpclient_extended_rdp_negotiation_failed;
			goto LBL_SYNC_PARAMS;
		default:
			adsp_client->inc_return = DEF_IRET_INT_ERROR;
			goto LBL_SYNC_PARAMS;
		}
		if(adsl_rdp_neg_resp->umc_selected_protocol != PROTOCOL_RDP) {
            struct dsd_hl_ssl_c_1& dsl_ssl_client = adsp_client->dsc_ssl_client;
            // Prepare client struct
            memset(&dsl_ssl_client, 0, sizeof(struct dsd_hl_ssl_c_1));
            dsl_ssl_client.inc_func = DEF_IFUNC_START;

			dsl_ssl_client.amc_aux = &m_subaux_rdpclient_ssl;
			dsl_ssl_client.vpc_userfld = adsp_client;
            dsl_ssl_client.vpc_config_id = adsp_client->vpc_config_id;
            dsl_ssl_client.amc_conn_callback = &m_ssl_conn_callback;
			adsp_client->boc_ssl_initialized = FALSE;
            adsp_client->iec_rdp_state = iec_state_rdp_tls_init;

#ifdef XH_INTERFACE
			ds__hmem* adsl_ssl_hmem_context = &adsp_client->dsc_ssl_hmem_context;
			memset(adsl_ssl_hmem_context, 0, sizeof(ds__hmem));
			adsl_ssl_hmem_context->in__aux_up_version = 1;
			adsl_ssl_hmem_context->am__aux2 = m_subaux_rdpclient_ssl;
			adsl_ssl_hmem_context->in__flags = 0;
			adsl_ssl_hmem_context->vp__context = adsp_client;
#endif

			//dsl_wa_alloc2.adsc_aux = &adsp_client->dsc_aux;
			//dsl_wa_alloc2.adsc_wa_cur = NULL;
			switch(adsl_rdp_neg_resp->umc_selected_protocol) {
			case PROTOCOL_SSL:
				adsp_client->dsc_credssp.dsc_base.boc_initialized = TRUE;
				break;
			case PROTOCOL_HYBRID: {
				adsp_client->dsc_credssp.dsc_base.boc_initialized = FALSE;
				break;
			}
			default:
				adsp_client->inc_return = DEF_IRET_INT_ERROR;
				goto LBL_SYNC_PARAMS;
			}
			adsp_client->dsc_rdpacc.adsc_gather_i_1_in = m_gather_i_1_skip_processed(adsc_gather_i_1_in);
            goto LBL_PROCESS_SSL;
        }
        adsp_client->iec_rdp_state = iec_state_rdp_pure;
		break;
	}
	case iec_state_rdp_pure:
		break;
	case iec_state_rdp_tls_init:
		goto LBL_SYNC_PARAMS2;
	case iec_state_rdp_tls_credssp:
		goto LBL_SYNC_PARAMS2;
    case iec_state_rdp_tls_rdp: {
		adsp_client->dsc_rdpacc.adsc_gather_i_1_in = m_gather_fifo_free_processed(&adsp_client->dsc_to_rdpacc);
        struct dsd_hl_ssl_c_1& dsl_ssl_client = adsp_client->dsc_ssl_client;
        if(adsp_client->dsc_rdpacc.inc_return != DEF_IRET_NORMAL)
			goto LBL_SYNC_PARAMS2;
		//adsp_client->dsc_to_ssl_cl
		if(adsp_client->dsc_rdpacc.adsc_gai1_out_to_server != NULL) {
#if 0
			if(achl_managed_wa != NULL) {
				adsl_cur_wa_alloc->adsc_aux->amc_aux(
					adsl_cur_wa_alloc->adsc_aux->vpc_userfld, DEF_AUX_MARK_WORKAREA_INC, achl_managed_wa, 0);
			}
#endif
			struct dsd_data_block* adsl_data_block = (struct dsd_data_block*)m_wa_allocator_alloc_lower(
				&adsp_client->dsc_wa_alloc1, sizeof(dsd_data_block), HL_ALIGNOF(dsd_data_block));
			if(adsl_data_block == NULL) {
				adsp_client->inc_return = DEF_IRET_ERRAU;
				goto LBL_SYNC_PARAMS;
			}
			adsl_data_block->adsc_wa1 = achl_managed_wa;
			adsl_data_block->adsc_wa2 = m_wa_allocator_share_inc(&adsp_client->dsc_wa_alloc1);
			adsl_data_block->adsc_data = adsp_client->dsc_rdpacc.adsc_gai1_out_to_server;
			adsp_client->dsc_rdpacc.adsc_gai1_out_to_server = NULL;
			//struct dsd_workarea_chain* adsc_wa_chain = (struct dsd_workarea_chain*)adsl_cur_wa_alloc->adsc_aux->vpc_userfld;
			adsl_data_block->dsc_workareas = dsl_rdp_wa_chain;
			//adsl_data_block->adsc_wa_aux = adsl_cur_wa_alloc->adsc_aux;
			//adsp_client->dsc_to_ssl_cl
			//dsl_ssl_client.adsc_gai1_in_cl = adsp_client->dsc_rdpacc.adsc_gai1_out_to_server;
			adsp_client->dsc_rdpacc.adsc_gai1_out_to_server = NULL;
			m_fifo_append(&adsp_client->dsc_to_ssl_cl, &adsl_data_block->dsc_slist_elem);
			goto LBL_PROCESS_SSL;
		}
		dsl_ssl_client.adsc_gai1_in_se = adsc_gather_i_1_in;
		if(dsl_ssl_client.adsc_gai1_in_se != NULL)
			goto LBL_PROCESS_SSL;
		if(bol_ssl_changed)
			goto LBL_PROCESS_SSL;
		goto LBL_SYNC_PARAMS2;
    }
	default:
		adsp_client->inc_return = DEF_IRET_INT_ERROR;
		goto LBL_SYNC_PARAMS;
	}
	adsp_client->adsc_gather_i_1_in = adsp_client->dsc_rdpacc.adsc_gather_i_1_in;
	adsp_client->dsc_rdpacc.adsc_gather_i_1_in = m_gather_i_1_skip_processed(adsc_gather_i_1_in);
	m_gather_fifo_append_list2(&dsl_gai1_out_to_server, adsp_client->dsc_rdpacc.adsc_gai1_out_to_server);
	adsp_client->dsc_rdpacc.adsc_gai1_out_to_server = NULL;
	goto LBL_SYNC_PARAMS2;
	} /*end of LBL_PROCESS_RDP */
LBL_SYNC_PARAMS2:
	adsp_client->inc_return = adsp_client->dsc_rdpacc.inc_return;
	if(adsp_client->inc_return != DEF_IRET_NORMAL) {
		adsp_client->inc_return = DEF_IRET_ERR_EXTENDED;
		adsp_client->iec_extended_result = iec_rdpclient_extended_rdpacc_failed;
	}
LBL_SYNC_PARAMS:
	if(adsp_client->inc_return != DEF_IRET_NORMAL) {
		goto LBL_CLEANUP;
	}
#ifdef HL_RDP_WEBTERM
	// Mark all remaining gathers
	m_gather_fifo_foreach(&adsp_client->dsc_to_rdpacc, &m_gather_i_2_ref_inc, &adsp_client->dsc_aux);
#endif
	adsp_client->achc_work_area = dsl_wa_alloc2.achc_lower;
	adsp_client->inc_len_work_area = dsl_wa_alloc2.achc_upper - dsl_wa_alloc2.achc_lower;
	adsp_client->adsc_cc_co1_ch = adsp_client->dsc_rdpacc.adsc_cc_co1_ch;
	adsp_client->adsc_se_co1_ch = adsp_client->dsc_rdpacc.adsc_se_co1_ch;
	adsp_client->adsc_gai1_out_to_server = dsl_gai1_out_to_server.adsc_first;
	adsp_client->boc_callagain = adsp_client->dsc_rdpacc.boc_callagain;
	return;
LBL_CLEANUP:
	struct dsd_call_credssp_01 dsl_credssp_call;
	dsl_credssp_call.dsc_base.inc_func = IM_GSSAPI_FUNC_CLOSE;
	dsl_credssp_call.dsc_base.adsc_context = &adsp_client->dsc_credssp.dsc_base;
	dsl_credssp_call.dsc_base.adsc_gather_in = NULL;
	dsl_credssp_call.dsc_base.adsc_wa_alloc1 = &adsp_client->dsc_wa_alloc1;
	m_gather_fifo_init(&dsl_credssp_call.dsc_base.dsc_gather_out);
	m_gssapi_credssp_01(&dsl_credssp_call.dsc_base);

	adsp_client->dsc_rdpacc.inc_func = DEF_IFUNC_CLOSE;
	adsp_client->dsc_rdpacc.adsc_gather_i_1_in = NULL;
#ifdef HL_RDP_WEBTERM
	m_wt_rdp_client_1(&adsp_client->dsc_rdpacc);
#else
	m_rdpclient_1(&adsp_client->dsc_rdpacc);
#endif

	m_rdp_client_2_cleanup_ssl(adsp_client);

	m_fifo_destroy(&adsp_client->dsc_to_ssl_cl, adsp_client->dsc_wa_alloc1.adsc_aux);
	m_gather_fifo_destroy(&adsp_client->dsc_to_rdpacc);
	m_wa_allocator_destroy(&adsp_client->dsc_wa_alloc1);

	adsp_client->adsc_cc_co1_ch = NULL;
	adsp_client->adsc_se_co1_ch = NULL;
	adsp_client->adsc_gai1_out_to_server = NULL;
	return;
}
