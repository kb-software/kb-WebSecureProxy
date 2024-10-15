#ifndef _HOB_GATHER_TRACER_HPP_
#define _HOB_GATHER_TRACER_HPP_

#define HL_GATHER_TRACER_CMD_INIT 0
#define HL_GATHER_TRACER_CMD_COMPRESS_BEGIN 1
#define HL_GATHER_TRACER_CMD_COMRPESS_IN 3
#define HL_GATHER_TRACER_CMD_COMRPESS_IN2 4
#define HL_GATHER_TRACER_CMD_COMPRESS_OUT 5
#define HL_GATHER_TRACER_CMD_COMPRESS_DONE 6
#define HL_GATHER_TRACER_CMD_END 6

#if !HOB_TK_NO_INCLUDE
#include <xs-tk-gather-tools-01.cpp>
#include <hob-cd-record-1.h>
#include <stdio.h>
#endif

#define LBL_FAIL_GOTO(b, l) if(!(b)) goto l
#define LBL_FAIL_RET(b) if(!(b)) return FALSE

struct dsd_gather_tracer {
	FILE* adsc_file;
};


static BOOL m_gather_tracer_init(dsd_gather_tracer* adps_this, const char* strp_file, BOOL bop_write) {
	adps_this->adsc_file = fopen(strp_file, bop_write ? "wb" : "rb");
	if(adps_this->adsc_file == NULL)
		return FALSE;
	return TRUE;
}

static BOOL m_gather_tracer_write_bytes(dsd_gather_tracer* adps_this, const void* achp_value, int inp_length) {
	if(adps_this->adsc_file == NULL)
		return FALSE;
	size_t szl_len = (size_t)inp_length;
	size_t szl_ret = fwrite(achp_value, sizeof(char), inp_length, adps_this->adsc_file);
	if(szl_ret != szl_len)
		return FALSE;
	return TRUE;
}

static BOOL m_gather_tracer_write_uint32(dsd_gather_tracer* adps_this, unsigned int unp_value) {
	char chrl_value[4];
	chrl_value[0] = (char)(unp_value>>0);
	chrl_value[1] = (char)(unp_value>>8);
	chrl_value[2] = (char)(unp_value>>16);
	chrl_value[3] = (char)(unp_value>>24);
	return m_gather_tracer_write_bytes(adps_this, chrl_value, 4);
}

static BOOL m_gather_tracer_write_gathers(dsd_gather_tracer* adps_this, const struct dsd_gather_i_1* adsp_gathers) {
	const struct dsd_gather_i_1* adsl_g = adsp_gathers;
	int inl_num_gathers = 0;
	while(adsl_g != NULL) {
		inl_num_gathers++;
		adsl_g = adsl_g->adsc_next;
	}
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, inl_num_gathers));
	adsl_g = adsp_gathers;
	while(adsl_g != NULL) {
		size_t inl_len = adsl_g->achc_ginp_end-adsl_g->achc_ginp_cur;
		LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, inl_len));
		LBL_FAIL_RET(m_gather_tracer_write_bytes(adps_this, adsl_g->achc_ginp_cur, inl_len));
		adsl_g = adsl_g->adsc_next;
	}
	return TRUE;
}

static void m_gather_tracer_destroy(dsd_gather_tracer* adps_this) {
	if(adps_this->adsc_file != NULL) {
		fclose(adps_this->adsc_file);
		adps_this->adsc_file = NULL;
	}
}


static BOOL m_gather_tracer_read_bytes(dsd_gather_tracer* adps_this, void* achp_value, int inp_length) {
	if(adps_this->adsc_file == NULL)
		return FALSE;
	size_t szl_len = (size_t)inp_length;
	size_t szl_ret = fread(achp_value, sizeof(char), inp_length, adps_this->adsc_file);
	if(szl_ret != szl_len)
		return FALSE;
	return TRUE;
}

static BOOL m_gather_tracer_read_uint32(dsd_gather_tracer* adps_this, unsigned int* aunp_value) {
	unsigned char chrl_value[4];
	LBL_FAIL_RET(m_gather_tracer_read_bytes(adps_this, chrl_value, 4));
	*aunp_value = (chrl_value[0]<<0) | (chrl_value[1]<<8) | (chrl_value[2]<<16) | (chrl_value[3]<<24);
	return TRUE;
}

static BOOL m_gather_tracer_read_int32(dsd_gather_tracer* adps_this, int* aunp_value) {
	return m_gather_tracer_read_uint32(adps_this, (unsigned int*)aunp_value);
}

static BOOL m_gather_tracer_read_gathers(dsd_gather_tracer* adps_this, struct dsd_gather_i_1** aadsp_gathers) {
	int inl_num_gathers = 0;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &inl_num_gathers));
	dsd_gather_i_1** aadsl_next = aadsp_gathers;
	*aadsl_next = NULL;
	while(inl_num_gathers > 0) {
		int inl_len;
		LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &inl_len));
		dsd_gather_i_1* adsl_gather = (dsd_gather_i_1*)malloc(sizeof(dsd_gather_i_1)+inl_len);
		adsl_gather->adsc_next = NULL;
		adsl_gather->achc_ginp_cur = (char*)(adsl_gather+1);
		adsl_gather->achc_ginp_end = adsl_gather->achc_ginp_cur + inl_len;
		LBL_FAIL_RET(m_gather_tracer_read_bytes(adps_this, adsl_gather->achc_ginp_cur, inl_len));
		*aadsl_next = adsl_gather;
		aadsl_next = &adsl_gather->adsc_next;
		inl_num_gathers--;
	}
	return TRUE;
}

static BOOL m_trace_cdrf_enc_init(dsd_gather_tracer* adps_this, const struct dsd_cdr_ctrl* adsp_cdrf_enc) {
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, HL_GATHER_TRACER_CMD_INIT));
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, adsp_cdrf_enc->imc_param_1));
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, adsp_cdrf_enc->imc_param_2));
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, adsp_cdrf_enc->imc_param_3));
	return TRUE;
}

static BOOL m_trace_cdrf_enc_compress_in(dsd_gather_tracer* adps_this, const struct dsd_cdr_ctrl* adsp_cdrf_enc) {
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, HL_GATHER_TRACER_CMD_COMPRESS_BEGIN));
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, HL_GATHER_TRACER_CMD_COMRPESS_IN));
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, adsp_cdrf_enc->boc_mp_flush));
	int iml_len = m_gather_i_1_count_data_len(adsp_cdrf_enc->adsc_gai1_in);
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, iml_len));
	LBL_FAIL_RET(m_gather_tracer_write_gathers(adps_this, adsp_cdrf_enc->adsc_gai1_in));
	return TRUE;
}

static BOOL m_trace_cdrf_enc_compress_in2(dsd_gather_tracer* adps_this, const struct dsd_cdr_ctrl* adsp_cdrf_enc) {
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, HL_GATHER_TRACER_CMD_COMRPESS_IN2));
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, adsp_cdrf_enc->achc_out_end-adsp_cdrf_enc->achc_out_cur));
	return TRUE;
}

static BOOL m_trace_cdrf_enc_compress_out(dsd_gather_tracer* adps_this, const struct dsd_cdr_ctrl* adsp_cdrf_enc, char* achp_out_start) {
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, HL_GATHER_TRACER_CMD_COMPRESS_OUT));
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, adsp_cdrf_enc->boc_sr_flush));
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, adsp_cdrf_enc->achc_out_cur-achp_out_start));
	LBL_FAIL_RET(m_gather_tracer_write_bytes(adps_this, achp_out_start, adsp_cdrf_enc->achc_out_cur-achp_out_start));
	return TRUE;
}

static BOOL m_trace_cdrf_enc_compress_done(dsd_gather_tracer* adps_this, const struct dsd_cdr_ctrl* adsp_cdrf_enc) {
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, HL_GATHER_TRACER_CMD_COMPRESS_DONE));
	return TRUE;
}

static BOOL m_trace_cdrf_enc_end(dsd_gather_tracer* adps_this) {
	LBL_FAIL_RET(m_gather_tracer_write_uint32(adps_this, HL_GATHER_TRACER_CMD_END));
	return TRUE;
}

static BOOL m_trace_cdrf_enc_read_init(dsd_gather_tracer* adps_this, struct dsd_cdr_ctrl* adsp_cdrf_enc) {
	int inl_cmd;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &inl_cmd));
	if(inl_cmd != HL_GATHER_TRACER_CMD_INIT)
		return FALSE;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &adsp_cdrf_enc->imc_param_1));
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &adsp_cdrf_enc->imc_param_2));
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &adsp_cdrf_enc->imc_param_3));
	return TRUE;
}

static BOOL m_trace_cdrf_enc_read_compress_in(dsd_gather_tracer* adps_this, struct dsd_cdr_ctrl* adsp_cdrf_enc, int* aimp_length) {
	int inl_cmd;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &inl_cmd));
	if(inl_cmd != HL_GATHER_TRACER_CMD_COMRPESS_IN)
		return FALSE;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &adsp_cdrf_enc->boc_mp_flush));
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, aimp_length));
	LBL_FAIL_RET(m_gather_tracer_read_gathers(adps_this, &adsp_cdrf_enc->adsc_gai1_in));
	return TRUE;
}

static BOOL m_trace_cdrf_enc_read_compress_in2(dsd_gather_tracer* adps_this, struct dsd_cdr_ctrl* adsp_cdrf_enc) {
	int inl_cmd;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &inl_cmd));
	if(inl_cmd != HL_GATHER_TRACER_CMD_COMRPESS_IN2)
		return FALSE;
	int inl_bufout;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &inl_bufout));
	char* achl_end = adsp_cdrf_enc->achc_out_cur + inl_bufout;
	if(achl_end > adsp_cdrf_enc->achc_out_end)
		return FALSE;
	adsp_cdrf_enc->achc_out_end = achl_end;
	return TRUE;
}

static BOOL m_trace_cdrf_enc_read_compress_out(dsd_gather_tracer* adps_this, struct dsd_cdr_ctrl* adsp_cdrf_enc) {
	int inl_cmd;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &inl_cmd));
	if(inl_cmd != HL_GATHER_TRACER_CMD_COMPRESS_OUT)
		return FALSE;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &adsp_cdrf_enc->boc_sr_flush));
	int inl_length;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &inl_length));
	char* achl_end = adsp_cdrf_enc->achc_out_cur + inl_length;
	if(achl_end > adsp_cdrf_enc->achc_out_end)
		return FALSE;
	adsp_cdrf_enc->achc_out_end = achl_end;
	LBL_FAIL_RET(m_gather_tracer_read_bytes(adps_this, adsp_cdrf_enc->achc_out_cur, inl_length));
	return TRUE;
}

static BOOL m_trace_cdrf_enc_read_compress_done(dsd_gather_tracer* adps_this, struct dsd_cdr_ctrl* adsp_cdrf_enc) {
	int inl_cmd;
	LBL_FAIL_RET(m_gather_tracer_read_int32(adps_this, &inl_cmd));
	if(inl_cmd != HL_GATHER_TRACER_CMD_COMPRESS_DONE)
		return FALSE;
	dsd_gather_i_1* adsl_gather = adsp_cdrf_enc->adsc_gai1_in;
	while(adsl_gather != NULL) {
		dsd_gather_i_1* adsl_next = adsl_gather->adsc_next;
		free(adsl_gather);
		adsl_gather = adsl_next;
	}
	adsp_cdrf_enc->adsc_gai1_in = NULL;
	return TRUE;
}

#ifndef SM_USE_GATHER_TRACER_REPLAY
#define SM_USE_GATHER_TRACER_REPLAY	1
#endif

#if SM_USE_GATHER_TRACER_REPLAY

typedef void amd_m_cdx_enc( struct dsd_cdr_ctrl *adsp_cdx_ctrl );

#define SM_USE_COMPARE_TRACED_COMPRESSION	(0)
#define SM_USE_COMPRESSION2	1
#define SM_USE_COMPARE_COMPRESSION2	(SM_USE_COMPRESSION2 && 0)
#define SM_USE_COMPRESSION3	1
#define SM_USE_COMPARE_COMPRESSION3	(SM_USE_COMPRESSION3 && 0)
#define SM_USE_COMPRESSION4	1
#define SM_USE_DECOMPRESSION4	1
#define SM_USE_DECOMPRESSION5	1

#include <zlib.h>

/* The following macro calls a zlib routine and checks the return
   value. If the return value ("status") is not OK, it prints an error
   message and exits the program. Zlib's error statuses are all less
   than zero. */

#define CALL_ZLIB(x) {                                                  \
        int status;                                                     \
        status = x;                                                     \
        if (status < 0) {                                               \
            fprintf (stderr,                                            \
                     "%s:%d: %s returned a bad status of %d.\n",        \
                     __FILE__, __LINE__, #x, status);                   \
            exit (EXIT_FAILURE);                                        \
        }                                                               \
    }

/* Maximum value for memLevel in deflateInit2 */
#ifndef MAX_MEM_LEVEL
#  ifdef MAXSEG_64K
#    define MAX_MEM_LEVEL 8
#  else
#    define MAX_MEM_LEVEL 9
#  endif
#endif

#define CHUNK 0x4000

static int m_compare_data(const char* achp_w1, const char* achp_w2, int imp_len) {
	for(int inl_p = 0; inl_p<imp_len; inl_p++) {
		if(achp_w1[inl_p] != achp_w2[inl_p])
			return inl_p;
	}
	return -1;
}

static BOOL m_replay_trace(char* achp_file, amd_m_cdx_enc amp_enc, const struct dsd_cdr_ctrl* adsp_cdr_ctrl) {
	struct dsd_gather_tracer dsl_tracer;
	LBL_FAIL_RET(m_gather_tracer_init(&dsl_tracer, achp_file, FALSE));
	struct dsd_cdr_ctrl dsl_cdr_ctrl = *adsp_cdr_ctrl;
	LBL_FAIL_RET(m_trace_cdrf_enc_read_init(&dsl_tracer, &dsl_cdr_ctrl));
	amp_enc(&dsl_cdr_ctrl);
	if(dsl_cdr_ctrl.imc_return != DEF_IRET_NORMAL)
		return FALSE;
	int inl_message_count = 0;
#if SM_USE_COMPRESSION2
	struct dsd_cdr_ctrl dsl_cdr_ctrl2;
	memset(&dsl_cdr_ctrl2, 0, sizeof(dsl_cdr_ctrl2));
	dsl_cdr_ctrl2.amc_aux = dsl_cdr_ctrl.amc_aux;
	dsl_cdr_ctrl2.vpc_userfld = dsl_cdr_ctrl.vpc_userfld;
	dsl_cdr_ctrl2.imc_param_1 = dsl_cdr_ctrl.imc_param_1;
	dsl_cdr_ctrl2.imc_param_2 = dsl_cdr_ctrl.imc_param_2;
	dsl_cdr_ctrl2.imc_param_3 = dsl_cdr_ctrl.imc_param_3;
	dsl_cdr_ctrl2.imc_param_4 = dsl_cdr_ctrl.imc_param_4;
	amp_enc(&dsl_cdr_ctrl2);
	if(dsl_cdr_ctrl2.imc_return != DEF_IRET_NORMAL)
		return FALSE;
#endif
	const char END_MARKER[] = { 0x00, 0x00, 0xff, 0xff };
#if SM_USE_COMPRESSION3
	z_stream dsl_zlib_strm;
	memset(&dsl_zlib_strm, 0, sizeof(dsl_zlib_strm));
	dsl_zlib_strm.zalloc = Z_NULL;
	dsl_zlib_strm.zfree  = Z_NULL;
	dsl_zlib_strm.opaque = Z_NULL;
	CALL_ZLIB (deflateInit2 (&dsl_zlib_strm, Z_BEST_COMPRESSION, Z_DEFLATED,
									dsl_cdr_ctrl.imc_param_2, 8,
									Z_DEFAULT_STRATEGY));
#endif
#if SM_USE_COMPRESSION4
	struct dsd_cdr_ctrl dsl_cdr_ctrl4;
	memset(&dsl_cdr_ctrl4, 0, sizeof(dsl_cdr_ctrl4));
	dsl_cdr_ctrl4.amc_aux = dsl_cdr_ctrl.amc_aux;
	dsl_cdr_ctrl4.vpc_userfld = dsl_cdr_ctrl.vpc_userfld;
	dsl_cdr_ctrl4.imc_param_1 = dsl_cdr_ctrl.imc_param_1;
	dsl_cdr_ctrl4.imc_param_2 = dsl_cdr_ctrl.imc_param_2;
	dsl_cdr_ctrl4.imc_param_3 = dsl_cdr_ctrl.imc_param_3;
	dsl_cdr_ctrl4.imc_param_4 = dsl_cdr_ctrl.imc_param_4;
	amp_enc(&dsl_cdr_ctrl4);
	if(dsl_cdr_ctrl2.imc_return != DEF_IRET_NORMAL)
		return FALSE;
#endif
#if SM_USE_DECOMPRESSION4
	z_stream dsl_zlib_strm_dec;
	memset(&dsl_zlib_strm_dec, 0, sizeof(dsl_zlib_strm_dec));
	dsl_zlib_strm_dec.zalloc = Z_NULL;
	dsl_zlib_strm_dec.zfree  = Z_NULL;
	dsl_zlib_strm_dec.opaque = Z_NULL;
	CALL_ZLIB (inflateInit2_( &dsl_zlib_strm_dec, dsl_cdr_ctrl.imc_param_2, ZLIB_VERSION, sizeof(dsl_zlib_strm_dec)));
#endif
#if SM_USE_DECOMPRESSION5
	z_stream dsl_zlib_strm_dec5;
	memset(&dsl_zlib_strm_dec5, 0, sizeof(dsl_zlib_strm_dec5));
	dsl_zlib_strm_dec5.zalloc = Z_NULL;
	dsl_zlib_strm_dec5.zfree  = Z_NULL;
	dsl_zlib_strm_dec5.opaque = Z_NULL;
	CALL_ZLIB (inflateInit2_( &dsl_zlib_strm_dec5, dsl_cdr_ctrl.imc_param_2, ZLIB_VERSION, sizeof(dsl_zlib_strm_dec5)));
#endif
	char chrl_work1[32 * 2048];
	char chrl_work2[32 * 2048];
	do {
		int inl_cmd;
		LBL_FAIL_RET(m_gather_tracer_read_int32(&dsl_tracer, &inl_cmd));
		switch(inl_cmd) {
		case HL_GATHER_TRACER_CMD_COMPRESS_BEGIN: {
			int iml_input_len;
		   LBL_FAIL_RET(m_trace_cdrf_enc_read_compress_in(&dsl_tracer, &dsl_cdr_ctrl, &iml_input_len));
			if(iml_input_len != m_gather_i_1_count_data_len(dsl_cdr_ctrl.adsc_gai1_in)) {
				printf("Error: Input size mismatch\n");
				return FALSE;
			}
#if SM_USE_COMPRESSION2
			char* achl_input2 = (char*)malloc(iml_input_len);
			const dsd_gather_i_1* adsl_tmp2 = dsl_cdr_ctrl.adsc_gai1_in;
			int inl_ret = m_gather1_copy_const(&adsl_tmp2, achl_input2, achl_input2+iml_input_len);
			if(inl_ret != iml_input_len) {
					printf("Error: m_gather1_copy failed\n");
					return FALSE;
			}
			char* achl_output2 = (char*)malloc(iml_input_len<<1);
			char* achl_output2_end2 = achl_output2 + (iml_input_len<<1);
			memset(achl_output2, 0, iml_input_len<<1);
			dsd_gather_i_1 dsl_tmp2b;
			dsl_tmp2b.achc_ginp_cur = achl_input2;
			dsl_tmp2b.achc_ginp_end = achl_input2 + iml_input_len;
			dsl_tmp2b.adsc_next = NULL;
			dsl_cdr_ctrl2.adsc_gai1_in = &dsl_tmp2b;
			dsl_cdr_ctrl2.achc_out_cur = achl_output2;
			dsl_cdr_ctrl2.achc_out_end = achl_output2_end2;
			dsl_cdr_ctrl2.boc_mp_flush = dsl_cdr_ctrl.boc_mp_flush;
			if(inl_message_count >= 1) {
				int a = 0;
			}
			do {
				amp_enc(&dsl_cdr_ctrl2);
				if(dsl_cdr_ctrl2.imc_return != DEF_IRET_NORMAL) {
					printf("Error: Compression failed return=%d\n", dsl_cdr_ctrl2.imc_return);
					return FALSE;
				}
			} while(!dsl_cdr_ctrl2.boc_sr_flush);
			const char* achl_output2_cur = achl_output2;
			const char* achl_output2_end = dsl_cdr_ctrl2.achc_out_cur;
			int iml_compressed2_len = achl_output2_end - achl_output2_cur;
#endif
#if SM_USE_COMPRESSION3
			char* achl_input3 = (char*)malloc(iml_input_len);
			const dsd_gather_i_1* adsl_tmp3 = dsl_cdr_ctrl.adsc_gai1_in;
			int inl_ret2 = m_gather1_copy_const(&adsl_tmp3, achl_input3, achl_input3+iml_input_len);
			if(inl_ret2 != iml_input_len) {
					printf("Error: m_gather1_copy failed\n");
					return FALSE;
			}
			char* achl_output3 = (char*)malloc(iml_input_len<<1);
			char* achl_output3_end2 = achl_output3 + (iml_input_len<<1);
			char* achl_output3_end;
			{
				dsl_zlib_strm.next_in = (Bytef*)achl_input3;
			   dsl_zlib_strm.avail_in = iml_input_len;
				char* achl_cur = achl_output3;
				do {
					int have = achl_output3_end2 - achl_cur;
					dsl_zlib_strm.avail_out = achl_output3_end2 - achl_cur;
					dsl_zlib_strm.next_out = (Bytef*)achl_cur;
					CALL_ZLIB (deflate (&dsl_zlib_strm, Z_SYNC_FLUSH));
					have = have - dsl_zlib_strm.avail_out;
					achl_cur += have;
					if(dsl_zlib_strm.avail_in == 0)
						break;
					if(dsl_zlib_strm.avail_out != 0)
						continue;
					break;
				}
				while (true);
				achl_output3_end = achl_cur;
			}
			if(memcmp(achl_output3_end-sizeof(END_MARKER), END_MARKER, sizeof(END_MARKER)) != 0) {
				printf("Error: End-Marker missing\n");
				return FALSE;
			}
			const char* achl_output3_cur = achl_output3;
			achl_output3_end -= sizeof(END_MARKER);
			int iml_compressed3_len = achl_output3_end - achl_output3_cur;
			if(iml_compressed3_len != iml_compressed2_len) {
				printf("Warning: Compressed length mismatch HOB=%d Official=%d\n",
					iml_compressed2_len, iml_compressed3_len);
			}
			int iml_compressed_min = min(iml_compressed2_len, iml_compressed3_len);
			if(memcmp(achl_output3, achl_output2, iml_compressed_min) != 0) {
				int inl_p = m_compare_data(achl_output3, achl_output2, iml_compressed_min);
				printf("Warning: Compressed data mismatch at pos %d\n", inl_p);
			}
#endif
#if SM_USE_COMPRESSION4
			char* achl_input4 = (char*)malloc(iml_input_len);
			const dsd_gather_i_1* adsl_tmp4 = dsl_cdr_ctrl.adsc_gai1_in;
			int inl_ret4 = m_gather1_copy_const(&adsl_tmp4, achl_input4, achl_input4+iml_input_len);
			if(inl_ret4 != iml_input_len) {
					printf("Error: m_gather1_copy failed\n");
					return FALSE;
			}
			char* achl_output4 = (char*)malloc(iml_input_len<<1);
			char* achl_output4_end2 = achl_output4 + (iml_input_len<<1);
			char* achl_output4_cur = achl_output4;
			memset(achl_output4, 0, iml_input_len<<1);
			dsd_gather_i_1 dsl_tmp4b;
			dsl_tmp4b.achc_ginp_cur = achl_input4;
			dsl_tmp4b.achc_ginp_end = achl_input4 + iml_input_len;
			dsl_tmp4b.adsc_next = NULL;
			dsl_cdr_ctrl4.adsc_gai1_in = &dsl_tmp4b;
			dsl_cdr_ctrl4.boc_mp_flush = dsl_cdr_ctrl.boc_mp_flush;
			if(inl_message_count >= 2) {
				int a = 0;
			}
			
			do {
				char chrl_temp[1];
				dsl_cdr_ctrl4.achc_out_cur = chrl_temp;
				dsl_cdr_ctrl4.achc_out_end = chrl_temp + sizeof(chrl_temp);
				amp_enc(&dsl_cdr_ctrl4);
				if(dsl_cdr_ctrl4.imc_return != DEF_IRET_NORMAL) {
					printf("Error: Compression failed return=%d\n", dsl_cdr_ctrl4.imc_return);
					return FALSE;
				}
				int inl_compressed_len = dsl_cdr_ctrl4.achc_out_cur - chrl_temp;
				if(inl_compressed_len > (achl_output4_end2-achl_output4_cur)) {
					printf("Error: Compression buffer too small\n");
					return FALSE;
				}
				int iml_total_compressed = achl_output4_cur - achl_output4;
				if(iml_total_compressed+inl_compressed_len > iml_compressed2_len) {
					printf("Error: Compressed output is too long\n");
					return FALSE;
				}
				if(memcmp(&achl_output2[iml_total_compressed], chrl_temp, inl_compressed_len) != 0) {
					printf("Error: Compressed output is wrong\n");
					return FALSE;
				}
				memcpy(achl_output4_cur, chrl_temp, inl_compressed_len);
				achl_output4_cur += inl_compressed_len;
			} while(!dsl_cdr_ctrl4.boc_sr_flush);
			const char* achl_output4_end = achl_output4_cur;
			achl_output4_cur = achl_output4;
			int iml_compressed4_len = achl_output4_end - achl_output4_cur;
			if(iml_compressed4_len != iml_compressed2_len) {
				printf("Error: Decompress length mismatch\n");
				return FALSE;
			}
#endif
#if SM_USE_DECOMPRESSION4
			{
#if 1
				const char* achl_compr_in = achl_output2;
				const char* achl_compr_in2 = achl_output2_end;
#else
				const char* achl_compr_in = achl_output3;
				const char* achl_compr_in2 = achl_output3_end;
#endif
				int inl_compressed_len = achl_compr_in2 - achl_compr_in;
				char* achl_input4 =  (char*)malloc(inl_compressed_len+sizeof(END_MARKER));
				char* achl_input4_end = achl_input4 + inl_compressed_len + sizeof(END_MARKER);
				memcpy(achl_input4, achl_compr_in, inl_compressed_len);
				memcpy(achl_input4_end - sizeof(END_MARKER), END_MARKER, sizeof(END_MARKER));
				char* achl_output4 = (char*)malloc(iml_input_len+16);
				char* achl_output4_end2 = achl_output4 + (iml_input_len+16);
				char* achl_output4_end;
				if(inl_message_count >= 28339) {
					int a = 0;
				}
				{
					dsl_zlib_strm_dec.next_in = (Bytef*)achl_input4;
					dsl_zlib_strm_dec.avail_in = achl_input4_end - achl_input4;
					char* achl_cur = achl_output4;
					do {
						int have = achl_output4_end2 - achl_cur;
						dsl_zlib_strm_dec.avail_out = achl_output4_end2 - achl_cur;
						dsl_zlib_strm_dec.next_out = (Bytef*)achl_cur;
						CALL_ZLIB (inflate (&dsl_zlib_strm_dec, Z_SYNC_FLUSH));
						have = have - dsl_zlib_strm_dec.avail_out;
						achl_cur += have;
						if(dsl_zlib_strm_dec.avail_in == 0)
							break;
						if(dsl_zlib_strm_dec.avail_out != 0)
							continue;
						break;
					}
					while (true);
					achl_output4_end = achl_cur;
				}
				if((achl_output4_end-achl_output4) != iml_input_len) {
					printf("Error: Decompress length mismatch\n");
					return FALSE;
				}
#if SM_USE_COMPRESSION2
				const char* achl_input = achl_input2;
#else
				const char* achl_input = achl_input3;
#endif
				if(memcmp(achl_output4, achl_input, iml_input_len) != 0) {
					printf("Error: Decompress data mismatch\n");
					return FALSE;
				}
				free(achl_input4);
				free(achl_output4);
			}
#endif
#if SM_USE_DECOMPRESSION5
			char* achl_output5 = (char*)malloc(iml_input_len<<1);
			char* achl_output5_end2 = achl_output5 + (iml_input_len<<1);
			char* achl_output5_cur = achl_output5;
#endif
			printf("m_crd_enc[%d] in in-length=%d\n",
				inl_message_count, iml_input_len);
			do {
				dsl_cdr_ctrl.achc_out_cur = chrl_work1;  /* current end of output data */
				dsl_cdr_ctrl.achc_out_end = chrl_work1 + sizeof(chrl_work1);  /* end of buffer for output data */
				LBL_FAIL_RET(m_trace_cdrf_enc_read_compress_in2(&dsl_tracer, &dsl_cdr_ctrl));
				int inl_buffer_size = dsl_cdr_ctrl.achc_out_end - dsl_cdr_ctrl.achc_out_cur;
				LBL_FAIL_RET(m_trace_cdrf_enc_read_compress_out(&dsl_tracer, &dsl_cdr_ctrl));
				int inl_expected_size = dsl_cdr_ctrl.achc_out_end - dsl_cdr_ctrl.achc_out_cur;
				dsl_cdr_ctrl.achc_out_cur = chrl_work2;  /* current end of output data */
				dsl_cdr_ctrl.achc_out_end = chrl_work2 + inl_buffer_size;  /* end of buffer for output data */
				printf("m_crd_enc[%d] in2 outbuf=%d in-length=%d\n",
					inl_message_count, inl_buffer_size, m_gather_i_1_count_data_len(dsl_cdr_ctrl.adsc_gai1_in));
				if(inl_message_count >= 1108) {
					int a = 0;
				}
				amp_enc(&dsl_cdr_ctrl);
				if(dsl_cdr_ctrl.imc_return != DEF_IRET_NORMAL) {
					printf("Error: Compression failed return=%d\n", dsl_cdr_ctrl.imc_return);
					return FALSE;
				}
				int inl_compressed_size = dsl_cdr_ctrl.achc_out_cur - chrl_work2;
				printf("m_crd_enc[%d] out outlen=%d in-rest=%d\n",
					inl_message_count, inl_compressed_size, m_gather_i_1_count_data_len(dsl_cdr_ctrl.adsc_gai1_in));
				if(inl_compressed_size != inl_expected_size) {
					printf("Error: Compression mismatch inl_compressed_size=%d inl_expected_size=%d\n", inl_compressed_size, inl_expected_size);
#if SM_USE_COMPARE_TRACED_COMPRESSION
					return FALSE;
#endif
				}
				if(memcmp(chrl_work1, chrl_work2, inl_compressed_size) != 0) {
					printf("Error: Compression data mismatch\n");
#if SM_USE_COMPARE_TRACED_COMPRESSION
					return FALSE;
#endif
				}
#if SM_USE_COMPRESSION2
				if(inl_compressed_size > (achl_output2_end-achl_output2_cur)) {
					printf("Error: Compression2 data mismatch\n");
#if SM_USE_COMPARE_COMPRESSION2
					return FALSE;
#endif
				}
				int inl_pos2 = memcmp(chrl_work2, achl_output2_cur, inl_compressed_size);
				if(inl_pos2 != 0) {
					int inl_p = m_compare_data(chrl_work2, achl_output2_cur, inl_compressed_size);
					printf("Error: Compression2 data mismatch inl_p=%d\n", inl_p);
#if SM_USE_COMPARE_COMPRESSION2
					return FALSE;
#endif
				}
				achl_output2_cur += inl_compressed_size;
#endif
#if SM_USE_COMPRESSION3
				if(inl_compressed_size > (achl_output3_end-achl_output3_cur)) {
					printf("Error: Compression3 data mismatch\n");
#if SM_USE_COMPARE_COMPRESSION3
					return FALSE;
#endif
				}
				int inl_pos3 = memcmp(chrl_work2, achl_output3_cur, inl_compressed_size);
				if(inl_pos3 != 0) {
					int inl_p = m_compare_data(chrl_work2, achl_output3_cur, inl_compressed_size);
					printf("Error: Compression3 data mismatch inl_p=%d\n", inl_p);
#if SM_USE_COMPARE_COMPRESSION3
					return FALSE;
#endif
				}
				achl_output3_cur += inl_compressed_size;
#endif
#if SM_USE_DECOMPRESSION5
				memcpy(achl_output5_cur, chrl_work2, inl_compressed_size);
				achl_output5_cur += inl_compressed_size;
#endif
				if(dsl_cdr_ctrl.boc_sr_flush)
					break;
			} while(true);
			LBL_FAIL_RET(m_trace_cdrf_enc_read_compress_done(&dsl_tracer, &dsl_cdr_ctrl));
#if SM_USE_COMPRESSION2
			if(achl_output2_cur < achl_output2_end) {
				printf("Error: Compression2 data mismatch missing=%d\n", (achl_output2_end-achl_output2_cur));
#if SM_USE_COMPARE_COMPRESSION2
				return FALSE;
#endif
			}
#endif
#if SM_USE_COMPRESSION3
			if(achl_output3_cur < achl_output3_end) {
				printf("Error: Compression3 data mismatch missing=%d\n", (achl_output3_end-achl_output3_cur));
#if SM_USE_COMPARE_COMPRESSION3
				return FALSE;
#endif
			}
#endif
#if SM_USE_DECOMPRESSION5
			{
#if 1
				const char* achl_compr_in = achl_output5;
				const char* achl_compr_in2 = achl_output5_cur;
#else
				const char* achl_compr_in = achl_output3;
				const char* achl_compr_in2 = achl_output3_end;
#endif
				int inl_compressed_len = achl_compr_in2 - achl_compr_in;
				char* achl_input4 =  (char*)malloc(inl_compressed_len+sizeof(END_MARKER));
				char* achl_input4_end = achl_input4 + inl_compressed_len + sizeof(END_MARKER);
				memcpy(achl_input4, achl_compr_in, inl_compressed_len);
				memcpy(achl_input4_end - sizeof(END_MARKER), END_MARKER, sizeof(END_MARKER));
				char* achl_output4 = (char*)malloc(iml_input_len+16);
				char* achl_output4_end2 = achl_output4 + (iml_input_len+16);
				char* achl_output4_end;
				if(inl_message_count >= 28339) {
					int a = 0;
				}
				{
					dsl_zlib_strm_dec5.next_in = (Bytef*)achl_input4;
					dsl_zlib_strm_dec5.avail_in = achl_input4_end - achl_input4;
					char* achl_cur = achl_output4;
					do {
						int have = achl_output4_end2 - achl_cur;
						dsl_zlib_strm_dec5.avail_out = achl_output4_end2 - achl_cur;
						dsl_zlib_strm_dec5.next_out = (Bytef*)achl_cur;
						CALL_ZLIB (inflate (&dsl_zlib_strm_dec5, Z_SYNC_FLUSH));
						have = have - dsl_zlib_strm_dec5.avail_out;
						achl_cur += have;
						if(dsl_zlib_strm_dec5.avail_in == 0)
							break;
						if(dsl_zlib_strm_dec5.avail_out != 0)
							continue;
						break;
					}
					while (true);
					achl_output4_end = achl_cur;
				}
				if((achl_output4_end-achl_output4) != iml_input_len) {
					printf("Error: Decompress length mismatch\n");
					return FALSE;
				}
#if SM_USE_COMPRESSION2
				const char* achl_input = achl_input2;
#else
				const char* achl_input = achl_input3;
#endif
				if(memcmp(achl_output4, achl_input, iml_input_len) != 0) {
					printf("Error: Decompress data mismatch\n");
					return FALSE;
				}
				free(achl_input4);
				free(achl_output4);
			}
			free(achl_output5);
#endif // SM_USE_DECOMPRESSION5
#if SM_USE_COMPRESSION2
			free(achl_output2);
			free(achl_input2);
#endif
#if SM_USE_COMPRESSION3
			free(achl_output3);
			free(achl_input3);
#endif
			inl_message_count++;
			break;
		}
		case HL_GATHER_TRACER_CMD_END:
			return TRUE;
		default:
			printf("Error: Invalid main command %d\n", inl_cmd);
			return FALSE;
		}
	} while(true);
}
#endif // SM_USE_GATHE_TRACER_REPLAY

#endif // _HOB_GATHER_TRACER_HPP_

