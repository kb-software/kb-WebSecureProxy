#ifndef __HOB_RDPCLIENT2_H__
#define __HOB_RDPCLIENT2_H__

#ifndef HL_USE_AUX_SSL_FUNCTIONS
#define HL_USE_AUX_SSL_FUNCTIONS	1
#endif

#if !HOB_TK_NO_INCLUDE
#ifdef HL_UNIX
#include <hob-unix01.h>
#include <stdarg.h>
#include <sys/types.h>
#else
#include <Windows.h>
#endif
#include <stdint.h>
#include <hob-xslunic1.h>
#include <hob-encry-1.h>
#include <hob-cd-record-1.h>
/*#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

#include <iostream>
#include <fstream>
#include <string>

#include "hob-xslunic1.h"
#include "hob-xsclib01.h"
#include "hob-tab-ascii-ansi-1.h"
#include "hob-tab-mime-base64.h"
#include "hob-ssl-01.h"
#include "hob-encry-1.h"
#include "hob-cd-record-1.h"
#include "hob-rdpclient1.h"*/
#ifdef HL_RDP_WEBTERM
#include <hob-webterm-rdp-01.h>
#else
#include <hob-rdpclient1.h>
#endif
#include <hob-ssl-01.h>
#include <hob-cert-ext.h>
#include <hob-ntlm-01.h>
#include <hob-tk-gather-tools-01.h>
#endif /*!HOB_TK_NO_INCLUDE*/

#ifndef DEF_IRET_ERR_EXTENDED
#define DEF_IRET_ERR_EXTENDED      7
#endif

static const int IM_GSSAPI_FUNC_START = 0;
static const int IM_GSSAPI_FUNC_INITIALIZE_CONTEXT = 1;
static const int IM_GSSAPI_FUNC_WRAP = 2;
static const int IM_GSSAPI_FUNC_UNWRAP = 3;
static const int IM_GSSAPI_FUNC_CLOSE = 4;

struct dsd_gssapi_01 {
	void (*amc_gssapi)(struct dsd_gssapi_01_call* adsp_call);
	BOOL boc_initialized;
};

struct dsd_gssapi_01_call {
	int inc_func;                     /* called function         */
	int inc_return;                   /* return code             */
	struct dsd_gssapi_01* adsc_context;
	struct dsd_workarea_allocator* adsc_wa_alloc1;
	struct dsd_gather_i_1* adsc_gather_in;
	struct dsd_gather_i_1_fifo dsc_gather_out;
};

struct dsd_gssapi_ntlm_params_01 {
	struct dsd_unicode_string dsc_ucs_domain;  /* domain name           */
	struct dsd_unicode_string dsc_ucs_userid;  /* userid / user name    */
	struct dsd_unicode_string dsc_ucs_password;  /* password            */
    struct dsd_unicode_string dsc_ucs_workstation;  /* workstation      */
};

struct dsd_gssapi_ntlm_01 {
   struct dsd_gssapi_01 dsc_base;
   enum ied_ntlm_function iec_state;
   struct dsd_gssapi_ntlm_params_01* adsc_params;
   char chrc_client_sign_key[LEN_NTLM_SIGN_KEY];
   char chrc_client_handle[RC4_STATE_SIZE];
   char chrc_server_sign_key[LEN_NTLM_SIGN_KEY];
   char chrc_server_handle[RC4_STATE_SIZE];
   uint32_t umc_client_seqnum;	/* Must be 32-bit number */
   uint32_t umc_server_seqnum;	/* Must be 32-bit number */
};

struct dsd_gssapi_ntlm_01_call {
	struct dsd_gssapi_01_call dsc_base;
	//struct dsd_ntlm_req dsc_ntlm_req;
};

enum ied_credssp_state {
	iec_credssp_state_start,
	iec_credssp_state_mech
};

struct dsd_gssapi_credssp_params_01 {
	struct dsd_gssapi_01* adsc_mech;
	struct dsd_unicode_string dsc_ucs_domain;  /* domain name           */
	struct dsd_unicode_string dsc_ucs_userid;  /* userid / user name    */
	struct dsd_unicode_string dsc_ucs_password;  /* password            */
	const char* achc_subject_public_key;
	int inc_subject_public_key_len;
};

struct dsd_credssp_01 {
	struct dsd_gssapi_01 dsc_base;
	struct dsd_gssapi_credssp_params_01* adsc_params;
	struct dsd_gssapi_01* adsc_mech;
	enum ied_credssp_state iec_state;
	unsigned int unc_error_code;
	int inc_last_seqfield;
	int inc_server_version;
};

struct dsd_call_credssp_01 {
	struct dsd_gssapi_01_call dsc_base;
};

void m_gssapi_ntlm_01(struct dsd_gssapi_01_call* adsp_call);
void m_gssapi_credssp_01(struct dsd_gssapi_01_call* adsp_call);

enum ied_state_rdp {
    iec_state_rdp_negotiate,
    iec_state_rdp_negotiate2,
    iec_state_rdp_pure,
    iec_state_rdp_tls_init,
    iec_state_rdp_tls_credssp,
    iec_state_rdp_tls_rdp,
};

typedef struct X509CERT_t X509CERT;

enum ied_rdpclient_extended_result {
	iec_rdpclient_extended_invalid,
	iec_rdpclient_extended_rdp_negotiation_failed,
	iec_rdpclient_extended_ssl_failed,
	iec_rdpclient_extended_credssp_no_credentials,
	iec_rdpclient_extended_credssp_failed,
	iec_rdpclient_extended_rdpacc_failed
};

#if HL_USE_AUX_SSL_FUNCTIONS
struct dsd_aux_ssl_functions {
	int (*m_cl_registerconfig)( char * achp_configdatabuf, int inp_configdatalen,
								char * achp_certdatabuf, int inp_certdatalen,
								char * achp_pdwbuf, int inp_pdwlen,
								BOOL boc_pwdfileflag,
								struct dsd_hl_ocsp_d_1 * adsp_ocspd,
								BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
								void * vpp_userfld,
								void ** avpp_config_id,
								BOOL bop_use_aux_seeding );
	int (*m_release_config)( BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                void * vpp_userfld,
                                void * vpp_config_id );
	void (*m_hlcl01)(struct dsd_hl_ssl_c_1 * pXIFCLStructu);
	int (*FromASN1_DNCommonNameToString)(HMEM_CTX_DEF
		X501_DN* pNameDesc, char** pDstNameBuf);
	int (*FromASN1CertToCertStruc)(HMEM_CTX_DEF
                                   char SrcBuf[],
                                   int SrcOffset, 
                                   int SrcLen,
                                   int CertType,
                                   int SortFlags,
                                   char* Pwd,
                                   int PwdLen,
                                   X509CERT * pCertStruc[]);
	void (*FreeCertStruc)(HMEM_CTX_DEF
                          X509CERT * CertStruc);
};
#endif

struct dsd_call_rdpclient_2 {
   int        inc_func;                     /* called function         */
   int        inc_return;                   /* return code             */
   ied_rdpclient_extended_result iec_extended_result;
   char *     achc_work_area;               /* addr work-area          */
   int        inc_len_work_area;            /* length work-area        */

   struct dsd_aux_helper dsc_aux;
#if HL_USE_AUX_SSL_FUNCTIONS
   struct dsd_aux_ssl_functions* adsc_aux_ssl_functions;
#endif
   BOOL       boc_callagain;                /* call again this direction */

   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
   struct dsd_gather_i_1 *adsc_gai1_out_to_server;  /* output data to server */
   struct dsd_cc_co1 *adsc_cc_co1_ch;       /* chain of client commands, input */
   struct dsd_se_co1 *adsc_se_co1_ch;       /* chain of commands from server, output */
#ifdef HL_RDP_WEBTERM
   struct dsd_wt_record_1 *adsc_wtr1_out;
#endif

   void* vpc_config_id;
   enum ied_state_rdp iec_rdp_state;
#ifdef HL_RDP_WEBTERM
   struct dsd_call_wt_rdp_client_1 dsc_rdpacc;
#else
   struct dsd_call_rdpclient_1 dsc_rdpacc;
#endif
   struct dsd_rdp_neg_resp dsc_rdp_neg_resp;
   BOOL boc_ssl_initialized;
   struct dsd_hl_ssl_c_1 dsc_ssl_client;
#ifdef XH_INTERFACE
   ds__hmem dsc_ssl_hmem_context;
#endif
   X509CERT* adsc_end_cert;
   //struct dsd_gssapi_ntlm_01 dsc_ntlm;
   struct dsd_credssp_01 dsc_credssp;

   struct dsd_workarea_chain dsc_wa_chain1;
   struct dsd_aux_helper dsc_wa_aux1;
   struct dsd_workarea_allocator dsc_wa_alloc1;
   struct dsd_gather_i_1_fifo dsc_to_rdpacc;
   //struct dsd_workarea_1 * adsc_workarea_1;
   struct dsd_workarea_chain dsc_wa_chain2;
   struct dsd_aux_helper dsc_wa_aux2;
   struct dsd_fifo dsc_to_ssl_cl;

   struct dsd_cc_co1 dsc_continue_after_ext;
   int inc_call_count;

   //struct dsd_rdp_co_client *adsc_rdp_co;   /* RDP communication       */
};

#ifdef HL_RDP_WEBTERM
void m_wt_rdp_client_2(struct dsd_call_rdpclient_2* adsp_client);
#else
void m_rdpclient_2(struct dsd_call_rdpclient_2* adsp_client);
#endif

#endif //!__HOB_RDPCLIENT2_H__
