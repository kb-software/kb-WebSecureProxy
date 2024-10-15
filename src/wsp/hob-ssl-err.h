#ifndef __HOB_SSL_ERROR_CODES__
#define __HOB_SSL_ERROR_CODES__
#ifdef _WIN32
#pragma once
#endif

#ifndef __HOB_SSL_ERR__
#define __HOB_SSL_ERR__

//-------------------------------------------------------
// Error codes from hsslerr.h
//-------------------------------------------------------

#define HSSL_OP_OK			0
#define HSSL_NULL_PTR			-1	// normally internal Error !!
#define	HSSL_PARAM_ERR			-2	// basic parameter error
#define	HSSL_ALLOC_ERR			-3	// basic allocation error

//-------------------------------------------------------
// Local used return values
//-------------------------------------------------------
#define HSSL_UNIQUE_ID_RETRY_EXCEED	-5

//----------------------------------------------------------------
// Specific Returncodes, range from -10 ... -599
//----------------------------------------------------------------

//-------------------------------------------------------------------
// Returncodes from Premaster Secret generation/encryption/decryption
//-------------------------------------------------------------------
#define HSSL_RSA_PREMASTER_ALLOC_ERR		-10
#define HSSL_RSA_PREMASTER_PUBL_ENC_ERR		-11
#define HSSL_RSA_PREMASTER_DEC_ALLOC_ER		-12
#define HSSL_RSA_PREMASTER_PRIV_DEC_ERR		-13
#define	HSSL_RSA_PREMASTER_RNG_ERR		-14

#define HSSL_DH_PREMASTER_ALLOC_ERR		-20
#define HSSL_DH_PREMASTER_KEYGEN_ERR		-21
#define HSSL_DH_PREMASTER_SECRET_ERR		-22
#define HSSL_DH_PREMASTER_LNUM_ERR		-23

#define	HSSL_RNG_FETCH_ERROR			-25

#define HSSL_SRP_PREMASTER_ALLOC_ERR -27
#define HSSL_SRP_PREMASTER_LNUM_ERR -28
#define HSSL_SRP_PREMASTER_PARAM_ERR -29

//---------------------------------------------------------------
// Returncodes from Compression / Decompression and Init routines
//---------------------------------------------------------------
#define HSSL_INIT_V42_CMPR_ALLOC_ERR		-30
#define HSSL_INIT_COMPR_INVALID_METHOD		-31
#define HSSL_UNSUPPORTED_COMPR_METHOD		-32
#define HSSL_UNDEFINED_COMPR_METHOD		-33

#define HSSL_COMPR_BUF_TOO_SHORT		-40
#define HSSL_COMPR_NULL_PTR			-41
#define HSSL_COMPR_FAILED			-42
#define HSSL_COMPR_INVALID_METHOD		-43

#define HSSL_DECOMPR_INVALID_DATA		-50
#define HSSL_DECOMPR_NULL_PTR			-51
#define HSSL_DECOMPR_FAILED			-52
#define HSSL_DECOMPR_INVALID_METHOD		-53

//-----------------------------------------------------
// Returncodes from MAC Append/Verify and Init routines
//-----------------------------------------------------
#define HSSL_INVALID_MAC_ALGOR			-60

#define HSSL_MAC_BUF_TOO_SHORT			-65
#define HSSL_MAC_TOO_FEW_DATA			-66
#define HSSL_MAC_VERIFY_ERR			-67

//---------------------------------------------------------
// Returncodes from Encryption/Decryption and Init routines
//---------------------------------------------------------
#define HSSL_INIT_RC4_CIPH_ALLOC_ERR		-70
#define HSSL_INIT_RC2_CIPH_ALLOC_ERR		-71
#define HSSL_INIT_DES_CIPH_ALLOC_ERR		-72
#define HSSL_INIT_3DES_CIPH_ALLOC_ERR		-73
#define HSSL_INIT_CIPH_INV_CIPH_ALGOR		-74
#define HSSL_INIT_AES_CIPH_ALLOC_ERR		-75

#define HSSL_ENCRYPT_INVALID_LEN		-80
#define HSSL_ENCRYPT_BUF_TOO_SHORT		-81
#define HSSL_ENCRYPT_INV_CIPH_ALGOR		-82

#define HSSL_DECRYPT_LEN_TOO_SHORT		-85
#define HSSL_DECRYPT_INVALID_LEN		-86
#define HSSL_DECRYPT_INVALID_PADDING		-87
#define HSSL_DECRYPT_INV_CIPH_ALGOR		-88

//------------------------------------------------------------
// Returncodes from Handshake processing State machine
//------------------------------------------------------------

#define HSSL_HSHAKE_GET_TX_TIMEOUT_ERR		-90
#define HSSL_HSHAKE_GET_RX_TIMEOUT_ERR		-91
#define HSSL_HSHAKE_SET_TX_TIMEOUT_ERR		-92
#define HSSL_HSHAKE_SET_RX_TIMEOUT_ERR		-93
#define HSSL_HSHAKE_TCP_TX_TIMEOUT		-94
#define HSSL_HSHAKE_TCP_RX_TIMEOUT		-95
#define	HSSL_HSHAKE_REMOTE_SHUTDOWN		-96
#define HSSL_HSHAKE_LCL_FATAL_ALERT		-97
#define	HSSL_HSHAKE_RENEGOTIATE_TIMEOUT		-98

//----------------------------------------------------------
// TCP transmit processing return codes
//----------------------------------------------------------
#define	HSSL_TX_TCP_TIMEOUT			-100
#define	HSSL_TX_TCP_ERROR			-101

#define HSSL_TX_QEL_ALLOC_ERR			-105
#define	HSSL_TX_LOCAL_SHUTDOWN			-106
#define HSSL_TX_ALLOC_ERR			-107
#define HSSL_TX_BUF_ALLOC_ERR			-107	// same !

//----------------------------------------------------------
// TCP Receive/Data assembly/Message processing return codes
//----------------------------------------------------------
#define HSSL_RX_TCP_ERROR			-110
#define HSSL_RX_UNSUPPORTED_VERSION		-111
#define HSSL_RX_BUF_ALLOC_ERR			-112
#define	HSSL_RX_ILLEGAL_PARAM			-113

#define HSSL_RX_HSHAKE_MSG_INVALID_SITE		-115
#define HSSL_RX_HSHAKE_MSG_INVAL_ORDER		-116
#define HSSL_RX_HSHAKE_UNKNOWN_MSG		-117
#define HSSL_RX_HSHAKE_UNEXPECTED_MSG   -118

//---------------------------------------------------------
// Received Change Cipher Spec Data processing return codes
//---------------------------------------------------------
#define HSSL_CHG_CIPHSPEC_MSG_UNEXPECTD		-120
#define HSSL_PEND_TX_STATES_NOT_INIT		-121
#define HSSL_PEND_RX_STATES_NOT_INIT		-122

//----------------------------------------------------
// Some more Fatal Alerts (not yet seen)
//----------------------------------------------------

#define	HSSL_ALERT_MSG_ACCESS_DENIED		-125
#define	HSSL_ALERT_MSG_DECODE_ERROR		-126
#define	HSSL_ALERT_MSG_DECRYPT_ERROR		-127
#define	HSSL_ALERT_MSG_ILLEGAL_PARAM		-128

//----------------------------------------------------
// Received Application Data processing return codes
//----------------------------------------------------
#define HSSL_RX_APPLDATA_NULL_MSG         -129
#define HSSL_RX_APPLDATA_QEL_ALLOC_ERR		-130

//----------------------------------------------------
// Alert Message processing return codes
//----------------------------------------------------

#define	HSSL_ALERT_MSG_UNEXPECTED_MSG		-131
#define	HSSL_ALERT_MSG_BAD_RECORD_MAC		-132
#define	HSSL_ALERT_MSG_DECRYPT_FAILED		-133
#define	HSSL_ALERT_MSG_RECORD_OVERFLOW		-134
#define	HSSL_ALERT_MSG_DECOMPR_FAILURE		-135
#define	HSSL_ALERT_MSG_HANDSHAKE_FAIL		-136

#define	HSSL_ALERT_MSG_EXPORT_RESTRICT		-137
#define	HSSL_ALERT_MSG_PROTOCOL_VERSION		-138

#define	HSSL_ALERT_MSG_UNKNOWN_CA		-139

#define HSSL_ALERT_MSG_NO_CLIENT_CERT		-140
#define HSSL_ALERT_MSG_NO_RENEGOTIATE		-141
#define HSSL_ALERT_MSG_FATAL_ALERT		-142

#define	HSSL_ALERT_MSG_BAD_CERT			-143
#define	HSSL_ALERT_MSG_UNSUP_CERT		-144
#define	HSSL_ALERT_MSG_REVOKED_CERT		-145
#define	HSSL_ALERT_MSG_EXPIRED_CERT		-146
#define	HSSL_ALERT_MSG_UNKNOWN_CERT		-147

#define	HSSL_ALERT_MSG_INSUFF_SECURITY		-148
#define	HSSL_ALERT_MSG_INTERNAL_ERROR		-149

// HSSL_ALERT_MSG_FATAL_CLOSE_NOTIFY down below as additional error code

//--------------------------------------------------
// Client Hello Message processing return codes
//--------------------------------------------------
#define HSSL_CLNT_HELLO_INVALID_MSGLEN		-150
#define	HSSL_CLNT_HELLO_UNSUPP_VERSION		-151
#define HSSL_CLNT_HELLO_INV_UTC_TIME		-152
#define HSSL_CLNT_HELLO_INV_SESS_ID_LEN		-153
#define HSSL_CLNT_HELLO_INV_SESSION_ID		-154
#define HSSL_CLNT_HELLO_SESSID_GEN_FAIL		-155
#define HSSL_CLNT_HELLO_NO_RENEGOTIATE		-156
#define HSSL_CLNT_HELLO_DIFFERENT_VERS		-157
#define HSSL_CLNT_HELLO_DIFF_CIPHSUITE		-158
#define HSSL_CLNT_HELLO_UNSUP_CIPHSUITE		-159
#define HSSL_CLNT_HELLO_DIFF_CMPRMETHOD		-160
#define HSSL_CLNT_HELLO_UNSUPP_CMPRMETH		-161
#define HSSL_CLNT_HELLO_UNDEF_CMPR_METH		-162
#define HSSL_CLNT_HELLO_DIFF_SESSION_ID		-163
#define HSSL_CLNT_HELLO_INV_SIG_LIST         -164
#define HSSL_CLNT_HELLO_SRP_UNK_ID           -165
#define HSSL_CLNT_HELLO_INAP_FALLBACK       -166

//--------------------------------------------------
// Server Hello Request Message processing return codes
//--------------------------------------------------
#define HSSL_SRVR_HELREQ_INVALID_MSGLEN		-170
#define HSSL_SRVR_HELREQ_NO_RENEGOTIATE		-171
#define HSSL_SRVR_HELREQ_UNEXPECTED_MSG		-172

#define HSSL_ALERT_MSG_FATAL_CLOSE_NOTIFY   -175

//--------------------------------------------------
// Server Hello Message processing return codes
//--------------------------------------------------
#define HSSL_SRVR_HELLO_INVALID_MSGLEN		-180
#define HSSL_SRVR_HELLO_UNSUPP_VERSION		-181
#define HSSL_SRVR_HELLO_INV_UTC_TIME		-182
#define HSSL_SRVR_HELLO_INV_RANDOM		-183
#define HSSL_SRVR_HELLO_INV_SESSID_LEN		-184
#define HSSL_SRVR_HELLO_INV_SESSION_ID		-185
#define HSSL_SRVR_HELLO_DIFF_CIPHSUITE		-186
#define HSSL_SRVR_HELLO_UNSUP_CIPHSUITE		-187
#define HSSL_SRVR_HELLO_DIFF_CMPRMETHOD		-188
#define HSSL_SRVR_HELLO_UNDEF_CMPRMETH		-189
#define HSSL_SRVR_HELLO_DIFFERENT_VERS		-190
#define HSSL_SRVR_HELLO_DIFF_SESSION_ID		-191
#define	HSSL_SRVR_HELLO_UNSEC_RENEGOT		-192

//--------------------------------------------------
// Server Hello Done processing return codes
//--------------------------------------------------
#define HSSL_SRVR_HLDONE_INVALID_MSGLEN		-200
#define HSSL_SRVR_HLDONE_EXPT_RESTRICT		-201

//--------------------------------------------------
// Certificate Message processing return codes
//--------------------------------------------------

#define	HSSL_CERTMSG_NO_OCSP_RESP		-202
#define	HSSL_CERTMSG_UNSUCC_OCSP_RESP		-203
#define	HSSL_CERTMSG_UNTRUST_OCSP_SIGN		-204
#define	HSSL_CERTMSG_UNTRUST_OCSP_NONCE		-205
#define	HSSL_CERTMSG_UNREL_OCSP_PROD_AT		-206
#define	HSSL_CERTMSG_UNREL_OCSP_MATCH		-207
#define	HSSL_CERTMSG_UNREL_OCSP_SRESP		-208
#define	HSSL_CERTMSG_UNKNOWN_OCSP_SRESP		-209

#define HSSL_CERTMSG_INVALID_MSGLEN		-210
#define HSSL_CERTMSG_NO_CLIENT_CERT		-211
#define HSSL_CERTMSG_NO_SERVER_CERT		-212
#define HSSL_CERTMSG_BAD_CERTLIST		-213
#define HSSL_CERTMSG_INV_KEYEXCHG_MODE		-214
#define HSSL_CERTMSG_ALG_EXCHG_MISMATCH		-215
#define HSSL_CERTMSG_CERT_PUBPARS_ERROR		-216
#define HSSL_CERTMSG_DHPAR_MISMATCH		-217
#define HSSL_CERTMSG_CERT_CHAIN_VFY_ERR		-218
#define HSSL_CERTMSG_CERT_CHAIN_REJECT		-219
#define HSSL_CERTMSG_CNAME_EXTRACT_ERR		-220
#define	HSSL_CERTMSG_SRVR_CNAME_UNKNOWN		-221
#define	HSSL_CERTMSG_CLNT_CNAME_UNKNOWN		-222
#define	HSSL_CERTMSG_CLNT_CNAME_EXCLUDE		-223
#define HSSL_CERTMSG_NO_TRUST_ROOT		-224
#define HSSL_CERTMSG_CERT_REVOKED		-225
#define HSSL_CERTMSG_CERT_EXPIRED		-226
#define HSSL_CERTMSG_BAD_CERTIFICATE		-227
#define HSSL_CERTMSG_CHAIN_OCSP_VFY_ERR		-228
#define HSSL_CERTMSG_REVOKSTATE_UNK_ERR		-229

//--------------------------------------------------
// Certificate Request Message processing return codes
//--------------------------------------------------
#define HSSL_CERTREQ_INVALID_MSGLEN		-230
#define HSSL_CERTREQ_SRVR_NOT_CERTIFIED		-231
#define HSSL_CERTREQ_INV_TYPES_LEN		-232
#define HSSL_CERTREQ_UNSUPP_CERT_TYPE		-233
#define HSSL_CERTREQ_INV_RDNLIST_LEN		-234
#define HSSL_CERTREQ_DH_PUBPARAMS_ERROR		-235
#define HSSL_CERTREQ_GET_ENDCERT_ERR		-236
#define HSSL_CERTREQ_GET_ENDCERT_NOCERT		-237
#define HSSL_CERTREQ_UNEXPECTED -238

//--------------------------------------------------
// Server Key Exchange Message processing return codes
//--------------------------------------------------
#define HSSL_SRVR_KEYEXC_INVALID_MSGLEN		-240
#define HSSL_SRVR_KEYEXC_RSA_ALLOC_ERR		-241
#define HSSL_SRVR_KEYEXC_RSAPAR_LOADERR		-242
#define HSSL_SRVR_KEYEXC_DH_ALLOC_ERR		-243
#define HSSL_SRVR_KEYEXC_DHPAR_LOAD_ERR		-244
#define HSSL_SRVR_KEYEXC_INV_KEYEX_MODE		-245
#define HSSL_SRVR_KEYEXC_SIGBUF_ALLOCER		-246
#define HSSL_SRVR_KEYEXC_SIG_RSADEC_ERR		-247
#define HSSL_SRVR_KEYEXC_SIGNAT_INVALID		-248
#define HSSL_SRVR_KEYEXC_INVALID_MSG         -249

#define HSSL_SRVR_KEYEXC_INVALID_EC_PARAMS -256
#define HSSL_SRVR_KEYEXC_EC_INTERNAL_ERR   -257

//---------------------------------------------------
// Certificate Verify Message processing return codes
//---------------------------------------------------
#define HSSL_CERTVFY_INVALID_MSGLEN		-250
#define HSSL_CERTVFY_SIGBUF_ALLOC_ERR		-251
#define HSSL_CERTVFY_SIGNAT_RSADEC_ERR		-252
#define HSSL_CERTVFY_SIGNATURE_INVALID		-253
#define HSSL_CERTVFY_INV_SIGNAT_ALGOR		-254

//----------------------------------------------------
// Client Key Exchange Message processing return codes
//----------------------------------------------------
#define HSSL_CLNT_KEYEXC_INVALID_MSGLEN		-260
#define HSSL_CLNT_KEYEXC_PREM_ALLOC_ERR		-261
#define HSSL_CLNT_KEYEXC_INV_DH_YC_DATA		-262
#define HSSL_CLNT_KEYEXC_DH_ALLOC_ERR		-263
#define HSSL_CLNT_KEYEXC_DHPAR_LOAD_ERR		-264
#define HSSL_CLNT_KEYEXC_DH_PREMGEN_ERR		-265
#define HSSL_CLNT_KEYEXC_INV_KEYEX_MODE		-266
#define HSSL_CLNT_KEYEXC_RNG_FETCH_ERR		-267
#define HSSL_CLNT_KEYEXC_SRP_ALLOC_ERR    -268
#define HSSL_CLNT_KEYEXC_SRP_PREMGEN_ERR  -269

#define HSSL_CLNT_KEYEC_ECDHE_ERR           -272

//----------------------------------------------------
// Finished Message processing return codes
//----------------------------------------------------
#define HSSL_FINISHED_INVALID_MSGLEN		-270
#define HSSL_FINISHED_VERIFY_ERR		-271

//--------------------------------------------------
// Certificate Message generate return codes
//--------------------------------------------------
#define HSSL_GENCERT_INV_KEY_EXCHG_MODE		-280
#define HSSL_GENCERT_BUILDCERTCHAIN_ERR		-281
#define HSSL_GENCERT_TO_PRIVPARS_ERROR		-282
#define HSSL_GENCERT_LISTGEN_FAILED		-283
#define HSSL_GENCERT_NO_CLIENT_CERT		-284
#define HSSL_GENCERT_MSGBUF_ALLOC_ERR		-285
#define HSSL_GENCERT_BUILDLCLCHAIN_ERR		-286

//--------------------------------------------------
// Certificate Request Message generate return codes
//--------------------------------------------------
#define HSSL_GENCREQ_INV_KEY_EXCHG_MODE		-290
#define HSSL_GENCREQ_RDNLIST_GEN_FAILED		-291
#define HSSL_GENCREQ_INV_SIG_LIST            -292

//--------------------------------------------------
// Server Key Exchange Message generate return codes
//--------------------------------------------------
#define HSSL_GEN_SRKYEX_RSAKEYGEN_ERR		-300
#define HSSL_GEN_SRKYEX_RSAPAR_STORE_ER		-301
#define HSSL_GEN_SRKYEX_MSGBUF_ALLOC_ER		-302
#define HSSL_GEN_SRKYEX_DH_PARAM_GEN_ER		-303
#define HSSL_GEN_SRKYEX_DH_KEY_GEN_ERR		-304
#define HSSL_GEN_SRKYEX_DHPAR_STORE_ERR		-305
#define HSSL_GEN_SRKYEX_INV_KEYEX_MODE		-306
#define HSSL_GEN_SRKYEX_SIG_RSAENC_ERR		-307
#define HSSL_GEN_SRKYEX_DSA_SIG_GEN_ERR		-308
#define HSSL_GEN_SRKYEX_SRP_ERR -310

#define HSSL_INIT_ECC_PARAM_ERR             -309
#define HSSL_INIT_ECC_PARAM_GEN_ERR         -311
#define HSSL_INIT_ECC_KEY_GEN_ERR           -312

//--------------------------------------------------
// Certificate Verify Message generate return codes
//--------------------------------------------------
#define HSSL_GEN_CERTVFY_INV_PUBLIC_ALG		-320
#define HSSL_GEN_CERTVFY_TO_PRIVPAR_ERR		-321
#define HSSL_GEN_CERTVFY_MSGBUF_ALLOCER		-322
#define HSSL_GEN_CERTVFY_SIG_RSAENC_ERR		-323
#define HSSL_GEN_CERTVFY_DSASIG_GEN_ERR		-324
#define HSSL_GEN_CERTVFY_INV_SIGNAT_ALG		-325

//--------------------------------------------------
// Client Key Exchange Message generate return codes
//--------------------------------------------------
#define HSSL_GEN_CLKYEX_RSA_PREMGEN_ERR		-330
#define HSSL_GEN_CLKYEX_MSGBUF_ALLOC_ER		-331
#define HSSL_GEN_CLKYEX_PREM_RSAENC_ERR		-332
#define HSSL_GEN_CLKYEX_DH_PREMGEN_ERR		-333
#define HSSL_GEN_CLKYEX_DHPAR_STORE_ERR		-334
#define HSSL_GEN_CLKYEX_INV_KEYEX_MODE		-335
#define HSSL_GEN_CLKYEX_MISSING_SRP_PARAM -336
#define HSSL_GEN_CLKYEX_ECC_INTERNAL_ERR    -337

//==========================================================
// Certificate chain reject error codes
//==========================================================
#define	HSSL_VFY_CHAIN_REJECT_BASE		-340	// not an error,is base
#define	HSSL_VFY_CHAIN_SELFSIGN_NOT_TOP		-341	// chain order reversed
#define	HSSL_VFY_CHAIN_INVAL_DATE_TIME		-342	// date time invalid
#define	HSSL_VFY_CHAIN_RDN_MATCH_ERR		-343	// RDNs matching error
#define	HSSL_VFY_CHAIN_ISSSUBJ_MISMATCH		-344	// issuer/subject match
#define	HSSL_VFY_CHAIN_GET_ROOT_ERR		-345	// could not fetch root
#define	HSSL_VFY_CHAIN_NO_TRUSTED_ROOT		-346	// root not trusted
#define	HSSL_VFY_CHAIN_ROOT_GETVAL_ERR		-347	// fetch value fail
#define	HSSL_VFY_CHAIN_CHK_ROOT_ERR		-348	// root process fail
#define	HSSL_VFY_CHAIN_DSA_DEF_ALLOCERR		-349	// allocation fault
#define	HSSL_VFY_CHAIN_DSA_NO_PARAMS		-350	// parameters missing
#define	HSSL_VFY_CHAIN_SIGNAT_CHK_ERR		-351	// signature params err
#define	HSSL_VFY_CHAIN_INVALID_SIGNAT		-352	// signature bad
#define	HSSL_VFY_CHAIN_NO_ROOT_ERR		-353	// no root in chain
#define	HSSL_VFY_CHAIN_BASIC_CONSTR_ERR		-354	// basic constr. err
#define	HSSL_VFY_CHAIN_KEYUSAGE_ERR		-355	// key usage fault

//==========================================================
// Returncodes from Extension processing
//==========================================================
#define	HSSL_EXT_TOO_FEW_DATA			-360
#define	HSSL_EXT_TOO_FEW_LIST_DATA		-361
#define HSSL_EXT_MISSING_EXT_DATA		-362
#define	HSSL_EXT_TOO_FEW_EXT_DATA		-363
#define	HSSL_EXT_TOO_MANY_EXT_DATA		-364
#define	HSSL_EXT_INCONSISTENT_EXT_DATA		-365
#define  HSSL_EXT_BAD_EXT_TYPE         -366
#define HSSL_EXT_DUPLICATE_SIG_ALG      -367
#define HSSL_EXT_REJECTED               -368

//==========================================================
// Returncodes from HLSSL_CONNECT/HLSSL_ACCEPT
//==========================================================

#define HSSL_NEWCONN_INVAL_SOCKINDEX		-400
#define HSSL_NEWCONN_SLOT_ALRDY_USED		-401
#define HSSL_NEWCONN_STRUC_ALLOC_ERR		-402
#define HSSL_NEWCONN_INV_CONN_ENTITY		-403
#define HSSL_NEWCONN_GEN_STARTMSG_ERR		-404
#define	HSSL_NEWCONN_STATE_ERR			-405	// XH-Interface
#define	HSSL_NEWCONN_INVALID_ID_ERR		-406	// XH-Interface
#define	HSSL_NEWCONN_OCSPV1_INIT_FAIL		-407	// XH-Interface

//==========================================================
// Returncodes from HSSL_INIT
//==========================================================

#define	HSSL_INVALID_USER_CALLBACK_METH		-408
#define HSSL_NO_CLIENT_CERTS			-409

#define HSSL_CFG_PWD_DECODE_FAILED		-410
#define HSSL_CFG_PWD_ERROR			-411
#define HSSL_CERTS_PWD_DECODE_FAILED		-412
#define HSSL_CERTS_PWD_ERROR			-413

#define	HSSL_CFG_READ_FAILED			-414
#define HSSL_CERT_READ_FAILED			-415
#define HSSL_CERT_TREE_GEN_FAILED		-416
#define HSSL_NO_SERVER_CERTS			-417
#define HSSL_ROOT_RDN_LIST_GEN_FAILED		-418

#define HSSL_REMOVE_SUITES_ALLOC_ERR		-419
#define HSSL_REMOVE_SUITES_INVKEYEX_ERR		-420
#define HSSL_NO_CIPHERSUITE_CERTS		-421
#define	HSSL_CONN_STRUC_ALLOC_ERR		-422
#define	HSSL_CFG_STRUC_ALLOC_ERR		-423

#define HSSL_CERTS_PROCESS_ERR			-424

//==========================================================
// Returncodes from HSSL_RELOAD_SUBJ_CNAMES_LIST
//==========================================================
#define	HSSL_LD_SCNLIST_NOT_INIT		-425
#define	HSSL_LD_SCNLIST_NO_LIST_IN_USE		-426
#define	HSSL_LD_SCNLIST_NO_LIST_IN_NEW		-427

// Additional messages fro TLS 1.1 initialization faults

#define	HSSL_CFG_TLS11_ONLY_EXPORT_CIPH_SUITES	-428
#define	HSSL_CFG_NO_SUPPORTED_CIPHER        -429

//============================================================
// Returncodes from HSSL_GET_CONN_Q_DATA/HSSL_GET_CONFG_Q_DATA
//============================================================
#define HSSL_GET_CONN_Q_DATA_NOT_CONN		-430
#define HSSL_GET_CONN_Q_DATA_INV_SOCK		-431
#define HSSL_GET_CONN_Q_DATA_LOCK_ERR		-432
#define HSSL_GET_CONN_Q_DATA_LEN_ERR		-433

#define HSSL_GET_CONFG_Q_DATA_LEN_ERR		-435

//()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()
//()								()
//() Returncodes for the XH Interface Module			()
//()								()
//()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()

#define	HSSL_XH_NOT_INITIALIZED_ERR		-440
#define	HSSL_XH_ALLOCATE_ERR			-441
#define	HSSL_XH_INVALID_STATE			-442
#define HSSL_XH_MISSING_GATHER_INPUT   -443

//===============================================================
// Returncodes from configuration processing etc.
//===============================================================

#define	HSSL_CFG_EXTCFG_DATA_INCOMPLETE		-460

#define	HSSL_INIT_OCSP_DATA_MISSING		-470

//()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()
//()								()
//() Returncodes for the Socket Provider Interface		()
//()								()
//()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()

#define	HSSL_HWSP_MAX_CONN_VALUE_ERR		-540
#define	HSSL_HWSP_CONNSTRU_ALLOC_ERR		-541

//()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()
//()								()
//() Returncodes for the JAVA Interface Modules			()
//()								()
//()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()()

//============================================================
// Returncodes from HSSLJIF (Java Socket Wrapper)
//============================================================
#define	HSSLJIF_CONNECT_DUPLICATE_REQ		-550
#define HSSLJIF_CONNECT_GET_SOCKPAR_ERR		-551
#define HSSLJIF_ACCEPT_NOTSAME_LISTENER		-552
#define HSSLJIF_ACCEPT_OUT_OF_SLOTS_ERR		-553
#define	HSSLJIF_ACCEPT_GET_STREAM_ERR		-554
#define HSSLJIF_ACCEPT_GET_SOCKPAR_ERR		-555
#define HSSLJIF_READ_NOT_CONNECTED_ERR		-556
#define	HSSLJIF_READ_NULLPTR			-557
#define HSSLJIF_READ_ERROR			-558
#define HSSLJIF_WRITE_NOT_CONNECTED_ERR		-559
#define	HSSLJIF_WRITE_NULLPTR			-560
#define HSSLJIF_WRITE_ERROR			-561
#define HSSLJIF_WRITE_OUT_OF_BUFFERS		-562
#define	HSSLJIF_READ_AVAIL_NOT_CONN_ERR		-563
#define HSSLJIF_READ_AVAIL_GET_ERROR		-564

//============================================================
// Returncodes from HSSLISTR (Socket Input Stream Handler)
//============================================================
#define HSSLISTR_SOCK_NOT_CONN_ERR		-570
#define HSSLISTR_STREAM_ALRDY_OPEN_ERR		-571
#define	HSSLISTR_STREAM_CLOSED_ERR		-572
#define	HSSLISTR_READ_ERR			-573
#define	HSSLISTR_READ_TIMEOUT			-574

//============================================================
// Returncodes from HSSLOSTR (Socket Output Stream Handler)
//============================================================
#define HSSLOSTR_SOCK_NOT_CONN_ERR		-575
#define HSSLOSTR_STREAM_ALRDY_OPEN_ERR		-576
#define	HSSLOSTR_STREAM_CLOSED_ERR		-577

//============================================================
// Returncodes from HSSJSOC (Java Socket Interface),
// HSSLCSOC (Java Client Socket Interface) and
// HSSLSSOC (Java Server Socket Interface)
//============================================================

#define	HSSLCSOC_RX_TIMEOUT_GET_ERR		-581
#define	HSSLCSOC_CONNECT_DUPLICATE_REQ		-582
#define	HSSLCSOC_CONNECT_OUT_OF_SOCKETS		-583
#define	HSSLCSOC_CONNECT_SOCKACCESS_ERR		-584
#define	HSSLCSOC_ACCEPT_DUPLICATE_REQ		-585
#define	HSSLCSOC_ACCEPT_INTF_GET_ERR		-586
#define	HSSLCSOC_ACCEPT_SOCKACCESS_ERR		-587
#define	HSSLCSOC_GET_ISTR_ALREADY_OPEN		-588
#define	HSSLCSOC_GET_OSTR_ALREADY_OPEN		-589
#define	HSSLCSOC_CLOSE_NOT_CONNECTED		-590
#define HSSLCSOC_GET_CONNDATA_NOT_CONN		-591
#define	HSSLCSOC_RX_TIMEOUT_SET_ERR		-592

#define	HSSLSSOC_ALREADY_LISTENING		-593
#define	HSSLSSOC_NO_LISTEN_PORT_GIVEN		-594
#define	HSSLSSOC_ACCEPT_NO_MORE_SOCKETS		-595
#define	HSSLSSOC_CLOSE_NOT_LISTENING		-596

#define WSAE_RX_TIMEOUT				-13000
#define WSAE_WOULD_BLOCK			-14000

#endif // !__HOB_SSL_ERR__

#ifndef __HOB_EXTCERT_ERR__
#define __HOB_EXTCERT_ERR__

//-------------------------------------------------------
// Error codes from hextcert.h
//-------------------------------------------------------

//-------------------------------------------------------------
// Error Codes, Range: -6100 ... -6199
//-------------------------------------------------------------

#define	HSSL_EXTCERT_PARAM_ERR		-2
#define	HSSL_EXTCERT_ALLOC_ERR		-3

#define	HSSL_EXTCERT_INTF_NOT_SUPPORTED	-6100
#define	HSSL_EXTCERT_INTF_NOT_LOADED_ER	-6101
#define	HSSL_EXTCERT_STRUC_ALLOC_FAILED	-6102
#define	HSSL_EXTCERT_INIT_GET_PATH_FAIL	-6103
#define	HSSL_EXTCERT_INIT_LOAD_LIB_FAIL	-6104
#define	HSSL_EXTCERT_INIT_ALLOC_FAILED	-6105
#define	HSSL_EXTCERT_INIT_PROCADR_FAIL	-6106
#define	HSSL_EXTCERT_INIT_LIBRARY_FAIL	-6107
#define	HSSL_EXTCERT_INIT_INV_LIB_TYPE	-6108

#define	HSSL_EXTCERT_NO_CLNT_CHAIN_DATA	-6110
#define	HSSL_EXTCERT_INV_CCHAIN_DATALEN	-6111
#define	HSSL_EXTCERT_CCHAIN_ADDCERT_ERR	-6112
#define	HSSL_EXTCERT_NO_CLNT_CERTS	-6113

#define	HSSL_EXTCERT_NO_SRVR_CERT	-6115
#define	HSSL_EXTCERT_NO_SRVR_CHAIN_DATA	-6116
#define	HSSL_EXTCERT_INV_SCHAIN_DATALEN	-6117
#define	HSSL_EXTCERT_SCHAIN_ADDCERT_ERR	-6118

#define	HSSL_EXTCERT_GET_ECERT_NO_CERTS	-6120
#define	HSSL_EXTCERT_GET_ECERT_NO_DATA	-6121

#define	HSSL_EXTCERT_PRIV_SIGN_NO_DATA	-6125
#define	HSSL_EXTCERT_PSIGN_BUF_TOOSMALL	-6126
#define	HSSL_EXTCERT_PSIGN_INV_SIGALGOR	-6127
#define	HSSL_EXTCERT_PSIGN_INV_RETLEN	-6128

#endif // !__HOB_EXTCERT_ERR__

#if !defined _HSSL_SESSION_CACHE_ERR_HDR_
#define _HSSL_SESSION_CACHE_ERR_HDR_
/** @addtogroup sslcache
* @{
* @file
* This header contains the error code definitions for the SSL cache 
* module for the WSP.
* @}
*/
#define	HCMA_QUERY_CMA_ERR		-9100
#define	HCMA_SETSIZE_CMA_ERR		-9101
#define	HCMA_LOCK_CMA_ERR		-9102
#define	HCMA_UNLOCK_CMA_ERR		-9103

#define	HS_SRVR_CACHE_NOTINITIALIZED	-9110
#define	HS_CLNT_CACHE_NOTINITIALIZED	-9111

#define	HS_CLNT_CACHE_IPADDR_FETCH_FAIL	-9115
#define	HS_CLNT_CACHE_UNK_SRVR_ADFAMILY	-9116

#endif // !defined _HSSL_SESSION_CACHE_ERR_HDR_

#endif // !__HOB_SSL_ERROR_CODES__
