#ifndef __HOB_CERT_ERR__
#define __HOB_CERT_ERR__
#ifdef _WIN32
#pragma once
#endif

//-----------------------------------------------------------------------------
// PKCS5
//-----------------------------------------------------------------------------

//==============================================
// Global Returncodes
//==============================================
#define PKCS5_OP_OK			0

/** @addtogroup pkcs5
* @{
* @file
* This header defines return codes for the PKCS 5 module.
* @}
*/
//===============================================
// Specific Returncodes, range from -650 ... -699
//===============================================

//----------------------------------------------
// Returncodes from PKCS5 private key Encryption
//----------------------------------------------
#define	PKCS5_ENC_INVALID_INPUT_DATA	-650
#define PKCS5_ENC_DST_BUF_ALLOC_ERR	-651

//----------------------------------------------
// Returncodes from PKCS5 private key Decryption
//----------------------------------------------
#define PKCS5_DEC_NOT_ENOUGH_ASN1_DATA	-660
#define PKCS5_DEC_INVALID_ASN1_DATA	-661
#define PKCS5_DEC_INVALID_ALGOR_ID	-662
#define	PKCS5_DEC_INVALID_ALGOR_PARAMS	-663
#define	PKCS5_DEC_DST_BUF_ALLOC_ERR	-664
#define PKCS5_DEC_INVALID_PADDING_SIZE	-665
#define PKCS5_DEC_INVALID_PADDING_DATA	-666

//-----------------------------------------------------------------------------
// ASN1
//-----------------------------------------------------------------------------

/** @addtogroup asn1
* @{
* @file
* This header contains the error code definitions for the certificate handling
* module.
* @}
*/

//--------------------------------------------------------
// global ASN.1 error codes
//--------------------------------------------------------
#define	ASN1_NULL_PTR		-1
#define	ASN1_PARAM_ERR		-2
#define	ASN1_ALLOC_ERR		-3

//--------------------------------------------------------
// Cert Chain verification Error reason codes
//--------------------------------------------------------

#define	ASN1_VFY_CHAIN_NO_REASON	0
#define	ASN1_VFY_CHAIN_SELFSIGN_NOT_TOP	-1
#define	ASN1_VFY_CHAIN_INVAL_DATE_TIME  -2
#define	ASN1_VFY_CHAIN_RDN_MATCH_ERR	-3
#define	ASN1_VFY_CHAIN_ISSSUBJ_MISMATCH -4
#define	ASN1_VFY_CHAIN_GET_ROOT_ERR	-5
#define	ASN1_VFY_CHAIN_NO_TRUSTED_ROOT	-6
#define	ASN1_VFY_CHAIN_ROOT_GETVAL_ERR	-7
#define	ASN1_VFY_CHAIN_CHK_ROOT_ERR	-8
#define	ASN1_VFY_CHAIN_DSA_DEF_ALLOCERR	-9
#define	ASN1_VFY_CHAIN_DSA_NO_PARAMS	-10
#define	ASN1_VFY_CHAIN_SIGNAT_CHK_ERR	-11
#define	ASN1_VFY_CHAIN_INVALID_SIGNAT	-12

#define	ASN1_VFY_CHAIN_NO_ROOT_ERR	-13
#define	ASN1_VFY_CHAIN_BASIC_CONSTR_ERR	-14
#define	ASN1_VFY_CHAIN_KEYUSAGE_ERR	-15

//===========================================
// Global Returncodes
//===========================================

#define	ASN1_OP_OK		 	 0

//==================================================
// Specific Returncodes, Range from -1100 ... -5999
//==================================================

//-------------------------------------------
// IDATA Array Allocation Returncodes
//-------------------------------------------
#define ASN1_IDATA_ALLOC_PARAMERR	-1100
#define ASN1_IDATA_ALLOC_ALLOC_ERR	-1101

//-------------------------------------------
// Copy to local IDATPARR Returncodes
//-------------------------------------------
#define ASN1_COPY_TO_LCL_ARR_ALLOC_ERR	-1120
#define ASN1_COPY_TO_LCL_BUF_ALLOC_ERR  -1121

//----------------------------------------------------------
// ASN1 type, length field and data length fetch Returncodes
//----------------------------------------------------------
#define ASN1_HDR_GET_NOT_PRESENT	-1140
#define ASN1_HDR_GET_NO_BASE		-1141
#define ASN1_HDR_GET_NO_DATA		-1142
#define ASN1_HDR_GET_DATA_INCOMPLETE	-1143
#define ASN1_HDR_GET_FLDLEN_ERR		-1144
#define ASN1_HDR_GET_INCONSIST_DATLEN	-1145

//--------------------------------------------------------
// Internal to ASN1/ASN1 to internal converter Returncodes
//--------------------------------------------------------
#define INT_TO_ASN1_PARAMERR_PHASE1	-1160
#define INT_TO_ASN1_ALLOC_ERR		-1161
#define INT_TO_ASN1_DATA_CHK_ERR	-1162
#define INT_TO_ASN1_DATA_MISSING	-1163
#define INT_TO_ASN1_SKIP_ERR		-1164
#define INT_TO_ASN1_LEN_ERR		-1165
#define INT_TO_ASN1_PHASE1_ERR		-1166
#define INT_TO_ASN1_PARAMERR_PHASE2	-1167
#define INT_TO_ASN1_PHASE2_ERR		-1168

#define ASN1_TO_INT_PARAMERR		-1180
#define ASN1_TO_INT_ALLOC_ERR		-1181
#define ASN1_TO_INT_DATA_MISSING	-1182
#define ASN1_TO_INT_SKIP_ERR		-1183
#define ASN1_TO_INT_WRONG_DATA		-1184
#define ASN1_TO_INT_LEN_ERR		-1185
#define ASN1_TO_INT_RAW_DATA_ERR	-1186
#define ASN1_TO_INT_STACK_ERR		-1187
#define ASN1_TO_INT_FLDLEN_ERR		-1188   

//--------------------------------------------
// ASN1 Sub-Fields Counter Routine Returncodes
//--------------------------------------------
#define ASN1_CNT_DATA_MISSING		-1200
#define ASN1_CNT_FLDLEN_ERR		-1201   

//-----------------------------------------------------------
// 32 Bit internal to ASN1 integer and vice versa Returncodes
//-----------------------------------------------------------
#define ASN1_BIT32NUM_TO_BUF_NULPTR_ERR -1220
#define ASN1_BIT32NUM_TO_BUF_ALLOC_ERR	-1221

#define ASN1_BUF_TO_BIT32NUM_NULPTR_ERR -1230
#define ASN1_BUF_TO_BIT32NUM_INVLEN_ERR -1231

//-------------------------------------------------------------------
// 32 Bit internal Flags to ASN1 bitstring and vice versa Returncodes
//-------------------------------------------------------------------
#define ASN1_BIT32FLG_TO_BUF_NULPTR_ERR	-1240
#define ASN1_BIT32FLG_TO_BUF_INVCNT_ERR -1241
#define	ASN1_BIT32FLG_TO_BUF_ALLOC_ERR  -1242

#define ASN1_BUF_TO_BIT32FLG_NULPTR_ERR -1250
#define ASN1_BUF_TO_BIT32FLG_INVLEN_ERR -1251
#define ASN1_BUF_TO_BIT32FLG_INVBIT_ERR -1252

//-------------------------------------------------------
// ASN1 Substrings to internal and vice versa Returncodes
//-------------------------------------------------------
#define ASN1_SUB_TO_INT_PARAM_ERR	-1260
#define ASN1_SUB_TO_INT_ALLOC_ERR	-1261
#define ASN1_SUB_TO_INT_DATA_MISSING	-1262
#define ASN1_SUB_TO_INT_FLDLEN_ERR	-1263

#define ASN1_INT_TO_SUB_PARAM_ERR	-1270
#define ASN1_INT_TO_SUB_ALLOC_ERR	-1271
#define ASN1_INT_TO_SUB_ERR		-1272
#define ASN1_INT_TO_SUB_DST_ALLOC_ERR	-1273
#define ASN1_INT_TO_SUB_DST_CONV_ERR	-1274

//----------------------------------------------------------
// ASN1 IBM-Container to internal and vice versa Returncodes
//----------------------------------------------------------
#define ASN1_IBM_CONT_TO_INT_ALLOC_ERR	-1280
#define ASN1_IBM_CONT_TO_INT_ERR	-1281
#define ASN1_IBM_CONT_INV_CONT_ERR	-1282

#define ASN1_INT_TO_IBM_CONT_PARAM_ERR  -1290
#define ASN1_INT_TO_IBM_CONT_DATA_ERR	-1291
#define ASN1_INT_TO_IBM_CONT_ERR	-1292

//--------------------------------------------------------------
// ASN1 X509Cert/TBS-Cert to internal and vice versa Returncodes
//--------------------------------------------------------------
#define ASN1_CERT_TO_INT_ALLOC_ERR	-1300
#define ASN1_CERT_TO_INT_ERR		-1301

#define ASN1_INT_TO_CERT_PARAM_ERR	-1310
#define ASN1_INT_TO_CERT_ERR		-1311

#define ASN1_TBS_CERT_TO_INT_ALLOC_ERR	-1320
#define ASN1_TBS_CERT_TO_INT_ERR	-1321

#define ASN1_INT_TO_TBS_CERT_PARAM_ERR	-1330
#define ASN1_INT_TO_TBS_CERT_ERR	-1331    

//----------------------------------------------------------------
// ASN1 X509 RDN/Extensions to internal and vice versa Returncodes
//----------------------------------------------------------------

#define ASN1_RDN_TO_INT_ERROR		-1350

#define ASN1_INT_TO_RDN_ERROR		-1360

#define ASN1_INT_TO_EXT_ERROR		-1370

#define ASN1_EXT_TO_INT_ERROR		-1380

#define	ASN1_OIDLIST_TO_INT_ERROR	-1385
#define	ASN1_INT_TO_OIDLIST_ERROR	-1386

//-------------------------------------------
// ASN1 OBJID comparison Returncodes
//-------------------------------------------
#define ASN1_OBJID_CMP_PARAM_ERR	-1400
#define ASN1_OBJID_CMP_MISSING_ENTRY	-1401
#define ASN1_OBJID_CMP_TOO_LARGE_PART	-1402
#define ASN1_OBJID_CMP_TOO_MANY_PARTS	-1403
#define ASN1_OBJID_CMP_MISFORMED_OBJID	-1404

#define ASN1_AVA_SORT_PARAM_ERR		-1420

//-------------------------------------------
// ASN1 Field values comparison Returncodes
//-------------------------------------------
#define ASN1_VAL_CMP_INVALID_ASN1_TYPE	-1430
#define ASN1_VAL_CMP_DATA_MISSING	-1431
#define ASN1_VAL_CMP_FLDLEN_ERR		-1432
#define ASN1_VAL_CMP_INCONSIST_DATLEN	-1433

//--------------------------------------------
// ASN1 Directory Names comparison Returncodes
//--------------------------------------------
#define ASN1_DIR_NAME_CMP_EMPTY_STRINGS -1435
#define ASN1_DIR_NAME_CMP_CELL_SIZE_ERR -1436

//-------------------------------------------------
// Decimal Number to Integer Conversion Returncodes
//-------------------------------------------------
#define ASN1_DEC_NUM_TO_INT_DIGITS_ERR	-1440
#define ASN1_DEC_NUM_TO_INT_INV_DIGIT	-1441
#define ASN1_DEC_NUM_TO_INT_NEGATIVE_ER -1442
//-------------------------------------------
// ASN1 Timestrings to internal Returncodes
//-------------------------------------------
#define ASN1_TIME_TO_INT_DATA_MISSING	-1450
#define ASN1_TIME_TO_INT_INVAL_YEAR 	-1451
#define ASN1_TIME_TO_INT_INVAL_MONTH	-1452
#define ASN1_TIME_TO_INT_INVAL_DAY	-1453
#define ASN1_TIME_TO_INT_INVAL_HOUR	-1454
#define ASN1_TIME_TO_INT_INVAL_MINUTES  -1455
#define ASN1_TIME_TO_INT_INVAL_SECONDS  -1456
#define ASN1_TIME_TO_INT_INVAL_MSECS	-1457
#define ASN1_TIME_TO_INT_INVAL_DELTHOUR	-1458
#define ASN1_TIME_TO_INT_INVAL_DELTMINS	-1459
#define ASN1_TIME_TO_INT_INVAL_DELTAOP	-1460
#define ASN1_TIME_TO_INT_INVAL_DATA     -1461
#define ASN1_TIME_TO_INT_INVAL_DATLEN   -1462

#define ASN1_CERT_VFY_INV_TIME_TYPE	-1470

#define ASN1_CERT_GET_TIME_INV_TIMETYPE	-1475

//-------------------------------------------
// ASN1 OBJID Algorithms check Returncodes
//-------------------------------------------
#define ASN1_GET_ALG_PARAM_ERR		-1480
#define ASN1_GET_ALG_NO_OID		-1481
#define ASN1_GET_ALG_UNKNOWN_OID	-1482
#define ASN1_GET_ALG_PURP_NOT_SUPPORTED	-1483

//-------------------------------------------
// Generation of ASN1 OBJIDs Returncodes
//-------------------------------------------
#define ASN1_GEN_OID_NULL_PTR_ERR	-1500
#define ASN1_GEN_OID_UNKNOWN_OID	-1501
#define ASN1_GEN_OID_BUF_ALLOC_ERR	-1502

//---------------------------------------------------------
// Decode from/Encode to ASN1 X509 Public Value Returncodes
//---------------------------------------------------------
#define ASN1_DEC_PUB_KEY_NULL_PTR_ERR	-1520
#define ASN1_DEC_PUB_KEY_ALLOC_ERR	-1521
#define ASN1_DEC_PUB_KEY_RSA_PAR_ERR	-1522
#define ASN1_DEC_PUB_KEY_RSA_VAL_ERR	-1523
#define ASN1_DEC_PUB_KEY_DH_PAR_ERR	-1524
#define ASN1_DEC_PUB_KEY_DH_VAL_ERR	-1525
#define ASN1_DEC_PUB_KEY_DSA_PAR_ERR	-1526
#define ASN1_DEC_PUB_KEY_DSA_VAL_ERR	-1527
#define ASN1_DEC_PUB_INTERNAL_ERR	-1530

#define ASN1_ENC_PUB_KEY_NULL_PTR_ERR	-1540
#define ASN1_ENC_PUB_KEY_UNKNOWN_ALGOR	-1541
#define ASN1_ENC_PUB_KEY_INV_DATA	-1542
#define ASN1_ENC_PUB_KEY_ARR_ALLOC_ERR	-1543
#define ASN1_ENC_PUB_KEY_OID_GEN_ERR	-1544
#define ASN1_ENC_PUB_KEY_RSA_PAR_ERR	-1545
#define ASN1_ENC_PUB_KEY_RSA_VAL_ERR	-1546
#define ASN1_ENC_PUB_KEY_DH_PAR_ERR	-1547
#define ASN1_ENC_PUB_KEY_DH_VAL_ERR	-1548
#define ASN1_ENC_PUB_KEY_DSA_PAR_ERR	-1549
#define ASN1_ENC_PUB_KEY_DSA_VAL_ERR	-1550

//-------------------------------------------------------------
// Decode from/Encode to ASN1 IBM Cont. Private Key Returncodes
//-------------------------------------------------------------
#define ASN1_DEC_PRIV_KEY_NULL_PTR_ERR	-1560
#define ASN1_DEC_PRIV_KEY_RSA_PAR_ERR	-1561
#define	ASN1_DEC_PRIV_KEY_RSA_VAL_ERR	-1562
#define ASN1_DEC_PRIV_KEY_DSA_PAR_ERR	-1563
#define	ASN1_DEC_PRIV_KEY_DSA_VAL_ERR	-1564
#define ASN1_DEC_PRIV_KEY_DH_PAR_ERR	-1565
#define	ASN1_DEC_PRIV_KEY_DH_VAL_ERR	-1566
#define ASN1_DEC_PRIV_KEY_ALLOC_ERR	-1567
#define ASN1_DEC_PRIV_KEY_INTERNAL_ERR	-1568

#define ASN1_ENC_PRIV_KEY_NULL_PTR_ERR	-1570
#define ASN1_ENC_PRIV_KEY_UNKNOWN_ALGOR	-1571
#define ASN1_ENC_PRIV_KEY_INV_DATA	-1572
#define ASN1_ENC_PRIV_KEY_ARR_ALLOC_ERR	-1573
#define ASN1_ENC_PRIV_KEY_VERS_GEN_ERR	-1574
#define ASN1_ENC_PRIV_KEY_OID_GEN_ERR	-1575
#define ASN1_ENC_PRIV_KEY_RSA_PAR_ERR	-1576
#define ASN1_ENC_PRIV_KEY_RSA_VAL_ERR	-1577
#define ASN1_ENC_PRIV_KEY_DSA_PAR_ERR	-1578
#define ASN1_ENC_PRIV_KEY_DSA_VAL_ERR	-1579
#define ASN1_ENC_PRIV_KEY_DH_PAR_ERR	-1580
#define ASN1_ENC_PRIV_KEY_DH_VAL_ERR	-1581
#define ASN1_ENC_PRIV_KEY_KEY_COPY_ERR	-1582
#define ASN1_ENC_PRIV_KEY_INF_GEN_ERR	-1583

//------------------------------------------------------
// Decode from/Encode to ASN1 X509 Signature Returncodes
//------------------------------------------------------
#define ASN1_DEC_SIGNAT_NULL_PTR_ERR	-1590
#define ASN1_DEC_SIGNAT_ALLOC_ERR	-1591
#define ASN1_DEC_SIGNAT_RSA_PAR_ERR	-1592
#define ASN1_DEC_SIGNAT_RSA_VAL_ERR	-1593
#define ASN1_DEC_SIGNAT_DSA_PAR_ERR	-1594
#define ASN1_DEC_SIGNAT_DSA_VAL_ERR	-1595
#define ASN1_DEC_SIGNAT_INV_ALG_TYPE	-1596

#define ASN1_ENC_SIGNAT_NULL_PTR_ERR	-1600
#define ASN1_ENC_SIGNAT_INV_DATA	-1601
#define ASN1_ENC_SIGNAT_INV_REQ_TYPE	-1602
#define ASN1_ENC_SIGNAT_ARR_ALLOC_ERR   -1603
#define ASN1_ENC_SIGNAT_OID_GEN_ERR	-1604
#define ASN1_ENC_SIGNAT_PAR_ALLOC_ERR   -1605
#define ASN1_ENC_SIGNAT_RSA_PAR_ERR	-1606
#define ASN1_ENC_SIGNAT_RSA_VAL_ERR	-1607
#define ASN1_ENC_SIGNAT_DH_PAR_ERR	-1608
#define ASN1_ENC_SIGNAT_DH_VAL_ERR	-1609
#define ASN1_ENC_SIGNAT_DSA_PAR_ERR	-1610
#define ASN1_ENC_SIGNAT_DSA_VAL_ERR	-1611

//--------------------------------------------------------------
// Decode from ASN1 X509 Signature Algor to internal Returncodes
//--------------------------------------------------------------
#define	ASN1_GET_CHK_SIGNAT_NULLPTR_ERR	-1620
#define ASN1_GET_CHK_SIGNAT_RSA_PAR_ERR -1621
#define	ASN1_GET_CHK_SIGNAT_DSA_PAR_ERR -1622
#define	ASN1_GET_CHK_SIGNAT_INV_TYPE	-1623
#define	ASN1_GET_CHK_SIGNAT_ALLOC_ERR	-1624

//------------------------------------------------
// Various internal used copy routines Returncodes
//------------------------------------------------
#define ASN1_BUF_TO_DESC_NULL_PTR_ERR	-1640
#define ASN1_BUF_TO_DESC_WRONG_INDEX	-1641

#define ASN1_BUF_TO_DATARR_NULLPTR_ERR	-1650
#define ASN1_BUF_TO_DATARR_ALLOC_ERR	-1651

#define ASN1_DATARR_ELEM_COPY_NULPT_ERR -1660
#define ASN1_DATARR_ELEM_COPY_ALLOC_ERR -1661

#define ASN1_DATARR_COPY_NULLPTR_ERR	-1670
#define ASN1_DATARR_COPY_INV_DST_ERR	-1671
#define ASN1_DATARR_COPY_INV_CNT_ERR	-1672

#define ASN1_DATARRDESC_COPY_NULPT_ERR  -1680

#define ASN1_LNUM_TO_DESC_NULLPTR_ERR   -1700
#define ASN1_LNUM_TO_DESC_INV_DESC_ERR  -1701
#define ASN1_LNUM_TO_DESC_ALLOC_ERR	-1702

#define ASN1_DESC_TO_LNUM_NULLPTR_ERR   -1710
#define ASN1_DESC_TO_LNUM_ALLOC_ERR	-1711
#define ASN1_DESC_TO_LNUM_CONV_ERR	-1712

//--------------------------------------------------------------
// 7/8 Bit Encoder/Decoder Returncodes, --- no longer used !!!--
//--------------------------------------------------------------
#define ASN1_BIT_DECODE_NULL_PTR	-1720
#define ASN1_BIT_DECODE_INVALID_LEN	-1721
#define ASN1_BIT_DECODE_ALLOC_ERR	-1722
#define ASN1_BIT_DECODE_DATA_ERR	-1723

#define ASN1_BIT_ENCODE_NULL_PTR	-1730
#define ASN1_BIT_ENCODE_INVALID_LEN	-1731
#define ASN1_BIT_ENCODE_ALLOC_ERR	-1732

//---------------------------------------------
// SSL vector extraction/generation Returncodes
//---------------------------------------------
#define ASN1_GET_VEC_LEN_LENCNT_ERR	-1740
#define ASN1_GET_VEC_LEN_TOO_FEW_DATA	-1741

#define ASN1_PUT_VEC_LEN_LENCNT_ERR	-1760
#define ASN1_PUT_VEC_LEN_LENGTH_ERR	-1761

//---------------------------------------------
// Certificate Structure allocation Returncodes
//---------------------------------------------
#define ASN1_CERT_ALLOC_NULL_PTR_ERR	-1780
#define ASN1_CERT_ALLOC_ALLOC_ERR	-1781
#define ASN1_CERT_ALLOC_ELEM_ALLOC_ERR	-1782

//-------------------------------------------------
// ASN1 X509 Cert to internal converter Returncodes
//-------------------------------------------------
#define ASN1_CERT_TO_STRUC_NULL_PTR_ERR -1800
#define	ASN1_CERT_TO_STRUC_NO_DATA	-1801
#define	ASN1_CERT_TO_STRUC_ALLOC_ERR	-1802
#define ASN1_CERT_TO_STRUC_ALG_MISMATCH -1803
#define ASN1_CERT_TO_STRUC_NO_IBM_CERT  -1804
#define ASN1_CERT_TO_STRUC_NO_SRVR_CERT -1805
#define ASN1_CERT_TO_STRUC_NO_PRIVKEY   -1806
#define ASN1_CERT_TO_STRUC_PRIVKEY_ERR  -1807
#define ASN1_CERT_TO_STRUC_VERSION_ERR	-1808
#define	ASN1_CERT_TO_STRUC_UNRECOG_CRIT	-1810

//--------------------------------------------
// Certificate matching Returncodes
//--------------------------------------------
#define ASN1_MATCH_CERT_NULL_PTR_ERR	-1820
#define ASN1_MATCH_CERTREQ_NULL_PTR_ERR	-1830

//-------------------------------------------------------------------
// 7-Bit Certificate List decoder Returncodes --- no longer used!!---
//-------------------------------------------------------------------
#define ASN1_GET_CERT_LIST_NULL_PTR_ERR -1840
#define ASN1_GET_CERT_LIST_NO_PWD_ERR	-1841
#define ASN1_GET_CERT_LIST_DATA_ERR	-1842
#define ASN1_GET_CERT_LIST_NOCERT_ERR   -1843
#define ASN1_GET_CERT_LIST_ARR_ALLOCERR -1844
#define ASN1_GET_CERT_LIST_ELM_ALLOCERR -1845

//---------------------------------------------------------
// Certificate List/Chain to internal converter Returncodes
//---------------------------------------------------------
#define ASN1_GET_CERTCHAIN_NULLPTR_ERR  -1860
#define ASN1_GET_CERTCHAIN_NO_CERTS	-1861
#define ASN1_GET_CERTCHAIN_ARR_ALLOCERR -1862

//-----------------------------------------------------
// ASN1 X509 Certificate Signature Verifier Returncodes
//-----------------------------------------------------
#define ASN1_VFY_CERT_NULL_PTR_ERR	-1900
#define ASN1_VFY_CERT_ALGOR_MISMATCH	-1901
#define ASN1_VFY_CERT_INV_ALGOR_ERR	-1902
#define ASN1_VFY_CERT_RSASTRU_ALLOC_ERR	-1903
#define ASN1_VFY_CERT_RSASTRU_LOAD_ERR	-1904
#define ASN1_VFY_CERT_RSA_SIGNAT_ERR	-1905
#define ASN1_VFY_CERT_DSASTRU_ALLOC_ERR	-1906
#define ASN1_VFY_CERT_DSASTRU_LOAD_ERR	-1907
#define ASN1_VFY_CERT_DSA_SIGNAT_ERR	-1908

//-----------------------------------------------------
// Trusted Root Certificate Checker/Fetcher Returncodes
//-----------------------------------------------------
#define	ASN1_CHK_TRUST_ROOT_NULLPTR_ERR -1920
#define	ASN1_CHK_TRUST_ROOT_NO_CERTS	-1921

#define ASN1_GET_TRUST_ROOT_NULLPTR_ERR -1940

#define	ASN1_COMPLETE_CHAIN_NULLPTR_ERR	-1942
#define	ASN1_COMPLETE_CHAIN_NO_CERTS	-1943

//--------------------------------------------
// Certificate Chain Verifier Returncodes
//--------------------------------------------
#define	ASN1_CERT_CHAIN_VFY_NULLPTR_ERR -1960
#define	ASN1_CERT_CHAIN_VFY_NO_CERTS	-1961
#define	ASN1_CERT_CHAIN_VFY_NO_ROOTS	-1962

//-----------------------------------------------------
// Certificate Chain /Root RDN List Builder Returncodes
//-----------------------------------------------------
#define ASN1_TO_CERT_CHAIN_NULLPTR_ERR	-2000
#define ASN1_TO_CERT_CHAIN_NO_CERTS	-2001
#define ASN1_TO_CERT_CHAIN_NO_ROOTS	-2002

#define ASN1_TO_ROOT_RDNLIST_NULLPTR	-2020
#define ASN1_TO_ROOT_RDNLIST_NO_ROOTS	-2021

//--------------------------------------------------------
// SSL Certificate Chain / RDN List Converters Returncodes
//--------------------------------------------------------
#define ASN1_FROM_SSL_CERTLIST_NULL_PTR -2040
#define ASN1_FROM_SSL_CERTLIST_LIST_ERR -2041

#define	ASN1_FROM_SSL_RDNLIST_NULL_PTR	-2060
#define	ASN1_FROM_SSL_RDNLIST_LIST_ERR  -2061
#define ASN1_FROM_SSL_RDNLIST_ALLOC_ERR -2062

#define ASN1_TO_SSL_LIST_NULL_PTR	-2080
#define ASN1_TO_SSL_LIST_ALLOC_ERR	-2081

//---------------------------------------------
// ASN1 Certificate Request Builder Returncodes
//---------------------------------------------
#define ASN1_CERT_REQ_TO_INT_ALLOC_ERR	-2100
#define ASN1_CERT_REQ_TO_INT_ERR	-2101

#define ASN1_TBSCRT_RQ_TO_INT_ALLOC_ERR	-2110
#define ASN1_TBSCERT_REQ_TO_INT_ERR	-2111

#define ASN1_INT_TO_CERT_REQ_PARAM_ERR	-2120
#define ASN1_INT_TO_CERT_REQ_ERR	-2121

#define ASN1_INT_TO_TBSCRT_RQ_PARAM_ERR	-2130
#define ASN1_INT_TO_TBSCERT_REQ_ERR	-2131

#define ASN1_TO_TBSVALIDITY_NULLPTR_ERR -2140
#define ASN1_TO_TBSVALIDITY_TIMETYP_ERR -2141

//--------------------------------------------
// ASN1 IBM Container Builder Returncodes
//--------------------------------------------
#define ASN1_TO_IBM_CONT_NULPTR_ERR	-2160

#define ASN1_TO_CONT_ORDINAL_NULPTR_ERR -2170
#define ASN1_TO_CONT_ORDINAL_INVNUM_ERR -2171

#define ASN1_TO_CONT_CERT_NULPTR_ERR	-2180
#define ASN1_TO_CONT_CERT_INV_LEN_ERR   -2181
#define ASN1_TO_CONT_CERT_INV_TYPE_ERR	-2182

#define ASN1_TO_CONT_PRIVKEY_NULPTR_ERR -2190
#define ASN1_TO_CONT_PRIVKEY_INVALG_ERR -2191
#define ASN1_TO_CONT_PRIVKEY_ENCR_ERR	-2192

#define ASN1_TO_CONT_NAME_NULPTR_ERR	-2200
#define ASN1_TO_CONT_NAME_INV_LEN_ERR   -2201

#define ASN1_TO_CONT_FLAGS_NULPTR_ERR   -2210
#define ASN1_TO_CONT_FLAGS_INV_BITS_ERR -2211

#define ASN1_TO_CONT_UNK_ALLOC_ERR	-2220

//------------------------------------------------
// ASN1 Public/Private Info Converters Returncodes
//------------------------------------------------
#define ASN1_PUB_INF_TO_RSA_NULLPTR_ERR -2230
#define ASN1_PUB_INF_TO_RSA_ALLOC_ERR	-2231

#define ASN1_PRIV_INF_TO_RSA_NULPTR_ERR -2240
#define ASN1_PRIV_INF_TO_RSA_ALLOC_ERR	-2241

#define ASN1_RSA_PUB_TO_DESC_NULPTR_ERR -2250
#define ASN1_RSA_PUB_TO_DESC_ALLOC_ERR  -2251

#define ASN1_RSA_PRIV_TO_DESC_NULPT_ERR	-2260
#define ASN1_RSA_PRIV_TO_DESC_ALLOC_ERR -2261

#define ASN1_PUB_INF_TO_DSA_NULLPTR_ERR -2270
#define ASN1_PUB_INF_TO_DSA_ALLOC_ERR	-2271

#define ASN1_PRIV_INF_TO_DSA_NULPTR_ERR -2280
#define ASN1_PRIV_INF_TO_DSA_ALLOC_ERR	-2281

#define ASN1_DSA_PUB_TO_DESC_NULPTR_ERR -2290
#define ASN1_DSA_PUB_TO_DESC_ALLOC_ERR  -2291

#define ASN1_DSA_PRIV_TO_DESC_NULPT_ERR	-2300
#define ASN1_DSA_PRIV_TO_DESC_ALLOC_ERR -2301

#define ASN1_PUB_INF_TO_DH_NULLPTR_ERR  -2310
#define ASN1_PUB_INF_TO_DH_ALLOC_ERR	-2311

#define ASN1_PRIV_INF_TO_DH_NULPTR_ERR  -2320
#define ASN1_PRIV_INF_TO_DH_ALLOC_ERR	-2321

#define ASN1_DH_PUB_TO_DESC_NULPTR_ERR	-2330
#define ASN1_DH_PUB_TO_DESC_ALLOC_ERR	-2331

#define ASN1_DH_PRIV_TO_DESC_NULPT_ERR	-2340
#define ASN1_DH_PRIV_TO_DESC_ALLOC_ERR  -2341

//--------------------------------------------
// ASN1 Cert/CertReq/OCSP Signer Returncodes
//--------------------------------------------

#define ASN1_SIGN_TBS_DATA_NULL_PTR_ERR -2360
#define ASN1_SIGN_TBS_DATA_RSA_LEN_ERR  -2361
#define ASN1_SIGN_TBS_DATA_DSA_LEN_ERR  -2362
#define ASN1_SIGN_TBS_DATA_INV_ALG_ERR  -2363
#define ASN1_SIGN_TBS_DATA_ALLOC_ERR	-2364
#define ASN1_SIGN_TBS_DATA_RSA_SIGN_ERR -2365
#define ASN1_SIGN_TBS_DATA_DSA_SIGN_ERR -2366

//-----------------------------------------------
// ASN1 Certificate Request Converter Returncodes
//-----------------------------------------------
#define ASN1_CERTREQ_ALLOC_NULL_PTR_ERR -2380
#define ASN1_CERTREQ_ALLOC_ERR		-2381
#define ASN1_CERTREQ_ELEM_ALLOC_ERR	-2382
#define ASN1_CERTREQ_TO_STRU_NULPTR_ERR -2383
#define ASN1_CERTREQ_TO_STRUC_NO_DATA	-2384
#define ASN1_CERTREQ_TO_STRUC_NO_KEY	-2385
#define ASN1_CERTREQ_TO_STRUC_NO_CRTREQ -2386
#define ASN1_CERTREQ_TO_STRUC_ALLOC_ERR -2387
#define ASN1_CRTREQ_TO_STRUC_NO_PRIVKEY -2388
#define ASN1_CRTREQ_TO_STRUC_PRIVKY_ERR -2389

//--------------------------------------------------------
// ASN1 Certificate Request Signature Verifier Returncodes
//--------------------------------------------------------
#define ASN1_VFY_CERTREQ_NULL_PTR_ERR	-2400
#define ASN1_VFY_CERTREQ_ALGOR_MISMATCH	-2401
#define ASN1_VFY_CERTREQ_INV_ALGOR_ERR	-2402
#define ASN1_VFY_CRTRQ_RSASTRU_LOAD_ERR	-2403
#define ASN1_VFY_CERTREQ_RSA_SIGNAT_ERR	-2404
#define ASN1_VFY_CRTRQ_DSASTRU_LOAD_ERR	-2405
#define ASN1_VFY_CERTREQ_DSA_SIGNAT_ERR	-2406

//---------------------------------------------
// ASN1 Certificate/CertReq Builder Returncodes
//---------------------------------------------
#define ASN1_STRUC_TO_CERT_NULPTR_ERR	-2420
#define ASN1_STRUC_TO_CERT_NO_KEY_ERR	-2421

#define ASN1_TO_CREQ_ATTBUF_ALLOC_ERR	-2430
#define ASN1_STRUC_TO_CREQ_NULPTR_ERR	-2431

//--------------------------------------------
// ASN1 RDN Builder Returncodes
//--------------------------------------------
#define ASN1_TO_RDN_STRING_NULLPTR_ERR	-2440
#define ASN1_TO_RDN_STRING_INVLEN_ERR	-2441
#define ASN1_TO_RDN_STRING_ALLOC_ERR	-2442

//---------------------------------------------
// ASN1 Visible String Builder Returncodes
//---------------------------------------------
#define ASN1_TO_VIS_STRING_NULLPTR_ERR	-2450
#define ASN1_TO_VIS_STRING_INVLEN_ERR	-2451
#define ASN1_TO_VIS_STRING_ALLOC_ERR	-2452
#define ASN1_TO_VIS_STRING_DATA_ERR	-2453

//------------------------------------------------------------------------
// ASN1 String Types/Integers/Bit/Bytestr. to Internal Decoder Returncodes
//------------------------------------------------------------------------
#define ASN1_FROM_STRING_NULLPTR_ERR	-2470
#define ASN1_FROM_STRING_INV_TYPE_ERR	-2471
#define ASN1_FROM_STRING_INSUF_DATA_ERR -2472
#define ASN1_FROM_STRING_INV_LEN_ERR	-2473
#define ASN1_FROM_STRING_INV_DATA_ERR	-2474
#define ASN1_FROM_STRING_ALLOC_ERR	-2475

#define ASN1_FROM_INTBOC_NULLPTR_ERR	-2480
#define ASN1_FROM_INTBOC_INV_TYPE_ERR	-2481
#define ASN1_FROM_INTBOC_INSUF_DATA_ERR -2482
#define ASN1_FROM_INTBOC_INV_LEN_ERR	-2483
#define ASN1_FROM_INTBOC_INV_DATA_ERR	-2484
#define ASN1_FROM_INTBOC_ALLOC_ERR	-2485

#define ASN1_FROM_LNUMHEX_NULLPTR_ERR	-2490
#define ASN1_FROM_LNUMHEX_ALLOC_ERR	-2491

#define ASN1_FROM_BYTES_NULLPTR_ERR	-2500
#define ASN1_FROM_BYTES_INV_LEN_ERR	-2501
#define ASN1_FROM_BYTES_ALLOC_ERR	-2502

#define ASN1_GET_RDN_OID_ERR		-2510
#define ASN1_GET_RDN_OID_NO_OID		-2511
#define ASN1_GET_RDN_OID_NOT_FOUND	-2512

#define ASN1_RDN_TO_STR_NULL_PTR_ERR	-2520
#define ASN1_RDN_TO_STR_ALLOC_ERR	-2521
#define ASN1_RDN_TO_STR_INV_ELEM_CNT	-2522
#define ASN1_RDN_TO_STR_NO_SRC_DAT	-2523
#define ASN1_RDN_TO_STR_SRC_ERR		-2524
#define ASN1_RDN_TO_STR_OID_ACCESS_ERR  -2525

#define ASN1_RDN_TO_CNAMESTR_NULPTR_ERR	-2530
#define ASN1_RDN_TO_CNAMESTR_INV_CNT	-2531
#define ASN1_RDN_TO_CNAMESTR_NO_SRC_DAT	-2532
#define ASN1_RDN_TO_CNAMESTR_SRC_ERR	-2533

//-------------------------------------------------
// X509 Subject RDN Common Name checker Returncodes
//-------------------------------------------------
#define	ASN1_CHK_SUBJ_COMNAME_NULPTR	-2540
#define ASN1_CHK_SUBJ_COMNAME_INV_LIST	-2541

//------------------------------------------------------------
// Internal RDN Strings to ASN1 type RDN converter Returncodes
//------------------------------------------------------------
#define ASN1_STR_ARR_TO_RDN_NULL_PTR	-2560
#define ASN1_STR_ARR_TO_RDN_INV_DATA	-2561
#define ASN1_STR_ARR_TO_RDN_NODATA_ERR  -2562

//-------------------------------------------------
// ASN.1 Sequence Wrapper / Unwrapper Returncodes
//-------------------------------------------------

#define	ASN1_SEQ_UNWRAP_ALLOC_ERR	-2570
#define	ASN1_SEQ_UNWRAP_ERR		-2571
#define	ASN1_SEQ_WRAP_ALLOC_ERR		-2572
#define	ASN1_SEQ_WRAP_ERR		-2573

//--------------------------------------------------------------
// From ASN1 Time Strings to internal and vice versa Returncodes
//--------------------------------------------------------------
#define ASN1_GET_CHK_LCL_INV_CURR_TIME	-2580
#define ASN1_GET_CHK_LCL_INV_UTC_TIME	-2581

#define ASN1_FROM_TIMESTR_NULLPTR_ERR	-2590
#define ASN1_FROM_TIMESTR_DATA_MISSING  -2591
#define ASN1_FROM_TIMESTR_INV_LEN	-2592
#define ASN1_FROM_TIMESTR_INV_TYPE	-2593
#define ASN1_FROM_TIMESTR_ALLOC_ERR	-2594
#define ASN1_FROM_TIMESTR_DECODE_ERR	-2595

#define ASN1_GEN_TIMESTR_BUF_TOO_SMALL	-2600
#define ASN1_GEN_TIMESTR_INV_UTC_TIME	-2601

#define TO_ASN1_TIME_STRING_NULLPTR_ERR	-2610
#define TO_ASN1_TIME_STRING_TIMETYP_ERR -2620

//------------------------------------------------------------------------
// Known ASN1 OBJID to internal String Returncodes, new converter
//------------------------------------------------------------------------
#define ASN1_OID_TO_INTSTR_INVALID_OID	-2630

//#define ASN1_OID_IND_TO_NAME_INV_LANG	-2631

//#define ASN1_RDN_OIDNAME_TO_STR_NULLPT	-2640
//#define ASN1_RDN_OIDNAME_TO_STR_ALLOCF	-2641

//------------------------------------------------
// Certificate List Allocation/Builder Returncodes
//------------------------------------------------
#define ASN1_CERTLIST_ALLOC_NULL_PTR	-2660
#define ASN1_CERTLIST_ALLOC_ERR		-2661

#define ASN1_CERTLIST_NULL_PTR		-2670
#define ASN1_CERTLIST_NO_CERTS		-2671

//----------------------------------------------
// Certificate Tree Generate Returncodes
//----------------------------------------------
#define ASN1_GEN_CERT_TREE_NULL_PTR	-2690
#define ASN1_GEN_CERT_TREE_PARAM_ERR	-2691
#define ASN1_GEN_CERT_TREE_ALLOC_ERR	-2692
#define ASN1_GEN_CERT_TREE_INV_ALGOR	-2693
#define ASN1_GEN_CERT_TREE_NO_ROOTS_ERR	-2694
#define ASN1_GEN_CERT_TREE_MATCH_ERR	-2695
#define ASN1_GEN_CERT_TREE_NO_END_CERTS	-2696

//------------------------------------------------
// IBM Container Password Substitution Returncodes
//------------------------------------------------
#define	ASN1_REENC_PRIVKEY_NULPTR_ERR	-2710
#define	ASN1_REENC_PRIVKEY_NO_DATA_ERR	-2711
#define ASN1_REENC_PRIVKEY_NO_PRIVKEY	-2712
#define	ASN1_REENC_PRIVKEY_DECRYPT_ERR	-2713
#define ASN1_REENC_PRIVKEY_ENCRYPT_ERR	-2714

//-------------------------------------------------
// ASN1 PKCS7 Certificate List Splitter Returncodes
//-------------------------------------------------
#define ASN1_PKCS7_CERT_LIST_NULL_PTR	-2730
#define ASN1_PKCS7_CERT_LIST_ALLOC_ERR	-2731
#define ASN1_PKCS7_CERT_LIST_TO_INT_ERR	-2732
#define ASN1_PKCS7_CERT_LIST_VERS_ERR	-2733
#define ASN1_PKCS7_CERT_LIST_FMT_ERR	-2734
#define ASN1_PKCS7_CERT_LIST_SPLIT_ERR	-2735
#define ASN1_PKCS7_CERT_CONV_ERR	-2736

#define ASN1_PKCS7_CERTBUF_ALLOC_ERR	-2740

#define ASN1_PKCS7_INT_TO_CERTLST_NULLP	-2750
#define ASN1_PKCS7_INT_TO_CERTLST_EMPTY	-2751
#define ASN1_PKCS7_INT_TO_CERTLST_ERR	-2752

//-------------------------------------------------------
// Certificate Info List Structure Allocation Returncodes
//-------------------------------------------------------
#define	ASN1_CERTPARR_ALLOC_NULL_PTR	-2760
#define	ASN1_CERTPARR_ALLOC_PARAM_ERR	-2761
#define	ASN1_CERTPARR_ALLOC_ALLOC_ERR	-2762

#define ASN1_GEN_CERTTREE_INFO_NULL_PTR	-2770
#define ASN1_GEN_CERTTREE_INFO_NO_CERTS	-2771
#define ASN1_GEN_CERTTREE_INFO_ALLOC_ER	-2772

//-------------------------------------------------------
// Certificate Verification Returncodes
//-------------------------------------------------------
#define	ASN1_CERT_VFY_NULLPTR_ERR	-2780

//-------------------------------------------------------
// Certificate List Verification Returncodes
//-------------------------------------------------------
#define	ASN1_CERT_LIST_VFY_NULLPTR_ERR	-2790
#define ASN1_CERT_LIST_VFY_NO_CERTS	-2791

//-------------------------------------------------------
// Certificate List Insertion processing Returncodes
//-------------------------------------------------------
#define	ASN1_INSERT_LIST_NULLPTR_ERR	-2800
#define	ASN1_INSERT_LIST_NO_CERTS	-2801
#define	ASN1_INSERT_LIST_ALLOC_ERR	-2802

//-------------------------------------------------------
// Certificate Tree Verification processing Returncodes
//-------------------------------------------------------
#define ASN1_TREE_VERIFY_NULLPTR_ERR	-2810
#define ASN1_TREE_VERIFY_NO_ROOTS	-2811
#define ASN1_TREE_VERIFY_ALLOC_ERR	-2812

//-------------------------------------------------------
// Certificate Structure Copy Routine Returncodes
//-------------------------------------------------------
#define ASN1_CERT_COPY_NULPT_ERR	-2820
#define	ASN1_CERT_COPY_TIMESTR_ALLOC_ER -2821

//-------------------------------------------------------
// Certificate Extension Processing routines
//-------------------------------------------------------

#define	ASN1_GET_BOOLEAN_NOT_PRESENT	-2830
#define	ASN1_GET_BOOLEAN_INVALID_SIZE	-2831

#define	ASN1_GET_BITSTR_BITS_INVAL_SIZE	-2836
#define	ASN1_GET_BITSTR_BITS_INVAL_FMT	-2837
#define	ASN1_GET_BITSTR_BITS_TOO_MANY	-2838

#define	ASN1_GET_SHORTINT_NOT_PRESENT	-2840

#define	ASN1_GET_EXT_OID_NO_OID		-2850

#define	ASN1_SPLIT_X509_EXT_DATA_ERR	-2855

#define	ASN1_X509_EXT_ALTN_NULLPT_ERR	-2857
#define	ASN1_X509_EXT_ALTN_UNDEF_VALS	-2858
#define	ASN1_X509_EXT_ALTN_TOOLESSITM	-2859

//-------------------------------------------------------
// CRL Processing routines
//-------------------------------------------------------

#define	ASN1_SIGN_TBS_INVALID_SIG_ALG	-2860
#define	ASN1_SIGN_TBS_INVALID_KEYTYPE	-2861

#define	ASN1_FROM_TBS_CRL_INVAL_VERSNUM	-2865
#define	ASN1_FROM_TBS_CRL_UNKOWN_VERS	-2866

#define	ASN1_FROM_CRL_SIGALGOR_MISMATCH	-2870
#define	ASN1_FROM_CRL_INVAL_REV_REASON	-2871

#define	ASN1_MATCH_HASH_NO_CERT_PUBKEY	-2875

#define	ASN1_TO_AUTH_KEYID_NO_PUBKEY	-2877
#define	ASN1_TO_AUTH_KEYID_NO_SUBJNAME	-2878
#define	ASN1_TO_AUTH_KEYID_NO_SERIALNR	-2879

//--------------------------------------------------------
// Specific matching results
//--------------------------------------------------------

#define ASN1_SIGNAT_VFY_OK		0
#define	ASN1_SIGNAT_ALGOR_MISMATCH	1
#define	ASN1_SIGNAT_PARAMS_MISSING	2
#define	ASN1_SIGNAT_UNKNOWN_ALGOR	3
#define ASN1_SIGNAT_VERIFY_FAILED	4

#define ASN1_NOT_TRUSTED_ROOT		0
#define ASN1_TRUSTED_ROOT		1

#define	ASN1_END_CERT_MATCH		0
#define ASN1_END_CERT_ALGORS_MISMATCH	-1
#define ASN1_END_CERT_PARAMS_MISMATCH	-2
#define ASN1_END_CERT_CA_ROOT_MISMATCH	-3

//------------------------------------------------------------
// Time Validity checking per Certificate Status results,
// value coded, 0x00: o.k.
// Status Bits 3-0
//------------------------------------------------------------

#define	ASN1_CSTAT_MISFORMED_VALIDITY	0x0001	// NotBefore > NotAfter
#define	ASN1_CSTAT_MISMATCHED_VALIDITY	0x0002	// not within signers range
#define	ASN1_CSTAT_NOT_YET_VALID	0x0003	// not yet valid
#define	ASN1_CSTAT_HAS_EXPIRED		0x0004	// has expired

#define	ASN1_CSTAT_TIME_VALIDITY_MASK	0x000F	// 4 Bits (1 reserved)

//-------------------------------------------------------------
// Issuer/Subject match checking per Certificate Status results,
// value coded, 0x00: o.k.
// Status Bits 7-4
//-------------------------------------------------------------

#define	ASN1_CSTAT_ISSUER_UNKNOWN	0x0010	// first not selfsigned
#define	ASN1_CSTAT_SELFSIGNED_NOT_ROOT	0x0020	// not at start of a chain
#define	ASN1_CSTAT_ISSUER_SUBJ_MISMATCH	0x0030	// issuer does not match subj.
#define	ASN1_CSTAT_ISSUER_SUBJ_MASK	0x00F0	// 4 Bits (2 res.)

//--------------------------------------------------------------------
// Basic Constraints checking per certificate Status results,
// bitcoded, cumulative, 0x00: o.k.
// Status Bits 11-8
//--------------------------------------------------------------------

#define	ASN1_CSTAT_BCSTR_CA_NOT_ALLOWED	0x0100	// issuer that may not act as CA
#define	ASN1_CSTAT_BCSTR_PATHLEN_EXCEED	0x0200	// distance exceeded
#define	ASN1_CSTAT_BCSTR_MASK		0x0F00	// 4 Bits (2 res.)

//--------------------------------------------------------------------
// Signature / Key Usage checking per certificate Status results,
// bitcoded, cumulative, 0x00: o.k.
// Status Bits 19-12
//--------------------------------------------------------------------

#define	ASN1_CSTAT_SIGN_FIRST_UNCHECKED	0x01000	// starts not with a root
#define	ASN1_CSTAT_SIGN_PARAMS_MISSING	0x02000	// Parameters missing
#define	ASN1_CSTAT_SIGN_ALGOR_MISMATCH	0x04000	// Key/Algorithm mismatch
#define	ASN1_CSTAT_SIGN_INVALID		0x08000	// Invalid signature
#define	ASN1_CSTAT_SIGN_INV_KEYUSAGE	0x10000	// Key usage not allowed
#define	ASN1_CSTAT_SIGN_MASK		0x0FF000 // 8 Bits (3 res.)

//------------------------------------------------------------
// Mask for 'Good' Status, Bits 19-0
//------------------------------------------------------------

#define	ASN1_CSTAT_GOOD_MASK		0x0FFFFF  // normal status bits/codes

//------------------------------------------------------------
// Additional Time Validity descriptor bits
// Status Bits: 31-24
//------------------------------------------------------------

#define	ASN1_CSTAT_NBEF_IN_RANGE_BIT	0x01000000 // NotBef. in signer's range
#define	ASN1_CSTAT_NAFT_IN_RANGE_BIT	0x02000000 // NotAft. in signer's range
#define	ASN1_CSTAT_NBEF_IS_VALID_BIT	0x04000000 // NotBef. <= CurrTime
#define	ASN1_CSTAT_NAFT_IS_VALID_BIT	0x08000000 // NotAft. >= CurrTime
#define	ASN1_CSTAT_NAFT_DELTA_VALID_BIT	0x10000000 // NotAft. >= CurrTime+Delta

#define	ASN1_CSTAT_TIMEFLAGS_MASK      0x0FF000000 //  8 Bits (3 reserved)

#if !defined __HOCSP_ERR_HEADER__
#define	__HOCSP_ERR_HEADER__
/** @addtogroup hocsp
* @{
* @file
* This file contains return codes for the OCSP module.
* @}
*/

#define	HTTP_OP_OK			0
#define	HTTP_NULL_PTR			-1
#define	HTTP_PARAM_ERR			-2
#define	HTTP_ALLOC_ERR			-3

// HTTP URL parser errors

#define	HTTP_URL_PARSE_INVALID		-9600
#define	HTTP_URL_PARSE_EMPTY		-9601
#define	HTTP_URL_PARSE_INVALID_PROTOCOL	-9602
#define	HTTP_URL_PARSE_NO_AUTHORITY	-9603
#define	HTTP_URL_PARSE_NO_SERVER	-9604
#define	HTTP_URL_PARSE_PORT_CONV_FAILED	-9605

// HTTP URL Connection object errors
#define	HTTP_URL_CONN_FAILED		-9606
#define	HTTP_URL_CONN_INVALID_TYPE	-9607

// HTTP Response header parse errors

#define	HTTP_HDR_PARSE_CONN_CLOSED	-9609
#define	HTTP_HDR_PARSE_RX_ERR		-9610
#define	HTTP_HDR_PARSE_RX_TIMED_OUT	-9611
#define	HTTP_HDR_PARSE_NO_STATUS_LINE	-9612
#define	HTTP_HDR_PARSE_INV_STATUS_LINE	-9613
#define	HTTP_HDR_PARSE_NO_RESP_STATUS	-9614

// HTTP connect errors

#define	HTTP_CONNECT_NO_HOST_NAME	-9615
#define	HTTP_CONNECT_INVALID_PORT	-9616
#define	HTTP_CONNECT_GET_ADRINFO_FAILED	-9617
#define	HTTP_CONNECT_RESOLVE_DNS_FAILED	-9618
#define	HTTP_CONNECT_CONNECT_FAILED	-9619

#define	HTTP_ALREADY_CONNECTED		-9620
#define	HTTP_NOT_CONNECTED		-9621

#define	HTTP_SEND_SET_METHOD_FAILED	-9625
#define	HTTP_SEND_REQUEST_HDR_FAILED	-9626
#define	HTTP_SEND_REQUEST_BODY_FAILED	-9627

// HTTP Response errors
#define	HTTP_RESP_SERVER_ERR_STATUS	-9630
#define	HTTP_RESP_NO_SERVER_STATUS	-9631
#define	HTTP_RESP_NOT_OCSP_TYPE		-9632
#define	HTTP_RESP_NO_RESPONSE_DATA	-9633
#define	HTTP_RESP_DATA_READ_FAILED	-9634

#define	HOCSP_OP_OK			0
#define	HOCSP_NULL_PTR			-1
#define	HOCSP_PARAM_ERR			-2
#define	HOCSP_ALLOC_ERR			-3

#define	HOCSP_CERTID_HASHTYPE_UNSUPP	-9640
#define	HOCSP_CERTID_NO_ISSUER_CERT	-9641
#define	HOCSP_CERTID_ISS_SUBJ_MISMATCH	-9642

#define	HOCSP_REQLIST_NO_CERT_IDS	-9644

#define	HOCSP_SIGN_REQ_INVALID_KEYTYPE	-9646
#define	HOCSP_SIGN_REQ_INVALID_SIG_ALG	-9647

#define	HOCSP_SRESP_INVALID_HASH_ALGOR	-9650
#define	HOCSP_SRESP_INVALID_GOOD_STATUS	-9651
#define	HOCSP_SRESP_MULTI_CERT_STATUS	-9652
#define	HOCSP_SRESP_INVALID_REV_REASON	-9653
#define	HOCSP_SRESP_INVALID_UNK_STATUS	-9654
#define	HOCSP_SRESP_MISSING_CERT_STATUS	-9655
#define	HOCSP_SRESP_UNKNOWN_CRIT_EXT	-9656

#define	HOCSP_RESP_INVALID_VERS_NUM	-9660
#define	HOCSP_RESP_UNKNOWN_VERSION_NUM	-9661
#define	HOCSP_RESP_MULTI_RESPONDER_IDS	-9662
#define	HOCSP_RESP_INVALID_KEYHASH_SIZE	-9663
#define	HOCSP_RESP_NO_RESPONDER_ID	-9664
#define	HOCSP_RESP_DUPLICATE_NONCE_EXT	-9665
#define	HOCSP_RESP_UNKNOWN_CRIT_EXT	-9666

#define	HOCSP_RESP_BYTES_NO_TYPE_OID	-9668
#define	HOCSP_RESP_BYTES_UNKNOWN_TYPE	-9669

#define	HOCSP_RESP_NO_STATUS		-9670
#define	HOCSP_RESP_INVALID_STATUS	-9671
#define	HOCSP_RESP_MISSING_RESP_BYTES	-9672

#define	HOCSP_MATCH_HASH_NO_CERT_PUBKEY	-9675

#endif // !defined __HOCSP_ERR_HEADER__

#define HTTP_OP_OK 0
// Server response Status codes

// 1XX: class 'Informational'
#define	HTTP_RSTATUS_CONTINUE		100	// Continue with request
#define	HTTP_RSTATUS_SWITCHING_PROTOS	101	// Switching protocols

// 2XX: class 'Success'
#define	HTTP_RSTATUS_OK			200	// OK.
#define	HTTP_RSTATUS_CREATED		201	// has been created
#define	HTTP_RSTATUS_ACCEPTED		202	// Request accepted
#define	HTTP_RSTATUS_NON_AUTHORITATIVE	203	// ???
#define	HTTP_RSTATUS_NO_CONTENT		204	// no content (message body)
#define	HTTP_RSTATUS_RESET_CONTENT	205	// reset request form
#define	HTTP_RSTATUS_PARTIAL_CONTENT	206	// part of content

// 3XX: class 'Redirection'

#define	HTTP_RSTATUS_MULT_CHOICE	300	// different locations avail.
#define	HTTP_RSTATUS_MOVED_PERMANENT	301	// location has moved
#define	HTTP_RSTATUS_FOUND		302	// ??
#define	HTTP_RSTATUS_SEE_OTHER		303	// ??
#define	HTTP_RSTATUS_NOT_MODIFIED	304	// content has not been modif.
#define	HTTP_RSTATUS_USE_PROXY		305	// should use a proxy
#define	HTTP_RSTATUS_TEMP_REDIRECT	307	// ???

// 4XX: class 'Client error'

#define	HTTP_RSTATUS_BAD_REQUEST	400	// malformed request
#define	HTTP_RSTATUS_UNAUTHORIZED	401	// must send authorization
#define	HTTP_RSTATUS_PAYMENT_REQUIRED	402	// reserved for future
#define	HTTP_RSTATUS_FORBIDDEN		403	// access not allowed
#define	HTTP_RSTATUS_NOT_FOUND		404	// URL not found
#define	HTTP_RSTATUS_BAD_METHOD		405	// Request method for URL n.a.
#define	HTTP_RSTATUS_NOT_ACCEPTABLE	406	// ??
#define	HTTP_RSTATUS_PROXYAUTH_REQUIRED	407	// must authenticate to proxy
#define	HTTP_RSTATUS_REQUEST_TIMEDOUT	408	// timeout
#define	HTTP_RSTATUS_CONFLICT		409	// resource conflict
#define	HTTP_RSTATUS_GONE		410	// resource no longer avail.
#define	HTTP_RSTATUS_LENGTH_REQUIRED	411	// must specify length for Req.
#define	HTTP_RSTATUS_PRECOND_FAILED	412	// ??
#define	HTTP_RSTATUS_REQ_TOO_LARGE	413	// request entity too large
#define	HTTP_RSTATUS_REQ_URI_TOO_LARGE	414	// request URI too large
#define	HTTP_RSTATUS_UNSUPP_MEDIA_TYPE	415	// media type not supported
#define	HTTP_RSTATUS_REQ_RANGE_NOTSAT	416	// range not satisfiable
#define	HTTP_RSTATUS_EXPECTATION_FAILED	417	// ??

// 5XX: class 'Server error'

#define	HTTP_RSTATUS_SERVER_ERROR	500	// internal server error
#define	HTTP_RSTATUS_NOT_IMPLEMENTED	501	// not implemented method
#define	HTTP_RSTATUS_BAD_GATEWAY	502	// invalid response from upstr.
#define	HTTP_RSTATUS_SERVICE_UNAVAIL	503	// temporary overload etc.
#define	HTTP_RSTATUS_GATEWAY_TIMEOUT	504	// timeout at gateway
#define	HTTP_RSTATUS_VERSION_NOT_SUPP	505	// version is not supported
//-------------------------------------------------------------
// Global valid return Codes
//-------------------------------------------------------------
/** @addtogroup hssl
* @{
* @file
* This header contains error codes used in the SSL protocol module.
* @}
*/

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
//HSSL_SRVR_KEYEXC_DH_PARAM_INSECURE   really defined below!

//---------------------------------------------------
// Certificate Verify Message processing return codes
//---------------------------------------------------
#define HSSL_CERTVFY_INVALID_MSGLEN		-250
#define HSSL_CERTVFY_SIGBUF_ALLOC_ERR		-251
#define HSSL_CERTVFY_SIGNAT_RSADEC_ERR		-252
#define HSSL_CERTVFY_SIGNATURE_INVALID		-253
#define HSSL_CERTVFY_INV_SIGNAT_ALGOR		-254
#define HSSL_SRVR_KEYEXC_DH_PARAM_INSECURE   -255     // Only here to keep it in numerical order

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

#define	PKCS12_OP_OK		0
#define	PKCS12_NULL_PTR		-1
#define	PKCS12_PARAM_ERR	-2
#define	PKCS12_ALLOC_ERR	-3

#define	PKCS12_UNSUPP_EMBEDDED_TYPE	-5800
#define	PKCS12_UNIVERSAL_UNWRAP_NO_DATA	-5801

#define	PKCS12_PFX_PDU_TO_INT_ERR	-5805
#define	PKCS12_PFX_PDU_FROM_INT_ERR	-5806
#define	PKCS12_PFX_PFX_TO_INT_ERR	-5807
#define	PKCS12_PFX_PFX_FROM_INT_ERR	-5808

#define	PKCS12_AUTHSAFE_TO_INT_ERROR	-5810
#define	PKCS12_AUTHSAFE_FROM_INT_ERROR	-5811
#define	PFX_AUTHSAFE_TO_INT_ERR		-5812
#define	PFX_AUTHSAFE_FROM_INT_ERR	-5813
#define	PFX_BAGGAGE_TO_INT_ERROR	-5814
#define	PFX_BAGGAGE_FROM_INT_ERROR	-5815
#define	PFX_ESPVK_TO_INT_ERROR		-5816
#define	PFX_ESPVK_FROM_INT_ERROR	-5817
#define	PKCS12_SAFECONTS_TO_INT_ERROR	-5818
#define	PKCS12_SAFECONTS_FROM_INT_ERROR	-5819
#define	PFX_SAFECONTS_TO_INT_ERROR	-5820
#define	PFX_SAFECONTS_FROM_INT_ERROR	-5821
#define	PFX_SAFEBAG_FROM_INT_ERROR	-5822
#define	PKCS12_SHRBAG_TO_INT_ERR	-5823
#define	PKCS12_SHRBAG_FROM_INT_ERR	-5824
#define	PKCS12_CERTBAG_TO_INT_ERR	-5825
#define	PKCS12_CERTBAG_FROM_INT_ERR	-5826
#define	PFX_CERTCRLS_TO_INT_ERROR	-5827
#define	PFX_CERTCRLS_FROM_INT_ERROR	-5828
#define	PFX_X509_CERTCRL_TO_INT_ERR	-5829
#define	PFX_X509_CERTCRL_FROM_INT_ERR	-5830
#define	PFX_CERTLIST_TO_INT_ERROR	-5831
#define	PFX_CERTLIST_FROM_INT_ERROR	-5832

#define	PKCS12_INTEGER_TO_INT_ERR	-5835
#define	PKCS12_INTEGER_FROM_INT_ERR	-5836
#define	PKCS12_OCTETSTR_TO_INT_ERR	-5837
#define	PKCS12_SET_TO_INT_ERR		-5838
#define	PKCS12_SET_OF_TO_INT_ERR	-5839
#define	PKCS12_SEQUENCE_TO_INT_ERR	-5840
#define	PKCS12_SEQUENCE_OF_TO_INT_ERR	-5841
#define	PKCS12_ANY_ASN1_TO_INT_ERROR	-5842
#define	PKCS12_ANY_ASN1_FROM_INT_ERROR	-5843
#define	PKCS12_ANY_OF_ASN1_TO_INT_ERROR	-5844
#define	PKCS12_BMPSTR_FROM_INT_ERR	-5845

#define	PKCS1_PRIVKEY_TO_INT_ERR	-5850
#define	PKCS1_PRIVKEY_FROM_INT_ERR	-5851
#define	X957_ALGPARS_TO_INT_ERR		-5852
#define	X957_ALGPARS_FROM_INT_ERR	-5853
#define	X957_PRIVVAL_FROM_INT_ERR	-5854
#define	X501_AVA_TO_INT_ERROR		-5855
#define	X501_AVA_FROM_INT_ERROR		-5856
#define	X501_ATTVAL_TO_INT_ERROR	-5857

#define	PKCS8_PRIVKEYINFO_TO_INT_ERR	-5860
#define	PKCS8_PRIVKEYINFO_FROM_INT_ERR	-5861
#define	PKCS8_PRIVKEYINFO_UNKNOWN_VERS	-5862

#define	PKCS9_OCTETSTR_TO_INT_ERR	-5865
#define	PKCS9_OCTETSTR_FROM_INT_ERR	-5866
#define	PKCS9_BMPSTR_TO_INT_ERR		-5867
#define	PKCS9_BMPSTR_FROM_INT_ERR	-5868	

#define	PKCS12_PBEPARS_TO_INT_ERR	-5870
#define	PKCS12_PBEPARS_FROM_INT_ERR	-5871

#define	PKCS7_ENCDATA_TO_INT_ERR	-5875
#define	PKCS7_ENCDATA_FROM_INT_ERR	-5876
#define	PKCS7_DIGESTINFO_TO_INT_ERR	-5877
#define	PKCS7_DIGESTINFO_FROM_INT_ERR	-5878
#define	PKCS7_CONTINFO_FROM_INT_ERR	-5879
#define	PKCS12_SAFEBAG_FROM_INT_ERR	-5880
#define	PKCS12_UNSUPP_SAFECONTENT_TYPE	-5881
#define	PKCS12_UNSUPP_SAFEBAG_TYPE	-5882
#define	PKCS12_CERTBAG_UNSUPP_CERT_TYPE	-5883

#define	PKCS2_INVALID_DIGEST_ALGOR	-5885
#define	PKCS2_UNKNOWN_DIGEST_ALGOR	-5886
#define	PKCS12_INVALID_SIGNAT_ALGOR	-5887
#define	PKCS12_UNKNOWN_SIGNAT_ALGOR	-5888
#define	PKCS12_INVALID_OIW_ALGOR	-5889
#define	PKCS12_UNKNOWN_OIW_ALGOR	-5890
#define	PKCS9_INVALID_ATT_TYPE		-5891
#define	PKCS9_UNKNOWN_ATT_TYPE		-5892

#define	PKCS12_GET_BITS_INVALID_SIZE	-5895
#define	PKCS12_GET_BITS_TOO_MANY 	-5896
#define	PKCS12_GET_BITS_INVALID_FORMAT	-5897

#define	PKCS12_NO_SAFE_CONTENT_ITEMS	-5900
#define	PKCS12_INVALID_CONTENT_TYPE	-5901
#define	PKCS12_UNKNOWN_CONTENT_TYPE	-5902
#define	PKCS12_INVALID_BAG_TYPE		-5903
#define	PKCS12_UNKNOWN_BAG_TYPE		-5904
#define	PFX_INVALID_BAG_TYPE		-5905
#define	PFX_UNKNOWN_BAG_TYPE		-5906
#define	PKCS12_INVALID_CERT_TYPE	-5907
#define	PKCS12_UNKNOWN_CERT_TYPE	-5908
#define	PKCS12_INVALID_CRL_TYPE		-5909
#define	PKCS12_UNKNOWN_CRL_TYPE		-5910
#define	PFX_INVALID_CERTCRL_TYPE	-5911
#define	PFX_UNKNOWN_CERTCRL_TYPE	-5912

#define	PKCS12_INVALID_RSA_ALGOR	-5915
#define	PKCS12_UNKNOWN_RSA_ALGOR	-5916
#define	PKCS12_INVALID_DSA_ALGOR	-5917
#define	PKCS12_UNKNOWN_DSA_ALGOR	-5918

#define	PFX_INVALID_TRANSP_MODE_TYPE	-5920
#define	PFX_UNKNOWN_TRANSP_MODE_TYPE	-5921
#define	PFX_INVALID_ESPVK_TYPE		-5922
#define	PFX_UNKNOWN_ESPVK_TYPE		-5923

#define	PKCS12_INVALID_PRIVKEY_ALGOR	-5925
#define	PKCS12_UNKNOWN_PRIVKEY_ALGOR	-5926
#define	PKCS12_INVALID_PRIVBAG_ALGOR	-5927

#define	PKCS12_INVALID_PBE_ALGOR	-5930
#define	PKCS12_UNKNOWN_PBE_ALGOR	-5931
#define	PFX_INVALID_PBE_ALGOR		-5932
#define	PFX_UNKNOWN_PBE_ALGOR		-5933
#define	PFX_INVALID_PRIVBAG_ALGOR_ID	-5934
#define	PFX_INVALID_CERTBAG_ALGOR_ID	-5935
#define	PKCS12_INVALID_X509_EXT_ATT_ID	-5936
#define	PKCS12_UNKNOWN_X509_EXT_ATT_ID	-5937

#define	PKCS12_NO_SAFECONTENT_DATA	-5940

#define	PKCS12_ENCR_INV_DSTLEN		-5945
#define	PKCS12_DECR_INV_SRCLEN		-5946
#define	PKCS12_INIT_AES_CIPH_TABLE_ERR	-5947
#define	PKCS12_DECRYPT_INVALID_PADDING	-5948

#define	PKCS12_HMAC_DST_BUF_TOO_SMALL	-5950
#define	PKCS12_HMAC_GEN_FAILED		-5951
#define	PKCS12_HMAC_VFY_INVALID_MACLEN	-5952
#define	PKCS12_HMAC_VFY_FAILED		-5953

#define	PFX_TOO_MANY_THUMBPRINTS	-5955
#define	PFX_UNKNOWN_THUMBPRINT_ALGPARS	-5956
#define	PFX_NO_BAGGAGE_ITEMS		-5957
#define	PFX_TOO_MANY_BAGGAGE_ITEMS	-5958
#define	PFX_BAGITEM_TOO_MANY_ESPVKS	-5959
#define	PFX_UNSUPP_SAFEBAG_TYPE		-5960
#define	PFX_UNSUPPORTED_CERTCRL_TYPE	-5961
#define	PFX_TOO_MANY_CERTCRLS		-5962
#define	PFX_NO_BAGS			-5963
#define	PFX_TOO_MANY_BAGS		-5964
#define	PFX_GEN_CERTNAME_INV_BAGTYPE	-5965

#define	PKCS12_KEYMATCH_NO_PRIVKEYS	-5970
#define	PKCS12_KEYMATCH_NO_CERTS	-5971
#define	PKCS12_KEYMATCH_NO_PRIVKEYID	-5972
#define	PKCS12_KEYMATCH_DUPL_CERTS	-5973
#define	PKCS12_KEYMATCH_DUPL_PRIVKEYID	-5974
#define	PKCS12_KEYMATCH_NO_CERT_FOR_KEY	-5975

#define	PKCS12_TOCERT_PRIV_ALG_MISMATCH	-5980
#define	PKCS12_TOCERT_NO_PRIV_PARAMS	-5981
#define	PKCS12_TOCERT_PUB_PAR_MISMATCH	-5982
#define	PKCS12_TOCERT_UNSUPP_PRIV_ALGOR	-5983

#define	PKCS12_TO_CERTLIST_NO_CERTS	-5985
#define	PKCS12_TO_CERTLIST_NO_PRIVKEY	-5986

#define	PKCS12_UNRECOGNIZED_PDU_ERR	-5990

#define	PKCS12_TO_CERTBAG_UNSUP_PRIVALG	-5992
#define	PKCS12_INVALID_CERT_PRIV_ALGOR	-5993

#define	PKCS12_RSA_VFY_INV_BUFLEN	-5995
#define	PKCS12_RSA_VFY_FAIL		-5996
#define	PKCS12_DSA_VFY_INV_BUFLEN	-5997

//-----------------------------------------------------------------------------
// BASE64
//-----------------------------------------------------------------------------
//=================================================
// Global Returncodes BASE64
//=================================================
#define	BASE64_OP_OK			 0
#define BASE64_NULL_PTR			-1	// normally internal Error !!

//-------------------------------------------------
// RFC822 Line Unfolder Returncodes
//-------------------------------------------------
#define RFC822_HDRLINE_GET_TOO_FEW_DATA -900
#define RFC822_HDRLINE_GET_ALLOC_ERR	-901

#define GET_COMPACTED_TXTLINE_ALLOC_ERR	-902

//-------------------------------------------------
// Base64 Coder/Decoder Returncodes
//-------------------------------------------------
#define FROM_BASE64_PARAM_ERR		-910
#define FROM_BASE64_START_NOT_FOUND	-911
#define FROM_BASE64_INVALID_END		-912

#define FROM_BASE64_INVALID_DATALEN	-913
#define FROM_BASE64_CHAR_ERR		-914
#define FROM_BASE64_PAD_ERR		-915

#define TO_BASE64_PARAM_ERR		-920
#define TO_BASE64_ALLOC_ERR		-921

//-------------------------------------------------
// SMime Decoder Returncodes
//-------------------------------------------------
#define FROM_SMIME_BOUNDARYBUF_ALLOC_ER -930
#define FROM_MIME_NO_MIME_FILE		-931
#define FROM_MIME_FMT_ERROR		-932
#define FROM_MIME_NO_DATA		-933

//-------------------------------------------------
// PEM Coder/Decoder Returncodes
//-------------------------------------------------
#define PEM_DECODE_START_NOT_FOUND	-940
#define PEM_DECODE_TOO_FEW_DATA		-941
#define PEM_DECODE_ALLOC_ERR		-942
#define PEM_DECODE_FMT_ERR		-943
#define PEM_DECODE_NO_ISSUER_ERR	-944
#define PEM_DECODE_END_NOT_FOUND	-945

#define PEM_ENCODE_NULL_PTR		-950
#define PEM_ENCODE_PARAM_ERR		-951
#define PEM_ENCODE_ALLOC_ERR		-952

#define FROM_PEM_CRQ_TO_STRUC_NULPTR	-960
#define FROM_PEM_CRQ_TO_STRUC_NO_DATA	-961
#define FROM_PEM_CRQ_INVALID_ORIG_CERT	-962
#define FROM_PEM_CRQ_INVALID_SIGNAT	-963
#define FROM_PEM_CRQ_INVALID_SIGNAT_ALG	-964
#define FROM_PEM_CRQ_MIC_SIGNAT_ERR	-965

#define TO_PEM_CRQ_INVALID_ALGOR	-970
#define TO_PEM_CRQ_NO_PRIV_KEY		-971
#define TO_PEM_CRQ_ALLOC_ERR		-972

#define FROM_PEM_CERTS_TO_STRUC_NO_DATA	-980
#define FROM_PEM_CERTS_INVALID_PUB_ALG	-981
#define FROM_PEM_CERTS_INVALID_SIGALG	-982
#define FROM_PEM_CERTS_MIC_SIGNAT_ERR	-983

#define TO_PEM_CERTS_INV_SIG_TYPEALG	-990
#define TO_PEM_CERTS_TOO_FEW_CERTS	-991
#define TO_PEM_CERTS_ORIG_INV_PUB_ALG	-992

//-------------------------------------------------
// Universal Decoder/Encoder Returncodes
//-------------------------------------------------

#define FROM_CERTS_CERTREQ_PARAM_ERR	-1000

#define TO_CERTS_CERTREQ_NO_DATA_ERR	-1010
#define TO_CERTS_CERTREQ_ALLOC_ERR	-1011
#define TO_CERTS_CERTREQ_INV_DATA_FMT	-1012
#define TO_CERTS_CERTREQ_PARAM_ERR	-1013

#define	TO_PEM_OPSSL_RSA_PRIVKEY_ERR	-1015
#define	TO_PEM_OPSSL_DSA_PRIVKEY_ERR	-1016

#endif // !__HOB_CERT_ERR__
