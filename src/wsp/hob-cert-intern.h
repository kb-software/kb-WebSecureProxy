#ifndef __HOB_CERT_INTERN__
#define __HOB_CERT_INTERN__
// Required headers: winsock.h, hob-encry-1.h, hob-cert-err.h, string.h
#ifdef _WIN32
#pragma once
#endif

/**
This header contains the internals of the HOBLink Secure 3 Certificate Module
*/

#ifndef __DEF_CLEAR_BIT_8__
#define __DEF_CLEAR_BIT_8__
/**
* Clears a BIT8 array (ClearBit8Array).
*
*  @param pArr Buffer base
*  @param Offset Start of data
*  @param Size Number of elements
*/
inline void ClearBit8Array(char* pArr, int Offset, int Size)
{
   if(Size > 0)
   {
      memset(pArr + Offset, 0, Size * sizeof(char));
   }  
}

#endif // !__DEF_CLEAR_BIT_8__

// from word to bytes

#define BIGword2char(w,c,i)  c[i+1] = (unsigned char) (w        & (unsigned char) 0xFF);\
                             c[i]   = (unsigned char) ((w >> 8) & (unsigned char) 0xFF);\
                             i += 2;

#define BIGchar2word(c,w,i) \
  {\
    w = ((int) (((int) c[i] & 0xFF)  << 8)) | \
        ((int) c[i+1] & 0xFF);\
        i +=2; \
  }

#define BIGchar2wordn(c,w,i) \
  {\
    w = ((int) (((int) c[i] & 0xFF)  << 8)) | \
        ((int) c[i+1] & 0xFF);\
  }

#define BIGchar2long(c,l,i) \
  {\
    l = ((int)  ((short) c[i+3] & (short) 0xFF)         & (int) 0xFFFF) | \
        ((int) (((short) c[i+2] & (short) 0xFF)  <<  8) & (int) 0xFFFF) | \
        ((int)  ((short) c[i+1] & (short) 0xFF)  << 16) | \
        ((int) (((short) c[i]   & (short) 0xFF)  <<  8) << 16); \
   i +=4;  \
  }

//-----------------------------------------------------------------------------
// PKCS5
//-----------------------------------------------------------------------------

#define	PKCS5_ALGOR_HDR_LEN	18			// Length
#define PKCS5_ALGOR_HDR_OFF	12			// Offset to Hash Type
#define PKCS5_ALGOR_OBJID_LEN	10			//without last value

//-----------------------------------------------------------------------------
// ASN1 basic defines
//-----------------------------------------------------------------------------

//=========================================================
// ASN1 Type Bitmasks : Class/Constructed/Universal
//=========================================================

#define	ASN1_CLASS_MASK			0xC0		// isolates bits 7,6
#define	ASN1_CLASS_UNIVERSAL		0x00		// Bit 7,6 = 00
#define	ASN1_CLASS_APPLICATION		0x40		// Bit 7,6 = 01
#define	ASN1_CLASS_CONTEXT_SPECIFIC	0x80		// Bit 7,6 = 10
#define	ASN1_CLASS_PRIVATE		0xC0		// Bit 7,6 = 11

#define	ASN1_CONSTRUCTED_MASK		0x20		// isolates bit 5
#define	ASN1_CONSTRUCTED		0x20		// Bit 5 = 1

#define	ASN1_UNIVERSAL_TYPE_MASK	0x1F		// isolates bits 4-0

//=========================================================
// ASN1 Universal types (not all defined, only required ones)
//=========================================================

#define	ASN1_UNIVERSAL_EOC		0		// End of context
#define	ASN1_UNIVERSAL_BOOLEAN		1		// Boolean
#define	ASN1_UNIVERSAL_INTEGER		2		// Integer
#define	ASN1_UNIVERSAL_BITSTRING	3		// Bitstring
#define	ASN1_UNIVERSAL_OCTETSTRING	4		// Octetstring
#define	ASN1_UNIVERSAL_NULL		5		// Null
#define	ASN1_UNIVERSAL_OBJECT_ID	6		// Object Identifier

#define	ASN1_UNIVERSAL_EXTERNAL		8		// External type (N/A)
#define	ASN1_UNIVERSAL_REAL		9		// Real type (N/A)
#define	ASN1_UNIVERSAL_ENUMERATED	10		// Enumerated type(N/A)
#define	ASN1_UNIVERSAL_EMBEDDEDPDV	11		// Embedded PDV (N/A)
#define	ASN1_UNIVERSAL_UTF8STR		12		// RFC 2044

#define	ASN1_UNIVERSAL_SEQUENCE		16		// Sequence (of)
#define	ASN1_UNIVERSAL_SET		17		// Set (of)

#define	ASN1_UNIVERSAL_NUMERICSTR	18		// Numeric string
#define	ASN1_UNIVERSAL_PRINTABLESTR	19		// Printable string
#define	ASN1_UNIVERSAL_TELETEXSTR	20		// TeleText/T61 str.
#define	ASN1_UNIVERSAL_VIDEOTEXSTR	21		// VideoText string
#define	ASN1_UNIVERSAL_IA5STR		22		// Int. Alphabet 5 str.
#define	ASN1_UNIVERSAL_UTC_TIMESTR	23		// UTC-Time string
#define	ASN1_UNIVERSAL_GEN_TIMESTR	24		// Generalized Time str
#define	ASN1_UNIVERSAL_GRAPHICSTR	25		// Graphic string
#define	ASN1_UNIVERSAL_VISIBLESTR	26		// Visible/ISO646 str.
#define	ASN1_UNIVERSAL_GENERALSTR	27		// Generalized/BMP str.
#define	ASN1_UNIVERSAL_UNIVSTR		28		// Universal str.
#define	ASN1_UNIVERSAL_CHARSTR		29		// unrestricted ch. str
#define	ASN1_UNIVERSAL_BMPSTR		30		// BMP string

#define	ASN1_UNIVERSAL_UTCTIME		23		// UTC Time, alias
#define	ASN1_UNIVERSAL_GENERAL_TIME	24		// General Time, alias

#define	ASN1_UNIVERSAL_CONTINUATION	31		// more data present

#define ASN1_RESERVED_OR_ANY		0xFF		// internal used

//----------------------------------------------------------
// local definitions
//----------------------------------------------------------

#define	ASN1_ID_UNIVERSAL		0
#define	ASN1_ID_APPLICATION		1
#define	ASN1_ID_CONTEXT_SPECIFIC	2
#define	ASN1_ID_PRIVATE			3

#define	ASN1_ID_PRIMITIVE		0
#define	ASN1_ID_CONSTRUCTED		1

//---------------------------------------------------------
// Maximum counts
//---------------------------------------------------------

#define	ASN1_MAX_OBJID_COMPONENTS	16

//--------------------------------------------------------
// OBJ-ID Roots / First leaves
//--------------------------------------------------------

#define	OBJ_ROOT_MULTIPLIER	40
#define	ITU_T_ROOT		0
#define	ISO_ROOT		1
#define	JOINT_ISO_ITU_T_ROOT	2

//--------------------------------------------------------
// Comparison Rules
//--------------------------------------------------------

#define ASN1_MATCH_RULE_UNKNOWN		0
#define	ASN1_MATCH_RULE_BOOLEAN		1
#define	ASN1_MATCH_RULE_INTEGER		2
#define	ASN1_MATCH_RULE_BITSTRING	3
#define	ASN1_MATCH_RULE_OCTETSTRING	4
#define	ASN1_MATCH_RULE_NULL		5
#define ASN1_MATCH_RULE_NUMERICSTRING	6
#define	ASN1_MATCH_RULE_OBJECTID	7
#define	ASN1_MATCH_RULE_UTC		8
#define	ASN1_MATCH_RULE_GENERAL_TIME	9

//--------------------------------------------------------
// Comparison Codes
//--------------------------------------------------------

#define	ASN1_1ST_GT_2ND			1
#define	ASN1_1ST_EQ_2ND			0
#define	ASN1_1ST_LT_2ND			-1

#define ASN1_SAME			0
#define ASN1_NOT_SAME			1
#define ASN1_CONTENT_SAME		2
#define ASN1_PARTIALLY_SAME		3

#define ASN1_SAME_STRINGS		0
#define ASN1_NOT_SAME_STRINGS		1

//-----------------------------------------------------------------------------
// ASN1 control tables
//-----------------------------------------------------------------------------

#if defined _WIN32
#if defined OPTIONAL
#undef OPTIONAL
#endif
#endif

//================================================================
// Global definitions for ASN1 control entries
//================================================================

#define	X_FIRST		0x01		// first in x-node list
#define X_LAST		0x02		// last  in x-node list
#define X_ONLY		0x03		// first and last
#define	X_MIDDLE	0x00		// not first not last

#define	CONSTRUCT	0x04		// constructed node
#define	OPTIONAL	0x08		// optional node
#define ANY_ASN1	0x10		// any types do match
#define DATA_INDEX	0x20		// data Index present

#define	DATA_RANGE	0x40		// data Index Range present
#define	MUST_MATCH	0x40		// when decoding: force type matches

#define ZERO_LEAD_FLAG	0x80		// special processing leading zeroes
					
#define CTL_ENTRY_SIZE	4		// NOTE: should be same as header array!
#define X_FLAGS_MASK	0x03

#define FLAG_OFFSET	0
#define ASN1_TYPE_OFF	1
#define	DATA_INDEX_OFF	2
#define	DATA_RANGE_OFF	3

#define HDR_ENTRY_SIZE		4
#define HDR_LEN_FLD_LEN_OFF	0
#define HDR_LEN_FLD_OFF		1

#define ANY_ASN1_LEN_FLD_LEN	0xFE
#define UNUSED_LEN_FLD_LEN	0xFF

//-----------------------------------------------------
// Data Array indices for IBM ASN1 Container processing
//-----------------------------------------------------

#define IBM_ORDINAL_INDEX		0	// Container ID
#define IBM_REQ_CERT_DATA_INDEX		1	// Certificate Request
#define	IBM_STD_CERT_DATA_INDEX		2	// certificate
#define IBM_SPC_CERT_DATA_INDEX		3	// same, but needed for ToASN1
#define IBM_PRIV_KEY_INFO_INDEX		4	// private key info
#define IBM_CONTAINER_NAME_INDEX	5	// name of container
#define IBM_FLAGS_INDEX			6	// container flags
#define IBM_UNKNOWN_INDEX		7	// empty sequence

#define IBM_CONTAINER_MAX_DATA_INDEX	8

#define	IBM_CONTAINER_CTL_CNT		15
#define	IBM_CONTAINER_CTL_SIZE		(15 * CTL_ENTRY_SIZE)

//-----------------------------------------------------
// Data Array indices for Certificate processing
//-----------------------------------------------------

#define X509_TBS_CERT_INDEX		0
#define	X509_VFY_SIGNAT_ALGOR_ID_INDEX	1
#define	X509_VFY_SIGNAT_ALGOR_PAR_INDEX	2
#define	X509_VFY_SIGNAT_DATA_INDEX	3

#define X509_CERT_MAX_DATA_INDEX	4		// number of elements

#define X509_CERT_CTL_CNT	6
#define X509_CERT_CTL_SIZE	(6 * CTL_ENTRY_SIZE)

//-----------------------------------------------------
// Data Array indices for TBS Certificate processing
//-----------------------------------------------------

#define X509_VERSION_INDEX		0
#define X509_SERIAL_INDEX		1
#define	X509_SIGNAT_ALGOR_ID_INDEX	2
#define	X509_SIGNAT_ALGOR_PAR_INDEX	3
#define X509_ISSUER_NAME_INDEX		4
#define X509_NOT_BEFORE_INDEX		5
#define X509_NOT_AFTER_INDEX		6
#define X509_SUBJECT_NAME_INDEX		7
#define X509_PUBLIC_ALGOR_ID_INDEX	8
#define X509_PUBLIC_ALGOR_PAR_INDEX	9
#define	X509_PUBLIC_DATA_INDEX		10
#define X509_ISSUER_UNIQUE_ID_INDEX	11
#define X509_SUBJECT_UNIQUE_ID_INDEX	12
#define	X509_EXTENSION_DATA_INDEX	13

#define X509_TBS_CERT_MAX_DATA_INDEX	14		// number of elements

#define X509_TBS_CERT_CTL_CNT	21
#define X509_TBS_CERT_CTL_SIZE	(21 * CTL_ENTRY_SIZE)

//-----------------------------------------------------
// Data Array indices for RDN Entry processing
//-----------------------------------------------------

#define X501_RDN_AVA_INDEX		0
#define X501_RDN_AVA_MAX_DATA_INDEX	1		// number of Elements

#define X501_RDN_AVA_CTL_CNT		1
#define X501_RDN_AVA_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array indices for X501 AVA (Attribute/Value) processing
//-------------------------------------------------------------

#define X501_AVA_OBJID_INDEX		0
#define	X501_AVA_VALUE_INDEX		1
#define X501_AVA_MAX_DATA_INDEX		2		// number of Elements

#define X501_AVA_CTL_CNT		3
#define X501_AVA_CTL_SIZE		(3 * CTL_ENTRY_SIZE)

//-----------------------------------------------------
// Data Array indices for Extension Entry processing
//-----------------------------------------------------

#define X509_EXT_OBJID_INDEX		0
#define X509_EXT_CRITICAL_INDEX		1
#define X509_EXT_VALUE_INDEX		2
#define	X509_EXT_MAX_DATA_INDEX		3		// number of Elements

#define X509_EXT_CTL_CNT		4
#define X509_EXT_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

//-----------------------------------------------------
// Authority / Subject Key Identifier Extensions
//-----------------------------------------------------

#define	AUTH_KEY_ID_INDEX		0	// Octet String
#define	AUTH_CERT_ISSUER_INDEX		1	// General Name
#define AUTH_SERIAL_INDEX		2	// Integer
#define AUTH_KEY_ID_MAX_DATA_INDEX	3	// number of Elements

#define AUTH_KEY_ID_CTL_CNT		4
#define AUTH_KEY_ID_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

#define SUBJ_KEY_ID_INDEX		0	// Octet String
#define SUBJ_KEY_ID_MAX_DATA_INDEX	1	// number of Elements

#define SUBJ_KEY_ID_CTL_CNT		1
#define SUBJ_KEY_ID_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//--------------------------------------------------------------------
// Key Usage / Extended Key usage /Private key usage period Extensions
//--------------------------------------------------------------------

#define KEY_USAGE_INDEX			0	// Bit String, Flags
#define KEY_USAGE_MAX_DATA_INDEX	1	// number of elements

#define KEY_USAGE_CTL_CNT		1
#define KEY_USAGE_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define EXT_KEY_USAGE_INDEX		0	// OBJ-Ids
#define EXT_KEY_USAGE_MAX_DATA_INDEX	1	// number of elements

#define EXT_KEY_USAGE_CTL_CNT		1
#define EXT_KEY_USAGE_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define	PRIV_KEY_USE_NOT_BEFORE_INDEX	0	// generalized time
#define	PRIV_KEY_USE_NOT_AFTER_INDEX	1	// generalized time
#define PRIV_KEY_USE_MAX_DATA_INDEX	2	// number of elements

#define PRIV_KEY_USE_PERIOD_CTL_CNT	3
#define PRIV_KEY_USE_PERIOD_CTL_SIZE	(3 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// Data Array indices for ASN.1 ObjID Splitter
//----------------------------------------------------------------

#define	OID_SPLIT_INDEX			0	// Any ASN.1
#define	OID_SPLIT_MAX_DATA_INDEX	1	// number of Elements

#define	OBJID_SPLIT_CTL_CNT		1
#define	OBJID_SPLIT_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//--------------------------------------------------------------------
// Certificate policies / Policy mapping Extensions
//--------------------------------------------------------------------

#define	POLICIES_CONTENT_INDEX		0	// policy elements
#define POLICIES_CONTENT_MAX_DATA_INDEX	1	// number of elements

#define	POLICIES_CONTENT_CTL_CNT	1
#define	POLICIES_CONTENT_CTL_SIZE	(1 * CTL_ENTRY_SIZE)

#define	POLICY_ELEMENT_ID_INDEX		0	// object ID
#define	POLICY_ELEMENT_QUAL_INDEX	1	// ANY ASN1
#define	POLICY_ELEMENT_MAX_DATA_INDEX	2	// number of elements

#define POLICY_ELEMENT_CTL_CNT		3
#define	POLICY_ELEMENT_CTL_SIZE		(3* CTL_ENTRY_SIZE)

#define	POLICIES_MAP_CONTENT_INDEX	0	// Mapping sequences
#define	POLICIES_MAP_MAX_DATA_INDEX	1	// number of elements

#define	POLICY_MAP_CTL_CNT		1
#define	POLICY_MAP_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define	ISSUER_DOMAIN_POLICY_ID_INDEX	0	// object ID
#define	SUBJECT_DOMAIN_POLICY_ID_INDEX	1	// object ID
#define	DOMAIN_POLICY_ID_MAX_DATA_INDEX	2	// number of elements

#define	POLICY_MAP_ELEMENT_CTL_CNT	3
#define	POLICY_MAP_ELEMENT_CTL_SIZE	(3 * CTL_ENTRY_SIZE)

//-----------------------------------------------------
// Issuer / Subject Alternate Name Extensions
//-----------------------------------------------------

#define	ALT_NAMES_CONTENT_INDEX		0	// General names sequence
#define ALT_NAMES_MAX_DATA_INDEX	1	// number of elements

#define	ALT_NAME_CTL_CNT		1
#define	ALT_NAME_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define	OTHER_NAME_INDEX		0	// unknown, OID ?
#define	RFC822_NAME_INDEX		1	// IA5 String
#define	DNS_NAME_INDEX			2	// IA5 String
#define	X400_NAME_INDEX			3	// X400 name
#define	GEN_RDN_NAME_INDEX		4	// RDN, w/o sequence
#define	EDI_PARTY_NAME_INDEX		5	// EDI name
#define	URI_NAME_INDEX			6	// IA5 String
#define	IP_ADR_NAME_INDEX		7	// IP-Address
#define	REGISTERED_NAME_INDEX		8	// Object ID
#define	GENERAL_NAME_MAX_DATA_INDEX	9	// number of elements

#define	GENERAL_NAME_CTL_CNT		9
#define	GENERAL_NAME_CTL_SIZE		(9 * CTL_ENTRY_SIZE)

//-----------------------------------------------------
// Basic-/Name-/Policy-Constraints Extensions
//-----------------------------------------------------

#define	CA_FLAG_INDEX			0	// boolean
#define	PATHLEN_CONSTR_INDEX		1	// integer
#define	BASIC_CONSTR_MAX_DATA_INDEX	2	// number of elements

#define	BASIC_CONSTRAINTS_CTL_CNT	3
#define	BASIC_CONSTRAINTS_CTL_SIZE	(3 * CTL_ENTRY_SIZE)

#define	PERMITTED_SUBTREE_INDEX		0	// subtree elements
#define	EXCLUDED_SUBTREE_INDEX		1	// subtree elements	
#define	NAME_CONSTRAINTS_MAX_DATA_INDEX	2	// number of elements

#define	NAME_CONSTRAINTS_CTL_CNT	3
#define	NAME_CONSTRAINTS_CTL_SIZE	(3* CTL_ENTRY_SIZE)

#define	BASE_NAME_INDEX			0	// RDN
#define	MIN_BASE_DIST_INDEX		1	// Integer
#define	MAX_BASE_DIST_INDEX		2	// Integer
#define GENERAL_SUBTREE_MAX_DATA_INDEX	3	// number of Elements

#define	GENERAL_SUBTREE_CTL_CNT		4
#define	GENERAL_SUBTREE_CTL_SIZE	(4 * CTL_ENTRY_SIZE)

#define	REQ_EXPL_POLICY_SKIP_INDEX	0	// Integer
#define	INH_POLICY_MAP_SKIP_INDEX	1	// Integer
#define	POLICY_CONSTR_MAX_DATA_INDEX	2	// number of elements

#define	POLICY_CONSTRAINTS_CTL_CNT	3
#define	POLICY_CONSTRAINTS_CTL_SIZE	(3 * CTL_ENTRY_SIZE)

//-----------------------------------------------------
// CRL-Distribution Points Extensions
//-----------------------------------------------------

#define	DIST_POINTS_INDEX		0	// Distribution point names
#define	CRL_DISTR_POINTS_MAX_DATA_INDEX	1	// number of elements

#define	CRL_DIST_POINTS_CTL_CNT		1
#define	CRL_DIST_POINTS_CTL_SIZE	(1 * CTL_ENTRY_SIZE)

#define	CRL_DIST_POINT_NAME_INDEX	0	// General Name
#define	CRL_REASONS_INDEX		1	// Bitstring
#define	CRL_ISSUER_NAME_INDEX		2	// General Name / RDN
#define	CRL_DIST_POINT_MAX_DATA_INDEX	3	// number of elements

#define	CRL_DIST_POINT_CTL_CNT		4
#define	CRL_DIST_POINT_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

#define	DIST_POINT_GEN_NAME_INDEX	0	// general name
#define	DIST_POINT_RDN_NAME_INDEX	1	// RDN
#define	DIST_POINT_NAME_MAX_DATA_INDEX	2	// number of elements

#define	DIST_POINT_NAME_CTL_CNT		2
#define	DIST_POINT_NAME_CTL_SIZE	(2 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// Data Array indices for RSA Public Key Info/Signature processing
// and RSA Private Key processing
//----------------------------------------------------------------

#define RSA_ALG_PAR_MAX_INDEX		1	// dummy !!!

#define RSA_PUB_ALG_CTL_CNT		1
#define RSA_PUB_ALG_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define	RSA_PUB_VAL_MOD_INDEX		0
#define RSA_PUB_VAL_EXP_INDEX		1

#define RSA_PUB_VAL_CTL_CNT		3
#define RSA_PUB_VAL_CTL_SIZE		(3 * CTL_ENTRY_SIZE)

#define RSA_PUB_VAL_MAX_INDEX		2
#define RSA_PUB_DATA_MAX_INDEX		2	// Params AND Values

#define	RSA_SIG_VAL_INDEX		0
#define RSA_SIG_MAX_INDEX		1

#define RSA_SIG_VAL_CTL_CNT		1
#define RSA_SIG_VAL_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define	RSA_PRIV_KEY_MODULUS_INDEX	0
#define	RSA_PRIV_KEY_PUBL_EXP_INDEX	1
#define	RSA_PRIV_KEY_PRIV_EXP_INDEX	2
#define RSA_PRIV_KEY_PRIME_P_INDEX	3
#define RSA_PRIV_KEY_PRIME_Q_INDEX	4
#define	RSA_PRIV_KEY_EXP1_INDEX		5
#define	RSA_PRIV_KEY_EXP2_INDEX		6
#define	RSA_PRIV_KEY_COEFF_INDEX	7
#define	RSA_PRIV_KEY_VERSION_INDEX	8

#define RSA_PRIV_KEY_MAX_INDEX		9

#define	RSA_PRIV_KEY_CTL_CNT		10
#define	RSA_PRIV_KEY_CTL_SIZE		(10 * CTL_ENTRY_SIZE)

// OPENSSL / SSLEAY format (in PEM files)
// NOTE: Indices MUST be same as for PKCS1 !!

#define	OPSSL_RSA_PRIV_MODULUS_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_MODULUS_INDEX)
#define	OPSSL_RSA_PRIV_PUBEXP_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_PUBL_EXP_INDEX)
#define	OPSSL_RSA_PRIV_PRIVEXP_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_PRIV_EXP_INDEX)	
#define	OPSSL_RSA_PRIV_PRIME_P_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_PRIME_P_INDEX)
#define	OPSSL_RSA_PRIV_PRIME_Q_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_PRIME_Q_INDEX)
#define	OPSSL_RSA_PRIV_DMODP_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_EXP1_INDEX)
#define	OPSSL_RSA_PRIV_DMODQ_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_EXP2_INDEX)
#define	OPSSL_RSA_PRIV_INVQMP_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_COEFF_INDEX)
#define	OPSSL_RSA_PRIV_VERSION_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_VERSION_INDEX)

#define	OPSSL_RSA_PRIV_MAX_DATA_INDEX	(RSA_ALG_PAR_MAX_INDEX+RSA_PRIV_KEY_MAX_INDEX)

#define	OPSSL_RSA_PRIVKEY_CTL_CNT	10
#define	OPSSL_RSA_PRIVKEY_CTL_SIZE	(10 * CTL_ENTRY_SIZE)

//-----------------------------------------------------
// Data Array indices for DH Public Key Info processing
//-----------------------------------------------------

#define DH_ALG_PAR_P_INDEX		0
#define DH_ALG_PAR_G_INDEX		1
#define DH_ALG_PAR_Q_INDEX		2
#define DH_ALG_PAR_J_INDEX		3	// ignored
#define DH_ALG_PAR_SEED_INDEX		4	// ignored
#define DH_ALG_PAR_PGCNT_INDEX		5	// ignored

#define DH_ALG_PAR_MAX_INDEX		6	

#define DH_PUB_ALG_CTL_CNT		8
#define DH_PUB_ALG_CTL_SIZE		(8 * CTL_ENTRY_SIZE)

#define DH_PUB_VAL_Y_INDEX		0
#define DH_PUB_VAL_MAX_INDEX		1

#define DH_PUB_VAL_CTL_CNT		1
#define DH_PUB_VAL_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define DH_PUB_DATA_MAX_INDEX		4	// Params AND Values

#define	DH_PRIV_KEY_YKEY_INDEX		0
#define	DH_PRIV_KEY_XKEY_INDEX		1
#define	DH_PRIV_KEY_VERSION_INDEX	2

#define DH_PRIV_KEY_MAX_INDEX		3

#define	DH_PRIV_KEY_CTL_CNT		4
#define	DH_PRIV_KEY_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// Data Array indices for DSA Public Key Info/Signature processing
// and DSA Private Key processing
//----------------------------------------------------------------

#define DSA_ALG_PAR_P_INDEX		0
#define DSA_ALG_PAR_Q_INDEX		1
#define DSA_ALG_PAR_G_INDEX		2
#define DSA_ALG_PAR_MAX_INDEX		3
#define OIW_DSA_ALG_PAR_MAX_INDEX	1

#define DSA_PUB_ALG_CTL_CNT		4
#define DSA_PUB_ALG_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

#define OIW_DSA_PUB_ALG_CTL_CNT		1
#define OIW_DSA_PUB_ALG_CTL_SIZE	(1 * CTL_ENTRY_SIZE)

#define DSA_PUB_VAL_Y_INDEX		0
#define DSA_PUB_VAL_MAX_INDEX		1

#define OIW_DSA_PUB_VAL_Y_INDEX		3

#define DSA_PUB_VAL_CTL_CNT		1
#define DSA_PUB_VAL_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define OIW_DSA_PUB_VAL_CTL_CNT		5
#define OIW_DSA_PUB_VAL_CTL_SIZE	(5 * CTL_ENTRY_SIZE)

#define DSA_PUB_DATA_MAX_INDEX		4	// Params AND Values

#define DSA_SIG_VAL_INDEX		0
#define DSA_SIG_MAX_INDEX		1

#define DSA_SIG_VAL_CTL_CNT		1
#define DSA_SIG_VAL_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define DSA_SIG_ALG_CTL_CNT		1
#define DSA_SIG_ALG_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

#define	DSA_PRIV_KEY_YKEY_INDEX		0
#define	DSA_PRIV_KEY_XKEY_INDEX		1
#define	DSA_PRIV_KEY_VERSION_INDEX	2

#define DSA_PRIV_KEY_MAX_INDEX		3

#define	DSA_PRIV_KEY_CTL_CNT		4
#define	DSA_PRIV_KEY_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

// OPENSSL / SSLEAY format (in PEM files)
// NOTE: Indices must be same as for DSA params + Private Key

#define	OPSSL_DSA_PRIV_MODULUS_P_INDEX	DSA_ALG_PAR_P_INDEX
#define	OPSSL_DSA_PRIV_GROUP_Q_INDEX	DSA_ALG_PAR_Q_INDEX
#define	OPSSL_DSA_PRIV_GEN_G_INDEX	DSA_ALG_PAR_G_INDEX
#define	OPSSL_DSA_PRIV_PUBVAL_Y_INDEX	(DSA_ALG_PAR_MAX_INDEX+DSA_PRIV_KEY_YKEY_INDEX)
#define	OPSSL_DSA_PRIV_PRIVVAL_X_INDEX	(DSA_ALG_PAR_MAX_INDEX+DSA_PRIV_KEY_XKEY_INDEX)
#define	OPSSL_DSA_PRIV_VERSION_INDEX	(DSA_ALG_PAR_MAX_INDEX+DSA_PRIV_KEY_VERSION_INDEX)

#define	OPSSL_DSA_PRIV_MAX_DATA_INDEX	(DSA_ALG_PAR_MAX_INDEX+DSA_PRIV_KEY_MAX_INDEX)

#define	OPSSL_DSA_PRIVKEY_CTL_CNT	7
#define	OPSSL_DSA_PRIVKEY_CTL_SIZE	(7 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// Data Array indices for PKCS8 Private Key Info processing
//----------------------------------------------------------------

#define PKCS8_VERSION_INDEX		0
#define	PKCS8_KEY_ALGOR_INDEX		1
#define PKCS8_KEY_ALG_PAR_INDEX		2
#define	PKCS8_KEY_VALUE_INDEX		3

#define PKCS8_KEY_MAX_DATA_INDEX	4

#define PKCS8_PRIV_KEY_INFO_CTL_CNT	6
#define PKCS8_PRIV_KEY_INFO_CTL_SIZE	(6 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// Data Array indices for PKCS10 Certificate Request processing
//----------------------------------------------------------------

#define CERT_REQ_INFO_INDEX		0
#define CERT_REQ_SIGNAT_ALGOR_ID_INDEX  1
#define CERT_REQ_SIGNAT_ALGOR_PAR_INDEX 2
#define	CERT_REQ_SIGNAT_DATA_INDEX	3
#define CERT_REQ_MAX_DATA_INDEX		4

#define CERT_REQ_CTL_CNT		6
#define CERT_REQ_CTL_SIZE	(6 * CTL_ENTRY_SIZE)

#define TBS_CERT_REQ_VERSION_INDEX	0
#define TBS_CERT_REQ_SUBJECT_RDN_INDEX	1
#define TBS_CERT_REQ_PUB_ALGOR_ID_INDEX	2
#define TBS_CERT_REQ_PUB_ALG_PAR_INDEX	3
#define TBS_CERT_REQ_PUBLIC_DATA_INDEX	4
#define TBS_CERT_REQ_ATTRIBUTES_INDEX	5
#define TBS_CERT_REQ_MAX_DATA_INDEX	6

#define TBS_CERT_REQ_CTL_CNT		9
#define TBS_CERT_REQ_CTL_SIZE	(TBS_CERT_REQ_CTL_CNT * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// Data Array indices for ASN.1 Sequence Wrapper
//----------------------------------------------------------------

#define	SEQ_WRAP_INDEX			0	// Any ASN.1
#define	SEQ_WRAP_MAX_DATA_INDEX		1	// number of Elements

#define	SEQ_WRAP_CTL_CNT		1
#define	SEQ_WRAP_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//==========================================================
//
// CRL Processing parameters
//
//==========================================================

//----------------------------------------------------------------
// Data Array indices for X509V3 CRL processing
//----------------------------------------------------------------

#define X509_CRL_TBS_CRL_INDEX		0
#define X509_CRL_SIGNAT_ALGOR_ID_INDEX  1
#define X509_CRL_SIGNAT_ALGOR_PAR_INDEX 2
#define X509_CRL_SIGNAT_DATA_INDEX	3
#define X509_CRL_MAX_DATA_INDEX		4

#define X509_CRL_CTL_CNT		6
#define X509_CRL_CTL_SIZE	(6 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// Data Array indices for TBS CRL processing
//----------------------------------------------------------------

#define X509_TBS_CRL_VERSION_INDEX	0
#define X509_TBS_CRL_SIGN_ALG_ID_INDEX	1
#define X509_TBS_CRL_SIGN_ALG_PAR_INDEX	2
#define X509_TBS_CRL_ISSUER_NAME_INDEX	3
#define X509_TBS_CRL_THIS_UPDATE_INDEX  4
#define X509_TBS_CRL_NEXT_UPDATE_INDEX  5
#define X509_TBS_CRL_REVOKD_CERTS_INDEX 6
#define X509_TBS_CRL_EXTENS_DATA_INDEX  7
#define X509_TBS_CRL_MAX_DATA_INDEX	8

#define X509_TBS_CRL_CTL_CNT		11
#define X509_TBS_CRL_CTL_SIZE	(11 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// Data Array indices for CRL Revoked Certificate entry processing
//----------------------------------------------------------------

#define REVOKED_CERT_SERIAL_INDEX	0
#define REVOKED_CERT_DATE_INDEX		1
#define REVOKED_CERT_EXT_INDEX		2
#define REVOKED_CERT_MAX_DATA_INDEX	3

#define REVOKED_CERT_CTL_CNT		4
#define REVOKED_CERT_CTL_SIZE	(4 * CTL_ENTRY_SIZE)

//==========================================================
// Data Array indices for CRL Extension processing
//==========================================================

//----------------------------------------------------------------
// CRL Number Extension processing
//----------------------------------------------------------------

#define	CRL_EXT_NUMBER_INDEX		0	// Integer
#define	CRL_EXT_NUMBER_MAX_DATA_INDEX	1	// number of Elements

#define	CRL_EXT_NUMBER_CTL_CNT		1
#define	CRL_EXT_NUMBER_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// CRL Issuing Distribution Point Extension processing
//----------------------------------------------------------------

#define	CRL_EXT_DISTPNT_NAME_INDEX	0	// General Name or RDN
#define	CRL_EXT_USER_CERTS_ONLY_INDEX	1	// Boolean, DEFAULT false
#define	CRL_EXT_CA_CERTS_ONLY_INDEX	2	// Boolean, DEFAULT false
#define	CRL_EXT_SOME_REASONS_INDEX	3	// Bit-String
#define	CRL_EXT_INDIRECT_CRL_INDEX	4	// Boolean, DEFAULT false
#define	CRL_EXT_DISTPNT_MAX_DATA_INDEX	5	// number of elements

#define	CRL_EXT_ISS_DIST_POINT_CTL_CNT	6
#define	CRL_EXT_ISS_DIST_POINT_CTL_SIZE	(6 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// CRL Delta CRL Indicator Extension processing
//----------------------------------------------------------------

#define	CRL_EXT_BASE_NUMBER_INDEX	0	// Integer
#define	CRL_EXT_BASE_NUM_MAX_DATA_INDEX	1	// number of elements

#define	CRL_EXT_DELTA_CRL_CTL_CNT	1
#define	CRL_EXT_DELTA_CRL_CTL_SIZE	(1 * CTL_ENTRY_SIZE)

//==========================================================
// Data Array indices for CRL Entry Extension processing
//==========================================================

//----------------------------------------------------------------
// CRL Entry Reason Code Extension processing
//----------------------------------------------------------------

#define	CRL_ENTRY_REASON_CODE_INDEX	0	// Enumerated (Integer)
#define	CRL_ENTRY_REASON_MAX_DATA_INDEX	1	// number of entries

#define	CRL_ENT_REASON_CTL_CNT		1
#define	CRL_ENT_REASON_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// CRL Entry Hold Instruction Code Extension processing
//----------------------------------------------------------------

#define	CRL_ENTRY_HOLD_INSTR_CODE_INDEX	0	// Object ID
#define	CRL_ENTRY_HOLD_MAX_DATA_INXDEX	1	// number of elements

#define	CRL_ENT_HOLD_CTL_CNT		1
#define	CRL_ENT_HOLD_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// CRL Entry Invalidity Date Extension processing
//----------------------------------------------------------------

#define	CRL_ENTRY_INVAL_DATE_INDEX	0	// Generalized Time
#define	CRL_ENTRY_IVDATE_MAX_DATA_INDEX	1	// number of elements

#define	CRL_ENT_INVAL_DATE_CTL_CNT	1
#define	CRL_ENT_INVAL_DATE_CTL_SIZE	(1 * CTL_ENTRY_SIZE)

//----------------------------------------------------------------
// CRL Entry Certificate Issuer Extension processing
//----------------------------------------------------------------

#define	CRL_ENTRY_CERT_ISSUER_INDEX	0	// General Name
#define	CRL_ENTRY_CERTISS_MAX_DATA_IND	1	// number of elements

#define	CRL_ENT_CERT_ISSUER_CTL_CNT	1
#define	CRL_ENT_CERT_ISSUER_CTL_SIZE	(1 * CTL_ENTRY_SIZE)

//================================================================
//
// PKCS 7 additional processing
//
//================================================================

//----------------------------------------------------------------
// Data Array indices for PKCS7 Certificate List processing
//----------------------------------------------------------------

#define PKCS7_SDATA_OID_INDEX		0
#define PKCS7_SDATA_VERSION_INDEX	1
#define PKCS7_SDATA_DIGEST_ALGORS_INDEX	2
#define PKCS7_SDATA_DATA_OID_INDEX	3
#define PKCS7_SDATA_DATA_CONT_INDEX	4
#define PKCS7_SDATA_CERTS_INDEX		5
#define PKCS7_SDATA_CRLS_INDEX		6
#define PKCS7_SDATA_SIGNER_INFOS_INDEX	7

#define PKCS7_CERTS_LIST_MAX_DATA_INDEX	8
#define PKCS7_CERTS_LIST_CTL_CNT	12
#define PKCS7_CERTS_LIST_CTL_SIZE	(12 * CTL_ENTRY_SIZE)

#define X509_CERT_ENTRY_INDEX		0
#define X509_CERT_ENTRY_MAX_DATA_INDEX	1

#define X509_CERT_ENTRY_CTL_CNT		1
#define X509_CERT_ENTRY_CTL_SIZE	(1 * CTL_ENTRY_SIZE)

#define FREE_BIT_MASK		0x01
#define FREE_CLEAR_BIT_MASK	0x02

//================================================================
// X.501 Attribute / Value Structure (strings)
//================================================================

typedef struct IDATA_t IDATA;
typedef struct IDATPARR_t IDATPARR;
typedef struct X501_DN_t X501_DN;
typedef struct X509CERT_t X509CERT;
typedef struct CTREESTR_t CTREESTR;
typedef struct HCERWTXT_t HCERWTXT;

/** @addtogroup asn1
* @{
*/
/**
* This structure contains a readable form of a X.509attribute / value pair. 
* Used for display operations.
*/
typedef struct X501_AVA_STR_t {
  int	  OidIndex;			//!< >= 0 known OID index
  char* pOidStr;			//!< OID in internal decimal/hex format
  int	  ValType;			//!< Value coding: 0 - string
  char* pValStr;			//!< Value in internal format 
} X501_AVA_STR;

/** @} */

//================================================================
// X.501 RDN String Structure, Collection of AVAs
//================================================================

/** @addtogroup asn1
* @{
*/
/**
* This structure is a container for X501_AVA_STR attribute / value string 
* structures for a X.501 relative distinguished name element. Used for 
* display operations.
*/ 
typedef struct X501_RDN_STR_t {
  int	  		AvaCnt;		//!< Number of attribute/value pairs in RDN
  X501_AVA_STR **	pAvaArr;	//!< Attribue/value structure array
} X501_RDN_STR;

/** @} */

//=================================================================
// X.501 DN *String* Structure, Collection of RDN String Structures
//=================================================================

/** @addtogroup asn1
* @{
*/
/**
* This structure is a container for X501_RDN_STR attribute / value string 
* container structures for a X.501 distinguished name. Used for display 
* operations.
*/
typedef struct X501_DN_STR_t {
  int	  	    RdnCnt;		//!< Number of RDN elements
  X501_RDN_STR ** pRdnArr;		//!< RDN structure array
} X501_DN_STR;

/** @} */

//================================================================
// Certificate Request Class Structure definition
// NOTE: Used for Splitting and Construction (in which case
// ----- some fields will have different contents !).
//================================================================

/** @addtogroup asn1
* @{
*/
/**
* This structure is the internal representation of a PKCS10 ertificate
* request.
*/
typedef struct PKCS10_CERTREQ_t {
  IDATPARR*	CertificateRequest;	//!< The certificate request in full size
  IDATPARR*	TBS_CertReqInfo;	//!< The portion to be signed
  IDATPARR*	CertReqSignature;	//!< (Algor/paras/)signat data, no hdr
  IDATPARR*	VersionNumber;		//!< Version number,	no header
  X501_DN*	Subject;		//!< Subject, RDN-chain no header
  IDATPARR*	SubjPubKeyParVal;	//!< (Algor/)param(s)/value(s) no header
  IDATPARR*	Attributes;		//!< Attributes with header

  IDATPARR*	PrivKeyData;		//!< Decrypted priv. key data, COPY !
  IDATPARR*	PEMTextData;		//!< Text data from PEM request
  IDATPARR*	PEMMicData;		//!< MIC data from PEM request

  int	SignatAlgor;			//!< Type of signature algorithm
  int	SignatType;			//!< Type of signature
  int	PublicKeyType;			//!< Type of public key
  int	PrivKeyType;			//!< Type of private key
  int	Flags;				//!< Is root/trusted/CA/has key
} PKCS10_CERTREQ;

/** @} */

//================================================================
// Certificate Tree Class Structure definition
// Used for Construction of the trees for SSL/Keymanagement
//================================================================

/** @addtogroup asn1
* @{
*/
/**
* This structure represents a collection of certificate trees.
*
* ppCertList is an array, containing all certificates.
* CNodeArray defines the tree structures. Its entries are groups of 8 
* <code>INT</code> values. They show: <ol>
* <li> Index of the parent node in the CNodeArray.
* <li> Index of the next sibling in the CNodeArray.
* <li> Index of the child in the CNodeArray.
* <li> Index of the certificate in the ppCertList.
* <li> Level in the tree, rel. 0
* <li> Flags of the node.
* <li> Certificate type.
* <li>  A reserved value.
*</ol>
* The other arrays are lists of indices for the CNodeArray for specific 
* certificate types (for example all root certificates) for easy access.
* They only contain those indices and are not constructed like CNodeArray.
*/
typedef struct CTREESTR_t {
        X509CERT ** ppCertList;		//!< Certificate list array
	int* CNodeArray;		//!< CNode array
	int* RootCaIndexArray;	//!< Root index array
	int* RootEndRsaIndexArray;	//!< RSA sign root index array
	int* RootEndDssIndexArray;	//!< DSS sign root index array
	int* SubCaIndexArray;		//!< SUB-CA index array
	int* EndRsaIndexArray;	//!< RSA sign end certs index array
	int* EndDssIndexArray;	//!< DSS sign end certs index array
	int* EndDhRsaIndexArray;	//!< DH-RSA end certs index array
	int* EndDhDssIndexArray;	//!< DH-DSS end certs index array
	int    CListCount;		//!< Number of certificates in ppCertList
	int    CNodeCount;		//!< Number of entries in CNodeArray
	int    CTreeDepth;		//!< max. depth of tree (rel.1)
	int    RootCaCount;		//!< Number of entries in RootCaIndexArray
	int    RootEndRsaCount;		//!< Number of entries in RootEndRsaIndexArray
	int    RootEndDssCount;		//!< Number of entries in RootEndDssIndexArray
	int    SubCaCount;		//!< Number of entries in SubCaIndexArray
	int    EndRsaCount;		//!< Number of entries in EndRsaIndexArray
	int    EndDssCount;		//!< Number of entries in EndDssIndexArray
	int    EndDhRsaCount;		//!< Number of entries in EndDhRsaIndexArray
	int    EndDhDssCount;		//!< Number of entries in EndDhDssIndexArray
} CTREESTR;

/** @} */

//---------------------------------------------------
// CNode Structure (Offsets for Integer Array)
//---------------------------------------------------

#define CN_P_INDEX		0		// Index of Parent for CNode
#define CN_S_INDEX		1		// Index to next of Same Level
#define CN_C_INDEX		2		// Index to Child of CNode
#define CN_CERTLIST_INDEX	3		// Index of Certificate in list
#define CN_LEVEL		4		// Level of tree (rel. 0)
#define CN_FLAGS		5		// Flags of CNode
#define	CN_CERT_TYPE		6		// Type of Certificate
#define CN_JTREE_INDEX		7		// reserved
#define	CNODE_SIZE		(CN_JTREE_INDEX+1) // number of Elements

//================================================================
// Certificate Chain/Tree Import Class Structure definition
//================================================================

/** @addtogroup asn1
* @{
*/
/**
* This structure is a container for a collection of certificates.
*/
typedef struct CERTPARR_t {
  int		Cnt;			//!< Number of entries
  int		Flags;			//!< Bit 0: 1 must free entries
  X509CERT **	ppArr;			//!< Array pointer
} CERTPARR;

#define FREE_BIT_MASK		0x01

/** @} */

//------------------------------------------------------------
// Internal Representation of Time (int array[])
//------------------------------------------------------------

#define	TIME_YEAR_INDEX		0		// 1st element
#define	TIME_MONTH_INDEX	1		// 2nd element
#define	TIME_DAY_INDEX		2		// 3rd element
#define	TIME_HOUR_INDEX		3		// 4th element
#define	TIME_MINUTES_INDEX	4		// 5th element
#define	TIME_SECONDS_INDEX	5		// 6th element
#define TIME_MILLI_SECONDS_INDEX 6		// 7th element
#define TIME_LOCAL_FLAG		7		// 8th element

#define	TIME_ARRAY_SIZE		8

//------------------------------------------------------------
// Internal Representation of RDN (BIT8PTR array[])
// NOTE: Ordered according to X.521 suggested naming scheme
// -----
//------------------------------------------------------------

#define RDN_COUNTRY_NAME_INDEX		0
#define RDN_LOCALITY_INDEX		1
#define RDN_STATE_OR_PROVINCE_INDEX	2
#define RDN_STREET_ADDRESS_INDEX	3
#define RDN_ORGANIZATION_NAME_INDEX	4
#define RDN_ORGANIZATION_UNIT_INDEX	5
#define RDN_TITLE_INDEX			6
#define RDN_POSTAL_CODE_INDEX		7
#define RDN_PHONE_NUMBER_INDEX		8
#define RDN_NAME_INDEX			9
#define RDN_COMMON_NAME_INDEX		10
#define RDN_SURNAME_INDEX		11
#define RDN_GIVEN_NAME_INDEX		12
#define RDN_INITIALS_INDEX		13
#define RDN_GENERATION_QUALIFIER_INDEX	14
#define RDN_DISTING_NAME_QUAL_INDEX	15
#define RDN_PKCS9_EMAIL_ADDRESS_INDEX	16
#define RDN_DOMAIN_COMPONENT_INDEX	17
#define RDN_ARRAY_MAX_DATA_INDEX	18

//--------------------------------------------------------------------
// Structures for Certificate Chain User Dialog Data formatting
//--------------------------------------------------------------------

/** @addtogroup asn1
* @{
*/
/**
* This structure is used for the user certificate accept dialog.
*/
typedef struct HCERWTXT_t {
  char**	pIssuerWTxtArr;		//!< Issuer strings in internal notation
  int		IssuerWTxtCnt;		//!< Number of elements
  char*	pIssuerDispWTxt;	//!< Short form of issuer text
  char**	pSubjectWTxtArr;	//!< Subject strings in internal notation
  int		SubjectWTxtCnt;		//!< Number of elements
  char*	pSubjectDispWTxt;	//!< Short form of subject text
  int NotBeforeTimeArr[TIME_ARRAY_SIZE]; //!< Not before time
  int NotAfterTimeArr[TIME_ARRAY_SIZE];  //!< Not after time
  char*	pSerialNumWTxt;		//!< Serial number in internal notation
  char*	pMD5FingerPrintWTxt;	//!< Fingerprint in internal notation
  int		StateFlags;		//!< State of verification
} HCERWTXT;

/** @} */

//==============================================================
//
// CRL processing structure
//
//==============================================================

//------------------------------------------------------
// CRL Entry structure (per revoked certificate)
//------------------------------------------------------

/** @addtogroup asn1
* @{
*/
/**
* This structure is a container for decoded CRL entry elements from a CRL.
*/
typedef struct CRLENT_t {
	IDATPARR*	pCertSerial;		//!< Certificate serial number
	int*		RevocationDate;		//!< TimeArray, revocation date
	int		RevocationDateTimeType;	//!< UTC/General time/default
	IDATPARR*	pEntryExtensions;	//!< Entry extensions
	int		ExtFlags;		//!< Extension flags
	int		RevocReason;		//!< Revocation reason  (Ext.)
	int*		InvalidityDate;		//!< Date of invalidity (Ext.)
	IDATPARR*	pCertIssuer;		//!< Issuer of cert.

} CRLENT;

/** @} */

//------------------------------------------------------
// CRL structure
//------------------------------------------------------

/** @addtogroup asn1
* @{
*/
/**
* This structure is the internal representation of a CRL.
*/
typedef struct CRLSTRU_t {
	IDATPARR*	pSignatAlgPar;		//!< Signature algorithm/params
	IDATPARR*	pSignature;		//!< Signature data
	int		SignatAlgor;		//!< Signature algorithm ID
	int		SignatType;		//!< Signature type
	int		SignatVerifyState;	//!< State of verification
	int		SignatChainResult;	//!< Chain check result
	int		SignatChainReason;	//!< Chain check hint
	IDATPARR*	pTBSCrl;		//!< Helper structure
	int		Version;		//!< Version number
	IDATPARR*	pTBSSignatAlgPar;	//!< Signature algorithm/params
	int		TBSSignatAlgor;		//!< Signature algorithm ID
	int		TBSSignatType;		//!< Signature type
	IDATPARR*	pIssuerName;		//!< Issuer name, raw
	X501_DN*	pIssuerDN;		//!< Issuer DN
	int*		ThisUpdate;		//!< This update time
	int		ThisUpdateTimeType;	//!< Default/UTC/general time of this update
	int*		NextUpdate;		//!< Next update time
	int		NextUpdateTimeType;	//!< Default/UTC/general time of next update
	CRLENT **	pRevokedCertsList;	//!< List of certificates
	int		RevokedCertsCount;	//!< number of entries / 0
	IDATPARR*	pCrlExtensions;		//!< Crl extensions
	int		ExtFlags;		//!< Extension flags
	IDATPARR*	pCrlNumber;		//!< CRL Number (ASN.1)
	int		CrlNumber;		//!< Decoded CRL number (< 2**31)
	IDATPARR*	pBaseCrlNumber;		//!< Base CRL number (ASN.1)
	int		BaseCrlNumber;		//!< Base CRL number, decoded
	IDATPARR*	pAuthKeyID;		//!< Authority key identifier
	IDATPARR*	pIssuerAltName;		//!< Issuer alternative name
	IDATPARR*	pCrlDistPoint;		//!< Distribution point
} CRLSTRU;

//-----------------------------------------------------------------------------
// ASN1 constants
//-----------------------------------------------------------------------------

//------------------------------------------------------------
// UTC Time definitions
//------------------------------------------------------------

#define	UTC_TIME_MIN_LEN		10	//YYMMDDHHMM
#define	UTC_TIME_DEFAULT_LEN		13	//YYMMDDHHMMSS"Z"
#define	GENERAL_TIME_MIN_LEN		12	//YYYYMMDDHHMM
#define	GENERAL_TIME_DEFAULT_LEN	15	//YYYYMMDDHHMMSS"Z"
#define	ZULU_CHAR			0x5A	// ASCII UPPER "Z"
#define	PLUS_CHAR			0x2B	// ASCII "+"
#define	MINUS_CHAR			0x2D	// ASCII "-"
#define	DOT_CHAR			0x2E	// ASCII "."
#define	LOCAL_TIME_LOWER_LIMIT		1995
#define	LOCAL_TIME_UPPER_LIMIT		3000	// will not occur (?)
#define MAX_MILLI_SECONDS		999
#define MAX_YEAR			9999	// Topmost for GeneralTime
#define GREGORIAN_YEAR			1582
#define UTC_TIME_FLAG			0
#define LOCAL_TIME_FLAG			1

//-------------------------------------------------------------
// ASN1 Time Type internal definitions
//-------------------------------------------------------------

#define	ASN1_TIME_TYPE_INVALID		0
#define	ASN1_TIME_TYPE_UTC		1
#define	ASN1_TIME_TYPE_GENTIME		2

#define IS_NOT_LEAP_YEAR	0
#define IS_LEAP_YEAR		1

#define ASN1_CERT_TIME_STATE_UNKNOWN	0
#define ASN1_CERT_TIME_VALID		1
#define ASN1_CERT_TIME_NOT_YET_VALID	2
#define ASN1_CERT_TIME_NO_LONGER_VALID	3

//------------------------------------------------------------
// Internal Algorithm Types:
// Public-/Signature-/Password-/Keyexchange Algors
//------------------------------------------------------------

#define INVALID_ALGOR		-1

//
// Public/Signature Algors
//

#define RSA_PUBLIC_ALGOR	0
#define	DH_PUBLIC_ALGOR		1
#define	DSA_PUBLIC_ALGOR	2

#define RSA_SIGNAT_ALGOR	0
#define	ANY_SIGNAT_ALGOR	1		// either RSA or DSA
#define	DSA_SIGNAT_ALGOR	2

//
// Signature Types
// NOTE: Keep the RSA types in that order !!!
//

enum ied_signature_types {
    PKCS1_MD2_WITH_RSA_ENC = 0,
    PKCS1_MD5_WITH_RSA_ENC,
    PKCS1_SHA1_WITH_RSA_ENC,
    TELESEC_RSA_WITH_RIPEMD160,
    PKCS1_SHA256_WITH_RSA_ENC,
    PKCS1_SHA384_WITH_RSA_ENC,
    PKCS1_SHA512_WITH_RSA_ENC,
    PKCS1_SHA224_WITH_RSA_ENC,
    X957_DSA_WITH_SHA1,
    OIW_DSA_WITH_SHA,
    OIW_DSA_WITH_SHA1,

    SIG_TYPE_COUNT,
};

//
// Password Algors
//

#define PKCS5_PBE_MD2_DES_CBC	0
#define PKCS5_PBE_MD5_DES_CBC	1
#define PKCS5_PBE_SHA1_DES_CBC	2

//
// Key Exchange Algors
//

#define PKCS1_RSA_ENCRYPTION	0
#define PKCS3_DH_KEY_AGREEMENT	1
#define X942_DH_PUBL_NUMBER	2

//-------------------------------------------------------------
// Parameters for the certificate structure
//-------------------------------------------------------------

#define	SELF_SIGNED_MASK		0x01
#define INVALID_TIME_MASK		0x02
#define	WELL_KNOWN_CA_MASK		0x04
#define PRIV_KEY_MASK			0x08
#define VERIFIED_SIGNAT_MASK		0x10

#define	SIGNAT_CHK_FAIL_MASK		0x20	// this certificate's signature
#define VALIDITY_CHK_FAIL_MASK		0x40	// this certificate's validity
#define CHAIN_CHK_FAIL_MASK		0x40	// this certificate's validity
#define	CHAIN_CHK_FATAL_FAIL_MASK	0x80	// issuer(s) check failed fatal
#define CHAIN_CHK_EXPIRED_MASK		0x100	// issuer(s) expired
#define	CHAIN_CHK_NOT_YET_VALID_MASK	0x200	// issuer(s) not yet valid

#define	ROOT_CERT_LIST			0	// Well Known CAs
#define CLIENT_CERT_LIST		1	// for the client, no keys
#define SERVER_CERT_LIST		2	// for the server, with keys

#define	ROOT_CERT			0	// Well Known CA
#define CLIENT_CERT			1	// for the client, no keys
#define SERVER_CERT			2	// for the server, with keys

#define CHAIN_MATCH			0
#define ROOT_MATCH			1
#define IDENTITY_MATCH			2

//---------------------------------------------------
// Parameters for Certificate Tree Structure
//---------------------------------------------------

#define	CNODE_RSA_CERT		0		// RSA sign
#define	CNODE_DSS_CERT		1		// DSS sign
#define CNODE_DH_RSA_CERT	2		// DH-RSA signed
#define	CNODE_DH_DSS_CERT	3		// DH-DSS signed

#define	CNODE_ROOT_CA_FLAG	0x01		// is root CA

//---------------------------------------------------
// Parameters for PKCS7 Certifcate Lists
//---------------------------------------------------

#define PKCS7_VERSION		1		// spec. 1.5

//---------------------------------------------------
// Entity definitions
//---------------------------------------------------

#ifndef SERVER_ENTITY
#define	SERVER_ENTITY	0		// note: same in HSSL.H
#define	CLIENT_ENTITY	1		// dto.
#endif

//------------------------------------------------------------
// Container Flags definitions
//------------------------------------------------------------

#define	IBM_CONT_FLAG_HOB_SW_USED	0x01		// Cert generated HOB
#define	IBM_CONT_FLAG_EXT_PRIV_KEY	0x02		// Key from external
#define	IBM_CONT_FLAG_EXT_CERT		0x04		// From external store

//------------------------------------------------------------
// Presence Flags for X509 Extensions (that can be recognized)
//------------------------------------------------------------

#define	X509EXT_AUTH_KEYID_PRES_BIT	0x400	// Bit 10
#define	X509EXT_SUBJ_KEYID_PRES_BIT	0x200	// Bit 9
#define	X509EXT_KEY_USAGE_PRES_BIT	0x100	// Bit 8
#define	X509EXT_CERT_POLICIES_PRES_BIT	0x080	// Bit 7
#define	X509EXT_SUBJ_ALTNAME_PRES_BIT	0x040	// Bit 6
#define	X509EXT_ISSUER_ALTNAME_PRES_BIT	0x020	// Bit 5
#define	X509EXT_BASIC_CONSTR_PRES_BIT	0x010	// Bit 4
#define	X509EXT_NAME_CONSTR_PRES_BIT	0x008	// Bit 3
#define	X509EXT_POLICY_CONSTR_PRES_BIT	0x004	// Bit 2
#define	X509EXT_EXT_KEYUSAGE_PRES_BIT	0x002	// Bit 1
#define	X509EXT_CRL_DISTPOINTS_PRES_BIT	0x001	// Bit 0

//==========================================================
// Flag Bistring Definition for X509 Extensions
// NOTE: All Flag Bitstrings use a BIT32 with Flags Left (MSB)
// ----- aligned. The LSB Bit is used to signal Presence !
//==========================================================

//---------------------------------------------------
// X509 Key usage Definitions, BITSTRING 9 Bits (X509.V3)
// also used for Private Key usage description
//---------------------------------------------------

#define	X509_KEYUSAGE_DIG_SIGNAT_BIT	0x80000000	// Bit 31 [ISO: Bit 0]
#define	X509_KEYUSAGE_NON_REPUD_BIT	0x40000000	// Bit 30 [ISO: Bit 1]
#define	X509_KEYUSAGE_KEY_ENC_BIT	0x20000000	// Bit 29 [ISO: Bit 2]
#define	X509_KEYUSAGE_DATA_ENC_BIT	0x10000000	// Bit 28 [ISO: Bit 3]
#define	X509_KEYUSAGE_KEY_AGREE_BIT	0x08000000	// Bit 27 [ISO: Bit 4]
#define	X509_KEYUSAGE_CERT_SIGN_BIT	0x04000000	// Bit 26 [ISO: Bit 5]
#define	X509_KEYUSAGE_CRL_SIGN_BIT	0x02000000	// Bit 25 [ISO: Bit 6]
#define	X509_KEYUSAGE_ENCR_ONLY_BIT	0x01000000	// Bit 24 [ISO: Bit 7]
#define	X509_KEYUSAGE_DECR_ONLY_BIT	0x00800000	// Bit 23 [ISO: Bit 8]
#define	X509_KEYUSAGE_VALID_MASK	0xFF800000	// Bit 31-23

#define	X509_KEYUSAGE_CRITICAL_BIT	0x00000002	// Bit 1
#define	X509_KEYUSAGE_VALID_BIT		0x00000001	// Bit 0
#define	X509_KEYUSAGE_USED_BITS		9

//---------------------------------------------------
// PKIX Extended Key usage Definitions (Key purpose)
//---------------------------------------------------

#define	PKIX_KEYPURP_SERVER_AUTH_BIT	0x00000001	// Bit  0 id-kp 1
#define	PKIX_KEYPURP_CLIENT_AUTH_BIT	0x00000002	// Bit  1 id-kp 2
#define	PKIX_KEYPURP_CODE_SIGN_BIT	0x00000004	// Bit  2 id-kp 3
#define	PKIX_KEYPURP_EMAIL_PROT_BIT	0x00000008	// Bit  3 id-kp 4
#define	PKIX_KEYPURP_IPSEC_ENDSYS_BIT	0x00000010	// Bit  4 id-kp 5
#define	PKIX_KEYPURP_IPSEC_TUNNEL_BIT	0x00000020	// Bit  5 id-kp 6
#define	PKIX_KEYPURP_IPSEC_USER_BIT	0x00000040	// Bit  6 id-kp 7
#define	PKIX_KEYPURP_TIME_STAMP_BIT	0x00000080	// Bit  7 id-kp 8
#define	PKIX_KEYPURP_OCSP_SIGN_BIT	0x00000100	// Bit  8 id-kp 9
#define	PKIX_KEYPURP_DVCS_BIT		0x00000200	// Bit  9 id-kp 10
#define	PKIX_KEYPURP_RESERVED_1_BIT	0x00000400	// Bit 10 id-kp 11
#define	PKIX_KEYPURP_RESERVED_2_BIT	0x00000800	// Bit 11 id-kp 12
#define	PKIX_KEYPURP_EAP_OVER_PPP_BIT	0x00001000	// Bit 12 id-kp 13
#define	PKIX_KEYPURP_EAP_OVER_LAN_BIT	0x00002000	// Bit 13 id-kp 14
#define	PKIX_KEYPURP_SCVP_SERVER_BIT	0x00004000	// Bit 14 id-kp 15
#define	PKIX_KEYPURP_SCVP_CLIENT_BIT	0x00008000	// Bit 15 id-kp 16

#define	PKIX_KEYPURP_USED_BITS		16
#define	PKIX_KEYPURP_VALID_BITS_MASK	0x0000F3FF	// ignore bit 10,11

#define	PKIX_KEYPURP_MIN_ID		0x01		// id-kp 1
#define	PKIX_KEYPURP_MAX_ID		0x10		// id-kp 16

//---------------------------------------------------
// X509 Extended Key usage definitions, collection of
// possible OID groups
//---------------------------------------------------

#define	X509_EXT_KEYUSAGE_PKIX_PRES_BIT	0x80000000	// Bit 31 PKIX found

#define	X509_EXT_KEYUSAGE_CRITICAL_BIT	0x00000002	// Bit 1
#define	X509_EXT_KEYUSAGE_VALID_BIT	0x00000001	// Bit 0

//--------------------------------------------------------------------
// X509 Basic Constraints, BOOLEAN: DEFAULT FALSE, True May Act as CA,
//			   INTEGER: PathLen [0..MAX]
//--------------------------------------------------------------------

#define	X509_BASICCONSTR_CA_FLAG_UNDEF	-1		// none given
#define	X509_BASICCONSTR_CA_FLAG	0x01		// may act as a CA
#define	X509_BASICCONSTR_CRIT_FLAG	0x02		// Bit 1 = 1-> Critical

#define	X509_BASICCONSTR_PATHLEN_UNDEF	-1		// none given
#define	X509_BASICCONSTR_PATHLEN_MIN	0		// minimal distance
#define	X509_BASICCONSTR_PATHLEN_MAX	0x7FFFFFFF	// maximal distance

//---------------------------------------------------
// Parameters for CRL Structure
//---------------------------------------------------

#define	INVALID_CRL_VERSION	-1
#define	CRL_VERSION_DEFAULT	0
#define	CRL_VERSION_V1		0
#define	CRL_VERSION_V2		1

#define	CRL_SIGNAT_INV_ALGOR		-4	// algors mismatch
#define	CRL_SIGNAT_NO_CERT		-3	// no certificate to verify
#define	CRL_SIGNAT_BAD			-2	// incorrect signature
#define	CRL_SIGNAT_NOT_VERIFIED		-1	// not yet checked
#define	CRL_SIGNAT_CHAIN_PROBLEM	0	// o.k. but cert chain error
#define	CRL_SIGNAT_VERIFY_OK		1	// o.k.

#define	CRL_REVOC_REASON_INVALID	-1	// not set
#define	CRL_REVOC_REASON_UNSPECIFIC	0	// not further specified
#define	CRL_REVOC_REASON_KEY_COMPR	1	// key compromise
#define	CRL_REVOC_REASON_CA_COMPR	2	// CA compromise
#define	CRL_REVOC_REASON_AFFIL_CHANGE	3	// affiliation changed
#define	CRL_REVOC_REASON_SUPERSEEDED	4	// ?
#define	CRL_REVOC_REASON_OP_CESSATION	5	// cessation of operation
#define	CRL_REVOC_REASON_CERT_HOLD	6	// cert on hold state
#define	CRL_REVOC_REASON_UNUSED		7	// not used
#define	CRL_REVOC_REASON_REMOVE_CRL	8	// ?

#define	CRLENT_EXT_UNRECOGN_CRIT_FLAG	0x01	// a critical extension...

#define	CRL_EXT_UNRECOGNIZED_CRIT_FLAG	0x01	// unrecognized critical...
#define	CRL_EXT_IS_DISTR_POINT_FLAG	0x02	// is from a distribution point
#define	CRL_EXT_ONLY_USER_CERTS_FLAG	0x04	// Only user certs in CRL
#define	CRL_EXT_ONLY_CA_CERTS_FLAG	0x08	// Only CA certs in CRL
#define	CRL_EXT_INDIRECT_CRL_FLAG	0x10	// Is an indirect CRL

#define	CRL_EXT_DIST_POINT_REASON_BITS	7	// only 7 bits used !!

#define	CRL_EXT_KEY_COMPROMISE_FLAG	0x4000	// has key compromise entries
#define	CRL_EXT_CA_COMPROMISE_FLAG	0x2000	// has CA compromise entries
#define	CRL_EXT_AFFIL_CHANGED_FLAG	0x1000	// has affil. changed entries
#define	CRL_EXT_KEY_SUPERSEEDED_FLAG	0x0800	// has superseeded entries
#define	CRL_EXT_OP_CESSATION_FLAG	0x0400	// has cessation of op. entries
#define	CRL_EXT_CERT_HOLD_FLAG		0x0200	// has cert hold entries

//-----------------------------------------------------------------------------
// OIDs
//-----------------------------------------------------------------------------

//-------------------------------------------
// OID Definitions 
//-------------------------------------------

#define OID_X520_COMMON_NAME				0
#define OID_X520_SURNAME				1
#define OID_X520_COUNTRY_NAME				2
#define OID_X520_LOCALITY_NAME				3
#define OID_X520_STATE_OR_PROVINCE_NAME			4
#define OID_X520_STREET_ADDRESS				5
#define OID_X520_ORGANIZATION_NAME			6
#define OID_X520_ORGANIZATION_UNIT_NAME			7
#define OID_X520_TITLE					8
#define OID_X520_POSTAL_CODE				9
#define OID_X520_PHONE_NUMBER				10
#define OID_X520_NAME					11
#define OID_X520_GIVEN_NAME				12
#define OID_X520_INITIALS				13
#define OID_X520_GENERATION_QUALIFIER			14
#define OID_X520_DIST_NAME_QUALIFIER			15
#define OID_X509_EXT_SUBJ_DIR_ATTS			16
#define OID_X509_EXT_SUBJ_KEY_ID			17
#define OID_X509_EXT_KEY_USAGE				18
#define OID_X509_EXT_PRIV_KEY_USAGE			19
#define OID_X509_EXT_SUBJ_ALT_NAME			20
#define OID_X509_EXT_ISSUER_ALT_NAME			21
#define OID_X509_EXT_BASIC_CONSTR			22
#define OID_X509_EXT_CRL_NUMBER				23
#define OID_X509_EXT_REASON_CODE			24
#define OID_X509_EXT_INSTRUCTION_CODE			25
#define OID_X509_EXT_INVALIDY_DATE			26
#define OID_X509_EXT_DELTA_CRL_IND			27
#define OID_X509_EXT_ISS_DISTR_POINT			28
#define OID_X509_EXT_CERT_ISSUER			29
#define OID_X509_EXT_NAME_CONSTR			30
#define OID_X509_EXT_CRL_DISTR_POINTS			31
#define OID_X509_EXT_CERT_POLICIES			32
#define OID_X509_EXT_CERT_POLICY_MAP			33
#define OID_X509_EXT_AUTH_KEY_ID			34
#define OID_X509_EXT_POLICY_CONSTR			35
#define OID_X509_EXT_EXT_KEY_USAGE			36
#define OID_OIW_DSA_SIGNAT_ALGOR			37
#define OID_OIW_DSA_WITH_SHA				38
#define OID_OIW_DSA_WITH_SHA1				39
#define OID_OIW_RSA_WITH_SHA1				40
#define OID_TELESEC_RIPEMD_ALGOR			41
#define OID_TELESEC_RSA_WITH_RIPEMD160			42
#define OID_X957_HOLD_INSTR_NONE			43
#define OID_X957_HOLD_INSTR_CALL_ISS			44
#define OID_X957_HOLD_INSTR_REJECT			45
#define OID_X957_DSA_SIGNAT_ALGOR			46
#define OID_X957_DSA_WITH_SHA1				47
#define OID_X942_DH_PUBL_NUMBER				48
#define OID_NIST_ALGORS					49
#define OID_PKIX_EXT_AUTH_INFO_ACCESS			50
#define OID_PKIX_KEYPURP_SERVER_AUTH			51
#define OID_PKIX_KEYPURP_CLIENT_AUTH			52
#define OID_PKIX_KEYPURP_CODE_SIGN			53
#define OID_PKIX_KEYPURP_EMAIL_PROTECT			54
#define OID_PKIX_KEYPURP_IPSEC_ENDSYS			55
#define OID_PKIX_KEYPURP_IPSEC_TUNNEL			56
#define OID_PKIX_KEYPURP_IPSEC_USER			57
#define OID_PKIX_KEYPURP_TIME_STAMPING			58
#define OID_PKIX_KEYPURP_OCSP_SIGNING			59
#define OID_PKIX_KEYPURP_DVCS				60
#define OID_PKIX_KEYPURP_EAP_OVER_PPP			61
#define OID_PKIX_KEYPURP_EAP_OVER_LAN			62
#define OID_PKIX_KEYPURP_SCVP_SERVER			63
#define OID_PKIX_KEYPURP_SCVP_CLIENT			64
#define OID_PKCS1_RSA_ENCRYPTION			65
#define OID_PKCS1_MD2_WITH_RSA_ENC			66
#define OID_PKCS1_MD5_WITH_RSA_ENC			67
#define OID_PKCS1_SHA1_WITH_RSA_ENC			68
#define OID_PKCS1_SHA256_WITH_RSA_ENC			69
#define OID_PKCS1_SHA384_WITH_RSA_ENC			70
#define OID_PKCS1_SHA512_WITH_RSA_ENC			71
#define OID_PKCS1_SHA224_WITH_RSA_ENC			72
#define OID_PKCS3_DH_KEY_AGREEMENT			73
#define OID_PKCS5_PBE_MD2_DES_CBC			74
#define OID_PKCS5_PBE_MD5_DES_CBC			75
#define OID_PKCS5_PBE_SHA1_DES_CBC			76
#define OID_PKCS7_DATA					77
#define OID_PKCS7_SIGNED_DATA				78
#define OID_PKCS9_EMAIL_ADDRESS				79
#define OID_NIST_SHA256_ALGOR				80
#define OID_NIST_SHA384_ALGOR				81
#define OID_NIST_SHA512_ALGOR				82
#define OID_NIST_SHA224_ALGOR				83
#define OID_MICROSOFT_DOMAIN_COMPONENT			84

#define MAX_OID_COUNT	85

//-------------------------------------------
// OID Group Definitions 
//-------------------------------------------

#define GRP_ALGOR_ID					0
#define GRP_X520_ATT					1
#define GRP_X520_EXT_ATT				2
#define GRP_X509_EXT_ATT				3
#define GRP_CRL_ENTRY_EXT				4
#define GRP_PKCS7_ATT					5
#define GRP_PKIX_KEY_PURPOSE				6

#define MAX_GRP_COUNT	7

//-------------------------------------------
// OID Group Size Definitions 
//-------------------------------------------

#define GRP_ALGOR_ID_CNT				26
#define GRP_X520_ATT_CNT				16
#define GRP_X520_EXT_ATT_CNT				2
#define GRP_X509_EXT_ATT_CNT				22
#define GRP_CRL_ENTRY_EXT_CNT				3
#define GRP_PKCS7_ATT_CNT				2
#define GRP_PKIX_KEY_PURPOSE_CNT			14
//-------------------------------------------
// Purpose Mask Definitions 
//-------------------------------------------

#define PURP_KEY_EXCHG_ALGOR				0x01
#define PURP_PUBLIC_ENCR_ALGOR				0x02
#define PURP_SIGNAT_ALGOR				0x04
#define PURP_SIGNAT_TYPE_AND_ALGOR			0x08
#define PURP_PASSWD_SIGNAT_TYPE_AND_ALG			0x10
#define PURP_PUBLIC_VALUE_ALGOR				0x20
#define PURP_PRIVATE_VALUE_ALGOR			0x40
//-------------------------------------------
// Language Definitions 
//-------------------------------------------

#define OID_LANGUAGE_English				0
#define OID_LANGUAGE_German				1

#define	OID_MAX_LANGUAGES				2

//------------------------------------------------------
// Types from decoding of encapsulated data
//------------------------------------------------------

#define PKCS10_DATA_TYPE	0
#define X509_DATA_TYPE		1
#define PKCS7_DATA_TYPE		2
#define PEM_REQ_DATA_TYPE	3
#define PEM_REPLY_DATA_TYPE	4
#define PEM_DATA_TYPE		5		// unspecified
#define	PKCS12_DATA_TYPE	6		// V1 / V3
#define	RSA_PRIVKEY_DATA_TYPE	7		// SSLEAY
#define	DSA_PRIVKEY_DATA_TYPE	8		// SSLEAY
#define B64_UNKNOWN_DATA_TYPE	-1		// NOTE: was formerly 6

//--------------------------------------------------------
// Chain Verification Status Codes (BIT-Encoded !)
// If all bits cleared usable with no restrictions.
// Either severity of restrictions depends on lowest bit set !
// NOTE: Do not change meaning of Bits 0-7 !
//--------------------------------------------------------

#define	ASN1_ENDCERT_USABLE		0x00000	// no restrictions

#define ASN1_ENDCERT_NOT_USABLE_MASK	0x00001	// is not usable
#define	ASN1_ENDCERT_NO_TRUST_ROOT	0x00002	// not trusted root
#define	ASN1_ENDCERT_REVOKED		0x00004	// revoked
#define	ASN1_ENDCERT_REVOKSTATE_UNKNOWN	0x00008	// revocation state not known

#define ASN1_ENDCERT_ROOT_TIMEOUT	0x00010	// root has timed out
#define ASN1_ENDCERT_CHAIN_ELEM_TIMEOUT 0x00020	// Element timeout
#define ASN1_ENDCERT_EXPIRED		0x00040	// End Cert expired
#define ASN1_ENDCERT_NOT_YET_VALID	0x00080	// End Cert not yet

#define	ASN1_ENDCERT_TIMEOUT_MASK	0x000F0	// 4 States

#define	ASN1_ENDCERT_NO_ROOT		0x00100	// no Root in chain
#define	ASN1_ENDCERT_SELFS_NOT_ALLOWED	0x00200	// found a selfsigned end/sub.
#define	ASN1_ENDCERT_CHAIN_BROKEN	0x00400	// issuer/subject match fail
#define	ASN1_ENDCERT_BASIC_CONSTR_FAIL	0x00800	// basic constraints violation
#define	ASN1_ENDCERT_SIGNAT_NOT_CHECKED	0x01000	// signature not checkable
#define	ASN1_ENDCERT_SIGNAT_FAIL	0x02000	// signature invalid
#define	ASN1_ENDCERT_KEYUSAGE_INVALID	0x04000	// key usage not for signing
#define	ASN1_ENDCERT_VALIDITY_INVALID	0x08000	// misformed validity
#define	ASN1_ENDCERT_OCSP_UNTRUSTED	0x10000	// no trusted responses OCSP
#define	ASN1_ENDCERT_OCSP_UNKNOWN	0x20000 // OCSP status unknown
#define	ASN1_ENDCERT_OCSP_REVOKED_CHAIN	0x40000	// One/More definitely revoked

#define	ASN1_ENDCERT_WTS_GENERATED_CERT	0x80000	// Encounterd a certificate generated by WTS

#define ASN1_ENDCERT_POLICY_MASK    0x800FF // Mask for policy-based bits
#define	ASN1_ENDCERT_CRITICAL_MASK	0x7FF00	// Critical Bits

//-----------------------------------------------------------
// Certificate ID structure used in requests and responses
//-----------------------------------------------------------

/** @addtogroup hocsp
*@{
*/
/**
* This structure is an internal representation for the OCSP CertID ASN.1 encoding.
*/
typedef struct HOCSCID_t {
	IDATPARR*	HashAlgor;	//!< Hash type/params
	IDATPARR*	IssuerNameHash;	//!< Hash of issuer's DN DER encoding
	IDATPARR*	IssuerKeyHash;	//!< Hash of issuer's public key field
	IDATPARR*	SerialNumber;	//!< Serial number from certificate
	int		HashAlgorType;	//!< Internal ID of the hash algorithm
	int		ResponseID;	//!< Forward link in request list
} HOCSCID;

/** @} */

//---------------------------------------------------------------
// Structure used for an OCSP request to check the response later
//---------------------------------------------------------------

#define	HOCSP_REQ_WAS_SIGNED_BIT	0x01	// sent a signed request

/** @addtogroup hocsp
*@{
*/
/**
* This structure is an internal representation for the OCSP request ASN.1 encoding.
*/
typedef struct HOCSREQ_t {
	HOCSCID ** pCertIdList;		//!< List of cert IDs
	int	CertIdCount;			//!< Number of IDs in list
	int	HashAlgorType;			//!< Type of hashing algor
	char*	pNonceData;			//!< Nonce data sent to server
	int	NonceDataLen;			//!< Size of nonce data

	IDATPARR* RequestorName;		//!< Requestor name (DER)
	IDATPARR* RequestList;		//!< List of requests (DER)
	IDATPARR* RequestExt;		//!< Extensions
	IDATPARR* Signature;			//!< Signature

	IDATPARR* OCSPRequest;		//!< ASN.1 encoded request

	X509CERT * pSignerCert;			//!< Certificate for signing
	int	SignatType;			//!< Type of signature
	int	Flags;				//!< Additional status
} HOCSREQ;

/** @} */

//-----------------------------------------------------------
// Single response structure
//-----------------------------------------------------------

/** @addtogroup hocsp
*@{
*/
/**
* This structure is an internal representation for the OCSP SingleResponse ASN.1 encoding.
*/
typedef struct HOCSRSP_t {
	HOCSCID * pCertID;		//!< CertID structure
	int	CertStatus;			//!< Status of cert
	int	ReliabilityStatus;		//!< If a bit is set->unreliable
	int	RequestID;			//!< ID (index) of associated REQ
	int*	pRevocationTimeArr;		//!< Revocation time (OPT.)
	int	RevocationReason;		//!< Reason of revocation (OPT.)
	int*	pThisUpdateTimeArr;		//!< This update time
	int*	pNextUpdateTimeArr;		//!< Next update time (OPT.)
	IDATPARR* pSingleExtensions;		//!< Single extensions (OPT.)
} HOCSRSP;

/** @} */

//---------------------------------------------------------------
// Structure used for the OCSP Response (with BasicResponse Data)
//---------------------------------------------------------------

/** @addtogroup hocsp
*@{
*/
/**
* This structure is an internal representation for the OCSP Response ASN.1 encoding.
*/
typedef struct HOCRESP_t {
	int		ResponseStatus;		//!< Primary status returned
	int		ReliabilityStatus;	//!< Reliability bits etc.
	IDATPARR*	pTBSResponse;		//!< Start/Size of raw response
	int		Version;		//!< Response version
	IDATPARR*	pResponderName;		//!< Raw responder name, copy
	X501_DN*	pResponderDNName;	//!< DN of responder
	char*		pResponderKeyHash;	//!< Public key hash of responder
	int		ResponderIDType;	//!< Type of responder ident.
	int*		pProducedAtTime;	//!< Time array
	HOCSRSP ** pResponseList;		//!< List of responses
	int		ResponseCount;		//!< Number of responses in list
	IDATPARR*	pSignatAlgor;		//!< Signature type/params
	int		SignatAlgor;		//!< Decoded signature algorithm
	int		SignatType;		//!< Decoded signature type
	IDATPARR*	pSignature;		//!< Signature
	int		SignatVerifyState;	//!< Verification state
	int		SignatChainResult;	//!< Signature cert chain check
	int		SignatChainReason;	//!< Signature cert chain check
	X509CERT **	pCertList;		//!< List of certificates
	int		CertsCount;		//!< Number of certificates
	IDATPARR*	pResponseExts;		//!< Response extensions
	char*		pNonceData;		//!< Nonce from sender
	int		NonceDataLen;		//!< Size of nonce data
} HOCRESP;

/** @} */
/** @addtogroup hocsp
* @{
*/
/**
* This structure is used to manage the OCSP context in the WSP C interface.
*/
typedef struct XH_OCSP_STRUC_t {
    int (* amc_ocsp_start)(void * vpp_userfld,
			   struct dsd_hl_ocsp_d_1 * pXhOcspConnStruc); //!< Connect to OCSP destination
    int (* amc_ocsp_send)(void * vpp_userfld, char * achp_buf, int inp_len); //!< Send data to OCSP dest
    struct dsd_hl_ocsp_rec * (* amc_ocsp_recv)(void * vpp_userfld); //!< Receive data from OCSP dest
    void (* amc_ocsp_stop)(void * vpp_userfld); //!< Disconnect from OCSP destination

    void *  pOcspCtxStruc;		//!< Context for OCSP functions
    ds__hmem * pMemCtxStruc;		//!< Context for memory allocation
    void *  pTestHlpCtxStruc;		//!< Context for tester TCP interface

    struct dsd_hl_ocsp_d_1 * pActOcspConnStruc; //!< Structure for connect

    int     ConnectedFlag;		//!< If <> 0 then connected
    struct dsd_hl_ocsp_rec * pRxStruc;	//!< Must be freed if no longer needed
    char* pRxBuf;			//!< Receive buffer, do NOT free !
    int     ActRxDataLen;		//!< Amount of data in buffer
    int     ActRxDataIndex;		//!< Index to next byte in buffer

    int reserved;
} XH_OCSP_STRUC;

/** @} */
//-----------------------------------------------------------------
// Control structure for OCSP chain verification checking
//-----------------------------------------------------------------

/** @addtogroup hocsp
*@{
*/
/**
* This structure is the control structure used for OCSP certificate chain checking.
*/
typedef struct HOCSPPAR_t {
	char*	pResponderUrls;			//!< Multi ASCIIz string
	int	ResponderUrlsOff;		//!< Start of data
	int	ResponderUrlsLen;		//!< Size of data, optional
	X509CERT ** pCertList;			//!< List of certificates
	int	CertsCount;			//!< Number of certs in list
	CTREESTR * pCertTree;			//!< Tree, used for completeing
	int	ProcessFlags;			//!< Processing flags
	int	HashAlgorType;			//!< Type of algorithm to use
	X509CERT * pSignerCert;			//!< Certificate for signing REQ
	int	SignatType;			//!< Type of signature for REQ
	int	TimeTolerance;			//!< +/- Tolerance in minutes
	int	ResponseStatusBits;		//!< Total response status
#if defined XH_INTERFACE
	ds__hmem * pMemCtxStruc;		//!< Allocation context structure
	XH_OCSP_STRUC * pOcspCtxStruc;		//!< OCSP context structure
	struct dsd_hl_ocsp_d_1 * pXhConnStrucList; //!< Configuration to use
#endif
} HOCSPPAR;

//-----------------------------------------------------------
// Miscellaneous parameters
//-----------------------------------------------------------

#define	OCSP_DEFAULT_TIME_TOLERANCE	240	// 4 hours (summertime etc.)

/** @addtogroup hocsp
*@{
*/
#define	OCSP_PROC_FLAG_DONT_SIGN	0x01	//!< inhibit signing anyway
#define	OCSP_PROC_FLAG_NO_REQ_NONCE	0x02	//!< do not send Req. Nonce data
#define	OCSP_PROC_FLAG_MISSING_NONCE_OK	0x04	//!< no response Nonce needed
#define	OCSP_PROC_FLAG_NO_COMPL_CHAIN	0x08	//!< do not send complete chain
#define	OCSP_PROC_FLAG_SORT_RESP_DN	0x10	//!< sort responder DN
#define	OCSP_PROC_FLAG_IGNORE_PROD_AT	0x20	//!< ignore producedAT time
/** @} */

#define	OCSP_RESP_STATUS_INVALID	-1
#define	OCSP_RESP_STATUS_SUCCESS	0
#define	OCSP_RESP_STATUS_MALFORMED_REQ	1
#define	OCSP_RESP_STATUS_INTERNAL_ERR	2
#define	OCSP_RESP_STATUS_TRY_LATER	3
#define	OCSP_RESP_STATUS_UNUSED		4	// is invalid !!
#define	OCSP_RESP_STATUS_SIGN_REQUIRED	5
#define	OCSP_RESP_STATUS_UNAUTHORIZED	6

#define	OCSP_RESP_VERSION_INVALID	-1
#define	OCSP_RESP_VERSION_DEFAULT	0	// is V1
#define	OCSP_RESP_VERSION_V1		0	// is V1

#define	OCSP_RESP_RESPONDER_ID_INVALID	-1
#define	OCSP_RESP_RESPONDER_ID_BYNAME	0
#define	OCSP_RESP_RESPONDER_ID_BYKEY	1

#define	OCSP_RESP_SIGNAT_INV_ALGOR	-4	// algors mismatch
#define	OCSP_RESP_SIGNAT_NO_CERT	-3	// no certificate to verify
#define	OCSP_RESP_SIGNAT_BAD		-2	// incorrect signature
#define	OCSP_RESP_SIGNAT_NOT_VERIFIED	-1	// not yet checked
#define	OCSP_RESP_SIGNAT_CHAIN_PROBLEM	0	// o.k. but cert chain error
#define	OCSP_RESP_SIGNAT_VERIFY_OK	1	// o.k.

#define	OCSP_NONCE_SIZE		16

#define	OCSP_CERT_STATUS_INVALID	-1
#define	OCSP_CERT_STATUS_GOOD		0
#define	OCSP_CERT_STATUS_REVOKED	1
#define	OCSP_CERT_STATUS_UNKNOWN	2

#define	OCSP_REVOC_REASON_INVALID	-1	// not set
#define	OCSP_REVOC_REASON_UNSPECIFIC	0	// not further specified
#define	OCSP_REVOC_REASON_KEY_COMPR	1	// key compromise
#define	OCSP_REVOC_REASON_CA_COMPR	2	// CA compromise
#define	OCSP_REVOC_REASON_AFFIL_CHANGE	3	// affiliation changed
#define	OCSP_REVOC_REASON_SUPERSEEDED	4	// ?
#define	OCSP_REVOC_REASON_OP_CESSATION	5	// cessation of operation
#define	OCSP_REVOC_REASON_CERT_HOLD	6	// cert on hold state
#define	OCSP_REVOC_REASON_UNUSED	7	// not used
#define	OCSP_REVOC_REASON_REMOVE_CRL	8	// ?

#define	OCSP_REQUEST_ID_INVALID		-1
#define	OCSP_RESPONSE_ID_INVALID	-1

//-----------------------------------------------------------
// Hash algorithm types for OCSP
//-----------------------------------------------------------

#define	OCSP_HASH_ALGOR_UNKNOWN		-1
#define	OCSP_HASH_ALGOR_SHA1		0

//-----------------------------------------------------------
// Response / Request matching results
//-----------------------------------------------------------

#define	OCSP_RESP_MATCH_OK		1	// match succesful
#define	OCSP_RESP_MATCH_UNKNOWN		0	// matching not yet done
#define	OCSP_RESP_MATCH_DIFFERENT_CNT	-1	// less/more responses than req.
#define	OCSP_RESP_MATCH_DUPLICATE	-2	// found duplicate response
#define	OCSP_RESP_MATCH_NOT_ALL_MATCHED	-3	// unsolicited request(s)

//-----------------------------------------------------------
// Single Response reliability status bits
//-----------------------------------------------------------

#define	OCSP_UNRELIABLE_THIS_UPD_A_BIT	0x01	// Bit 0 ThisUpdate >= CurTime
#define	OCSP_UNRELIABLE_THIS_UPD_B_BIT	0x02	// Bit 1 ThisUpdate >= ProdAt

#define	OCSP_UNRELIABLE_NEXT_UPD_A_BIT	0x04	// Bit 2 NextUpdate < CurTime
#define	OCSP_UNRELIABLE_NEXT_UPD_B_BIT	0x08	// Bit 3 NextUpdate < ProdAt

//-----------------------------------------------------------
// Total Response status bits: trustable,reliable etc.
//-----------------------------------------------------------
/** @addtogroup hocsp
*@{
*/
#define	OCSP_NO_RESPONSE_BIT		0x001	//!< Bit 0 no response/error
#define	OCSP_RESPONSE_UNSUCCESSFUL_BIT	0x002	//!< Bit 1 unsuccesful response
#define	OCSP_UNTRUSTED_SIGNATURE_BIT	0x004	//!< Bit 2 Signature not verified
#define	OCSP_UNTRUSTED_NONCE_BIT	0x008	//!< Bit 3 nonce missing/bad_
#define	OCSP_UNRELIABLE_PRODUCED_AT_BIT	0x010	//!< Bit 4 prodAt out of range
#define	OCSP_UNRELIABLE_MATCH_A_BIT	0x020	//!< Bit 5 not same Req/Resp
#define	OCSP_UNRELIABLE_MATCH_B_BIT	0x040	//!< Bit 6 not all matched
#define	OCSP_UNRELIABLE_MATCH_C_BIT	0x080	//!< Bit 7 duplicate
#define	OCSP_UNRELIABLE_MATCH_D_BIT	0x100	//!< Bit 8 no match processed
#define	OCSP_SRESP_UNRELIABLE_BIT	0x200	//!< Bit 9 one/more resp. unrel.
#define	OCSP_SRESP_UNKNOWN_BIT		0x400	//!< Bit 10 one/more unknown
#define	OCSP_SRESP_REVOKED_BIT		0x800	//!< Bit 11 one/more revoked
/** @} */

#define	OCSP_RELIABILITY_CHECK_MASK1	0x3FF	// Bit 0-9
#define	OCSP_RELIABILITY_CHECK_MASK2	0x7FF	// Bit 0-10
#define	OCSP_RELIABILITY_CHECK_MASK3	0x1EF	// Bit 0-3,4-8

#define	OCSP_RELIABILITY_STATUS_MASK	0x0FFF	// Bit 0-11

//-----------------------------------------------------------
// Certificate ID matching results
//-----------------------------------------------------------

#define	OCSP_SAME	0
#define	OCSP_NOT_SAME	1

/** @addtogroup http
* @{
* @file
* This header defines structures, used by the HTTP module.
*/
/**
* This structure implements the data equivalent of the JAVA URL class as a C 
* structure.
*/
typedef struct URL_STRUC_t {
	char* pFullUrl;			//!< Copy of Raw URL
	char*	pProtocol;			//!< Name of Protocol
	char*	pHost;				//!< Name of host to connect to
	int	PortNr;				//!< Destination port number
	char* pFile;				//!< File portion (path+query)
	char*	pQuery;				//!< Query portion of URL
	char*	pAuthority;			//!< Host + Port part
	char*	pPath;				//!< The path to the URL
	char*	pReference;			//!< Loacal reference part
} URL_STRUC;

#if !defined __NOSTRLIB__

#if !defined SOCKET && !defined WIN64 && !defined EM64T
#define  SOCKET   int
#endif

typedef struct SADDRIN_t SADDRIN;
typedef struct HTTP_MSG_HDRS_t HTTP_MSG_HDRS;
/**
* This structure implements the data element equivalent of the JAVA HttpURLConnection
* class as a C structure.
*/
typedef struct HTTP_URLCONN_t {
	URL_STRUC * pUrlStruc;			//!< The URL
	SADDRIN * pHostAddress;		//!< IP-Address of host (server)
	int	doInput;			//!< <> 0 allow Input from serv.
	int	doOutput;			//!< <> 0 allow Output to server
	SOCKET	HttpSocket;			//!< Connection socket
	int	Connected;			//!< <> 0 -> connected
        int	ClosedFlag;			//!< <> 0 -> socket closed
	int	FailedOnce;			//!< Not used
	int	ResponseStatusCode;		//!< Response status
	char*	pResponseStatusMsg;		//!< Response status message
	char*	pRequestMethod;			//!< Request method
	int	RequestsSetFlag;		//!< <> 0 -> Request initialized
	HTTP_MSG_HDRS * pRequestHdrsStruc;	//!< Request headers structure
	HTTP_MSG_HDRS * pResponseHdrsStruc;	//!< Response headers structure
	char*	pRequestData;			//!< Request message data
	int	RequestDataLen;			//!< Size of Request message data
#if defined XH_INTERFACE
	XH_OCSP_STRUC * pXhOcspStruc;		//!< Structure for XH-interface
#endif	
} HTTP_URLCONN;

/** @} */
#ifdef XH_INTERFACE

#ifndef DEF_HL_OCSP_D_1
#define DEF_HL_OCSP_D_1
/** HOBLink OCSP definition */
struct dsd_hl_ocsp_d_1 {
   struct dsd_hl_ocsp_d_1 *adsc_next;       /**< Next in chain           */
   char       *achc_url;                    /**< URL of OCSP responder   */
   int        inc_url_len;                  /**< Length URL              */
};
#endif

#ifndef DEF_HL_OCSP_REC
#define DEF_HL_OCSP_REC
/** HOBLink OCSP received. The received data are directly behind
* this structure in memory.   */
struct dsd_hl_ocsp_rec {
   int        inp_data_len;                 /**< length data received    */
   /**< zero = end of connection,
   -1 (or < 0) is error    */
};
/** @} */

//----------------------------------------------------------------
// Helper structure for XH interface tester TCP functions 
//----------------------------------------------------------------
/** @addtogroup hocsp
* @{
*/
/**
* This is a helper structure for the TCP functions.
*/
typedef struct XH_TCP_HLP_STRUC_t {
	ds__hmem * pMemCtxStruc;		//!< alloc/free structure
	SOCKET	   TcpSocket;			//!< connected socket
        int	   ConnectedFlag;		//!< <> 0 -> connected
} XH_TCP_HLP_STRUC;
/** @} */
#endif
#endif // XH_INTERFACE

#endif // !defined __NOSTRLIB__

#if defined _WIN32
#if !defined C_OUT
#include <winsock.h>
#endif // C_OUT

#define	SOCKLEN_T	int
#define	SA_FAMILY_T	short
#endif

#if !defined C_OUT
#include <stdlib.h>
#endif // C_OUT

//-------------------------------------------------------------
// Includes for the UNIX systems
//-------------------------------------------------------------

#if !defined C_OUT
#if !defined HL_HPUX && !defined HL_OPENUNIX && !defined HL_FREEBSD && !defined HL_MACOS
#include <time.h>
#else
#include <sys/time.h>
#include <netinet/in.h>
#endif
#endif // C_OUT

#if defined HL_LINUX || defined HL_SOLARIS || defined HL_HPUX || defined HL_FREEBSD || defined HL_OPENUNIX || defined HL_MACOS

#define	UNIX
#if !defined C_OUT
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#if !defined HL_HPUX && !defined HL_LINUX
#include <sys/filio.h>
#endif
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#endif // C_OUT

#if !defined SOCKET_ERROR
#define	SOCKET_ERROR	-1
#endif

#if defined HL_HPUX || defined HL_OPENUNIX
#if defined HL_HPUX
#define	SOCKLEN_T int
#else // OPENUNIX
#define	SOCKLEN_T size_t
#define	AI_NUMERICHOST	0x04
#endif
#else // not HPUX / OPENUNIX
#define	SOCKLEN_T socklen_t
#endif

#define	SA_FAMILY_T	sa_family_t

#endif // SOLARIS , HPUX, OPENUNIX

#if defined HL_LINUX || defined HL_AIX || defined HL_FREEBSD || defined HL_MACOS
#define	UNIX

#if !defined C_OUT
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#endif // C_OUT

#if defined SOCKLEN_T
#undef SOCKLEN_T
#endif
#define	SOCKLEN_T	socklen_t

#define	SA_FAMILY_T	sa_family_t

#if !defined SOCKET_ERROR
#define	SOCKET_ERROR	-1
#endif
#endif // LINUX_GNU

#define	MAX_ADDRIN_SIZE		16

#if !defined SOCKET && !defined WIN64 && !defined EM64T
//#define	SOCKET	int
#endif

#define	SRVR_SOCKET	SOCKET
#define	SRVR_SOCKET_PTR	SOCKET *

#if !defined AF_UNSPEC
#define	AF_UNSPEC	0
#define	PF_UNSPEC	0
#define	AF_INET		2
#define	PF_INET		2
#endif

#if !defined AF_INET6
#define	AF_INET6	26
#define	PF_INET6	26
#endif

#if !defined IPPROTO_IP
#define IPPROTO_IP	0
#define	IPPROTO_TCP	6
#define	IPPROTO_UDP	17
#endif

#if !defined IPPROTO_IPV6
#define IPPROTO_IPV6	41
#endif

#if !defined SOCK_STREAM
#define	SOCK_STREAM	1
#define	SOCK_DGRAM	2
#define	SOCK_RAW	3
#endif

#define SOCK_OPT_REUSEADDR	1
#define	SOCK_OPT_KEEPALIVE	2
#define	SOCK_OPT_LINGER		3
#define	SOCK_OPT_TCP_NODELAY	4

#if !defined BOOL
#define	BOOL int
#endif

#if !defined INADDR_ANY
#define	INADDR_ANY	0x00000000
#define	INADDR_NONE	0xFFFFFFFF
#endif

#define	IPV4_ADRLEN	4
#define	IPV6_ADRLEN	16

#define	INET_ADDRSTRLEN	16	// inclusive NUL, ddd.ddd.ddd.dddNUL
#define	INET6_ADDRSTRLEN 46	// incl. NUL xxxx:......:ddd.ddd.ddd.dddNUL

#if !defined INVALID_SOCKET
#define	INVALID_SOCKET	-1
#endif

// from new IPV6 interface

#if !defined AI_PASSIVE
#define	AI_PASSIVE	0x08
#define	AI_CANONNAME	0x10
#define	AI_NUMERICHOST	0x20

#define EAI_ADDRFAMILY	1
#define EAI_AGAIN	2
#define EAI_BADFLAGS	3
#define EAI_FAIL	4
#define EAI_FAMILY	5
#define EAI_MEMORY	6
#define EAI_NODATA	7
#define EAI_NONAME	8
#define EAI_SERVICE	9
#define EAI_SOCKTYPE	10
#define EAI_SYSTEM	11
#else	// all defined but FREE_BSD has missing definitions
#if !defined EAI_ADDRFAMILY
#define EAI_ADDRFAMILY	1
#endif
#if !defined EAI_NODATA
#define EAI_NODATA	7
#endif
#endif

#if !defined NI_NOFQDN
#define	NI_NOFQDN	0x01
#define	NI_NUMERICHOST	0x02
#define	NI_NAMEREQD	0x04
#define	NI_NUMERICSERV	0x08
#define	NI_DGRAM	0x10
#endif

#if !defined NI_MAXHOST
#define	NI_MAXHOST	1025
#define	NI_MAXSERV	32
#endif

//--------------------------------------------------------------
// Address Info structure
//--------------------------------------------------------------

/** @addtogroup util
* @{
*/
/**
* This structure is used to represent an IPV4/IPV6 address info structure.
*/
typedef struct ADDRINF_t {
	int	Flags;			//!< Passive | canonname
	int	AdrFamily;		//!< AF_INET/AF_INET6
	int	SockType;		//!< STREAM/DGRAM
	int	Protocol;		//!< IPPROTO_IP/IPPROTO_IPV6
	int	AdrLen;			//!< 4/16
	char*	pCanonName;		//!< ASCIIz string
	SADDRIN * pSockAdr;		//!< Address structure
	struct ADDRINF_t * pNext;	//!< Next structure pointer
} ADDRINF;

//--------------------------------------------------------------
// Inet Socket Address Structure
//--------------------------------------------------------------

/** @addtogroup util
* @{
*/
/**
* This structure is used to represent internet socket addresses.
*/
typedef struct SADDRIN_t {
	int	AdrFamily;			//!< AF_INET/AF_INET6
	int	AdrLen;				//!< length of address
	int	Port;				//!< Port (16 bit)
	char InetAdr[MAX_ADDRIN_SIZE];	//!< Address, BIG endian
} SADDRIN;

/** @} */

//--------------------------------------------------------------
// HostEntry structure
//--------------------------------------------------------------

/** @addtogroup util
* @{
*/
/**
* This structure is used to represent a host entry.
*/
typedef struct HSTENT_t {
	char*	pHostName;	//!< ASCIIz name of host, normally DNS-name
	char** pAliasArr;	//!< Array of ASCIIz alias names
	int	AliasNamesCnt;	//!< Number of entries
	int	AdrFamily;	//!< Address family
	int	AdrLen;		//!< Size of addresses
	int	AdrCnt;		//!< Number of addresses
	char** pAdrArr;	//!< Address array
}HSTENT;

/** @addtogroup http
* @{
* @file
* This header defines the special message header structure, used by the 
* HTTP module.
*/
/**
* This structure is used to hold HTTP message request/response headers for 
* HTTP message exchanges.
*/
typedef struct HTTP_MSG_HDRS_t {
	char** pFieldNameArr;		//!< Array of the field names ('keys')
	char** pFieldValueArr;	//!< Array of the field values
	int	UsedSlots;		//!< Number of elements currently in use
	int	AllocedSlots;		//!< Number of elements allocated
}HTTP_MSG_HDRS;

/**@}*/

#define	CR_CHAR		0x0D
#define	LF_CHAR		0x0A
#define	HTAB_CHAR	0x09
#define	SPC_CHAR	0x20
#define	COLON_CHAR	0x3A

#define	HTTP_HEADER_TIMEOUT	60	// 1 minute
#define	LINE_BUF_DEFAULT_LEN	80

#define	DEFAULT_HTTP_PORT		80
#define	DEFAULT_HTTP_CONNECT_RETRY_CNT	1

//-------------------------------------------------------
// Typedefs for Prototyping
//-------------------------------------------------------

typedef int (* LPInitCryptoApiDll)(int nOpMode, char pbyWrDirBuf[],
		int nWrDirBufOff, int nWrDirBufLen, char pbyAddInBuf[],
		int nAddInBufOff, int nAddInBufLen, int pnCrApiType[]);

typedef int (* LPGetCChainForSrvrVerify)(char pbyInputDataBuf[],
		int nIDOffset, int nIDLength, int nOpMode,
		char* ppbyDestBuf[], int pnNmbOfCerts[], int pnMaxDataLen[]);

typedef int (* LPGetClntCChainForAuthent)(char pbyRdnInput[],
		int nRdnDOffset, int nRdnDLength, char pbySigAlgInput[],
		int nSAlgDOffset, int nSAlgDLength,
		char pbySubjectSelIn[], int nSubSelOffset,
		int nSubSelLength, int nOpMode,
		int pnPrevCertID[], int pnPrevStoreID[],
		char* ppbyDestBuf[], int pnNmbOfCerts[],
		int pnMaxDataLen[]);

typedef int (* LPSignDataWithCPrivKey)(char pbyCertDInput[],
		int nCertDOffset, int nCertDLength,
		char pbyDataInput[], int nDataOffset, int nDataLength,
		int nOpMode, char* ppbyDestBuf[], int pnMaxDataLen[]);

typedef int (* LPForgetCertIniEntry)(int nOpMode);

#if defined __VPN_INTERFACE__
typedef int (* LPVpnStartup)(void);
typedef int (* LPVpnCleanup)(void);
typedef int (* LPVpnConnState)(int WaitTimeMillis);
#endif // __VPN_INTERFACE__

#if !defined __VPN_INTERFACE__

#define	HSSL_EX_MODULE_DLLNAME		L"HOBsecCTE.dll"

#define	INIT_CRAPI_PROC_NAME		"InitCryptoApiDll"
#define	GET_SRVR_VERIFY_CCHAIN_NAME	"GetCChainForSrvrVerify"
#define	GET_CLNT_AUTHENT_CCHAIN_NAME	"GetClntCChainForAuthent"
#define	SIGN_DATA_CLNT_PRIVKEY_NAME	"SignDataWithCPrivKey"
#define	CRAPI_FORGET_INI_NAME		"ForgetCertIniEntry"

#else						// for VPN

#define	HSSL_EX_MODULE_DLLNAME		L"hvpnmstr.dll"

#define	INIT_CRAPI_PROC_NAME		"VPNInitCryptoApiDll"
#define	GET_SRVR_VERIFY_CCHAIN_NAME	"VPNGetCChainForSrvrVerify"
#define	GET_CLNT_AUTHENT_CCHAIN_NAME	"VPNGetClntCChainForAuthent"
#define	SIGN_DATA_CLNT_PRIVKEY_NAME	"VPNSignDataWithCPrivKey"
#define	CRAPI_FORGET_INI_NAME		"VPNForgetCertIniEntry"
#define	EXT_DLL_STARTUP_NAME		"VPNMasterStartup"
#define	EXT_DLL_CLEANUP_NAME		"VPNMasterCleanup"
#define	EXT_DLL_CONNCHK_NAME		"VPNMasterGetConnState"
#endif // !defined __VPN_INTERFACE__

//-------------------------------------------------------------
// Indices into Function Pointer Array for call (C only)
//-------------------------------------------------------------

#define	INIT_CRYPTO_API_DLL_IND		0
#define	GET_CCHAIN_FOR_SRVR_VERIFY_IND	1
#define	GET_CLIENT_CCHAIN_FOR_AUTH_IND	2
#define	SIGN_DATA_WITH_CPRIVKEY_IND	3
#define	FORGET_CERT_INI_ENTRY_IND	4
#if !defined __VPN_INTERFACE__
#define	EXT_CERT_MAX_FUNCT_CNT		5
#else
#define	STARTUP_ENTRY_IND		5
#define	CLEANUP_ENTRY_IND		6
#define	CONN_CHECK_ENTRY_IND		7
#define	EXT_CERT_MAX_FUNCT_CNT		8
#endif // __VPN_INTERFACE__

// ASN.1 parser controls and defines (hocspctl.hc)

#define	OCSP_ATT_TYPES_BASE_OID_LEN	8
#define	OCSP_BASIC_RESP_BASE_OID_LEN	9
#define	OCSP_NONCE_BASE_OID_LEN		9
#define	OCSP_CRL_BASE_OID_LEN		9
#define	OCSP_RESP_BASE_OID_LEN		9
#define	OCSP_NOCHECK_BASE_OID_LEN	9
#define	OCSP_ARCHIV_CUTOFF_BASE_OID_LEN	9
#define	OCSP_SERVICE_LOC_BASE_OID_LEN	9
#define	OCSP_SHA1_HASH_OID_LEN		5

// general used definitions

// Extension parsing
#define	OCSP_EXTN_ID_INDEX	0			// OID of the Extension
#define	OCSP_EXTN_CRIT_INDEX	1			// Critical flag
#define	OCSP_EXTN_VAL_INDEX	2			// Value of extension
#define	OCSP_EXTN_MAX_DATA_INDEX 3

#define	OCSP_EXT_CTL_CNT	4
#define	OCSP_EXT_CTL_SIZE	(OCSP_EXT_CTL_CNT * HDR_ENTRY_SIZE)

// general name (pre)parsing
#define	OCSP_GEN_NAME_CTL_SIZE	9 * HDR_ENTRY_SIZE
#define	OCSP_OTHER_NAME_INDEX		0	// 'othername' object
#define	OCSP_RFC822_NAME_INDEX		1	// rfc822 name	(decoded)
#define	OCSP_DNS_NAME_INDEX		2	// dns name	(decoded)
#define	OCSP_OR_ADDR_INDEX		3	// x.400 name object
#define	OCSP_DN_NAME_INDEX		4	// Directory name object
#define	OCSP_EDI_PARTY_NAME_INDEX	5	// EDI party name object
#define	OCSP_URI_NAME_INDEX		6	// uri name	(decoded)
#define	OCSP_IPADR_NAME_INDEX		7	// ip-address name (decoded)
#define	OCSP_REGISTERED_ID_NAME_INDEX	8	// registered OID (decoded)

// Both request and response

// Certificate ID object parsing

#define	OCSP_CERTID_HASH_ALGID_INDEX	0		// hash algorithm OID
#define	OCSP_CERTID_HASH_ALGPAR_INDEX	1		// algor. params (NULL)
#define	OCSP_CERTID_ISS_NAME_HASH_INDEX	2		// issuer name's hash
#define	OCSP_CERTID_ISS_KEY_HASH_INDEX	3		// issuer key's hash
#define	OCSP_CERTID_SERIALNR_INDEX	4		// certificate serial#
#define	OCSP_CERTID_MAX_DATA_INDEX	5

#define	OCSP_CERTID_CTL_CNT	7
#define	OCSP_CERTID_CTL_SIZE	(OCSP_CERTID_CTL_CNT * HDR_ENTRY_SIZE)

// Request related definitions

// Request signature parsing
#define	OCSP_REQ_SIGNAT_ALGID_INDEX	0	// algorithm OID
#define	OCSP_REQ_SIGNAT_ALGPAR_INDEX	1	// algorithm parameters
#define	OCSP_REQ_SIGNAT_VAL_INDEX	2	// signature value
#define	OCSP_REQ_SIGNAT_CERTS_INDEX	3	// certificate list of signer
#define	OCSP_REQ_SIGNAT_MAX_DATA_INDEX	4

#define	OCSP_REQ_SIG_CTL_CNT	7
#define	OCSP_REQ_SIG_CTL_SIZE	(OCSP_REQ_SIG_CTL_CNT * HDR_ENTRY_SIZE)

// Requestor name parsing
#define	OCSP_REQ_NAME_INDEX		0	// Requestor name
#define	OCSP_REQ_NAME_MAX_DATA_INDEX	1

#define	OCSP_REQ_NAME_CTL_CNT	2
#define	OCSP_REQ_NAME_CTL_SIZE	(OCSP_REQ_NAME_CTL_CNT * HDR_ENTRY_SIZE)

// single request element parsing
#define	OCSP_SREQ_CERTID_INDEX		0	// Certificate ID object
#define	OCSP_SREQ_EXTENSIONS_INDEX	1	// Extensions for this element
#define	OCSP_SREQ_MAX_DATA_INDEX	2

#define	OCSP_SREQ_CTL_CNT	3
#define	OCSP_SREQ_CTL_SIZE	(OCSP_SREQ_CTL_CNT * HDR_ENTRY_SIZE)

// 'To be signed' request data parsing
#define	OCSP_TBS_REQ_VERSION_INDEX	0	// Version of request
#define	OCSP_TBS_REQ_GENNAME_INDEX	1	// Requestor's general name
#define	OCSP_TBS_REQ_REQLIST_INDEX	2	// List of Request entries
#define	OCSP_TBS_REQ_EXTS_INDEX		3	// Extensions for Request
#define	OCSP_TBS_REQ_MAX_DATA_INDEX	4

#define	OCSP_TBS_REQ_CTL_CNT	6
#define	OCSP_TBS_REQ_CTL_SIZE	(OCSP_TBS_REQ_CTL_CNT * HDR_ENTRY_SIZE)

// OCSP-Request parsing
#define	OCSP_REQ_TBSREQ_INDEX		0		// the request data
#define	OCSP_REQ_SIGNAT_INDEX		1		// signature of data
#define	OCSP_REQ_MAX_DATA_INDEX		2

#define	OCSP_REQ_CTL_CNT	3
#define	OCSP_REQ_CTL_SIZE	(OCSP_REQ_CTL_CNT * HDR_ENTRY_SIZE)

// Response related definitions

// Single response parsing
#define	OCSP_SRESP_CERTID_INDEX		0	// Certificate ID object
#define	OCSP_SRESP_CERTSTAT_GOOD_INDEX	1	// good status
#define	OCSP_SRESP_CERTREV_TIME_INDEX	2	// revocation time
#define	OCSP_SRESP_CERTREV_REASON_INDEX	3	// revocation reason
#define	OCSP_SRESP_CERTSTAT_UNK_INDEX	4	// unknown status
#define	OCSP_SRESP_THIS_UPD_INDEX	5	// start of response validity
#define	OCSP_SRESP_NEXT_UPD_INDEX	6	// end of response validity
#define	OCSP_SRESP_EXTS_INDEX		7	// extensions for this response
#define	OCSP_SRESP_MAX_DATA_INDEX	8

#define	OCSP_SINGLE_RESP_CTL_CNT 13
#define	OCSP_SINGLE_RESP_CTL_SIZE (OCSP_SINGLE_RESP_CTL_CNT * HDR_ENTRY_SIZE)

// Response list splitter definitions
#define	OCSP_RESP_LIST_ENTRY_INDEX	0	// one entry in the list
#define	OCSP_RESP_LIST_MAX_DATA_INDEX	1

#define	OCSP_RESP_LIST_CTL_CNT 1
#define	OCSP_RESP_LIST_CTL_SIZE (OCSP_RESP_LIST_CTL_CNT * HDR_ENTRY_SIZE)

// 'To be signed' response data parsing
#define	OCSP_RESP_DATA_VERS_INDEX	0	// Version of response
#define	OCSP_RESP_DATA_RESP_NAME_INDEX	1	// Responder ID byName
#define	OCSP_RESP_DATA_RESP_KEY_INDEX	2	// Responder ID byKey
#define	OCSP_RESP_DATA_PROD_AT_INDEX	3	// time when response generated
#define	OCSP_RESP_DATA_RESP_LIST_INDEX	4	// list of responses
#define	OCSP_RESP_DATA_EXTS_INDEX	5	// extensions (all responses)
#define	OCSP_RESP_DATA_MAX_DATA_INDEX	6

#define	OCSP_RESP_DATA_CTL_CNT 11
#define	OCSP_RESP_DATA_CTL_SIZE	(OCSP_RESP_DATA_CTL_CNT * HDR_ENTRY_SIZE)

// OCSP basic response object parsing
#define	OCSP_BRESP_TBSDATA_INDEX	0		// to be signed object
#define	OCSP_BRESP_SIGNAT_ALGID_INDEX	1		// signature algor OID
#define	OCSP_BRESP_SIGNAT_ALGPAR_INDEX	2		// algor params (NULL)
#define	OCSP_BRESP_SIGNAT_VAL_INDEX	3		// signature value
#define	OCSP_BRESP_CERTS_INDEX		4		// list of certificates
#define	OCSP_BRESP_MAX_DATA_INDEX	5

#define	OCSP_BASIC_RESP_CTL_CNT	8
#define	OCSP_BASIC_RESP_CTL_SIZE (OCSP_BASIC_RESP_CTL_CNT * HDR_ENTRY_SIZE)

// formal response format parsing
#define	OCSP_RESP_BYTES_TYPE_INDEX	0		// response format OID
#define	OCSP_RESP_BYTES_DATA_INDEX	1		// response (Data)
#define	OCSP_RESP_BYTES_MAX_DATA_INDEX	2

#define	OCSP_RESP_BYTES_CTL_CNT 3
#define	OCSP_RESP_BYTES_CTL_SIZE (OCSP_RESP_BYTES_CTL_CNT * HDR_ENTRY_SIZE)

// OCSP response outer object parsing
#define	OCSP_RESP_STATUS_INDEX		0		// global status
#define	OCSP_RESP_BYTES_INDEX		1		// response data if any
#define	OCSP_RESP_MAX_DATA_INDEX	2

#define	OCSP_RESP_CTL_CNT 3
#define	OCSP_RESP_CTL_SIZE (OCSP_RESP_CTL_CNT * HDR_ENTRY_SIZE)

#if !defined __HSTRHLP_HEADER__
#define __HSTRHLP_HEADER__
/** @addtogroup util
* @{
* @file
* This header contains some macros for string helper functions.
* @}
*/
#define	NUMBER_TYPE_DECIMAL		0
#define	NUMBER_TYPE_OCTAL		1
#define	NUMBER_TYPE_HEX			2
#define	NUMBER_TYPE_INTEGER		3

#endif // __HSTRHLP_HEADER__

/**
* This structure is used to hold private key or certificate data and associated attributes.
*/
typedef struct P12BAG_t {
	//---------------------------------------------------------
        //!< Elements used for all bags: Type and selected attributes
	//---------------------------------------------------------
	int	BagType;			//!< Type of bag
	int	FriendlyNameLen;		//!< Name attribute size
	char* pFriendlyName;			//!< Friendly name
	int	LocalKeyIDLen;			//!< KeyID attribute size
	char*	pLocalKeyID;			//!< Allocated buffer
	int	DigestAlgor;			//!< Used for PFX KeyID
	//---------------------------------------------------------
        //!< Elements used with ShroudedKeyBag
	//---------------------------------------------------------
	int	PrivKeyType;			//!< Type of private key
	int	PrivKeyUsageValid;		//!< Usage is present
	int	PrivKeyUsage;			//!< Usage of key
	IDATPARR* pPrivKeyDesc;		//!< Private key descriptor
	//---------------------------------------------------------
        //!< Elements used with CertBag
	//---------------------------------------------------------
	int	AssocPrivKeyBagIndex;		//!< Index of PrivateKeyBag
	IDATPARR* pCertDesc;			//!< Certificate descriptor
} P12BAG;

/**
* This structure is used to store the data for an ASN.1 encoded PKCS-12/PFX structure.
*/
typedef struct PK12STRU_t {
	//---------------------------------------------------------
        //!< General Parameters
	//---------------------------------------------------------
	int	PFXType;		//!< Type used (V1 / V3)
	//---------------------------------------------------------
        //!< Encryption/Decryption related data
	//---------------------------------------------------------
        char*	pPwd;			//!< Password as ASCII
        int	PwdOff;			//!< Start of password data
        int	PwdLen;			//!< Size of password
        char*	pUniPwd;		//!< Password as UNICODE, zero padded
	int	UniPwdOff;		//!< Start of unicode password data
        int	UniPwdLen;		//!< Size of unicode password
	int	PrivKeyPBEEncAlgorID;	//!< Encryption algor for priv.key(s)
	int	PrivSaltLen;		//!< Size of salt to use for private keys
	int	PrivIteratCnt;		//!< Iteration count to use for private keys
	int	CertPBEEncAlgorID;	//!< Encryption algor for cert(s)
	int	CertSaltLen;		//!< Size of salt to use for certs
	int	CertIteratCnt;		//!< Iteration count to use for certs
	int	PFXPrivSaltLen;		//!< Size of privacy salt
	int	MACSaltLen;		//!< Size of HMAC salt
	int	MACIteratCnt;		//!< Iteration count for HMAC
	//---------------------------------------------------------
        //!< Private Key Bag Array
	//---------------------------------------------------------
	int	PrivKeysCnt;		//!< Number of private key bags
	P12BAG ** pPrivKeyBagsArr;	//!< Array with key bags
	//---------------------------------------------------------
        //!< Certificates Bag Array
	//---------------------------------------------------------
	int	CertsCnt;		//!< Number of cert bags
	P12BAG ** pCertBagsArr;	//!< Array with cert bags
}PK12STRU;

//-------------------------------------------------------------
// ASN.1 related definitions,
// X509, X9.57, PKCS7, PKCS8, PKCS9 and PKCS12
//-------------------------------------------------------------
#define	X509_ID_CE_SUBID_MIN		1
#define	X509_ID_CE_KEY_USAGE_SUBID	15	// id-ce (15)
#define	X509_ID_CE_SUBID_MAX		37

#define	OIW_ALGORS_SUBID_MIN		26
#define	OIW_DSA_ALGOR_SUBID		26	// OIW (26)
#define	OIW_ALGORS_SUBID_MAX		26

#define	X957_DSA_SUBID_MIN		1
#define	X957_DSA_ALGOR_SUBID		1	// X9.57-dsa (1)
#define	X957_DSA_WITH_SHA_ALGOR_SUBID	2	// X9.57-dsa (2) deprecated
#define	X957_DSA_WITH_SHA1_ALGOR_SUBID	3	// X9.57-dsa (3)
#define	X957_DSA_SUBID_MAX		3

#define	PKCS1_RSA_SUBID_MIN		1
#define	PKCS1_RSA_ALGOR_SUBID		1	// pkcs-1 (1)
#define	PKCS1_MD2_WITH_RSA_ALGOR_SUBID	2	// pkcs-1 (2)
#define	PKCS1_MD4_WITH_RSA_ALGOR_SUBID	3	// pkcs-1 (3) deprecated
#define	PKCS1_MD5_WITH_RSA_ALGOR_SUBID	4	// pkcs-1 (4)
#define	PKCS1_SHA1_WITH_RSA_ALGOR_SUBID	5	// pkcs-1 (5)
#define	PKCS1_RSA_SUBID_MAX		5

#define	PKCS2_DIGESTALG_SUBID_MIN	2
#define	PKCS2_MD2_DIGEST_ALGOR_SUBID	2	// pkcs-2 (2)
#define	PKCS2_MD4_DIGEST_ALGOR_SUBID	4	// pkcs-2 (4) deprecated
#define	PKCS2_MD5_DIGEST_ALGOR_SUBID	5	// pkcs-2 (5)
#define	PKCS2_DIGESTALG_SUBID_MAX	5

#define	PKCS7_CONTENT_SUBID_MIN		1
#define	PKCS7_CONTENT_DATA_SUBID	1	// pkcs-7 (1)
#define	PKCS7_CONTENT_SIGDATA_SUBID	2	// pkcs-7 (2)
#define	PKCS7_CONTENT_ENVDATA_SUBID	3	// pkcs-7 (3)
#define	PKCS7_CONTENT_SIGENVDATA_SUBID	4	// pkcs-7 (4)
#define	PKCS7_CONTENT_DIGDATA_SUBID	5	// pkcs-7 (5)
#define	PKCS7_CONTENT_ENCDATA_SUBID	6	// pkcs-7 (6)
#define	PKCS7_CONTENT_SUBID_MAX		6

#define	PKCS9_ATT_SUBID_MIN		20
#define	PKCS9_ATT_FRIENDLY_NAME_SUBID	20	// pkcs-9-at-friendlyName
#define	PKCS9_ATT_LOCAL_KEYID_SUBID	21	// pkcs-9-at-localKeyId
#define	PKCS9_ATT_SUBID_MAX		21

#define	PKCS12_CERT_TYPE_SUBID_MIN	1
#define	PKCS12_X509_CERT_TYPE_SUBID	1	// pkcs-9 22 (1)
#define	PKCS12_SDSI_CERT_TYPE_SUBID	2	// pkcs-9 22 (2)
#define	PKCS12_CERT_TYPE_SUBID_MAX	2

#define	PKCS12_CRL_TYPE_SUBID_MIN	1
#define	PKCS12_X509_CRL_TYPE_SUBID	1	// pkcs-9 23 (1)
#define	PKCS12_CRL_TYPE_SUBID_MAX	1

#define	PKCS12_BAG_SUBID_MIN		1
#define	PKCS12_KEYBAG_SUBID		1	// pkcs-12 10 1 (1)
#define	PKCS12_PKCS8_SHRBAG_SUBID	2	// pkcs-12 10 1 (2)
#define	PKCS12_CERTBAG_SUBID		3	// pkcs-12 10 1 (3)
#define	PKCS12_CRLBAG_SUBID		4	// pkcs-12 10 1 (4)
#define	PKCS12_SECRBAG_SUBID		5	// pkcs-12 10 1 (5)
#define	PKCS12_SAFECONTBAG_SUBID	6	// pkcs-12 10 1 (6)
#define	PKCS12_BAG_SUBID_MAX		6

#define	PFX_TRANSP_MODE_SUBID_MIN	1
#define	PFX_TRANSP_MODE_OFFLINE_SUBID	1	// pkcs-12 1 1 (V1)
#define	PFX_TRANSP_MODE_ONLINE_SUBID	2	// pkcs-12 1 2 (V1)
#define	PFX_TRANSP_MODE_SUBID_MAX	2

#define	PFX_ESPVK_SUBID_MIN		1
#define	PFX_ESPVK_PKCS8_SHROUDING_SUBID	1	// pkcs-12 2 1 (V1)
#define	PFX_ESPVK_SUBID_MAX		1

#define	PFX_BAGTYPE_SUBID_MIN		1
#define	PFX_BAGTYPE_KEYBAG_SUBID	1	// pkcs-12 3 1 (V1)
#define	PFX_BAGTYPE_CERTCRLBAG_SUBID	2	// pkcs-12 3 2 (V1)
#define	PFX_BAGTYPE_SECRETBAG_SUBID	3	// pkcs-12 3 3 (V1)
#define	PFX_BAGTYPE_SUBID_MAX		3

#define	PFX_CERTCRL_TYPE_SUBID_MIN	1
#define	PFX_CERTCRL_TYPE_X509_SUBID	1	// pkcs-12 4 1 (V1)
#define	PFX_CERTCRL_TYPE_SDSI_SUBID	2	// pkcs-12 4 2 (V1)
#define	PFX_CERTCRL_TYPE_SUBID_MAX	2

//-------------------------------------------------------------
// ASN PKCS12/PFX Encoder/Decoder related definitions
//-------------------------------------------------------------
#define	X509_ID_CE_BASE_OID_LEN		2	// X509 Extensions
#define	X509_KEY_USAGE_MAX_BITS		9	// X509 V3 (93) Spec

#define	X957_DSA_ALGORS_BASE_OID_LEN	6	// X9.57 DSA

#define	OIW_ALGORS_BASE_OID_LEN		4	// OIW

#define	PKCS1_RSA_ALGORS_BASE_OID_LEN	8	// pkcs-1
#define	PKCS2_DIGEST_ALGS_BASE_OID_LEN	7	// pkcs-2

#define	PKCS7_CONT_TYPES_BASE_OID_LEN	8	// pkcs-7

#define	PKCS9_ATT_TYPES_BASE_OID_LEN	8	// pkcs-9
#define	PKCS9_CERT_TYPES_BASE_OID_LEN	9	// pkcs-9 22
#define	PKCS9_CRL_TYPES_BASE_OID_LEN	9	// pkcs-9 23

#define	PFX_MODE_IDS_BASE_OID_LEN	9	// pkcs-12 1  (V1)
#define	PFX_ESPVK_IDS_BASE_OID_LEN	9	// pkcs-12 2  (V1)
#define	PFX_BAG_IDS_BASE_OID_LEN	9	// pkcs-12 3  (V1)
#define	PFX_CERT_IDS_BASE_OID_LEN	9	// pkcs-12 4  (V1)
#define	PFX_ENC_PBE_IDS_BASE_OID_LEN	10	// pkcs-12 5  (V1)
#define	PFX_PKCS5_ENCPBEID_BASE_OID_LEN 9	// pkcs-5  10 (V1)

#define	PKCS12_PBE_TYPES_BASE_OID_LEN	9	// pkcs-12 1
#define	PKCS12_BAG_TYPES_BASE_OID_LEN	10	// pkcs-12 10 1

//-------------------------------------------------------------
// Data Array Indices for ASN.1 ANY processing
//-------------------------------------------------------------
#define	ASN1_ANY_VALUE_INDEX		0	// Embedded Data

#define	ASN1_ANY_MAX_DATA_INDEX		1

#define	ASN1_ANY_CTL_CNT		1
#define	ASN1_ANY_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for ASN.1 INTEGER processing
//-------------------------------------------------------------
#define	ASN1_INTEGER_VALUE_INDEX	0	// Embedded Data

#define	ASN1_INTEGER_MAX_DATA_INDEX	1

#define	ASN1_INTEGER_CTL_CNT		1
#define	ASN1_INTEGER_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for ASN.1 BITSTRING processing
//-------------------------------------------------------------
#define	ASN1_BITSTR_VALUE_INDEX		0	// Embedded Data

#define	ASN1_BITSTR_MAX_DATA_INDEX	1

#define	ASN1_BITSTR_CTL_CNT		1
#define	ASN1_BITSTR_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for ASN.1 OCTETSTRING processing
//-------------------------------------------------------------
#define	ASN1_OCTESTSTR_VALUE_INDEX	0	// Embedded Data

#define	ASN1_OCTETSTR_MAX_DATA_INDEX	1

#define	ASN1_OCTETSTR_CTL_CNT		1
#define	ASN1_OCTETSTR_CTL_SIZE		(1 * CTL_ENTRY_SIZE)
//-------------------------------------------------------------
// Data Array Indices for ASN.1 BMPSTRING processing
//-------------------------------------------------------------
#define	ASN1_BMPSTR_VALUE_INDEX		0	// Embedded Data

#define	ASN1_BMPSTR_MAX_DATA_INDEX	1

#define	ASN1_BMPSTR_CTL_CNT		1
#define	ASN1_BMPSTR_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for ASN.1 SET / SET OF processing
//-------------------------------------------------------------
#define	ASN1_SET_VALUE_INDEX		0	// Embedded Data

#define	ASN1_SET_MAX_DATA_INDEX		1

#define	ASN1_SET_CTL_CNT		1
#define	ASN1_SET_CTL_SIZE		(1 * CTL_ENTRY_SIZE)
//-------------------------------------------------------------
// Data Array Indices for ASN.1 SEQUENCE / SEQUENCE OF processing
//-------------------------------------------------------------
#define	ASN1_SEQUENCE_VALUE_INDEX	0	// Embedded Data

#define	ASN1_SEQUENCE_MAX_DATA_INDEX	1

#define	ASN1_SEQUENCE_CTL_CNT		1
#define	ASN1_SEQUENCE_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for X501 AVA (Attribute/Value) processing
//-------------------------------------------------------------
#define	X501_AVA_ATTRIB_OID_INDEX	0	// AttributeID: OID
#define	X501_AVA_ATTRIB_VALUE_INDEX	1	// AttributeValue: ANY

#define	X501_AVA_MAX_DATA_INDEX		2

#define	X501_AVA_CTL_CNT		3
#define	X501_AVA_CTL_SIZE		(3 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------------
// Data Array Indices for X9.57 Private Key processing
// NOTE: To be compatible to HASN1.C private key formatters:
// ----- 1. First come the 'parameters' p,q and g
//	 2. then empty element to store the public value Y
//	 3. the private value X
//	 4. a dummy element
//-------------------------------------------------------------------
#define	X957_PRIVKEY_MODUL_P_INDEX	0	// INT: Modulus p
#define	X957_PRIVKEY_PRIME_Q_INDEX	1	// INT: Prime q
#define	X957_PRIVKEY_GENERATOR_G_INDEX	2	// INT: Generator g
#define	X957_PRIVKEY_PUB_Y_INDEX	3	// INT: Public value y
#define	X957_PRIVKEY_PRIV_X_INDEX	4	// INT: Private value x
#define	X957_PRIVKEY_DUMMY_INDEX	5	// unused

#define	X957_PRIVKEY_MAX_DATA_INDEX	6

//-------------------------------------------------------------------
// Data Array Indices for X9.57 Algorithm Params processing
// NOTE: KEEP Indices in same order as for private key !!!
// -----
//-------------------------------------------------------------------
#define	X957_ALGPAR_MODUL_P_INDEX	0	// INT: Modulus p
#define	X957_ALGPAR_PRIME_Q_INDEX	1	// INT: Prime q
#define	X957_ALGPAR_GENERATOR_G_INDEX	2	// INT: Generator g

#define	X957_ALGPAR_MAX_DATA_INDEX	3

#define	X957_ALGPAR_CTL_CNT		4
#define	X957_ALGPAR_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------------
// Data Array Indices for PKCS1 PrivateKey processing
// NOTE: To be compatible to HASN1.C private key formatters:
// ----- 1. there is an empty Element at the Start of the Array
//	 2. the RSA Version is stored in the last element
//-------------------------------------------------------------------
#define	PKCS1_PRIVKEY_DUMMY_INDEX	0	// not used
#define	PKCS1_PRIVKEY_MODUL_INDEX	1	// INT: Modulus n
#define	PKCS1_PRIVKEY_PUBEXP_INDEX	2	// INT: Public Exp e
#define	PKCS1_PRIVKEY_PRIVEXP_INDEX	3	// INT: Private Exp d
#define	PKCS1_PRIVKEY_PRIME_P_INDEX	4	// INT: Prime p
#define	PKCS1_PRIVKEY_PRIME_Q_INDEX	5	// INT: Prime q
#define	PKCS1_PRIVKEY_DMOD_PM1_INDEX	6	// INT: Exp1 d mod(p-1)
#define	PKCS1_PRIVKEY_DMOD_QM1_INDEX	7	// INT: Exp2 d mod(q-1)
#define	PKCS1_PRIVKEY_INVQ_MODP_INDEX	8	// INT: Coeff q**-1 mod(p)
#define	PKCS1_PRIVKEY_VERSION_INDEX	9	// INT: Version (0)

#define	PKCS1_PRIVKEY_MAX_DATA_INDEX	10

#define	PKCS1_PRIVKEY_CTL_CNT		10
#define	PKCS1_PRIVKEY_CTL_SIZE		(10 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS7 DigestInfo processing
//-------------------------------------------------------------
#define	PKCS7_DIGESTINFO_ALGID_INDEX	0	// AlgorID: OID
#define	PKCS7_DIGESTINFO_ALGPAR_INDEX	1	// AlgorParams: ANY
#define	PKCS7_DIGESTINFO_DATA_INDEX	2	// Digest: OCTETSTR

#define	PKCS7_DIGESTINFO_MAX_DATA_INDEX	3

#define	PKCS7_DIGESTINFO_CTL_CNT	5
#define	PKCS7_DIGESTINFO_CTL_SIZE	(5 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS7 ContentInfo processing
//-------------------------------------------------------------
#define	PKCS7_CONTINFO_TYPE_INDEX	0	// Content Type OID
#define	PKCS7_CONTINFO_DATA_INDEX	1	// Content Data, Optional

#define	PKCS7_CONTINFO_MAX_DATA_INDEX	2

#define	PKCS7_CONTINFO_CTL_CNT		4
#define	PKCS7_CONTINFO_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS7 data type Content processing
//-------------------------------------------------------------
#define	PKCS7_DATA_TYPE_VALUE_INDEX	0	// Octet String: data

#define	PKCS7_DATA_TYPE_MAX_DATA_INDEX	1

#define	PKCS7_CONTDATA_CTL_CNT		1
#define	PKCS7_CONTDATA_CTL_SIZE		(1 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------------
// Data Array Indices for PKCS7 envelopedData type Content processing
//-------------------------------------------------------------------
#define	PKCS7_ENVDATA_VERSION_INDEX	0	// Version, 0 OR 1
#define	PKCS7_ENVDATA_RECIPINFOS_INDEX	1	// Recipient Infos
#define	PKCS7_ENVDATA_TYPE_INDEX	2	// Content type (Encr.)
#define	PKCS7_ENVDATA_ENCALGID_INDEX	3	// Public Encr. Algor OID
#define	PKCS7_ENVDATA_ENCALGPAR_INDEX	4	// Public Encr. Algor Params
#define	PKCS7_ENVDATA_ENCDATA_INDEX	5	// Public encrypted Contents

#define	PKCS7_ENVDATA_MAX_DATA_INDEX	6

#define	PKCS7_CONT_ENVDATA_CTL_CNT	10
#define	PKCS7_CONT_ENVDATA_CTL_SIZE	(10 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------------
// Data Array Indices for PKCS7 encryptedData type Content processing
//-------------------------------------------------------------------
#define	PKCS7_ENCDATA_VERSION_INDEX	0	// version (0)
#define	PKCS7_ENCDATA_TYPE_INDEX	1	// Content type (encr. data)
#define	PKCS7_ENCDATA_ENCALG_ID_INDEX	2	// Key Encryption Algor OID
#define	PKCS7_ENCDATA_ENCALG_PAR_INDEX	3	// Key Encryption AlgorParams
#define	PKCS7_ENCDATA_ENCDATA_INDEX	4	// Key Encrypted data, ITAG[0]
#define	PKCS7_ENCDATA_ENCDATA_CON_INDEX	5	// Key Encrypted data, ETAG[0]

#define	PKCS7_ENCDATA_MAX_DATA_INDEX	6

#define	PKCS7_CONT_ENCDATA_CTL_CNT	9
#define	PKCS7_CONT_ENCDATA_CTL_SIZE	(9 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------------
// Data Array Indices for PKCS7 SignerInfo Subtype processing
//-------------------------------------------------------------------
#define	PKCS7_ENCDATA_VERSION_INDEX	0	// INT: Version (1 OR 2)
#define	PKCS7_SIGINFO_ISSUER_INDEX	1	// SEQ: Issuer RDN
#define	PKCS7_SIGINFO_SERIAL_INDEX	2	// INT: Cert SerialNumber
#define	PKCS7_SIGINFO_DIGALG_ID_INDEX	3	// OID: DigestAlgorID
#define	PKCS7_SIGINFO_DIGALG_PAR_INDEX	4	// ANY: DigestAlgorPar, Opt.
#define	PKCS7_SIGINFO_AUTH_ATTS_INDEX	5	// SET/SEQ: Authenticated Atts.
#define	PKCS7_SIGINFO_ENCALG_ID_INDEX	6	// OID: Encr. Algor ID
#define	PKCS7_SIGINFO_ENCALG_PAR_INDEX	7	// ANY: Encr. Algor Params
#define	PKCS7_SIGINFO_ENCDIGEST_INDEX	8	// OCTSTR: Encrypted Digest
#define	PKCS7_SIGINFO_UNAUTH_ATTS_INDEX	9	// SET/SEQ: UnauthenticatedAtts

#define	PKCS7_SIGINFO_MAX_DATA_INDEX	10

#define	PKCS7_SIGNER_INFO_V1_CTL_CNT	14
#define	PKCS7_SIGNER_INFO_V1_CTL_SIZE	(14 * CTL_ENTRY_SIZE)

#define	PKCS7_SIGNER_INFO_V2_CTL_CNT	16
#define	PKCS7_SIGNER_INFO_V2_CTL_SIZE	(16 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------------
// Data Array Indices for PKCS7 RecipientInfo Subtype processing
//-------------------------------------------------------------------
#define	PKCS7_RECPINFO_VERSION_INDEX	0	// Version (0)
#define	PKCS7_RECPINFO_ISSUER_INDEX	1	// SEQ: Issuer RDN
#define	PKCS7_RECPINFO_SERIAL_INDEX	2	// INT: Cert Serial Number
#define	PKCS7_RECPINFO_ENCALG_ID_INDEX	3	// OID: Key Encr. Algor ID
#define	PKCS7_RECPINFO_ENCALG_PAR_INDEX	4	// ANY: Key Encr. Algor Params
#define	PKCS7_RECPINFO_KEY_DATA_INDEX	5	// OCTSTR: Encrypted Key Data

#define	PKCS7_RECPINFO_MAX_DATA_INDEX	6

#define	PKCS7_RECPIENT_INFO_CTL_CNT	9
#define	PKCS7_RECPIENT_INFO_CTL_SIZE	(9 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS8 PrivateKeyInfo processing
//-------------------------------------------------------------
#define	PKCS8_PRIVKEYINFO_VERSION_INDEX	0	// Version: INT (0)
#define	PKCS8_PRIVKEYINFO_ALGID_INDEX	1	// AlgorID: OID
#define	PKCS8_PRIVKEYINFO_ALGPAR_INDEX	2	// AlgorPar: ANY
#define	PKCS8_PRIVKEYINFO_PRIVDAT_INDEX	3	// PrivKeyData: OCTETSTR
#define	PKCS8_PRIVKEYINFO_ATTSSET_INDEX	4	// Atts: SET OF (Opt)

#define	PKCS8_PRIVKEYINFO_MAX_DATA_IND	5

#define	PKCS8_PRIVKEYINFO_CTL_CNT	7
#define	PKCS8_PRIVKEYINFO_CTL_SIZE	(7 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 PBE Parameters processing
//-------------------------------------------------------------
#define	PKCS12_PBE_PARAMS_SALT_INDEX	0	// OCTETSTR: Salt
#define	PKCS12_PBE_PARAMS_ITERAT_INDEX	1	// INT: IterationCount

#define	PKCS12_PBE_PARAMS_MAX_DATA_IND	2

#define	PKCS12_PBE_PARAMS_CTL_CNT	3
#define	PKCS12_PBE_PARAMS_CTL_SIZE	(3 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V3/V1 PFX PDU processing
//-------------------------------------------------------------
#define	PKCS12_PFX_PDU_VERSION_INDEX	0	// Version (3) or Absent (1)
#define	PKCS12_PFX_PDU_CONTTYPE_INDEX	1	// PKCS7 ContentInfo:Type
#define	PKCS12_PFX_PDU_CONTDATA_INDEX	2	// PKCS7 ContentInfo:Content
#define	PKCS12_PFX_PDU_MAC_ALGID_INDEX	3	// MacData:DigestInfo:AlgorID
#define	PKCS12_PFX_PDU_MAC_ALGPAR_INDEX	4	// MacData:DigestInfo:AlgPars
#define	PKCS12_PFX_PDU_MAC_DIGEST_INDEX	5	// MacData:DigestInfo:Digest
#define	PKCS12_PFX_PDU_MAC_SALT_INDEX	6	// MacData:macSalt
#define	PKCS12_PFX_PDU_MAC_ITERAT_INDEX	7	// MacData:iterations DEFAULT 1

#define	PKCS12_PFX_PDU_MAX_DATA_INDEX	8

#define	PKCS12_PFX_PDU_CTL_CNT		14
#define	PKCS12_PFX_PDU_CTL_SIZE		(14 * CTL_ENTRY_SIZE)

#define	PFX_PFX_PDU_CTL_CNT		12
#define	PFX_PFX_PDU_CTL_SIZE		(12 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V3/V1 general Safebag processing
//-------------------------------------------------------------
#define	PKCS12_SAFEBAG_ID_VALUE_INDEX	0	// Type of Safebag
#define	PKCS12_SAFEBAG_VALUE_INDEX	1	// Contents of Safebag
#define	PKCS12_SAFEBAG_NAME_ATTS_INDEX	2	// Optional Attributes SET/Name

#define	PKCS12_SAFEBAG_MAX_DATA_INDEX	3

#define	PKCS12_SAFEBAG_CTL_CNT		5
#define	PKCS12_SAFEBAG_CTL_SIZE		(5 * CTL_ENTRY_SIZE) 

#define	PFX_SAFEBAG_CTL_CNT		4
#define	PFX_SAFEBAG_CTL_SIZE		(4 * CTL_ENTRY_SIZE) 

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V3 Keybag processing
//-------------------------------------------------------------
#define	PKCS12_KEYBAG_VERSION_INDEX	0	// PKCS8:PKeyInfo:Version(0)
#define	PKCS12_KEYBAG_PRIV_ALGID_INDEX	1	// PKCS8:PKeyInfo:PrivKeyAlgID
#define	PKCS12_KEYBAG_PRIV_ALGPAR_INDEX	2	// PKCS8:PKeyInfo:PrivKeyAlgPar
#define	PKCS12_KEYBAG_PRIV_DATA_INDEX	3	// PKCS8:PKeyInfo:PrivKeyData
#define	PKCS12_KEYBAG_PRIV_ATTS_INDEX	4	// PKCS8:PKeyInfo:PrivAtts(Opt)

#define	PKCS12_KEYBAG_MAX_DATA_INDEX	5

#define	PKCS12_KEYBAG_CTL_CNT		7
#define	PKCS12_KEYBAG_CTL_SIZE		(7 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 PKCS8ShroudedKeybag processing
//-------------------------------------------------------------
#define	PKCS12_SHRBAG_ENCALG_ID_INDEX	0	// PKCS8:EncPrivInfo:EncAlgID
#define	PKCS12_SHRBAG_ENCALG_PAR_INDEX	1	// PKCS8:EncPrivInfo:EncAlgPar
#define	PKCS12_SHRBAG_ENC_DATA_INDEX	2	// PKCS8:EncPrivInfo:EncData

#define	PKCS12_SHRBAG_MAX_DATA_INDEX	3

#define	PKCS12_SHROUDED_KEYBAG_CTL_CNT	5
#define	PKCS12_SHROUDED_KEYBAG_CTL_SIZE	(5 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 Certbag processing
//-------------------------------------------------------------
#define	PKCS12_CERTBAG_CERT_ID_INDEX	0	// Cert Type OID
#define	PKCS12_CERTBAG_VALUE_INDEX	1	// Cert OCTETSTR/IA5STR

#define	PKCS12_CERTBAG_MAX_DATA_INDEX	2

#define	PKCS12_CERTBAG_CTL_CNT		4
#define	PKCS12_CERTBAG_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 CRLbag processing
//-------------------------------------------------------------
#define	PKCS12_CRLBAG_CRL_ID_INDEX	0	// CRL Type OID
#define	PKCS12_CRLBAG_VALUE_INDEX	1	// CRL OCTETSTR

#define	PKCS12_CRLBAG_MAX_DATA_INDEX	2

#define	PKCS12_CRLBAG_CTL_CNT		4
#define	PKCS12_CRLBAG_CTL_SIZE		(4 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 SecretBag processing
//-------------------------------------------------------------
#define	PKCS12_SECRETBAG_ID_INDEX	0	// Secret Type OID
#define	PKCS12_SECRETBAG_VALUE_INDEX	1	// Secret value, Any defined

#define	PKCS12_SECRETBAG_MAX_DATA_INDEX	2

#define	PKCS12_SECRETBAG_CTL_CNT	4
#define	PKCS12_SECRETBAG_CTL_SIZE	(4 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 SafeContentsBag processing
//-------------------------------------------------------------
#define	PKCS12_SAFECONTBAG_BAGS_INDEX	0	// Sequence of Bags

#define	PKCS12_SAFECONTBAG_MAX_DATA_IND	1

#define	PKCS12_SAFECONTBAG_CTL_CNT	2
#define	PKCS12_SAFECONTBAG_CTL_SIZE	(2 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V1 AuthenticatedSafe processing
//-------------------------------------------------------------
#define	PFX_AUTHSAFE_VERSION_INDEX	0	// Version DEFAULT 1
#define	PFX_AUTHSAFE_TRANSP_MODE_INDEX	1	// TranspMode DEFAULT off-line
#define	PFX_AUTHSAFE_PRIVSALT_INDEX	2	// PrivacySalt, Optional
#define	PFX_AUTHSAFE_BAGGAGE_SET_IND	3	// Baggage SET, Optional
#define	PFX_AUTHSAFE_CONTTYPE_INDEX	4	// Content Type
#define	PFX_AUTHSAFE_CONTDATA_INDEX	5	// Content Value

#define	PFX_AUTHSAFE_MAX_DATA_INDEX	6

#define	PFX_AUTHSAFE_CTL_CNT		9
#define	PFX_AUTHSAFE_CTL_SIZE		(9 * CTL_ENTRY_SIZE) 

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V1 Baggage processing
//-------------------------------------------------------------
#define	PFX_BAGGAGE_DATA_INDEX		0	// BaggageItems

#define	PFX_BAGGAGE_MAX_DATA_INDEX	1

#define	PFX_BAGGAGE_CTL_CNT		1
#define	PFX_BAGGAGE_CTL_SIZE		(1 * CTL_ENTRY_SIZE) 

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V1 BaggageItem processing
//-------------------------------------------------------------
#define	PFX_BAGGAGEITEM_ESPVKS_INDEX	0	// Espvks
#define	PFX_BAGGAGEITEM_UNENC_SECR_IND	1	// unencryptedSecrets

#define	PFX_BAGGAGEITEM_MAX_DATA_INDEX	2

#define	PFX_BAGGAGE_ITEM_CTL_CNT	3
#define	PFX_BAGGAGE_ITEM_CTL_SIZE	(3 * CTL_ENTRY_SIZE) 

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V1 Espvk processing
//-------------------------------------------------------------
#define	PFX_ESPVK_OID_INDEX		0	// espvkOID
#define	PFX_ESPVK_ASSOC_CERTS_INDEX	1	// Thumbprints
#define	PFX_ESPVK_REGENERABLE_INDEX	2	// BOOLEAN DEFAULT FALSE
#define	PFX_ESPVK_NICKNAME_INDEX	3	// nickName: BMPString
#define	PFX_ESPVK_PVKADDITIONAL_INDEX	4	// ANY, Optional
#define	PFX_ESPVK_CIPHALG_ID_INDEX	5	// encAlgorID (OID)
#define	PFX_ESPVK_SALT_DATA_INDEX	6	// encAlgPars.Salt (OCTSTR)
#define	PFX_ESPVK_ITERAT_CNT_INDEX	7	// encAlgPars.IteratCnt (INT)
#define	PFX_ESPVK_ENC_DATA_INDEX	8	// encData: (OCTSTR)

#define	PFX_ESPVK_MAX_DATA_INDEX	9

#define	PFX_ESPVK_CTL_CNT		15
#define	PFX_ESPVK_CTL_SIZE		(15 * CTL_ENTRY_SIZE) 

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V1 SafeContent/Bags processing
//-------------------------------------------------------------
#define	PFX_SAFECONT_OR_BAGS_BAGS_INDEX	0	// SafeBags / Bags

#define	PFX_SAFECONT_BAGS_MAX_DATA_IND	1

#define	PFX_SAFECONT_BAGS_CTL_CNT	1
#define	PFX_SAFECONT_BAGS_CTL_SIZE	(1 * CTL_ENTRY_SIZE) 

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V1 PrivateKey(Bag) processing
//-------------------------------------------------------------
#define	PFX_PRIVKEY_ASSOC_CERTS_INDEX	0	// Thumbprints SET
#define	PFX_PRIVKEY_REGENERABLE_INDEX	1	// BOOLEAN DEFAULT FALSE
#define	PFX_PRIVKEY_NICKNAME_INDEX	2	// nickName BMPString
#define	PFX_PRIVKEY_PVKADDITIONAL_INDEX	3	// ANY
#define	PFX_PRIVKEY_VERSION_INDEX	4	// PKCS8:PrivKeyVersion (0)
#define	PFX_PRIVKEY_PRIV_ALGID_INDEX	5	// PKCS8:PrivKeyAlgID: OID
#define	PFX_PRIVKEY_PRIV_ALGPAR_INDEX	6	// PKCS8:PrivKeyAlgPar:ANY
#define	PFX_PRIVKEY_PRIV_DATA_INDEX	7	// PKCS8:PrivKeyData:OCTSTR
#define	PFX_PRIVKEY_PRIV_ATTS_INDEX	8	// PKCS8:Attribs, OPTIONAL

#define	PFX_PRIVKEY_MAX_DATA_INDEX	9

#define	PFX_PRIVKEY_BAG_CTL_CNT		13
#define	PFX_PRIVKEY_BAG_CTL_SIZE	(13 * CTL_ENTRY_SIZE) 

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V1 CertCRLBag processing
//-------------------------------------------------------------
#define	PFX_CERTCRL_BAG_OID_INDEX	0	// CertCRLType: OID
#define	PFX_CERTCRL_BAG_VALUE_INDEX	1	// CertCRLValue: ANY

#define	PFX_CERTCRL_BAG_MAX_DATA_INDEX	2

#define	PFX_CERTCRL_BAG_CTL_CNT		4
#define	PFX_CERTCRL_BAG_CTL_SIZE	(4 * CTL_ENTRY_SIZE) 

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V1 X509CertCRL processing
//-------------------------------------------------------------
#define	PFX_X509_CERTCRL_CONTTYPE_INDEX	0	// ContentType, signedData
#define	PFX_X509_CERTCRL_VERSION_INDEX	1	// SigData.Version: INT (1)
#define	PFX_X509_CERTCRL_DIGESTALGS_IND	2	// SigData.DigestAlgIDs:SET OF 
#define	PFX_X509_CERTCRL_CONT_TYPE_IND	3	// ContentType, data
#define	PFX_X509_CERTCRL_CONT_VAL_IND	4	// ContentValue, empty
#define	PFX_X509_CERTCRL_CERTS_INDEX	5	// X509/Extended Certificates,
#define	PFX_X509_CERTCRL_CRLS_INDEX	6	// X509 CRLs,
#define	PFX_X509_CERTCRL_SIGINFOS_INDEX	7	// SignerInfos: SET OF

#define	PFX_X509_CERTCRL_MAX_DATA_INDEX	8

#define	PFX_X509_CERTCRL_CTL_CNT	12
#define	PFX_X509_CERTCRL_CTL_SIZE	(12 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Data Array Indices for PKCS12 V1 X509CertList processing
//-------------------------------------------------------------
#define	PFX_X509_CERTLIST_CERT_INDEX	0	// X509Cert: SEQ

#define	PFX_X509_CERTLIST_MAX_DATA_IND	1

#define	PFX_X509_CERTLIST_CTL_CNT	1
#define	PFX_X509_CERTLIST_CTL_SIZE	(1 * CTL_ENTRY_SIZE)

//-------------------------------------------------------------
// Definitions for PKCS12 V1 Signature Algors
// NOTE: Order must be same as the PKCS12 HashTypes below !!
//-------------------------------------------------------------

#define	PKCS12_SIGNAT_ALGOR_INVALID	INVALID_ALGOR
#define	PKCS12_SIGNAT_ALGOR_MD2		0
#define	PKCS12_SIGNAT_ALGOR_MD5		1
#define	PKCS12_SIGNAT_ALGOR_SHA1	2

//-------------------------------------------------------------
// Definitions for PKCS12 V3 Hashes
//-------------------------------------------------------------

#define	PKCS12_HASH_TYPE_MD2	0
#define	PKCS12_HASH_TYPE_MD5	1
#define	PKCS12_HASH_TYPE_SHA1	2

#define	PKCS12_MAX_DIGEST_LEN		20		// SHA1 is longest
#define	PKCS12_MAX_DIGEST_BLOCK_LEN	64		// Same for all
#define	PKCS12_MAX_HASH_ARRAY_SIZE	24		// MD5/SHA1 is longest

#define	PFX_MAC_LEN		16

#define	PKCS12_HMAC_IPAD	0x36
#define	PKCS12_HMAC_OPAD	0x5C

#define	PKCS12_HMAC_VFY		0
#define	PKCS12_HMAC_GEN		1

// Definitions for Encrypt/Decrypt

#define	PKCS12_ENCRYPT		0
#define	PKCS12_DECRYPT		1

//-------------------------------------------------------------------
// Definitions for PKCS12 Cipher Algors
//-------------------------------------------------------------------
#define	PKCS12_LOW_SECURITY		0
#define	PKCS12_MEDIUM_SECURITY		1
#define	PKCS12_HIGH_SECURITY		2

#define	PKCS12_DEFAULT_ITERAT_CNT	2000

#define	PFX_DEFAULT_SALT_LEN		16
#define	PFX_DEFAULT_ITERAT_CNT		1

#define	PKCS12_KEYDATA_TYPE_ID_KEY	0x01		// Type ID for Key
#define	PKCS12_KEYDATA_TYPE_ID_IV	0x02		// Type ID for IV
#define	PKCS12_KEYDATA_TYPE_ID_HMAC	0x03		// Type ID for HMAC

#define	PKCS12_MAX_KEY_LEN		32		// AES-256 Bit
#define	PKCS12_MAX_IV_LEN		16		// AES

//------------------------------------------------------------------------ 
// Definition for PKCS12 PBE Types, also used in ASN.1 OIDs (Last Element)
//------------------------------------------------------------------------ 
#define	PFX_PBE_MIN_ALGORS		1
#define	PKCS12_PBE_MIN_ALGORS		1
#define	PKCS12_PBE_SHA_RC4_128		1	// RC4  128 Bit, SHA-Hash
#define	PKCS12_PBE_SHA_RC4_40		2	// RC4   40 Bit, SHA-Hash
#define	PKCS12_PBE_SHA_3DESC_CBC_3KEYS	3	// 3DES 192 Bit, SHA-Hash
#define	PKCS12_PBE_SHA_3DESC_CBC_2KEYS	4	// 3DES 128 Bit, SHA-Hash
#define	PKCS12_PBE_SHA_RC2_CBC_128	5	// RC2  128 Bit, SHA-Hash
#define	PKCS12_PBE_SHA_RC2_CBC_40	6	// RC2   40 Bit, SHA-Hash
#define PKCS12_PBE_SHA_DES_CBC		7	// DES   56 Bit, SHA-Hash (PFX)

#define	PFX_PBE_MAX_ALGORS		5	// 1..5
#define	PKCS12_PBE_MAX_ALGORS		6
#define	PKCS12_PFX_PBE_MAX_ALGORS	7
#define	PKCS12_PBE_ALGOR_MAX_BLKLEN	16

#define	PFX_PKCS5_DES_ALGOR_ID		10

// Symmetric Encrypt/Decrypt Algorithm Definitions

// Algorithm Family Definitions 

#define	PKCS12_CIPHER_ALG_FAMILY_RC4	0	// RC4 Algorithms
#define	PKCS12_CIPHER_ALG_FAMILY_DES	1	// DES Algorithms
#define	PKCS12_CIPHER_ALG_FAMILY_RC2	2	// RC2 Algorithms
#define	PKCS12_CIPHER_ALG_FAMILY_AES	3	// AES Algorithms

// Family Specific Subtype Definitions
// RC4, RC2, AES -- none, Keysize/Round determines subtype

#define	PKCS12_CIPHER_3DES_3KEYS_ALG	0	// 3DES-CBC 3 Keys, K1 K2 K3
#define	PKCS12_CIPHER_3DES_2KEYS_ALG	1	// 3DES-CBC 2 Keys, K1 K2 K1
#define	PKCS12_CIPHER_DES_ALG		2	// DES-CBC, used in PFX

// PBE Algors Definition 'Structures' (Int-Arrays)
#define	PBE_HASH_ALG_TYPE_IND		0	// Hash Type
#define	PBE_CIPHER_ALG_FAMILY_IND	1	// Algor Family Type
#define	PBE_CIPHER_ALG_SUBTYPE_IND	2	// Subtype within Family (DES)
#define	PBE_CIPHER_ALG_BLKSIZE_IND	3	// Blocksize of Algor, 0-Stream
#define	PBE_CIPHER_ALG_KEYSIZE_IND	4	// Size for Key needed (Bytes)
#define	PBE_CIPHER_ALG_IVSIZE_IND	5	// Size of IV needed   (Bytes)
#define	PBE_CIPHER_ALG_RESERVED1_IND	6	// reserved
#define	PBE_CIPHER_ALG_RESERVED2_IND	7	// reserved
#define	PBE_ALG_DESC_MAX_SIZE		8	// Entries Per Structure !

//-------------------------------------------------------------------
// Definitions for PKCS12/PFX known Private Key Algors
//-------------------------------------------------------------------
#define	PKCS12_PRIVKEY_ALGOR_RSA	0
#define	PKCS12_PRIVKEY_ALGOR_X957_DSA	1

#define	PKCS12_UNKNOWN_PDU_TYPE		-1
#define	PKCS12_V3_PDU_TYPE		0
#define	PKCS12_V1_PDU_TYPE		1

/**
* Compares the content of 2 Bit8 arrays of same length (CmpBit8Arrays).
*
*  @param pArr1 First array
*  @param Arr1Off Start of data in first array
*  @param pArr2 Second array
*  @param Arr2Off Start of data in second array
*  @param ArrLen Length of data
*  @return ASN1_SAME, if arrays are identical, ASN1_NOT_SAME otherwise
*/
inline int CmpBit8Arrays(char* pArr1, int Arr1Off,
				      char* pArr2, int Arr2Off, int ArrLen)
{
  if((pArr1 == NULL) || (pArr2 == NULL) || (ArrLen <= 0))
    return(ASN1_NOT_SAME);

  while(ArrLen != 0)
  {
    if(pArr1[Arr1Off++] != pArr2[Arr2Off++])
      return(ASN1_NOT_SAME);
    ArrLen--;
  }
  return(ASN1_SAME);
}

extern int ToASN1_32MsbBitsBitstringBuf(HMEM_CTX_DEF
	int Bits, char** ppBuf, int* pDataLen);
extern int MatchDatArrays(IDATA** DatArray1,
			int StartIndex1, IDATA** DatArray2,
			int StartIndex2, int ElementCount);
extern unsigned char PKCS5_AlgorObjID[];


// Eyecatcher defines of the eyecatcher used by the PKCS#5 PBES 2 and PBMAC1 implementation
// ----------------------------------------------------------------------------------------
// PKCS#5 eyecatcher
extern const char chrg_eyecatcher_hob[];
extern const size_t szg_eyecatcher_hob_len;


// OID defines of the identifiers used by the PKCS#5 PBES 2 and PBMAC1 implementation
// ----------------------------------------------------------------------------------
// HMAC OIDs
extern const unsigned char byrg_hmac_sha1_alg_id[];
extern const size_t szg_hmac_sha1_alg_id_len;

extern const unsigned char byrg_hmac_sha256_alg_id[];
extern const size_t szg_hmac_sha256_alg_id_len;

extern const unsigned char byrg_hmac_sha384_alg_id[];
extern const size_t szg_hmac_sha384_alg_id_len;

extern const unsigned char byrg_hmac_sha512_alg_id[];
extern const size_t szg_hmac_sha512_alg_id_len;


// function OIDs
extern const unsigned char byrg_pbkdf2_oid[];
extern const size_t szg_pbkdf2_oid_len;

extern const unsigned char byrg_pbes2_oid[];
extern const size_t szg_pbes2_oid_len;

extern const unsigned char byrg_pbmac1_oid[];
extern const size_t szg_pbmac1_oid_len;


// AES OIDs
extern const unsigned char byrg_aes128_cbc_oid[];
extern const size_t szg_aes128_cbc_oid_len;

extern const unsigned char byrg_aes192_cbc_oid[];
extern const size_t szg_aes192_cbc_oid_len;

extern const unsigned char byrg_aes256_cbc_oid[];
extern const size_t szg_aes256_cbc_oid_len;


extern const size_t szg_aes_alg_id_len;
extern const size_t szg_hmac_id_len;


/**
 *  Subroutine m_get_hmac_len returns the required number of bytes
 *  for an ASN.1 DER encoded MAC octet string depending on the given
 *  HMAC hash type (m_get_hmac_len).
 *
 *  @param iep_enc_hash_type   This parameter defines the hash type enumeration value.
 *  @return                    The function returns the number of required bytes.
 */
extern "C" size_t m_get_hmac_len(enum ie_hmac_types iep_enc_hash_type);

/**
 *  Subroutine m_pkcs5_struc_is_valid checks the validity of the dsd_stru_pkcs5_pbes_params
 *  input structure and its structure elements. (m_pkcs5_struc_is_valid).
 *
 *  @param[in]   adsp_pbmac1_params    This pointer to a dsd_stru_pkcs5_pbes_params structure
 *                                     defines all the input elements, such as input data array,
 *                                     its length, iteration count, salt value and algorithms.
 *  @return      The function returns the number of required bytes.
 */
extern "C" bool m_pkcs5_struc_is_valid(dsd_stru_pkcs5_pbes_params * adsp_pkcs5_params);


#ifndef _PKCS11_H_
#define _PKCS11_H_ 1

#if defined _WIN32

#ifdef __cplusplus
extern "C" {
#endif

//-----------------------------------------
// Required MACROS for pkcs11 include files
//-----------------------------------------
#define CK_PTR *
//#define CK_DEFINE_FUNCTION(returntype, name) \
//   returntype __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returntype, name) \
   returntype __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returntype, name) \
   returntype __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returntype, name) returntype (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#pragma pack(push, cryptoki, 1)
/* pkcs11.h include file for PKCS #11. */
/* $Revision: 1.4 $ */

/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or 
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the 
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

/* Before including this file (pkcs11.h) (or pkcs11t.h by
 * itself), 6 platform-specific macros must be defined.  These
 * macros are described below, and typical definitions for them
 * are also given.  Be advised that these definitions can depend
 * on both the platform and the compiler used (and possibly also
 * on whether a Cryptoki library is linked statically or
 * dynamically).
 *
 * In addition to defining these 6 macros, the packing convention
 * for Cryptoki structures should be set.  The Cryptoki
 * convention on packing is that structures should be 1-byte
 * aligned.
 *
 * If you're using Microsoft Developer Studio 5.0 to produce
 * Win32 stuff, this might be done by using the following
 * preprocessor directive before including pkcs11.h or pkcs11t.h:
 *
 * #pragma pack(push, cryptoki, 1)
 *
 * and using the following preprocessor directive after including
 * pkcs11.h or pkcs11t.h:
 *
 * #pragma pack(pop, cryptoki)
 *
 * If you're using an earlier version of Microsoft Developer
 * Studio to produce Win16 stuff, this might be done by using
 * the following preprocessor directive before including
 * pkcs11.h or pkcs11t.h:
 *
 * #pragma pack(1)
 *
 * In a UNIX environment, you're on your own for this.  You might
 * not need to do (or be able to do!) anything.
 *
 *
 * Now for the macros:
 *
 *
 * 1. CK_PTR: The indirection string for making a pointer to an
 * object.  It can be used like this:
 *
 * typedef CK_BYTE CK_PTR CK_BYTE_PTR;
 *
 * If you're using Microsoft Developer Studio 5.0 to produce
 * Win32 stuff, it might be defined by:
 *
 * #define CK_PTR *
 *
 * If you're using an earlier version of Microsoft Developer
 * Studio to produce Win16 stuff, it might be defined by:
 *
 * #define CK_PTR far *
 *
 * In a typical UNIX environment, it might be defined by:
 *
 * #define CK_PTR *
 *
 *
 * 2. CK_DEFINE_FUNCTION(returnType, name): A macro which makes
 * an exportable Cryptoki library function definition out of a
 * return type and a function name.  It should be used in the
 * following fashion to define the exposed Cryptoki functions in
 * a Cryptoki library:
 *
 * CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(
 *   CK_VOID_PTR pReserved
 * )
 * {
 *   ...
 * }
 *
 * If you're using Microsoft Developer Studio 5.0 to define a
 * function in a Win32 Cryptoki .dll, it might be defined by:
 *
 * #define CK_DEFINE_FUNCTION(returnType, name) \
 *   returnType __declspec(dllexport) name
 *
 * If you're using an earlier version of Microsoft Developer
 * Studio to define a function in a Win16 Cryptoki .dll, it
 * might be defined by:
 *
 * #define CK_DEFINE_FUNCTION(returnType, name) \
 *   returnType __export _far _pascal name
 *
 * In a UNIX environment, it might be defined by:
 *
 * #define CK_DEFINE_FUNCTION(returnType, name) \
 *   returnType name
 *
 *
 * 3. CK_DECLARE_FUNCTION(returnType, name): A macro which makes
 * an importable Cryptoki library function declaration out of a
 * return type and a function name.  It should be used in the
 * following fashion:
 *
 * extern CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(
 *   CK_VOID_PTR pReserved
 * );
 *
 * If you're using Microsoft Developer Studio 5.0 to declare a
 * function in a Win32 Cryptoki .dll, it might be defined by:
 *
 * #define CK_DECLARE_FUNCTION(returnType, name) \
 *   returnType __declspec(dllimport) name
 *
 * If you're using an earlier version of Microsoft Developer
 * Studio to declare a function in a Win16 Cryptoki .dll, it
 * might be defined by:
 *
 * #define CK_DECLARE_FUNCTION(returnType, name) \
 *   returnType __export _far _pascal name
 *
 * In a UNIX environment, it might be defined by:
 *
 * #define CK_DECLARE_FUNCTION(returnType, name) \
 *   returnType name
 *
 *
 * 4. CK_DECLARE_FUNCTION_POINTER(returnType, name): A macro
 * which makes a Cryptoki API function pointer declaration or
 * function pointer type declaration out of a return type and a
 * function name.  It should be used in the following fashion:
 *
 * // Define funcPtr to be a pointer to a Cryptoki API function
 * // taking arguments args and returning CK_RV.
 * CK_DECLARE_FUNCTION_POINTER(CK_RV, funcPtr)(args);
 *
 * or
 *
 * // Define funcPtrType to be the type of a pointer to a
 * // Cryptoki API function taking arguments args and returning
 * // CK_RV, and then define funcPtr to be a variable of type
 * // funcPtrType.
 * typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, funcPtrType)(args);
 * funcPtrType funcPtr;
 *
 * If you're using Microsoft Developer Studio 5.0 to access
 * functions in a Win32 Cryptoki .dll, in might be defined by:
 *
 * #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
 *   returnType __declspec(dllimport) (* name)
 *
 * If you're using an earlier version of Microsoft Developer
 * Studio to access functions in a Win16 Cryptoki .dll, it might
 * be defined by:
 *
 * #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
 *   returnType __export _far _pascal (* name)
 *
 * In a UNIX environment, it might be defined by:
 *
 * #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
 *   returnType (* name)
 *
 *
 * 5. CK_CALLBACK_FUNCTION(returnType, name): A macro which makes
 * a function pointer type for an application callback out of
 * a return type for the callback and a name for the callback.
 * It should be used in the following fashion:
 *
 * CK_CALLBACK_FUNCTION(CK_RV, myCallback)(args);
 *
 * to declare a function pointer, myCallback, to a callback
 * which takes arguments args and returns a CK_RV.  It can also
 * be used like this:
 *
 * typedef CK_CALLBACK_FUNCTION(CK_RV, myCallbackType)(args);
 * myCallbackType myCallback;
 *
 * If you're using Microsoft Developer Studio 5.0 to do Win32
 * Cryptoki development, it might be defined by:
 *
 * #define CK_CALLBACK_FUNCTION(returnType, name) \
 *   returnType (* name)
 *
 * If you're using an earlier version of Microsoft Developer
 * Studio to do Win16 development, it might be defined by:
 *
 * #define CK_CALLBACK_FUNCTION(returnType, name) \
 *   returnType _far _pascal (* name)
 *
 * In a UNIX environment, it might be defined by:
 *
 * #define CK_CALLBACK_FUNCTION(returnType, name) \
 *   returnType (* name)
 *
 *
 * 6. NULL_PTR: This macro is the value of a NULL pointer.
 *
 * In any ANSI/ISO C environment (and in many others as well),
 * this should best be defined by
 *
 * #ifndef NULL_PTR
 * #define NULL_PTR 0
 * #endif
 */

/* All the various Cryptoki types and #define'd values are in the
 * file pkcs11t.h. */
/* pkcs11t.h include file for PKCS #11. */
/* $Revision: 1.10 $ */

/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

/* See top of pkcs11.h for information about the macros that
 * must be defined and the structure-packing conventions that
 * must be set before including this file. */

#ifndef _PKCS11T_H_
#define _PKCS11T_H_ 1

#define CRYPTOKI_VERSION_MAJOR 2
#define CRYPTOKI_VERSION_MINOR 20
#define CRYPTOKI_VERSION_AMENDMENT 3

#define CK_TRUE 1
#define CK_FALSE 0

#ifndef CK_DISABLE_TRUE_FALSE
#ifndef FALSE
#define FALSE CK_FALSE
#endif

#ifndef TRUE
#define TRUE CK_TRUE
#endif
#endif

/* an unsigned 8-bit value */
typedef unsigned char     CK_BYTE;

/* an unsigned 8-bit character */
typedef CK_BYTE           CK_CHAR;

/* an 8-bit UTF-8 character */
typedef CK_BYTE           CK_UTF8CHAR;

/* a BYTE-sized Boolean flag */
typedef CK_BYTE           CK_BBOOL;

/* an unsigned value, at least 32 bits long */
typedef unsigned long int CK_ULONG;

/* a signed value, the same size as a CK_ULONG */
/* CK_LONG is new for v2.0 */
typedef long int          CK_LONG;

/* at least 32 bits; each bit is a Boolean flag */
typedef CK_ULONG          CK_FLAGS;

/* some special values for certain CK_ULONG variables */
#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE    0

typedef CK_BYTE     CK_PTR   CK_BYTE_PTR;
typedef CK_CHAR     CK_PTR   CK_CHAR_PTR;
typedef CK_UTF8CHAR CK_PTR   CK_UTF8CHAR_PTR;
typedef CK_ULONG    CK_PTR   CK_ULONG_PTR;
typedef void        CK_PTR   CK_VOID_PTR;

/* Pointer to a CK_VOID_PTR-- i.e., pointer to pointer to void */
typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;

/* The following value is always invalid if used as a session */
/* handle or object handle */
#define CK_INVALID_HANDLE 0

typedef struct CK_VERSION {
  CK_BYTE       major;  /* integer portion of version number */
  CK_BYTE       minor;  /* 1/100ths portion of version number */
} CK_VERSION;

typedef CK_VERSION CK_PTR CK_VERSION_PTR;

typedef struct CK_INFO {
  /* manufacturerID and libraryDecription have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  CK_VERSION    cryptokiVersion;     /* Cryptoki interface ver */
  CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
  CK_FLAGS      flags;               /* must be zero */

  /* libraryDescription and libraryVersion are new for v2.0 */
  CK_UTF8CHAR   libraryDescription[32];  /* blank padded */
  CK_VERSION    libraryVersion;          /* version of library */
} CK_INFO;

typedef CK_INFO CK_PTR    CK_INFO_PTR;

/* CK_NOTIFICATION enumerates the types of notifications that
 * Cryptoki provides to an application */
/* CK_NOTIFICATION has been changed from an enum to a CK_ULONG
 * for v2.0 */
typedef CK_ULONG CK_NOTIFICATION;
#define CKN_SURRENDER       0

/* The following notification is new for PKCS #11 v2.20 amendment 3 */
#define CKN_OTP_CHANGED     1

typedef CK_ULONG          CK_SLOT_ID;

typedef CK_SLOT_ID CK_PTR CK_SLOT_ID_PTR;

/* CK_SLOT_INFO provides information about a slot */
typedef struct CK_SLOT_INFO {
  /* slotDescription and manufacturerID have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  CK_UTF8CHAR   slotDescription[64];  /* blank padded */
  CK_UTF8CHAR   manufacturerID[32];   /* blank padded */
  CK_FLAGS      flags;

  /* hardwareVersion and firmwareVersion are new for v2.0 */
  CK_VERSION    hardwareVersion;  /* version of hardware */
  CK_VERSION    firmwareVersion;  /* version of firmware */
} CK_SLOT_INFO;

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag              Mask        Meaning
 */
#define CKF_TOKEN_PRESENT     0x00000001  /* a token is there */
#define CKF_REMOVABLE_DEVICE  0x00000002  /* removable devices*/
#define CKF_HW_SLOT           0x00000004  /* hardware slot */

typedef CK_SLOT_INFO CK_PTR CK_SLOT_INFO_PTR;

/* CK_TOKEN_INFO provides information about a token */
typedef struct CK_TOKEN_INFO {
  /* label, manufacturerID, and model have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  CK_UTF8CHAR   label[32];           /* blank padded */
  CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
  CK_UTF8CHAR   model[16];           /* blank padded */
  CK_CHAR       serialNumber[16];    /* blank padded */
  CK_FLAGS      flags;               /* see below */

  /* ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount,
   * ulRwSessionCount, ulMaxPinLen, and ulMinPinLen have all been
   * changed from CK_USHORT to CK_ULONG for v2.0 */
  CK_ULONG      ulMaxSessionCount;     /* max open sessions */
  CK_ULONG      ulSessionCount;        /* sess. now open */
  CK_ULONG      ulMaxRwSessionCount;   /* max R/W sessions */
  CK_ULONG      ulRwSessionCount;      /* R/W sess. now open */
  CK_ULONG      ulMaxPinLen;           /* in bytes */
  CK_ULONG      ulMinPinLen;           /* in bytes */
  CK_ULONG      ulTotalPublicMemory;   /* in bytes */
  CK_ULONG      ulFreePublicMemory;    /* in bytes */
  CK_ULONG      ulTotalPrivateMemory;  /* in bytes */
  CK_ULONG      ulFreePrivateMemory;   /* in bytes */

  /* hardwareVersion, firmwareVersion, and time are new for
   * v2.0 */
  CK_VERSION    hardwareVersion;       /* version of hardware */
  CK_VERSION    firmwareVersion;       /* version of firmware */
  CK_CHAR       utcTime[16];           /* time */
} CK_TOKEN_INFO;

/* The flags parameter is defined as follows:
 *      Bit Flag                    Mask        Meaning
 */
#define CKF_RNG                     0x00000001  /* has random #
                                                 * generator */
#define CKF_WRITE_PROTECTED         0x00000002  /* token is
                                                 * write-
                                                 * protected */
#define CKF_LOGIN_REQUIRED          0x00000004  /* user must
                                                 * login */
#define CKF_USER_PIN_INITIALIZED    0x00000008  /* normal user's
                                                 * PIN is set */

/* CKF_RESTORE_KEY_NOT_NEEDED is new for v2.0.  If it is set,
 * that means that *every* time the state of cryptographic
 * operations of a session is successfully saved, all keys
 * needed to continue those operations are stored in the state */
#define CKF_RESTORE_KEY_NOT_NEEDED  0x00000020

/* CKF_CLOCK_ON_TOKEN is new for v2.0.  If it is set, that means
 * that the token has some sort of clock.  The time on that
 * clock is returned in the token info structure */
#define CKF_CLOCK_ON_TOKEN          0x00000040

/* CKF_PROTECTED_AUTHENTICATION_PATH is new for v2.0.  If it is
 * set, that means that there is some way for the user to login
 * without sending a PIN through the Cryptoki library itself */
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100

/* CKF_DUAL_CRYPTO_OPERATIONS is new for v2.0.  If it is true,
 * that means that a single session with the token can perform
 * dual simultaneous cryptographic operations (digest and
 * encrypt; decrypt and digest; sign and encrypt; and decrypt
 * and sign) */
#define CKF_DUAL_CRYPTO_OPERATIONS  0x00000200

/* CKF_TOKEN_INITIALIZED if new for v2.10. If it is true, the
 * token has been initialized using C_InitializeToken or an
 * equivalent mechanism outside the scope of PKCS #11.
 * Calling C_InitializeToken when this flag is set will cause
 * the token to be reinitialized. */
#define CKF_TOKEN_INITIALIZED       0x00000400

/* CKF_SECONDARY_AUTHENTICATION if new for v2.10. If it is
 * true, the token supports secondary authentication for
 * private key objects. This flag is deprecated in v2.11 and
   onwards. */
#define CKF_SECONDARY_AUTHENTICATION  0x00000800

/* CKF_USER_PIN_COUNT_LOW if new for v2.10. If it is true, an
 * incorrect user login PIN has been entered at least once
 * since the last successful authentication. */
#define CKF_USER_PIN_COUNT_LOW       0x00010000

/* CKF_USER_PIN_FINAL_TRY if new for v2.10. If it is true,
 * supplying an incorrect user PIN will it to become locked. */
#define CKF_USER_PIN_FINAL_TRY       0x00020000

/* CKF_USER_PIN_LOCKED if new for v2.10. If it is true, the
 * user PIN has been locked. User login to the token is not
 * possible. */
#define CKF_USER_PIN_LOCKED          0x00040000

/* CKF_USER_PIN_TO_BE_CHANGED if new for v2.10. If it is true,
 * the user PIN value is the default value set by token
 * initialization or manufacturing, or the PIN has been
 * expired by the card. */
#define CKF_USER_PIN_TO_BE_CHANGED   0x00080000

/* CKF_SO_PIN_COUNT_LOW if new for v2.10. If it is true, an
 * incorrect SO login PIN has been entered at least once since
 * the last successful authentication. */
#define CKF_SO_PIN_COUNT_LOW         0x00100000

/* CKF_SO_PIN_FINAL_TRY if new for v2.10. If it is true,
 * supplying an incorrect SO PIN will it to become locked. */
#define CKF_SO_PIN_FINAL_TRY         0x00200000

/* CKF_SO_PIN_LOCKED if new for v2.10. If it is true, the SO
 * PIN has been locked. SO login to the token is not possible.
 */
#define CKF_SO_PIN_LOCKED            0x00400000

/* CKF_SO_PIN_TO_BE_CHANGED if new for v2.10. If it is true,
 * the SO PIN value is the default value set by token
 * initialization or manufacturing, or the PIN has been
 * expired by the card. */
#define CKF_SO_PIN_TO_BE_CHANGED     0x00800000

typedef CK_TOKEN_INFO CK_PTR CK_TOKEN_INFO_PTR;

/* CK_SESSION_HANDLE is a Cryptoki-assigned value that
 * identifies a session */
typedef CK_ULONG          CK_SESSION_HANDLE;

typedef CK_SESSION_HANDLE CK_PTR CK_SESSION_HANDLE_PTR;

/* CK_USER_TYPE enumerates the types of Cryptoki users */
/* CK_USER_TYPE has been changed from an enum to a CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_USER_TYPE;
/* Security Officer */
#define CKU_SO    0
/* Normal user */
#define CKU_USER  1
/* Context specific (added in v2.20) */
#define CKU_CONTEXT_SPECIFIC   2

/* CK_STATE enumerates the session states */
/* CK_STATE has been changed from an enum to a CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_STATE;
#define CKS_RO_PUBLIC_SESSION  0
#define CKS_RO_USER_FUNCTIONS  1
#define CKS_RW_PUBLIC_SESSION  2
#define CKS_RW_USER_FUNCTIONS  3
#define CKS_RW_SO_FUNCTIONS    4

/* CK_SESSION_INFO provides information about a session */
typedef struct CK_SESSION_INFO {
  CK_SLOT_ID    slotID;
  CK_STATE      state;
  CK_FLAGS      flags;          /* see below */

  /* ulDeviceError was changed from CK_USHORT to CK_ULONG for
   * v2.0 */
  CK_ULONG      ulDeviceError;  /* device-dependent error code */
} CK_SESSION_INFO;

/* The flags are defined in the following table:
 *      Bit Flag                Mask        Meaning
 */
#define CKF_RW_SESSION          0x00000002  /* session is r/w */
#define CKF_SERIAL_SESSION      0x00000004  /* no parallel */

typedef CK_SESSION_INFO CK_PTR CK_SESSION_INFO_PTR;

/* CK_OBJECT_HANDLE is a token-specific identifier for an
 * object  */
typedef CK_ULONG          CK_OBJECT_HANDLE;

typedef CK_OBJECT_HANDLE CK_PTR CK_OBJECT_HANDLE_PTR;

/* CK_OBJECT_CLASS is a value that identifies the classes (or
 * types) of objects that Cryptoki recognizes.  It is defined
 * as follows: */
/* CK_OBJECT_CLASS was changed from CK_USHORT to CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_OBJECT_CLASS;

/* The following classes of objects are defined: */
/* CKO_HW_FEATURE is new for v2.10 */
/* CKO_DOMAIN_PARAMETERS is new for v2.11 */
/* CKO_MECHANISM is new for v2.20 */
#define CKO_DATA              0x00000000
#define CKO_CERTIFICATE       0x00000001
#define CKO_PUBLIC_KEY        0x00000002
#define CKO_PRIVATE_KEY       0x00000003
#define CKO_SECRET_KEY        0x00000004
#define CKO_HW_FEATURE        0x00000005
#define CKO_DOMAIN_PARAMETERS 0x00000006
#define CKO_MECHANISM         0x00000007

/* CKO_OTP_KEY is new for PKCS #11 v2.20 amendment 1 */
#define CKO_OTP_KEY           0x00000008

#define CKO_VENDOR_DEFINED    0x80000000

typedef CK_OBJECT_CLASS CK_PTR CK_OBJECT_CLASS_PTR;

/* CK_HW_FEATURE_TYPE is new for v2.10. CK_HW_FEATURE_TYPE is a
 * value that identifies the hardware feature type of an object
 * with CK_OBJECT_CLASS equal to CKO_HW_FEATURE. */
typedef CK_ULONG          CK_HW_FEATURE_TYPE;

/* The following hardware feature types are defined */
/* CKH_USER_INTERFACE is new for v2.20 */
#define CKH_MONOTONIC_COUNTER  0x00000001
#define CKH_CLOCK           0x00000002
#define CKH_USER_INTERFACE  0x00000003
#define CKH_VENDOR_DEFINED  0x80000000

/* CK_KEY_TYPE is a value that identifies a key type */
/* CK_KEY_TYPE was changed from CK_USHORT to CK_ULONG for v2.0 */
typedef CK_ULONG          CK_KEY_TYPE;

/* the following key types are defined: */
#define CKK_RSA             0x00000000
#define CKK_DSA             0x00000001
#define CKK_DH              0x00000002

/* CKK_ECDSA and CKK_KEA are new for v2.0 */
/* CKK_ECDSA is deprecated in v2.11, CKK_EC is preferred. */
#define CKK_ECDSA           0x00000003
#define CKK_EC              0x00000003
#define CKK_X9_42_DH        0x00000004
#define CKK_KEA             0x00000005

#define CKK_GENERIC_SECRET  0x00000010
#define CKK_RC2             0x00000011
#define CKK_RC4             0x00000012
#define CKK_DES             0x00000013
#define CKK_DES2            0x00000014
#define CKK_DES3            0x00000015

/* all these key types are new for v2.0 */
#define CKK_CAST            0x00000016
#define CKK_CAST3           0x00000017
/* CKK_CAST5 is deprecated in v2.11, CKK_CAST128 is preferred. */
#define CKK_CAST5           0x00000018
#define CKK_CAST128         0x00000018
#define CKK_RC5             0x00000019
#define CKK_IDEA            0x0000001A
#define CKK_SKIPJACK        0x0000001B
#define CKK_BATON           0x0000001C
#define CKK_JUNIPER         0x0000001D
#define CKK_CDMF            0x0000001E
#define CKK_AES             0x0000001F

/* BlowFish and TwoFish are new for v2.20 */
#define CKK_BLOWFISH        0x00000020
#define CKK_TWOFISH         0x00000021

/* SecurID, HOTP, and ACTI are new for PKCS #11 v2.20 amendment 1 */
#define CKK_SECURID         0x00000022
#define CKK_HOTP            0x00000023
#define CKK_ACTI            0x00000024

/* Camellia is new for PKCS #11 v2.20 amendment 3 */
#define CKK_CAMELLIA                   0x00000025
/* ARIA is new for PKCS #11 v2.20 amendment 3 */
#define CKK_ARIA                       0x00000026

#define CKK_VENDOR_DEFINED  0x80000000

/* CK_CERTIFICATE_TYPE is a value that identifies a certificate
 * type */
/* CK_CERTIFICATE_TYPE was changed from CK_USHORT to CK_ULONG
 * for v2.0 */
typedef CK_ULONG          CK_CERTIFICATE_TYPE;

/* The following certificate types are defined: */
/* CKC_X_509_ATTR_CERT is new for v2.10 */
/* CKC_WTLS is new for v2.20 */
#define CKC_X_509           0x00000000
#define CKC_X_509_ATTR_CERT 0x00000001
#define CKC_WTLS            0x00000002
#define CKC_VENDOR_DEFINED  0x80000000

/* CK_ATTRIBUTE_TYPE is a value that identifies an attribute
 * type */
/* CK_ATTRIBUTE_TYPE was changed from CK_USHORT to CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_ATTRIBUTE_TYPE;

/* The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
   consists of an array of values. */
#define CKF_ARRAY_ATTRIBUTE    0x40000000

/* The following OTP-related defines are new for PKCS #11 v2.20 amendment 1
   and relates to the CKA_OTP_FORMAT attribute */
#define CK_OTP_FORMAT_DECIMAL      0
#define CK_OTP_FORMAT_HEXADECIMAL  1
#define CK_OTP_FORMAT_ALPHANUMERIC 2
#define CK_OTP_FORMAT_BINARY       3

/* The following OTP-related defines are new for PKCS #11 v2.20 amendment 1
   and relates to the CKA_OTP_..._REQUIREMENT attributes */
#define CK_OTP_PARAM_IGNORED       0
#define CK_OTP_PARAM_OPTIONAL      1
#define CK_OTP_PARAM_MANDATORY     2

/* The following attribute types are defined: */
#define CKA_CLASS              0x00000000
#define CKA_TOKEN              0x00000001
#define CKA_PRIVATE            0x00000002
#define CKA_LABEL              0x00000003
#define CKA_APPLICATION        0x00000010
#define CKA_VALUE              0x00000011

/* CKA_OBJECT_ID is new for v2.10 */
#define CKA_OBJECT_ID          0x00000012

#define CKA_CERTIFICATE_TYPE   0x00000080
#define CKA_ISSUER             0x00000081
#define CKA_SERIAL_NUMBER      0x00000082

/* CKA_AC_ISSUER, CKA_OWNER, and CKA_ATTR_TYPES are new
 * for v2.10 */
#define CKA_AC_ISSUER          0x00000083
#define CKA_OWNER              0x00000084
#define CKA_ATTR_TYPES         0x00000085

/* CKA_TRUSTED is new for v2.11 */
#define CKA_TRUSTED            0x00000086

/* CKA_CERTIFICATE_CATEGORY ...
 * CKA_CHECK_VALUE are new for v2.20 */
#define CKA_CERTIFICATE_CATEGORY        0x00000087
#define CKA_JAVA_MIDP_SECURITY_DOMAIN   0x00000088
#define CKA_URL                         0x00000089
#define CKA_HASH_OF_SUBJECT_PUBLIC_KEY  0x0000008A
#define CKA_HASH_OF_ISSUER_PUBLIC_KEY   0x0000008B
#define CKA_CHECK_VALUE                 0x00000090

#define CKA_KEY_TYPE           0x00000100
#define CKA_SUBJECT            0x00000101
#define CKA_ID                 0x00000102
#define CKA_SENSITIVE          0x00000103
#define CKA_ENCRYPT            0x00000104
#define CKA_DECRYPT            0x00000105
#define CKA_WRAP               0x00000106
#define CKA_UNWRAP             0x00000107
#define CKA_SIGN               0x00000108
#define CKA_SIGN_RECOVER       0x00000109
#define CKA_VERIFY             0x0000010A
#define CKA_VERIFY_RECOVER     0x0000010B
#define CKA_DERIVE             0x0000010C
#define CKA_START_DATE         0x00000110
#define CKA_END_DATE           0x00000111
#define CKA_MODULUS            0x00000120
#define CKA_MODULUS_BITS       0x00000121
#define CKA_PUBLIC_EXPONENT    0x00000122
#define CKA_PRIVATE_EXPONENT   0x00000123
#define CKA_PRIME_1            0x00000124
#define CKA_PRIME_2            0x00000125
#define CKA_EXPONENT_1         0x00000126
#define CKA_EXPONENT_2         0x00000127
#define CKA_COEFFICIENT        0x00000128
#define CKA_PRIME              0x00000130
#define CKA_SUBPRIME           0x00000131
#define CKA_BASE               0x00000132

/* CKA_PRIME_BITS and CKA_SUB_PRIME_BITS are new for v2.11 */
#define CKA_PRIME_BITS         0x00000133
#define CKA_SUBPRIME_BITS      0x00000134
#define CKA_SUB_PRIME_BITS     CKA_SUBPRIME_BITS
/* (To retain backwards-compatibility) */

#define CKA_VALUE_BITS         0x00000160
#define CKA_VALUE_LEN          0x00000161

/* CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
 * CKA_ALWAYS_SENSITIVE, CKA_MODIFIABLE, CKA_ECDSA_PARAMS,
 * and CKA_EC_POINT are new for v2.0 */
#define CKA_EXTRACTABLE        0x00000162
#define CKA_LOCAL              0x00000163
#define CKA_NEVER_EXTRACTABLE  0x00000164
#define CKA_ALWAYS_SENSITIVE   0x00000165

/* CKA_KEY_GEN_MECHANISM is new for v2.11 */
#define CKA_KEY_GEN_MECHANISM  0x00000166

#define CKA_MODIFIABLE         0x00000170

/* CKA_ECDSA_PARAMS is deprecated in v2.11,
 * CKA_EC_PARAMS is preferred. */
#define CKA_ECDSA_PARAMS       0x00000180
#define CKA_EC_PARAMS          0x00000180

#define CKA_EC_POINT           0x00000181

/* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
 * are new for v2.10. Deprecated in v2.11 and onwards. */
#define CKA_SECONDARY_AUTH     0x00000200
#define CKA_AUTH_PIN_FLAGS     0x00000201

/* CKA_ALWAYS_AUTHENTICATE ...
 * CKA_UNWRAP_TEMPLATE are new for v2.20 */
#define CKA_ALWAYS_AUTHENTICATE  0x00000202

#define CKA_WRAP_WITH_TRUSTED    0x00000210
#define CKA_WRAP_TEMPLATE        (CKF_ARRAY_ATTRIBUTE|0x00000211)
#define CKA_UNWRAP_TEMPLATE      (CKF_ARRAY_ATTRIBUTE|0x00000212)

/* CKA_OTP... atttributes are new for PKCS #11 v2.20 amendment 3. */
#define CKA_OTP_FORMAT                0x00000220
#define CKA_OTP_LENGTH                0x00000221
#define CKA_OTP_TIME_INTERVAL         0x00000222
#define CKA_OTP_USER_FRIENDLY_MODE    0x00000223
#define CKA_OTP_CHALLENGE_REQUIREMENT 0x00000224
#define CKA_OTP_TIME_REQUIREMENT      0x00000225
#define CKA_OTP_COUNTER_REQUIREMENT   0x00000226
#define CKA_OTP_PIN_REQUIREMENT       0x00000227
#define CKA_OTP_COUNTER               0x0000022E
#define CKA_OTP_TIME                  0x0000022F
#define CKA_OTP_USER_IDENTIFIER       0x0000022A
#define CKA_OTP_SERVICE_IDENTIFIER    0x0000022B
#define CKA_OTP_SERVICE_LOGO          0x0000022C
#define CKA_OTP_SERVICE_LOGO_TYPE     0x0000022D

/* CKA_HW_FEATURE_TYPE, CKA_RESET_ON_INIT, and CKA_HAS_RESET
 * are new for v2.10 */
#define CKA_HW_FEATURE_TYPE    0x00000300
#define CKA_RESET_ON_INIT      0x00000301
#define CKA_HAS_RESET          0x00000302

/* The following attributes are new for v2.20 */
#define CKA_PIXEL_X                     0x00000400
#define CKA_PIXEL_Y                     0x00000401
#define CKA_RESOLUTION                  0x00000402
#define CKA_CHAR_ROWS                   0x00000403
#define CKA_CHAR_COLUMNS                0x00000404
#define CKA_COLOR                       0x00000405
#define CKA_BITS_PER_PIXEL              0x00000406
#define CKA_CHAR_SETS                   0x00000480
#define CKA_ENCODING_METHODS            0x00000481
#define CKA_MIME_TYPES                  0x00000482
#define CKA_MECHANISM_TYPE              0x00000500
#define CKA_REQUIRED_CMS_ATTRIBUTES     0x00000501
#define CKA_DEFAULT_CMS_ATTRIBUTES      0x00000502
#define CKA_SUPPORTED_CMS_ATTRIBUTES    0x00000503
#define CKA_ALLOWED_MECHANISMS          (CKF_ARRAY_ATTRIBUTE|0x00000600)

#define CKA_VENDOR_DEFINED     0x80000000

/* CK_ATTRIBUTE is a structure that includes the type, length
 * and value of an attribute */
typedef struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  CK_VOID_PTR       pValue;

  /* ulValueLen went from CK_USHORT to CK_ULONG for v2.0 */
  CK_ULONG          ulValueLen;  /* in bytes */
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;

/* CK_DATE is a structure that defines a date */
typedef struct CK_DATE{
  CK_CHAR       year[4];   /* the year ("1900" - "9999") */
  CK_CHAR       month[2];  /* the month ("01" - "12") */
  CK_CHAR       day[2];    /* the day   ("01" - "31") */
} CK_DATE;

/* CK_MECHANISM_TYPE is a value that identifies a mechanism
 * type */
/* CK_MECHANISM_TYPE was changed from CK_USHORT to CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_MECHANISM_TYPE;

/* the following mechanism types are defined: */
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x00000000
#define CKM_RSA_PKCS                   0x00000001
#define CKM_RSA_9796                   0x00000002
#define CKM_RSA_X_509                  0x00000003

/* CKM_MD2_RSA_PKCS, CKM_MD5_RSA_PKCS, and CKM_SHA1_RSA_PKCS
 * are new for v2.0.  They are mechanisms which hash and sign */
#define CKM_MD2_RSA_PKCS               0x00000004
#define CKM_MD5_RSA_PKCS               0x00000005
#define CKM_SHA1_RSA_PKCS              0x00000006

/* CKM_RIPEMD128_RSA_PKCS, CKM_RIPEMD160_RSA_PKCS, and
 * CKM_RSA_PKCS_OAEP are new for v2.10 */
#define CKM_RIPEMD128_RSA_PKCS         0x00000007
#define CKM_RIPEMD160_RSA_PKCS         0x00000008
#define CKM_RSA_PKCS_OAEP              0x00000009

/* CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_X9_31, CKM_SHA1_RSA_X9_31,
 * CKM_RSA_PKCS_PSS, and CKM_SHA1_RSA_PKCS_PSS are new for v2.11 */
#define CKM_RSA_X9_31_KEY_PAIR_GEN     0x0000000A
#define CKM_RSA_X9_31                  0x0000000B
#define CKM_SHA1_RSA_X9_31             0x0000000C
#define CKM_RSA_PKCS_PSS               0x0000000D
#define CKM_SHA1_RSA_PKCS_PSS          0x0000000E

#define CKM_DSA_KEY_PAIR_GEN           0x00000010
#define CKM_DSA                        0x00000011
#define CKM_DSA_SHA1                   0x00000012
#define CKM_DH_PKCS_KEY_PAIR_GEN       0x00000020
#define CKM_DH_PKCS_DERIVE             0x00000021

/* CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE,
 * CKM_X9_42_DH_HYBRID_DERIVE, and CKM_X9_42_MQV_DERIVE are new for
 * v2.11 */
#define CKM_X9_42_DH_KEY_PAIR_GEN      0x00000030
#define CKM_X9_42_DH_DERIVE            0x00000031
#define CKM_X9_42_DH_HYBRID_DERIVE     0x00000032
#define CKM_X9_42_MQV_DERIVE           0x00000033

/* CKM_SHA256/384/512 are new for v2.20 */
#define CKM_SHA256_RSA_PKCS            0x00000040
#define CKM_SHA384_RSA_PKCS            0x00000041
#define CKM_SHA512_RSA_PKCS            0x00000042
#define CKM_SHA256_RSA_PKCS_PSS        0x00000043
#define CKM_SHA384_RSA_PKCS_PSS        0x00000044
#define CKM_SHA512_RSA_PKCS_PSS        0x00000045

/* SHA-224 RSA mechanisms are new for PKCS #11 v2.20 amendment 3 */
#define CKM_SHA224_RSA_PKCS            0x00000046
#define CKM_SHA224_RSA_PKCS_PSS        0x00000047

#define CKM_RC2_KEY_GEN                0x00000100
#define CKM_RC2_ECB                    0x00000101
#define CKM_RC2_CBC                    0x00000102
#define CKM_RC2_MAC                    0x00000103

/* CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0 */
#define CKM_RC2_MAC_GENERAL            0x00000104
#define CKM_RC2_CBC_PAD                0x00000105

#define CKM_RC4_KEY_GEN                0x00000110
#define CKM_RC4                        0x00000111
#define CKM_DES_KEY_GEN                0x00000120
#define CKM_DES_ECB                    0x00000121
#define CKM_DES_CBC                    0x00000122
#define CKM_DES_MAC                    0x00000123

/* CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0 */
#define CKM_DES_MAC_GENERAL            0x00000124
#define CKM_DES_CBC_PAD                0x00000125

#define CKM_DES2_KEY_GEN               0x00000130
#define CKM_DES3_KEY_GEN               0x00000131
#define CKM_DES3_ECB                   0x00000132
#define CKM_DES3_CBC                   0x00000133
#define CKM_DES3_MAC                   0x00000134

/* CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN,
 * CKM_CDMF_ECB, CKM_CDMF_CBC, CKM_CDMF_MAC,
 * CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0 */
#define CKM_DES3_MAC_GENERAL           0x00000135
#define CKM_DES3_CBC_PAD               0x00000136
#define CKM_CDMF_KEY_GEN               0x00000140
#define CKM_CDMF_ECB                   0x00000141
#define CKM_CDMF_CBC                   0x00000142
#define CKM_CDMF_MAC                   0x00000143
#define CKM_CDMF_MAC_GENERAL           0x00000144
#define CKM_CDMF_CBC_PAD               0x00000145

/* the following four DES mechanisms are new for v2.20 */
#define CKM_DES_OFB64                  0x00000150
#define CKM_DES_OFB8                   0x00000151
#define CKM_DES_CFB64                  0x00000152
#define CKM_DES_CFB8                   0x00000153

#define CKM_MD2                        0x00000200

/* CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0 */
#define CKM_MD2_HMAC                   0x00000201
#define CKM_MD2_HMAC_GENERAL           0x00000202

#define CKM_MD5                        0x00000210

/* CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0 */
#define CKM_MD5_HMAC                   0x00000211
#define CKM_MD5_HMAC_GENERAL           0x00000212

#define CKM_SHA_1                      0x00000220

/* CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0 */
#define CKM_SHA_1_HMAC                 0x00000221
#define CKM_SHA_1_HMAC_GENERAL         0x00000222

/* CKM_RIPEMD128, CKM_RIPEMD128_HMAC,
 * CKM_RIPEMD128_HMAC_GENERAL, CKM_RIPEMD160, CKM_RIPEMD160_HMAC,
 * and CKM_RIPEMD160_HMAC_GENERAL are new for v2.10 */
#define CKM_RIPEMD128                  0x00000230
#define CKM_RIPEMD128_HMAC             0x00000231
#define CKM_RIPEMD128_HMAC_GENERAL     0x00000232
#define CKM_RIPEMD160                  0x00000240
#define CKM_RIPEMD160_HMAC             0x00000241
#define CKM_RIPEMD160_HMAC_GENERAL     0x00000242

/* CKM_SHA256/384/512 are new for v2.20 */
#define CKM_SHA256                     0x00000250
#define CKM_SHA256_HMAC                0x00000251
#define CKM_SHA256_HMAC_GENERAL        0x00000252

/* SHA-224 is new for PKCS #11 v2.20 amendment 3 */
#define CKM_SHA224                     0x00000255
#define CKM_SHA224_HMAC                0x00000256
#define CKM_SHA224_HMAC_GENERAL        0x00000257

#define CKM_SHA384                     0x00000260
#define CKM_SHA384_HMAC                0x00000261
#define CKM_SHA384_HMAC_GENERAL        0x00000262
#define CKM_SHA512                     0x00000270
#define CKM_SHA512_HMAC                0x00000271
#define CKM_SHA512_HMAC_GENERAL        0x00000272

/* SecurID is new for PKCS #11 v2.20 amendment 1 */
#define CKM_SECURID_KEY_GEN            0x00000280
#define CKM_SECURID                    0x00000282

/* HOTP is new for PKCS #11 v2.20 amendment 1 */
#define CKM_HOTP_KEY_GEN    0x00000290
#define CKM_HOTP            0x00000291

/* ACTI is new for PKCS #11 v2.20 amendment 1 */
#define CKM_ACTI            0x000002A0
#define CKM_ACTI_KEY_GEN    0x000002A1

/* All of the following mechanisms are new for v2.0 */
/* Note that CAST128 and CAST5 are the same algorithm */
#define CKM_CAST_KEY_GEN               0x00000300
#define CKM_CAST_ECB                   0x00000301
#define CKM_CAST_CBC                   0x00000302
#define CKM_CAST_MAC                   0x00000303
#define CKM_CAST_MAC_GENERAL           0x00000304
#define CKM_CAST_CBC_PAD               0x00000305
#define CKM_CAST3_KEY_GEN              0x00000310
#define CKM_CAST3_ECB                  0x00000311
#define CKM_CAST3_CBC                  0x00000312
#define CKM_CAST3_MAC                  0x00000313
#define CKM_CAST3_MAC_GENERAL          0x00000314
#define CKM_CAST3_CBC_PAD              0x00000315
#define CKM_CAST5_KEY_GEN              0x00000320
#define CKM_CAST128_KEY_GEN            0x00000320
#define CKM_CAST5_ECB                  0x00000321
#define CKM_CAST128_ECB                0x00000321
#define CKM_CAST5_CBC                  0x00000322
#define CKM_CAST128_CBC                0x00000322
#define CKM_CAST5_MAC                  0x00000323
#define CKM_CAST128_MAC                0x00000323
#define CKM_CAST5_MAC_GENERAL          0x00000324
#define CKM_CAST128_MAC_GENERAL        0x00000324
#define CKM_CAST5_CBC_PAD              0x00000325
#define CKM_CAST128_CBC_PAD            0x00000325
#define CKM_RC5_KEY_GEN                0x00000330
#define CKM_RC5_ECB                    0x00000331
#define CKM_RC5_CBC                    0x00000332
#define CKM_RC5_MAC                    0x00000333
#define CKM_RC5_MAC_GENERAL            0x00000334
#define CKM_RC5_CBC_PAD                0x00000335
#define CKM_IDEA_KEY_GEN               0x00000340
#define CKM_IDEA_ECB                   0x00000341
#define CKM_IDEA_CBC                   0x00000342
#define CKM_IDEA_MAC                   0x00000343
#define CKM_IDEA_MAC_GENERAL           0x00000344
#define CKM_IDEA_CBC_PAD               0x00000345
#define CKM_GENERIC_SECRET_KEY_GEN     0x00000350
#define CKM_CONCATENATE_BASE_AND_KEY   0x00000360
#define CKM_CONCATENATE_BASE_AND_DATA  0x00000362
#define CKM_CONCATENATE_DATA_AND_BASE  0x00000363
#define CKM_XOR_BASE_AND_DATA          0x00000364
#define CKM_EXTRACT_KEY_FROM_KEY       0x00000365
#define CKM_SSL3_PRE_MASTER_KEY_GEN    0x00000370
#define CKM_SSL3_MASTER_KEY_DERIVE     0x00000371
#define CKM_SSL3_KEY_AND_MAC_DERIVE    0x00000372

/* CKM_SSL3_MASTER_KEY_DERIVE_DH, CKM_TLS_PRE_MASTER_KEY_GEN,
 * CKM_TLS_MASTER_KEY_DERIVE, CKM_TLS_KEY_AND_MAC_DERIVE, and
 * CKM_TLS_MASTER_KEY_DERIVE_DH are new for v2.11 */
#define CKM_SSL3_MASTER_KEY_DERIVE_DH  0x00000373
#define CKM_TLS_PRE_MASTER_KEY_GEN     0x00000374
#define CKM_TLS_MASTER_KEY_DERIVE      0x00000375
#define CKM_TLS_KEY_AND_MAC_DERIVE     0x00000376
#define CKM_TLS_MASTER_KEY_DERIVE_DH   0x00000377

/* CKM_TLS_PRF is new for v2.20 */
#define CKM_TLS_PRF                    0x00000378

#define CKM_SSL3_MD5_MAC               0x00000380
#define CKM_SSL3_SHA1_MAC              0x00000381
#define CKM_MD5_KEY_DERIVATION         0x00000390
#define CKM_MD2_KEY_DERIVATION         0x00000391
#define CKM_SHA1_KEY_DERIVATION        0x00000392

/* CKM_SHA256/384/512 are new for v2.20 */
#define CKM_SHA256_KEY_DERIVATION      0x00000393
#define CKM_SHA384_KEY_DERIVATION      0x00000394
#define CKM_SHA512_KEY_DERIVATION      0x00000395

/* SHA-224 key derivation is new for PKCS #11 v2.20 amendment 3 */
#define CKM_SHA224_KEY_DERIVATION      0x00000396

#define CKM_PBE_MD2_DES_CBC            0x000003A0
#define CKM_PBE_MD5_DES_CBC            0x000003A1
#define CKM_PBE_MD5_CAST_CBC           0x000003A2
#define CKM_PBE_MD5_CAST3_CBC          0x000003A3
#define CKM_PBE_MD5_CAST5_CBC          0x000003A4
#define CKM_PBE_MD5_CAST128_CBC        0x000003A4
#define CKM_PBE_SHA1_CAST5_CBC         0x000003A5
#define CKM_PBE_SHA1_CAST128_CBC       0x000003A5
#define CKM_PBE_SHA1_RC4_128           0x000003A6
#define CKM_PBE_SHA1_RC4_40            0x000003A7
#define CKM_PBE_SHA1_DES3_EDE_CBC      0x000003A8
#define CKM_PBE_SHA1_DES2_EDE_CBC      0x000003A9
#define CKM_PBE_SHA1_RC2_128_CBC       0x000003AA
#define CKM_PBE_SHA1_RC2_40_CBC        0x000003AB

/* CKM_PKCS5_PBKD2 is new for v2.10 */
#define CKM_PKCS5_PBKD2                0x000003B0

#define CKM_PBA_SHA1_WITH_SHA1_HMAC    0x000003C0

/* WTLS mechanisms are new for v2.20 */
#define CKM_WTLS_PRE_MASTER_KEY_GEN         0x000003D0
#define CKM_WTLS_MASTER_KEY_DERIVE          0x000003D1
#define CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   0x000003D2
#define CKM_WTLS_PRF                        0x000003D3
#define CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  0x000003D4
#define CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  0x000003D5

#define CKM_KEY_WRAP_LYNKS             0x00000400
#define CKM_KEY_WRAP_SET_OAEP          0x00000401

/* CKM_CMS_SIG is new for v2.20 */
#define CKM_CMS_SIG                    0x00000500

/* CKM_KIP mechanisms are new for PKCS #11 v2.20 amendment 2 */
#define CKM_KIP_DERIVE	               0x00000510
#define CKM_KIP_WRAP	               0x00000511
#define CKM_KIP_MAC	               0x00000512

/* Camellia is new for PKCS #11 v2.20 amendment 3 */
#define CKM_CAMELLIA_KEY_GEN           0x00000550
#define CKM_CAMELLIA_ECB               0x00000551
#define CKM_CAMELLIA_CBC               0x00000552
#define CKM_CAMELLIA_MAC               0x00000553
#define CKM_CAMELLIA_MAC_GENERAL       0x00000554
#define CKM_CAMELLIA_CBC_PAD           0x00000555
#define CKM_CAMELLIA_ECB_ENCRYPT_DATA  0x00000556
#define CKM_CAMELLIA_CBC_ENCRYPT_DATA  0x00000557
#define CKM_CAMELLIA_CTR               0x00000558

/* ARIA is new for PKCS #11 v2.20 amendment 3 */
#define CKM_ARIA_KEY_GEN               0x00000560
#define CKM_ARIA_ECB                   0x00000561
#define CKM_ARIA_CBC                   0x00000562
#define CKM_ARIA_MAC                   0x00000563
#define CKM_ARIA_MAC_GENERAL           0x00000564
#define CKM_ARIA_CBC_PAD               0x00000565
#define CKM_ARIA_ECB_ENCRYPT_DATA      0x00000566
#define CKM_ARIA_CBC_ENCRYPT_DATA      0x00000567

/* Fortezza mechanisms */
#define CKM_SKIPJACK_KEY_GEN           0x00001000
#define CKM_SKIPJACK_ECB64             0x00001001
#define CKM_SKIPJACK_CBC64             0x00001002
#define CKM_SKIPJACK_OFB64             0x00001003
#define CKM_SKIPJACK_CFB64             0x00001004
#define CKM_SKIPJACK_CFB32             0x00001005
#define CKM_SKIPJACK_CFB16             0x00001006
#define CKM_SKIPJACK_CFB8              0x00001007
#define CKM_SKIPJACK_WRAP              0x00001008
#define CKM_SKIPJACK_PRIVATE_WRAP      0x00001009
#define CKM_SKIPJACK_RELAYX            0x0000100a
#define CKM_KEA_KEY_PAIR_GEN           0x00001010
#define CKM_KEA_KEY_DERIVE             0x00001011
#define CKM_FORTEZZA_TIMESTAMP         0x00001020
#define CKM_BATON_KEY_GEN              0x00001030
#define CKM_BATON_ECB128               0x00001031
#define CKM_BATON_ECB96                0x00001032
#define CKM_BATON_CBC128               0x00001033
#define CKM_BATON_COUNTER              0x00001034
#define CKM_BATON_SHUFFLE              0x00001035
#define CKM_BATON_WRAP                 0x00001036

/* CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
 * CKM_EC_KEY_PAIR_GEN is preferred */
#define CKM_ECDSA_KEY_PAIR_GEN         0x00001040
#define CKM_EC_KEY_PAIR_GEN            0x00001040

#define CKM_ECDSA                      0x00001041
#define CKM_ECDSA_SHA1                 0x00001042

/* CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, and CKM_ECMQV_DERIVE
 * are new for v2.11 */
#define CKM_ECDH1_DERIVE               0x00001050
#define CKM_ECDH1_COFACTOR_DERIVE      0x00001051
#define CKM_ECMQV_DERIVE               0x00001052

#define CKM_JUNIPER_KEY_GEN            0x00001060
#define CKM_JUNIPER_ECB128             0x00001061
#define CKM_JUNIPER_CBC128             0x00001062
#define CKM_JUNIPER_COUNTER            0x00001063
#define CKM_JUNIPER_SHUFFLE            0x00001064
#define CKM_JUNIPER_WRAP               0x00001065
#define CKM_FASTHASH                   0x00001070

/* CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC,
 * CKM_AES_MAC_GENERAL, CKM_AES_CBC_PAD, CKM_DSA_PARAMETER_GEN,
 * CKM_DH_PKCS_PARAMETER_GEN, and CKM_X9_42_DH_PARAMETER_GEN are
 * new for v2.11 */
#define CKM_AES_KEY_GEN                0x00001080
#define CKM_AES_ECB                    0x00001081
#define CKM_AES_CBC                    0x00001082
#define CKM_AES_MAC                    0x00001083
#define CKM_AES_MAC_GENERAL            0x00001084
#define CKM_AES_CBC_PAD                0x00001085

/* AES counter mode is new for PKCS #11 v2.20 amendment 3 */
#define CKM_AES_CTR                    0x00001086

/* BlowFish and TwoFish are new for v2.20 */
#define CKM_BLOWFISH_KEY_GEN           0x00001090
#define CKM_BLOWFISH_CBC               0x00001091
#define CKM_TWOFISH_KEY_GEN            0x00001092
#define CKM_TWOFISH_CBC                0x00001093

/* CKM_xxx_ENCRYPT_DATA mechanisms are new for v2.20 */
#define CKM_DES_ECB_ENCRYPT_DATA       0x00001100
#define CKM_DES_CBC_ENCRYPT_DATA       0x00001101
#define CKM_DES3_ECB_ENCRYPT_DATA      0x00001102
#define CKM_DES3_CBC_ENCRYPT_DATA      0x00001103
#define CKM_AES_ECB_ENCRYPT_DATA       0x00001104
#define CKM_AES_CBC_ENCRYPT_DATA       0x00001105

#define CKM_DSA_PARAMETER_GEN          0x00002000
#define CKM_DH_PKCS_PARAMETER_GEN      0x00002001
#define CKM_X9_42_DH_PARAMETER_GEN     0x00002002

#define CKM_VENDOR_DEFINED             0x80000000

typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;

/* CK_MECHANISM is a structure that specifies a particular
 * mechanism  */
typedef struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR       pParameter;

  /* ulParameterLen was changed from CK_USHORT to CK_ULONG for
   * v2.0 */
  CK_ULONG          ulParameterLen;  /* in bytes */
} CK_MECHANISM;

typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;

/* CK_MECHANISM_INFO provides information about a particular
 * mechanism */
typedef struct CK_MECHANISM_INFO {
    CK_ULONG    ulMinKeySize;
    CK_ULONG    ulMaxKeySize;
    CK_FLAGS    flags;
} CK_MECHANISM_INFO;

/* The flags are defined as follows:
 *      Bit Flag               Mask        Meaning */
#define CKF_HW                 0x00000001  /* performed by HW */

/* The flags CKF_ENCRYPT, CKF_DECRYPT, CKF_DIGEST, CKF_SIGN,
 * CKG_SIGN_RECOVER, CKF_VERIFY, CKF_VERIFY_RECOVER,
 * CKF_GENERATE, CKF_GENERATE_KEY_PAIR, CKF_WRAP, CKF_UNWRAP,
 * and CKF_DERIVE are new for v2.0.  They specify whether or not
 * a mechanism can be used for a particular task */
#define CKF_ENCRYPT            0x00000100
#define CKF_DECRYPT            0x00000200
#define CKF_DIGEST             0x00000400
#define CKF_SIGN               0x00000800
#define CKF_SIGN_RECOVER       0x00001000
#define CKF_VERIFY             0x00002000
#define CKF_VERIFY_RECOVER     0x00004000
#define CKF_GENERATE           0x00008000
#define CKF_GENERATE_KEY_PAIR  0x00010000
#define CKF_WRAP               0x00020000
#define CKF_UNWRAP             0x00040000
#define CKF_DERIVE             0x00080000

/* CKF_EC_F_P, CKF_EC_F_2M, CKF_EC_ECPARAMETERS, CKF_EC_NAMEDCURVE,
 * CKF_EC_UNCOMPRESS, and CKF_EC_COMPRESS are new for v2.11. They
 * describe a token's EC capabilities not available in mechanism
 * information. */
#define CKF_EC_F_P             0x00100000
#define CKF_EC_F_2M            0x00200000
#define CKF_EC_ECPARAMETERS    0x00400000
#define CKF_EC_NAMEDCURVE      0x00800000
#define CKF_EC_UNCOMPRESS      0x01000000
#define CKF_EC_COMPRESS        0x02000000

#define CKF_EXTENSION          0x80000000 /* FALSE for this version */

typedef CK_MECHANISM_INFO CK_PTR CK_MECHANISM_INFO_PTR;

/* CK_RV is a value that identifies the return value of a
 * Cryptoki function */
/* CK_RV was changed from CK_USHORT to CK_ULONG for v2.0 */
typedef CK_ULONG          CK_RV;

#define CKR_OK                                0x00000000
#define CKR_CANCEL                            0x00000001
#define CKR_HOST_MEMORY                       0x00000002
#define CKR_SLOT_ID_INVALID                   0x00000003

/* CKR_FLAGS_INVALID was removed for v2.0 */

/* CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED are new for v2.0 */
#define CKR_GENERAL_ERROR                     0x00000005
#define CKR_FUNCTION_FAILED                   0x00000006

/* CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS,
 * and CKR_CANT_LOCK are new for v2.01 */
#define CKR_ARGUMENTS_BAD                     0x00000007
#define CKR_NO_EVENT                          0x00000008
#define CKR_NEED_TO_CREATE_THREADS            0x00000009
#define CKR_CANT_LOCK                         0x0000000A

#define CKR_ATTRIBUTE_READ_ONLY               0x00000010
#define CKR_ATTRIBUTE_SENSITIVE               0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID            0x00000012
#define CKR_ATTRIBUTE_VALUE_INVALID           0x00000013
#define CKR_DATA_INVALID                      0x00000020
#define CKR_DATA_LEN_RANGE                    0x00000021
#define CKR_DEVICE_ERROR                      0x00000030
#define CKR_DEVICE_MEMORY                     0x00000031
#define CKR_DEVICE_REMOVED                    0x00000032
#define CKR_ENCRYPTED_DATA_INVALID            0x00000040
#define CKR_ENCRYPTED_DATA_LEN_RANGE          0x00000041
#define CKR_FUNCTION_CANCELED                 0x00000050
#define CKR_FUNCTION_NOT_PARALLEL             0x00000051

/* CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
#define CKR_FUNCTION_NOT_SUPPORTED            0x00000054

#define CKR_KEY_HANDLE_INVALID                0x00000060

/* CKR_KEY_SENSITIVE was removed for v2.0 */

#define CKR_KEY_SIZE_RANGE                    0x00000062
#define CKR_KEY_TYPE_INCONSISTENT             0x00000063

/* CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED, CKR_KEY_NEEDED,
 * CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED,
 * CKR_KEY_NOT_WRAPPABLE, and CKR_KEY_UNEXTRACTABLE are new for
 * v2.0 */
#define CKR_KEY_NOT_NEEDED                    0x00000064
#define CKR_KEY_CHANGED                       0x00000065
#define CKR_KEY_NEEDED                        0x00000066
#define CKR_KEY_INDIGESTIBLE                  0x00000067
#define CKR_KEY_FUNCTION_NOT_PERMITTED        0x00000068
#define CKR_KEY_NOT_WRAPPABLE                 0x00000069
#define CKR_KEY_UNEXTRACTABLE                 0x0000006A

#define CKR_MECHANISM_INVALID                 0x00000070
#define CKR_MECHANISM_PARAM_INVALID           0x00000071

/* CKR_OBJECT_CLASS_INCONSISTENT and CKR_OBJECT_CLASS_INVALID
 * were removed for v2.0 */
#define CKR_OBJECT_HANDLE_INVALID             0x00000082
#define CKR_OPERATION_ACTIVE                  0x00000090
#define CKR_OPERATION_NOT_INITIALIZED         0x00000091
#define CKR_PIN_INCORRECT                     0x000000A0
#define CKR_PIN_INVALID                       0x000000A1
#define CKR_PIN_LEN_RANGE                     0x000000A2

/* CKR_PIN_EXPIRED and CKR_PIN_LOCKED are new for v2.0 */
#define CKR_PIN_EXPIRED                       0x000000A3
#define CKR_PIN_LOCKED                        0x000000A4

#define CKR_SESSION_CLOSED                    0x000000B0
#define CKR_SESSION_COUNT                     0x000000B1
#define CKR_SESSION_HANDLE_INVALID            0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED    0x000000B4
#define CKR_SESSION_READ_ONLY                 0x000000B5
#define CKR_SESSION_EXISTS                    0x000000B6

/* CKR_SESSION_READ_ONLY_EXISTS and
 * CKR_SESSION_READ_WRITE_SO_EXISTS are new for v2.0 */
#define CKR_SESSION_READ_ONLY_EXISTS          0x000000B7
#define CKR_SESSION_READ_WRITE_SO_EXISTS      0x000000B8

#define CKR_SIGNATURE_INVALID                 0x000000C0
#define CKR_SIGNATURE_LEN_RANGE               0x000000C1
#define CKR_TEMPLATE_INCOMPLETE               0x000000D0
#define CKR_TEMPLATE_INCONSISTENT             0x000000D1
#define CKR_TOKEN_NOT_PRESENT                 0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED              0x000000E1
#define CKR_TOKEN_WRITE_PROTECTED             0x000000E2
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID     0x000000F0
#define CKR_UNWRAPPING_KEY_SIZE_RANGE         0x000000F1
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  0x000000F2
#define CKR_USER_ALREADY_LOGGED_IN            0x00000100
#define CKR_USER_NOT_LOGGED_IN                0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED          0x00000102
#define CKR_USER_TYPE_INVALID                 0x00000103

/* CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES
 * are new to v2.01 */
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN    0x00000104
#define CKR_USER_TOO_MANY_TYPES               0x00000105

#define CKR_WRAPPED_KEY_INVALID               0x00000110
#define CKR_WRAPPED_KEY_LEN_RANGE             0x00000112
#define CKR_WRAPPING_KEY_HANDLE_INVALID       0x00000113
#define CKR_WRAPPING_KEY_SIZE_RANGE           0x00000114
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT    0x00000115
#define CKR_RANDOM_SEED_NOT_SUPPORTED         0x00000120

/* These are new to v2.0 */
#define CKR_RANDOM_NO_RNG                     0x00000121

/* These are new to v2.11 */
#define CKR_DOMAIN_PARAMS_INVALID             0x00000130

/* These are new to v2.0 */
#define CKR_BUFFER_TOO_SMALL                  0x00000150
#define CKR_SAVED_STATE_INVALID               0x00000160
#define CKR_INFORMATION_SENSITIVE             0x00000170
#define CKR_STATE_UNSAVEABLE                  0x00000180

/* These are new to v2.01 */
#define CKR_CRYPTOKI_NOT_INITIALIZED          0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED      0x00000191
#define CKR_MUTEX_BAD                         0x000001A0
#define CKR_MUTEX_NOT_LOCKED                  0x000001A1

/* The following return values are new for PKCS #11 v2.20 amendment 3 */
#define CKR_NEW_PIN_MODE                      0x000001B0
#define CKR_NEXT_OTP                          0x000001B1

/* This is new to v2.20 */
#define CKR_FUNCTION_REJECTED                 0x00000200

#define CKR_VENDOR_DEFINED                    0x80000000

/* CK_NOTIFY is an application callback that processes events */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_NOTIFY)(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_NOTIFICATION   event,
  CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
);

/* CK_FUNCTION_LIST is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki functions */
/* CK_FUNCTION_LIST is new for v2.0 */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;

typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

/* CK_CREATEMUTEX is an application callback for creating a
 * mutex object */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_CREATEMUTEX)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
);

/* CK_DESTROYMUTEX is an application callback for destroying a
 * mutex object */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_DESTROYMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);

/* CK_LOCKMUTEX is an application callback for locking a mutex */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_LOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);

/* CK_UNLOCKMUTEX is an application callback for unlocking a
 * mutex */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNLOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);

/* CK_C_INITIALIZE_ARGS provides the optional arguments to
 * C_Initialize */
typedef struct CK_C_INITIALIZE_ARGS {
  CK_CREATEMUTEX CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX LockMutex;
  CK_UNLOCKMUTEX UnlockMutex;
  CK_FLAGS flags;
  CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag                           Mask       Meaning
 */
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001
#define CKF_OS_LOCKING_OK                  0x00000002

typedef CK_C_INITIALIZE_ARGS CK_PTR CK_C_INITIALIZE_ARGS_PTR;

/* additional flags for parameters to functions */

/* CKF_DONT_BLOCK is for the function C_WaitForSlotEvent */
#define CKF_DONT_BLOCK     1

/* CK_RSA_PKCS_OAEP_MGF_TYPE is new for v2.10.
 * CK_RSA_PKCS_OAEP_MGF_TYPE  is used to indicate the Message
 * Generation Function (MGF) applied to a message block when
 * formatting a message block for the PKCS #1 OAEP encryption
 * scheme. */
typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;

typedef CK_RSA_PKCS_MGF_TYPE CK_PTR CK_RSA_PKCS_MGF_TYPE_PTR;

/* The following MGFs are defined */
/* CKG_MGF1_SHA256, CKG_MGF1_SHA384, and CKG_MGF1_SHA512
 * are new for v2.20 */
#define CKG_MGF1_SHA1         0x00000001
#define CKG_MGF1_SHA256       0x00000002
#define CKG_MGF1_SHA384       0x00000003
#define CKG_MGF1_SHA512       0x00000004
/* SHA-224 is new for PKCS #11 v2.20 amendment 3 */
#define CKG_MGF1_SHA224       0x00000005

/* CK_RSA_PKCS_OAEP_SOURCE_TYPE is new for v2.10.
 * CK_RSA_PKCS_OAEP_SOURCE_TYPE  is used to indicate the source
 * of the encoding parameter when formatting a message block
 * for the PKCS #1 OAEP encryption scheme. */
typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;

typedef CK_RSA_PKCS_OAEP_SOURCE_TYPE CK_PTR CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR;

/* The following encoding parameter sources are defined */
#define CKZ_DATA_SPECIFIED    0x00000001

/* CK_RSA_PKCS_OAEP_PARAMS is new for v2.10.
 * CK_RSA_PKCS_OAEP_PARAMS provides the parameters to the
 * CKM_RSA_PKCS_OAEP mechanism. */
typedef struct CK_RSA_PKCS_OAEP_PARAMS {
        CK_MECHANISM_TYPE hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
        CK_VOID_PTR pSourceData;
        CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

typedef CK_RSA_PKCS_OAEP_PARAMS CK_PTR CK_RSA_PKCS_OAEP_PARAMS_PTR;

/* CK_RSA_PKCS_PSS_PARAMS is new for v2.11.
 * CK_RSA_PKCS_PSS_PARAMS provides the parameters to the
 * CKM_RSA_PKCS_PSS mechanism(s). */
typedef struct CK_RSA_PKCS_PSS_PARAMS {
        CK_MECHANISM_TYPE    hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_ULONG             sLen;
} CK_RSA_PKCS_PSS_PARAMS;

typedef CK_RSA_PKCS_PSS_PARAMS CK_PTR CK_RSA_PKCS_PSS_PARAMS_PTR;

/* CK_EC_KDF_TYPE is new for v2.11. */
typedef CK_ULONG CK_EC_KDF_TYPE;

/* The following EC Key Derivation Functions are defined */
#define CKD_NULL                 0x00000001
#define CKD_SHA1_KDF             0x00000002

/* CK_ECDH1_DERIVE_PARAMS is new for v2.11.
 * CK_ECDH1_DERIVE_PARAMS provides the parameters to the
 * CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE mechanisms,
 * where each party contributes one key pair.
 */
typedef struct CK_ECDH1_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

typedef CK_ECDH1_DERIVE_PARAMS CK_PTR CK_ECDH1_DERIVE_PARAMS_PTR;

/* CK_ECDH2_DERIVE_PARAMS is new for v2.11.
 * CK_ECDH2_DERIVE_PARAMS provides the parameters to the
 * CKM_ECMQV_DERIVE mechanism, where each party contributes two key pairs. */
typedef struct CK_ECDH2_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
} CK_ECDH2_DERIVE_PARAMS;

typedef CK_ECDH2_DERIVE_PARAMS CK_PTR CK_ECDH2_DERIVE_PARAMS_PTR;

typedef struct CK_ECMQV_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
  CK_OBJECT_HANDLE publicKey;
} CK_ECMQV_DERIVE_PARAMS;

typedef CK_ECMQV_DERIVE_PARAMS CK_PTR CK_ECMQV_DERIVE_PARAMS_PTR;

/* Typedefs and defines for the CKM_X9_42_DH_KEY_PAIR_GEN and the
 * CKM_X9_42_DH_PARAMETER_GEN mechanisms (new for PKCS #11 v2.11) */
typedef CK_ULONG CK_X9_42_DH_KDF_TYPE;
typedef CK_X9_42_DH_KDF_TYPE CK_PTR CK_X9_42_DH_KDF_TYPE_PTR;

/* The following X9.42 DH key derivation functions are defined
   (besides CKD_NULL already defined : */
#define CKD_SHA1_KDF_ASN1        0x00000003
#define CKD_SHA1_KDF_CONCATENATE 0x00000004

/* CK_X9_42_DH1_DERIVE_PARAMS is new for v2.11.
 * CK_X9_42_DH1_DERIVE_PARAMS provides the parameters to the
 * CKM_X9_42_DH_DERIVE key derivation mechanism, where each party
 * contributes one key pair */
typedef struct CK_X9_42_DH1_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
} CK_X9_42_DH1_DERIVE_PARAMS;

typedef struct CK_X9_42_DH1_DERIVE_PARAMS CK_PTR CK_X9_42_DH1_DERIVE_PARAMS_PTR;

/* CK_X9_42_DH2_DERIVE_PARAMS is new for v2.11.
 * CK_X9_42_DH2_DERIVE_PARAMS provides the parameters to the
 * CKM_X9_42_DH_HYBRID_DERIVE and CKM_X9_42_MQV_DERIVE key derivation
 * mechanisms, where each party contributes two key pairs */
typedef struct CK_X9_42_DH2_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
} CK_X9_42_DH2_DERIVE_PARAMS;

typedef CK_X9_42_DH2_DERIVE_PARAMS CK_PTR CK_X9_42_DH2_DERIVE_PARAMS_PTR;

typedef struct CK_X9_42_MQV_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
  CK_OBJECT_HANDLE publicKey;
} CK_X9_42_MQV_DERIVE_PARAMS;

typedef CK_X9_42_MQV_DERIVE_PARAMS CK_PTR CK_X9_42_MQV_DERIVE_PARAMS_PTR;

/* CK_KEA_DERIVE_PARAMS provides the parameters to the
 * CKM_KEA_DERIVE mechanism */
/* CK_KEA_DERIVE_PARAMS is new for v2.0 */
typedef struct CK_KEA_DERIVE_PARAMS {
  CK_BBOOL      isSender;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pRandomB;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
} CK_KEA_DERIVE_PARAMS;

typedef CK_KEA_DERIVE_PARAMS CK_PTR CK_KEA_DERIVE_PARAMS_PTR;

/* CK_RC2_PARAMS provides the parameters to the CKM_RC2_ECB and
 * CKM_RC2_MAC mechanisms.  An instance of CK_RC2_PARAMS just
 * holds the effective keysize */
typedef CK_ULONG          CK_RC2_PARAMS;

typedef CK_RC2_PARAMS CK_PTR CK_RC2_PARAMS_PTR;

/* CK_RC2_CBC_PARAMS provides the parameters to the CKM_RC2_CBC
 * mechanism */
typedef struct CK_RC2_CBC_PARAMS {
  /* ulEffectiveBits was changed from CK_USHORT to CK_ULONG for
   * v2.0 */
  CK_ULONG      ulEffectiveBits;  /* effective bits (1-1024) */

  CK_BYTE       iv[8];            /* IV for CBC mode */
} CK_RC2_CBC_PARAMS;

typedef CK_RC2_CBC_PARAMS CK_PTR CK_RC2_CBC_PARAMS_PTR;

/* CK_RC2_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC2_MAC_GENERAL mechanism */
/* CK_RC2_MAC_GENERAL_PARAMS is new for v2.0 */
typedef struct CK_RC2_MAC_GENERAL_PARAMS {
  CK_ULONG      ulEffectiveBits;  /* effective bits (1-1024) */
  CK_ULONG      ulMacLength;      /* Length of MAC in bytes */
} CK_RC2_MAC_GENERAL_PARAMS;

typedef CK_RC2_MAC_GENERAL_PARAMS CK_PTR \
  CK_RC2_MAC_GENERAL_PARAMS_PTR;

/* CK_RC5_PARAMS provides the parameters to the CKM_RC5_ECB and
 * CKM_RC5_MAC mechanisms */
/* CK_RC5_PARAMS is new for v2.0 */
typedef struct CK_RC5_PARAMS {
  CK_ULONG      ulWordsize;  /* wordsize in bits */
  CK_ULONG      ulRounds;    /* number of rounds */
} CK_RC5_PARAMS;

typedef CK_RC5_PARAMS CK_PTR CK_RC5_PARAMS_PTR;

/* CK_RC5_CBC_PARAMS provides the parameters to the CKM_RC5_CBC
 * mechanism */
/* CK_RC5_CBC_PARAMS is new for v2.0 */
typedef struct CK_RC5_CBC_PARAMS {
  CK_ULONG      ulWordsize;  /* wordsize in bits */
  CK_ULONG      ulRounds;    /* number of rounds */
  CK_BYTE_PTR   pIv;         /* pointer to IV */
  CK_ULONG      ulIvLen;     /* length of IV in bytes */
} CK_RC5_CBC_PARAMS;

typedef CK_RC5_CBC_PARAMS CK_PTR CK_RC5_CBC_PARAMS_PTR;

/* CK_RC5_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC5_MAC_GENERAL mechanism */
/* CK_RC5_MAC_GENERAL_PARAMS is new for v2.0 */
typedef struct CK_RC5_MAC_GENERAL_PARAMS {
  CK_ULONG      ulWordsize;   /* wordsize in bits */
  CK_ULONG      ulRounds;     /* number of rounds */
  CK_ULONG      ulMacLength;  /* Length of MAC in bytes */
} CK_RC5_MAC_GENERAL_PARAMS;

typedef CK_RC5_MAC_GENERAL_PARAMS CK_PTR \
  CK_RC5_MAC_GENERAL_PARAMS_PTR;

/* CK_MAC_GENERAL_PARAMS provides the parameters to most block
 * ciphers' MAC_GENERAL mechanisms.  Its value is the length of
 * the MAC */
/* CK_MAC_GENERAL_PARAMS is new for v2.0 */
typedef CK_ULONG          CK_MAC_GENERAL_PARAMS;

typedef CK_MAC_GENERAL_PARAMS CK_PTR CK_MAC_GENERAL_PARAMS_PTR;

/* CK_DES/AES_ECB/CBC_ENCRYPT_DATA_PARAMS are new for v2.20 */
typedef struct CK_DES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE      iv[8];
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
} CK_DES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_DES_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR;

typedef struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE      iv[16];
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
} CK_AES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_AES_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR;

/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS provides the parameters to the
 * CKM_SKIPJACK_PRIVATE_WRAP mechanism */
/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
  CK_ULONG      ulPasswordLen;
  CK_BYTE_PTR   pPassword;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
  CK_ULONG      ulPAndGLen;
  CK_ULONG      ulQLen;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pPrimeP;
  CK_BYTE_PTR   pBaseG;
  CK_BYTE_PTR   pSubprimeQ;
} CK_SKIPJACK_PRIVATE_WRAP_PARAMS;

typedef CK_SKIPJACK_PRIVATE_WRAP_PARAMS CK_PTR \
  CK_SKIPJACK_PRIVATE_WRAP_PTR;

/* CK_SKIPJACK_RELAYX_PARAMS provides the parameters to the
 * CKM_SKIPJACK_RELAYX mechanism */
/* CK_SKIPJACK_RELAYX_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_RELAYX_PARAMS {
  CK_ULONG      ulOldWrappedXLen;
  CK_BYTE_PTR   pOldWrappedX;
  CK_ULONG      ulOldPasswordLen;
  CK_BYTE_PTR   pOldPassword;
  CK_ULONG      ulOldPublicDataLen;
  CK_BYTE_PTR   pOldPublicData;
  CK_ULONG      ulOldRandomLen;
  CK_BYTE_PTR   pOldRandomA;
  CK_ULONG      ulNewPasswordLen;
  CK_BYTE_PTR   pNewPassword;
  CK_ULONG      ulNewPublicDataLen;
  CK_BYTE_PTR   pNewPublicData;
  CK_ULONG      ulNewRandomLen;
  CK_BYTE_PTR   pNewRandomA;
} CK_SKIPJACK_RELAYX_PARAMS;

typedef CK_SKIPJACK_RELAYX_PARAMS CK_PTR \
  CK_SKIPJACK_RELAYX_PARAMS_PTR;

typedef struct CK_PBE_PARAMS {
  CK_BYTE_PTR      pInitVector;
  CK_UTF8CHAR_PTR  pPassword;
  CK_ULONG         ulPasswordLen;
  CK_BYTE_PTR      pSalt;
  CK_ULONG         ulSaltLen;
  CK_ULONG         ulIteration;
} CK_PBE_PARAMS;

typedef CK_PBE_PARAMS CK_PTR CK_PBE_PARAMS_PTR;

/* CK_KEY_WRAP_SET_OAEP_PARAMS provides the parameters to the
 * CKM_KEY_WRAP_SET_OAEP mechanism */
/* CK_KEY_WRAP_SET_OAEP_PARAMS is new for v2.0 */
typedef struct CK_KEY_WRAP_SET_OAEP_PARAMS {
  CK_BYTE       bBC;     /* block contents byte */
  CK_BYTE_PTR   pX;      /* extra data */
  CK_ULONG      ulXLen;  /* length of extra data in bytes */
} CK_KEY_WRAP_SET_OAEP_PARAMS;

typedef CK_KEY_WRAP_SET_OAEP_PARAMS CK_PTR \
  CK_KEY_WRAP_SET_OAEP_PARAMS_PTR;

typedef struct CK_SSL3_RANDOM_DATA {
  CK_BYTE_PTR  pClientRandom;
  CK_ULONG     ulClientRandomLen;
  CK_BYTE_PTR  pServerRandom;
  CK_ULONG     ulServerRandomLen;
} CK_SSL3_RANDOM_DATA;

typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
  CK_SSL3_RANDOM_DATA RandomInfo;
  CK_VERSION_PTR pVersion;
} CK_SSL3_MASTER_KEY_DERIVE_PARAMS;

typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS CK_PTR \
  CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_SSL3_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hClientMacSecret;
  CK_OBJECT_HANDLE hServerMacSecret;
  CK_OBJECT_HANDLE hClientKey;
  CK_OBJECT_HANDLE hServerKey;
  CK_BYTE_PTR      pIVClient;
  CK_BYTE_PTR      pIVServer;
} CK_SSL3_KEY_MAT_OUT;

typedef CK_SSL3_KEY_MAT_OUT CK_PTR CK_SSL3_KEY_MAT_OUT_PTR;

typedef struct CK_SSL3_KEY_MAT_PARAMS {
  CK_ULONG                ulMacSizeInBits;
  CK_ULONG                ulKeySizeInBits;
  CK_ULONG                ulIVSizeInBits;
  CK_BBOOL                bIsExport;
  CK_SSL3_RANDOM_DATA     RandomInfo;
  CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_SSL3_KEY_MAT_PARAMS;

typedef CK_SSL3_KEY_MAT_PARAMS CK_PTR CK_SSL3_KEY_MAT_PARAMS_PTR;

/* CK_TLS_PRF_PARAMS is new for version 2.20 */
typedef struct CK_TLS_PRF_PARAMS {
  CK_BYTE_PTR  pSeed;
  CK_ULONG     ulSeedLen;
  CK_BYTE_PTR  pLabel;
  CK_ULONG     ulLabelLen;
  CK_BYTE_PTR  pOutput;
  CK_ULONG_PTR pulOutputLen;
} CK_TLS_PRF_PARAMS;

typedef CK_TLS_PRF_PARAMS CK_PTR CK_TLS_PRF_PARAMS_PTR;

/* WTLS is new for version 2.20 */
typedef struct CK_WTLS_RANDOM_DATA {
  CK_BYTE_PTR pClientRandom;
  CK_ULONG    ulClientRandomLen;
  CK_BYTE_PTR pServerRandom;
  CK_ULONG    ulServerRandomLen;
} CK_WTLS_RANDOM_DATA;

typedef CK_WTLS_RANDOM_DATA CK_PTR CK_WTLS_RANDOM_DATA_PTR;

typedef struct CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
  CK_MECHANISM_TYPE   DigestMechanism;
  CK_WTLS_RANDOM_DATA RandomInfo;
  CK_BYTE_PTR         pVersion;
} CK_WTLS_MASTER_KEY_DERIVE_PARAMS;

typedef CK_WTLS_MASTER_KEY_DERIVE_PARAMS CK_PTR \
  CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_WTLS_PRF_PARAMS {
  CK_MECHANISM_TYPE DigestMechanism;
  CK_BYTE_PTR       pSeed;
  CK_ULONG          ulSeedLen;
  CK_BYTE_PTR       pLabel;
  CK_ULONG          ulLabelLen;
  CK_BYTE_PTR       pOutput;
  CK_ULONG_PTR      pulOutputLen;
} CK_WTLS_PRF_PARAMS;

typedef CK_WTLS_PRF_PARAMS CK_PTR CK_WTLS_PRF_PARAMS_PTR;

typedef struct CK_WTLS_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hMacSecret;
  CK_OBJECT_HANDLE hKey;
  CK_BYTE_PTR      pIV;
} CK_WTLS_KEY_MAT_OUT;

typedef CK_WTLS_KEY_MAT_OUT CK_PTR CK_WTLS_KEY_MAT_OUT_PTR;

typedef struct CK_WTLS_KEY_MAT_PARAMS {
  CK_MECHANISM_TYPE       DigestMechanism;
  CK_ULONG                ulMacSizeInBits;
  CK_ULONG                ulKeySizeInBits;
  CK_ULONG                ulIVSizeInBits;
  CK_ULONG                ulSequenceNumber;
  CK_BBOOL                bIsExport;
  CK_WTLS_RANDOM_DATA     RandomInfo;
  CK_WTLS_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_WTLS_KEY_MAT_PARAMS;

typedef CK_WTLS_KEY_MAT_PARAMS CK_PTR CK_WTLS_KEY_MAT_PARAMS_PTR;

/* CMS is new for version 2.20 */
typedef struct CK_CMS_SIG_PARAMS {
  CK_OBJECT_HANDLE      certificateHandle;
  CK_MECHANISM_PTR      pSigningMechanism;
  CK_MECHANISM_PTR      pDigestMechanism;
  CK_UTF8CHAR_PTR       pContentType;
  CK_BYTE_PTR           pRequestedAttributes;
  CK_ULONG              ulRequestedAttributesLen;
  CK_BYTE_PTR           pRequiredAttributes;
  CK_ULONG              ulRequiredAttributesLen;
} CK_CMS_SIG_PARAMS;

typedef CK_CMS_SIG_PARAMS CK_PTR CK_CMS_SIG_PARAMS_PTR;

typedef struct CK_KEY_DERIVATION_STRING_DATA {
  CK_BYTE_PTR pData;
  CK_ULONG    ulLen;
} CK_KEY_DERIVATION_STRING_DATA;

typedef CK_KEY_DERIVATION_STRING_DATA CK_PTR \
  CK_KEY_DERIVATION_STRING_DATA_PTR;

/* The CK_EXTRACT_PARAMS is used for the
 * CKM_EXTRACT_KEY_FROM_KEY mechanism.  It specifies which bit
 * of the base key should be used as the first bit of the
 * derived key */
/* CK_EXTRACT_PARAMS is new for v2.0 */
typedef CK_ULONG CK_EXTRACT_PARAMS;

typedef CK_EXTRACT_PARAMS CK_PTR CK_EXTRACT_PARAMS_PTR;

/* CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE is new for v2.10.
 * CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE is used to
 * indicate the Pseudo-Random Function (PRF) used to generate
 * key bits using PKCS #5 PBKDF2. */
typedef CK_ULONG CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE;

typedef CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE CK_PTR CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR;

/* The following PRFs are defined in PKCS #5 v2.0. */
#define CKP_PKCS5_PBKD2_HMAC_SHA1 0x00000001

/* CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE is new for v2.10.
 * CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE is used to indicate the
 * source of the salt value when deriving a key using PKCS #5
 * PBKDF2. */
typedef CK_ULONG CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE;

typedef CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE CK_PTR CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR;

/* The following salt value sources are defined in PKCS #5 v2.0. */
#define CKZ_SALT_SPECIFIED        0x00000001

/* CK_PKCS5_PBKD2_PARAMS is new for v2.10.
 * CK_PKCS5_PBKD2_PARAMS is a structure that provides the
 * parameters to the CKM_PKCS5_PBKD2 mechanism. */
typedef struct CK_PKCS5_PBKD2_PARAMS {
        CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE           saltSource;
        CK_VOID_PTR                                pSaltSourceData;
        CK_ULONG                                   ulSaltSourceDataLen;
        CK_ULONG                                   iterations;
        CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
        CK_VOID_PTR                                pPrfData;
        CK_ULONG                                   ulPrfDataLen;
        CK_UTF8CHAR_PTR                            pPassword;
        CK_ULONG_PTR                               ulPasswordLen;
} CK_PKCS5_PBKD2_PARAMS;

typedef CK_PKCS5_PBKD2_PARAMS CK_PTR CK_PKCS5_PBKD2_PARAMS_PTR;

/* All CK_OTP structs are new for PKCS #11 v2.20 amendment 3 */

typedef CK_ULONG CK_OTP_PARAM_TYPE;
typedef CK_OTP_PARAM_TYPE CK_PARAM_TYPE; /* B/w compatibility */

typedef struct CK_OTP_PARAM {
    CK_OTP_PARAM_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_OTP_PARAM;

typedef CK_OTP_PARAM CK_PTR CK_OTP_PARAM_PTR;

typedef struct CK_OTP_PARAMS {
    CK_OTP_PARAM_PTR pParams;
    CK_ULONG ulCount;
} CK_OTP_PARAMS;

typedef CK_OTP_PARAMS CK_PTR CK_OTP_PARAMS_PTR;

typedef struct CK_OTP_SIGNATURE_INFO {
    CK_OTP_PARAM_PTR pParams;
    CK_ULONG ulCount;
} CK_OTP_SIGNATURE_INFO;

typedef CK_OTP_SIGNATURE_INFO CK_PTR CK_OTP_SIGNATURE_INFO_PTR;

/* The following OTP-related defines are new for PKCS #11 v2.20 amendment 1 */
#define CK_OTP_VALUE          0
#define CK_OTP_PIN            1
#define CK_OTP_CHALLENGE      2
#define CK_OTP_TIME           3
#define CK_OTP_COUNTER        4
#define CK_OTP_FLAGS          5
#define CK_OTP_OUTPUT_LENGTH  6
#define CK_OTP_OUTPUT_FORMAT  7

/* The following OTP-related defines are new for PKCS #11 v2.20 amendment 1 */
#define CKF_NEXT_OTP          0x00000001
#define CKF_EXCLUDE_TIME      0x00000002
#define CKF_EXCLUDE_COUNTER   0x00000004
#define CKF_EXCLUDE_CHALLENGE 0x00000008
#define CKF_EXCLUDE_PIN       0x00000010
#define CKF_USER_FRIENDLY_OTP 0x00000020

/* CK_KIP_PARAMS is new for PKCS #11 v2.20 amendment 2 */
typedef struct CK_KIP_PARAMS {
    CK_MECHANISM_PTR  pMechanism;
    CK_OBJECT_HANDLE  hKey;
    CK_BYTE_PTR       pSeed;
    CK_ULONG          ulSeedLen;
} CK_KIP_PARAMS;

typedef CK_KIP_PARAMS CK_PTR CK_KIP_PARAMS_PTR;

/* CK_AES_CTR_PARAMS is new for PKCS #11 v2.20 amendment 3 */
typedef struct CK_AES_CTR_PARAMS {
    CK_ULONG ulCounterBits;
    CK_BYTE cb[16];
} CK_AES_CTR_PARAMS;

typedef CK_AES_CTR_PARAMS CK_PTR CK_AES_CTR_PARAMS_PTR;

/* CK_CAMELLIA_CTR_PARAMS is new for PKCS #11 v2.20 amendment 3 */
typedef struct CK_CAMELLIA_CTR_PARAMS {
    CK_ULONG ulCounterBits;
    CK_BYTE cb[16];
} CK_CAMELLIA_CTR_PARAMS;

typedef CK_CAMELLIA_CTR_PARAMS CK_PTR CK_CAMELLIA_CTR_PARAMS_PTR;

/* CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS is new for PKCS #11 v2.20 amendment 3 */
typedef struct CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE      iv[16];
    CK_BYTE_PTR  pData;
    CK_ULONG     length;
} CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR;

/* CK_ARIA_CBC_ENCRYPT_DATA_PARAMS is new for PKCS #11 v2.20 amendment 3 */
typedef struct CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE      iv[16];
    CK_BYTE_PTR  pData;
    CK_ULONG     length;
} CK_ARIA_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_ARIA_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR;

#define __PASTE(x,y)      x##y

/* ==============================================================
 * Define the "extern" form of all the entry points.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_PKCS11_FUNCTION_INFO(name) \
  extern CK_DECLARE_FUNCTION(CK_RV, name)

/* pkcs11f.h has all the information about the Cryptoki
 * function prototypes. */
#include "pkcs11f.h"

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO

/* ==============================================================
 * Define the typedef form of all the entry points.  That is, for
 * each Cryptoki function C_XXX, define a type CK_C_XXX which is
 * a pointer to that kind of function.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_PKCS11_FUNCTION_INFO(name) \
  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, __PASTE(CK_,name))

/* pkcs11f.h has all the information about the Cryptoki
 * function prototypes. */
#include "pkcs11f.h"

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO

/* ==============================================================
 * Define structed vector of entry points.  A CK_FUNCTION_LIST
 * contains a CK_VERSION indicating a library's Cryptoki version
 * and then a whole slew of function pointers to the routines in
 * the library.  This type was declared, but not defined, in
 * pkcs11t.h.
 * ==============================================================
 */

#define CK_PKCS11_FUNCTION_INFO(name) \
  __PASTE(CK_,name) name;
  
struct CK_FUNCTION_LIST {

  CK_VERSION    version;  /* Cryptoki version */

/* Pile all the function pointers into the CK_FUNCTION_LIST. */
/* pkcs11f.h has all the information about the Cryptoki
 * function prototypes. */
#include "pkcs11f.h"

};

#undef CK_PKCS11_FUNCTION_INFO

#undef __PASTE

#endif

#ifdef __cplusplus
}
#endif

#pragma pack(pop, cryptoki)
#endif // defined _WIN32
#endif

#ifdef __cplusplus
extern "C" {
#endif

//===============================================================
// Socket Routines Externals
//===============================================================

#if !defined __HCSOCK_LIB__

#if !defined SOCKET && !defined WIN64 && !defined EM64T
#define  SOCKET   int
#endif

typedef struct SADDRIN_t SADDRIN;
typedef struct HSTENT_t HSTENT;
typedef struct ADDRINF_t ADDRINF;
extern SADDRIN *  DupAdrStruc(HMEM_CTX_DEF
                              SADDRIN * pSrcAdr);

extern int  InetNtop(int AddressFamily, 
                     char pSrcBuf[],
                     int SrcOff,
                     char pDstBuf[], 
                     int DstOff,
                     int DstBufLen, 
                     int ModeFlags);

extern int  GetInetAddressStringType(char pSrcBuf[], 
                                     int SrcOff,
                                     int SrcLen);

extern int  InetPton(int AddressFamily, 
                     char pSrcBuf[],
                     int SrcOff, 
                     int SrcLen,
                     char pDstBuf[],
                     int DstOff);

extern void  FreeHostentStruct(HMEM_CTX_DEF
                               HSTENT* pHostEnt);

extern void  FreeAddrInfoStruct(HMEM_CTX_DEF
                                ADDRINF * pAddrInfo);
extern ADDRINF *  AllocAddrInfoStruct(HMEM_CTX_DEF
                                      int Mode);

extern HSTENT*  GetHostByAddr(HMEM_CTX_DEF
                              SADDRIN * pAddrStruc);

extern HSTENT*  HGetHostByName(HMEM_CTX_DEF
                               char pNameBuf[],
                               int NameOff);
extern int  HGetHostName(char pNameBuf[],
                         int NameOff,
                         int NameBufLen);
extern int  GetPeerName(SOCKET TheSocket,
                        SADDRIN * pRemAdrStruc);
extern int  GetSockName(SOCKET TheSocket,
                        SADDRIN * pLclAdrStruc);
extern int  GetSockOpt(SOCKET TheSocket,
                       int OptName,
                       int pOptState[], 
                       int pAddVal[]);
extern int  SetSockOpt(SOCKET TheSocket, 
                       int OptName,
                       int OptState, 
                       int AddVal);
extern int  IoctlSocket(SOCKET TheSocket, 
                        int Mode, 
                        int Timeout);

extern int  WordToDecimalAscii(int BinWord,
                               char pDstBuf[], 
                               int DstOff);

extern int  CheckLocalInetAdr(HMEM_CTX_DEF
                              SADDRIN * pAdrStruc);

extern int  GetNameInfo(HMEM_CTX_DEF
                        SADDRIN * pAdrStruc,
                        char pHostName[], 
                        int HostNameOff,
                        int HostNameBufLen,
                        char pPortName[], 
                        int PortNameOff,
                        int PortNameBufLen,
                        int Flags);

extern int  GetAddrInfo(HMEM_CTX_DEF
                        char pHostName[],
                        int HostNameOff,
                        char pServName[], 
                        int ServNameOff,
                        ADDRINF * pHint,
                        ADDRINF * ppAdrInfo[]);

extern int  SockAccept(SOCKET ListenSocket,
                       SADDRIN * pAddrStruc,
                       SOCKET pNewSock[]);
extern int  SockShutdown(SOCKET TheSocket, 
                         int How);
extern int  CloseSocket(SOCKET TheSocket);
extern int  CloseServerSocket(SOCKET TheSocket);

extern int  GetAdrType(char pAddr[], 
                       int AddrLen);

extern int  BindAndConnect(SADDRIN * pDstAddr,
                           SADDRIN * pSrcAddr, 
                           SOCKET pNewSock[]);

extern int  BindAndListen(SADDRIN * pListenAddr, 
                          int BackLog,
                          SOCKET pListenSock[]);

extern int  SendSock(SOCKET TheSocket, 
                     char pTxBuf[],
                     int TxOff,
                     int TxLen);

extern int  SendWaitSock(SOCKET TheSocket, 
                         char pTxBuf[], 
                         int TxOff,
                         int TxLen, 
                         int Timeout);

extern int  ReceiveSock(SOCKET TheSocket,
                        char pRxBuf[],
                        int RxOff,
                        int RxBufLen);
extern int  ReceiveWaitSock(SOCKET TheSocket, 
                            char pRxBuf[],
                            int RxOff,
                            int RxBufLen,
                            int Timeout);

//===============================================================
// Memory, String Routines Externals
//===============================================================

#if !defined __HSTRING_LIB__

extern int  Memchr(char pBuf[], 
                   int Offset,
                   int c,
                   int FindLen);
extern int  Memcmp(char pBuf1[], 
                   int Buf1Off,
                   char pBuf2[], 
                   int Buf2Off, 
                   int DataLen);
extern void  Memcpy(char pDstBuf[],
                    int DstOff,
                    char pSrcBuf[], 
                    int SrcOff, 
                    int SrcLen);
extern void  Memmove(char pDstBuf[], 
                     int DstOff,
                     char pSrcBuf[], 
                     int SrcOff,
                     int SrcLen);

extern void  Memset(char pBuf[],
                    int Offset,
                    int c, 
                    int BufLen);

extern int  Strlen(char pBuf[], 
                   int Offset);

extern double  Atof(char pBuf[], 
                    int Offset);
extern int  Atoi(char pBuf[], 
                 int Offset);
extern int  Atol(char pBuf[], 
                     int Offset);

extern void  Strcat(char pDstBuf[], 
                    int DstOff,
                    char pSrcBuf[],
                    int SrcOff);
extern int  Strncat(char pDstBuf[], 
                    int DstOff,
                    char pSrcBuf[], 
                    int SrcOff, 
                    int AppendLen);
extern void  Strcpy(char pDstBuf[], 
                    int DstOff,
                    char pSrcBuf[], 
                    int SrcOff);
extern int  Strncpy(char pDstBuf[], 
                    int DstOff,
                    char pSrcBuf[], 
                    int SrcOff,
                    int BufLen);

extern int  Strchr(char pBuf[],
                   int Offset,
                   int c);
extern int  Strrchr(char pBuf[],
                    int Offset,
                    int c);
extern int  Strcmp(char pStr1[], 
                   int Str1Off,
                   char pStr2[], 
                   int Str2Off);
extern int  Strncmp(char pStr1[],
                    int Str1Off,
                    char pStr2[],
                    int Str2Off,
                    int MaxCmpLen);
extern char*  Strdup(HMEM_CTX_DEF
                     char pStr[], 
                     int Offset);
extern int  Strcspn(char pStr[],
                    int StrOff,
                    char pDelim[], 
                    int DelimOff);
extern int  Strspn(char pStr[],
                   int StrOff,
                   char pAllowed[], 
                   int AllowedOff);
extern int  Strpbrk(char pStr[], 
                    int StrOff,
                    char pSel[], 
                    int SelOff);

extern int  Strstr(char pStr[], 
                   int StrOff,
                   char pSub[], 
                   int SubOff);
extern int  Strtok(char pStr[], 
                   int StrOff,
                   char pDelim[], 
                   int DelimOff);

extern int  To_Lower(int c);
extern int  To_Upper(int c);

extern void  Strlower(char pStr[], 
                      int StrOff);

extern int  IsAlnum(int c);
extern int  IsAlpha(int c);
extern int  IsAscii(int c);
extern int  IsCntrl(int c);
extern int  IsDigit(int c);
extern int  IsGraph(int c);
extern int  IsLower(int c);
extern int  IsPrint(int c);
extern int  IsPunct(int c);
extern int  IsSpace(int c);
extern int  IsUpper(int c);
extern int  IsXdigit(int c);

#endif // !defined __HSTRING_LIB__

#if !defined __HSTR_HELPER_LIB__

extern void  Memrev(char pBuf[], 
                    int Off,
                    int Len);
extern char  ToLowerChar(char c);

extern int  StrnSlen(char pStr[],
                     int Off, 
                     int Len);

extern char*  Strndup(HMEM_CTX_DEF
                      char pStr[],
                      int Off, 
                      int Len);

extern int  Stricmp(char* pStr1,
                    int Str1Off,
                    char* pStr2,
                    int Str2Off);
extern int  Strnicmp(char* pStr1,
                     int Str1Off,
                     int Str1Len,
                     char* pStr2, 
                     int Str2Off, 
                     int Str2Len);
extern int  JStrncmp(char pStr1[], 
                     int Str1Off,
                     int Str1Len,
                     char * pStr2, 
                     int CaseIgnoreFlag);
extern char*  JStrdup(HMEM_CTX_DEF 
                      char * pStr2);

extern int  BinToAsciizHexStr(char pSrcBuf[], 
                              int SrcOff,
                              int SrcLen, 
                              char pDstBuf[],
                              int DstOff, 
                              int DstBufLen);

extern int  HexAsciizToBinStr(char pSrcBuf[], 
                              int SrcOff,
                              int SrcLen, 
                              char pDstBuf[],
                              int DstOff,
                              int DstBufLen,
                              int pProcessedLen[]);

extern int  Strnchr(char* pStr,
                    int StrOff,
                    int StrLen,
                    char FindChar);
extern int  Strnichr(char pStr[],
                     int StrOff, 
                     int StrLen,
                     char FindChar);

extern int  Strnrchr(char* pStr, 
                     int StrOff, 
                     int StrLen,
                     char FindChar);
extern int  Strnspn(char pStr[],
                    int StrOff, 
                    int StrLen,
                    char pCharset[], 
                    int CharsetOff,
                    int CharsetLen);
extern int  Strnpbrk(char pStr[],
                     int StrOff,
                     int StrLen,
                     char pCharset[],
                     int CharsetOff,
                     int CharsetLen);
extern int  StrnpbrkRev(char pStr[], 
                        int StrOff, 
                        int StrLen,
                        char pCharset[],
                        int CharsetOff,
                        int CharsetLen);

extern int  GetAsciizLineLen(char* pSrcBuf, 
                             int SrcOff,
                             int SrcLen, 
                             int pSkipLen[]);
extern int  GetWspacesAsciizStr(char* pStr, 
                                int StrOff,
                                int StrLen,
                                int ModeFlags,
                                int SpcChar);
extern int  GetWspacesRevAsciizStr(char* pStr, 
                                   int StrOff,
                                   int StrLen);
extern int  GetNonWspacesAsciizStr(char* pStr, 
                                   int StrOff,
                                   int StrLen,
                                   int ModeFlags, 
                                   int SpcChar);
extern int  ChopAsciizStrCrLf(char* pStr,
                              int StrOff);

extern int  GetListElement(char pList[], 
                           int ListOff, 
                           int ListLen,
                           int pElementIndex[], 
                           int pElementLen[]);

extern int  CountListElements(char pList[],
                              int ListOff,
                              int ListLen);

extern int  MatchLists(char pPrimList[], 
                       int PrimOff, 
                       int PrimLen,
                       char pSecList[], 
                       int SecOff, 
                       int SecLen,
                       int CaseIgnoreFlag,
                       int pElementIndex[],
                       int pElementLen[]);

extern int  ListInList(char pPrimList[],
                       int PrimOff,
                       int PrimLen,
                       char pSecList[], 
                       int SecOff, 
                       int SecLen,
                       int CaseIgnoreFlag, 
                       int ExcludeMode);

extern int  FindStrIndex(char pStrBuf[],
                         int StrOff,
                         int StrLen,
                         char * pStrArr[], 
                         int StartIndex,
                         int ArrayLen,
                         int CaseIgnoreFlag);

extern int  ArrayToList(HMEM_CTX_DEF 
                        char * pStrArr[], 
                        int StartIndex,
                        int ArrayLen, 
                        char* ppList[], 
                        int pListLen[]);

extern int  StrListToIDList( HMEM_CTX_DEF 
                            char pStrList[], 
                            int StrListOff,
                            int StrListLen,
                            char * pStrArr[],
                            int pIDArr[],
                            int StartIndex,	
                            int ArrayLen,
                            int CaseIgnoreFlag,
                            char* ppIDList[], 
                            int pIDListLen[]);

extern int  StrToBit32Num(char pInpBuf[], 
                          int InpOff,
                          int InpLen, 
                          int NumberType, 
                          int pNumber[]);

extern int  MatchPattern(char pStr[],
                         int StrOff,
                         int StrLen,
                         char pPat[],
                         int PatOff,
                         int PatLen, 
                         int CaseIgnoreFlag);

extern int  MatchPatternList(char pStr[], 
                             int StrOff,
                             int StrLen,
                             char pList[], 
                             int ListOff,
                             int ListLen,
                             int CaseIgnoreFlag);

extern int  GenCanonicList(HMEM_CTX_DEF 
                           char pSrcList[], 
                           int SrcOff,
                           int SrcLen,
                           char* ppDstList[], 
                           int pDstListLen[]);

extern int  Bit32ToAsciizStr(int IntVal, 
                             int FormatFlags,
                             char pDstBuf[], 
                             int DstOff,
                             int DstBufLen);

#endif // !defined __HSTR_HELPER_LIB__ 

#endif // !defined __HCSOCK_LIB__

//-----------------------------------------------------------------------------
// BASE 64
//-----------------------------------------------------------------------------
#ifndef __BASE64_HEADER__
#define __BASE64_HEADER__
//----------------------------------------------------------------------
// Header/Trailer String Tables
//----------------------------------------------------------------------

#define MAX_CHARS_PER_LINE	64
#define CRLF_LEN		2
#define CR_CHAR			0x0D
#define LF_CHAR			0x0A
#define SPACE_CHAR		0x20
#define HTAB_CHAR		0x09
#define EQUAL_CHAR		0x3D
#define MINUS_CHAR		0x2D
#define QUOT_MARK_CHAR		0x22
#define BACKSLASH_CHAR		0x5C
#define LSQ_BRACKET_CHAR	0x5B
#define RSQ_BRACKET_CHAR	0x5D
#define DEL_CHAR		0x7F
#define COMMA_CHAR		0x2C
#define L_BRACKET_CHAR		0x28
#define R_BRACKET_CHAR		0x29
#define COLON_CHAR		0x3A
#define SEMICOLON_CHAR		0x3B

#define	CERT_REQ_TYPE		0
#define	X509_CERT_TYPE		1
#define	CERT_TYPE		2

//------------------------------------------------------
// Basic recognized file Types
//------------------------------------------------------

#define BINARY_FILE_TYPE	0		// DER encoded
#define	BASE64_ENCAP_FILE_TYPE	1
#define PEM_FILE_TYPE		2
#define	SMIME_FILE_TYPE		3
#define B64_UNKNOWN_FILE_TYPE	-1		// NOTE: was formerly 4

//------------------------------------------------------
// Types from decoding of encapsulated data
//------------------------------------------------------

#define PKCS10_DATA_TYPE	0
#define X509_DATA_TYPE		1
#define PKCS7_DATA_TYPE		2
#define PEM_REQ_DATA_TYPE	3
#define PEM_REPLY_DATA_TYPE	4
#define PEM_DATA_TYPE		5		// unspecified
#define	PKCS12_DATA_TYPE	6		// V1 / V3
#define	RSA_PRIVKEY_DATA_TYPE	7		// SSLEAY
#define	DSA_PRIVKEY_DATA_TYPE	8		// SSLEAY
#define B64_UNKNOWN_DATA_TYPE	-1		// NOTE: was formerly 6


//--------------------------------------------------------
// Encapsulation String types (Indices into table)
//--------------------------------------------------------

#define	ENCAP_NEW_STR_INDEX		0
#define	ENCAP_X509_STR_INDEX		1
#define	ENCAP_CERTREQ_STR_INDEX		2
#define	ENCAP_CERT_STR_INDEX		3
#define ENCAP_PEMMSG_STR_INDEX		4
#define	ENCAP_PKCS7_STR_INDEX		5
#define	ENCAP_PKCS7_SHRT_STR_INDEX	6
#define	ENCAP_RSA_PRIV_STR_INDEX	7
#define	ENCAP_DSA_PRIV_STR_INDEX	8
#define ENCAP_STR_COUNT			9



#define ENCAP_DELIM_STR_LEN		5
#define ENCAP_START_STR_LEN		6	// including trailing Space !
#define ENCAP_END_STR_LEN		4	// including trailing Space !
#define ENCAP_NEW_STR_LEN		4	// including trailing Space !
#define ENCAP_CERTREQ_STR_LEN		19
#define ENCAP_X509_STR_LEN		5	// including trailing Space !
#define ENCAP_CERT_STR_LEN		11
#define ENCAP_PEMMSG_STR_LEN		24
#define ENCAP_PKCS7_STR_LEN		19
#define	ENCAP_PKCS7_SHRT_STR_LEN	5
#define	ENCAP_RSA_PRIV_STR_LEN		15
#define	ENCAP_DSA_PRIV_STR_LEN		15

#define ENCAP_MINIMAL_STR_LEN		5	// least possible


static  const char EncapDelimStr [] =
  "-----";

static  const char EncapStartStr [] =
  "BEGIN ";

static  const char EncapEndStr [] =
  "END ";

static  const char EncapNewStr [] =
  "NEW ";

static  const char EncapCertReqStr [] =
  "CERTIFICATE REQUEST";

static  const char EncapX509Str [] =
  "X509 ";

static  const char EncapCertStr [] =
  "CERTIFICATE";

static  const char EncapPEMStr [] =
  "PRIVACY-ENHANCED MESSAGE";

static  const char EncapPkcs7Str [] =
  "PKCS #7 SIGNED DATA";

static  const char EncapPkcs7shrtStr [] =
  "PKCS7";

static  const char EncapRsaPrivkeyStr [] =
  "RSA PRIVATE KEY";

static  const char EncapDsaPrivkeyStr [] =
  "DSA PRIVATE KEY";


//--------------------------------------------------------
// Length table of the partial strings
// NOTE: Indices must be same as for string access table !
//--------------------------------------------------------

#define ENCAP_OPT_MASK		0x80


static  const int EncapStrCmpLenTab[ENCAP_STR_COUNT] = {
	ENCAP_NEW_STR_LEN,
	ENCAP_X509_STR_LEN,
	ENCAP_CERTREQ_STR_LEN,
	ENCAP_CERT_STR_LEN,
	ENCAP_PEMMSG_STR_LEN,
	ENCAP_PKCS7_STR_LEN,
	ENCAP_PKCS7_SHRT_STR_LEN,
	ENCAP_RSA_PRIV_STR_LEN,
	ENCAP_DSA_PRIV_STR_LEN
};
static  const char * EncapStrPtrTab [ENCAP_STR_COUNT] = {
	EncapNewStr,
	EncapX509Str,
	EncapCertReqStr,
	EncapCertStr,
	EncapPEMStr,
	EncapPkcs7Str,
	EncapPkcs7shrtStr,
	EncapRsaPrivkeyStr,
	EncapDsaPrivkeyStr,
};

//--------------------------------------------------------
// Control Table for delimiter line parser
//--------------------------------------------------------

#define ENCAP_STR_ENTRIES_COUNT	7

static  const unsigned char EncapStrCtrlTab[23] = {
					// 1. PKCS10 Certificate Request
    (unsigned char) 2,				//    number of Elements for Entry
    (unsigned char) PKCS10_DATA_TYPE,	  	//    type of Entry
    (unsigned char) (ENCAP_NEW_STR_INDEX | ENCAP_OPT_MASK),// String-Index 1
    (unsigned char) ENCAP_CERTREQ_STR_INDEX,	//    String Index 2

					// 2. X509 Certificate
    (unsigned char) 2,				//    number of Elements for Entry
    (unsigned char) X509_DATA_TYPE,	  	//    type of Entry
    (unsigned char) (ENCAP_X509_STR_INDEX | ENCAP_OPT_MASK), // String-Index 1
    (unsigned char) ENCAP_CERT_STR_INDEX,		//    String Index 2

					// 3. PEM X509 Certs / PEM CertReq.
    (unsigned char) 1,				//    number of Elements for Entry
    (unsigned char) PEM_DATA_TYPE,	  	//    type of Entry
    (unsigned char) ENCAP_PEMMSG_STR_INDEX,	//    String-Index 1

					// 4. PKCS7 Certificate(s)
    (unsigned char) 1,				//    number of Elements for Entry
    (unsigned char) PKCS7_DATA_TYPE,	  	//    type of Entry
    (unsigned char) ENCAP_PKCS7_STR_INDEX,	//    String-Index 1

					// 5. PKCS7 Certificate(s) (short description)
    (unsigned char) 1,				//    number of Elements for Entry
    (unsigned char) PKCS7_DATA_TYPE,	  	//    type of Entry
    (unsigned char) ENCAP_PKCS7_SHRT_STR_INDEX,	//    String-Index 1

					// 6. RSA Private key (Openssl/SSLEay)
    (unsigned char) 1,				//    number of Elements for Entry
    (unsigned char) RSA_PRIVKEY_DATA_TYPE,	//    type of Entry
    (unsigned char) ENCAP_RSA_PRIV_STR_INDEX,	//    String-Index 1

					// 7. DSA Private key (Openssl/SSLEay)
    (unsigned char) 1,				//    number of Elements for Entry
    (unsigned char) DSA_PRIVKEY_DATA_TYPE,	//    type of Entry
    (unsigned char) ENCAP_DSA_PRIV_STR_INDEX,	//    String-Index 1
};	  

//--------------------------------------------------
// Mime related Strings
//--------------------------------------------------

#define MIME_VERS_STR_TOTAL_LEN	16	// total length
#define MIME_VERS_FIELD_NAME_LEN 12	// only field name

#define CONTENT_TYPE_LEN	13
#define BOUNDARY_PAR_NAME_LEN	9
#define BOUNDARY_PAR_MIN_LEN	1
#define BOUNDARY_PAR_MAX_LEN	69
#define MULTIPART_TYPE_LEN	10
#define APPLICATION_TYPE_LEN	12
#define xPKCS7_MIME_STR_LEN	12
#define PKCS7_MIME_STR_LEN	10		// without x-
#define xPKCS10_MIME_STR_LEN	8
#define PKCS10_MIME_STR_LEN	6		// without x-


static  const char MimeVersStr [] =
  "MIME-Version:1.0";

static  const char ContentTypeStr [] =
  "Content-Type:";

static  const char BoundaryParStr [] =
  "boundary=";

static  const char MultipartStr [] =
  "multipart/";

static  const char ApplicationStr [] =
  "application/";

static  const char xPkcs7MimeStr [] =
  "x-pkcs7-mime";

static  const char xPkcs10MimeStr [] =
  "x-pkcs10";


#define PEM_PROC_ID			0x34	// ASCII 4

#define BEGIN_PEM_STR_LEN		40
#define END_PEM_STR_LEN			38

#define PROC_TYPE_NAME_STR_LEN		10
#define CONT_DOMAIN_NAME_STR_LEN	15
#define ORIG_CERT_NAME_STR_LEN		23
#define ISSUER_CERT_NAME_STR_LEN	19
#define MIC_INFO_NAME_STR_LEN		 9
#define RFC822_STR_LEN			 6
#define MIC_ONLY_STR_LEN		 8
#define RSA_MD_STR_LEN			 6
#define RSA_STR_LEN			 3

static  const char EndPEMStr [] =
  "-----END PRIVACY-ENHANCED MESSAGE-----";

static  const char ProcTypeNameStr [] =
  "Proc-Type:";

static  const char MicOnlyStr [] =
  "MIC-ONLY";

static  const char ContentDomainStr [] =
  "Content-Domain:";

static  const char RFC822Str [] =
  "RFC822";

static  const char OriginatorCertStr [] =
  "Originator-Certificate:";

static  const char IssuerCertStr [] =
  "Issuer-Certificate:";

static  const char MicInfoStr [] =
  "MIC-Info:";

static  const char RsaMdStr [] =
  "RSA-MD";

#define PEM_REQ_TEXT_FLD_LEN	24

static  const char PemReqText [] =
  "This is an RFC-1424 CSR.";

//----------------------------------------------------------------------
// Decoder-Table (20h-7Fh), Invalid Codes = 0FFh, Padding-Code = 0FEh
//----------------------------------------------------------------------
static  const unsigned char Base64DecodeTab[6*16]  = {
//	        0            1            2            3
	(unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF,// 20h-23h
//	       SPC           !            "            #
//
//	        4            5            6            7
	(unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF,// 24h-27h
//	        $            %            &            '
//
//	        8            9            A            B
	(unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0x3E,// 28h-2Bh
//	        (            )            *            +
//
//	        C            D            E            F
	(unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0x3F,// 2Ch-2Fh
//	        ,            -            .            /
//
//	        0            1            2            3
	(unsigned char) 0x34, (unsigned char) 0x35, (unsigned char) 0x36, (unsigned char) 0x37,// 30h-33h
//	       '0'          '1'          '2'          '3'
//
//	         4            5            6            7
	 (unsigned char) 0x38, (unsigned char) 0x39, (unsigned char) 0x3A, (unsigned char) 0x3B,// 34h-37h
//	        '4'          '5'          '6'          '7'
//
//	        8            9            A            B
	(unsigned char) 0x3C, (unsigned char) 0x3D, (unsigned char) 0xFF, (unsigned char) 0xFF,// 38h-3Bh
//	       '8'          '9'           :            ; 
//
//	        C            D            E            F
	(unsigned char) 0xFF, (unsigned char) 0xFE, (unsigned char) 0xFF, (unsigned char) 0xFF,// 3Ch-3Fh
//	        <            =            >            ?
//
//	        0            1            2            3
	(unsigned char) 0xFF, (unsigned char) 0x00, (unsigned char) 0x01, (unsigned char) 0x02,// 40h-43h
//	        @           'A'          'B'          'C'
//
//	        4            5            6            7
	(unsigned char) 0x03, (unsigned char) 0x04, (unsigned char) 0x05, (unsigned char) 0x06,// 44h-47h
//	       'D'          'E'          'F'          'G'
//
//	        8            9            A            B
	(unsigned char) 0x07, (unsigned char) 0x08, (unsigned char) 0x09, (unsigned char) 0x0A,// 48h-4Bh
//	       'H'          'I'          'J'          'K'
//
//	        C            D            E            F
	(unsigned char) 0x0B, (unsigned char) 0x0C, (unsigned char) 0x0D, (unsigned char) 0x0E,// 4Ch-4Fh
//	       'L'          'M'          'N'          'O'
//
//	        0            1            2            3
	(unsigned char) 0x0F, (unsigned char) 0x10, (unsigned char) 0x11, (unsigned char) 0x12,// 50h-53h
//	       'P'          'Q'          'R'          'S'
//
//	        4            5            6            7
	(unsigned char) 0x13, (unsigned char) 0x14, (unsigned char) 0x15, (unsigned char) 0x16,// 54h-57h
//	       'T'          'U'          'V'          'W'
//
//	        8            9            A            B
	(unsigned char) 0x17, (unsigned char) 0x18, (unsigned char) 0x19, (unsigned char) 0xFF,// 58h-5Bh
//	       'X'          'Y'          'Z'           [
//
//	        C            D            E            F
	(unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF,// 5Ch-5Fh
//	        \            ]            ^            _
//
//	        0            1            2            3
	(unsigned char) 0xFF, (unsigned char) 0x1A, (unsigned char) 0x1B, (unsigned char) 0x1C,// 60h-63h
//	        `           'a'          'b'          'c'
//
//	        4            5            6            7
	(unsigned char) 0x1D, (unsigned char) 0x1E, (unsigned char) 0x1F, (unsigned char) 0x20,// 64h-67h
//	       'd'          'e'          'f'          'g'
//
//	        8            9            A            B
	(unsigned char) 0x21, (unsigned char) 0x22, (unsigned char) 0x23, (unsigned char) 0x24,// 68h-6Bh
//	       'h'          'i'          'j'          'k'
//
//	        C            D            E            F
	(unsigned char) 0x25, (unsigned char) 0x26, (unsigned char) 0x27, (unsigned char) 0x28,// 6Ch-6Fh
//	       'l'          'm'          'n'          'o'
//
//	        0            1            2            3
	(unsigned char) 0x29, (unsigned char) 0x2A, (unsigned char) 0x2B, (unsigned char) 0x2C,// 70h-73h
//	       'p'          'q'          'r'          's'
//
//	        4            5            6            7
	(unsigned char) 0x2D, (unsigned char) 0x2E, (unsigned char) 0x2F, (unsigned char) 0x30,// 74h-77h
//	       't'          'u'          'v'          'w'
//
//	        8            9            A            B
	(unsigned char) 0x31, (unsigned char) 0x32, (unsigned char) 0x33, (unsigned char) 0xFF,// 78h-7Bh
//	       'x'          'y'          'z'           {
//
//	        C            D            E            F
	(unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF, (unsigned char) 0xFF // 7Ch-7Fh
//	        |            }            ~           DEL
};
//----------------------------------------------------------------------
// Encoder-Table (00h-3Fh)
//----------------------------------------------------------------------
static  const char Base64EncodeTab[4*16]  = {
//	        0            1            2            3
	(unsigned char) 0x41, (unsigned char) 0x42, (unsigned char) 0x43, (unsigned char) 0x44,// 00h-03h
//	       'A'          'B'          'C'          'D'
//
//	        4            5            6            7
	(unsigned char) 0x45, (unsigned char) 0x46, (unsigned char) 0x47, (unsigned char) 0x48,// 04h-07h
//	       'E'          'F'          'G'          'H'
//
//	        8            9            A            B
	(unsigned char) 0x49, (unsigned char) 0x4A, (unsigned char) 0x4B, (unsigned char) 0x4C,// 08h-0Bh
//	       'I'          'J'          'K'          'L'
//
//	        C            D            E            F
	(unsigned char) 0x4D, (unsigned char) 0x4E, (unsigned char) 0x4F, (unsigned char) 0x50,// 0Ch-0Fh
//	       'M'          'N'          'O'          'P'
//
//	        0            1            2            3
	(unsigned char) 0x51, (unsigned char) 0x52, (unsigned char) 0x53, (unsigned char) 0x54,// 10h-13h
//	       'Q'          'R'          'S'          'T'
//
//	        4            5            6            7
	(unsigned char) 0x55, (unsigned char) 0x56, (unsigned char) 0x57, (unsigned char) 0x58,// 14h-17h
//	       'U'          'V'          'W'          'X'
//
//	        8            9            A            B
	(unsigned char) 0x59, (unsigned char) 0x5A, (unsigned char) 0x61, (unsigned char) 0x62,// 18h-1Bh
//	       'Y'          'Z'          'a'          'b'
//
//	        C            D            E            F
	(unsigned char) 0x63, (unsigned char) 0x64, (unsigned char) 0x65, (unsigned char) 0x66,// 1Ch-1Fh
//	       'c'          'd'          'e'          'f'
//
//	        0            1            2            3
	(unsigned char) 0x67, (unsigned char) 0x68, (unsigned char) 0x69, (unsigned char) 0x6A,// 20h-23h
//	       'g'          'h'          'i'          'j'
//
//	        4            5            6            7
	(unsigned char) 0x6B, (unsigned char) 0x6C, (unsigned char) 0x6D, (unsigned char) 0x6E,// 24h-27h
//	       'k'          'l'          'm'          'n'
//
//	        8            9            A            B
	(unsigned char) 0x6F, (unsigned char) 0x70, (unsigned char) 0x71, (unsigned char) 0x72,// 28h-2Bh
//	       'o'          'p'          'q'          'r'
//
//	        C            D            E            F
	(unsigned char) 0x73, (unsigned char) 0x74, (unsigned char) 0x75, (unsigned char) 0x76,// 2Ch-2Fh
//	       's'          't'          'u'          'v'
//
//	        0            1            2            3
	(unsigned char) 0x77, (unsigned char) 0x78, (unsigned char) 0x79, (unsigned char) 0x7A,// 30h-33h
//	       'w'          'x'          'y'          'z'
//
//	        4            5            6            7
	(unsigned char) 0x30, (unsigned char) 0x31, (unsigned char) 0x32, (unsigned char) 0x33,// 34h-37h
//	       '0'          '1'          '2'          '3'
//
//	        8            9            A            B
	(unsigned char) 0x34, (unsigned char) 0x35, (unsigned char) 0x36, (unsigned char) 0x37,// 38h-3Bh
//	       '4'          '5'          '6'          '7'
//
//	        C            D            E            F
	(unsigned char) 0x38, (unsigned char) 0x39, (unsigned char) 0x2B, (unsigned char) 0x2F,// 3Ch-3Fh
//	       '8'          '9'           +            /
};

#endif // __BASE64_HEADER__

/**
* Decodes OPENSSL RSA private key encoding (from PEM file) to
* a newly allocated RSA structure (FromOpensslRsaPrivKey).
*
*  @param pInpBuf Buffer containing ASN.1 encoding of openssl RSA private key
*  @param InpOff Start offset of data
*  @param InpLen Length of data
*  @param ppRsaStruc Pointer to store the new RSA structure
*  @return 0 on success, error code otherwise
*/
extern int  FromOpensslRsaPrivKey(HMEM_CTX_DEF 
                                  char* pInpBuf,
                                  int InpOff,
                                  int InpLen, 
                                  RSA_STRUC** ppRsaStruc);

/**
* Encodes RSA structure to OPENSSL RSA private key encoding (for PEM file)
* and stores it in a newly allocated buffer (ToOpensslRsaPrivKey).
*
*  @param pRsaStruc RSA structure with priv. key
*  @param ppDstBuf Pointer for storing the destination buffer
*  @param pDstLen Length of data returned
*  @return 0 on success, error code otherwise
*/
extern int  ToOpensslRsaPrivKey(HMEM_CTX_DEF
                                RSA_STRUC* pRsaStruc, 
                                char** ppDstBuf,
                                int* pDstLen);

/**
* Decodes OPENSSL DSA private key encoding (from PEM file) to
* a newly allocated DSA structure (FromOpensslDsaPrivKey).
*
*  @param pInpBuf Buffer containing ASN.1 encoding of openssl DSA private key
*  @param InpOff Start offset of data
*  @param InpLen Length of data
*  @param ppDsaStruc Pointer to store the new DSA structure
*  @return 0 on success, error code otherwise
*/
extern int  FromOpensslDsaPrivKey(HMEM_CTX_DEF 
                                  char* pInpBuf, 
                                  int InpOff,
                                  int InpLen,
                                  DSA_STRUC** ppDsaStruc);

/**
* Encodes DSA structure to OPENSSL DSA private key encoding (for PEM file)
* and stores it in a newly allocated buffer (ToOpensslDsaPrivKey).
*
*  @param pDsaStruc DSA structure with priv. key
*  @param ppDstBuf Pointer for storing the destination buffer
*  @param pDstLen Length of data returned
*  @return 0 on success, error code otherwise
*/
extern int  ToOpensslDsaPrivKey(HMEM_CTX_DEF 
                                DSA_STRUC* pDsaStruc, 
                                char** ppDstBuf, 
                                int* pDstLen);


/**
* Makes a deep copy of a X501 DN structure (AllocCopyX501DnDesc). 
* The destination structure itself
* must already be allocated, the content is (re-)allocated as required.
* 
*  @param pSrcNameDesc Source descriptor
*  @param pDstNameDesc Destination descriptor
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  AllocCopyX501DnDesc(HMEM_CTX_DEF
                                X501_DN* pSrcNameDesc, 
                                X501_DN* pDstNameDesc);

/**
* Converts a time structure to ASN.1 UTC or Generalized Time type and stores it
* to a newly allocated <code>IDATPARR</code> (ToASN1_TimeString).
*
*  @param TimeArray Pointer to time array structure to encode
*  @param TimeType Encoding to use <br>
*               1 - UTC <br>
*               2 - Generalized Time
*  @param pDstArrDesc Allocated descriptor
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  ToASN1_TimeString(HMEM_CTX_DEF
                              int* TimeArray, 
                              int TimeType, 
                              IDATPARR** pDstArrDesc);
/**
* Allocates a certificate request structure, initializes values to default and
* allocates <code>IDATPARR</code> elements (1 for each entry).
*
*  @param pCertReqStruc Pointer where to store allocated certificate request 
                        structure
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  AllocCertReqStruc(HMEM_CTX_DEF
                              PKCS10_CERTREQ ** pCertReqStruc);

/**
* Frees certificate request structure content (FreeCertReqStruc).
*
* NOTE: The structure itsself must be freed separately
*
*  @param CertReqStruc Certificate request structure
*/
extern void  FreeCertReqStruc(HMEM_CTX_DEF 
                              PKCS10_CERTREQ * CertReqStruc);

/**
* Converts a given ASN.1 encoded
* certificate array into a newly allocated array of internal structures (FromCertListToCertStrucListEX).
*
* Note: The structures will contain a copy of the original data
* so that the certificate buffer can be freed.
*
*  @param CertDescList Pointer to <code>IDATA</code> container structure with list of 
*                       certificates as elements
*  @param ProcessFlags Processing flags: <br>
*               Bit 0 - 1 : Do NOT sort RDNs <br>
*               Bit 1 - 1 : Process extensions <br>
*               Bit 2 - 1 : Ignore unknown
*               Critical extensions <br>
*               Bit 3 - 1 : Ignore all extens.
*               errors <br>
*               Bit 4-31 - reserved
*  @param ppCertsArray Pointer to place new ceritficate array
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromCertListToCertStrucListEX(HMEM_CTX_DEF 
                                          IDATPARR* 
                                          CertDescList, 
                                          int ProcessFlags,
                                          X509CERT *** ppCertsArray);

/**
* Allocates an array of internal represented
* certificate structure pointers (AllocCertStructList). 
* All pointers are initialized to NULL.
*
*  @param ppCertListArray Return pointer for allocated array
*  @param CertCount Requested size of the array
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  AllocCertStructList(HMEM_CTX_DEF
                                X509CERT *** ppCertListArray,
                                int CertCount);

/**
* Splits ASN.1 certificate
* request and loads the components to internal certificate
* request structure (FromASN1CertReqToCertReqStruc).
*
* NOTE: Attributes checking must still be implemented
*
* Does some preprocessing on the components:
* <ol>
* <li> Splits IBM container with certificate/private key if requested,
* <li> Checks known and valid signature algor and params
* <li> Compares TBS CertRequest signat algor/params to cert request
* <li> Subdecodes/checks subject public algor/params/value
* <li> Subdecodes subject RDNs
* </ol>
*
* If a special certificate (with key) is presented:
* <ol>
* <li> Checks/decrypts private key using given password
* <li> Checks the algor type and params against the certificate requests
*     public algor and params
* <li> Subdecodes the private values and stores them
* </ol>
*
* NOTE: To enable freeing of the underlying certificate request buffer
*   the certificate request as is is copied into a local buffer.
*	 The private params are also copied.
*
*  @param SrcBuf Source buffer
*  @param SrcOffset Start offset of data
*  @param SrcLen Length of data
*  @param CertReqType Type of certificate request: <br>
*               0 - pure ASN.1 <br>
*               1 - IBM enveloped CertReq,
*               private key not decoded
*               if present <br>
*               2 - IBM enveloped CertReq with
*               private key,
*               private key decoded <br>
*  @param SortFlag == 0 - sort the RDN components <br>
*               != 0 - don't sort the RDN components
*  @param Pwd Password for key CertReq
*  @param PwdLen Length of password
*  @param pCertReqStruc Pointer where to store allocated certificate 
*                         request structure
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromASN1CertReqToCertReqStruc(HMEM_CTX_DEF	
                                          char* SrcBuf,
                                          int SrcOffset,
                                          int SrcLen,		
                                          int CertReqType,
                                          int SortFlag,
                                          char* Pwd,
                                          int PwdLen,	
                                          PKCS10_CERTREQ ** pCertReqStruc);

/**
* Generates data structures
* in internal notation ('Data Elements') from given ASN.1 encoded 
* PKCS7 signed data certificate list input byte stream (FromASN1_PKCS7CertListEX).
*
* Before decoding, check if more data present than required:
* <ol>
* <li> Assure that data start with an ASN1 sequence.
* <li> Get the length of the sequence.
* <li> Truncate data length if required.
* </ol>
* This is done due to some dumb PKCS7 generators that append e.g.
* CR/LFs at end of PKCS7 binary data.
*
* The PKCS7 signed data certificate list is split into:
*<ol>
* <li> Signed data OID, must be 'signed data'.
* <li> Signed data version, must be 0 or 1.
* <li> DigestAlgorithms (Set of algorithm identifiers), ignored .
* <li> ContentInfo OID, must be 'data'.
* <li> ContentInfo data (Explicit[0] sequence), ignored.
* <li> Certificates (sequence of certificates), w.o. header.
* <li> SignerInfo (sequence), ignored.
* </ol>
* After verification of PKCS7 format, the certificates sequence
* is subsplit into single certificates. These DER encoded
* certificates are then converted into internal certificate
* structures and a list of those is built.
*
* Note: Required structures will be allocated and filled
*
*  @param InpBuf ASN.1 datastream buffer
*  @param InpOffset Start offset of data
*  @param InpLen Length of data
*  @param ProcessFlags Processing flags: <br>
*               Bit 0 - 1 : Do NOT sort RDNs <br>
*               Bit 1 - 1 : Process extensions <br>
*               Bit 2 - 1 : Ignore unknown
*               Critical extensions <br>
*               Bit 3 - 1 : Ignore all extens.
*               errors <br>
*               Bit 4-31 - reserved
*  @param ppCertStrucList Pointer where to store list array of certificate 
*                         structures
*  @param pCertCnt Number of certificates
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  FromASN1_PKCS7CertListEX(HMEM_CTX_DEF 
                                     char* InpBuf, 
                                     int InpOffset,
                                     int InpLen, 
                                     int ProcessFlags,
                                     X509CERT *** ppCertStrucList, 
                                     int* pCertCnt);

/**
* Checks, if given ASN.1 encoding represents a PFX (PKCS12 V1) or
* PKCS12 V3 Format (PKCS12_CheckDecodeFormat).
*
* If a password is given, it tries to decode data.
* If a Certlist Pointer is given, it converts it to internal structure.
* 
*
*  @param pBuf Data buffer base
*  @param Offset Start offset of Data
*  @param DataLen Length of data
*  @param pPwd Password (ASCII). Optional
*  @param PwdOff Start offset of password
*  @param PwdLen Length of password
*  @param pPkcs12Type Return parameter for detected PKCS12 type. Optional
*  @param ppPfxStruc Structure pointer / NULL
*  @param ppCertList List to fill / NULL
*  @param pCertsCnt Number of Certs / NULL
*  @return 0 on success, error code otherwise
*/
extern int  PKCS12_CheckDecodeFormat(char* pBuf,
                                     int Offset,   
                                     int DataLen,
                                     char* pPwd, 
                                     int PwdOff,
                                     int PwdLen,   
                                     int* pPkcs12Type,
                                     PK12STRU ** ppPfxStruc,  
                                     X509CERT *** ppCertList,
                                     int* pCertsCnt);

/**
* Generates ASN.1 DER-encoded PKCS7 signed data
* certificate list from given certificate structures array and stores it
* in a new buffer (ToASN1_PKCS7CertList).
*
* NOTE: There must be already a certificate present in the
*	    certlist structures 
*
*  @param pCertStrucList Array of certificates
*  @param CertsCnt Number of certificates
*  @param ppDstBuf Pointer for storing the new data buffer
*  @param pDstLen Length of data
*
*  @return ASN1_OP_OK on success, error code otherwise
*/
extern int  ToASN1_PKCS7CertList(HMEM_CTX_DEF 
                                 X509CERT ** pCertStrucList, 
                                 int CertsCnt,
                                 char** ppDstBuf, 
                                 int* pDstLen);


#ifdef __cplusplus
}
#endif

#endif // !__HOB_CERT_INTERN__
