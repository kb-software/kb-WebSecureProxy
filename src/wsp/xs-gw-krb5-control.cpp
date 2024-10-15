#define NEW110210
#define WITH_USER_GROUP
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-gw-krb5-control                                  |*/
/*| -------------                                                     |*/
/*|  Main Control Class for xs-gw-krb5-lib functionality to:          |*/
/*|     - get a TGT                                                   |*/
/*|     - renew a TGT                                                 |*/
/*|     - get Service Tickets                                         |*/
/*|  JF 01.09.09                                                      |*/
/*|     - initialization of a krb5 security context for a             |*/
/*|       client/server architecture                                  |*/
/*|     - regarding to a krb5 security context encoding and decoding  |*/
/*|       of data                                                     |*/
/*|  JF 16.11.09                                                      |*/
/*|     - encapsulation and decapsulation of krb5 tokens in gss token |*/
/*|  JF 21.01.10                                                      |*/
/*|     - regarding to a krb5 security context encoding and decoding  |*/
/*|       of data with m_gss_wrap and m_gss_unwrap                    |*/
/*|  JF 11.02.10                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  independant of operating system,                                 |*/
/*|  so any C++ compiler may be used.                                 |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(HL_UNIX)
#include <pthread.h>
#include <netdb.h>
#include <stdarg.h>
#include <hob-unix01.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <hob-krb5-defines.h>
#ifdef HOB_KERBEROS_CPP
#ifdef HL_KRB5_WSP_ACTIV
//#define TRY_091003  /* only because of errors at Visual Studio */
// to-do 30.09.09 KB - when exception is caught - mark-thread ???
#endif
#include <exception>

#include <cstring>
//#include <ctype.h>
#include <hob-krb5-asn1.h>
#include <heim_err.h>
#include <krb5_err.h>

#ifdef HL_KRB5_WSP_ACTIV
#ifdef XYZ1
#ifdef PTYPE
#undef PTYPE
#endif
#endif
#define PTYPE "C"
/* windows or operating system header files */
#define DOMNode void
#endif
#define EXT_GR_850_TO_819
#include <hltabaw2.h>
#include <hob-xslunic1.h>
#include <hob-avl03.h>
#ifdef HL_KRB5_WSP_ACTIV
#include "hob-xsclib01.h"
#include "hob-wsppriv.h"                    /* privileges              */
#include <hob-xslcontr.h>                   /* HOB Control             */
#include <hob-netw-01.h>                    /* HOB Networking          */
#include <hob-wspsu1.h>
#include <hob-xbipgw08-1.h>
#endif
#define NOT_INCLUDED_CLIB
#include <hob-xbipgw08-2.h>
#include <hob-xslhcla1.hpp>
#define GSS_S_FAILURE (13ul << 16)
#ifdef HOB_KRB5_UNIT_TEST
struct dsd_hl_aux_c_cma_1 dsg_cma_1;    /* CMA structure for unit tests */
struct dsd_hl_aux_c_cma_1 dsg_cma_2;    /* CMA structure for unit tests */
HL_LONGLONG test_time_stamp;                 /* timer for Unit tests */
#endif


/**
Reads the length field of ASN1 data.
The length of the field and the value are parsed.

@param[in]  aucp_len_field Pointer to the start of the length field.
@param[out] ainp_field_len Pointer to return the total length of the length field in bytes
@param[out] ainp_data_len  Pointer to return the length of the value field in bytes

@return 0 on success, != 0 otherwise
*/
static int m_get_asn1_len(const unsigned char* aucp_len_field, int* ainp_field_len, int* ainp_data_len){
   int inl_len_bytes = (*aucp_len_field) & 0x7f;
   *ainp_field_len = 1;
   if( 0 == ((*aucp_len_field)&0x80) ){
      //short form
      *ainp_data_len = *aucp_len_field;
      return 0;
   }
   // long form
   if( sizeof(int) < inl_len_bytes ){
      // length to big
      return -1;
   }

   // Set length field length and increment pointer
   *ainp_field_len += inl_len_bytes;

   // read length of value
   *ainp_data_len = 0;
   while( 0 < inl_len_bytes ){
      aucp_len_field++;
      (*ainp_data_len) <<= 8;
      *ainp_data_len += *aucp_len_field;
      inl_len_bytes--;
   }

   if( 0x80 > *ainp_data_len){
      // should be short form
      return -2;
   }
   return 0;
}

/**
Checks an ASN1 tag and skips tag, length and (if intended) value fields.

Tag is always assumed to be short form. If a tag mismatch is found, data and
length pointers are not modified. This allows checking for optional values.

@param[inout]  aaucp_data  [in]Address of the pointer to the ASN1 tag.
                           [out]Pointer moved beyond the skipped fields.
@param[inout]  ainp_len    [in]Length of the data before skipping.
                           [out]Length of the remaining data after skipping.
@param[in]     ucp_tag     The ASN1 tag to be checked for.
@param[in]     bop_mismatch_is_error   If FALSE, returns 0 on tag mismatch,
                                       else returns error on mismatch.
@param[in]     bop_skip_val   If TRUE, skips the value field.

@return length of the value field, <0 on error
*/
static int m_check_and_skip(const unsigned char** aaucp_data,
                            int* ainp_len,
                            unsigned char ucp_tag,
                            BOOL bop_mismatch_is_error,
                            BOOL bop_skip_val)
{
   int inl_len_field_len = 0;
   int inl_val_len = 0;
   int inl_ret = 0;
   if( ucp_tag != (**aaucp_data) ){
      if(bop_mismatch_is_error){
         return -1;
      }
      return 0;
   }
   (*aaucp_data)++;
   (*ainp_len)--;

   inl_ret = m_get_asn1_len((*aaucp_data), &inl_len_field_len, &inl_val_len);
   if( (0 != inl_ret) || ((*ainp_len) < (inl_len_field_len + inl_val_len)) ){
      return -2;
   }

   (*aaucp_data)+= inl_len_field_len;
   (*ainp_len) -= inl_len_field_len;

   if(bop_skip_val){
      (*aaucp_data)+= inl_val_len;
      (*ainp_len) -= inl_val_len;
   }
   return inl_val_len;
}

/**
Extracts position and length of the krb5_token from a SPNEGO response of
type NegotiationToken.

For example it would extract the krb5 blob from the wrapping Security Blob
in an SMB2 Session Setup Response.

The returned pointer points at a position of the value field of the response token
within the input data. It is NOT separately allocated and only valid, while the
original data is valid.

For checking the input: The first byte must be 0xa1.

@param[in]  aucp_spnego_resp  Buffer with the SPNEGO response to be parsed.
@param[in]  inp_resp_len      Length of the SPNGEO response.
@param[out] aaucp_token       Returns a pointer to the response token element.
@param[out] ainp_token_len    Returns the length of the response token element.

@return 0 on success, !=0 on error.
*/
static int m_get_krb5_token_from_neg_response(const unsigned char* aucp_spnego_resp,
                                              int inp_resp_len,
                                              unsigned char** aaucp_token,
                                              int* ainp_token_len)
{
   int inl_ret = 0;
   // input validation
   if( (NULL == aucp_spnego_resp) ||
      (NULL == aaucp_token) ||
      (NULL == ainp_token_len) )
   {
      return -1;
   }

   // check response header (Choice tag and sequence tag)
   inl_ret = m_check_and_skip(&aucp_spnego_resp, &inp_resp_len, 0xa1, TRUE, FALSE);
   if( 0 > inl_ret ){
      return -2;
   }

   inl_ret = m_check_and_skip(&aucp_spnego_resp, &inp_resp_len, 0x30, TRUE, FALSE);
   if( 0 > inl_ret ){
      return -2;
   }

   // check for negState field, skip it
   inl_ret = m_check_and_skip(&aucp_spnego_resp, &inp_resp_len, 0xa0, FALSE, TRUE);
   if( 0 > inl_ret ){
      return -2;
   }

   // check for supportedMech field, skip it
   inl_ret = m_check_and_skip(&aucp_spnego_resp, &inp_resp_len, 0xa1, FALSE, TRUE);
   if( 0 > inl_ret ){
      return -2;
   }

   // This must be the token field, get the value
   inl_ret = m_check_and_skip(&aucp_spnego_resp, &inp_resp_len, 0xa2, TRUE, FALSE);
   if( 0 > inl_ret ){
      return -2;
   }

   // remove the octet string tag and length fields, the value is the result
   inl_ret = m_check_and_skip(&aucp_spnego_resp, &inp_resp_len, 0x04, TRUE, FALSE);
   if( 0 > inl_ret ){
      return -2;
   }

   // Set the result and return
   *aaucp_token = (unsigned char*)aucp_spnego_resp;
   *ainp_token_len = inl_ret;
   return 0;
}

/////////////////////////////////////////////////////////////
//
// ds_spnego.hpp
//
// SPNEGO Token Parser Header File
//
// Contains the definitions required to properly parse a
// SPNEGO token using ASN.1 DER helpers.
//
/////////////////////////////////////////////////////////////

#ifndef __SPNEGOPARSE_HPP_KRB__
#define __SPNEGOPARSE_HPP_KRB__

#ifndef __SPNEGO_DEFINES_HPP__
#define __SPNEGO_DEFINES_HPP__


// Users of SPNEGO Token Handler API will request these as well as free them.
typedef void*  SPNEGO_TOKEN_HANDLE;


// Defines the element types that are found in each of the tokens.
typedef enum ied_spnego_element_type {
   ien_spnego_element_min,  // Lower bound

   // Init token elements
   ien_spnego_init_mechtypes,
   ien_spnego_init_req_flags,
   ien_spnego_init_mech_token,
   ien_spnego_init_mech_list_mic,

   // Targ token elements
   ien_spnego_targ_neg_result,
   ien_spnego_targ_supported_mech,
   ien_spnego_targ_response_token,
   ien_spnego_targ_mech_list_mic,

   ien_spnego_element_max   // Upper bound
} SPNEGO_ELEMENT_TYPE;


// Token Element Availability.  Elements in both token types are optional. Since there are only
// 4 elements in each Token, we will allocate space to hold the information, but we need a way to
// indicate whether or not an element is available.
#define SPNEGO_TOKEN_ELEMENT_UNAVAILABLE 0
#define SPNEGO_TOKEN_ELEMENT_AVAILABLE 1


// Token type values.  SPNEGO has 2 token types: NegTokenInit and NegTokenTarg
#define SPNEGO_TOKEN_INIT 0
#define SPNEGO_TOKEN_TARG 1


// GSS Mechanism OID enumeration.  We only really handle 3 different OIDs.
// These are stored in an array structure defined in the parsing code.
typedef enum ied_spnego_mech_oid {
   // Init token elements
   ien_spnego_mech_oid_kerberos_v5_legacy, // Really V5, but OID off by 1 bit
   ien_spnego_mech_oid_kerberos_v5,
   ien_spnego_mech_oid_spnego,
   ien_spnego_mech_oid_not_used
} SPNEGO_MECH_OID;
#define SPNEGO_MECH_OID_MIN    ien_spnego_mech_oid_kerberos_v5_legacy
#define SPNEGO_MECH_OID_MAX    ien_spnego_mech_oid_spnego


// Defines the negResult values.
// The negState 3 ('request-mic') is not supported by lib_spnego.
typedef enum ied_spnego_neg_result {
   ien_spnego_negresult_success,
   ien_spnego_negresult_incomplete,
   ien_spnego_negresult_rejected,
   ien_spnego_negresult_not_used = -1
} SPNEGO_NEGRESULT;


//
// Context Flags in NegTokenInit
//

// ContextFlags values MUST be zero or a combination of the below
#define SPNEGO_NEGINIT_CONTEXT_DELEG_FLAG    0x80     // JF: Request delegated credentials for use by the context acceptor. Specifies whether or not the server may act as a proxy for the client.
#define SPNEGO_NEGINIT_CONTEXT_MUTUAL_FLAG   0x40     // JF: Request mutual authentication to validate the identity of the context acceptor.
#define SPNEGO_NEGINIT_CONTEXT_REPLAY_FLAG   0x20     // JF: Request message replay detection for signed or sealed messages.
#define SPNEGO_NEGINIT_CONTEXT_SEQUENCE_FLAG 0x10     // JF: Request message sequence checking for signed or sealed messages.
#define SPNEGO_NEGINIT_CONTEXT_ANON_FLAG     0x8      // JF: Request initiator anonymity.
#define SPNEGO_NEGINIT_CONTEXT_CONF_FLAG     0x4
#define SPNEGO_NEGINIT_CONTEXT_INTEG_FLAG    0x2


// Mask to retrieve valid values.
#define SPNEGO_NEGINIT_CONTEXT_MASK          0xFE  // Logical combination of above flags

//
// SPNEGO API return codes.
//

// API function was successful
#define SUCCESS                         0

// The supplied Token was invalid
#define SPNEGO_E_INVALID_TOKEN         -1

// An invalid length was encountered
#define SPNEGO_E_INVALID_LENGTH        -2

// The Token Parse failed
#define SPNEGO_E_PARSE_FAILED          -3

// The requested value was not found
#define SPNEGO_E_NOT_FOUND             -4

// The requested element is not available
#define SPNEGO_E_ELEMENT_UNAVAILABLE   -5

// Out of Memory
#define SPNEGO_E_OUT_OF_MEMORY         -6

// Not Implemented
#define SPNEGO_E_NOT_IMPLEMENTED       -7

// Invalid Parameter
#define SPNEGO_E_INVALID_PARAMETER     -8

// Token Handler encountered an unexpected OID
#define SPNEGO_E_UNEXPECTED_OID        -9

// The requested token was not found
#define SPNEGO_E_TOKEN_NOT_FOUND       -10

// An unexpected type was encountered in the encoding
#define SPNEGO_E_UNEXPECTED_TYPE       -11

// The buffer was too small
#define SPNEGO_E_BUFFER_TOO_SMALL      -12

// A Token Element was invalid (e.g. improper length or value)
#define SPNEGO_E_INVALID_ELEMENT       -13



#endif

#ifndef __DERPARSE_HPP_KRB__
#define __DERPARSE_HPP_KRB__



// Identifier Types
#define  IDENTIFIER_MASK               0xC0  // Bits 7 and 8
#define  IDENTIFIER_UNIVERSAL          0x00  // 00 = universal
#define  IDENTIFIER_APPLICATION        0x40  // 01 = application
#define  IDENTIFIER_CONTEXT_SPECIFIC   0x80  // 10 = context specific
#define  IDENTIFIER_PRIVATE            0xC0  // 11 = Private

// Encoding type
#define FORM_MASK       0x20    /* Bit 6 */
#define PRIMITIVE       0x00    /* 0 = primitive */
#define CONSTRUCTED     0x20    /* 1 = constructed */

// Universal tags
#define TAG_MASK        0x1F    /* Bits 5 - 1 */
#define BOOLEAN         0x01    /*  1: TRUE or FALSE */
#define INTEGER         0x02    /*  2: Arbitrary precision integer */
#define BITSTRING       0x03    /*  2: Sequence of bits */
#define OCTETSTRING     0x04    /*  4: Sequence of bytes */
#define NULLTAG         0x05    /*  5: NULL */
#define OID             0x06    /*  6: Object Identifier (numeric sequence) */
#define OBJDESCRIPTOR   0x07    /*  7: Object Descriptor (human readable) */
#define EXTERNAL        0x08    /*  8: External / Instance Of */
#define REAL            0x09    /*  9: Real (Mantissa * Base^Exponent) */
#define ENUMERATED      0x0A    /* 10: Enumerated */
#define EMBEDDED_PDV    0x0B    /* 11: Embedded Presentation Data Value */
#define SEQUENCE        0x10    /* 16: Constructed Sequence / Sequence Of */
#define SET             0x11    /* 17: Constructed Set / Set Of */
#define NUMERICSTR      0x12    /* 18: Numeric String (digits only) */
#define PRINTABLESTR    0x13    /* 19: Printable String */
#define T61STR          0x14    /* 20: T61 String (Teletex) */
#define VIDEOTEXSTR     0x15    /* 21: Videotex String */
#define IA5STR          0x16    /* 22: IA5 String */
#define UTCTIME         0x17    /* 23: UTC Time */
#define GENERALIZEDTIME 0x18    /* 24: Generalized Time */
#define GRAPHICSTR      0x19    /* 25: Graphic String */
#define VISIBLESTR      0x1A    /* 26: Visible String (ISO 646) */
#define GENERALSTR      0x1B    /* 27: General String */
#define UNIVERSALSTR    0x1C    /* 28: Universal String */
#define BMPSTR          0x1E    /* 30: Basic Multilingual Plane String */

// Length encoding
#define LEN_XTND  0x80      /* Indefinite or long form */
#define LEN_MASK  0x7f      /* Bits 7 - 1 */

//
// SPNEGO Token Parsing Constants
//

// Fixed Length of NegTokenInit ReqFlags field
#define  SPNEGO_NEGINIT_MAXLEN_REQFLAGS   2

// Difference in bits for ReqFlags token
#define  SPNEGO_NEGINIT_REQFLAGS_BITDIFF  1

// Fixed Length of NegTokenTarg NegResult field
#define  SPNEGO_NEGTARG_MAXLEN_NEGRESULT  1

// Application Specific Construct - Always at the start of a NegTokenInit
#define  SPNEGO_NEGINIT_APP_CONSTRUCT     ( IDENTIFIER_APPLICATION | CONSTRUCTED ) // 0x60

// Constructed Sequence token - after the actual token identifier token
#define  SPNEGO_CONSTRUCTED_SEQUENCE      ( SEQUENCE | CONSTRUCTED )

// MechList Type Identifier
#define  SPNEGO_MECHLIST_TYPE      ( SEQUENCE | CONSTRUCTED | OID )

//
// NegTokenInit - Token Identifier and Elements
//

// NegTokenInit - 0xa0
#define  SPNEGO_NEGINIT_TOKEN_IDENTIFIER  ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                             SPNEGO_TOKEN_INIT )

// Structure elements for NegTokenInit
#define  SPNEGO_NEGINIT_MECHTYPES   0x0   // MechTypes is element 0
#define  SPNEGO_NEGINIT_REQFLAGS    0x1   // ReqFlags is element 1
#define  SPNEGO_NEGINIT_MECHTOKEN   0x2   // MechToken is element 2
#define  SPNEGO_NEGINIT_MECHLISTMIC 0x3   // MechListMIC is element 3

// MechTypes element is 0xa0
#define  SPNEGO_NEGINIT_ELEMENT_MECHTYPES    ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                                SPNEGO_NEGINIT_MECHTYPES )

// ReqFlags element is 0xa1
#define  SPNEGO_NEGINIT_ELEMENT_REQFLAGS     ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                                SPNEGO_NEGINIT_REQFLAGS )

// MechToken element is 0xa2
#define  SPNEGO_NEGINIT_ELEMENT_MECHTOKEN    ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                                SPNEGO_NEGINIT_MECHTOKEN )

// MechListMIC element is 0xa3
#define  SPNEGO_NEGINIT_ELEMENT_MECHLISTMIC  ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                                SPNEGO_NEGINIT_MECHLISTMIC )

//
// NegTokenTarg - Token Identifier and Elements
//

// NegTokenTarg - 0xa1
#define  SPNEGO_NEGTARG_TOKEN_IDENTIFIER  ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                             SPNEGO_TOKEN_TARG )

// Structure elements for NegTokenTarg
#define  SPNEGO_NEGTARG_NEGRESULT         0x0   // NegResult is element 0
#define  SPNEGO_NEGTARG_SUPPORTEDMECH     0x1   // SupportedMech is element 1
#define  SPNEGO_NEGTARG_RESPONSETOKEN     0x2   // ResponseToken is element 2
#define  SPNEGO_NEGTARG_MECHLISTMIC       0x3   // MechListMIC is element 3

// NegResult element is 0xa0
#define  SPNEGO_NEGTARG_ELEMENT_NEGRESULT          ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                                      SPNEGO_NEGTARG_NEGRESULT )

// SupportedMech element is 0xa1
#define  SPNEGO_NEGTARG_ELEMENT_SUPPORTEDMECH      ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                                      SPNEGO_NEGTARG_SUPPORTEDMECH )

// ResponseToken element is 0xa2
#define  SPNEGO_NEGTARG_ELEMENT_RESPONSETOKEN      ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                                      SPNEGO_NEGTARG_RESPONSETOKEN )

// MechListMIC element is 0xa3
#define  SPNEGO_NEGTARG_ELEMENT_MECHLISTMIC        ( IDENTIFIER_CONTEXT_SPECIFIC | CONSTRUCTED |  \
                                                      SPNEGO_NEGTARG_MECHLISTMIC )


// Defines a GSS Mechanism OID.  We keep a single static array
// of these which we'll use for validation/searches/parsing.
typedef struct dsd_mech_oid {
   unsigned char*    auc_oid;            // Byte representation of OID
   int               in_len;             // Length of the OID, length and identifier
   int               in_actual_data_len; // Length of the actual OID
   SPNEGO_MECH_OID   ds_mech_oid;        // Which OID is this?
} MECH_OID;



class ds_parse_der_krb5 {
public:
    ds_parse_der_krb5();
    ~ds_parse_der_krb5(void);

    MECH_OID m_get_from_mech_oid_list(SPNEGO_MECH_OID dsl_mech_oid);

    long m_asn_der_calc_token_length     (long lo_length, long lo_data_length);
    long m_asn_der_calc_element_length   (long lo_data_length, long* alo_internal_len);
    int  m_asn_der_check_token           (unsigned char* auc_token_data, unsigned char uc_token,
                                          long nCheckLength, long lo_boundary_length, long* alo_len, long* alo_len_token);
    int  m_asn_der_check_oid             (unsigned char* auc_token_data, SPNEGO_MECH_OID dsl_mech_oid, long lo_boundary_length, long* alo_len_token);
    long m_asn_der_calc_mech_list_length (SPNEGO_MECH_OID dsl_enum_mechoid, long* alo_internal_len);
    int  m_asn_der_write_token           (unsigned char* auc_data, unsigned char uc_type, unsigned char* auc_token_value, long lo_length);
    int  m_asn_der_write_oid             (unsigned char* auc_data, SPNEGO_MECH_OID dsl_enum_mech_oid);
    long m_asn_der_write_mech_list       (unsigned char* auc_data, SPNEGO_MECH_OID dsl_enum_mechoid);
    int  m_asn_der_write_element         (unsigned char* auc_data, unsigned char uc_element_sequence,
                                          unsigned char uc_type, unsigned char* auc_token_value, long lo_length);

private:
    int m_asn_der_calc_num_length_bytes  (long lo_length);
    int m_asn_der_get_length             (unsigned char* auc_len_data, long lo_boundary_length, long* alo_len, long* alo_num_len_bytes);
    int m_asn_der_write_length           (unsigned char* auc_data, long lo_length);

    // Create an array of MECH_OID.
    void m_fill_mech_oid_list();
    MECH_OID dsg_mech_oid_array[4];
};

#endif // __DERPARSE_HPP_KRB__


//#define USE_WSP_HELPER // Set this flag, when e.g. alloc shall be replaced by retreaving memory from WSP.


// Indicates if we copy data when creating a SPNEGO_TOKEN structure or not
#define SPNEGO_TOKEN_INTERNAL_COPYPTR           0
#define SPNEGO_TOKEN_INTERNAL_COPYDATA          0x1

// Internal flag dictates whether or not we will free the binary data when
// the SPNEG_TOKEN structure is destroyed
#define  SPNEGO_TOKEN_INTERNAL_FLAGS_FREEDATA   0x1


// Each SPNEGO Token Type can be broken down into a
// maximum of 4 separate elements.
#define  MAX_NUM_TOKEN_ELEMENTS  4

//
// Element offsets in the array
//

// INIT elements
#define  SPNEGO_INIT_MECHTYPES_ELEMENT    0
#define  SPNEGO_INIT_REQFLAGS_ELEMENT     1
#define  SPNEGO_INIT_MECHTOKEN_ELEMENT    2
#define  SPNEGO_INIT_MECHLISTMIC_ELEMENT  3

// Response elements
#define  SPNEGO_TARG_NEGRESULT_ELEMENT    0
#define  SPNEGO_TARG_SUPPMECH_ELEMENT     1
#define  SPNEGO_TARG_RESPTOKEN_ELEMENT    2
#define  SPNEGO_TARG_MECHLISTMIC_ELEMENT  3


// Defines an individual SPNEGO Token Element.
typedef struct dsd_spnego_element {
   size_t                ui_struct_size;        // Size of the element structure
   int                   in_element_present;    // Is the field present?  Must be either
                                             // SPNEGO_TOKEN_ELEMENT_UNAVAILABLE or
                                             // SPNEGO_TOKEN_ELEMENT_AVAILABLE
   SPNEGO_ELEMENT_TYPE   ds_element_type;       // The Element Type
   unsigned char         uc_type;               // Data Type
   unsigned char*        auc_data;              // Points to actual Data
   unsigned long         ul_data_length;        // Actual Data Length
} SPNEGO_ELEMENT;

// Structure size in case we later choose to extend the structure
#define  SPNEGO_ELEMENT_SIZE sizeof(SPNEGO_ELEMENT)


// Packages a SPNEGO Token Encoding.  There are two types of
// encodings: NegTokenInit and NegTokenTarg.  Each encoding can
// contain up to four distinct, optional elements.
typedef struct dsd_spnego_token {
   size_t            ui_struct_size;                           // Size of the Token structure
   unsigned long     ul_flags;                                 // Internal Structure Flags - Reserved!
   int               in_token_type;                            // Token Type - Must be
                                                               // SPNEGO_TOKEN_INIT or
                                                               // SPNEGO_TOKEN_TARG
   unsigned char*    auc_binary_data;                          // Points to binary token data
   unsigned long     ul_binary_data_len;                       // Length of the actual binary data
   int               in_num_elements;                          // Number of elements
   SPNEGO_ELEMENT    dsr_element_array[MAX_NUM_TOKEN_ELEMENTS];// Holds the elements for the token
} SPNEGO_TOKEN;

// Structure size in case we later choose to extend the structure
#define  SPNEGO_TOKEN_SIZE sizeof(SPNEGO_TOKEN)


class ds_spnego_krb {
public:
    ds_spnego_krb();
    ~ds_spnego_krb(void);


    int m_is_valid_mech_oid       (SPNEGO_MECH_OID dsl_mech_oid);
    int m_is_valid_context_flags  (unsigned char uc_context_flags);
    int m_is_valid_neg_result     (SPNEGO_NEGRESULT dsl_neg_result);
    int m_is_valid_spnego_token   (SPNEGO_TOKEN* ads_spnego_token);
    int m_is_valid_spnego_element (SPNEGO_TOKEN* ads_spnego_token,SPNEGO_ELEMENT_TYPE dsl_spnego_element);
    int m_init_token_from_binary  (unsigned char uc_copy_data, unsigned long ul_flags,
                                   unsigned char* auc_token_data, unsigned long ul_length,
                                   SPNEGO_TOKEN** aadsl_spnego_token);

    int m_find_mech_oid_in_mech_list      (SPNEGO_ELEMENT* ads_spnego_element, SPNEGO_MECH_OID MechOID,
                                           int* ain_mech_type_index);
    int m_calc_min_spnego_init_token_size (long lo_mech_token_length, long lo_mech_list_mic_length,
                                           SPNEGO_MECH_OID dsl_mech_oid, int in_req_flags_available,
                                           long* plTokenSize, long* plInternalLength);
    int m_calc_min_spnego_targ_token_size (SPNEGO_MECH_OID dsl_mech_type, SPNEGO_NEGRESULT dsl_spnego_neg_result,
                                           long lo_mech_token_len, long nMechTokenMIC,
                                           long* alo_token_size, long* alo_internal_token_length);
    int m_create_spnego_init_token        (SPNEGO_MECH_OID dsl_mech_type, unsigned char uc_context_flags,
                                           unsigned char* auc_mech_token, unsigned long ul_mech_token_len,
                                           unsigned char* auc_mech_list_mic, unsigned long ulMechListMICLen,
                                           unsigned char* auc_token_data, long lo_token_length, long lo_internal_token_length );
    int m_create_spnego_targ_token        (SPNEGO_MECH_OID dsl_mech_type, SPNEGO_NEGRESULT dsl_spnego_neg_result,
                                           unsigned char* auc_mech_token, unsigned long ul_mech_token_len,
                                           unsigned char* auc_mech_list_mic, unsigned long ul_mech_list_mic_len,
                                           unsigned char* auc_token_data, long lo_token_length, long lo_internal_token_length);

    void m_free_spnego_token              (SPNEGO_TOKEN* ads_spnego_token);

// Initializes SPNEGO_TOKEN structure from DER encoded binary data
int m_spnego_init_from_binary( unsigned char* auc_token_data, unsigned long ul_length, SPNEGO_TOKEN_HANDLE* adsl_spnego_token_handle );

// Initializes SPNEGO_TOKEN structure for a NegTokenInit type using the supplied parameters
int m_spnego_create_neg_token_init( SPNEGO_MECH_OID dsl_mech_type,
          unsigned char uc_context_flags, unsigned char* auc_mech_token,
          unsigned long ul_mech_token_len, unsigned char* pbMechTokenMIC,
          unsigned long ulMechTokenMIC, char* adsl_spnego_token_handle, int& inp_token_len);

// Initializes SPNEGO_TOKEN structure for a NegTokenTarg type using the supplied parameters
int m_spnego_create_neg_token_targ( SPNEGO_MECH_OID dsl_mech_type,
          SPNEGO_NEGRESULT dsl_spnego_neg_result, unsigned char* auc_mech_token,
          unsigned long ul_mech_token_len, unsigned char* auc_mech_list_mic,
          unsigned long ul_mech_list_mic_len, SPNEGO_TOKEN_HANDLE* adsl_spnego_token_handle);


/* Reading an Init Token */

// Returns the Initial Mech Type in the MechList element in the NegInitToken.
int m_spnego_is_mech_type_available(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, SPNEGO_MECH_OID MechOID, int * piMechTypeIndex);

// Returns the value from the context flags element in the NegInitToken as an unsigned long
int m_spnego_get_context_flags(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_context_flags);

/* Reading a Response Token */

// Returns the value from the negResult element (Status code of GSS call - 0,1,2)
int m_spnego_get_negotiation_result(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, SPNEGO_NEGRESULT* adsl_neg_result);

// Returns the Supported Mech Type from the NegTokenTarg.
int m_spnego_get_supported_mech_type(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, SPNEGO_MECH_OID* adsl_mech_oid  );


/* Reading either Token Type */

// Returns the actual Mechanism data from the token (this is what is passed into GSS-API functions
int m_spnego_get_mech_token(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_token_data, unsigned long* aul_data_len);

// Returns the Message Integrity BLOB in the token
int m_spnego_get_mech_list_mic(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_mic_data, unsigned long* aul_data_len);

// Frees opaque data
void m_spnego_free_data(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle);

private:
    ds_parse_der_krb5 dsg_parse_der;

    int m_calc_element_array_index                  (SPNEGO_TOKEN* ads_spnego_token,SPNEGO_ELEMENT_TYPE dsl_spnego_element);
    int m_init_spnego_token_type                    (SPNEGO_TOKEN* ads_spnego_token, long* alo_len_token,
                                                     long* alo_remaining_token_length, unsigned char** aauc_first_element);
    int m_init_spnego_token_elements                (SPNEGO_TOKEN* ads_spnego_token, unsigned char* auc_token_data,
                                                     long lo_remaining_token_len);
    int m_get_spnego_init_token_mech_list           (unsigned char* auc_token_data, int in_mech_list_length,
                                                     SPNEGO_ELEMENT* ads_spnego_element);
    int m_init_spnego_token_element_from_basic_type (unsigned char* auc_token_data, int in_element_length,
                                                     unsigned char uc_expected_type,
                                                     SPNEGO_ELEMENT_TYPE dsl_spnego_element_type,
                                                     SPNEGO_ELEMENT* ads_spnego_element);
    int m_init_spnego_token_element_from_oid        (unsigned char* auc_token_data, int in_element_length,
                                                     SPNEGO_ELEMENT_TYPE dsl_spnego_element_type,
                                                     SPNEGO_ELEMENT* ads_spnego_element);
    int m_validate_mech_list                        (unsigned char* auc_mech_list_data, long lo_boundary_length);

    SPNEGO_TOKEN* m_alloc_empty_spnego_token        (unsigned char uc_copy_data, unsigned long ul_flags,
                                                     unsigned char* auc_token_data, unsigned long ul_token_size);

    void m_init_spnego_token_element_array          (SPNEGO_TOKEN* ads_spnego_token);

/* Miscelaneous API Functions */

// Copies binary representation of SPNEGO Data into user supplied buffer
int m_spnego_token_get_binary(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_token_data,
                              unsigned long * aul_data_len);

// Returns SPNEGO Token Type
int m_spnego_get_token_type(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, int * piTokenType);

};

#endif

ds_parse_der_krb5::ds_parse_der_krb5()
{
    m_fill_mech_oid_list();
}

ds_parse_der_krb5::~ds_parse_der_krb5(void)
{
}


/**
 * Fill the global array, which holds MECH_OIDs for legacy-Kerberos, real Kerberos, SPNEGO and an empty structure.
 *
 * Attention: legacy-Kerberos is needed, because there was a bug in former Windows versions:
 * http://msdn.microsoft.com/en-us/library/cc247079(PROT.10).aspx
 * "Windows 2000 incorrectly encoded the OID for the Kerberos protocol in the supportedMech field. Rather than the
 * OID { iso(1) member-body(2) United States(840) mit(113554) infosys(1) gssapi(2) krb5(2) }, an implementation error truncated
 * the values at 16 bits. Therefore, the OID became { iso(1) member-body(2) United States(840) ???(48018) infosys(1) gssapi(2) krb5 (2) }.
 *
 * @author: Joachim Frank
*/
void ds_parse_der_krb5::m_fill_mech_oid_list() {
    //  1.2.840.48018.1.2.2
    dsg_mech_oid_array[0].auc_oid            = (unsigned char*) "\x06\x09\x2a\x86\x48\x82\xf7\x12\x01\x02\x02";
    dsg_mech_oid_array[0].in_len             = 11;
    dsg_mech_oid_array[0].in_actual_data_len = 9;
    dsg_mech_oid_array[0].ds_mech_oid        = ien_spnego_mech_oid_kerberos_v5_legacy;

    //  1.2.840.113554.1.2.2 Kerberos
    dsg_mech_oid_array[1].auc_oid            = (unsigned char*) "\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
    dsg_mech_oid_array[1].in_len             = 11;
    dsg_mech_oid_array[1].in_actual_data_len = 9;
    dsg_mech_oid_array[1].ds_mech_oid        = ien_spnego_mech_oid_kerberos_v5;

    //  1.3.6.1.1.5.5.2
    dsg_mech_oid_array[2].auc_oid            = (unsigned char*) "\x06\x06\x2b\x06\x01\x05\x05\x02";
    dsg_mech_oid_array[2].in_len             = 8;
    dsg_mech_oid_array[2].in_actual_data_len = 6;
    dsg_mech_oid_array[2].ds_mech_oid        = ien_spnego_mech_oid_spnego;

    //  Placeholder
    dsg_mech_oid_array[3].auc_oid            = (unsigned char*) "";
    dsg_mech_oid_array[3].in_len             = 0;
    dsg_mech_oid_array[3].in_actual_data_len = 0;
    dsg_mech_oid_array[3].ds_mech_oid        = ien_spnego_mech_oid_not_used;
}


/**
 * Retrieve a structure MECH_OID from the global array.
 *
 * @param[in] dsl_mech_oid true: The index inside the array.
 * @return MECH_OID. In case of invalid dsl_mech_oid , the default () will be returned.
 * @author: Joachim Frank
*/
MECH_OID ds_parse_der_krb5::m_get_from_mech_oid_list(SPNEGO_MECH_OID dsl_mech_oid) {
    if ( (dsl_mech_oid < SPNEGO_MECH_OID_MIN) || (dsl_mech_oid > SPNEGO_MECH_OID_MAX) ) {
        dsl_mech_oid = ien_spnego_mech_oid_not_used;
    }
    return dsg_mech_oid_array[dsl_mech_oid];
}


/**
 * Interprets the data at auc_len_data as a DER length. The length must fit within the bounds
 * of lo_boundary_length. We do not process lengths that take more than 4 bytes.
 *
 * @param[in] auc_len_data Pointer to DER-Length-Data, which shall be written.
 * @param[in] lo_boundary_length Length that value must not exceed.
 * @param[out] alo_len Filled out with length value.
 * @param[out] alo_num_len_bytes Filled out with number of bytes consumed by DER length.
 * @return SUCCESS (=0) if successful. In case of error an explicit error number is returned.
*/
int ds_parse_der_krb5::m_asn_der_get_length(unsigned char* auc_len_data, long lo_boundary_length,
                                       long* alo_len, long* alo_num_len_bytes ) {
    if (!(*auc_len_data & LEN_XTND)) {
        //----------------------------
        // Extended length bit is NOT set. Length info is in one byte.
        //----------------------------
        *alo_len = *auc_len_data & LEN_MASK;
        *alo_num_len_bytes = 1;
        return SUCCESS;
    }


    //----------------------------
    // Extended length bit is set
    //----------------------------

    // Lower 7 bits contain the number of trailing bytes that describe the length.
    int inl_num_len_bytes = *auc_len_data & LEN_MASK;

    // Check that the number of bytes we are about to read is within our boundary constraints.
    if (inl_num_len_bytes > lo_boundary_length - 1) {
        return SPNEGO_E_INVALID_LENGTH;
    }

    // We don't deal with lengths greater than 4 bytes.
    if ( (inl_num_len_bytes < 1) || (inl_num_len_bytes > 4) ) {
        return -100;
    }

    // Initial length
    *alo_len = 0L;

    // Read next byte.
    auc_len_data++;


    // Detect Enderness and process according to it.
    char chr_us[2];
    *((unsigned short *)&chr_us[0])=0x0001;
    if (chr_us[0] == 1) {
        // Little Endian

        // There may be a cleaner way to do this, but for now...
        switch (inl_num_len_bytes) {
        case 1: {
            *(((unsigned char*)alo_len)    ) = *auc_len_data;
            break;
        }
        case 2:  {
            *(((unsigned char*)alo_len)    ) = *(auc_len_data + 1);
            *(((unsigned char*)alo_len) + 1) = *(auc_len_data    );
            break;
        }
        case 3: {
            // JF: original seems to be wrong!
            // *(((unsigned char*)alo_len)    ) = *(auc_len_data + 2);
            // *(((unsigned char*)alo_len) + 2) = *(auc_len_data + 1);
            // *(((unsigned char*)alo_len) + 3) = *(auc_len_data    );
            *(((unsigned char*)alo_len)    ) = *(auc_len_data + 2);
            *(((unsigned char*)alo_len) + 1) = *(auc_len_data + 1);
            *(((unsigned char*)alo_len) + 2) = *(auc_len_data    );
            break;
        }
        case 4: {
            *(((unsigned char*)alo_len)    ) = *(auc_len_data + 3);
            *(((unsigned char*)alo_len) + 1) = *(auc_len_data + 2);
            *(((unsigned char*)alo_len) + 2) = *(auc_len_data + 1);
            *(((unsigned char*)alo_len) + 3) = *(auc_len_data    );
            break;
        }
        default: { // JF: error handling
            return -101;
        }
        }  // switch (inl_num_len_bytes)
    }
    else if (chr_us[0] == 0) {
        // We are Big-Endian, so the length can be copied in from the source as is. Ensure
        // that we adjust for the number of bytes we actually copy.
        memcpy( ( (unsigned char *) alo_len ) + ( 4 - inl_num_len_bytes ),
             auc_len_data, inl_num_len_bytes );
    }
    else { // Unknown endianess.
        return -200;
    }

    // Account for the initial length byte.
    *alo_num_len_bytes = inl_num_len_bytes + 1;
    return SUCCESS;
}



/**
 * Checks the data pointed to by auc_token_data for the specified token identifier and the length
 * that immediately follows. If lo_len_with_token is > 0, the calculated length must match. The length
 * must also not exceed the specified boundary length.
 *
 * @param[in] auc_token_data Pointer to a token.
 * @param[in] uc_token Token identifier, which shall be checked.
 * @param[in] lo_len_with_token Expected token length (with data)
 * @param[in] lo_boundary_length Length that value must not exceed.
 * @param[out] alo_len Filled out with data length.
 * @param[out] alo_len_token Filled out with number of bytes consumed by token identifier and length.
 * @return SUCCESS (=0) if successful. In case of error an explicit error number is returned.
*/
int ds_parse_der_krb5::m_asn_der_check_token( unsigned char* auc_token_data, unsigned char uc_token,
                        long lo_len_with_token, long lo_boundary_length,
                        long* alo_len, long* alo_len_token ) {
    // Make sure that we've at least got 2 bytes of room to work with.
    if (lo_boundary_length < 2) {
        return SPNEGO_E_INVALID_LENGTH;
    }

    // The first byte of the token data MUST match the specified token.
    if ( *auc_token_data != uc_token ) {
        return SPNEGO_E_TOKEN_NOT_FOUND;
    }

    long lo_num_length_bytes = 0L;

    // Next byte indicates the length
    auc_token_data++;

    // Get the length described by the token
    int inl_ret = m_asn_der_get_length(auc_token_data, lo_boundary_length, alo_len, &lo_num_length_bytes);
    if (inl_ret != SUCCESS ) {
        return -200;
    }

    // Verify that the length is LESS THAN the boundary length (this should prevent us walking out of our buffer).
    if ( (lo_boundary_length - (lo_num_length_bytes + 1) < *alo_len )) {
        return (SPNEGO_E_INVALID_LENGTH - 100);
    }

    // If we were passed a length to check, do so now.
    if (lo_len_with_token > 0L) {
        // Check that the expected length matches
        if ( (lo_len_with_token - (lo_num_length_bytes + 1)) != *alo_len) {
            return (SPNEGO_E_INVALID_LENGTH - 300);
        }
    }

    *alo_len_token = lo_num_length_bytes + 1;
    return SUCCESS;
}



/**
 * Checks the data pointed to by auc_token_data for the specified OID.
 *
 * @param[in] auc_token_data Pointer to a token.
 * @param[in] dsl_mech_oid OID we are looking for.
 * @param[in] lo_boundary_length Length that value must not exceed.
 * @param[out] alo_len_token Filled out with number of bytes consumed by token and data.
 * @return SUCCESS (=0) if successful. In case of error an explicit error number is returned.
*/
int ds_parse_der_krb5::m_asn_der_check_oid( unsigned char* auc_token_data, SPNEGO_MECH_OID dsl_mech_oid,
                                      long lo_boundary_length, long* alo_len_token ) {
    long  lo_length = 0L;
    int inl_ret = m_asn_der_check_token(auc_token_data, OID, 0L, lo_boundary_length,
                                        &lo_length, alo_len_token);

    // Verify that we have an OID token
    if (inl_ret != SUCCESS) {
        return 1;
    }

    // Add the data length to the Token Length
    *alo_len_token += lo_length;

    // Token Lengths plus the actual length must match the length in our OID list element.
    // If it doesn't, we're done
    if (*alo_len_token != m_get_from_mech_oid_list(dsl_mech_oid).in_len) {
        return SPNEGO_E_UNEXPECTED_OID;
    }

    // Compare the token and the expected field.
    if (memcmp(auc_token_data, m_get_from_mech_oid_list(dsl_mech_oid).auc_oid, *alo_len_token) != 0) {
        return (SPNEGO_E_UNEXPECTED_OID - 100);
    }

    return SUCCESS;
}



/**
 * Calculate the number of length bytes necessary to represent a length value.
 * For our purposes, a 32-bit value should be enough to describe the length.
 *
 * @param[in] lo_length Length, for which the number of bytes, which are required for representation, shall be calculated.
 * @return Number of bytes necessary to represent the length.
*/
int ds_parse_der_krb5::m_asn_der_calc_num_length_bytes(long lo_length) {
    if (lo_length <= 0x7F) {
        // A single byte will be sufficient for describing this length.
        // The byte will simply contain the length.
        return 1;
    }
    else if (lo_length <= 0xFF) {
        // Two bytes are necessary, one to say how many following bytes
        // describe the length, and one to give the length.
        return 2;
    }
    else if (lo_length <= 0xFFFF) {
        // Three bytes are necessary, one to say how many following bytes
        // describe the length, and two to give the length.
        return 3;
    }
    else if (lo_length <= 0xFFFFFF) {
        // Four bytes are necessary, one to say how many following bytes
        // describe the length, and three to give the length.
        return 4;
    }

    // Five bytes are necessary, one to say how many following bytes
    // describe the length, and four to give the length
    return 5;
}



/**
 * Calculate a token and value size, based on a supplied length value, and any binary
 * data that will need to be written out.
 *
 * @param[in] lo_length Length to calculate length bytes for.
 * @param[in] lo_data_length Actual data length value.
 * @return Number of bytes necessary to represent a token, length and data.
*/
long ds_parse_der_krb5::m_asn_der_calc_token_length(long lo_length, long lo_data_length) {
   // Add a byte to the length size to account for a single byte to
   // hold the token type.
   long  lo_total_length = m_asn_der_calc_num_length_bytes(lo_length) + 1;

   return lo_total_length + lo_data_length;
}



/**
 * Calculate an element length.  An element consists of a sequence token, a type token and then the data.
 *
 * @param[in] lo_length Length to calculate length bytes for.
 * @param[out] alo_internal_len Filled out with length of element without sequence info.
 * @return Number of bytes necessary to represent an element.
*/
long ds_parse_der_krb5::m_asn_der_calc_element_length(long lo_data_length, long* alo_internal_len) {
   // First the type token and the actual data
   long  lo_total_len = m_asn_der_calc_token_length( lo_data_length, lo_data_length );

   // Internal length is the length without the element sequence token.
   if (alo_internal_len != NULL) {
      *alo_internal_len = lo_total_len;
   }

   // Next add in the element's sequence token (remember that its
   // length is the total length of the type token and data)
   lo_total_len += m_asn_der_calc_token_length(lo_total_len, 0L);

   return lo_total_len;
}



/**
 * Calculate a MechList length. A mechlist consists of a NegTokenInit sequence token,
 * a sequence token for the MechList and finally a list of OIDs. In our case, we only really have one OID.
 *
 * @param[in] dsl_enum_mechoid Mech OID to put in list.
 * @param[out] alo_internal_len Filled out with length of element without the primary sequence token.
 * @return Number of bytes necessary to represent an mechList.
*/
long ds_parse_der_krb5::m_asn_der_calc_mech_list_length(SPNEGO_MECH_OID dsl_enum_mechoid, long* alo_internal_len) {
   // First the OID
   long  lo_total_len = m_get_from_mech_oid_list(dsl_enum_mechoid).in_len;

   // Next add in a sequence token
   lo_total_len += m_asn_der_calc_token_length(lo_total_len, 0L);

   // Internal length is the length without the element sequence token
   if (alo_internal_len != NULL) {
      *alo_internal_len = lo_total_len;
   }

   // Finally add in the element's sequence token
   lo_total_len += m_asn_der_calc_token_length(lo_total_len, 0L);

   return lo_total_len;
}



/**
 * Write out a length value following DER rules.
 *
 * @param[out] auc_data Buffer to write into.
 * @param[in] lo_lengthLength to write out.
 * @return Number of bytes written out. Negative means error.
*/
int ds_parse_der_krb5::m_asn_der_write_length(unsigned char* auc_data, long lo_length) {
    int in_num_bytes_required = m_asn_der_calc_num_length_bytes(lo_length);
    int in_num_length_bytes = in_num_bytes_required - 1;

    if ( in_num_bytes_required > 1 ) {
        // Write out the number of bytes following which will be used
        *auc_data = (unsigned char ) ( LEN_XTND | in_num_length_bytes );

        // Point to where we'll actually write the length
        auc_data++;

        // Detect Enderness and process according to it.
        char chr_us[2];
        *((unsigned short *)&chr_us[0])=0x0001;
        if (chr_us[0] == 1) {
            // Little Endian
            // There may be a cleaner way to do this, but for now, this seems to be
            // an easy way to do the transformation
            switch (in_num_length_bytes) {
            case 1: {
                // Cast the length to a single byte, since we know that it is 0x7F or less.
                *auc_data = (unsigned char) lo_length;
                break;
            }
            case 2: {
                * auc_data      = *(((unsigned char*)&lo_length) + 1);
                *(auc_data + 1) = *(((unsigned char*)&lo_length)    );
                break;
            }
            case 3: {
                // JF: original seems to be wrong!
                //* auc_data      = *(((unsigned char*)&lo_length) + 3);
                //*(auc_data + 1) = *(((unsigned char*)&lo_length) + 2);
                //*(auc_data + 2) = *(((unsigned char*)&lo_length)    );
                * auc_data      = *(((unsigned char*)&lo_length) + 2);
                *(auc_data + 1) = *(((unsigned char*)&lo_length) + 1);
                *(auc_data + 2) = *(((unsigned char*)&lo_length)    );
                break;
             }
             case 4: {
                * auc_data      = *(((unsigned char*)&lo_length) + 3);
                *(auc_data + 1) = *(((unsigned char*)&lo_length) + 2);
                *(auc_data + 2) = *(((unsigned char*)&lo_length) + 1);
                *(auc_data + 3) = *(((unsigned char*)&lo_length)    );
                break;
             }
             default: { // JF: error handling
                 return -1;
             }
             } // SWITCH (in_num_length_bytes)
        }
        else if (chr_us[0] == 0) {
            // We are Big-Endian, so the length can be copied in from the source
            // as is.  Ensure that we adjust for the number of bytes we actually copy.
            memcpy(auc_data, ((unsigned char*) &lo_length ) + (4 - in_num_length_bytes), in_num_length_bytes);
        }
        else { // Unknown endianess.
            return -200;
        }
   }  // IF > 1 byte for length
   else {
      // Cast the length to a single byte, since we know that it
      // is 0x7F or less (or we wouldn't only need a single byte).
      *auc_data = (unsigned char)lo_length;
   }

   return in_num_bytes_required;
}



/**
 * Write out a token and any associated data. If auc_token_value is non-NULL, then it
 * is written out in addition to the token identifier and the length bytes.
 *
 * @param[out] auc_data Buffer to write into.
 * @param[in] uc_type Token Type.
 * @param[in] auc_token_value Actual Value.
 * @param[in] lo_length Length of data.
 * @return Number of bytes written out. Negative means error.
*/
int ds_parse_der_krb5::m_asn_der_write_token(unsigned char* auc_data, unsigned char uc_type,
                     unsigned char* auc_token_value, long lo_length) {
   int in_total_bytes_written_out = 0L;
   int in_num_length_bytes_written = 0L;

   // Write out the type
   *auc_data = uc_type;

   // Wrote 1 byte, and move data pointer
   in_total_bytes_written_out++;
   auc_data++;

   // Now write out the length and adjust the number of bytes written out
   in_num_length_bytes_written = m_asn_der_write_length( auc_data, lo_length );
   if (in_num_length_bytes_written < 0) { // JF: error handling
       return in_num_length_bytes_written;
   }

   in_total_bytes_written_out += in_num_length_bytes_written;
   auc_data += in_num_length_bytes_written;

   // Write out the token value if we got one.  The assumption is that the
   // lo_length value indicates how many bytes are in auc_token_value.
   if (auc_token_value != NULL) {
      memcpy(auc_data, auc_token_value, lo_length);
      in_total_bytes_written_out += lo_length;
   }

   return in_total_bytes_written_out;
}



/**
 * Write out an OID. For these we have the raw bytes listed in a global structure.
 * The caller simply indicates which OID should be written and we will splat out the data.
 *
 * @param[out] auc_data Buffer to write into.
 * @param[in] dsl_enum_mech_oid OID to write out.
 * @return Number of bytes written out.
*/
int ds_parse_der_krb5::m_asn_der_write_oid(unsigned char* auc_data, SPNEGO_MECH_OID dsl_enum_mech_oid) {

   memcpy(auc_data, m_get_from_mech_oid_list(dsl_enum_mech_oid).auc_oid, m_get_from_mech_oid_list(dsl_enum_mech_oid).in_len);

   return m_get_from_mech_oid_list(dsl_enum_mech_oid).in_len;
}



/**
 * Write out a MechList. A MechList consists of the Init Token Sequence, a sequence token and then the list
 * of OIDs. In our case the OID is from a global array of known OIDs.
 *
 * @param[out] auc_data Buffer to write into.
 * @param[in] dsl_enum_mech_oid OID to put in MechList.
 * @return Number of bytes written out.
*/
long ds_parse_der_krb5::m_asn_der_write_mech_list(unsigned char* auc_data, SPNEGO_MECH_OID dsl_enum_mechoid) {
   // First get the length
   long lo_internal_length = 0L;
   long lo_mech_list_length = m_asn_der_calc_mech_list_length( dsl_enum_mechoid, &lo_internal_length );
   long lo_temp_length = m_asn_der_write_token( auc_data, SPNEGO_NEGINIT_ELEMENT_MECHTYPES,
                                    NULL, lo_internal_length );

   // Adjust the data pointer
   auc_data += lo_temp_length;

   // Now write the Sequence token and the OID (the OID is a BLOB in the global structure.
   lo_temp_length = m_asn_der_write_token(auc_data, SPNEGO_CONSTRUCTED_SEQUENCE,
                                    m_get_from_mech_oid_list(dsl_enum_mechoid).auc_oid,
                                    m_get_from_mech_oid_list(dsl_enum_mechoid).in_len);

   return lo_mech_list_length;
}



/**
 * Write out a SPNEGO Token element. An element consists of a sequence token, a type
 * token and the associated data.
 *
 * @param[out] auc_data Buffer to write into.
 * @param[in] uc_element_sequence Sequence token.
 * @param[in] uc_type Token type.
 * @param[in] auc_token_value Actual Value.
 * @param[in] lo_length Length of data.
 * @return Number of bytes written out.
*/
int ds_parse_der_krb5::m_asn_der_write_element(unsigned char* auc_data, unsigned char uc_element_sequence,
                        unsigned char uc_type, unsigned char* auc_token_value, long lo_length) {
   // First get the length
   long lo_internal_length = 0L;
   long lo_element_length = m_asn_der_calc_element_length(lo_length, &lo_internal_length);

   // Write out the sequence byte and the length of the type and data
   long lo_temp_length = m_asn_der_write_token( auc_data, uc_element_sequence, NULL, lo_internal_length );

   // Adjust the data pointer
   auc_data += lo_temp_length;

   // Now write the type and the data.
   lo_temp_length = m_asn_der_write_token( auc_data, uc_type, auc_token_value, lo_length );

   return lo_element_length;
}


ds_spnego_krb::ds_spnego_krb()
{
}

ds_spnego_krb::~ds_spnego_krb(void)
{
}


/**
 * Calculate the required length for a SPNEGO NegTokenInit token based on the supplied variable
 * length values and which elements are present.
 * Note that because the lengths can be represented by an arbitrary number of bytes in DER
 * encodings, we actually calculate the lengths backwards, so we always know how many bytes
 * we will potentially be writing out.
 *
 * @param[in] lo_mech_token_length Length of the MechToken element.
 * @param[in] lo_mech_list_mic_length Length of the MechListMIC element.
 * @param[in] dsl_mech_oid OID for MechList.
 * @param[in] in_req_flags_available Is ContextFlags element available.
 * @param[out] alo_token_size Filled out with total size of token.
 * @param[out] alo_internal_token_length Filled out with length minus length for initial token.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_calc_min_spnego_init_token_size( long lo_mech_token_length, long lo_mech_list_mic_length,
                                                 SPNEGO_MECH_OID dsl_mech_oid, int in_req_flags_available,
                                                 long* alo_token_size, long* alo_internal_token_length ) {
   long lo_total_length = 0;
   long lo_temp_length= 0L;

   // We will calculate this by walking the token backwards

   // Start with MIC Element
   if (lo_mech_list_mic_length > 0L) {
      lo_temp_length = dsg_parse_der.m_asn_der_calc_element_length(lo_mech_list_mic_length, NULL);

      // Check for rollover error
      if (lo_temp_length < lo_mech_list_mic_length) {
         return SPNEGO_E_INVALID_LENGTH;
      }

      lo_total_length += lo_temp_length;
   }

   // Next is the MechToken
   if (lo_mech_token_length > 0L) {
      lo_temp_length += dsg_parse_der.m_asn_der_calc_element_length(lo_mech_token_length, NULL);

      // Check for rollover error
      if (lo_temp_length < lo_total_length) {
         return (SPNEGO_E_INVALID_LENGTH - 100);
      }

      lo_total_length = lo_temp_length;
   }

   // Next is the ReqFlags
   if (in_req_flags_available) {
      lo_temp_length += dsg_parse_der.m_asn_der_calc_element_length(SPNEGO_NEGINIT_MAXLEN_REQFLAGS, NULL);

      // Check for rollover error
      if (lo_temp_length < lo_total_length) {
         return (SPNEGO_E_INVALID_LENGTH - 200);
      }

      lo_total_length = lo_temp_length;
   }

   // Next is the MechList - This is REQUIRED
   lo_temp_length += dsg_parse_der.m_asn_der_calc_mech_list_length(dsl_mech_oid, NULL);

   // Check for rollover error
   if (lo_temp_length < lo_total_length) {
      return (SPNEGO_E_INVALID_LENGTH - 300);
   }

   lo_total_length = lo_temp_length;

   // Following four fields are the basic header tokens

   // Sequence Token
   lo_temp_length += dsg_parse_der.m_asn_der_calc_token_length(lo_total_length, 0L);

   // Check for rollover error
   if (lo_temp_length < lo_total_length) {
      return (SPNEGO_E_INVALID_LENGTH - 400);
   }

   lo_total_length = lo_temp_length;

   // Neg Token Identifier Token
   lo_temp_length += dsg_parse_der.m_asn_der_calc_token_length(lo_total_length, 0L);

   // Check for rollover error
   if (lo_temp_length < lo_total_length) {
      return (SPNEGO_E_INVALID_LENGTH - 500);
   }

   lo_total_length = lo_temp_length;

   // SPNEGO OID Token
   lo_temp_length += dsg_parse_der.m_get_from_mech_oid_list(ien_spnego_mech_oid_spnego).in_len;

   // Check for rollover error
   if (lo_temp_length < lo_total_length) {
      return (SPNEGO_E_INVALID_LENGTH - 600);
   }

   lo_total_length = lo_temp_length;

   // App Constructed Token
   lo_temp_length += dsg_parse_der.m_asn_der_calc_token_length(lo_total_length, 0L);

   // Check for rollover error
   if (lo_temp_length < lo_total_length) {
      return (SPNEGO_E_INVALID_LENGTH - 700);
   }

   // The internal length doesn't include the number of bytes for the initial token.
   *alo_internal_token_length = lo_total_length;
   lo_total_length = lo_temp_length;

   // We're done
   *alo_token_size = lo_total_length;
   return SUCCESS;
}



/**
 * Use DER to fill out auc_token_data with a SPNEGO NegTokenInit Token.
 * Note that because the lengths can be represented by an arbitrary number of bytes in
 * DER encodings, we actually calculate the lengths backwards, so we always know how many
 * bytes we will potentially be writing out.
 *
 * @param[in] dsl_mech_type OID in MechList.
 * @param[in] uc_context_flags ContextFlags value.
 * @param[in] auc_mech_token Mech Token Binary Data.
 * @param[in] ul_mech_token_len Length of Mech Token.
 * @param[in] auc_mech_list_mic MechListMIC Binary Data.
 * @param[in] ulMechListMIC Length of MechListMIC.
 * @param[out] auc_token_data Buffer to write token into.
 * @param[in] lo_token_length Length of auc_token_data buffer.
 * @param[in] alo_internal_token_length Length of full token without leading token bytes.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_create_spnego_init_token(SPNEGO_MECH_OID dsl_mech_type, unsigned char uc_context_flags,
                                          unsigned char* auc_mech_token, unsigned long ul_mech_token_len,
                                          unsigned char* auc_mech_list_mic, unsigned long ul_mech_list_mic_len,
                                          unsigned char* auc_token_data, long lo_token_length,
                                          long lo_internal_token_length) {
   long lo_temp_length= 0L;
   long lo_total_bytes_written = 0L;
   long lo_internal_length = 0L;

   unsigned char* auc_write_token_data = auc_token_data + lo_token_length;

   // We will write the token out backwards to properly handle the cases
   // where the length bytes become adjustable

   // Start with MIC Element
   if (ul_mech_list_mic_len > 0L) {
      lo_temp_length = dsg_parse_der.m_asn_der_calc_element_length( ul_mech_list_mic_len, &lo_internal_length );

      // Decrease the auc_write_token_data, now we know the length and write it out.
      auc_write_token_data -= lo_temp_length;
      lo_temp_length = dsg_parse_der.m_asn_der_write_element(auc_write_token_data, SPNEGO_NEGINIT_ELEMENT_MECHLISTMIC,
                              OCTETSTRING, auc_mech_list_mic, ul_mech_list_mic_len);

      // Adjust Values and sanity check
      lo_total_bytes_written += lo_temp_length;
      lo_internal_token_length -= lo_temp_length;

      if ( (lo_total_bytes_written > lo_token_length) || (lo_internal_token_length < 0) ) {
         return SPNEGO_E_INVALID_LENGTH;
      }
   }  // IF MechListMIC is present

   // Next is the MechToken
   if (ul_mech_token_len > 0L) {
      lo_temp_length = dsg_parse_der.m_asn_der_calc_element_length( ul_mech_token_len, &lo_internal_length );

      // Decrease the auc_write_token_data, now we know the length and write it out.
      auc_write_token_data -= lo_temp_length;
      lo_temp_length = dsg_parse_der.m_asn_der_write_element(auc_write_token_data, SPNEGO_NEGINIT_ELEMENT_MECHTOKEN,
                              OCTETSTRING, auc_mech_token, ul_mech_token_len);
      // Adjust Values and sanity check
      lo_total_bytes_written += lo_temp_length;
      lo_internal_token_length -= lo_temp_length;

      if ( (lo_total_bytes_written > lo_token_length) || (lo_internal_token_length < 0) ) {
         return (SPNEGO_E_INVALID_LENGTH - 100);
      }

   }  // IF MechToken Length is present

   // Next is the ReqFlags
   if (uc_context_flags > 0L) {
      lo_temp_length = dsg_parse_der.m_asn_der_calc_element_length(SPNEGO_NEGINIT_MAXLEN_REQFLAGS, &lo_internal_length);

      // We need a byte that indicates how many bits difference between the number
      // of bits used in final octet (we only have one) and the max (8)

      // Temporary buffer to hold the REQ Flags as BIT String Data
      unsigned char ucr_temp_req_flags[SPNEGO_NEGINIT_MAXLEN_REQFLAGS];
      ucr_temp_req_flags[0] = SPNEGO_NEGINIT_REQFLAGS_BITDIFF;
      ucr_temp_req_flags[1] = uc_context_flags;

      // Decrease the auc_write_token_data, now we know the length and write it out.
      auc_write_token_data -= lo_temp_length;
      lo_temp_length = dsg_parse_der.m_asn_der_write_element(auc_write_token_data, SPNEGO_NEGINIT_ELEMENT_REQFLAGS,
                              BITSTRING, ucr_temp_req_flags, SPNEGO_NEGINIT_MAXLEN_REQFLAGS);

      // Adjust Values and sanity check
      lo_total_bytes_written += lo_temp_length;
      lo_internal_token_length -= lo_temp_length;

      if ( (lo_total_bytes_written > lo_token_length) || (lo_internal_token_length < 0) ) {
         return (SPNEGO_E_INVALID_LENGTH - 200);
      }

   }  // IF ContextFlags

   // Next is the MechList - This is REQUIRED
   lo_temp_length = dsg_parse_der.m_asn_der_calc_mech_list_length(dsl_mech_type, &lo_internal_length);

   // Decrease the auc_write_token_data, now we know the length and write it out.
   auc_write_token_data -= lo_temp_length;
   lo_temp_length = dsg_parse_der.m_asn_der_write_mech_list( auc_write_token_data, dsl_mech_type );

   // Adjust Values and sanity check
   lo_total_bytes_written += lo_temp_length;
   lo_internal_token_length -= lo_temp_length;

   if ( (lo_total_bytes_written > lo_token_length) || (lo_internal_token_length < 0) ) {
      return (SPNEGO_E_INVALID_LENGTH - 300);
   }

   // The next tokens we're writing out reflect the total number of bytes we have actually written out.

   // Sequence Token
   lo_temp_length = dsg_parse_der.m_asn_der_calc_token_length(lo_total_bytes_written, 0L);

   // Decrease the auc_write_token_data, now we know the length and write it out.
   auc_write_token_data -= lo_temp_length;
   lo_temp_length = dsg_parse_der.m_asn_der_write_token(auc_write_token_data, SPNEGO_CONSTRUCTED_SEQUENCE,
                                    NULL, lo_total_bytes_written);

   // Adjust Values and sanity check
   lo_total_bytes_written += lo_temp_length;
   lo_internal_token_length -= lo_temp_length;

   if ( (lo_total_bytes_written > lo_token_length) || (lo_internal_token_length < 0) ) {
      return (SPNEGO_E_INVALID_LENGTH - 400);
   }

   // Neg Init Token Identifier Token
   lo_temp_length = dsg_parse_der.m_asn_der_calc_token_length(lo_total_bytes_written, 0L);

   // Decrease the auc_write_token_data, now we know the length and write it out.
   auc_write_token_data -= lo_temp_length;
   lo_temp_length = dsg_parse_der.m_asn_der_write_token(auc_write_token_data, SPNEGO_NEGINIT_TOKEN_IDENTIFIER,
                                    NULL, lo_total_bytes_written);

   // Adjust Values and sanity check
   lo_total_bytes_written += lo_temp_length;
   lo_internal_token_length -= lo_temp_length;

   if ( (lo_total_bytes_written > lo_token_length) || (lo_internal_token_length < 0) ) {
      return (SPNEGO_E_INVALID_LENGTH - 500);
   }

   // SPNEGO OID Token
   lo_temp_length = dsg_parse_der.m_get_from_mech_oid_list(ien_spnego_mech_oid_spnego).in_len;

   // Decrease the auc_write_token_data, now we know the length and write it out.
   auc_write_token_data -= lo_temp_length;
   lo_temp_length = dsg_parse_der.m_asn_der_write_oid(auc_write_token_data, ien_spnego_mech_oid_spnego);

   // Adjust Values and sanity check
   lo_total_bytes_written += lo_temp_length;
   lo_internal_token_length -= lo_temp_length;

   if ( (lo_total_bytes_written > lo_token_length) || (lo_internal_token_length < 0) ) {
      return (SPNEGO_E_INVALID_LENGTH - 600);
   }

   // App Constructed Token
   lo_temp_length = dsg_parse_der.m_asn_der_calc_token_length( lo_total_bytes_written, 0L );

   // Decrease the auc_write_token_data, now we know the length and write it out.
   auc_write_token_data -= lo_temp_length;
   lo_temp_length = dsg_parse_der.m_asn_der_write_token(auc_write_token_data, SPNEGO_NEGINIT_APP_CONSTRUCT,
                                    NULL, lo_total_bytes_written);

   // Adjust Values and sanity check
   lo_total_bytes_written += lo_temp_length;

   // Don't adjust the internal token length here, it doesn't account the initial bytes written
   // out (we really don't need to keep a running count here, but for debugging, it helps to be able
   // to see the total number of bytes written out as well as the number of bytes left to write).
   if ( (lo_total_bytes_written == lo_token_length) && (lo_internal_token_length == 0) &&
        (auc_write_token_data == auc_token_data) ) {
      return SUCCESS;
   }

   return (SPNEGO_E_INVALID_LENGTH - 700);
}



/**
 * Calculate the required length for a SPNEGO NegTokenTarg token based on the supplied variable
 * length values and which elements are present.
 * Note that because the lengths can be represented by an arbitrary number of bytes in DER
 * encodings, we actually calculate the lengths backwards, so we always know how many bytes we will potentially be writing out.
 *
 * @param[in] dsl_mech_type Supported dsl_mech_type.
 * @param[in] dsl_spnego_neg_result Neg Result.
 * @param[in] lo_mech_token_len Length of the MechToken Element.
 * @param[in] lo_mech_list_mic_len Length of the MechListMIC Element.
 * @param[out] lo_token_length Filled out with total size of token.
 * @param[out] alo_internal_token_length Filled out with length minus length for initial token.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_calc_min_spnego_targ_token_size(SPNEGO_MECH_OID dsl_mech_type, SPNEGO_NEGRESULT dsl_spnego_neg_result,
                                                 long lo_mech_token_len, long lo_mech_list_mic_len,
                                                 long* alo_token_size, long* alo_internal_token_length) {
   long lo_total_length = 0;
   long lo_temp_length= 0L;

   // We will calculate this by walking the token backwards

   // Start with MIC Element
   if (lo_mech_list_mic_len > 0L) {
      lo_temp_length = dsg_parse_der.m_asn_der_calc_element_length(lo_mech_list_mic_len, NULL);

      // Check for rollover error
      if (lo_temp_length < lo_mech_list_mic_len) {
         return SPNEGO_E_INVALID_LENGTH;
      }

      lo_total_length += lo_temp_length;
   }

   // Next is the MechToken
   if (lo_mech_token_len > 0L) {
      lo_temp_length += dsg_parse_der.m_asn_der_calc_element_length(lo_mech_token_len, NULL);

      // Check for rollover error
      if (lo_temp_length < lo_total_length) {
         return (SPNEGO_E_INVALID_LENGTH - 100);
      }

      lo_total_length = lo_temp_length;
   }

   // Supported dsl_mech_type
   if (ien_spnego_mech_oid_not_used != dsl_mech_type) {
      // Supported MechOID element - we use the token function since
      // we already know the size of the OID token and value
      lo_temp_length += dsg_parse_der.m_asn_der_calc_element_length(dsg_parse_der.m_get_from_mech_oid_list(dsl_mech_type).in_actual_data_len, NULL);

      // Check for rollover error
      if (lo_temp_length < lo_total_length) {
         return (SPNEGO_E_INVALID_LENGTH - 200);
      }

      lo_total_length = lo_temp_length;
   }  // IF dsl_mech_type is available

   // NegResult Element
   if (ien_spnego_negresult_not_used != dsl_spnego_neg_result) {
      lo_temp_length += dsg_parse_der.m_asn_der_calc_element_length(SPNEGO_NEGTARG_MAXLEN_NEGRESULT, NULL);

      // Check for rollover error
      if (lo_temp_length < lo_total_length) {
         return (SPNEGO_E_INVALID_LENGTH - 300);
      }

      lo_total_length = lo_temp_length;
   }  // IF negResult is available

   // Following two fields are the basic header tokens

   // Sequence Token
   lo_temp_length += dsg_parse_der.m_asn_der_calc_token_length(lo_total_length, 0L);

   // Check for rollover error
   if (lo_temp_length < lo_total_length) {
      return (SPNEGO_E_INVALID_LENGTH - 400);
   }

   lo_total_length = lo_temp_length;

   // Neg Token Identifier Token
   lo_temp_length += dsg_parse_der.m_asn_der_calc_token_length(lo_total_length, 0L);

   // Check for rollover error
   if (lo_temp_length < lo_total_length) {
      return (SPNEGO_E_INVALID_LENGTH - 500);
   }

   // The internal length doesn't include the number of bytes for the initial token
   *alo_internal_token_length = lo_total_length;
   lo_total_length = lo_temp_length;

   // We're done
   *alo_token_size = lo_total_length;
   return SUCCESS;
}



/**
 * Use DER to fill out auc_token_data with a SPNEGO NegTokenTarg Token.
 * Note that because the lengths can be represented by an arbitrary number of bytes in DER
 * encodings, we actually calculate the lengths backwards, so we always know how many bytes we will potentially be writing out.
 *
 * @param[in] dsl_mech_type Supported dsl_mech_type.
 * @param[in] dsl_spnego_neg_result Neg Result.
 * @param[in] auc_mech_token Mech Token Binary Data.
 * @param[in] lo_mech_token_len Length of the MechToken Element.
 * @param[in] auc_mech_list_mic MechListMIC Binary Data.
 * @param[in] lo_mech_list_mic_len Length of the MechListMIC Element.
 * @param[out] auc_token_data Buffer to write token into.
 * @param[in] lo_token_length Length of auc_token_data buffer.
 * @param[in] lo_internal_token_length Length of full token without leading token bytes.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_create_spnego_targ_token(SPNEGO_MECH_OID dsl_mech_type, SPNEGO_NEGRESULT dsl_spnego_neg_result,
                                          unsigned char* auc_mech_token, unsigned long ul_mech_token_len,
                                          unsigned char* auc_mech_list_mic, unsigned long ul_mech_list_mic_len,
                                          unsigned char* auc_token_data,
                                          long lo_token_len, long lo_internal_token_len) {
   long lo_temp_length = 0L;
   long lo_total_bytes_written = 0L;
   long lo_internal_length = 0L;

   // We will write the token out backwards to properly handle the cases where the length bytes become
   // adjustable, so the write location is initialized to point *just* past the end of the buffer.
   unsigned char* auc_write_token_data = auc_token_data + lo_token_len;

   // Start with MIC Element
   if (ul_mech_list_mic_len > 0L) {
      lo_temp_length = dsg_parse_der.m_asn_der_calc_element_length( ul_mech_list_mic_len, &lo_internal_length );

      // Decrease the auc_write_token_data, now we know the length and write it out.
      auc_write_token_data -= lo_temp_length;
      lo_temp_length = dsg_parse_der.m_asn_der_write_element(auc_write_token_data, SPNEGO_NEGTARG_ELEMENT_MECHLISTMIC,
                              OCTETSTRING, auc_mech_list_mic, ul_mech_list_mic_len);

      // Adjust Values and sanity check
      lo_total_bytes_written += lo_temp_length;
      lo_internal_token_len -= lo_temp_length;

      if ( (lo_total_bytes_written > lo_token_len) || (lo_internal_token_len < 0) ) {
         return SPNEGO_E_INVALID_LENGTH;
      }
   }  // IF MechListMIC is present

   // Next is the MechToken
   if (ul_mech_token_len > 0L) {
      lo_temp_length = dsg_parse_der.m_asn_der_calc_element_length( ul_mech_token_len, &lo_internal_length );

      // Decrease the auc_write_token_data, now we know the length and write it out.
      auc_write_token_data -= lo_temp_length;
      lo_temp_length = dsg_parse_der.m_asn_der_write_element(auc_write_token_data, SPNEGO_NEGTARG_ELEMENT_RESPONSETOKEN,
                              OCTETSTRING, auc_mech_token, ul_mech_token_len);
      // Adjust Values and sanity check
      lo_total_bytes_written += lo_temp_length;
      lo_internal_token_len -= lo_temp_length;

      if ( (lo_total_bytes_written > lo_token_len) || (lo_internal_token_len < 0) ) {
         return (SPNEGO_E_INVALID_LENGTH - 100);
      }
   }  // IF MechToken Length is present

   // Supported Mech Type
   if (ien_spnego_mech_oid_not_used != dsl_mech_type) {
      lo_temp_length = dsg_parse_der.m_asn_der_calc_element_length(dsg_parse_der.m_get_from_mech_oid_list(dsl_mech_type).in_actual_data_len,
                                             &lo_internal_length);

      // Decrease the auc_write_token_data, now we know the length and write it out.
      auc_write_token_data -= lo_temp_length;
      lo_temp_length = dsg_parse_der.m_asn_der_write_token(auc_write_token_data, SPNEGO_NEGTARG_ELEMENT_SUPPORTEDMECH,
                                       dsg_parse_der.m_get_from_mech_oid_list(dsl_mech_type).auc_oid,
                                       dsg_parse_der.m_get_from_mech_oid_list(dsl_mech_type).in_len);

      // Adjust Values and sanity check
      lo_total_bytes_written += lo_temp_length;
      lo_internal_token_len -= lo_temp_length;

      if ( (lo_total_bytes_written > lo_token_len) || (lo_internal_token_len < 0) ) {
         return (SPNEGO_E_INVALID_LENGTH - 200);
      }
   }  // IF dsl_mech_type is present

   // Neg Result
   // NegResult Element
   if (ien_spnego_negresult_not_used != dsl_spnego_neg_result) {
      unsigned char  ucTemp = (unsigned char) dsl_spnego_neg_result;

      lo_temp_length = dsg_parse_der.m_asn_der_calc_element_length( SPNEGO_NEGTARG_MAXLEN_NEGRESULT, &lo_internal_length );

      // Decrease the auc_write_token_data, now we know the length and write it out.
      auc_write_token_data -= lo_temp_length;
      lo_temp_length = dsg_parse_der.m_asn_der_write_element(auc_write_token_data, SPNEGO_NEGTARG_ELEMENT_NEGRESULT,
                              ENUMERATED, &ucTemp, SPNEGO_NEGTARG_MAXLEN_NEGRESULT);

      // Adjust Values and sanity check
      lo_total_bytes_written += lo_temp_length;
      lo_internal_token_len -= lo_temp_length;

      if ( (lo_total_bytes_written > lo_token_len) || (lo_internal_token_len < 0) ) {
         return (SPNEGO_E_INVALID_LENGTH - 300);
      }
   }  // If eNegResult is available

   // The next tokens we're writing out reflect the total number of bytes
   // we have actually written out.

   // Sequence Token
   lo_temp_length = dsg_parse_der.m_asn_der_calc_token_length(lo_total_bytes_written, 0L);

   // Decrease the auc_write_token_data, now we know the length and write it out.
   auc_write_token_data -= lo_temp_length;
   lo_temp_length = dsg_parse_der.m_asn_der_write_token(auc_write_token_data, SPNEGO_CONSTRUCTED_SEQUENCE,
                                    NULL, lo_total_bytes_written);

   // Adjust Values and sanity check
   lo_total_bytes_written += lo_temp_length;
   lo_internal_token_len -= lo_temp_length;

   if ( (lo_total_bytes_written > lo_token_len) || (lo_internal_token_len < 0) ) {
      return (SPNEGO_E_INVALID_LENGTH - 400);
   }

   // Neg Targ Token Identifier Token
   lo_temp_length = dsg_parse_der.m_asn_der_calc_token_length( lo_total_bytes_written, 0L );

   // Decrease the auc_write_token_data, now we know the length and write it out.
   auc_write_token_data -= lo_temp_length;
   lo_temp_length = dsg_parse_der.m_asn_der_write_token(auc_write_token_data, SPNEGO_NEGTARG_TOKEN_IDENTIFIER,
                                    NULL, lo_total_bytes_written);

   // Adjust Values and sanity check
   lo_total_bytes_written += lo_temp_length;

   // Don't adjust the internal token length here, it doesn't account the initial bytes written out (we
   // really don't need to keep a running count here, but for debugging, it helps to be able to see the total
   // number of bytes written out as well as the number of bytes left to write).
   if ( (lo_total_bytes_written == lo_token_len) && (lo_internal_token_len == 0) &&
        (auc_write_token_data == auc_token_data) ) {
      return SUCCESS;
   }

   return (SPNEGO_E_INVALID_LENGTH - 400);
}



/**
 * Allocate a SPNEGO_TOKEN data structure and initializes it. Based on the value of uc_copy_data,
 * if non-zero, we copy the data into a buffer we allocate in this function, otherwise, we copy the data pointer direcly.
 *
 * @param[in] uc_copy_data Flag to copy data or pointer.
 * @param[in] ul_flags Flags for SPNEGO_TOKEN data member.
 * @param[in] auc_token_data Binary token data.
 * @param[in] ul_token_size Size of auc_token_data.
 * @return Pointer to initialized SPNEGO_TOKEN struct, if successful; otherwise NULL.
*/
SPNEGO_TOKEN* ds_spnego_krb::m_alloc_empty_spnego_token(unsigned char uc_copy_data, unsigned long ul_flags,
                                    unsigned char* auc_token_data, unsigned long ul_token_size) {
    SPNEGO_TOKEN* ads_spnego_token = (SPNEGO_TOKEN*) calloc(1, sizeof(SPNEGO_TOKEN));
    if (ads_spnego_token == NULL) {
        return NULL;
    }

    // Set the token size
    ads_spnego_token->ui_struct_size = SPNEGO_TOKEN_SIZE;

    // Initialize the element array
    m_init_spnego_token_element_array(ads_spnego_token);

    // Assign the flags value
    ads_spnego_token->ul_flags = ul_flags;

    // IF uc_copy_data is TRUE, we will allocate a buffer and copy data into it.
    // Otherwise, we will just copy the pointer and the length.  This is so we
    // can cut out additional allocations for performance reasons
    if (SPNEGO_TOKEN_INTERNAL_FLAGS_FREEDATA == uc_copy_data) {
        // Alloc the internal buffer.  Cleanup on failure.
#ifdef USE_WSP_HELPER
        ads_spnego_token->auc_binary_data = (unsigned char*)ads_wsp_helper->m_cb_get_memory((int)(ul_token_size * sizeof(unsigned char)), true);
#else
        ads_spnego_token->auc_binary_data = (unsigned char*) calloc(ul_token_size, sizeof(unsigned char));
#endif
        if ( NULL == ads_spnego_token->auc_binary_data ) {
#ifdef USE_WSP_HELPER
            ads_wsp_helper->m_cb_free_memory(ads_spnego_token);
#else
            free(ads_spnego_token);
#endif
            return NULL;
        }

        // We must ALWAYS free this buffer
        ads_spnego_token->ul_flags |= SPNEGO_TOKEN_INTERNAL_FLAGS_FREEDATA;

        // Copy the data locally
        memcpy( ads_spnego_token->auc_binary_data, auc_token_data, ul_token_size );
        ads_spnego_token->ul_binary_data_len = ul_token_size;
    }  // IF uc_copy_data
    else {
        // Copy the pointer and the length directly - ul_flags will control whether or not
        // we are allowed to free the value
        ads_spnego_token->auc_binary_data = auc_token_data;
        ads_spnego_token->ul_binary_data_len = ul_token_size;
    }

    return ads_spnego_token;
}



/**
 * If non-NULL, interpret ads_spnego_token, freeing any internal allocations and finally the actual structure.
 *
 * @param[in] ads_spnego_token Points to SPNEGO_TOKEN to free.
 * @return void.
*/
void ds_spnego_krb::m_free_spnego_token(SPNEGO_TOKEN* ads_spnego_token) {
    if (ads_spnego_token != NULL) {
        // Cleanup internal allocation per the flags
        if ( ads_spnego_token->ul_flags & SPNEGO_TOKEN_INTERNAL_FLAGS_FREEDATA &&
            NULL != ads_spnego_token->auc_binary_data ) {
#ifdef USE_WSP_HELPER
                ads_wsp_helper->m_cb_free_memory(ads_spnego_token->auc_binary_data);
#else
                free( ads_spnego_token->auc_binary_data );
#endif
                ads_spnego_token->auc_binary_data = NULL;
        }

#ifdef USE_WSP_HELPER
        ads_wsp_helper->m_cb_free_memory(ads_spnego_token);
#else
        free ( ads_spnego_token );
#endif
    }
}



/**
 * Initialize the element array data member of a SPNEGO_TOKEN data structure.
 *
 * @param[in] ads_spnego_token Points to SPNEGO_TOKEN to free.
 * @return void.
*/
void ds_spnego_krb::m_init_spnego_token_element_array(SPNEGO_TOKEN* ads_spnego_token) {
    // Set the number of elemnts
    ads_spnego_token->in_num_elements = MAX_NUM_TOKEN_ELEMENTS;

    // Initially, all elements are unavailable
    for (int in_idx = 0; in_idx < MAX_NUM_TOKEN_ELEMENTS; in_idx++) {
        // Set the element size as well
        ads_spnego_token->dsr_element_array[in_idx].ui_struct_size = SPNEGO_ELEMENT_SIZE;
        ads_spnego_token->dsr_element_array[in_idx].in_element_present = SPNEGO_TOKEN_ELEMENT_UNAVAILABLE;
    }
}



/**
 * Walk the underlying binary data for a SPNEGO_TOKEN data structure and determines the type
 * of the underlying token based on token header information.
 *
 * @param[in] ads_spnego_token Points to SPNEGO_TOKEN to free.
 * @param[out] alo_len_token Filled out with total token length.
 * @param[out] alo_remaining_token_length Filled out with remaining length after header is parsed.
 * @param[out] aauc_first_element Filled out with pointer to first element after header info.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_init_spnego_token_type(SPNEGO_TOKEN* ads_spnego_token, long* alo_len_token,
                           long* alo_remaining_token_length, unsigned char** aauc_first_element) {
   long  lo_actual_token_length = 0L;
   long  lo_boundary_length = ads_spnego_token->ul_binary_data_len;
   unsigned char* auc_token_data = ads_spnego_token->auc_binary_data;

   // First byte MUST be either an APP_CONSTRUCT or the NEGTARG_TOKEN_TARG
   if (*auc_token_data == SPNEGO_NEGINIT_APP_CONSTRUCT) {
       // Validate the above token - this will tell us the actual length of the token
       // per the encoding (minus the actual token bytes)
       int inl_ret = dsg_parse_der.m_asn_der_check_token(auc_token_data, SPNEGO_NEGINIT_APP_CONSTRUCT, 0L, lo_boundary_length,
                                          alo_len_token, &lo_actual_token_length);
       if (inl_ret != SUCCESS) {
           return (SPNEGO_E_INVALID_TOKEN - 100);
       }

       // Initialize the remaining token length value.  This will be used to tell the caller how much
       // token there is left once we've parsed the header (they could calculate it from the other values,
       // but this is a bit friendlier)
       *alo_remaining_token_length = *alo_len_token;

       // Make adjustments to next token
       auc_token_data += lo_actual_token_length;
       lo_boundary_length -= lo_actual_token_length;

       // The next token should be an OID
       inl_ret = dsg_parse_der.m_asn_der_check_oid(auc_token_data, ien_spnego_mech_oid_spnego, lo_boundary_length,
                                          &lo_actual_token_length);
       if (inl_ret != SUCCESS) {
           return (SPNEGO_E_INVALID_TOKEN - 200);
       }

       // Make adjustments to next token
       auc_token_data += lo_actual_token_length;
       lo_boundary_length -= lo_actual_token_length;
       *alo_remaining_token_length -= lo_actual_token_length;

       // The next token should specify the NegTokenInit
       inl_ret = dsg_parse_der.m_asn_der_check_token(auc_token_data, SPNEGO_NEGINIT_TOKEN_IDENTIFIER,
                                                *alo_remaining_token_length, lo_boundary_length, alo_len_token,
                                                &lo_actual_token_length);
       if (inl_ret != SUCCESS) {
           return (SPNEGO_E_INVALID_TOKEN - 300);
       }

       // Make adjustments to next token
       auc_token_data += lo_actual_token_length;
       lo_boundary_length -= lo_actual_token_length;
       *alo_remaining_token_length -= lo_actual_token_length;

       // The next token should specify the start of a sequence
       inl_ret = dsg_parse_der.m_asn_der_check_token(auc_token_data, SPNEGO_CONSTRUCTED_SEQUENCE,
                                                   *alo_remaining_token_length, lo_boundary_length, alo_len_token,
                                                   &lo_actual_token_length);
       if (inl_ret != SUCCESS) {
           return (SPNEGO_E_INVALID_TOKEN - 400);
       }

       // NegTokenInit header is now checked out!

       // Make adjustments to next token
       *alo_remaining_token_length -= lo_actual_token_length;

       // Store pointer to first element
       *aauc_first_element = auc_token_data + lo_actual_token_length;
       ads_spnego_token->in_token_type = SPNEGO_TOKEN_INIT;

       return SUCCESS;
   }  // IF check app construct token

   if (*auc_token_data == SPNEGO_NEGTARG_TOKEN_IDENTIFIER) { // it's a NegTokenTarg
       // The next token should specify the NegTokenInit
       int inl_ret = dsg_parse_der.m_asn_der_check_token(auc_token_data, SPNEGO_NEGTARG_TOKEN_IDENTIFIER,
                                          *alo_remaining_token_length, lo_boundary_length, alo_len_token,
                                          &lo_actual_token_length);
       if (inl_ret != SUCCESS) {
           return (SPNEGO_E_INVALID_TOKEN - 500);
       }

       // Initialize the remaining token length value. This will be used to tell the caller how much
       // token there is left once we've parsed the header (they could calculate it from the other
       // values, but this is a bit friendlier)
       *alo_remaining_token_length = *alo_len_token;

       // Make adjustments to next token
       auc_token_data += lo_actual_token_length;
       lo_boundary_length -= lo_actual_token_length;

       // The next token should specify the start of a sequence
       inl_ret = dsg_parse_der.m_asn_der_check_token(auc_token_data, SPNEGO_CONSTRUCTED_SEQUENCE,
                                             *alo_remaining_token_length, lo_boundary_length, alo_len_token,
                                             &lo_actual_token_length);
       if (inl_ret != SUCCESS) {
           return (SPNEGO_E_INVALID_TOKEN - 600);
       }

       // NegTokenInit header is now checked out!

       // Make adjustments to next token
       *alo_remaining_token_length -= lo_actual_token_length;

       // Store pointer to first element
       *aauc_first_element = auc_token_data + lo_actual_token_length;
       ads_spnego_token->in_token_type = SPNEGO_TOKEN_TARG;

       return SUCCESS;
   }  // IF it's a NegTokenTarg

   return SPNEGO_E_INVALID_TOKEN;
}



/**
 * Check that auc_token_data is pointing at something that at least *looks* like a MechList and
 * then fills out the supplied SPNEGO_ELEMENT structure.
 *
 * @param[in] auc_token_data Points to binary MechList element in NegTokenInit.
 * @param[in] lo_mech_list_length Length of the MechList.
 * @param[out] ads_spnego_element Filled out with MechList Element data.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_get_spnego_init_token_mech_list(unsigned char* auc_token_data, int lo_mech_list_length,
                                 SPNEGO_ELEMENT* ads_spnego_element) {
    long  lo_length = 0L;
    long  lo_actual_token_length = 0L;

    // Actual MechList is prepended by a Constructed Sequence Token
    int inl_ret = dsg_parse_der.m_asn_der_check_token(auc_token_data, SPNEGO_CONSTRUCTED_SEQUENCE,
                                       lo_mech_list_length, lo_mech_list_length,
                                       &lo_length, &lo_actual_token_length);
    if (inl_ret != SUCCESS) {
        return SPNEGO_E_INVALID_TOKEN;
    }

    // Adjust for this token
    lo_mech_list_length -= lo_actual_token_length;
    auc_token_data += lo_actual_token_length;

    // Perform simple validation of the actual MechList (i.e. ensure that
    // the OIDs in the MechList are reasonable).
    inl_ret = m_validate_mech_list(auc_token_data, lo_length);
    if (inl_ret != SUCCESS) {
        return (SPNEGO_E_INVALID_TOKEN - 100);
    }

    // Initialize the element now
    ads_spnego_element->ds_element_type    = ien_spnego_init_mechtypes;
    ads_spnego_element->in_element_present = SPNEGO_TOKEN_ELEMENT_AVAILABLE;
    ads_spnego_element->uc_type            = SPNEGO_MECHLIST_TYPE;
    ads_spnego_element->ul_data_length     = lo_length;
    ads_spnego_element->auc_data           = auc_token_data;

    return SUCCESS;
}



/**
 * Check that auc_token_data is pointing at the specified DER type. If so, then we verify that lengths are
 * proper and then fill out the SPNEGO_ELEMENT data structure.
 *
 * @param[in] auc_token_data Points to binary element data in a SPNEGO token.
 * @param[in] in_element_length Length of the element.
 * @param[in] uc_expected_type Expected DER type.
 * @param[in] dsl_spnego_element_type Element type.
 * @param[out] ads_spnego_element Filled out with element data.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_init_spnego_token_element_from_basic_type(unsigned char* auc_token_data, int in_element_length,
                                          unsigned char uc_expected_type, SPNEGO_ELEMENT_TYPE dsl_spnego_element_type,
                                          SPNEGO_ELEMENT* ads_spnego_element) {
    // The type BYTE must match our token data or something is badly wrong
    if ( *auc_token_data != uc_expected_type) {
        return SPNEGO_E_UNEXPECTED_TYPE;
    }

    // Check that we are pointing at the specified type
    long  lo_length = 0L;
    long  lo_actual_token_length = 0L;
    int inl_ret = dsg_parse_der.m_asn_der_check_token(auc_token_data, uc_expected_type,
                                          in_element_length, in_element_length,
                                          &lo_length, &lo_actual_token_length);
    if (inl_ret != SUCCESS) {
        return (SPNEGO_E_UNEXPECTED_TYPE - 100);
    }

    // Adjust for this token
    in_element_length -= lo_actual_token_length;
    auc_token_data += lo_actual_token_length;

    // Initialize the element now
    ads_spnego_element->ds_element_type    = dsl_spnego_element_type;
    ads_spnego_element->in_element_present = SPNEGO_TOKEN_ELEMENT_AVAILABLE;
    ads_spnego_element->uc_type            = uc_expected_type;
    ads_spnego_element->ul_data_length     = lo_length;
    ads_spnego_element->auc_data           = auc_token_data;

    return SUCCESS;
}



/**
 * Initialize a dsd_spnego_element from an OID - normally, this would have used the Basic Type
 * function above, but since we do binary compares on the OIDs against the DER information
 * as well as the OID, we need to account for that.
 *
 * @param[in] auc_token_data Points to binary element data in a SPNEGO token.
 * @param[in] in_element_length Length of the element.
 * @param[in] dsl_spnego_element_type Element type.
 * @param[out] ads_spnego_element Filled out with element data.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_init_spnego_token_element_from_oid(unsigned char* auc_token_data, int in_element_length,
                                   SPNEGO_ELEMENT_TYPE dsl_spnego_element_type,
                                   SPNEGO_ELEMENT* ads_spnego_element) {
    // The type BYTE must match our token data or something is badly wrong
    if (*auc_token_data != OID ) {
        return SPNEGO_E_UNEXPECTED_TYPE;
    }

    // Check that we are pointing at an OID type
    long  lo_length = 0L;
    long  lo_actual_token_length = 0L;
    int inl_ret = dsg_parse_der.m_asn_der_check_token(auc_token_data, OID,
                                          in_element_length, in_element_length,
                                          &lo_length, &lo_actual_token_length);
    if (inl_ret != SUCCESS) {
        return (SPNEGO_E_UNEXPECTED_TYPE - 100);
    }

    // Don't adjust any values for this function

    // Initialize the element now
    ads_spnego_element->ds_element_type    = dsl_spnego_element_type;
    ads_spnego_element->in_element_present = SPNEGO_TOKEN_ELEMENT_AVAILABLE;
    ads_spnego_element->uc_type            = OID;
    ads_spnego_element->ul_data_length     = in_element_length;
    ads_spnego_element->auc_data           = auc_token_data;

    return SUCCESS;
}



/**
 * Interpret the data at auc_token_data based on the TokenType in ads_spnego_token. Since some elements
 * are optional (technically all are but the token becomes quite useless if this is so), we check if
 * an element exists before filling out the element in the array.
 *
 * @param[in] ads_spnego_token Points to SPNEGO_TOKEN struct.
 * @param[in] auc_token_data Points to initial binary element data in a SPNEGO token.
 * @param[in] lo_remaining_token_len Length remaining past header.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_init_spnego_token_elements(SPNEGO_TOKEN* ads_spnego_token,
                                            unsigned char* auc_token_data, long lo_remaining_token_len) {
    // The following arrays contain the token identifiers for the elements
    // comprising the actual token.  All values are optional, and there are no defaults.
    /* JF static*/ unsigned char uc_neg_token_init_elements[] =
      { SPNEGO_NEGINIT_ELEMENT_MECHTYPES, SPNEGO_NEGINIT_ELEMENT_REQFLAGS,
        SPNEGO_NEGINIT_ELEMENT_MECHTOKEN, SPNEGO_NEGINIT_ELEMENT_MECHLISTMIC };

    /* JF static*/ unsigned char uc_neg_token_targ_elements[] =
      { SPNEGO_NEGTARG_ELEMENT_NEGRESULT, SPNEGO_NEGTARG_ELEMENT_SUPPORTEDMECH,
        SPNEGO_NEGTARG_ELEMENT_RESPONSETOKEN, SPNEGO_NEGTARG_ELEMENT_MECHLISTMIC };

    int inl_ret = SUCCESS;
    long lo_element_length = 0L;
    long lo_actual_token_length = 0L;
    unsigned char* auc_elements = NULL;

    // Point to the correct array
    switch(ads_spnego_token->in_token_type) {
    case SPNEGO_TOKEN_INIT: {
        auc_elements = uc_neg_token_init_elements;
        break;
    }
    case SPNEGO_TOKEN_TARG: {
        auc_elements = uc_neg_token_targ_elements;
        break;
    }
    default: { // JF
        return -823;
    }
    }// SWITCH tokentype


    // Enumerate the element arrays and look for the tokens at our current location.
    for (int in_idx = 0L;
         SUCCESS == inl_ret &&
         in_idx < MAX_NUM_TOKEN_ELEMENTS &&
         lo_remaining_token_len > 0L;
         in_idx++) {
        // Check if the token exists
        inl_ret = dsg_parse_der.m_asn_der_check_token(auc_token_data, auc_elements[in_idx],
                                          0L, lo_remaining_token_len,
                                          &lo_element_length, &lo_actual_token_length);
        if (inl_ret == SUCCESS ) { // Token was found.
            // Token data should skip over the sequence token and then
            // call the appropriate function to initialize the element
            auc_token_data += lo_actual_token_length;

            // Lengths in the elements should NOT go beyond the element length

            // Different tokens mean different elements
            if (SPNEGO_TOKEN_INIT == ads_spnego_token->in_token_type) {
                // Handle each element as appropriate
                switch(auc_elements[in_idx]) {
                case SPNEGO_NEGINIT_ELEMENT_MECHTYPES: {
                    // This is a Mech List that specifies which OIDs the
                    // originator of the Init Token supports.
                    inl_ret = m_get_spnego_init_token_mech_list(auc_token_data, lo_element_length,
                                                         &ads_spnego_token->dsr_element_array[in_idx]);
                    break;
                }
                case SPNEGO_NEGINIT_ELEMENT_REQFLAGS: {
                    // This is a BITSTRING which specifies the flags that the receiver
                    // pass to the gss_accept_sec_context() function.
                    inl_ret = m_init_spnego_token_element_from_basic_type(auc_token_data, lo_element_length,
                                                                  BITSTRING, ien_spnego_init_req_flags,
                                                                  &ads_spnego_token->dsr_element_array[in_idx]);
                    break;
                }
                case SPNEGO_NEGINIT_ELEMENT_MECHTOKEN: {
                    // This is an OCTETSTRING which contains a GSSAPI token corresponding
                    // to the first OID in the MechList.
                    inl_ret = m_init_spnego_token_element_from_basic_type(auc_token_data, lo_element_length,
                                                                  OCTETSTRING, ien_spnego_init_mech_token,
                                                                  &ads_spnego_token->dsr_element_array[in_idx]);
                    break;
                }
                case SPNEGO_NEGINIT_ELEMENT_MECHLISTMIC: {
                    // This is an OCTETSTRING which contains a message integrity BLOB.
                    inl_ret = m_init_spnego_token_element_from_basic_type(auc_token_data, lo_element_length,
                                                                  OCTETSTRING, ien_spnego_init_mech_list_mic,
                                                                  &ads_spnego_token->dsr_element_array[in_idx]);
                    break;
                }
                }  // SWITCH Element
            }
            else { // SPNEGO_TOKEN_TARG
                switch(auc_elements[in_idx]) {
                case SPNEGO_NEGTARG_ELEMENT_NEGRESULT: {
                    // This is an ENUMERATION which specifies result of the last GSS
                    // token negotiation call.
                    inl_ret = m_init_spnego_token_element_from_basic_type(auc_token_data, lo_element_length,
                                                                  ENUMERATED, ien_spnego_targ_neg_result,
                                                                  &ads_spnego_token->dsr_element_array[in_idx]);
                    break;
                }
                case SPNEGO_NEGTARG_ELEMENT_SUPPORTEDMECH: {
                    // This is an OID which specifies a supported mechanism.
                    inl_ret = m_init_spnego_token_element_from_oid(auc_token_data, lo_element_length,
                                                           ien_spnego_targ_mech_list_mic,
                                                           &ads_spnego_token->dsr_element_array[in_idx]);
                    break;
                }
                case SPNEGO_NEGTARG_ELEMENT_RESPONSETOKEN: {
                    //  This is an OCTETSTRING which specifies results of the last GSS
                    //  token negotiation call.
                    inl_ret = m_init_spnego_token_element_from_basic_type(auc_token_data, lo_element_length,
                                                                  OCTETSTRING, ien_spnego_targ_response_token,
                                                                  &ads_spnego_token->dsr_element_array[in_idx]);
                    break;
                }
                case SPNEGO_NEGTARG_ELEMENT_MECHLISTMIC: {
                    // This is an OCTETSTRING which specifies a message integrity BLOB.
                    inl_ret = m_init_spnego_token_element_from_basic_type(auc_token_data, lo_element_length,
                                                                  OCTETSTRING, ien_spnego_targ_mech_list_mic,
                                                                  &ads_spnego_token->dsr_element_array[in_idx]);
                    break;
                }
                }  // SWITCH Element
            }  // SPNEGO_TOKEN_TARG

            // Account for the entire token and following data
            lo_remaining_token_len -= ( lo_actual_token_length + lo_element_length );

            // Token data should skip past the element length now
            auc_token_data += lo_element_length;
        }  // IF Token found
        else if (inl_ret == SPNEGO_E_TOKEN_NOT_FOUND) {
            // For now, this is a benign error (remember, all elements are optional, so
            // if we don't find one, it's okay).
            inl_ret = SUCCESS;
        }
    }  // FOR enum elements

    // We should always run down to 0 remaining bytes in the token. If not, we've got a bad token.
     if ( SUCCESS == inl_ret && lo_remaining_token_len != 0L ) {
         inl_ret = SPNEGO_E_INVALID_TOKEN;
     }
     return inl_ret;
}



/**
 * Walk the MechList for MechOID. When it is found, the index in the list is
 * written to ain_mech_type_index.
 *
 * @param[in] ads_spnego_element SPNEGO_ELEMENT for MechList.
 * @param[in] dsl_mech_oid OID we're looking for.
 * @param[out] ain_mech_type_index Index in the list where OID was found.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_find_mech_oid_in_mech_list(SPNEGO_ELEMENT* ads_spnego_element, SPNEGO_MECH_OID dsl_mech_oid,
                          int* ain_mech_type_index) {
   int inl_ret = SPNEGO_E_NOT_FOUND;
   int in_idx = 0;
   long lo_length = 0L;
   long lo_boundary_length = ads_spnego_element->ul_data_length;
   unsigned char* auc_mech_list_data = ads_spnego_element->auc_data;

   while( SUCCESS != inl_ret && lo_boundary_length > 0L ) {
      // Use the helper function to check the OID
      if ( ( inl_ret = dsg_parse_der.m_asn_der_check_oid( auc_mech_list_data, dsl_mech_oid, lo_boundary_length, &lo_length ) )
                     == SUCCESS ) {
         *ain_mech_type_index = in_idx;
      }

      // Adjust for the current OID
      auc_mech_list_data += lo_length;
      lo_boundary_length -= lo_length;
      in_idx++;
   }  // WHILE enuming OIDs

   return inl_ret;
}



/**
 * Check the data at auc_mech_list_data to see if it looks like a MechList.
 * As part of this, we walk the list and ensure that none of the OIDs
 * have a length that takes us outside of lo_boundary_length.
 *
 * @param[in] auc_mech_list_data Pointer to binary MechList data.
 * @param[in] lo_boundary_length Length we must not exceed.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_validate_mech_list(unsigned char* auc_mech_list_data, long lo_boundary_length) {
   int inl_ret = SUCCESS;
   long lo_length = 0L;
   long lo_token_length = 0L;

   while( SUCCESS == inl_ret && lo_boundary_length > 0L ) {
      // Verify that we have something that at least *looks* like an OID - in other
      // words it has an OID identifier and specifies a length that doesn't go beyond
      // the size of the list.
      inl_ret = dsg_parse_der.m_asn_der_check_token( auc_mech_list_data, OID, 0L, lo_boundary_length,
                                  &lo_length, &lo_token_length );

      // Adjust for the current OID
      auc_mech_list_data += ( lo_length + lo_token_length );
      lo_boundary_length -= ( lo_length + lo_token_length );

   }  // WHILE enuming OIDs

   return inl_ret;

}



/**
 * Check for a valid dsl_mech_oid value.
 *
 * @param[in] dsl_mech_oid mechOID id enumeration.
 * @return 1, if successful; otherwise 0.
*/
int ds_spnego_krb::m_is_valid_mech_oid(SPNEGO_MECH_OID dsl_mech_oid) {
   return (dsl_mech_oid >= ien_spnego_mech_oid_kerberos_v5_legacy &&
           dsl_mech_oid <= ien_spnego_mech_oid_spnego);
}



/**
 * Check for a valid ContextFlags value.
 *
 * @param[in] uc_context_flags ContextFlags value.
 * @return 1, if successful; otherwise 0.
*/
int ds_spnego_krb::m_is_valid_context_flags(unsigned char uc_context_flags) {
    // Mask out our valid bits.  If there is anything leftover, this
    // is not a valid value for Context Flags
   return ( ( uc_context_flags & ~SPNEGO_NEGINIT_CONTEXT_MASK ) == 0 );
}



/**
 * Check for a valid NegResult value.
 *
 * @param[in] dsl_neg_result NegResult value.
 * @return 1, if successful; otherwise 0.
*/
int ds_spnego_krb::m_is_valid_neg_result(SPNEGO_NEGRESULT dsl_neg_result) {
   return (dsl_neg_result >= ien_spnego_negresult_success &&
           dsl_neg_result <= ien_spnego_negresult_rejected);
}



/**
 * Performs simple heuristic on location pointed to by ads_spnego_token.
 *
 * @param[in] ads_spnego_token  Points to SPNEGO_TOKEN data structure.
 * @return 1, if successful; otherwise 0.
*/
int ds_spnego_krb::m_is_valid_spnego_token(SPNEGO_TOKEN* ads_spnego_token) {
    // Parameter should be non-NULL
    if (NULL == ads_spnego_token) {
        return 0; // error
    }

    // Length should be at least the size defined in the header
    if ( ads_spnego_token->ui_struct_size >= SPNEGO_TOKEN_SIZE ) {
        // Number of elements should be >= our maximum - if it's greater, that's
        // okay, since we'll only be accessing the elements up to MAX_NUM_TOKEN_ELEMENTS
        if (ads_spnego_token->in_num_elements >= MAX_NUM_TOKEN_ELEMENTS) {
            //  Check for proper token type
            if (SPNEGO_TOKEN_INIT == ads_spnego_token->in_token_type ||
                SPNEGO_TOKEN_TARG == ads_spnego_token->in_token_type ) {
                    return 1;
            }
        }
    }  // IF struct size makes sense

    return 0; // error
}



/**
 * Checks that dsl_spnego_element has a valid value and is appropriate for
 * the SPNEGO token encapsulated by ads_spnego_token.
 *
 * @param[in] ads_spnego_token  Points to SPNEGO_TOKEN data structure.
 * @param[in] dsl_spnego_element spnegoElement Type from enumeration.
 * @return 1, if successful; otherwise 0.
*/
int ds_spnego_krb::m_is_valid_spnego_element(SPNEGO_TOKEN* ads_spnego_token, SPNEGO_ELEMENT_TYPE dsl_spnego_element) {
   int   inl_ret = 0;

   // Check boundaries
   if (dsl_spnego_element > ien_spnego_element_min &&
       dsl_spnego_element < ien_spnego_element_max) {
      // Check for appropriateness to token type
      if (SPNEGO_TOKEN_INIT == ads_spnego_token->in_token_type) {
         inl_ret = (dsl_spnego_element >= ien_spnego_init_mechtypes &&
                    dsl_spnego_element <= ien_spnego_init_mech_list_mic);
      }
      else {
         inl_ret = (dsl_spnego_element >= ien_spnego_targ_neg_result &&
                    dsl_spnego_element <= ien_spnego_targ_mech_list_mic);
      }
   }  // IF boundary conditions are met

   return inl_ret;
}



/**
 * Based on the Token Type, calculates the index in the element array
 * at which the specified element can be found.
 *
 * @param[in] ads_spnego_token  Points to SPNEGO_TOKEN data structure.
 * @param[in] dsl_spnego_element spnegoElement Type from enumeration.
 * @return index in the SPNEGO_TOKEN element array that the element can be found
*/
int ds_spnego_krb::m_calc_element_array_index(SPNEGO_TOKEN* ads_spnego_token,SPNEGO_ELEMENT_TYPE dsl_spnego_element) {
   int   inl_ret = 0;

   // Offset is difference between value and initial element identifier
   // (these differ based on ucTokenType)
   if (SPNEGO_TOKEN_INIT == ads_spnego_token->in_token_type) {
      inl_ret = dsl_spnego_element - ien_spnego_init_mechtypes;
   }
   else {
      inl_ret = dsl_spnego_element - ien_spnego_targ_neg_result;
   }

   return inl_ret;
}


/**
 * Initialize SPNEGO_TOKEN structure from DER encoded binary data.
 *
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_init_token_from_binary(unsigned char uc_copy_data, unsigned long ul_flags,
                        unsigned char* auc_token_data, unsigned long ul_length,
                        SPNEGO_TOKEN** aadsl_spnego_token) {
   int            inl_ret = SPNEGO_E_INVALID_PARAMETER;
   SPNEGO_TOKEN*  ads_spnego_token = NULL;
   unsigned char* auc_first_element = NULL;
   long           lo_token_length = 0L;
   long           lo_remaining_token_len = 0L;

   // Basic Parameter Validation
   if (  NULL != auc_token_data &&
         NULL != aadsl_spnego_token &&
         0L != ul_length ) {
      // Allocate the empty token, then initialize the data structure.
      ads_spnego_token = m_alloc_empty_spnego_token( uc_copy_data, ul_flags, auc_token_data, ul_length );
      if (NULL == ads_spnego_token) {
          return SPNEGO_E_OUT_OF_MEMORY;
      }

     // Copy the binary data locally

     // Initialize the token type
     if ( ( inl_ret = m_init_spnego_token_type(ads_spnego_token, &lo_token_length,
                                            &lo_remaining_token_len, &auc_first_element) )
                    == SUCCESS )  {
        // Initialize the element array
        if ( ( inl_ret = m_init_spnego_token_elements( ads_spnego_token, auc_first_element,
                                                  lo_remaining_token_len ) )
                       == SUCCESS ) {
           *aadsl_spnego_token = ads_spnego_token;
        }

     }  // IF Init Token Type

     // Cleanup on error condition
     if (SUCCESS != inl_ret) {
        // JF m_spnego_free_data( ads_spnego_token );
         m_free_spnego_token( ads_spnego_token);
     }
   }  // IF Valid parameters

   return inl_ret;
}



/**
 * Initializes a SPNEGO_TOKEN_HANDLE from the supplied binary data. Data is copied
 * locally. Returned data structure must be freed by calling m_spnego_free_data().
 *
 * @param[in] auc_token_data Binary Token Data.
 * @param[in] ul_length Length of binary Token Data.
 * @param[out] adsl_spnego_token_handle SPNEGO_TOKEN_HANDLE pointer.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_init_from_binary(unsigned char* auc_token_data, unsigned long ul_length, SPNEGO_TOKEN_HANDLE* adsl_spnego_token_handle) {
   SPNEGO_TOKEN** aadsl_spnego_token = (SPNEGO_TOKEN**) adsl_spnego_token_handle;

   // Pass off to a handler function that allows tighter control over how the token structure
   // is handled.  In this case, we want the token data copied and we want the associated buffer
   // freed.
   int inl_ret = m_init_token_from_binary(SPNEGO_TOKEN_INTERNAL_COPYDATA,
                                 SPNEGO_TOKEN_INTERNAL_FLAGS_FREEDATA, auc_token_data,
                                 ul_length, aadsl_spnego_token);
   return inl_ret;
}



/**
 * Initializes a SPNEGO_TOKEN_HANDLE for a NegTokenInit type from the supplied parameters.
 * uc_context_flags may be 0 or must be a valid flag combination. MechToken data can be NULL - if not, it
 * must correspond to the dsl_mech_type. MechListMIC can also be NULL.
 * Returned data structure must be freed by calling m_spnego_free_data().
 *
 * @param[in] dsl_mech_type dsl_mech_type to specify in MechTypeList element.
 * @param[in] uc_context_flags Context Flags element value.
 * @param[in] auc_mech_token Pointer to binary MechToken Data.
 * @param[in] ul_mech_token_len Length of MechToken Data.
 * @param[in] auc_mech_list_mic Pointer to binary MechListMIC Data.
 * @param[in] ul_mech_list_mic_len Length of MechListMIC Data.
 * @param[out] adsl_spnego_token_handle SPNEGO_TOKEN_HANDLE pointer.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_create_neg_token_init(SPNEGO_MECH_OID dsl_mech_type, unsigned char uc_context_flags,
          unsigned char* auc_mech_token, unsigned long ul_mech_token_len,
          unsigned char* auc_mech_list_mic, unsigned long ul_mech_list_mic_len,
          char* adsl_spnego_token_handle, int& inp_token_len) {
    long  lo_token_length = 0L;
    long  lo_internal_token_length = 0L;
    unsigned char* auc_token_data = NULL;

    if (!m_is_valid_mech_oid(dsl_mech_type) ||
        !m_is_valid_context_flags(uc_context_flags)) {
        return SPNEGO_E_INVALID_PARAMETER;
    }

    // Get the actual token size
    int inl_ret = m_calc_min_spnego_init_token_size(ul_mech_token_len, ul_mech_list_mic_len,
                                                    dsl_mech_type, (uc_context_flags != 0L),
                                                    &lo_token_length, &lo_internal_token_length);
    if (inl_ret != SUCCESS) {
        return (inl_ret - 200);
    }
    if (lo_token_length > inp_token_len){
       return -99999;
    }

    // Allocate a buffer to hold the data.
#ifdef USE_WSP_HELPER
    auc_token_data = (unsigned char*)ads_wsp_helper->m_cb_get_memory((int)lo_token_length, true);
#else
    auc_token_data = (unsigned char*)calloc( 1, lo_token_length );
#endif


    if (NULL == auc_token_data) {
        return SPNEGO_E_OUT_OF_MEMORY;
    }

    // Now write the token
    inl_ret = m_create_spnego_init_token(dsl_mech_type, uc_context_flags,
                                         auc_mech_token, ul_mech_token_len,
                                         auc_mech_list_mic, ul_mech_list_mic_len,
                                         auc_token_data, lo_token_length,
                                         lo_internal_token_length);
    if (inl_ret != SUCCESS ) {
       free(auc_token_data);
        return (inl_ret - 400);
    }

    // Copy the binary token, set length and free used buffer
    memcpy(adsl_spnego_token_handle, auc_token_data, lo_token_length);
    inp_token_len = lo_token_length;
    free(auc_token_data);
    return SUCCESS;
}



/**
 * Initializes a SPNEGO_TOKEN_HANDLE for a NegTokenTarg type from the supplied parameters.
 * uc_context_flags may be 0 or must be a valid flag combination. MechToken data can be NULL - if not, it
 * must correspond to the dsl_mech_type. MechListMIC can also be NULL.
 * Returned data structure must be freed by calling m_spnego_free_data().
 *
 * @param[in] dsl_mech_type  dsl_mech_type to specify in MechTypeList element.
 * @param[in] dsl_spnego_neg_result  NegResult value.
 * @param[in] auc_mech_token  Pointer to response MechToken Data.
 * @param[in] ul_mech_token_len Length of MechToken Data.
 * @param[in] auc_mech_list_mic  Pointer to binary MechListMIC Data.
 * @param[in] ul_mech_list_mic_len Length of MechListMIC Data.
 * @param[out] adsl_spnego_token_handle SPNEGO_TOKEN_HANDLE pointer.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_create_neg_token_targ(SPNEGO_MECH_OID dsl_mech_type, SPNEGO_NEGRESULT dsl_spnego_neg_result,
          unsigned char* auc_mech_token, unsigned long ul_mech_token_len,
          unsigned char* auc_mech_list_mic, unsigned long ul_mech_list_mic_len,
          SPNEGO_TOKEN_HANDLE* adsl_spnego_token_handle) {
   int   inl_ret = SPNEGO_E_INVALID_PARAMETER;
   long  lo_token_length = 0L;
   long  lo_internal_token_length = 0L;
   unsigned char* auc_token_data = NULL;
   SPNEGO_TOKEN** aadsl_spnego_token = (SPNEGO_TOKEN**) adsl_spnego_token_handle;

   // ien_spnego_mech_oid_not_used and ien_spnego_negresult_not_used
   // are okay here, however a valid MechOid is required
   // if ien_spnego_negresult_success or ien_spnego_negresult_incomplete is specified.
   if ( NULL != aadsl_spnego_token &&
        ( m_is_valid_mech_oid( dsl_mech_type ) || ien_spnego_mech_oid_not_used == dsl_mech_type ) &&
        ( m_is_valid_neg_result( dsl_spnego_neg_result ) || ien_spnego_negresult_not_used == dsl_spnego_neg_result ) &&
        !( !m_is_valid_mech_oid( dsl_mech_type ) && ( ien_spnego_negresult_success == dsl_spnego_neg_result ||
              ien_spnego_negresult_incomplete == dsl_spnego_neg_result ) ) )   {
      // Get the actual token size
      if ( ( inl_ret = m_calc_min_spnego_targ_token_size( dsl_mech_type, dsl_spnego_neg_result, ul_mech_token_len,
                                                         ul_mech_list_mic_len, &lo_token_length,
                                                         &lo_internal_token_length ) )
                        == SUCCESS ) {
         // Allocate a buffer to hold the data.
#ifdef USE_WSP_HELPER
         auc_token_data = (unsigned char*)ads_wsp_helper->m_cb_get_memory((int)lo_token_length, true);
#else
         auc_token_data = (unsigned char*)calloc( 1, lo_token_length );
#endif

         if ( NULL != auc_token_data ) {
            // Now write the token
            if ( ( inl_ret = m_create_spnego_targ_token( dsl_mech_type,
                                                 dsl_spnego_neg_result, auc_mech_token,
                                                 ul_mech_token_len, auc_mech_list_mic,
                                                 ul_mech_list_mic_len, auc_token_data,
                                                 lo_token_length, lo_internal_token_length ) )
                              == SUCCESS ) {

               // This will copy our allocated pointer, and ensure that the sructure cleans
               // up the data later
               inl_ret = m_init_token_from_binary( SPNEGO_TOKEN_INTERNAL_COPYPTR,
                                             SPNEGO_TOKEN_INTERNAL_FLAGS_FREEDATA,
                                             auc_token_data, lo_token_length, aadsl_spnego_token );

            }

            // Cleanup on failure
            if ( SUCCESS != inl_ret ) {
#ifdef USE_WSP_HELPER
               ads_wsp_helper->m_cb_free_memory(auc_token_data);
#else
               free( auc_token_data );
#endif
            }
         }  // IF alloc succeeded
         else {
            inl_ret = SPNEGO_E_OUT_OF_MEMORY;
         }
      }  // If calculated token size
   }  // IF Valid Parameters

   return inl_ret;
}



/**
 * Copies binary SPNEGO token data from dsl_spnego_token_handle into the user
 * supplied buffer.  If auc_token_data is NULL, or the value in aul_data_len
 * is too small, the function will return SPNEGO_E_BUFFER_TOO_SMALL and
 * fill out aul_data_len with the minimum required buffer size.
 *
 * @param[in] dsl_spnego_token_handle Initialized SPNEGO_TOKEN_HANDLE.
 * @param[out] auc_token_data Buffer to copy token into.
 * @param[in/out] aul_data_len  Length of auc_token_data buffer, filled out with actual size used upon function return.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_token_get_binary(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_token_data,
                           unsigned long * aul_data_len) {
   int   inl_ret = SPNEGO_E_INVALID_PARAMETER;
   SPNEGO_TOKEN*  ads_spnego_token = (SPNEGO_TOKEN*) dsl_spnego_token_handle;

   // Check parameters - auc_token_data is optional
   if (  m_is_valid_spnego_token( ads_spnego_token ) &&
         NULL != aul_data_len ) {

      // Check for Buffer too small conditions
      if ( NULL == auc_token_data ||
            ads_spnego_token->ul_binary_data_len > *aul_data_len ) {
         *aul_data_len = ads_spnego_token->ul_binary_data_len;
         inl_ret = SPNEGO_E_BUFFER_TOO_SMALL;
      }
      else {
         memcpy( auc_token_data, ads_spnego_token->auc_binary_data, ads_spnego_token->ul_binary_data_len );
         *aul_data_len = ads_spnego_token->ul_binary_data_len;
         inl_ret = SUCCESS;
      }
   }  // IF parameters OK

   return inl_ret;
}



/**
 * Frees up resources consumed by dsl_spnego_token_handle.  The supplied data
 * pointer is invalidated by this function.
 *
 * @param[in] dsl_spnego_token_handle Initialized SPNEGO_TOKEN_HANDLE.
 * @return void
*/
void ds_spnego_krb::m_spnego_free_data(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle) {
   m_free_spnego_token( (SPNEGO_TOKEN*) dsl_spnego_token_handle);
   return;
}



/**
 * The function will analyze dsl_spnego_token_handle and return the appropriate
 * type in piTokenType.
 *
 * @param[in] dsl_spnego_token_handle Initialized SPNEGO_TOKEN_HANDLE.
 * @param[out] piTokenType Filled out with token type value.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_get_token_type(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, int * piTokenType) {
   SPNEGO_TOKEN*  ads_spnego_token = (SPNEGO_TOKEN*) dsl_spnego_token_handle;

   if (  m_is_valid_spnego_token( ads_spnego_token ) &&
         NULL != piTokenType &&
         ads_spnego_token) {
      // Check that the type in the structure makes sense
      if (SPNEGO_TOKEN_INIT == ads_spnego_token->in_token_type ||
          SPNEGO_TOKEN_TARG == ads_spnego_token->in_token_type) {
         *piTokenType = ads_spnego_token->in_token_type;
         return SUCCESS;
      }
   }  // IF parameters OK

   return SPNEGO_E_INVALID_PARAMETER;
}



/**
 * dsl_spnego_token_handle must reference a token of type NegTokenInit. The
 * function will search the MechTypeList element for an OID corresponding
 * to the specified MechOID.  If one is found, the index (0 based) will
 * be passed into the ain_mech_type_index parameter.
 * -> Returns the Initial Mech Type in the MechList element in the NegInitToken.
 *
 * @param[in] dsl_spnego_token_handle Initialized SPNEGO_TOKEN_HANDLE.
 * @param[in] dsl_mech_oid MechOID to search MechTypeList for
 * @param[out] ain_mech_type_index Filled out with index in MechTypeList element if MechOID is found.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_is_mech_type_available(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, SPNEGO_MECH_OID dsl_mech_oid, int * ain_mech_type_index) {
   int   inl_ret = SPNEGO_E_INVALID_PARAMETER;
   SPNEGO_TOKEN*  ads_spnego_token = (SPNEGO_TOKEN*) dsl_spnego_token_handle;

   // Check parameters
   if (m_is_valid_spnego_token( ads_spnego_token ) &&
       NULL != ain_mech_type_index &&
       m_is_valid_mech_oid( dsl_mech_oid ) &&
       SPNEGO_TOKEN_INIT == ads_spnego_token->in_token_type) {

      // Check if MechList is available
      if ( ads_spnego_token->dsr_element_array[SPNEGO_INIT_MECHTYPES_ELEMENT].in_element_present
            == SPNEGO_TOKEN_ELEMENT_AVAILABLE ) {
         // Locate the MechOID in the list element
         inl_ret = m_find_mech_oid_in_mech_list(
                     &ads_spnego_token->dsr_element_array[SPNEGO_INIT_MECHTYPES_ELEMENT],
                     dsl_mech_oid, ain_mech_type_index );
      }
      else {
         inl_ret = SPNEGO_E_ELEMENT_UNAVAILABLE;
      }
   }  // IF parameters OK

   return inl_ret;
}



/**
 * dsl_spnego_token_handle must reference a token of type NegTokenInit.  The
 * function will copy data from the ContextFlags element into the
 * location auc_context_flags points to.  Note that the function will
 * fail if the actual ContextFlags data appears invalid.
 *
 * @param[in] dsl_spnego_token_handle Initialized SPNEGO_TOKEN_HANDLE.
 * @param[out] auc_context_flags Filled out with ContextFlags value.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_get_context_flags(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_context_flags) {
   int   inl_ret = SPNEGO_E_INVALID_PARAMETER;
   SPNEGO_TOKEN*  ads_spnego_token = (SPNEGO_TOKEN*) dsl_spnego_token_handle;

   // Check parameters
   if (m_is_valid_spnego_token( ads_spnego_token ) &&
       NULL != auc_context_flags &&
       SPNEGO_TOKEN_INIT == ads_spnego_token->in_token_type) {

      // Check if ContextFlags is available
      if ( ads_spnego_token->dsr_element_array[SPNEGO_INIT_REQFLAGS_ELEMENT].in_element_present
            == SPNEGO_TOKEN_ELEMENT_AVAILABLE ) {
         // The length should be two, the value should show a 1 bit difference in the difference byte, and
         // the value must be valid
         if ( ads_spnego_token->dsr_element_array[SPNEGO_INIT_REQFLAGS_ELEMENT].ul_data_length == SPNEGO_NEGINIT_MAXLEN_REQFLAGS &&
               ads_spnego_token->dsr_element_array[SPNEGO_INIT_REQFLAGS_ELEMENT].auc_data[0] == SPNEGO_NEGINIT_REQFLAGS_BITDIFF &&
               m_is_valid_context_flags( ads_spnego_token->dsr_element_array[SPNEGO_INIT_REQFLAGS_ELEMENT].auc_data[1] ) ) {
            *auc_context_flags = ads_spnego_token->dsr_element_array[SPNEGO_INIT_REQFLAGS_ELEMENT].auc_data[1];
            inl_ret = SUCCESS;
         }
         else {
            inl_ret = SPNEGO_E_INVALID_ELEMENT;
         }
      }
      else {
         inl_ret = SPNEGO_E_ELEMENT_UNAVAILABLE;
      }

   }  // IF parameters OK

   return inl_ret;
}



/**
 * dsl_spnego_token_handle must reference a token of type NegTokenInit.  The
 * function will copy data from the NegResult element into the
 * location pointed to by adsl_neg_result.  Note that the function will
 * fail if the actual NegResult data appears invalid.
 *
 * @param[in] dsl_spnego_token_handle Initialized SPNEGO_TOKEN_HANDLE.
 * @param[out] adsl_neg_result Filled out with NegResult value.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_get_negotiation_result(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, SPNEGO_NEGRESULT* adsl_neg_result) {
   int   inl_ret = SPNEGO_E_INVALID_PARAMETER;
   SPNEGO_TOKEN*  ads_spnego_token = (SPNEGO_TOKEN*) dsl_spnego_token_handle;

   // Check parameters
   if (m_is_valid_spnego_token( ads_spnego_token ) &&
       NULL != adsl_neg_result &&
       SPNEGO_TOKEN_TARG == ads_spnego_token->in_token_type) {
      // Check if NegResult is available
      if ( ads_spnego_token->dsr_element_array[SPNEGO_TARG_NEGRESULT_ELEMENT].in_element_present
            == SPNEGO_TOKEN_ELEMENT_AVAILABLE ) {
         // Must be 1 byte long and a valid value
         if ( ads_spnego_token->dsr_element_array[SPNEGO_TARG_NEGRESULT_ELEMENT].ul_data_length == SPNEGO_NEGTARG_MAXLEN_NEGRESULT &&
               m_is_valid_neg_result( (SPNEGO_NEGRESULT) *ads_spnego_token->dsr_element_array[SPNEGO_TARG_NEGRESULT_ELEMENT].auc_data ) ) {
            *adsl_neg_result = (SPNEGO_NEGRESULT)*ads_spnego_token->dsr_element_array[SPNEGO_TARG_NEGRESULT_ELEMENT].auc_data;
            inl_ret = SUCCESS;
         }
         else {
            *adsl_neg_result = (SPNEGO_NEGRESULT)*ads_spnego_token->dsr_element_array[SPNEGO_TARG_NEGRESULT_ELEMENT].auc_data; // JF 20.05.10: return the read value in this case (to write it to log).
            inl_ret = SPNEGO_E_INVALID_ELEMENT;
         }
      }
      else {
         inl_ret = SPNEGO_E_ELEMENT_UNAVAILABLE;
      }
   }  // IF parameters OK

   return inl_ret;
}



/**
 * dsl_spnego_token_handle must reference a token of type NegTokenInit.  The
 * function will check the Supported dsl_mech_type element, and if it
 * corresponds to a supported dsl_mech_type ( ien_spnego_mech_oid_kerberos_v5_legacy
 * or ien_spnego_mech_oid_kerberos_v5 ), will set the location pointed
 * to by adsl_mech_oid equal to the appropriate value.
 *
 * @param[in] dsl_spnego_token_handle Initialized SPNEGO_TOKEN_HANDLE.
 * @param[out] adsl_mech_oid Filled out with Supported dsl_mech_type value.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_get_supported_mech_type(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, SPNEGO_MECH_OID* adsl_mech_oid) {
   int   inl_ret = SPNEGO_E_INVALID_PARAMETER;
   int   in_idx = 0L;
   long  lo_length = 0L;
   SPNEGO_TOKEN*  ads_spnego_token = (SPNEGO_TOKEN*) dsl_spnego_token_handle;

   // Check parameters
   if (m_is_valid_spnego_token( ads_spnego_token ) &&
       NULL != adsl_mech_oid &&
       SPNEGO_TOKEN_TARG == ads_spnego_token->in_token_type) {
      // Check if MechList is available
      if ( ads_spnego_token->dsr_element_array[SPNEGO_TARG_SUPPMECH_ELEMENT].in_element_present
            == SPNEGO_TOKEN_ELEMENT_AVAILABLE ) {
         for ( in_idx = 0;
               inl_ret != SUCCESS &&
               dsg_parse_der.m_get_from_mech_oid_list((SPNEGO_MECH_OID)in_idx).ds_mech_oid != ien_spnego_mech_oid_not_used;
               in_idx++ ) {
             if ( ( inl_ret = dsg_parse_der.m_asn_der_check_oid(
                        ads_spnego_token->dsr_element_array[SPNEGO_TARG_SUPPMECH_ELEMENT].auc_data,
                        (SPNEGO_MECH_OID)in_idx,
                        ads_spnego_token->dsr_element_array[SPNEGO_TARG_SUPPMECH_ELEMENT].ul_data_length,
                        &lo_length ) ) == SUCCESS ) {
               *adsl_mech_oid = (SPNEGO_MECH_OID)in_idx;
            }
         }  // For enum MechOIDs
      }
      else {
         inl_ret = SPNEGO_E_ELEMENT_UNAVAILABLE;
      }
   }  // IF parameters OK

   return inl_ret;
}



/**
 * dsl_spnego_token_handle can point to either NegTokenInit or a NegTokenTarg token.
 * The function will copy the MechToken (the initial MechToken if
 * NegTokenInit, the response MechToken if NegTokenTarg) from the
 * underlying token into the buffer pointed to by auc_token_data.  If
 * auc_token_data is NULL, or the value in aul_data_len is too small, the
 * function will return SPNEGO_E_BUFFER_TOO_SMALL and fill out aul_data_len
 * with the minimum required buffer size.  The token can then be passed
 * to a GSS-API function for processing.
 *
 * @param[in] dsl_spnego_token_handle Initialized SPNEGO_TOKEN_HANDLE.
 * @param[out] auc_token_data Buffer to copy MechToken into.
  * @param[in/out] aul_data_len Length of auc_token_data buffer, filled out with actual size used upon function return.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_get_mech_token(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_token_data, unsigned long* aul_data_len) {
   int   inl_ret = SPNEGO_E_INVALID_PARAMETER;
   SPNEGO_TOKEN*  ads_spnego_token = (SPNEGO_TOKEN*) dsl_spnego_token_handle;
   SPNEGO_ELEMENT*   ads_spnego_element = NULL;

   // Check parameters
   if (  m_is_valid_spnego_token( ads_spnego_token ) && NULL != aul_data_len ) {
      // Point at the proper Element
      if (SPNEGO_TOKEN_INIT == ads_spnego_token->in_token_type) {
         ads_spnego_element = &ads_spnego_token->dsr_element_array[SPNEGO_INIT_MECHTOKEN_ELEMENT];
      }
      else {
         ads_spnego_element = &ads_spnego_token->dsr_element_array[SPNEGO_TARG_RESPTOKEN_ELEMENT];
      }

      // Check if dsl_mech_type is available
      if ( SPNEGO_TOKEN_ELEMENT_AVAILABLE == ads_spnego_element->in_element_present ) {
         // Check for Buffer too small conditions
         if ( NULL == auc_token_data || ads_spnego_element->ul_data_length > *aul_data_len ) {
            *aul_data_len = ads_spnego_element->ul_data_length;
            inl_ret = SPNEGO_E_BUFFER_TOO_SMALL;
         }
         else {
            memcpy(auc_token_data, ads_spnego_element->auc_data, ads_spnego_element->ul_data_length);
            *aul_data_len = ads_spnego_element->ul_data_length;
            inl_ret = SUCCESS;
         }
      }
      else {
         inl_ret = SPNEGO_E_ELEMENT_UNAVAILABLE;
      }
   }  // IF parameters OK

   return inl_ret;
}



/**
 * dsl_spnego_token_handle can point to either NegTokenInit or a NegTokenTarg token.
 * The function will copy the MechListMIC data from the underlying token
 * into the buffer pointed to by auc_mic_data.  If auc_mic_data is NULL,
 * or the value in aul_data_len is too small, the function will return
 * SPNEGO_E_BUFFER_TOO_SMALL and fill out aul_data_len with the minimum
 * required buffer size.
 *
 * @param[in] dsl_spnego_token_handle Initialized SPNEGO_TOKEN_HANDLE.
 * @param[out] auc_mic_data Buffer to copy MechListMIC data into.
 * @param[in/out] aul_data_len Length of auc_token_data buffer, filled out with actual size used upon function return.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_krb::m_spnego_get_mech_list_mic(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_mic_data, unsigned long* aul_data_len) {
   int   inl_ret = SPNEGO_E_INVALID_PARAMETER;
   SPNEGO_TOKEN*  ads_spnego_token = (SPNEGO_TOKEN*) dsl_spnego_token_handle;
   SPNEGO_ELEMENT*   ads_spnego_element = NULL;

   // Check parameters
   if ( m_is_valid_spnego_token( ads_spnego_token ) &&     NULL != aul_data_len ) {
      // Point at the proper Element
      if (SPNEGO_TOKEN_INIT == ads_spnego_token->in_token_type) {
         ads_spnego_element = &ads_spnego_token->dsr_element_array[SPNEGO_INIT_MECHLISTMIC_ELEMENT];
      }
      else {
         ads_spnego_element = &ads_spnego_token->dsr_element_array[SPNEGO_TARG_MECHLISTMIC_ELEMENT];
      }

      // Check if dsl_mech_type is available
      if ( SPNEGO_TOKEN_ELEMENT_AVAILABLE == ads_spnego_element->in_element_present ) {
         // Check for Buffer too small conditions
         if ( NULL == auc_mic_data || ads_spnego_element->ul_data_length > *aul_data_len ) {
            *aul_data_len = ads_spnego_element->ul_data_length;
            inl_ret = SPNEGO_E_BUFFER_TOO_SMALL;
         }
         else {
            memcpy( auc_mic_data, ads_spnego_element->auc_data, ads_spnego_element->ul_data_length );
            *aul_data_len = ads_spnego_element->ul_data_length;
            inl_ret = SUCCESS;
         }
      }
      else {
         inl_ret = SPNEGO_E_ELEMENT_UNAVAILABLE;
      }
   }  // IF parameters OK

   return inl_ret;
}

using namespace std;
#ifndef HL_KRB5_WSP_ACTIV
struct dsd_hco_wothr {};
struct dsd_aux_cf1 {};
struct dsd_aux_krb5_sign_on_1 {};
#endif
struct dsd_config_pw {
    char * ach_princi_name;
    char * ach_passwd;
    char * ach_new_passwd;
    char * ach_default_realm;
    char * ach_server;
    void * a_kdc_ip_address;
    int im_kdc_port;
    int im_kdc_pw_change_port;
    int im_max_retries;
    int im_fcache_version;
    int im_max_skew;
    int im_max_ticket_size;
    void ** aa_memory_area;
    void ** aa_temp_memory_area;
    void * a_tracer;
    int in_trace_lvl;
    void * a_ip_address_context;
    int im_timeout;
};

struct dsd_aux_krb5_mit_to_heim {               /* Kerberos Keytab conversion */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
   char       *achc_mit_data;               /* input data (\0-terminated) */
   int        imc_mit_data_len;             /* length of input data */
   char       *achc_heim_data_buffer;         /* output buffer for Heimdal kt data */
   int        imc_heim_buffer_len;           /* length output buffer for kt data */
   int        imc_heim_len_ret;              /* returned length of kt data */
   struct dsd_unicode_string dsc_password;  /* Password for keydump*/
   struct dsd_unicode_string dsc_realm;  /* Keytab realm */
};


struct dsd_memory_traces {
    const void ** aa_memory_area;     /*pointer to memory areas*/
    int* ain_mem_len;           /*length of the memory areas*/
    char** aach_mem_names;      /*names of the memory areas*/
    int in_mem_count;           /*number of memory areas*/
};

struct dsd_krb_error_msg {
    char ch_msg_tag;            /*tag for the trace message*/
    int in_error_code;          /*error code*/
    char* ach_error_msg;        /*message string for the error code*/
};

struct dsd_aux_stor_header {                /* Auxiliary Header        */
    struct dsd_aux_stor_header *adsc_next;   /* address next in chain   */
    unsigned int umc_length;                 /* length including header */
    unsigned int umc_no_ele;                 /* number of elements      */
    unsigned int umc_len_gap;                /* maximum length gap      */
};

struct dsd_aux_krb5_se_req_acc_1 {           /* Kerberos accept AP REQ */
    enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
    void *     vpc_handle;                   /* handle returned         */
    struct dsd_krb5_kdc_1 *adsp_krb5_kdc_1;  /* KDC information         */
    struct dsd_aux_krb5_sign_on_1 *adsc_server;  /* Server Principal data */
    char       *achc_in_buffer;          /* in buffer for GSS AP REQ token */
    int        imc_in_buffer_len;        /* length in buffer for GSS AP REQ tokens */
    char       *achc_out_buffer;          /* out buffer for GSS AP REP token */
    int        imc_out_buffer_len;        /* length out buffer for GSS AP REP tokens */
    BOOL       boc_check_replay;          /* Flag for replay cache */
    BOOL       boc_error_token;           /* Flag if error token was generated */
};

/* Header structure for replay cache. followed by the entries, forming a binary tree */
struct dsd_krb5_rep_c_header {
    HL_LONGLONG retention_time;             /*time until which the cache has to be kept*/
    int im_len;                             /*total number of entries following this header*/
    int im_max_len;                         /*highest possible number of entries*/
    int im_time_skew;                       /*time skew applied to this cache*/
};

struct dsd_krb5_rep_c_entry {    /* entry for krb5 replay cache */
    unsigned char vorc_auth_hash[20];            /* Hash value of the entry */  //Todo: Unsigned
    int imc_left_index;                 /* Index of the left child. -1 for no child */
    int imc_right_index;                /* Index of the right child. -1 for no child */
};

class krb5_tracer;

extern "C" {
    int m_get_tgt( struct dsd_config_tgt       * ads_conf );
    int m_get_ticket( struct dsd_config_ticket    * ads_conf );
    void m_aux_stor_start( void **aap_anchor );
    void m_aux_stor_end( void **aap_anchor );
    void m_aux_stor_free( void **aap_anchor, void *ap_free );
    void * m_aux_stor_alloc( void **aap_anchor              , int implen );
    void * m_aux_stor_realloc( void **aap_anchor, void *ap_old, int implen );

    int m_init_sec_context_client( struct dsd_heimdal_context*,const e_krb5_flags );
    int m_init_sec_context_server( struct dsd_heimdal_context*, dsd_config_server* );
    int m_init_krb5_context( struct dsd_heimdal_context*,
    struct dsd_config_server_client*,void* );
    int m_krb5_data_free( struct dsd_heimdal_context*,krb5_data* );
    int m_gss_encapsulate( struct dsd_heimdal_context*,krb5_data*,krb5_data*,const char* );
    int m_gss_decapsulate( struct dsd_heimdal_context*,krb5_data*,krb5_data*,const char*,const char* );
    int m_gss_wrap( struct dsd_heimdal_context*,krb5_data*,krb5_data* );
    int m_gss_unwrap( struct dsd_heimdal_context*,krb5_data*,krb5_data* );
    int m_change_pw( struct dsd_config_pw* );
    int m_enter_cs();
    int m_leave_cs();
    void m_krb5_trace( krb5_tracer*, char, int, struct dsd_memory_traces*, void**, char*, ... );
    void m_krb5_sha1( const void *data, size_t len, void *dest, void **aa_temp_memory );
    void m_krb5_trace_memcat( void ** aa_temp_memory, struct dsd_memory_traces* dsp_trace, void* ap_memory_area, int inp_mem_length, char* achp_mem_name );
    struct dsd_memory_traces* m_init_krb5_mem_trace( void ** aa_temp_memory );
    void m_free_krb5_mem_trace( void ** aa_temp_memory, struct dsd_memory_traces* adsl_trace );
    char* m_krb5_strcat( void** aap_memory_ptr, char* achl_dest, char* achl_src );
    BOOL m_cma_get_tgt_area(struct dsd_hl_aux_c_cma_1 *adsp_cma_1,
    struct dsd_aux_cf1 *adsp_aux_cf1,
    struct dsd_unicode_string *adsp_userid,
    struct dsd_unicode_string *adsp_usergroup,
        int imp_lock_type);
    int m_krb5_check_replay_cache( struct dsd_aux_cf1 *adsp_aux_cf1,
        const char* achp_service_principal_name,
        const void * avop_authenticator_hash,
        int imp_max_skew
        );
    struct dsd_krb5_rep_c_entry * m_create_replay_cache_entry (
        const struct krb5_authenticator * adsp_authenticator,
        const char* achp_next_entry,
        int imp_next_entry_len,
        void ** aa_memory_area
        );
    struct dsd_krb5_rep_c_header* m_create_replay_cache_header(
        const int* aimp_cache_list,
        int imp_clist_len,
        const char* achp_first_entry,
        int imp_first_entry_len,
        void ** aa_memory_area);
    void m_throw_exception(int inp_error_code);
    int m_krb5_mk_error(struct dsd_heimdal_context * ads_context_main, krb5_data** aadsp_out_buf, int inp_error_code );
    int mit_prop_dump(  const char *achp_keytab,
                    const char *achp_pw_salt,
                    const char *achp_pw,
                    char *achp_dest_buf,
                    size_t szp_dest_len,
                    void **aavop_mem_ptr);
    int m_get_gss_session_key(struct dsd_heimdal_context * adsp_context_main,
                              char* achp_out_buf,
                              int inp_out_len,
                              int* ainp_key_len);
}

int m_hl_inet_ntop4( const unsigned char *achrp_src, char *achrp_dst, int inp_len_dst );
int m_hl_inet_ntop6( const unsigned char *achrp_src, char *achrp_dst, int inp_len_dst );
dsd_hcla_critsect_1* m_init_critsect();
void m_hl_aux_stor_clear( void **aa_memory_ptr );

class Krb5_Heimdal;

dsd_hcla_critsect_1* adsg_heimdal_cs=m_init_critsect();

dsd_hcla_critsect_1* m_init_critsect()
{
    dsd_hcla_critsect_1* adsl_critsect=new dsd_hcla_critsect_1();
    adsl_critsect->m_create();
    return adsl_critsect;
}

void m_hl_aux_stor_clear( void *a_memory_ptr )
{
    struct dsd_aux_stor_header* ads_work_ptr=( struct dsd_aux_stor_header* )a_memory_ptr;
    while( ads_work_ptr!=NULL ) {
        memset( ads_work_ptr+1,0,ads_work_ptr->umc_length-sizeof( struct dsd_aux_stor_header ) );
        ads_work_ptr=ads_work_ptr->adsc_next;
    }
}//void m_hl_aux_stor_clear(void *a_memory_ptr);
/*
* Wrapper functions for calling critical section within Heimdal
*/

int m_enter_cs()
{
    return adsg_heimdal_cs->m_enter();
}

int m_leave_cs()
{
    return adsg_heimdal_cs->m_leave();
}

static const int ins_tracemsg_len = 384;


static int in_session_counter=0;
/**
*  Class for tracing the use of the Heimdal module depending on trace level
*
* @version  0.7
* @author   Stephan Schulze
* @date     2011/01/18
*
*/

class krb5_tracer
{
    int inc_session_nr;
    int inc_trace_lvl;
    struct dsd_krb5_kdc_1 * ads_kdc;
    const char* ach_prefix;
public:
    krb5_tracer( struct dsd_krb5_kdc_1 * adsp_kdc,
       int inp_trace_lvl = 1,
        char* achp_prefix="KRB" ) :
    inc_session_nr(0),
       inc_trace_lvl(inp_trace_lvl),
        ads_kdc(adsp_kdc),
        ach_prefix(achp_prefix){
            /*this->ads_kdc=adsp_kdc;
            this->ach_prefix=achp_prefix;*/

            m_enter_cs();
            this->inc_session_nr=in_session_counter;
            in_session_counter++;
            m_leave_cs();
    }//krb5_tracer(char* ach_conf_name, int in_trace_lvl, char* ach_kdc_ip, int in_kdc_port);

    /**
    *  Returns the currently set trace level.
    *
    *  @return The set trace level
    */

    int m_get_trace_lvl() {
        return inc_trace_lvl;
    }

    /**
    *  Creates a trace message and prints it with m_hlnew_printf().
    *
    *  @param char inp_trace_lvl_tag                   Tag for the trace level of the message
    *  @param int inp_msg_nr                           ID Number for the message
    *  @param struct dsd_memory_traces* ads_traces     Pointer to a set of memory blocks
    *  @param void** aap_memory_ptr                    Pointer to memory container
    *  @param char* achp_msg                           Format for additional parameters
    *  @param ...                                      Additional parameters
    */

    void m_trace( const char chp_trace_lvl_tag,
        const int inp_msg_nr,
        const struct dsd_memory_traces* ads_traces,
        void** aap_memory_ptr,
        const char* achp_msg,
        ... );

    /**
    *  Dumps the given memory area as formated string.
    *
    *  @param void* ap_memory_area     Address of the memory area
    *  @param void* inp_mem_len        Length of the memory area
    *  @param void** aap_memory_ptr    Pointer to memory container
    *  @return char*                   The dump as string
    */

    char* m_dump_memory( const void* ap_memory_area, int inp_mem_len, void** aap_memory_ptr );

};//class krb5_tracer

class Krb5_Heimdal_exception : public exception
{
   int inc_error_code;
public:
   Krb5_Heimdal_exception(int inp_error_code) :
      exception(),
         inc_error_code(inp_error_code)
      {}
      int mc_get_error_code() {return inc_error_code;}
      ~Krb5_Heimdal_exception() throw() {}
};


//-----------------------------------------------------------------------------
// Class Krb5_Heimdal
//-----------------------------------------------------------------------------

class Krb5_Heimdal
{
public:
   enum ERROR_CONTROL {
      NO_CONTROL_ERROR         = 0,
      NEXT_KDC                 = 1,
      NEXT_SERVER              = 2,
      HEIMDAL_CONTROL_ERROR    = 3,
      INTERNAL_HEIMDAL_ERROR   = 4,
      EXTERNAL_ERROR           = 5,
      DEFAULT_ERROR            = 6
   };
   Krb5_Heimdal() :
      a_tracer(NULL),
      ie_error(NO_CONTROL_ERROR),
      im_error_code(0),
      in_trace_lvl(0),
      ds_context_main(dsd_heimdal_context()),
      a_memory_area(NULL),
      a_temp_memory_area(NULL),
#ifdef WITHOUT_FILE
      a_ccache(( void* )0),
      im_length_ccache(0),
#endif
      boc_do_spnego(false)
   {
      m_aux_stor_start( &a_memory_area );
      m_aux_stor_start( &a_temp_memory_area );
      memset(&ds_context_main,0,sizeof(dsd_heimdal_context));
   }
#ifdef WITHOUT_FILE
   Krb5_Heimdal( void * a_old_ccache, int im_length_old_ccache ) :
      a_tracer(NULL),
      ie_error(NO_CONTROL_ERROR),
      im_error_code(0),
      in_trace_lvl(0),
      ds_context_main(dsd_heimdal_context()),
      a_memory_area(NULL),
      a_temp_memory_area(NULL),
      a_ccache(( void* )0),
      im_length_ccache(im_length_old_ccache),
      boc_do_spnego(false)
   {
      m_aux_stor_start( &a_memory_area );
      m_aux_stor_start( &a_temp_memory_area );
      memset(&ds_context_main,0,sizeof(dsd_heimdal_context));
      a_ccache        = m_aux_stor_alloc( &a_memory_area, im_length_ccache );
      memcpy( a_ccache,a_old_ccache,im_length_ccache );
   }
#endif
   ~Krb5_Heimdal() {
#ifdef WITHOUT_FILE
      m_del_ccache();
#endif
      m_hl_aux_stor_clear(a_temp_memory_area);
      m_hl_aux_stor_clear(a_memory_area);
      m_aux_stor_end( &a_temp_memory_area );
      m_aux_stor_end( &a_memory_area );
      delete a_tracer;
   }

   void m_invalidate(void){ ie_error = DEFAULT_ERROR;}

   int m_get_cred( struct dsd_aux_cf1            * adsp_aux_cf1,
   struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
   struct dsd_krb5_kdc_1         * ads_conf,
   struct dsd_unicode_string * ads_user_name  = NULL,
   struct dsd_unicode_string * ads_user_group = NULL,
   struct dsd_unicode_string * ads_password   = NULL,
   struct dsd_unicode_string * ads_serv_name  = NULL );
   int m_krb5_data_free( struct dsd_aux_cf1            * adsp_aux_cf1,
   struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
      krb5_data * ads_data );
   int m_init_krb5_context( struct dsd_aux_cf1            * adsp_aux_cf1,
   struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
      krb5_data * ads_init_data,
      const e_krb5_flags ap_req_options );
   int m_init_krb5_context(
   struct dsd_aux_cf1            * adsp_aux_cf1,
   struct dsd_aux_krb5_se_ti_check_1 * adsp_check_param,
      krb5_data * ads_init_data,
      krb5_data ** aads_out);
   int m_init_krb5_context(struct dsd_krb5_kdc_1* ads_conf,
      struct dsd_unicode_string* ads_user_name, const e_krb5_flags ap_req_options,
      krb5_data ** aads_out );
   int m_gss_encapsulate( struct dsd_aux_cf1* adsp_aux_cf1,
   struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
      krb5_data * ads_krb5_token,
      krb5_data * ads_gss_token,
      const char* ach_tok_id );
   int m_gss_decapsulate( struct dsd_aux_cf1* adsp_aux_cf1,
   struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
      krb5_data * ads_krb5_token,
      krb5_data * ads_gss_token,
      const char* ach_tok_id,
      const char* ach_tok_id_2 );
   int m_gss_wrap( struct dsd_aux_cf1* adsp_aux_cf1,
   struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
      krb5_data * ads_inbuf,
      krb5_data * ads_outbuf );
   int m_gss_unwrap( struct dsd_aux_cf1* adsp_aux_cf1,
   struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
      krb5_data * ads_inbuf,
      krb5_data * ads_outbuf );
   int m_krb5_change_pw(struct dsd_aux_cf1* adsp_aux_cf1,
                        struct dsd_krb5_kdc_1* ads_conf,
                        struct dsd_krb5_kdc_server* ads_kdc_server,
                        struct dsd_unicode_string * ads_user_name,
                        struct dsd_unicode_string * ads_password,
                        struct dsd_unicode_string * ads_new_password);

   int m_gss_get_session_key(struct dsd_aux_krb5_get_session_key* adsp_get_session_key);

   ERROR_CONTROL m_get_error_type() {
      return ie_error;
   }
   signed long  m_get_error_code() {
      return im_error_code;
   }
   krb5_tracer* m_get_tracer() {
      return a_tracer;
   }
   void m_set_tracer( krb5_tracer* ap_tracer ) {
      if( a_tracer!=NULL ) {
         delete( a_tracer );
      }
      a_tracer=ap_tracer;
      if( ap_tracer!=NULL ) {
         in_trace_lvl=ap_tracer->m_get_trace_lvl();
      } else {
         in_trace_lvl=0;
      }
   }
   int m_get_trace_lvl() {return in_trace_lvl;}
   void m_set_do_spnego(bool bop_new_val) { boc_do_spnego = bop_new_val; }
   bool m_do_spnego(void) { return boc_do_spnego; }
private:
   krb5_tracer * a_tracer;
   ERROR_CONTROL ie_error;
   signed long  im_error_code;
   int in_trace_lvl;
   struct dsd_heimdal_context ds_context_main;
   void * a_memory_area;
   void * a_temp_memory_area;
#ifdef WITHOUT_FILE
   void * a_ccache;
   int im_length_ccache;
   bool boc_do_spnego;
   void m_del_ccache() {
      if( a_ccache ) {
         memset( a_ccache,'\0',im_length_ccache );
         m_aux_stor_free( &a_memory_area, a_ccache );
         a_ccache        = ( void* )0;
         im_length_ccache = 0;
      }
   }
#endif
   void m_get_tgt( struct dsd_aux_cf1            * adsp_aux_cf1,
   struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
   struct dsd_krb5_kdc_1         * ads_conf,
   struct dsd_krb5_kdc_server* ads_kdc_server,
   struct dsd_unicode_string * ads_user_name,
   struct dsd_unicode_string * ads_password,
   struct dsd_unicode_string * ads_serv_name  = NULL );
   char * m_get_principal_utf8_0_terminated( struct dsd_unicode_string * ads_user_name );
   char * m_get_default_realm_0_terminated( struct dsd_krb5_kdc_1 * ads_conf );
   char * m_get_password_0_terminated( struct dsd_unicode_string * ads_password );
   void m_get_string_utf8_0_terminated( struct dsd_unicode_string * ads_string,
   struct dsd_unicode_string * ads_new_string );
   void * m_get_IP( struct dsd_krb5_kdc_server * ads_kdc_server, void ** aa_ip_context );
   void m_parse_name_w( char**,char**,char***,int*,int*,int*,char** );
   void m_parse_name( char*,char**,char**,char***,int* );
   void m_reset_temporary_memory();
};

//-----------------------------------------------------------------------------
// Class Krb5_Heimdal public methods
//-----------------------------------------------------------------------------

int Krb5_Heimdal::m_gss_get_session_key(struct dsd_aux_krb5_get_session_key* adsp_get_session_key)
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   int inl_ret = m_get_gss_session_key(&ds_context_main, adsp_get_session_key->achc_key_buffer,
      adsp_get_session_key->imc_key_buffer_len, &(adsp_get_session_key->imc_key_len_ret));
   switch(inl_ret){
      case 0:
         adsp_get_session_key->iec_ret_krb5 = ied_ret_krb5_ok;
         break;
      case -1:
         adsp_get_session_key->iec_ret_krb5 = ied_ret_krb5_buf_too_sm;
         break;
      case -2:
         ie_error = INTERNAL_HEIMDAL_ERROR;
         im_error_code = KRB5KRB_AP_ERR_NOKEY;
         return INTERNAL_HEIMDAL_ERROR;
      default:
         ie_error = HEIMDAL_CONTROL_ERROR;
         im_error_code = 0;
         return HEIMDAL_CONTROL_ERROR;
   }

   return inl_ret;
}

int Krb5_Heimdal::m_init_krb5_context(
                                 struct dsd_aux_cf1            * adsp_aux_cf1,
                                 struct dsd_aux_krb5_se_ti_check_1 * adsp_check_param,
                                 krb5_data * ads_init_data,
                                 krb5_data ** aads_out)
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }

   *aads_out                = NULL;
   signed long int il_ret   = 0;
   void * a_ip_context = NULL;
   char* achl_principal_name_ptr;
   int inl_principal_name_len;
   struct dsd_config_server ds_serv = {
      adsp_check_param->imc_clock_skew,            //max_skew
      adsp_check_param->achc_keytab,                  //keytab
      adsp_check_param->imc_len_keytab,               //length of keytab
      ads_init_data,
      aads_out,
      &a_temp_memory_area                 //temporary memory
      ,
      &a_memory_area             //memory_area
      ,
      a_tracer                           //tracer
      ,
      in_trace_lvl        //trace level
      ,
      a_ip_context,              //ip_context
   };
   if(!((*ds_serv.achc_keytab == 0x05) && (*(ds_serv.achc_keytab+1) == 0x02)) &&
      (*(ds_serv.achc_keytab + ds_serv.inc_keytab_len -1) != 0)){
         /* Heimdal Keytab without 0-termination, generate 0-terminated version */
         ds_serv.inc_keytab_len++;
         ds_serv.achc_keytab = (char*)m_aux_stor_alloc(&a_temp_memory_area,ds_serv.inc_keytab_len);
         memcpy(ds_serv.achc_keytab,adsp_check_param->achc_keytab,adsp_check_param->imc_len_keytab);
         ds_serv.achc_keytab[adsp_check_param->imc_len_keytab] = 0;
   }
   ds_context_main.ds_data_init_in.length = ads_init_data->length;
   ds_context_main.ds_data_init_in.data   = ads_init_data->data;
   try{
      il_ret = ::m_init_sec_context_server( &ds_context_main, &ds_serv );
      if( ds_context_main.ds_data_init_out.data )
         *aads_out = &( ds_context_main.ds_data_init_out );
      if( il_ret ) {
         im_error_code = il_ret;
         ie_error = INTERNAL_HEIMDAL_ERROR;
         return il_ret;
      }
      if(adsp_aux_cf1){ /** @todo implement switch for replay cache */
         il_ret=::m_krb5_check_replay_cache( adsp_aux_cf1,
            ds_context_main.ach_service,
            ds_context_main.a_gen_ptr,
            adsp_check_param->imc_clock_skew
            );
         if(il_ret){
            im_error_code = il_ret;
            if( KRB5KRB_AP_ERR_REPEAT == il_ret ){
               ::m_krb5_mk_error( &ds_context_main, aads_out, il_ret );
               ie_error = INTERNAL_HEIMDAL_ERROR;
            } else {
               ie_error = HEIMDAL_CONTROL_ERROR;
               *aads_out = NULL;
            }
            return il_ret;
            //Todo: actions at a detected replay?
         }
      }
      /* Copy the principal names and realms */
      achl_principal_name_ptr = strchr((char*)ds_context_main.ach_hostname, '@');
      inl_principal_name_len = achl_principal_name_ptr - ds_context_main.ach_hostname;
      adsp_check_param->dsc_ucs_princ_client.imc_len_str = inl_principal_name_len;
      adsp_check_param->dsc_ucs_princ_client.iec_chs_str = ied_chs_utf_8;
      adsp_check_param->dsc_ucs_princ_client.ac_str = malloc(inl_principal_name_len);
      memcpy(adsp_check_param->dsc_ucs_princ_client.ac_str,ds_context_main.ach_hostname, inl_principal_name_len);

      achl_principal_name_ptr++;
      inl_principal_name_len = strlen(achl_principal_name_ptr);
      adsp_check_param->dsc_ucs_realm_client.imc_len_str = inl_principal_name_len;
      adsp_check_param->dsc_ucs_realm_client.iec_chs_str = ied_chs_utf_8;
      adsp_check_param->dsc_ucs_realm_client.ac_str = malloc(inl_principal_name_len);
      memcpy(adsp_check_param->dsc_ucs_realm_client.ac_str,achl_principal_name_ptr, inl_principal_name_len);

      achl_principal_name_ptr = strchr((char*)ds_context_main.ach_service, '@');
      inl_principal_name_len = achl_principal_name_ptr - ds_context_main.ach_service;
      adsp_check_param->dsc_ucs_princ_service.imc_len_str = inl_principal_name_len;
      adsp_check_param->dsc_ucs_princ_service.iec_chs_str = ied_chs_utf_8;
      adsp_check_param->dsc_ucs_princ_service.ac_str = malloc(inl_principal_name_len);
      memcpy(adsp_check_param->dsc_ucs_princ_service.ac_str,ds_context_main.ach_service, inl_principal_name_len);

      achl_principal_name_ptr++;
      inl_principal_name_len = strlen(achl_principal_name_ptr);
      adsp_check_param->dsc_ucs_realm_service.imc_len_str = inl_principal_name_len;
      adsp_check_param->dsc_ucs_realm_service.iec_chs_str = ied_chs_utf_8;
      adsp_check_param->dsc_ucs_realm_service.ac_str = malloc(inl_principal_name_len);
      memcpy(adsp_check_param->dsc_ucs_realm_service.ac_str,achl_principal_name_ptr, inl_principal_name_len);
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return il_ret;
   }
   if(ds_serv.inc_keytab_len != adsp_check_param->imc_len_keytab){
      memset(ds_serv.achc_keytab, 0, ds_serv.inc_keytab_len);
      m_aux_stor_free(&a_temp_memory_area,ds_serv.achc_keytab);
   }
   m_aux_stor_free( &a_temp_memory_area, ds_context_main.a_gen_ptr);
   return 0;
}


int Krb5_Heimdal::m_init_krb5_context(
                                 struct dsd_krb5_kdc_1* ads_conf,
                                 struct dsd_unicode_string * ads_user_name,
                                 const e_krb5_flags ap_req_options,
                                 krb5_data ** aads_out )
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   *aads_out                = NULL;
   signed long int il_ret   = 0;
   struct dsd_krb5_kdc_server * ads_kdc_server;
   if( ads_conf )
      if( ads_conf->adsc_kdc_server )
         ads_kdc_server = ads_conf->adsc_kdc_server;
      else {
         ie_error = HEIMDAL_CONTROL_ERROR;
         im_error_code = 0;
         return HEIMDAL_CONTROL_ERROR;
      }
   else {
      ie_error = HEIMDAL_CONTROL_ERROR;
      im_error_code = 0;
      return HEIMDAL_CONTROL_ERROR;
   }
   char * ach_default_realm = m_get_default_realm_0_terminated( ads_conf );
   char * ach_principal     = m_get_principal_utf8_0_terminated( ads_user_name );
   if( !( ach_default_realm && ach_principal ) ) {
      return ie_error;
   }
   void * a_ip_context;
   void * a_kdc_ip_addr     = m_get_IP( ads_kdc_server, &a_ip_context );
   struct dsd_config_ticket ds_conf_ticket = {
      ach_default_realm,            //default_realm
      ach_principal,                //server
      a_kdc_ip_addr,                //kdc_ip_address
      ads_kdc_server->imc_port,     //kdc_port
      ads_conf->imc_ticket_lifetime,//ticket_life
      3,                            //max_retries
      4,                            //fcache_version
      ads_conf->imc_clockskew,      //max_skew
      ads_kdc_server->imc_max_ticket_size,//max_ticket_size
#ifdef WITHOUT_FILE
      a_ccache,                  //tgt
      im_length_ccache           //length_tgt
#endif
      ,
      &a_memory_area             //memory_area
      ,
      &a_temp_memory_area                 //temporary memory
      ,
      a_tracer                           //tracer
      ,
      in_trace_lvl        //trace level
      ,
      a_ip_context,              //ip_context
      ads_kdc_server->imc_timeout//timeout
   };
   //StSch Trace Point 3003
   if( in_trace_lvl>=2 ) {
      void* a_temp_memory;
      m_aux_stor_start( &a_temp_memory );
      struct dsd_memory_traces* ads_traces=m_init_krb5_mem_trace( &a_temp_memory );
      m_krb5_trace_memcat( &a_temp_memory,ads_traces,&ds_conf_ticket,sizeof( dsd_config_ticket ),
         "ds_conf_ticket:" );
      m_krb5_trace_memcat( &a_temp_memory, ads_traces,a_ccache,64,"CCache:" );
      a_tracer->m_trace( 'T',3003 ,ads_traces,&a_temp_memory,"" );
      m_aux_stor_end( &a_temp_memory );
   }
   try{
      do{
         a_kdc_ip_addr  = m_get_IP( ads_kdc_server, &a_ip_context );
         ds_conf_ticket.a_ip_address_context = a_ip_context;
         ds_conf_ticket.a_kdc_ip_address = a_kdc_ip_addr;
         ds_conf_ticket.im_kdc_port =ads_kdc_server->imc_port;
         ds_conf_ticket.im_max_ticket_size = ads_kdc_server->imc_max_ticket_size;
         ds_conf_ticket.im_timeout = ads_kdc_server->imc_timeout;
         il_ret = ::m_get_ticket( &ds_conf_ticket );
         if(il_ret != KRB5_KDC_UNREACH){
            break;
         }
         ads_kdc_server = ads_kdc_server->adsc_next;
      }while(ads_kdc_server!= NULL);
      if( il_ret ) {
         im_error_code = il_ret;
         ie_error = INTERNAL_HEIMDAL_ERROR;
         m_reset_temporary_memory();
         return il_ret;
      }
#ifdef WITHOUT_FILE
      m_del_ccache();
      a_ccache         = ds_conf_ticket.a_tgt;
      im_length_ccache = ds_conf_ticket.im_length_tgt;
#endif
      m_reset_temporary_memory();
      char * ach_first;
      char * ach_second;
      char ** aach_rest;
      int im_rest_length;
      m_parse_name( ach_principal,&ach_first,&ach_second,&aach_rest,&im_rest_length );
      struct dsd_config_server_client ds_clie = {
         ads_conf->imc_clockskew,            //max_skew
         ach_default_realm,                  //default_realm
         ach_second,
         ach_first,
         ( const char** )aach_rest,
         im_rest_length,
         'c',                                //client
         NULL
         ,&a_memory_area                  //memory_area
         ,
         &a_temp_memory_area                 //temporary memory
         ,
         a_tracer                           //tracer
         ,
         in_trace_lvl         //trace level
      };
      struct dsd_config_client ds_only_cl = {
         4
#ifdef WITHOUT_FILE
         ,a_ccache                        //tgt
         ,im_length_ccache                //length_tgt
#endif
      };
      il_ret = ::m_init_krb5_context( &ds_context_main, &ds_clie, &ds_only_cl );
      m_aux_stor_free( &a_memory_area, ach_default_realm );
      m_aux_stor_free( &a_memory_area, ach_principal );
      if( il_ret ) {
         im_error_code = il_ret;
         ie_error = INTERNAL_HEIMDAL_ERROR;
         m_reset_temporary_memory();
         return il_ret;
      }
      il_ret = ::m_init_sec_context_client( &ds_context_main, ap_req_options );
      if( il_ret ) {
         im_error_code = il_ret;
         ie_error = INTERNAL_HEIMDAL_ERROR;
         m_reset_temporary_memory();
         return il_ret;
      }
      *aads_out = &( ds_context_main.ds_data_init_out );
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return il_ret;
   }
   return 0;
}

int Krb5_Heimdal::m_init_krb5_context( struct dsd_aux_cf1 * ,
                                       struct dsd_aux_krb5_sign_on_1 * ,
                                       krb5_data * ads_init_data,
                                       const e_krb5_flags ap_req_options )
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   signed long int il_ret = 0;
   ds_context_main.ds_data_init_in.length = ads_init_data->length;
   ds_context_main.ds_data_init_in.data   = ads_init_data->data;
   try{
      il_ret = ::m_init_sec_context_client( &ds_context_main, ap_req_options );
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
   }
   if( il_ret ) {
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return il_ret;
   }
   return 0;
}


int Krb5_Heimdal::m_krb5_data_free( struct dsd_aux_cf1 * ,
                                    struct dsd_aux_krb5_sign_on_1 * ,
                                    krb5_data * ads_data )
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   signed long int il_ret = 0;
   try {
      il_ret = ::m_krb5_data_free( &ds_context_main, ads_data );
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
   }
   if( il_ret ) {
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return il_ret;
   }
   return 0;
}


int Krb5_Heimdal::m_gss_encapsulate( struct dsd_aux_cf1 * ,
                                     struct dsd_aux_krb5_sign_on_1 * ,
                                     krb5_data * ads_krb5_token,
                                     krb5_data * ads_gss_token,
                                     const char* ach_tok_id )
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   if( (NULL == ads_krb5_token) || (NULL == ads_gss_token)
      || (NULL == ach_tok_id) )
   {
      im_error_code = 0;
      ie_error = EXTERNAL_ERROR;
      return EXTERNAL_ERROR;
   }

   signed long int il_ret = 0;
   try {
      il_ret = ::m_gss_encapsulate( &ds_context_main,
         ads_krb5_token,
         ads_gss_token,
         ach_tok_id );
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
   }
   if( il_ret ) {
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return il_ret;
   }
   return 0;
}

int Krb5_Heimdal::m_gss_decapsulate( struct dsd_aux_cf1 * ,
                                     struct dsd_aux_krb5_sign_on_1 * ,
                                     krb5_data * ads_krb5_token,
                                     krb5_data * ads_gss_token,
                                     const char* ach_tok_id,
                                     const char* ach_tok_id_2 )
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   signed long int il_ret = 0;
   try {
      il_ret = ::m_gss_decapsulate( &ds_context_main,
         ads_krb5_token,
         ads_gss_token,
         ach_tok_id,
         ach_tok_id_2 );
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
   }
   if( il_ret ) {
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return il_ret;
   }
   return 0;
}


int Krb5_Heimdal::m_gss_wrap( struct dsd_aux_cf1 *  ,
                              struct dsd_aux_krb5_sign_on_1 * ,
                              krb5_data * ads_inbuf,
                              krb5_data * ads_outbuf )
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   signed long int il_ret = 0;
   try {
      il_ret = ::m_gss_wrap( &ds_context_main,
         ads_inbuf,
         ads_outbuf );
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
   }
   if( il_ret ) {
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return il_ret;
   }
   return 0;
}

int Krb5_Heimdal::m_gss_unwrap( struct dsd_aux_cf1 * ,
                                struct dsd_aux_krb5_sign_on_1 * ,
                                krb5_data * ads_inbuf,
                                krb5_data * ads_outbuf )
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   signed long int il_ret = 0;
   //StSch Trace Point 3004
   if( in_trace_lvl>=2 ) {
      void* a_temp_memory;
      m_aux_stor_start( &a_temp_memory );
      struct dsd_memory_traces* ads_traces=m_init_krb5_mem_trace( &a_temp_memory );
      m_krb5_trace_memcat( &a_temp_memory,ads_traces,ads_inbuf,16, "Unwrap inbuf:" );
      a_tracer->m_trace( 'T',3004,ads_traces,&a_temp_memory,"" );
      m_aux_stor_end( &a_temp_memory );
   }
   try {
      il_ret = ::m_gss_unwrap( &ds_context_main,
         ads_inbuf,
         ads_outbuf );
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return il_ret;
   }
   if( il_ret ) {
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return il_ret;
   }
   return 0;
}


int Krb5_Heimdal::m_get_cred( struct dsd_aux_cf1            * adsp_aux_cf1,
                              struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
                              struct dsd_krb5_kdc_1         * ads_conf,
                              struct dsd_unicode_string * ads_user_name,
                              struct dsd_unicode_string * ,
                              struct dsd_unicode_string * ads_password,
                              struct dsd_unicode_string * ads_serv_name )
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   struct dsd_krb5_kdc_server * adsl_kdc_server;
   int im_ret;
   ie_error = HEIMDAL_CONTROL_ERROR;
   if( ads_conf == NULL || ads_conf->adsc_kdc_server == NULL ){
      im_error_code = 0;
      return HEIMDAL_CONTROL_ERROR;
   }
   adsl_kdc_server = ads_conf->adsc_kdc_server;
   do{
      if( !ads_user_name )
         //m_get_renw_tgt( adsp_aux_cf1,ads_conf,adsc_kdc_server );  //StSch most likely never called
         ;
      else if( !ads_password )
         //m_get_ticket( adsp_aux_cf1,adsp_akso1,ads_conf,adsc_kdc_server,ads_user_name )//StSch most likely never called
         ;
      else if( !ads_conf->boc_allow_initital_ticket )
         m_get_tgt( adsp_aux_cf1,adsp_akso1,ads_conf,adsl_kdc_server,ads_user_name,ads_password );
      else
         m_get_tgt( adsp_aux_cf1,adsp_akso1,ads_conf,adsl_kdc_server,ads_user_name,ads_password,ads_serv_name );
      im_ret = ie_error;

      if( ie_error != INTERNAL_HEIMDAL_ERROR && im_error_code != KRB5_KDC_UNREACH ){
         break; //only try next KDC, if this one can't be reached
      }
      adsl_kdc_server= adsl_kdc_server->adsc_next;
   }while(adsl_kdc_server != NULL);
   return im_ret;
}



int Krb5_Heimdal::m_krb5_change_pw( struct dsd_aux_cf1 * adsp_aux_cf1,
                                    struct dsd_krb5_kdc_1         * ads_conf,
                                    struct dsd_krb5_kdc_server* ads_kdc_server,
                                    struct dsd_unicode_string * ads_user_name,
                                    struct dsd_unicode_string * ads_password,
                                    struct dsd_unicode_string * ads_new_password )
{
   // Check, if state is valid
   if( NO_CONTROL_ERROR != ie_error){
      return ie_error;
   }
   signed long int il_ret = 0;
   char * ach_default_realm = m_get_default_realm_0_terminated( ads_conf );
   char * ach_principal     = m_get_principal_utf8_0_terminated( ads_user_name );
   char * ach_passw         = m_get_password_0_terminated( ads_password );
   char * ach_new_passw     = m_get_password_0_terminated( ads_new_password );
   if( !( ach_default_realm && ach_passw && ach_principal && ach_new_passw ) ) {
      ie_error = HEIMDAL_CONTROL_ERROR;
      im_error_code = 0;
      return HEIMDAL_CONTROL_ERROR;
   }
   char * ach_server;
#ifdef HL_KRB5_WSP_ACTIV
#endif
   int im_length_krbtgt = 7;
   ach_server = ( char* )m_aux_stor_alloc( &a_memory_area, im_length_krbtgt + ads_conf->imc_len_default_realm + 1 );
   memcpy( ach_server,"changepw/",im_length_krbtgt );
   memcpy( ach_server + im_length_krbtgt,ach_default_realm,ads_conf->imc_len_default_realm + 1 );
#ifdef HL_KRB5_WSP_ACTIV
#ifndef B090930
   // to-do 30.09.09 KB - when exception is caught - mark-thread ???
   m_hco_wothr_blocking( adsp_aux_cf1->adsc_hco_wothr );  /* mark thread blocking */
#endif
#endif
   void * a_ip_context;
   void * a_kdc_ip_addr = m_get_IP( ads_kdc_server, &a_ip_context );
   struct dsd_config_pw ds_conf_pw = {
      ach_principal,                   //princi_name
      ach_passw,                       //passwd
      ach_new_passw,                   //new_passwd
      ach_default_realm,               //default_realm
      ach_server,                      //server
      a_kdc_ip_addr,                   //kdc_ip_address
      ads_kdc_server->imc_port,        //kdc_port
      464,                             //kdc change password port //Todo: make configurable
      3,                           //max_retries
      4,                           //fcache_version
      ads_conf->imc_clockskew,            //max_skew
      ads_kdc_server->imc_max_ticket_size,//max_ticket_size
      &a_memory_area               //memory_area
      ,
      &a_temp_memory_area                 //temporary memory
      ,
      a_tracer                           //tracer
      ,
      in_trace_lvl         //trace level
      ,
      a_ip_context,                //ip_context
      ads_kdc_server->imc_timeout  //timeout
   };
#ifdef HL_KRB5_WSP_ACTIV
#ifndef B090930
   // to-do 30.09.09 KB - when exception is caught - mark-thread ???
   m_hco_wothr_active( adsp_aux_cf1->adsc_hco_wothr, FALSE );  /* mark thread active */
#endif
#endif
   try {
      il_ret = ::m_change_pw( &ds_conf_pw );
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
   }
   if( il_ret ) {
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return INTERNAL_HEIMDAL_ERROR;
   }
   return 0;
}

//-----------------------------------------------------------------------------
// Class Krb5_Heimdal private methods
//-----------------------------------------------------------------------------

/*
* Clear and restart temporary memory after certaint functions and errors
*/

void Krb5_Heimdal::m_reset_temporary_memory()
{
   m_hl_aux_stor_clear( a_temp_memory_area );
   m_aux_stor_end( &a_temp_memory_area );
   m_aux_stor_start( &a_temp_memory_area );
}//end void Krb5_Heimdal::m_reset_temporary_memory()


void Krb5_Heimdal::m_parse_name_w( char ** aach_first,
                                   char ** aach_second,
                                   char *** aaach_rest,
                                   int * aim_rest_length,
                                   int * aim_switch,
                                   int * aim_i,
                                   char ** aach_temp_org )
{
   char ** aach_temp;
   if( !*aim_switch ) {
      aach_temp = aach_first;
      ( *aim_switch )++;
   } else if( *aim_switch == 1 ) {
      aach_temp = aach_second;
      ( *aim_switch )++;
   } else {
      ( *aim_rest_length )++;
      ( *aaach_rest ) = ( char** )m_aux_stor_realloc( &a_memory_area, *aaach_rest,( *aim_rest_length )*sizeof( char* ) );
      aach_temp = &(( *aaach_rest )[( *aim_rest_length ) -1] );
   }
   *aach_temp = ( char* )m_aux_stor_alloc( &a_memory_area, ( *aim_i ) + 1 );
   memcpy( *aach_temp,*aach_temp_org,*aim_i );
   ( *aach_temp )[*aim_i] = '\0';
   *aach_temp_org = *aach_temp_org + *aim_i + 1;
   *aim_i = 0;
}
void Krb5_Heimdal::m_parse_name( char * ach_principal,
                                 char ** aach_first,
                                 char ** aach_second,
                                 char *** aaach_rest,
                                 int * aim_rest_length )
{
   char * ach_temp  = ach_principal;
   int im_i         = 0;
   int im_switch    = 0;
   *aach_first      = NULL;
   *aach_second     = NULL;
   *aaach_rest      = NULL;
   *aim_rest_length = 0;
   while( ach_temp[im_i] != '\0' ) {
      if( ach_temp[im_i] == '/' ) {
         m_parse_name_w( aach_first,aach_second,aaach_rest,aim_rest_length,&im_switch,&im_i,&ach_temp );
      }
      im_i++;
   }
   m_parse_name_w( aach_first,aach_second,aaach_rest,aim_rest_length,&im_switch,&im_i,&ach_temp );
}

void * Krb5_Heimdal::m_get_IP( struct dsd_krb5_kdc_server * ds_kdc_server,
                               void ** aa_ip_context )
{
#ifndef HL_KRB5_WSP_ACTIV
   *aa_ip_context = ( ds_kdc_server->adsc_server_ineta ) + 1;
#else
   *aa_ip_context = ds_kdc_server;
#endif
   return (( struct dsd_ineta_single_1* )(( ds_kdc_server->adsc_server_ineta ) + 1 ) ) + 1;
}

void Krb5_Heimdal::m_get_tgt( struct dsd_aux_cf1            * adsp_aux_cf1,
                              struct dsd_aux_krb5_sign_on_1 * adsp_akso1,
                              struct dsd_krb5_kdc_1         * ads_conf,
                              struct dsd_krb5_kdc_server* ads_kdc_server,
                              struct dsd_unicode_string * ads_user_name,
                              struct dsd_unicode_string * ads_password,
                              struct dsd_unicode_string * ads_serv_name )
{
   signed long int il_ret = 0;
   char * ach_default_realm = m_get_default_realm_0_terminated( ads_conf );
   char * ach_principal     = m_get_principal_utf8_0_terminated( ads_user_name );
   char * ach_passw         = m_get_password_0_terminated( ads_password );
   if( !( ach_default_realm && ach_passw && ach_principal ) ) {
      return;
   }
   char * ach_server;
#ifdef HL_KRB5_WSP_ACTIV
   int    iml1, iml2, iml3;               /* working-variables       */
   BOOL   bol1;                           /* working-variable        */
   char * achl_w1;                        /* working-variable        */
   struct dsd_hl_aux_c_cma_1 dsl_cma_1;
#endif
   if( ads_serv_name ) {
      ach_server = m_get_principal_utf8_0_terminated( ads_serv_name );
      if( !ach_server ) {
         return;
      }
   } else {
      int im_length_krbtgt = 7;
      ach_server = ( char* )m_aux_stor_alloc( &a_memory_area, im_length_krbtgt + ads_conf->imc_len_default_realm + 1 );
      memcpy( ach_server,"krbtgt/",im_length_krbtgt );
      memcpy( ach_server + im_length_krbtgt,ach_default_realm,ads_conf->imc_len_default_realm + 1 );
   }
#ifdef HL_KRB5_WSP_ACTIV
#ifndef B090930
   // to-do 30.09.09 KB - when exception is caught - mark-thread ???
   /** @todo Where is the blocking activity? StSch 27.02.12*/
   m_hco_wothr_blocking( adsp_aux_cf1->adsc_hco_wothr );  /* mark thread blocking */
#endif
#endif
   void * a_ip_context;
   void * a_kdc_ip_addr = m_get_IP( ads_kdc_server, &a_ip_context );
   struct dsd_config_tgt ds_conf_tgt = {
      ach_principal,                   //princi_name
      ach_passw,                       //passwd
      ach_default_realm,               //default_realm
      ach_server,                      //server
      a_kdc_ip_addr,                   //kdc_ip_address
      ads_kdc_server->imc_port,        //kdc_port
      ads_conf->imc_ticket_lifetime,   //ticket_life
      ads_conf->imc_renewable_lifetime,//renew_life
      0,                           //start_time
      3,                           //max_retries
      4,                           //fcache_version
      ads_conf->imc_clockskew,            //max_skew
      ads_kdc_server->imc_max_ticket_size,//max_ticket_size
#ifdef WITHOUT_FILE
      ( void* )0,                  //tgt
      0                            //length_tgt
#endif
      ,
      &a_memory_area               //memory_area
      ,
      &a_temp_memory_area                 //temporary memory
      ,
      a_tracer                           //tracer
      ,
      in_trace_lvl         //trace level
      ,
      a_ip_context,                //ip_context
      ads_kdc_server->imc_timeout  //timeout
   };
#ifdef HL_KRB5_WSP_ACTIV
#ifndef B090930
   // to-do 30.09.09 KB - when exception is caught - mark-thread ???
   m_hco_wothr_active( adsp_aux_cf1->adsc_hco_wothr, FALSE );  /* mark thread active */
#endif
#endif
   try {
      il_ret = ::m_get_tgt( &ds_conf_tgt );
   } catch (Krb5_Heimdal_exception &dsp_exception) {
      il_ret = dsp_exception.mc_get_error_code();
   }
   m_aux_stor_free( &a_memory_area, ach_default_realm );
   m_aux_stor_free( &a_memory_area, ach_principal );
   m_aux_stor_free( &a_memory_area, ach_server );
   if( il_ret ) {
      im_error_code = il_ret;
      ie_error = INTERNAL_HEIMDAL_ERROR;
      m_reset_temporary_memory();
      return;
   }
   m_reset_temporary_memory();
#ifdef WITHOUT_FILE
   m_del_ccache();
   a_ccache         = ds_conf_tgt.a_tgt;
   im_length_ccache = ds_conf_tgt.im_length_tgt;
#ifdef HL_KRB5_WSP_ACTIV
   /* store TGT in CMA                                               */
   if(!m_cma_get_tgt_area(&dsl_cma_1,adsp_aux_cf1, &adsp_akso1->dsc_user_name,&adsp_akso1->dsc_user_group,
      D_CMA_READ_DATA | D_CMA_WRITE_DATA)){
         ie_error = HEIMDAL_CONTROL_ERROR;
         im_error_code = 0;
         return;
   }
   /* calculate length of CMA entry                                  */
   /* first length NHASN of KRB5 configuration name                  */
   iml1 = ads_conf->imc_len_name;         /* get length              */
   iml2 = 0;                              /* clear length NHASN      */
   do {
      iml2++;                              /* increment length NHASN  */
      iml1 >>= 7;                          /* shift value             */
   } while( iml1 > 0 );
   dsl_cma_1.inc_len_cma_area = iml2 + ads_conf->imc_len_name + ds_conf_tgt.im_length_tgt;
   dsl_cma_1.iec_ccma_def = ied_ccma_set_size;  /* set new size of cma area */
   bol1 = m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
   /* fill CMA area                                                  */
   achl_w1 = ( char * ) dsl_cma_1.achc_cma_area + iml2; /* address cma area plus length NHASN */
   iml3 = 0;                              /* clear more flag         */
   iml1 = ads_conf->imc_len_name;         /* get length              */
#ifdef B100112
   iml2 = 0;                              /* clear length NHASN      */
#endif
   do {                                   /* loop to create NHASN    */
      *( --achl_w1 ) = ( unsigned char )(( iml1 & 0X7F ) | iml3 );
      iml1 >>= 7;                          /* shift value             */
      iml3 = 0X80;                         /* set more flag           */
   } while( iml1 > 0 );
   memcpy(( char * ) dsl_cma_1.achc_cma_area + iml2,
      ads_conf + 1,
      ads_conf->imc_len_name );
   memcpy(( char * ) dsl_cma_1.achc_cma_area + iml2 + ads_conf->imc_len_name,
      ds_conf_tgt.a_tgt,
      ds_conf_tgt.im_length_tgt );
   // to-do 30.09.09 KB - when expires the ticket ???
   dsl_cma_1.imc_retention_time = ads_conf->imc_ticket_lifetime;  /* retention time in seconds */
   dsl_cma_1.iec_ccma_def = ied_ccma_retention_set;  /* set retention time */
   bol1 = m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
   dsl_cma_1.iec_ccma_def = ied_ccma_lock_rel_upd;  /* release lock and update */
   bol1 = m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
#endif
#endif
   ie_error = NO_CONTROL_ERROR;
}

void Krb5_Heimdal::m_get_string_utf8_0_terminated( struct dsd_unicode_string * ads_string,
                                                   struct dsd_unicode_string * ads_new_string )
{
   ads_new_string->iec_chs_str = ied_chs_utf_8;
   ads_new_string->imc_len_str = m_len_vx_vx( ads_new_string->iec_chs_str,
      ads_string->ac_str,
      ads_string->imc_len_str,
      ads_string->iec_chs_str );
   if( ads_new_string->imc_len_str < 0 ) {
      ads_new_string->ac_str=NULL;
      ie_error = HEIMDAL_CONTROL_ERROR;
      im_error_code = 0;
      return;
   }
   ads_new_string->ac_str = m_aux_stor_alloc( &a_memory_area, ads_new_string->imc_len_str + 1 );
   if( m_cpy_vx_vx( ads_new_string->ac_str,
      ads_new_string->imc_len_str + 1, ads_new_string->iec_chs_str,
      ads_string->ac_str,
      ads_string->imc_len_str, ads_string->iec_chs_str ) == ads_new_string->imc_len_str ) {
         *(( char* )( ads_new_string->ac_str ) + ads_new_string->imc_len_str ) = '\0';
   } else {
      ads_new_string->ac_str=NULL;
      ie_error = HEIMDAL_CONTROL_ERROR;
      im_error_code = 0;
      return;
   }
}

char * Krb5_Heimdal::m_get_principal_utf8_0_terminated( struct dsd_unicode_string * ads_user_name )
{
   if( ads_user_name ) {
      struct dsd_unicode_string ds_principal;
      m_get_string_utf8_0_terminated( ads_user_name,&ds_principal );
      return ( char* )( ds_principal.ac_str );
   } else {
      ie_error = HEIMDAL_CONTROL_ERROR;
      im_error_code = 0;
      return NULL;
   }
}

char * Krb5_Heimdal::m_get_default_realm_0_terminated( struct dsd_krb5_kdc_1 * ads_conf )
{
   if( ads_conf->imc_len_default_realm > 0 ) {
      char * ach_default_realm = ( char* )m_aux_stor_alloc( &a_memory_area, ads_conf->imc_len_default_realm + 1 );
      char * ach_quelle = ( char* )( ads_conf + 1 ) + ads_conf->imc_len_name + ads_conf->imc_len_comment;
      memcpy( ach_default_realm, ach_quelle,ads_conf->imc_len_default_realm );
      ach_default_realm[ads_conf->imc_len_default_realm] = '\0';
      return ach_default_realm;
   } else {
      ie_error = HEIMDAL_CONTROL_ERROR;
      im_error_code = 0;
      return NULL;
   }
}

char * Krb5_Heimdal::m_get_password_0_terminated( struct dsd_unicode_string * ads_password )
{
   struct dsd_unicode_string ds_passwd;
   m_get_string_utf8_0_terminated( ads_password,&ds_passwd );
   return ( char* )( ds_passwd.ac_str );
}



#ifdef HL_KRB5_WSP_ACTIV
static int m_set_wsp_error( Krb5_Heimdal & ds_heim_inst, enum ied_ret_krb5_def * ied_ret_krb5 )
{
    switch( ds_heim_inst.m_get_error_type() ) {
case Krb5_Heimdal::NO_CONTROL_ERROR:
    *ied_ret_krb5 =  ied_ret_krb5_ok;
    return 0;
case Krb5_Heimdal::INTERNAL_HEIMDAL_ERROR: {
    if( ds_heim_inst.m_get_trace_lvl()>=1 ) {
        void* a_temp_memory;
        m_aux_stor_start( &a_temp_memory );
        int inl_error_nr=ds_heim_inst.m_get_error_code();
        char* achl_error_msg=( char* )m_aux_stor_alloc( &a_temp_memory, ins_tracemsg_len );
        if( inl_error_nr>=ERROR_TABLE_BASE_asn1&&inl_error_nr<=ASN1_PARSE_ERROR ) {
            inl_error_nr-=ERROR_TABLE_BASE_asn1-2000;
            strcpy( achl_error_msg, asn1_error_strings[inl_error_nr-2000] );
        } else if( inl_error_nr>=ERROR_TABLE_BASE_krb5&&inl_error_nr<=KRB5_DELTAT_BADFORMAT ) {
            inl_error_nr-=ERROR_TABLE_BASE_krb5;
            strcpy( achl_error_msg, krb5_error_strings[inl_error_nr] );
        } else if( inl_error_nr>=ERROR_TABLE_BASE_heim&&inl_error_nr<=HEIM_EAI_SYSTEM ) {
            inl_error_nr-=ERROR_TABLE_BASE_heim-1000;
            strcpy( achl_error_msg, heim_error_strings[inl_error_nr-1000] );
        }
        ( ds_heim_inst.m_get_tracer() )->m_trace( 'I',inl_error_nr,NULL,&a_temp_memory,
            "%s",achl_error_msg );
        m_aux_stor_end( &a_temp_memory );
    }
    switch( ds_heim_inst.m_get_error_code() ) {
case KRB5_KDC_UNREACH:
    *ied_ret_krb5 =  ied_ret_krb5_kdc_inv        ;
    break;
case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
    ;
case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
    *ied_ret_krb5 =  ied_ret_krb5_userid_unknown ;
    break;
case KRB5KDC_ERR_PREAUTH_FAILED:
    ;
case KRB5KRB_AP_ERR_BAD_INTEGRITY:
    *ied_ret_krb5 =  ied_ret_krb5_password       ;
    break;
case KRB5KRB_AP_ERR_NOKEY:
   *ied_ret_krb5 = ied_ret_krb5_key_not_found;
   break;
case KRB5KRB_AP_ERR_REPEAT:
    ; //Todo: Add errors
case GSS_S_FAILURE:
    ;
default:
    *ied_ret_krb5 =  ied_ret_krb5_misc           ;
    }
    goto out;
                                           }
default: {
    *ied_ret_krb5 =  ied_ret_krb5_misc;
    goto out;
         }
    }
out:
    return 1;
}

void krb5_tracer::m_trace( const char chp_trace_lvl_tag,
                           const int inp_msg_nr,
                           const struct dsd_memory_traces* ads_mem_trace,
                           void** aap_memory_ptr,
                           const char *achp_msg,
                           ... )
{
    char* achl_kdc_ip = NULL;
    if(ads_kdc != NULL){
       if(( *( unsigned short int* )(( this->ads_kdc->adsc_kdc_server->adsc_server_ineta )+1 ) )==AF_INET ) {
           achl_kdc_ip=( char* )m_aux_stor_alloc( aap_memory_ptr, 16 );
           m_hl_inet_ntop4((( const unsigned char* )(( this->ads_kdc->adsc_kdc_server->adsc_server_ineta )+1 ) )+4,
               achl_kdc_ip, 16 );
       } else {
           achl_kdc_ip=( char* )m_aux_stor_alloc( aap_memory_ptr, sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255\0" );
           m_hl_inet_ntop6((( const unsigned char* )(( this->ads_kdc->adsc_kdc_server->adsc_server_ineta )+1 ) )+4,
               achl_kdc_ip, sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255\0" );
       }
    }
    // set pointer to the parameter list
    va_list  dsp_list;
    va_start( dsp_list, achp_msg );
    //format the trace message
    char *avol_1 = ( char* )m_aux_stor_alloc( aap_memory_ptr, ins_tracemsg_len );
    int iml_1 = 0;
    if(ads_kdc != NULL){
       iml_1 = ::m_hlsnprintf( avol_1, ins_tracemsg_len, ied_chs_utf_8,
           ( const char * )"%s%04i%c  Conf=%.*(.*)s Session=%i Ineta=%s:%i  ",
           this->ach_prefix, inp_msg_nr, chp_trace_lvl_tag,
           this->ads_kdc->imc_len_name, ied_chs_utf_8,
           this->ads_kdc+1, this->inc_session_nr, achl_kdc_ip,
           this->ads_kdc->adsc_kdc_server->imc_port );
    } else {
       iml_1 = ::m_hlsnprintf( avol_1, ins_tracemsg_len, ied_chs_utf_8,
           ( const char * )"%s%04i%c  ",
           this->ach_prefix, inp_msg_nr, chp_trace_lvl_tag);
    }
    ::m_hlvsnprintf(( void * )(( char * )avol_1 + iml_1 ), ins_tracemsg_len - iml_1, ied_chs_utf_8,
        ( const char * )achp_msg, dsp_list );
    va_end( dsp_list );
    //dump memory for given adresses
    if( ads_mem_trace!=NULL && ads_mem_trace->in_mem_count ) {
        avol_1=::m_krb5_strcat( aap_memory_ptr,( char * )avol_1,"\n" );
        int inl_in1=0;
        //::m_hlnew_printf( 0, "    Network byte order");
        int inl_max_dump=176;
        char* ach_temp_string=( char* )m_aux_stor_alloc( aap_memory_ptr, 1024 );
        for( ; inl_in1<ads_mem_trace->in_mem_count ; inl_in1++ ) {
            if( *( ads_mem_trace->ain_mem_len+inl_in1 )>inl_max_dump ) {
                ach_temp_string=( char* )m_aux_stor_realloc( aap_memory_ptr, ach_temp_string,
                    ( *( ads_mem_trace->ain_mem_len+inl_in1 )+16 )*5 );
                inl_max_dump=*ads_mem_trace->ain_mem_len+16;
            }
            ach_temp_string=m_dump_memory( *( ads_mem_trace->aa_memory_area+inl_in1 ),
                *( ads_mem_trace->ain_mem_len+inl_in1 ),
                aap_memory_ptr );
            avol_1=::m_krb5_strcat( aap_memory_ptr,( char * )avol_1,*( ads_mem_trace->aach_mem_names+inl_in1 ) );
            avol_1=::m_krb5_strcat( aap_memory_ptr,( char * )avol_1,ach_temp_string );
        }
        m_aux_stor_free( aap_memory_ptr, ach_temp_string );
        *( avol_1+strlen( avol_1 )-1 )='\0';
    }
    char *avol_2 = ( char* )m_aux_stor_alloc( aap_memory_ptr, strlen( avol_1 )+6+sizeof( dsd_unicode_string ) );
    ::m_hlsnprintf( avol_2,strlen( avol_1 )+6+sizeof( dsd_unicode_string ),ied_chs_utf_8,"%s",avol_1 );
    ::m_hlnew_printf( 0/*HLOG_INFO1*/, ( char * )avol_2 );
    m_aux_stor_free( aap_memory_ptr, avol_1 );
    m_aux_stor_free( aap_memory_ptr, avol_2 );
}//krb5_tracer::m_trace(char chp_trace_lvl_tag, int inp_msg_nr, void **aap_memory_addresses, int *ainp_mem_len, char **aachp_mem_name, char *achp_msg, ...);

char* krb5_tracer::m_dump_memory( const void *ap_memory_area,
                                  int inp_mem_len,
                                  void** aap_memory_ptr )
{
    const char* achl_in_buffer=( const char* ) ap_memory_area;      //local copy of memory pointer
    const char* achl_basic_string="    0x00000000  ........ ........ ........ ........  ................\n";
    //basic layout of a line
    const int inl_offset=16;                                        //offset from start of line to first memory content
    const int inl_line_size=strlen( achl_basic_string );            //length of a line
    char* achl_dump_string=( char* )m_aux_stor_alloc( aap_memory_ptr,
        ( inp_mem_len+1 )*inl_line_size+2 );    //stores result
    char* achl_work_ptr=achl_dump_string;                           //used for working on result string
    char achl_text_dump[16];                                         //keeps the text representation of a line
    int inl_in1, inl_in2;                                           //working variables
    //initialize some things
    *achl_dump_string='\n';
    achl_work_ptr++;
    memset( achl_text_dump,'.',16 );
    memcpy( achl_work_ptr,achl_basic_string, inl_line_size );
    memset( achl_work_ptr+inl_offset-2,' ',1 );
    achl_work_ptr+= inl_offset;
    inl_in1=0;
    inl_in2=0;
    //main work loop
    while( inl_in1<inp_mem_len ) {
        //copy first half byte
        *achl_work_ptr=(( unsigned char )*achl_in_buffer )>>4;
        //create character representation (hex value)
        if( *achl_work_ptr<10 ) {
            *achl_work_ptr=(( *achl_work_ptr )|0x30 );
        } else {
            *achl_work_ptr=(( *achl_work_ptr )+87 );
        }
        achl_work_ptr++;
        //second half byte
        *achl_work_ptr=((( char )*achl_in_buffer )&0x0f );
        if( *achl_work_ptr<10 ) {
            *achl_work_ptr=( *achl_work_ptr )|0x30;
        } else {
            *achl_work_ptr=( *achl_work_ptr )+87;
        }
        achl_work_ptr++;
        //write non-controll characters
        if((( unsigned char )( *achl_in_buffer ) )>0x1f && (( unsigned char )( *achl_in_buffer ) )!=0x7f ) {
            achl_text_dump[inl_in2]=*achl_in_buffer;
        }
        //increment counters and memory pointer
        achl_in_buffer++;
        inl_in1++;
        inl_in2++;
        inl_in2=inl_in2&0x0f;
        if( inl_in2 ) {
            if( !( inl_in2&0x03 ) ) {
                achl_work_ptr++;
            }
        } else {
            //copy text on a finished line and switch to next line
            achl_work_ptr+=2;
            memcpy( achl_work_ptr,achl_text_dump,16 );
            memset( achl_text_dump,'.',16 );
            achl_work_ptr+= 17;
            memcpy( achl_work_ptr,achl_basic_string, inl_line_size );
            ::m_hlsnprintf( achl_work_ptr+6,inl_offset-7,ied_chs_utf_8,"%08x",inl_in1 );
            memset( achl_work_ptr+inl_offset-2,' ',1 );
            achl_work_ptr+= inl_offset;
        }
    }
    if( inl_in2 ) {
        //if there is an unfinished line left, fill up with blanks
        memset( achl_work_ptr,' ',( 35-( 2*inl_in2 ) ) );
        memset( achl_text_dump+inl_in2,' ',16-inl_in2 );
        if( inl_in2<12 ) {
            achl_work_ptr++;
            if( inl_in2<8 ) {
                achl_work_ptr++;
                if( inl_in2<4 ) {
                    achl_work_ptr++;
                }
            }
        }
        achl_work_ptr+= 34-( 2*inl_in2 );
        memcpy( achl_work_ptr,achl_text_dump,16 );
        achl_work_ptr+=16;
    } else {
        achl_work_ptr-=( inl_offset+1 );
    }
    //terminate string
    *achl_work_ptr='\n';
    achl_work_ptr++;
    *achl_work_ptr=NULL;
    return achl_dump_string;
}//char* krb5_tracer::m_dump_memory(void *ap_memory_area, int inp_mem_len)


void m_krb5_trace( krb5_tracer* adsp_tracer,
                   char chp_trace_lvl_tag,
                   int inp_msg_nr,
                   struct dsd_memory_traces* ads_mem_trace,
                   void** aap_memory_ptr,
                   char* achp_msg,
                   ... )
{
   va_list  dsp_list;
   va_start( dsp_list, achp_msg );
   char *avol_1 = ( char* )m_aux_stor_alloc( aap_memory_ptr, ins_tracemsg_len );
   ::m_hlvsnprintf(( void * )(( char * )avol_1 ), ins_tracemsg_len, ied_chs_utf_8,
      ( const char * )achp_msg, dsp_list );
   adsp_tracer->m_trace( chp_trace_lvl_tag,
      inp_msg_nr,
      ads_mem_trace,
      aap_memory_ptr,
      "%s",
      avol_1 );
   m_aux_stor_free( aap_memory_ptr, avol_1 );
   va_end( dsp_list );
}//void m_trace( krb5_tracer* adsp_tracer, char chp_trace_lvl_tag, int inp_msg_nr, const void** aap_memory_addresses, int* ainp_mem_len, char** aachp_mem_name, char* achp_msg, ...);

/* sign on to Kerberos KDC                                           */
extern "C" BOOL m_krb5_sign_on( struct dsd_aux_cf1 *adsp_aux_cf1,
                                struct dsd_krb5_kdc_1 *adsp_krb5_kdc_1,
                                struct dsd_aux_krb5_sign_on_1 *adsp_akso1 )
{
   // Input validation
   if( NULL == adsp_aux_cf1 || NULL == adsp_krb5_kdc_1 || NULL == adsp_akso1 )
   {
      return FALSE;
   }

   //StSch Trace Point 3001
   Krb5_Heimdal ds_krb5_instanc = Krb5_Heimdal();
   if( adsp_krb5_kdc_1 == NULL){
      adsp_akso1->iec_ret_krb5 = ied_ret_krb5_kdc_not_sel;
      return TRUE;
   }
   if( adsp_krb5_kdc_1->imc_trace_level ) {
      void* a_temp_memory;
      m_aux_stor_start( &a_temp_memory );
      krb5_tracer* ads_krb5_tracer = new krb5_tracer( adsp_krb5_kdc_1,
                                                      adsp_krb5_kdc_1->imc_trace_level,
                                                      "KRB" );
      struct dsd_memory_traces* ads_mem_trace=m_init_krb5_mem_trace( &a_temp_memory );
      char* achl_trace_msg= "User Name=%.*(.*)s,\nUser Group=%.*(.*)s";
      void* a_chcksum_pw=m_aux_stor_alloc( &a_temp_memory,20 );
      char chl_trace_tag='I';

      if( adsp_krb5_kdc_1->imc_trace_level>=2 ) {
         dsd_krb5_kdc_server* ads_krb5_kdc=adsp_krb5_kdc_1->adsc_kdc_server->adsc_next;
         int inl_in1=3;
         chl_trace_tag='T';
         m_krb5_sha1( adsp_akso1->dsc_password.ac_str,
            adsp_akso1->dsc_password.imc_len_str, a_chcksum_pw, &a_temp_memory );
         m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace,
            adsp_krb5_kdc_1, sizeof( dsd_krb5_kdc_1 ),"adsp_krb5_kdc_1:" );
         m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace,
            a_chcksum_pw, 20, "P-Hash:" );
         m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace,
            adsp_krb5_kdc_1->adsc_kdc_server, sizeof( dsd_krb5_kdc_server ),
            "krb5 kdc:" );
         for( ; ads_krb5_kdc!=NULL; ads_krb5_kdc=ads_krb5_kdc->adsc_next,inl_in1++ ) {
            m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace,ads_krb5_kdc,
               sizeof( dsd_krb5_kdc_server ),"krb5 kdc:" );
         }
      }

      ads_krb5_tracer->m_trace( chl_trace_tag, 3001, ads_mem_trace, &a_temp_memory,
         achl_trace_msg, adsp_akso1->dsc_user_name.imc_len_str,
         adsp_akso1->dsc_user_name.iec_chs_str, adsp_akso1->dsc_user_name.ac_str,
         adsp_akso1->dsc_user_group.imc_len_str, adsp_akso1->dsc_user_group.iec_chs_str,
         adsp_akso1->dsc_user_group.ac_str );
      m_aux_stor_end( &a_temp_memory );
      ds_krb5_instanc.m_set_tracer( ads_krb5_tracer );
   }
   if( m_set_wsp_error( ds_krb5_instanc,&( adsp_akso1->iec_ret_krb5 ) ) )
      return TRUE;
   if( ds_krb5_instanc.m_get_cred( adsp_aux_cf1,
                                   adsp_akso1,
                                   adsp_krb5_kdc_1,
                                   &adsp_akso1->dsc_user_name,   /* Username Sign On */
                                   &adsp_akso1->dsc_user_group,  /* Usergroup Sign On */
                                   &adsp_akso1->dsc_password ) ) /* Password Sign On */
   {
      m_set_wsp_error( ds_krb5_instanc,&( adsp_akso1->iec_ret_krb5 ) );
   }
   return TRUE;
} /* end m_krb5_sign_on()                                            */

/**
This function generates a krb5_tracer instance and makes a log entry for the
m_krb5_se_ti_get function.

The instance must be released with delte later.

@param[in]  adsp_krb5_kdc_1   KDC structure handed to m_krb5_se_ti_get.
@param[in]  adsp_akstg1       Parameter structure of m_krb5_se_ti_get.
@param[in]  adsp_sdh_is1      Structure containing additional User ID information.

@return Pointer to the new krb5_tracer instance
*/
static krb5_tracer* m_log_krb5_se_ti_get(struct dsd_krb5_kdc_1 *adsp_krb5_kdc_1,
                                         struct dsd_aux_krb5_se_ti_get_1 *adsp_akstg1,
                                         struct dsd_sdh_ident_set_1* adsp_sdh_is1)
{
   void* a_temp_memory;
   m_aux_stor_start( &a_temp_memory );
   krb5_tracer* ads_krb5_tracer = new krb5_tracer( adsp_krb5_kdc_1, adsp_krb5_kdc_1->imc_trace_level, "KRB" );
   struct dsd_memory_traces* ads_mem_trace=m_init_krb5_mem_trace( &a_temp_memory );
   char* achl_trace_msg= "User Name=%.*(.*)s,\nUser Group=%.*(.*)s, Service Name=%.*(.*)s, Service Group=%.*(.*)s";
   char chl_trace_tag='I';
   if( adsp_krb5_kdc_1->imc_trace_level>=2 ) {
      dsd_krb5_kdc_server* ads_krb5_kdc=adsp_krb5_kdc_1->adsc_kdc_server->adsc_next;
      int inl_in1=2;
      chl_trace_tag='T';
      m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace, adsp_krb5_kdc_1, sizeof( dsd_krb5_kdc_1 ),"adsp_krb5_kdc_1:" );
      m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace, adsp_krb5_kdc_1->adsc_kdc_server, sizeof( dsd_krb5_kdc_server ),
         "krb5 kdc:" );
      for( ; ads_krb5_kdc!=NULL; ads_krb5_kdc=ads_krb5_kdc->adsc_next,inl_in1++ ) {
         m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace,ads_krb5_kdc,sizeof( dsd_krb5_kdc_server ),"krb5 kdc:" );
      }
   }
   if( adsp_sdh_is1->iec_ret_g_idset1 != ied_ret_g_idset1_ok || adsp_sdh_is1->dsc_userid.imc_len_str == 0){
      ads_krb5_tracer->m_trace( chl_trace_tag, 3002, ads_mem_trace, &a_temp_memory,
         "no UID,Service Name=%.*(.*)s, Service Group=%.*(.*)s", adsp_akstg1->dsc_server_name.imc_len_str,
         adsp_akstg1->dsc_server_name.iec_chs_str,adsp_akstg1->dsc_server_name.ac_str,
         adsp_akstg1->dsc_server_group.imc_len_str,adsp_akstg1->dsc_server_group.iec_chs_str,
         adsp_akstg1->dsc_server_group.ac_str );
   } else{
      ads_krb5_tracer->m_trace( chl_trace_tag, 3002, ads_mem_trace, &a_temp_memory, achl_trace_msg,
         adsp_sdh_is1->dsc_userid.imc_len_str, adsp_sdh_is1->dsc_userid.iec_chs_str,
         adsp_sdh_is1->dsc_userid.ac_str, adsp_sdh_is1->dsc_user_group.imc_len_str, adsp_sdh_is1->dsc_user_group.iec_chs_str,
         adsp_sdh_is1->dsc_user_group.ac_str,adsp_akstg1->dsc_server_name.imc_len_str,
         adsp_akstg1->dsc_server_name.iec_chs_str,adsp_akstg1->dsc_server_name.ac_str,
         adsp_akstg1->dsc_server_group.imc_len_str,adsp_akstg1->dsc_server_group.iec_chs_str,
         adsp_akstg1->dsc_server_group.ac_str );
   }
   m_aux_stor_end( &a_temp_memory );
   return ads_krb5_tracer;
}

/* get Kerberos Service Ticket                                       */
extern "C" BOOL m_krb5_se_ti_get( struct dsd_aux_cf1 *adsp_aux_cf1,
                                  struct dsd_krb5_kdc_1 *adsp_krb5_kdc_1,
                                  struct dsd_aux_krb5_se_ti_get_1 *adsp_akstg1 )
{
   // input validation
   if( NULL == adsp_aux_cf1 || NULL == adsp_krb5_kdc_1 || NULL == adsp_akstg1)
   {
      return FALSE;
   }

   krb5_tracer* ads_krb5_tracer=NULL;
   int        iml1, iml2;           /* working-variables       */
   BOOL       bol1;                       /* working-variable        */
   signed char chl1;                      /* working-variable        */
   char       *achl_w1, *achl_w2;         /* working-variable        */
   struct dsd_krb5_kdc_1 *adsl_krb5_kdc_1_w1;
   struct dsd_gate_1 *adsl_gate_1;
   struct dsd_sdh_ident_set_1 dsl_sdh_is1;
   struct dsd_hl_aux_c_cma_1 dsl_cma_1;
   if( adsp_krb5_kdc_1 == NULL){
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_kdc_not_sel;
      return TRUE;
   }
   bol1 = m_aux_get_ident_set_1( adsp_aux_cf1, &dsl_sdh_is1 );
   if( bol1 == FALSE ) {                  /* error occured           */
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      return TRUE;                         /* all done                */
   }
   if( dsl_sdh_is1.iec_ret_g_idset1 == ied_ret_g_idset1_not_found ) { /* ident not found */
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_no_sign_on;  /* session not signed on */
      return TRUE;                         /* all done                */
   }
   //StSch Trace Point 3002
   if( adsp_krb5_kdc_1->imc_trace_level ) {
      ads_krb5_tracer = m_log_krb5_se_ti_get(adsp_krb5_kdc_1, adsp_akstg1, &dsl_sdh_is1);
   }
   if( dsl_sdh_is1.iec_ret_g_idset1 != ied_ret_g_idset1_ok ) { /* not ident known, parameters returned, o.k. */
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      return TRUE;                         /* all done                */
   }
   if( dsl_sdh_is1.dsc_userid.imc_len_str == 0 ) { /* no userid      */
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_no_sign_on;  /* session not signed on */
      return TRUE;                         /* all done                */
   }
   /* get TGT from CMA                                               */
   if(!m_cma_get_tgt_area(&dsl_cma_1,adsp_aux_cf1,&dsl_sdh_is1.dsc_userid,&dsl_sdh_is1.dsc_user_group,
      D_CMA_READ_DATA | D_CMA_SHARE_READ)){
         adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
         return TRUE;                       /* all done                */
   }
   if( dsl_cma_1.inc_len_cma_area == 0 ) { /* no TGT found           */
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_no_tgt;  /* TGT not found */
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
      m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
      return TRUE;                         /* all done                */
   }
   /* retrieve KRB5 configuration name                               */
   achl_w1 = dsl_cma_1.achc_cma_area;     /* address cma area        */
   achl_w2 = dsl_cma_1.achc_cma_area + dsl_cma_1.inc_len_cma_area;  /* add length of cma area */
   iml1 = 0;                              /* clear decoded value     */
   iml2 = 4;                              /* maximum number of digits */
   for(;;) {                        /* loop to retrieve digits */
      if( achl_w1 >= achl_w2 ) {           /* at end of CMA area      */
         adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
         dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
         m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
         return TRUE;                       /* all done                */
      }
      chl1 = *achl_w1++;                   /* get next byte           */
      iml1 <<= 7;                          /* shift old value         */
      iml1 |= chl1 & 0X7F;                 /* apply new bits          */
      if( chl1 >= 0 ) break;               /* more bit not set        */
      iml2--;
      if( iml2 <= 0 ) {                    /* too many digits         */
         adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
         dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
         m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
         return TRUE;                       /* all done                */
      }
   }
   if( iml1 <= 0 ) {                      /* length invalid          */
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
      m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
      return TRUE;                         /* all done                */
   }
   if(( achl_w1 + iml1 ) >= achl_w2 ) {   /* no space for TGT        */
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
      m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
      return TRUE;                         /* all done                */
   }
   if( adsp_krb5_kdc_1 ) {                /* KDC passed              */
      if(( iml1 == adsp_krb5_kdc_1->imc_len_name )
         && ( !memcmp( achl_w1, adsp_krb5_kdc_1 + 1, iml1 ) ) ) {
            adsl_krb5_kdc_1_w1 = adsp_krb5_kdc_1;  /* use this KDC        */
            goto p_kdc_ok;                     /* KDC is valid            */
      }
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
      m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
      return TRUE;                         /* all done                */
   }
   adsl_gate_1 = m_conn2gate( adsp_aux_cf1->adsc_conn );
   iml2 = 0;                              /* clear index             */
   while( iml2 < adsl_gate_1->imc_no_krb5_kdc ) { /* loop over of Kerberos 5 KDCs */
      adsl_krb5_kdc_1_w1 = adsl_gate_1->adsrc_krb5_kdc_1[ iml2 ];
      if(( iml1 == adsl_krb5_kdc_1_w1->imc_len_name )
         && ( !memcmp( achl_w1, adsl_krb5_kdc_1_w1 + 1, iml1 ) ) ) {
            goto p_kdc_ok;                     /* KDC is valid            */
      }
      iml2++;                              /* increment index         */
   }
   /* KDC not found                                                  */
   // to-do 04.02.10 KB other error number
   //     adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_kdc_not_found;  /* previously used KDC not found */
   adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
   dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock  */
   m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
   return TRUE;                           /* all done                */
p_kdc_ok:                              /* KDC is valid            */
   Krb5_Heimdal* adsl_krb5_inst = new Krb5_Heimdal( achl_w1 + iml1,( int )( achl_w2 - ( achl_w1 + iml1 ) ) );
   adsp_akstg1->vpc_handle = adsl_krb5_inst;
   adsl_krb5_inst->m_set_tracer( ads_krb5_tracer );
   if( m_set_wsp_error( *adsl_krb5_inst,&( adsp_akstg1->iec_ret_krb5 ) ) )
      goto out;
   /* copy TGT                                                       */
   // to-do 04.10.09 KB - the TGT is between achl_w1 and achl_w2
   dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock  */ /** @todo check, if lock is always released propperly */
   bol1 = m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
   if( bol1 == FALSE ) {                  /* error occured           */
      adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      goto out;
   }
   krb5_data * ads_token;
   krb5_data  ds_token_gss;
   if(adsl_krb5_inst->m_init_krb5_context(
      adsp_krb5_kdc_1,
      &( adsp_akstg1->dsc_server_name ),
      AP_OPTS_MUTUAL_REQUIRED_e,
      &ads_token ) ) {
         m_set_wsp_error( *adsl_krb5_inst,&( adsp_akstg1->iec_ret_krb5 ) );
         goto out;
   }
   if(adsl_krb5_inst->m_gss_encapsulate(
      ( struct dsd_aux_cf1* )0,
      ( struct dsd_aux_krb5_sign_on_1* )0,
      ads_token,
      &ds_token_gss,
      "\x01\x00" ) ) {
         m_set_wsp_error( *adsl_krb5_inst,&( adsp_akstg1->iec_ret_krb5 ) );
         goto out;
   }

   if( (adsp_akstg1->imc_options & HL_KRB5_OPT_GSSAPI) != 0){
      ds_spnego_krb dsl_spnego_creator;
      int inl_length = adsp_akstg1->imc_ticket_buffer_len;
      int inl_ret = dsl_spnego_creator.m_spnego_create_neg_token_init(
                                                   ien_spnego_mech_oid_kerberos_v5,
                                                   0, (unsigned char*)ds_token_gss.data,
                                                   ds_token_gss.length, NULL, 0,
                                                   adsp_akstg1->achc_ticket_buffer,
                                                   inl_length);
      switch(inl_ret)
      {
      case 0:
         adsp_akstg1->imc_ticket_length = inl_length;
         break;
      case -99999:
         adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_buf_too_sm;
         goto out;
      default:
         adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_misc;
         goto out;
      }
      adsl_krb5_inst->m_set_do_spnego(true);
   } else {
      if( adsp_akstg1->imc_ticket_buffer_len < ds_token_gss.length )
      {
         adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_buf_too_sm;
         goto out;
      }
      adsp_akstg1->imc_ticket_length = ds_token_gss.length;
      memcpy( adsp_akstg1->achc_ticket_buffer,ds_token_gss.data,ds_token_gss.length );
      adsl_krb5_inst->m_set_do_spnego(false);
   }
   adsp_akstg1->iec_ret_krb5 = ied_ret_krb5_ok;
   return TRUE;
out:
   delete adsl_krb5_inst;
   adsp_akstg1->vpc_handle = NULL;
   return TRUE;
} /* end m_krb5_se_ti_get()                                          */

/* Kerberos check Service Ticket Response                            */
extern "C" BOOL m_krb5_se_ti_c_r( struct dsd_aux_cf1 *,
                                  struct dsd_aux_krb5_se_ti_c_r_1 *adsp_akstc1 )
{
   // input validation
   if( NULL == adsp_akstc1 )
   {
      return FALSE;
   }

   krb5_data ds_token;
   krb5_data ds_token_gss;
   if( (( class Krb5_Heimdal* )( adsp_akstc1->vpc_handle ) )->m_do_spnego()){
      // This should be a SPNEGO blob, search for the krb5 blob inside
      unsigned char * aucl_real_buffer = NULL;
      int inl_real_len = 0;
      int inl_ret = m_get_krb5_token_from_neg_response(
         (unsigned char *)adsp_akstc1->achc_response_buffer,
         adsp_akstc1->imc_response_length, &aucl_real_buffer, &inl_real_len);
      if( 0 != inl_ret ){
         // Not SPNEGO or no krb5 blob inside
         adsp_akstc1->iec_ret_krb5 = ied_ret_krb5_misc;
         return FALSE;
      }
      adsp_akstc1->achc_response_buffer = (char*)aucl_real_buffer;
      adsp_akstc1->imc_response_length = inl_real_len;
   }

   ds_token_gss.data   = adsp_akstc1->achc_response_buffer;
   ds_token_gss.length = adsp_akstc1->imc_response_length;
   if((( class Krb5_Heimdal* )( adsp_akstc1->vpc_handle ) )->m_gss_decapsulate(
      ( struct dsd_aux_cf1* )0,
      ( struct dsd_aux_krb5_sign_on_1* )0,
      &ds_token,
      &ds_token_gss,
      "\x02\x00","\x03\x00" ) ) {
         m_set_wsp_error( *(( class Krb5_Heimdal* )( adsp_akstc1->vpc_handle ) ),&( adsp_akstc1->iec_ret_krb5 ) );
         return TRUE;
   }
   if((( class Krb5_Heimdal* )( adsp_akstc1->vpc_handle ) )->m_init_krb5_context(
      ( struct dsd_aux_cf1* )0,
      ( struct dsd_aux_krb5_sign_on_1* )0,
      &ds_token,
      AP_OPTS_MUTUAL_REQUIRED_e ) ) {
         m_set_wsp_error( *(( class Krb5_Heimdal* )( adsp_akstc1->vpc_handle ) ),&( adsp_akstc1->iec_ret_krb5 ) );
         return TRUE;                                    /* all done                */
   }
   adsp_akstc1->iec_ret_krb5 = ied_ret_krb5_ok;  /* success           */
   return TRUE;                            /* all done                */
} /* end m_krb5_se_ti_c_r()                                          */

/* Kerberos encrypt data                                             */
extern "C" BOOL m_krb5_encrypt( struct dsd_aux_cf1 *,
                                struct dsd_aux_krb5_encrypt *adsp_akenc1 )
{
   // input validation
   if( NULL == adsp_akenc1 )
   {
      return FALSE;
   }

   krb5_data ds_data;
   krb5_data ds_packet;
   ds_data.length = adsp_akenc1->imc_len_inp_data;
   ds_data.data   = adsp_akenc1->achc_inp_data;
   if((( class Krb5_Heimdal* )( adsp_akenc1->vpc_handle ) )->m_gss_wrap(( struct dsd_aux_cf1* )0,
      ( struct dsd_aux_krb5_sign_on_1* )0,
      &ds_data,&ds_packet ) ) {
         m_set_wsp_error( *(( class Krb5_Heimdal* )( adsp_akenc1->vpc_handle ) ),&( adsp_akenc1->iec_ret_krb5 ) );
         return TRUE;                                    /* all done                */
   }
   if( adsp_akenc1->imc_enc_buffer_len < ds_packet.length ) {
      adsp_akenc1->iec_ret_krb5 = ied_ret_krb5_buf_too_sm;  /* buffer size is to small */
      return TRUE;                                         /* all done                */
   }
   adsp_akenc1->imc_enc_len_ret = ds_packet.length;
   memcpy( adsp_akenc1->achc_out_enc_buffer,ds_packet.data,ds_packet.length );
   if((( class Krb5_Heimdal* )( adsp_akenc1->vpc_handle ) )->m_krb5_data_free(( struct dsd_aux_cf1* )0,
      ( struct dsd_aux_krb5_sign_on_1* )0,
      &ds_packet ) ) {
         m_set_wsp_error( *(( class Krb5_Heimdal* )( adsp_akenc1->vpc_handle ) ),&( adsp_akenc1->iec_ret_krb5 ) );
         return TRUE;                                    /* all done                */
   }
   adsp_akenc1->iec_ret_krb5 = ied_ret_krb5_ok;  /* success           */
   return TRUE;                            /* all done                */
} /* end m_krb5_encrypt()                                            */

/* Kerberos decrypt data                                             */
extern "C" BOOL m_krb5_decrypt( struct dsd_aux_cf1 *,
                                struct dsd_aux_krb5_decrypt *adsp_akdec1 )
{
   // input validation
   if( NULL == adsp_akdec1 )
   {
      return FALSE;
   }

   krb5_data ds_data;
   krb5_data ds_packet;
   ds_data.length = adsp_akdec1->imc_len_inp_enc_data;
   ds_data.data   = adsp_akdec1->achc_inp_enc_data;
   if((( class Krb5_Heimdal* )( adsp_akdec1->vpc_handle ) )->m_gss_unwrap(( struct dsd_aux_cf1* )0,
      ( struct dsd_aux_krb5_sign_on_1* )0,
      &ds_data,&ds_packet ) ) {
         m_set_wsp_error( *(( class Krb5_Heimdal* )( adsp_akdec1->vpc_handle ) ),&( adsp_akdec1->iec_ret_krb5 ) );
         return TRUE;                                    /* all done                */
   }
   if( adsp_akdec1->imc_dec_buffer_len < ds_packet.length ) {
      adsp_akdec1->iec_ret_krb5 = ied_ret_krb5_buf_too_sm;  /* buffer size is to small */
      return TRUE;                                         /* all done                */
   }
   adsp_akdec1->imc_dec_len_ret = ds_packet.length;
   memcpy( adsp_akdec1->achc_out_dec_buffer,ds_packet.data,ds_packet.length );
   if((( class Krb5_Heimdal* )( adsp_akdec1->vpc_handle ) )->m_krb5_data_free(( struct dsd_aux_cf1* )0,
      ( struct dsd_aux_krb5_sign_on_1* )0,
      &ds_packet ) ) {
         m_set_wsp_error( *(( class Krb5_Heimdal* )( adsp_akdec1->vpc_handle ) ),&( adsp_akdec1->iec_ret_krb5 ) );
         return TRUE;                                    /* all done                */
   }
   adsp_akdec1->iec_ret_krb5 = ied_ret_krb5_ok;  /* success           */
   return TRUE;                            /* all done                */
} /* end m_krb5_decrypt()                                            */

/**
Fetches the session key of a session initialized by m_krb5_se_ti_get.

The key will be stored in the buffer provided by adsp_get_session_key. If no or
insufficient buffer is provided, ied_ret_krb5_buf_too_sm is returned and the
required length is written to imc_key_len_ret. If no key is found,
ied_ret_krb5_key_not_found is returned.

If the input pointer or session object are NULL, FALSE is returned.

@param[inout]  adsp_get_session_key Pointer to the structure holding all parameters.

@return TRUE on success, FALSE on error.
*/
extern "C" BOOL m_krb5_get_session_key( struct dsd_aux_krb5_get_session_key* adsp_get_session_key )
{
   // Input validation
   if( NULL == adsp_get_session_key ||
      NULL == adsp_get_session_key->vpc_handle)
   {
      // No input or session pointer
      return FALSE;
   }
   if( (( class Krb5_Heimdal* )(adsp_get_session_key->vpc_handle))->
      m_gss_get_session_key(adsp_get_session_key)){
         if( (adsp_get_session_key->imc_key_len_ret) > (adsp_get_session_key->imc_key_buffer_len) ) {
            adsp_get_session_key->iec_ret_krb5 = ied_ret_krb5_buf_too_sm;
         } else {
            m_set_wsp_error( *(( class Krb5_Heimdal* )( adsp_get_session_key->vpc_handle ) ),
               &( adsp_get_session_key->iec_ret_krb5 ) );
         }
         (( class Krb5_Heimdal* )(adsp_get_session_key->vpc_handle))->m_invalidate();
         return FALSE;
   }
   return TRUE;
}

/* Kerberos release Service Ticket Resources                         */
extern "C" BOOL m_krb5_se_ti_rel( struct dsd_aux_cf1 *,
                                  struct dsd_aux_krb5_se_ti_rel_1 *adsp_akstr1 )
{
   // input validation
   if( NULL == adsp_akstr1 )
   {
      return FALSE;
   }
   adsp_akstr1->iec_ret_krb5 = ied_ret_krb5_ok;
   delete(( class Krb5_Heimdal* )adsp_akstr1->vpc_handle );
   return TRUE;                          /* all done                */
} /* end m_krb5_se_ti_rel()                                        */

/* release Kerberos TGT                                            */
extern "C" BOOL m_krb5_logoff( struct dsd_aux_cf1 *adsp_aux_cf1,
                               struct dsd_aux_krb5_logoff *adsp_aklo )
{
   // input validation
   if( NULL == adsp_aux_cf1 || NULL == adsp_aklo )
   {
      return FALSE;
   }

   BOOL       bol1;                       /* working-variable        */
   struct dsd_sdh_ident_set_1 dsl_sdh_is1;
   struct dsd_hl_aux_c_cma_1 dsl_cma_1;
   bol1 = m_aux_get_ident_set_1( adsp_aux_cf1, &dsl_sdh_is1 );
   if( bol1 == FALSE ) {                /* error occured           */
      adsp_aklo->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      return TRUE;                       /* all done                */
   }
   if( dsl_sdh_is1.iec_ret_g_idset1 == ied_ret_g_idset1_not_found ) { /* ident not found */
      adsp_aklo->iec_ret_krb5 = ied_ret_krb5_no_sign_on;  /* session not signed on */
      return TRUE;                       /* all done                */
   }
   if( dsl_sdh_is1.iec_ret_g_idset1 != ied_ret_g_idset1_ok ) { /* not ident known, parameters returned, o.k. */
      adsp_aklo->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      return TRUE;                       /* all done                */
   }
   if( dsl_sdh_is1.dsc_userid.imc_len_str == 0 ) { /* no userid    */
      adsp_aklo->iec_ret_krb5 = ied_ret_krb5_no_sign_on;  /* session not signed on */
      return TRUE;                       /* all done                */
   }
   /* get TGT from CMA                                             */
   if(!m_cma_get_tgt_area(&dsl_cma_1,adsp_aux_cf1,&dsl_sdh_is1.dsc_userid,&dsl_sdh_is1.dsc_user_group,
      D_CMA_ALL_ACCESS)){ /** @todo check, if propper flags are set */
         adsp_aklo->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
         return TRUE;                       /* all done                */
   }
   if( dsl_cma_1.inc_len_cma_area == 0 ) { /* no TGT found         */
      adsp_aklo->iec_ret_krb5 = ied_ret_krb5_no_tgt;  /* TGT not found */
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
      m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
      return TRUE;                       /* all done                */
   }
   /* delete entry in CMA                                          */
   dsl_cma_1.inc_len_cma_area = 0;
   dsl_cma_1.iec_ccma_def = ied_ccma_set_size;  /* set new size of cma area */
   m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 ); /** @todo make memset 0 for tgt */
   dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
   m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
   adsp_aklo->iec_ret_krb5 = ied_ret_krb5_ok;  /* success          */
return TRUE;                         /* all done                */
} /* end m_krb5_logoff()                                           */

/* assign Kerberos Configuration Entry to session                  */
extern "C" struct dsd_krb5_kdc_1 * m_krb5_session_assign_conf( struct dsd_aux_cf1 *adsp_aux_cf1,
                                                               struct dsd_aux_krb5_session_assign_conf *adsp_aksac )
{
   // input validation
   if( NULL == adsp_aux_cf1 || NULL == adsp_aksac )
   {
      return FALSE;
   }

   /** @todo Find out, what this function is doing */
   int        iml1, iml2;         /* working-variables       */
   BOOL       bol1;                     /* working-variable        */
   signed char chl1;                    /* working-variable        */
   char       *achl_w1, *achl_w2;       /* working-variable        */
   struct dsd_krb5_kdc_1 *adsl_krb5_kdc_1_w1;
   struct dsd_gate_1 *adsl_gate_1;
   struct dsd_sdh_ident_set_1 dsl_sdh_is1;
   struct dsd_hl_aux_c_cma_1 dsl_cma_1;

   bol1 = m_aux_get_ident_set_1( adsp_aux_cf1, &dsl_sdh_is1 );
   if( bol1 == FALSE ) {                /* error occured           */
      adsp_aksac->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      return NULL;                       /* all done                */
   }
   if( dsl_sdh_is1.iec_ret_g_idset1 == ied_ret_g_idset1_not_found ) { /* ident not found */
      adsp_aksac->iec_ret_krb5 = ied_ret_krb5_no_sign_on;  /* session not signed on */
      return NULL;                       /* all done                */
   }
   if( dsl_sdh_is1.iec_ret_g_idset1 != ied_ret_g_idset1_ok ) { /* not ident known, parameters returned, o.k. */
      adsp_aksac->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      return NULL;                       /* all done                */
   }
   if( dsl_sdh_is1.dsc_userid.imc_len_str == 0 ) { /* no userid    */
      adsp_aksac->iec_ret_krb5 = ied_ret_krb5_no_sign_on;  /* session not signed on */
      return NULL;                       /* all done                */
   }
   /* get TGT from CMA                                             */
   if(!m_cma_get_tgt_area(&dsl_cma_1,adsp_aux_cf1,&dsl_sdh_is1.dsc_userid,&dsl_sdh_is1.dsc_user_group,
      D_CMA_READ_DATA | D_CMA_SHARE_READ)){
         adsp_aksac->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
         return NULL;                       /* all done                */
   }
   if( dsl_cma_1.inc_len_cma_area == 0 ) { /* no TGT found           */
      adsp_aksac->iec_ret_krb5 = ied_ret_krb5_no_tgt;  /* TGT not found */
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
      m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
      return NULL;                       /* all done                */
   }
   /* retrieve KRB5 configuration name                             */
   achl_w1 = dsl_cma_1.achc_cma_area;   /* address cma area        */
   achl_w2 = dsl_cma_1.achc_cma_area + dsl_cma_1.inc_len_cma_area;  /* add length of cma area */
   iml1 = 0;                            /* clear decoded value     */
   iml2 = 4;                            /* maximum number of digits */
   for(;;) {                      /* loop to retrieve digits */
      if( achl_w1 >= achl_w2 ) {         /* at end of CMA area      */
         adsp_aksac->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
         dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
         m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
         return NULL;                     /* all done                */
      }
      chl1 = *achl_w1++;                 /* get next byte           */
      iml1 <<= 7;                        /* shift old value         */
      iml1 |= chl1 & 0X7F;               /* apply new bits          */
      if( chl1 >= 0 ) break;             /* more bit not set        */
      iml2--;
      if( iml2 <= 0 ) {                  /* too many digits         */
         adsp_aksac->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
         dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
         m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
         return NULL;                     /* all done                */
      }
   }
   if( iml1 <= 0 ) {                    /* length invalid          */
      adsp_aksac->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
      m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
      return NULL;                       /* all done                */
   }
   if(( achl_w1 + iml1 ) >= achl_w2 ) { /* no space for TGT        */
      adsp_aksac->iec_ret_krb5 = ied_ret_krb5_misc;  /* miscellaneous error */
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */
      m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
      return NULL;                       /* all done                */
   }
   adsl_gate_1 = m_conn2gate( adsp_aux_cf1->adsc_conn );
   iml2 = 0;                            /* clear index             */
   while( iml2 < adsl_gate_1->imc_no_krb5_kdc ) { /* loop over of Kerberos 5 KDCs */
      adsl_krb5_kdc_1_w1 = adsl_gate_1->adsrc_krb5_kdc_1[ iml2 ];
      if(( iml1 == adsl_krb5_kdc_1_w1->imc_len_name )
         && ( !memcmp( achl_w1, adsl_krb5_kdc_1_w1 + 1, iml1 ) ) ) {
            adsp_aksac->iec_ret_krb5 = ied_ret_krb5_ok;  /* success     */
            /** @todo Check, if it is intended to keep the CMA locked */
            return adsl_krb5_kdc_1_w1;       /* all done                */
      }
      iml2++;                            /* increment index         */
   }
   /* KDC not found                                                  */
   adsp_aksac->iec_ret_krb5 = ied_ret_krb5_kdc_not_found;  /* previously used KDC not found */
   dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;  /* release lock */ /** @todo check, if locks are released propperly */
   m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
   return NULL;                         /* all done                */
} /* end m_krb5_session_assign_conf()                              */

/*
* Change a Principals password
* @param adsp_aux_cf1 Main configuration structure
* @param adsp_krb5_kdc_1 KDC Configuration
* @param adsp_akso1 Login data, including new password. Passwords will be 0ed out
*
* @return Always TRUE
*/
extern "C" BOOL m_krb5_change_pw( struct dsd_aux_cf1 *adsp_aux_cf1,
                                  struct dsd_krb5_kdc_1 *adsp_krb5_kdc_1,
                                  struct dsd_aux_krb5_sign_on_1 *adsp_akso1)
{
   // Input validation
   if( NULL == adsp_aux_cf1 || NULL == adsp_krb5_kdc_1 || NULL == adsp_akso1 )
   {
      return FALSE;
   }

   //StSch Trace Point 3005
   Krb5_Heimdal ds_krb5_instanc = Krb5_Heimdal();   /* temporary instance for PW change */
   if( adsp_krb5_kdc_1 == NULL){
      adsp_akso1->iec_ret_krb5 = ied_ret_krb5_kdc_not_sel;
      return TRUE;
   }
   if( adsp_krb5_kdc_1->imc_trace_level ) {
      void* a_temp_memory;
      m_aux_stor_start( &a_temp_memory );
      krb5_tracer* ads_krb5_tracer = new krb5_tracer( adsp_krb5_kdc_1, adsp_krb5_kdc_1->imc_trace_level, "KRB" );
      struct dsd_memory_traces* ads_mem_trace=m_init_krb5_mem_trace( &a_temp_memory );
      char* achl_trace_msg= "User Name=%.*(.*)s,\nUser Group=%.*(.*)s";
      void* a_chcksum_pw=m_aux_stor_alloc( &a_temp_memory,20 );
      char chl_trace_tag='I';
      if( adsp_krb5_kdc_1->imc_trace_level>=2 ) {
         dsd_krb5_kdc_server* ads_krb5_kdc=adsp_krb5_kdc_1->adsc_kdc_server->adsc_next;
         int inl_in1=3;
         chl_trace_tag='T';
         m_krb5_sha1( adsp_akso1->dsc_password.ac_str, adsp_akso1->dsc_password.imc_len_str, a_chcksum_pw, &a_temp_memory );
         m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace, adsp_krb5_kdc_1, sizeof( dsd_krb5_kdc_1 ),"adsp_krb5_kdc_1:" );
         m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace, a_chcksum_pw, 20, "P-Hash:" );
         m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace, adsp_krb5_kdc_1->adsc_kdc_server, sizeof( dsd_krb5_kdc_server ),
            "krb5 kdc:" );
         for( ; ads_krb5_kdc!=NULL; ads_krb5_kdc=ads_krb5_kdc->adsc_next,inl_in1++ ) {
            m_krb5_trace_memcat( &a_temp_memory, ads_mem_trace,ads_krb5_kdc,sizeof( dsd_krb5_kdc_server ),"krb5 kdc:" );
         }
      }
      ads_krb5_tracer->m_trace( chl_trace_tag, 3005, ads_mem_trace, &a_temp_memory, achl_trace_msg,
         adsp_akso1->dsc_user_name.imc_len_str, adsp_akso1->dsc_user_name.iec_chs_str,
         adsp_akso1->dsc_user_name.ac_str, adsp_akso1->dsc_user_group.imc_len_str, adsp_akso1->dsc_user_group.iec_chs_str,
         adsp_akso1->dsc_user_group.ac_str );
      m_aux_stor_end( &a_temp_memory );
      ds_krb5_instanc.m_set_tracer( ads_krb5_tracer );
   }

   if( m_set_wsp_error( ds_krb5_instanc,&( adsp_akso1->iec_ret_krb5 ) ) )
      return TRUE;
   if( ds_krb5_instanc.m_krb5_change_pw( adsp_aux_cf1,
                                         adsp_krb5_kdc_1,
                                         adsp_krb5_kdc_1->adsc_kdc_server,
                                         &adsp_akso1->dsc_user_name,   /* Username Sign On */
                                         &adsp_akso1->dsc_password,    /* Old password */
                                         &adsp_akso1->dsc_new_password ) ) /* Change password */
   {
      m_set_wsp_error( ds_krb5_instanc,&( adsp_akso1->iec_ret_krb5 ) );
   }
   return TRUE;

}//extern "C" BOOL m_krb5_change_pw( struct dsd_aux_cf1 *adsp_aux_cf1, struct dsd_krb5_kdc_1 *adsp_krb5_kdc_1, struct dsd_aux_krb5_sign_on_1 *adsp_akso1 );

/**
*  Checks an AS_REQ with a provided keytab.
*
*  This function is used to create a service-side, validating an incomming AS_REQ and writing a proper reply.
*
*  The provided keytab must be either in in raw MIT binary format (covers Active Directory) or in Heimdal keydump format.
*  When providing a Heimdal dump, it should be 0-terminated. The function can compensate missing 0-termination, but with
*  loss of performance. Binary keytabs must not be 0-terminated.
*
*/
extern "C" BOOL m_krb5_se_ti_check_request( struct dsd_aux_cf1 *,
                                            struct dsd_aux_krb5_se_ti_check_1 * adsp_aux_krb5_se_ti_check_1)
{
   // Input validation
   if( NULL == adsp_aux_krb5_se_ti_check_1 )
   {
      return FALSE;
   }
   krb5_tracer * adsl_tracer = new  krb5_tracer(NULL);
   Krb5_Heimdal * adsl_heim_instance= new Krb5_Heimdal();
   krb5_data ds_token;
   krb5_data ds_token_gss;
   krb5_data *ads_token_out;
   krb5_data ds_token_gss_out;

   if (NULL == adsp_aux_krb5_se_ti_check_1){
      return FALSE;
   }
   ds_token_gss.data   = adsp_aux_krb5_se_ti_check_1->achc_ticket_in;
   ds_token_gss.length = adsp_aux_krb5_se_ti_check_1->imc_ticket_length;
   if( ( NULL == adsp_aux_krb5_se_ti_check_1->achc_keytab ) ){
      adsp_aux_krb5_se_ti_check_1->iec_ret_krb5 = ied_ret_krb5_misc;
      return FALSE;
   }
   adsl_heim_instance->m_set_tracer(adsl_tracer);
   if(adsl_heim_instance->m_gss_decapsulate(
      ( struct dsd_aux_cf1* )0,
      ( struct dsd_aux_krb5_sign_on_1* )0,
      &ds_token,
      &ds_token_gss,
      "\x01\x00",NULL ) ) {
         m_set_wsp_error( *adsl_heim_instance,&( adsp_aux_krb5_se_ti_check_1->iec_ret_krb5 ) );
         goto out;
   }
   if(adsl_heim_instance->m_init_krb5_context(
      ( struct dsd_aux_cf1* )0,
      adsp_aux_krb5_se_ti_check_1,
      &ds_token,
      &ads_token_out ) )
   {
      m_set_wsp_error( *adsl_heim_instance,&( adsp_aux_krb5_se_ti_check_1->iec_ret_krb5 ) );
      if(ads_token_out){
         if(adsl_heim_instance->m_gss_encapsulate(
            ( struct dsd_aux_cf1* )0,
            ( struct dsd_aux_krb5_sign_on_1* )0,
            ads_token_out,
            &ds_token_gss_out,
            "\x03\x00"))
         {
            m_set_wsp_error( *adsl_heim_instance,&( adsp_aux_krb5_se_ti_check_1->iec_ret_krb5 ) );
            goto out;
         }
         if( ( NULL == adsp_aux_krb5_se_ti_check_1->achc_mutual_resp_buffer) ||
            ( adsp_aux_krb5_se_ti_check_1->imc_mutual_resp_buffer_len < ds_token_gss_out.length )) {
               adsp_aux_krb5_se_ti_check_1->iec_ret_krb5 = ied_ret_krb5_buf_too_sm;  /* buffer size is to small */
               goto out;
         }
         adsp_aux_krb5_se_ti_check_1->imc_mutual_resp_length = ds_token_gss_out.length;  /* length of returned service ticket */
         memcpy( adsp_aux_krb5_se_ti_check_1->achc_mutual_resp_buffer,ds_token_gss_out.data,ds_token_gss_out.length );
      }
      goto out;
   }
   if(adsl_heim_instance->m_gss_encapsulate(
      ( struct dsd_aux_cf1* )0,
      ( struct dsd_aux_krb5_sign_on_1* )0,
      ads_token_out,
      &ds_token_gss_out,
      "\x02\x00")) {
         m_set_wsp_error( *adsl_heim_instance,&( adsp_aux_krb5_se_ti_check_1->iec_ret_krb5 ) );
         goto out;
   }
   if( ( NULL == adsp_aux_krb5_se_ti_check_1->achc_mutual_resp_buffer) ||
      (adsp_aux_krb5_se_ti_check_1->imc_mutual_resp_buffer_len < ds_token_gss_out.length )) {
         adsp_aux_krb5_se_ti_check_1->iec_ret_krb5 = ied_ret_krb5_buf_too_sm;  /* buffer size is to small */
         goto out;
   }
   adsp_aux_krb5_se_ti_check_1->imc_mutual_resp_length = ds_token_gss_out.length;  /* length of returned service ticket */
   memcpy( adsp_aux_krb5_se_ti_check_1->achc_mutual_resp_buffer,ds_token_gss_out.data,ds_token_gss_out.length );
   if(adsp_aux_krb5_se_ti_check_1->dsc_aux_krb5_opt_1.ibc_no_ret_handle) {
      delete adsl_heim_instance;
   } else {
      adsp_aux_krb5_se_ti_check_1->vpc_handle=adsl_heim_instance;
   }
   adsp_aux_krb5_se_ti_check_1->iec_ret_krb5 = ied_ret_krb5_ok;  /* success           */
   return TRUE;                            /* all done                */
out:
   delete adsl_heim_instance;
   return TRUE;
}//extern "C" BOOL m_krb5_se_ti_check_request( struct dsd_aux_cf1 *, struct dsd_aux_krb5_se_ti_check_1 * );

extern "C" BOOL m_cma_get_tgt_area(struct dsd_hl_aux_c_cma_1 *adsp_cma_1,
                                   struct dsd_aux_cf1 *adsp_aux_cf1,
                                   struct dsd_unicode_string *adsp_userid,
                                   struct dsd_unicode_string *adsp_usergroup,
                                   int imp_lock_type)
{
   /*workign variables*/
   char * achl_w1;
   char chrl_work1[512];
   int iml1;
   BOOL bol1;
   memset( adsp_cma_1, 0, sizeof( struct dsd_hl_aux_c_cma_1 ) );
   achl_w1 = chrl_work1;
   *achl_w1++ = 'k';
   *achl_w1++ = 'r';
   *achl_w1++ = 'b';
   *achl_w1++ = '5';
   /* zero as separator                                            */
   *achl_w1++ = ( unsigned char ) 0XC0;
   *achl_w1++ = ( unsigned char ) 0X80;
   /* user-group                                                   */
#ifdef WITH_USER_GROUP
   if( adsp_usergroup->imc_len_str != 0 ) { /* length string in elements */
      iml1 = m_cpy_lc_vx_vx( achl_w1, chrl_work1 + sizeof( chrl_work1 ) - achl_w1, ied_chs_utf_8,
         adsp_usergroup->ac_str,
         adsp_usergroup->imc_len_str,
         adsp_usergroup->iec_chs_str );
      achl_w1 += iml1;
   }
#endif
   /* zero as separator                                            */
   *achl_w1++ = ( unsigned char ) 0XC0;
   *achl_w1++ = ( unsigned char ) 0X80;
   /* user-name                                                    */
   iml1 = m_cpy_lc_vx_vx( achl_w1, chrl_work1 + sizeof( chrl_work1 ) - achl_w1, ied_chs_utf_8,
      adsp_userid->ac_str,
      adsp_userid->imc_len_str,
      adsp_userid->iec_chs_str );
   achl_w1 += iml1;
   adsp_cma_1->ac_cma_name = chrl_work1;    /* cma name              */
   adsp_cma_1->iec_chs_name = ied_chs_utf_8;  /* character set       */
   adsp_cma_1->inc_len_cma_name = achl_w1 - chrl_work1;  /* length cma name in elements */
   adsp_cma_1->iec_ccma_def = ied_ccma_lock_global;  /* set global lock */
   adsp_cma_1->imc_lock_type = imp_lock_type;  /* set access type */
   bol1 = m_cma1_proc( adsp_aux_cf1, adsp_cma_1 );
   if( bol1 == FALSE ) {                /* error occured           */
      return FALSE;                       /* all done                */
   }
   return TRUE;
}//int m_cma_get_tgt_area(struct dsd_hl_aux_c_cma_1 *adsp_cma_1, struct dsd_aux_cf1 *adsp_aux_cf1, struct dsd_unicode_string *adsp_userid, struct dsd_unicode_string *adsp_usergroup, int imp_lock_type);

/**
*  Replay cache function for use in m_krb5_se_req_acc(). Replay cache use is exclusive per
*  Service Principle name. Parameters will not be checked!
*
*  @param adsp_aux_cf1                     Main configuration structure.
*  @param achp_service_principal_name      Name of the Service Principal receiving the AP REQ.
*  @param avop_authenticator_hash          SHA1 Hash of the Authenticator.
*  @param imp_max_skew                     KRB5 time skew.
*
*  @return Returns 0, if no Replay is detected, -1 on CMA error and KRB5KRB_AP_ERR_REPEAT,
*          if a replay is detected.
**/
extern "C" int m_krb5_check_replay_cache( struct dsd_aux_cf1 *adsp_aux_cf1,
                                          const char* achp_service_principal_name,
                                          const void * avop_authenticator_hash,
                                          int imp_max_skew)
{
   /* Working variables */
   char chrl_work1[512];
   char *achl_w1;
   int iml1;
   BOOL bol1;
   struct dsd_hl_aux_c_cma_1 dsl_cma_1;
   int iml_ret=0;                              /* Return value */
   BOOL bol_update_cma=false;                  /* Flag, if cache is updated */
   HL_LONGLONG current_time;                   /* Current timestamp */
   struct dsd_krb5_rep_c_header * adsl_cache1 = NULL;  /* Pointer to first cache */
   struct dsd_krb5_rep_c_header * adsl_cache2 = NULL;  /* Pointer to second cache */
   struct dsd_krb5_rep_c_entry * adsl_new_entry;       /* Pointer for new cache entry */
   struct dsd_krb5_rep_c_entry * adsl_root_entry;      /* Pointer to root of current cache */
   struct dsd_krb5_rep_c_entry * adsl_current_entry;   /* Search pointer */

#ifndef HOB_KRB5_UNIT_TEST
   current_time=m_get_epoch_ms()/1000;
#else
   current_time=test_time_stamp;
#endif
   iml1=strlen(achp_service_principal_name);
   achl_w1=chrl_work1;
   memcpy(achl_w1,achp_service_principal_name,iml1);
   achl_w1+=iml1;
   /* zero as separator                                            */
   *achl_w1++ = ( unsigned char ) 0XC0;
   *achl_w1++ = ( unsigned char ) 0X80;
   memcpy(achl_w1,"replay_cache",13);
   /* Get the cache sections */
   dsl_cma_1.ac_cma_name = chrl_work1;    /* cma name              */
   dsl_cma_1.iec_chs_name = ied_chs_utf_8;  /* character set       */
   dsl_cma_1.inc_len_cma_name = iml1+15;  /* length cma name in elements */
   dsl_cma_1.iec_ccma_def = ied_ccma_lock_global;  /* set global lock */
   dsl_cma_1.imc_lock_type = D_CMA_ALL_ACCESS;  /* set access type */
#ifndef HOB_KRB5_UNIT_TEST
   bol1 = m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
   if(!bol1){
      return -1;
   }
#else
   dsl_cma_1=dsg_cma_1;
#endif
   if( dsl_cma_1.inc_len_cma_area ==0 ){
      /* Initialize cache */
      dsl_cma_1.iec_ccma_def = ied_ccma_set_size;
      dsl_cma_1.inc_len_cma_area = 2*(sizeof(struct dsd_krb5_rep_c_header)+
         sizeof(struct dsd_krb5_rep_c_entry));
#ifndef HOB_KRB5_UNIT_TEST
      m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
#else
      dsl_cma_1.achc_cma_area=(char*)realloc(dsl_cma_1.achc_cma_area,dsl_cma_1.inc_len_cma_area);
      dsg_cma_1=dsl_cma_1;
#endif
      memset(dsl_cma_1.achc_cma_area,0,dsl_cma_1.inc_len_cma_area);
      adsl_cache1=(struct dsd_krb5_rep_c_header*)dsl_cma_1.achc_cma_area;
      adsl_cache1->im_max_len=1;
   }
   adsl_cache1=(struct dsd_krb5_rep_c_header *)dsl_cma_1.achc_cma_area;
   adsl_cache2=(struct dsd_krb5_rep_c_header *)(dsl_cma_1.achc_cma_area+
      dsl_cma_1.inc_len_cma_area/2);

   /* First check the older cache */
   if(adsl_cache2->im_time_skew<imp_max_skew){
      /* Time skew was raised, correct retention time */
      adsl_cache2->retention_time+=(2*(imp_max_skew-adsl_cache2->im_time_skew));
      adsl_cache2->im_time_skew=imp_max_skew;
      bol_update_cma=true;
   }
   if(adsl_cache2->retention_time>current_time){
      int inl_next_index=0;
      int inl_memcmp_result;
      adsl_root_entry = (struct dsd_krb5_rep_c_entry *)(adsl_cache2+1);
      while(inl_next_index!=-1){
         adsl_current_entry = adsl_root_entry+inl_next_index;
         inl_memcmp_result=memcmp(avop_authenticator_hash,
            adsl_current_entry->vorc_auth_hash,20);
         if(inl_memcmp_result>0){
            inl_next_index=adsl_current_entry->imc_right_index;
         }else if(inl_memcmp_result<0){
            inl_next_index=adsl_current_entry->imc_left_index;
         }else{
            /* Replay found */
            iml_ret=KRB5KRB_AP_ERR_REPEAT;
            goto out;
         }
      }
   }
   /* Then check the newer cache */
   if(adsl_cache1 && adsl_cache1->im_time_skew<imp_max_skew){
      /* Time skew was raised, correct retention time */
      adsl_cache1->retention_time+=(2*(imp_max_skew-adsl_cache1->im_time_skew));
      adsl_cache1->im_time_skew=imp_max_skew;
      bol_update_cma=true;
   }

   if(adsl_cache1->retention_time<current_time){
      /* No cache or cache outdated */
      adsl_cache1->im_len=1;
      adsl_cache1->retention_time=current_time+(2*imp_max_skew);
      adsl_cache1->im_time_skew=imp_max_skew;
      adsl_new_entry=(struct dsd_krb5_rep_c_entry*)(adsl_cache1+1);
      adsl_new_entry->imc_left_index=-1;
      adsl_new_entry->imc_right_index=-1;
      memcpy(adsl_new_entry->vorc_auth_hash,avop_authenticator_hash,20);
#ifndef HOB_KRB5_UNIT_TEST
      bol_update_cma=true;
#endif
   }else{
      /* Search current cache */
      int inl_next_index=0;
      int inl_memcmp_result;
      adsl_root_entry = (struct dsd_krb5_rep_c_entry *)(adsl_cache1+1);
      do{
         adsl_current_entry = adsl_root_entry+inl_next_index;
         inl_memcmp_result=memcmp(avop_authenticator_hash,
            adsl_current_entry->vorc_auth_hash,20);
         if(inl_memcmp_result>0){
            inl_next_index=adsl_current_entry->imc_right_index;
         }else if(inl_memcmp_result<0){
            inl_next_index=adsl_current_entry->imc_left_index;
         }else{
            /* Replay found */
            iml_ret=KRB5KRB_AP_ERR_REPEAT;
            goto out;
         }
      }while(inl_next_index!=-1);
      if(adsl_cache1->retention_time<(current_time+imp_max_skew)){
         /* Current cache is old, copy to CMA 2 and make new one */
         memcpy(adsl_cache2,adsl_cache1,dsl_cma_1.inc_len_cma_area/2);
         adsl_cache1->im_len=1;
         adsl_cache1->retention_time=current_time+(2*imp_max_skew);
         adsl_cache1->im_time_skew=imp_max_skew;
         adsl_new_entry=(struct dsd_krb5_rep_c_entry*)(adsl_cache1+1);
         adsl_new_entry->imc_left_index=-1;
         adsl_new_entry->imc_right_index=-1;
         memcpy(adsl_new_entry->vorc_auth_hash,avop_authenticator_hash,20);
         bol_update_cma=true;
#ifdef HOB_KRB5_UNIT_TEST
         dsg_cma_1=dsl_cma_1;
#endif
      } else {
         /* Add entry to current cache */
         int iml_new_entry_offset;
         iml_new_entry_offset=sizeof(struct dsd_krb5_rep_c_header)+
            adsl_cache1->im_len*sizeof(struct dsd_krb5_rep_c_entry);
         if(inl_memcmp_result>0){
            adsl_current_entry->imc_right_index=adsl_cache1->im_len;
         }else{
            adsl_current_entry->imc_left_index=adsl_cache1->im_len;
         }
         adsl_cache1->im_len++;
         if(adsl_cache1->im_len>adsl_cache1->im_max_len){
            /* Resizing needed */
            adsl_cache1->im_max_len++;
            dsl_cma_1.iec_ccma_def = ied_ccma_set_size;
            dsl_cma_1.inc_len_cma_area +=2*sizeof(struct dsd_krb5_rep_c_entry);
#ifndef HOB_KRB5_UNIT_TEST
            m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
#else
            dsl_cma_1.achc_cma_area=(char*)realloc(dsl_cma_1.achc_cma_area,dsl_cma_1.inc_len_cma_area);
            dsg_cma_1=dsl_cma_1;
#endif
            adsl_cache1=(struct dsd_krb5_rep_c_header *)dsl_cma_1.achc_cma_area;
            /* Move old cache section */ //Todo: better comment
            memmove(dsl_cma_1.achc_cma_area+iml_new_entry_offset+sizeof(struct dsd_krb5_rep_c_entry),
               dsl_cma_1.achc_cma_area+iml_new_entry_offset,iml_new_entry_offset);
         }
         adsl_new_entry=(struct dsd_krb5_rep_c_entry*)(dsl_cma_1.achc_cma_area+
            iml_new_entry_offset);
         adsl_new_entry->imc_left_index=-1;
         adsl_new_entry->imc_right_index=-1;
         memcpy(adsl_new_entry->vorc_auth_hash,avop_authenticator_hash,20);
         bol_update_cma=true;
#ifdef HOB_KRB5_UNIT_TEST
         dsg_cma_1=dsl_cma_1;
#endif
      }
   }

out:
#ifndef HOB_KRB5_UNIT_TEST
   if(bol_update_cma){
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_rel_upd;
   }else{
      dsl_cma_1.iec_ccma_def = ied_ccma_lock_release;
   }
   m_cma1_proc( adsp_aux_cf1, &dsl_cma_1 );
#endif

   return iml_ret;

}//extern "C" int m_krb5_check_replay_cache( struct dsd_aux_cf1 *adsp_aux_cf1, const char* achp_service_principal_name, const struct krb5_authenticator, int imp_max_skew )

/**
*  Conversion function for MIT keytabs.
*
*  As MIT keytabs are encrypted with a master key, they have to be converted to a
*  clear text format before using. As this is somewhat timeconsuming, it should be done,
*  when loading the keytab.
*
*  The returned keytab will be in Heimdal format, cleartext and null-terminated. The length will include this
*  terminating null char.
*
*  It's recommended to hand in the MIT keytab with a terminating null character. It MUST be encrypted with
*  AES128-CTS-HMAC-SHA96 (kdb5_util -k aes128-cts-hmac-sha1-96 dump -mkeyconvert filename).
*
*  @param adsp_keytab_data Structure containg the MIT keytab, master password, realm and return buffer.
*
*  @return Always TRUE.
*/
extern "C" BOOL m_krb5_keytab_mit_to_heim(struct dsd_aux_krb5_mit_to_heim* adsp_keytab_data)
{
   // Input validation
   if( NULL == adsp_keytab_data )
   {
      return FALSE;
   }

   void* avol_temp_memory;
   char* achl_salt;
   char* achl_pw;
   char* achl_mit_tab;
   m_aux_stor_start(&avol_temp_memory);
   achl_salt = (char*)m_aux_stor_alloc(&avol_temp_memory,adsp_keytab_data->dsc_realm.imc_len_str+3);
   memcpy(achl_salt,adsp_keytab_data->dsc_realm.ac_str,adsp_keytab_data->dsc_realm.imc_len_str);
   achl_salt[adsp_keytab_data->dsc_realm.imc_len_str] = 'K';
   achl_salt[adsp_keytab_data->dsc_realm.imc_len_str+1] = 'M';
   achl_salt[adsp_keytab_data->dsc_realm.imc_len_str+2] = 0;
   achl_pw = (char*)m_aux_stor_alloc(&avol_temp_memory,adsp_keytab_data->dsc_password.imc_len_str+3);
   memcpy(achl_pw,adsp_keytab_data->dsc_password.ac_str,adsp_keytab_data->dsc_password.imc_len_str);
   achl_pw[adsp_keytab_data->dsc_password.imc_len_str] = 0;
   if(*(adsp_keytab_data->achc_mit_data+adsp_keytab_data->imc_mit_data_len-1) != 0){
      achl_mit_tab = (char*)m_aux_stor_alloc(&avol_temp_memory,adsp_keytab_data->imc_mit_data_len+1);
      memcpy(achl_mit_tab,adsp_keytab_data->achc_mit_data,adsp_keytab_data->imc_mit_data_len);
      achl_mit_tab[adsp_keytab_data->imc_mit_data_len] = 0;
   } else {
      achl_mit_tab = adsp_keytab_data->achc_mit_data;
   }
   int inl_ret = mit_prop_dump( achl_mit_tab,
      achl_salt,
      achl_pw,
      adsp_keytab_data->achc_heim_data_buffer,
      adsp_keytab_data->imc_heim_buffer_len,
      &avol_temp_memory);
   if(inl_ret > 0){
      adsp_keytab_data->imc_heim_len_ret = inl_ret;
      adsp_keytab_data->iec_ret_krb5 = ied_ret_krb5_ok;
   } else {
      switch(inl_ret){
         case 0:
            adsp_keytab_data->iec_ret_krb5 = ied_ret_krb5_buf_too_sm;
            break;
         case -1:
            adsp_keytab_data->iec_ret_krb5 = ied_ret_krb5_decrypt_err;
            break;
         default:
            adsp_keytab_data->iec_ret_krb5 = ied_ret_krb5_misc;
      }
   }
   m_aux_stor_end(&avol_temp_memory);
   return TRUE;
}//extern "C" BOOL m_krb5_keytab_mit_to_heim(struct dsd_aux_krb5_mit_to_heim* adsp_keytab_data);
extern "C" void m_throw_exception(int inp_error_code){
    throw(Krb5_Heimdal_exception(inp_error_code));
}
#endif
#endif

