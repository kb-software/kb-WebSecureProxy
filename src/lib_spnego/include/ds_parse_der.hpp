#ifndef __DERPARSE_HPP__
#define __DERPARSE_HPP__

#include "spnego_defines.hpp"


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



class ds_parse_der {
public:
    ds_parse_der();
    ~ds_parse_der(void);

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

#endif // __DERPARSE_HPP__
