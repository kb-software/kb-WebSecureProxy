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
