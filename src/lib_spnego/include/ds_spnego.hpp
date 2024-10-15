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

#ifndef __SPNEGOPARSE_HPP__
#define __SPNEGOPARSE_HPP__

#include "spnego_defines.hpp"

#include "ds_parse_der.hpp"

#define USE_WSP_HELPER // Set this flag, when e.g. alloc shall be replaced by retreaving memory from WSP.


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

class ds_wsp_helper; // forward definition

class ds_spnego {
public:
    ds_spnego();
    ~ds_spnego(void);

    void m_init         (ds_wsp_helper* adsl_wsp_helper);

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
          unsigned long ulMechTokenMIC, SPNEGO_TOKEN_HANDLE* adsl_spnego_token_handle);

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
    ds_parse_der dsg_parse_der;
    ds_wsp_helper* ads_wsp_helper;

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