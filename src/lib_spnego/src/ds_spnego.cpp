//-------------------------------------------------------------------------------------------//
// ds_spnego.cpp         Main class of lib_spnego.                                           //
//                                                                                           //
// Contains functions to create and to parse SPNEGO Tokens.                                  //
// The negState 3 ('request-mic') is not supported by lib_spnego.                            //
//                                                                                           //
// RFCs: 4178, 4559, 2743, 2744.                                                             //
//                                                                                           //
// Author:  Joachim Frank                                                                    //
// Date:    30.04.2010                                                                       //
//                                                                                           //
// Code was copied from Sanj Surati, fitted to HOB's requests and slightly improved.         //
// See:  http://msdn.microsoft.com/en-us/library/ms995331.aspx                               //
//-------------------------------------------------------------------------------------------//


#include <stdlib.h>
#include <stdio.h>
#include <memory.h>


#include <ds_wsp_helper.h>
#include "spnego_defines.hpp"
#include "ds_parse_der.hpp"
#include "ds_spnego.hpp"


ds_spnego::ds_spnego()
{
}

ds_spnego::~ds_spnego(void)
{
}


void ds_spnego::m_init(ds_wsp_helper* adsl_wsp_helper) {
    ads_wsp_helper = adsl_wsp_helper;
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
int ds_spnego::m_calc_min_spnego_init_token_size( long lo_mech_token_length, long lo_mech_list_mic_length,
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
int ds_spnego::m_create_spnego_init_token(SPNEGO_MECH_OID dsl_mech_type, unsigned char uc_context_flags,
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
int ds_spnego::m_calc_min_spnego_targ_token_size(SPNEGO_MECH_OID dsl_mech_type, SPNEGO_NEGRESULT dsl_spnego_neg_result,
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
int ds_spnego::m_create_spnego_targ_token(SPNEGO_MECH_OID dsl_mech_type, SPNEGO_NEGRESULT dsl_spnego_neg_result,
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
SPNEGO_TOKEN* ds_spnego::m_alloc_empty_spnego_token(unsigned char uc_copy_data, unsigned long ul_flags,
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
void ds_spnego::m_free_spnego_token(SPNEGO_TOKEN* ads_spnego_token) {
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
void ds_spnego::m_init_spnego_token_element_array(SPNEGO_TOKEN* ads_spnego_token) {
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
int ds_spnego::m_init_spnego_token_type(SPNEGO_TOKEN* ads_spnego_token, long* alo_len_token,
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
int ds_spnego::m_get_spnego_init_token_mech_list(unsigned char* auc_token_data, int lo_mech_list_length,
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
int ds_spnego::m_init_spnego_token_element_from_basic_type(unsigned char* auc_token_data, int in_element_length,
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
int ds_spnego::m_init_spnego_token_element_from_oid(unsigned char* auc_token_data, int in_element_length,
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
int ds_spnego::m_init_spnego_token_elements(SPNEGO_TOKEN* ads_spnego_token,
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
int ds_spnego::m_find_mech_oid_in_mech_list(SPNEGO_ELEMENT* ads_spnego_element, SPNEGO_MECH_OID dsl_mech_oid,
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
int ds_spnego::m_validate_mech_list(unsigned char* auc_mech_list_data, long lo_boundary_length) {
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
int ds_spnego::m_is_valid_mech_oid(SPNEGO_MECH_OID dsl_mech_oid) {
   return (dsl_mech_oid >= ien_spnego_mech_oid_kerberos_v5_legacy &&
           dsl_mech_oid <= ien_spnego_mech_oid_spnego);
}



/**
 * Check for a valid ContextFlags value.
 *
 * @param[in] uc_context_flags ContextFlags value.
 * @return 1, if successful; otherwise 0.
*/
int ds_spnego::m_is_valid_context_flags(unsigned char uc_context_flags) {
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
int ds_spnego::m_is_valid_neg_result(SPNEGO_NEGRESULT dsl_neg_result) {
   return (dsl_neg_result >= ien_spnego_negresult_success &&
           dsl_neg_result <= ien_spnego_negresult_rejected);
}



/**
 * Performs simple heuristic on location pointed to by ads_spnego_token.
 *
 * @param[in] ads_spnego_token  Points to SPNEGO_TOKEN data structure.
 * @return 1, if successful; otherwise 0.
*/
int ds_spnego::m_is_valid_spnego_token(SPNEGO_TOKEN* ads_spnego_token) {
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
int ds_spnego::m_is_valid_spnego_element(SPNEGO_TOKEN* ads_spnego_token, SPNEGO_ELEMENT_TYPE dsl_spnego_element) {
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
int ds_spnego::m_calc_element_array_index(SPNEGO_TOKEN* ads_spnego_token,SPNEGO_ELEMENT_TYPE dsl_spnego_element) {
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
int ds_spnego::m_init_token_from_binary(unsigned char uc_copy_data, unsigned long ul_flags,
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
int ds_spnego::m_spnego_init_from_binary(unsigned char* auc_token_data, unsigned long ul_length, SPNEGO_TOKEN_HANDLE* adsl_spnego_token_handle) {
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
int ds_spnego::m_spnego_create_neg_token_init(SPNEGO_MECH_OID dsl_mech_type, unsigned char uc_context_flags,
          unsigned char* auc_mech_token, unsigned long ul_mech_token_len,
          unsigned char* auc_mech_list_mic, unsigned long ul_mech_list_mic_len,
          SPNEGO_TOKEN_HANDLE* adsl_spnego_token_handle) {
    long  lo_token_length = 0L;
    long  lo_internal_token_length = 0L;
    unsigned char* auc_token_data = NULL;
    SPNEGO_TOKEN** aadsl_spnego_token = (SPNEGO_TOKEN**) adsl_spnego_token_handle;

    if (NULL == aadsl_spnego_token ||
        !m_is_valid_mech_oid(dsl_mech_type) ||
        !m_is_valid_context_flags(uc_context_flags)) {
        return SPNEGO_E_INVALID_PARAMETER;
    }

    // Get the actual token size
    int inl_ret = m_calc_min_spnego_init_token_size(ul_mech_token_len, ul_mech_list_mic_len, 
                                                    dsl_mech_type, (uc_context_flags != 0L), 
                                                    &lo_token_length, &lo_internal_token_length);
    if (inl_ret != SUCCESS ) {
        return (inl_ret - 200);
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
        return (inl_ret - 400);
    }
  
    // This will copy our allocated pointer, and ensure that the sructure cleans
    // up the data later
    inl_ret = m_init_token_from_binary(SPNEGO_TOKEN_INTERNAL_COPYPTR,
                                       SPNEGO_TOKEN_INTERNAL_FLAGS_FREEDATA,
                                       auc_token_data, lo_token_length, aadsl_spnego_token);
    if (inl_ret != SUCCESS ) {
#ifdef USE_WSP_HELPER
        ads_wsp_helper->m_cb_free_memory(auc_token_data);
#else
        free(auc_token_data);
#endif
        return (inl_ret - 600);
    }

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
int ds_spnego::m_spnego_create_neg_token_targ(SPNEGO_MECH_OID dsl_mech_type, SPNEGO_NEGRESULT dsl_spnego_neg_result,
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
int ds_spnego::m_spnego_token_get_binary(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_token_data,
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
void ds_spnego::m_spnego_free_data(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle) {
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
int ds_spnego::m_spnego_get_token_type(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, int * piTokenType) {
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
int ds_spnego::m_spnego_is_mech_type_available(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, SPNEGO_MECH_OID dsl_mech_oid, int * ain_mech_type_index) {
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
int ds_spnego::m_spnego_get_context_flags(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_context_flags) {
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
int ds_spnego::m_spnego_get_negotiation_result(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, SPNEGO_NEGRESULT* adsl_neg_result) {
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
int ds_spnego::m_spnego_get_supported_mech_type(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, SPNEGO_MECH_OID* adsl_mech_oid) {
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
int ds_spnego::m_spnego_get_mech_token(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_token_data, unsigned long* aul_data_len) {
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
int ds_spnego::m_spnego_get_mech_list_mic(SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle, unsigned char* auc_mic_data, unsigned long* aul_data_len) {
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
