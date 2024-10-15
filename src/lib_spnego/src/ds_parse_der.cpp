//-------------------------------------------------------------------------------------------//
// ds_parse_der.cpp                                                                          //
//                                                                                           //
// Contains implementation of ASN.1 DER read/write functions as defined in ds_parse_der.hpp. //
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

#include "ds_parse_der.hpp"



ds_parse_der::ds_parse_der()
{
    m_fill_mech_oid_list();
}

ds_parse_der::~ds_parse_der(void)
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
void ds_parse_der::m_fill_mech_oid_list() {
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
MECH_OID ds_parse_der::m_get_from_mech_oid_list(SPNEGO_MECH_OID dsl_mech_oid) {
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
int ds_parse_der::m_asn_der_get_length(unsigned char* auc_len_data, long lo_boundary_length,
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
int ds_parse_der::m_asn_der_check_token( unsigned char* auc_token_data, unsigned char uc_token,
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
int ds_parse_der::m_asn_der_check_oid( unsigned char* auc_token_data, SPNEGO_MECH_OID dsl_mech_oid,
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
int ds_parse_der::m_asn_der_calc_num_length_bytes(long lo_length) {
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
long ds_parse_der::m_asn_der_calc_token_length(long lo_length, long lo_data_length) {
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
long ds_parse_der::m_asn_der_calc_element_length(long lo_data_length, long* alo_internal_len) {
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
long ds_parse_der::m_asn_der_calc_mech_list_length(SPNEGO_MECH_OID dsl_enum_mechoid, long* alo_internal_len) {
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
int ds_parse_der::m_asn_der_write_length(unsigned char* auc_data, long lo_length) {
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
int ds_parse_der::m_asn_der_write_token(unsigned char* auc_data, unsigned char uc_type,
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
int ds_parse_der::m_asn_der_write_oid(unsigned char* auc_data, SPNEGO_MECH_OID dsl_enum_mech_oid) {

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
long ds_parse_der::m_asn_der_write_mech_list(unsigned char* auc_data, SPNEGO_MECH_OID dsl_enum_mechoid) {
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
int ds_parse_der::m_asn_der_write_element(unsigned char* auc_data, unsigned char uc_element_sequence,
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
