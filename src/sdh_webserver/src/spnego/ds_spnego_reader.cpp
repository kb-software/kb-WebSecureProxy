/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| ds_spnego_reader builds a layer between the application and the         |*/
/*| lib_spnego and provides some convenient methods to the application.     |*/
/*| The class must do more sophisticated analysing (e.g. for returned       |*/
/*| MechTokens or MIC tokens) in future.                                    |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Joachim Frank                                                         |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   May 2010                                                              |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

#include "../ds_session.h"
#include "ds_spnego_reader.h"


ds_spnego_reader::ds_spnego_reader(ds_session* adsl_session_in) {
    m_init(adsl_session_in);
}

ds_spnego_reader::~ds_spnego_reader(void) {}


/*! \brief Class initializing function
 *
 * @ingroup authentication
 * 
 * Initialize the member 'ads_session' and ds_hstrings.
 *
 * @param[in] adsl_session_in The current class ds_session.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_reader::m_init(ds_session* adsl_session_in) {
    ads_session = adsl_session_in;

    dsg_spnego.m_init(ads_session->ads_wsp_helper);

    // set defaults
    dsg_neg_state = ien_spnego_negresult_not_used;
    dsg_supported_mech = ien_spnego_mech_oid_not_used;
    hstr_reponse_token.m_setup(ads_session->ads_wsp_helper, 0);
    hstr_mechlist_mic.m_setup(ads_session->ads_wsp_helper, 0);

    return SUCCESS;
}


/*! \brief Parse a SPNEGO token
 *
 * @ingroup authentication
 * 
 * Parse a SPNEGO token
 *
 * @param[in] auc_data Data to be parsed.
 * @param[in] ul_len Length of data to be parsed.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_reader::m_parse(unsigned char* auc_data, unsigned long ul_len) {
    SPNEGO_TOKEN_HANDLE dsl_spnego_token_handle;
    int inl_ret = dsg_spnego.m_spnego_init_from_binary(auc_data, ul_len, &dsl_spnego_token_handle);
    if (inl_ret != SUCCESS) {
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE250E: SPNEGO: Cannot convert the data into a binary structure. Error %d.", inl_ret);
        return 1;
    }
    
    //---------------
    // negState
    //---------------
    // RFC 4178-4.2.2: Required in the first reply from the target. This field, if present, contains the state of the negotiation.
    //                 This can be: accept-completed (0), accept-incomplete (1), reject (2), request-mic (3).
    // The negState 3 ('request-mic') is not supported by lib_spnego!

    SPNEGO_NEGRESULT dsl_spnego_neg_state;
    inl_ret = dsg_spnego.m_spnego_get_negotiation_result(dsl_spnego_token_handle, &dsl_spnego_neg_state);
    if (inl_ret != SUCCESS) {
        if (inl_ret == SPNEGO_E_ELEMENT_UNAVAILABLE) {
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_warning, "HIWSW350W: SPNEGO: No field 'negState' found.");
            //dsg_neg_state = ien_spnego_negresult_not_used;
        }
        else if (inl_ret == SPNEGO_E_INVALID_ELEMENT) {
            // e.g. If the negState is 3, we end here. The negState 3 ('request-mic') is NOT supported by lib_spnego.
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "HIWSW050W: SPNEGO: Invalid field 'negState' found: %d.", dsl_spnego_neg_state);
        }
        else {
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_error, "HIWSE450E: SPNEGO: Reading field 'negState' failed with error %d.", inl_ret);
        }
        dsg_neg_state = ien_spnego_negresult_not_used;
    }
    else {
        dsd_const_string hstr_readable;
        m_nego_state_to_string(dsl_spnego_neg_state, hstr_readable); 
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI752I: SPNEGO: 'negState': %d (%.*s)", dsl_spnego_neg_state,
            hstr_readable.m_get_len(), hstr_readable.m_get_ptr());
        dsg_neg_state = dsl_spnego_neg_state;
    }

    if (dsg_neg_state == 3) { // The negState 3 ('request-mic') is not supported by lib_spnego. -> error;
        ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE051E: SPNEGO: The delivered negState 'request-mic' is not supported.");
        return 3;
    }

    //---------------
    // supportedMech
    //---------------
    // RFC 4178-4.2.2: This field SHALL only be present in the first reply from the target. It MUST be one of the mechanism(s) offered by the initiator.

    inl_ret = dsg_spnego.m_spnego_get_supported_mech_type(dsl_spnego_token_handle, &dsg_supported_mech);
    if (inl_ret != SUCCESS)  {
        if (inl_ret == SPNEGO_E_ELEMENT_UNAVAILABLE) {
            ads_session->ads_wsp_helper->m_log(ied_sdh_log_warning, "HIWSW390W: SPNEGO: No field 'supportedMech' found.");
        }
        else {
            ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "HIWSW550W: SPNEGO: Reading field 'supportedMech' failed with error %d.", inl_ret);
        }
        dsg_supported_mech = ien_spnego_mech_oid_not_used;
        // Go on
    }
    else {
        dsd_const_string hstr_readable;
        m_nego_mechtype_to_string(dsg_supported_mech, hstr_readable);
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI625I: SPNEGO: Supported MechType: %d (%.*s)",
            dsg_supported_mech, hstr_readable.m_get_len(), hstr_readable.m_get_ptr());
    }


    //---------------
    // ResponseToken
    //---------------
    // RFC 4178-4.2.2: This field, if present, contains tokens specific to the mechanism selected.

    unsigned long ul_token_len = 0;
    hstr_reponse_token.m_reset();
    // Calling with NULL will calculate the required length into ul_token_len.
    inl_ret = dsg_spnego.m_spnego_get_mech_token(dsl_spnego_token_handle, NULL, &ul_token_len);
    if (inl_ret == SPNEGO_E_ELEMENT_UNAVAILABLE) {
        ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSWI40I: SPNEGO: No field 'ResponseToken' found.");
    }
    else if (inl_ret == SPNEGO_E_BUFFER_TOO_SMALL) {
        // A response token is available. ul_token_len holds its length.
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI125I: SPNEGO: ResponseToken has length %lu.", ul_token_len);

        if (ul_token_len > 0) {
            // Response token found.
            // ResponseToken with length 0 is treated as 'not available'!

            // Read it by calling the method again with a sufficient large buffer.
            char* ach_resp_token = ads_session->ads_wsp_helper->m_cb_get_memory(ul_token_len, true);
            if (ach_resp_token == NULL) {
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE580E: SPNEGO: Cannot allocate memory."); // Desaster...
            }
            else {
                inl_ret = dsg_spnego.m_spnego_get_mech_token(dsl_spnego_token_handle, (unsigned char*)ach_resp_token, &ul_token_len);
                if (inl_ret != SUCCESS)  { // Only for sure. Should not happen.
                    ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "HIWSW580W: SPNEGO: Reading field 'ResponseToken' failed with error %d.", inl_ret);
                }
                else { // Write the token to the global variable.
                    hstr_reponse_token.m_set(ach_resp_token, ul_token_len);
                }
                ads_session->ads_wsp_helper->m_cb_free_memory(ach_resp_token);
            }
        }
    }
    else {
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "HIWSW550W: SPNEGO: Reading field 'ResponseToken' failed with error %d.", inl_ret);
    }


    //---------------
    // mechlistMIC
    //---------------
    // RFC 4178-4.2.2: This field, if present, contains an MIC token for the mechanism list in the initial negotiation message.

    ul_token_len = 0;
    hstr_mechlist_mic.m_reset();
    // Calling with NULL will calculate the required length into ul_token_len.
    inl_ret = dsg_spnego.m_spnego_get_mech_list_mic(dsl_spnego_token_handle, NULL, &ul_token_len);
    if (inl_ret == SPNEGO_E_ELEMENT_UNAVAILABLE) {
        ads_session->ads_wsp_helper->m_log(ied_sdh_log_info, "HIWSWI41I: SPNEGO: No field 'mechlistMIC' found.");
    }
    else if (inl_ret == SPNEGO_E_BUFFER_TOO_SMALL) {
        // A mechlistMIC is available. ul_token_len holds its length.
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_info, "HIWSI128I: SPNEGO: mechlistMIC has length %lu.", ul_token_len);

        if (ul_token_len > 0) {
            // mechlistMIC found.
            // mechlistMIC with length 0 is treated as 'not available'.

            // Read it by calling the method again with a sufficient large buffer.
            char* ach_mechlistmic = ads_session->ads_wsp_helper->m_cb_get_memory(ul_token_len, true);
            if (ach_mechlistmic == NULL) {
                ads_session->ads_wsp_helper->m_log(ied_sdh_log_error, "HIWSE581E: SPNEGO: Cannot allocate memory."); // Desaster...
            }
            else {
                inl_ret = dsg_spnego.m_spnego_get_mech_list_mic(dsl_spnego_token_handle, (unsigned char*)ach_mechlistmic, &ul_token_len);
                if (inl_ret != SUCCESS)  { // Only for sure. Should not happen.
                    ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "HIWSW560W: SPNEGO: Reading field 'mechlistMIC' failed with error %d.", inl_ret);
                }
                else { // Write to the global variable.
                    hstr_mechlist_mic.m_set(ach_mechlistmic, ul_token_len);
                }
                ads_session->ads_wsp_helper->m_cb_free_memory(ach_mechlistmic);
            }
        }
    }
    else {
        ads_session->ads_wsp_helper->m_logf(ied_sdh_log_warning, "HIWSW541W: SPNEGO: Reading field 'mechlistMIC' failed with error %d.", inl_ret);
    }        

    return SUCCESS;
}


/*! \brief Get negState
 *
 * @ingroup authentication
 * 
 * Get the negState field from the parsed SPNEGO.
 * RFC4178: "This field is REQUIRED in the first reply from the target, and is OPTIONAL thereafter. When negState is absent, the
 * actual state should be inferred from the state of the negotiated mechanism context."
 * Values: ien_spnego_negresult_success, ien_spnego_negresult_incomplete, ien_spnego_negresult_rejected, ien_spnego_negresult_not_used.
 *
 * @return The negState (RFC4178).
*/
SPNEGO_NEGRESULT ds_spnego_reader::m_get_neg_state() {
    return dsg_neg_state;
}


/*! \brief Get mechanism
 *
 * @ingroup authentication
 * 
 * Get the supported mechanism from the parsed SPNEGO.
 * RFC4178: "This field SHALL only be present in the first reply from the target."
 * Values:    ien_spnego_mech_oid_kerberos_v5_legacy, ien_spnego_mech_oid_kerberos_v5, ien_spnego_mech_oid_spnego, ien_spnego_mech_oid_not_used.
 *
 * @return The supportedMech (RFC4178).
*/
SPNEGO_MECH_OID ds_spnego_reader::m_get_supported_mech() {
    return dsg_supported_mech;
}


/*! \brief Get response
 *
 * @ingroup authentication
 * 
 * Get the response token from the parsed SPNEGO.
 * RFC4178: "This field, if present, contains tokens specific to the mechanism selected."
 *
 * @return The responseToken (RFC4178). Empty, if not available.
*/
dsd_const_string ds_spnego_reader::m_get_reponse_token() {
    return hstr_reponse_token.m_const_str();
}


/*! \brief GET MIC token
 *
 * @ingroup authentication
 * 
 * Get the MIC token for the mechanism list from the parsed SPNEGO.
 * RFC4178: "This field, if present, contains an MIC token for the mechanism list in the initial negotiation message."
 * Attention: MIC is not supported by lib_spnego!
 *
 * @return The mechlistMIC (RFC4178). Empty, if not available.
*/
dsd_const_string ds_spnego_reader::m_get_mechlist_mic() {
    return hstr_mechlist_mic.m_const_str();
}


/*! \brief Get negState string
 *
 * @ingroup authentication
 * 
 * Fill a ds_hstring with a readable string, which represents the negState.
 *
 * @param[in] dsl_neg_state The negotiation's state to be converted to a string. Example: ien_spnego_negresult_success.
 * @param[out] ahstr Filled with a readable string, which represents the negState.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_reader::m_nego_state_to_string(SPNEGO_NEGRESULT dsl_neg_state, dsd_const_string& rdsp_out) {
    if (dsl_neg_state == ien_spnego_negresult_success) {
        rdsp_out = "success";
    }
    else if (dsl_neg_state == ien_spnego_negresult_incomplete) {
        rdsp_out = "incomplete";
    }
    else if (dsl_neg_state == ien_spnego_negresult_rejected) {
        rdsp_out = "rejected";
    }
    else if (dsl_neg_state == ien_spnego_negresult_not_used) {
        rdsp_out = "<not used>";
    }
    else if (dsl_neg_state == 3) {  // The negState 3 ('request-mic') is not supported by lib_spnego.
        rdsp_out = "request-mic";
    }
    else {
        rdsp_out = "<unknown>";
    }
    return SUCCESS;
}


/*! \brief Get mechtype string
 *
 * @ingroup authentication
 * 
 * Fill a ds_hstring with a readable string, which represents the mechanism type (=OID).
 *
 * @param[in] dsl_mech_oid The mechanism type (=OID) to be converted to a string. Example: ien_spnego_mech_oid_kerberos_v5_legacy.
 * @param[out] ahstr Filled with a readable string, which represents the mechType.
 * @return SUCCESS (=0), if successful; otherwise an error number.
*/
int ds_spnego_reader::m_nego_mechtype_to_string(SPNEGO_MECH_OID dsl_mech_oid, dsd_const_string& rdsp_out) {
    if (dsl_mech_oid == ien_spnego_mech_oid_kerberos_v5_legacy) {
        rdsp_out = "Kerberos Microsoft";
    }
    else if (dsl_mech_oid == ien_spnego_mech_oid_kerberos_v5) {
        rdsp_out = "Kerberos v5";
    }
    else if (dsl_mech_oid == ien_spnego_mech_oid_spnego) {
        rdsp_out = "SPNEGO";
    }
    else {
        rdsp_out = "<unknown>";
    }
    return SUCCESS;
}


