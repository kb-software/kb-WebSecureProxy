#ifndef __SPNEGO_READER_H
#define __SPNEGO_READER_H

#include <ds_spnego.hpp>

class ds_session; //forward-definition!!

/*! \brief Negotiation class
 *
 * @ingroup webserver
 *
 * This class is used to determine which authentication protocol should be spoken
 */
class ds_spnego_reader
{
public:
    ds_spnego_reader(ds_session* adsl_session_in);
    ~ds_spnego_reader(void);

    int m_parse  (unsigned char* auc_data, unsigned long ul_len);

    SPNEGO_NEGRESULT  m_get_neg_state       ();
    SPNEGO_MECH_OID   m_get_supported_mech  ();
    dsd_const_string  m_get_reponse_token   ();
    dsd_const_string  m_get_mechlist_mic    ();

private:
    ds_session* ads_session;
    ds_spnego dsg_spnego;

    // The 4 items, which a negRespToken can contain.
    SPNEGO_NEGRESULT dsg_neg_state;      // Negotiation state; defined as ied_spnego_neg_result in spnego_defines.hpp
    SPNEGO_MECH_OID  dsg_supported_mech; // The target responds the selected mechanism as 'supportedMech'. This field SHALL only be present in the first reply from the target.
    ds_hstring hstr_reponse_token;       // ResponseToken: This field, if present, contains tokens specific to the mechanism selected.
    ds_hstring hstr_mechlist_mic;        // mechlistMIC: This field, if present, contains an MIC token for the mechanism list in the initial negotiation message.

    int m_init   (ds_session* adsl_session_in);

    int m_nego_state_to_string    (SPNEGO_NEGRESULT dsl_neg_state, dsd_const_string& rdsp_out); // TODO: shift this method to SPNEGO-lib ?
    int m_nego_mechtype_to_string (SPNEGO_MECH_OID dsl_mech_oid, dsd_const_string& rdsp_out);   // TODO: shift this method to SPNEGO-lib ?
};

#endif
