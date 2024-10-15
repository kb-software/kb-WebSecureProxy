#include "ds_ppp_tunnel.h"
#include "rdvpn_globals.h"

ds_ppp_tunnel::ds_ppp_tunnel()
{
}

ds_ppp_tunnel::~ds_ppp_tunnel(void)
{
}

/*! \brief Init function
 *
 * @ingroup configuration
 */
void ds_ppp_tunnel::m_init(ds_wsp_helper* adsl_wsp_helper) {
    hstr_address.m_init(adsl_wsp_helper);
    hstr_enabled.m_init(adsl_wsp_helper);
    hstr_localhost.m_init(adsl_wsp_helper);
    hstr_server_entry_name.m_init(adsl_wsp_helper);
    hstr_system_parameters.m_init(adsl_wsp_helper);
}

/*! \brief Setup function
 *
 * @ingroup configuration
 */
void ds_ppp_tunnel::m_setup(ds_wsp_helper* adsl_wsp_helper) {
    hstr_address.m_setup(adsl_wsp_helper);
    hstr_enabled.m_setup(adsl_wsp_helper);
    hstr_localhost.m_setup(adsl_wsp_helper);
    hstr_server_entry_name.m_setup(adsl_wsp_helper);
    hstr_system_parameters.m_setup(adsl_wsp_helper);
}

/*! \brief Check if tunnel is enabled
 *
 * @ingroup configuration
 */
bool ds_ppp_tunnel::m_is_enabled(void) const {
    return bo_is_enabled;
}

/*! \brief Set the tunnel to enabled
 *
 * @ingroup configuration
 *
 * intern
 * Attention: This method is implicitly called by m_set_enabled(ds_hstring*).
 */
void ds_ppp_tunnel::m_set_enabled(bool bo_enabled) {
    bo_is_enabled = bo_enabled;
}

/*! \brief Get the address
 *
 * @ingroup configuration
 */
const dsd_const_string ds_ppp_tunnel::m_get_address(void) const {
    return hstr_address.m_const_str();
}

/*! \brief Set address
 *
 * @ingroup configuration 
 */
void ds_ppp_tunnel::m_set_address(const dsd_unicode_string& ahstr_address) {
    hstr_address.m_set(ahstr_address);
}

/*! \brief Get enabled string
 *
 * @ingroup configuration
 *
 * 
 */
const dsd_const_string ds_ppp_tunnel::m_get_enabled(void) const {
    return hstr_enabled.m_const_str();
}


/*! \brief 
 *
 * @ingroup configuration
 *
 * intern
 * We expect YES or NO. Calling application must handle all other strings!
 */
void ds_ppp_tunnel::m_set_enabled(const dsd_unicode_string& ahstr_enabled) {
    hstr_enabled.m_set(ahstr_enabled);

    // We expect YES or NO.
    if (hstr_enabled.m_equals_ic(STRING_YES)) {
        m_set_enabled(true);
        return;
    }
    if (hstr_enabled.m_equals_ic(STRING_NO)) {
        m_set_enabled(false);
        return;
    }
    
    // All other strings must be handled by calling application.
}

/*! \brief Get localhost
 *
 * @ingroup configuration
 *
 * 
 */
const dsd_const_string ds_ppp_tunnel::m_get_localhost(void) const {
    return hstr_localhost.m_const_str();
}

/*! \brief Set localhost
 *
 * @ingroup configuration
 *
 *
 */
void ds_ppp_tunnel::m_set_localhost(const dsd_unicode_string& ahstr_localhost) {
    hstr_localhost.m_set(ahstr_localhost);
}

/*! \brief Get server entry name
 *
 * @ingroup configuration
 *
 * 
 */
const dsd_const_string ds_ppp_tunnel::m_get_server_entry_name(void) const {
    return hstr_server_entry_name.m_const_str();
}

/*! \brief Set server entry name
 *
 * @ingroup configuration
 *
 * 
 */
void ds_ppp_tunnel::m_set_server_entry_name(const dsd_unicode_string& ahstr_name) {
    hstr_server_entry_name.m_set(ahstr_name);
}

/*! \brief Get system parameters
 *
 * @ingroup configuration
 *
 * 
 */
const dsd_const_string ds_ppp_tunnel::m_get_system_parameters(void) const {
    return hstr_system_parameters.m_const_str();
}

/*! \brief Set system parameters
 *
 * @ingroup configuration
 *
 * 
 */
void ds_ppp_tunnel::m_set_system_parameters(const dsd_const_string& ahstr_system_parameters) {
    hstr_system_parameters.m_set(ahstr_system_parameters);
}

/*! \brief Get tunnel ID
 *
 * @ingroup configuration
 *
 * 
 */
int ds_ppp_tunnel::m_get_id(void) const {
    return in_id;
}

/*! \brief Set tunnel ID
 *
 * @ingroup configuration
 *
 * 
 */
void ds_ppp_tunnel::m_set_id(int inl_id) {
    in_id = inl_id;
}

