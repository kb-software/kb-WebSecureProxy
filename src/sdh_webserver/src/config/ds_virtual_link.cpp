#include "ds_virtual_link.h"
#include "rdvpn_globals.h"

ds_virtual_link::ds_virtual_link()
{
}

ds_virtual_link::~ds_virtual_link(void)
{
}

/*! \brief Initalizer function
 *
 * @ingroup configuration
 */
void ds_virtual_link::m_init(ds_wsp_helper* adsl_wsp_helper) {
    hstr_alias.m_init(adsl_wsp_helper);
    hstr_url.m_init(adsl_wsp_helper);
    hstr_authority.m_init(adsl_wsp_helper);
    hstr_path.m_init(adsl_wsp_helper);
}

/*! \brief Setup function
 *
 * @ingroup configuration
 */
void ds_virtual_link::m_setup(ds_wsp_helper* adsl_wsp_helper) {
    hstr_alias.m_setup(adsl_wsp_helper);
    hstr_url.m_setup(adsl_wsp_helper);
    hstr_authority.m_setup(adsl_wsp_helper);
    hstr_path.m_setup(adsl_wsp_helper);
}

/*! \brief Get the port
 *
 * @ingroup configuration
 */
int ds_virtual_link::m_get_port(void) const {
    return in_port;
}

/*! \brief Set the port
 *
 * @ingroup configuration
 */
void ds_virtual_link::m_set_port(int inl_port) {
    in_port = inl_port;
}

/*! \brief Get the protocol
 *
 * @ingroup configuration
 */
int ds_virtual_link::m_get_protocol(void) const {
    return in_protocol;
}

/*! \brief Set the protocol
 *
 * @ingroup configuration
 */
void ds_virtual_link::m_set_protocol(int inl_protocol) {
    in_protocol = inl_protocol;
}

/*! \brief Get alias
 *
 * @ingroup configuration 
 */
dsd_const_string ds_virtual_link::m_get_alias(void) const {
    return hstr_alias.m_const_str();
}

/*! \brief Set alias
 *
 * @ingroup configuration
 */
void ds_virtual_link::m_set_alias(const dsd_const_string& ahstr_alias) {
    hstr_alias.m_set(ahstr_alias);
}

/*! \brief Set alias
 *
 * @ingroup configuration
 */
void ds_virtual_link::m_set_alias(struct dsd_unicode_string* ads_alias) {
    hstr_alias.m_set(ads_alias);
}

/*! \brief Get URL
 *
 * @ingroup configuration
 */
dsd_const_string ds_virtual_link::m_get_url(void) const {
    return hstr_url.m_const_str();
}

/*! \brief Set URL
 *
 * @ingroup configuration
 */
void ds_virtual_link::m_set_url(const dsd_const_string& ahstr_url) {
    hstr_url.m_set(ahstr_url);
}

/*! \brief Set URL
 *
 * @ingroup configuration
 */
void ds_virtual_link::m_set_url(struct dsd_unicode_string* ads_url) {
    hstr_url.m_set(ads_url);
}

/*! \brief Get authority
 *
 * @ingroup configuration
 */
dsd_const_string ds_virtual_link::m_get_authority(void) const {
    return hstr_authority.m_const_str();
}

/*! \brief Set authority
 *
 * @ingroup configuration
 */
void ds_virtual_link::m_set_authority(const dsd_const_string& ahstr_authority) {
    hstr_authority.m_set(ahstr_authority);
}

/*! \brief Get path
 *
 * @ingroup configuration
 */
dsd_const_string ds_virtual_link::m_get_path(void) const {
    return hstr_path.m_const_str();
}

/*! \brief Set path
 *
 * @ingroup configuration 
 */
void ds_virtual_link::m_set_path(const dsd_const_string& ahstr_path) {
    hstr_path.m_set(ahstr_path);
}
