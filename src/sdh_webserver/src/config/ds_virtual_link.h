#ifndef DS_VIRTUAL_LINK_H
#define DS_VIRTUAL_LINK_H

#include <ds_wsp_helper.h>
#include <ds_hstring.h>

/*! \brief Virtual Link Configuration class
 *
 * @ingroup configuration
 *
 * Class which stores information about the virtual link configuration
 * Example:
 *      <virtual-link>
 *		   <alias>/HOBWebFileAccess</alias>
 *		   <url>/http://localhost:8080/</url>
 *		</virtual-link>
*/
class ds_virtual_link
{
public:
    ds_virtual_link();
    ~ds_virtual_link(void);

    void m_init(ds_wsp_helper* ads_wsp_helper);
    void m_setup(ds_wsp_helper* adsl_wsp_helper);

    int m_get_protocol (void) const;
    int m_get_port     (void) const;

    dsd_const_string m_get_alias     (void) const;
    dsd_const_string m_get_url       (void) const;
    dsd_const_string m_get_authority (void) const;
    dsd_const_string m_get_path      (void) const;

    void m_set_protocol (int inl_protocol);
    void m_set_port     (int in_port);

    void m_set_alias     (const dsd_const_string& ahstr_alias);
    void m_set_alias     (struct dsd_unicode_string* ads_alias);
    void m_set_url       (const dsd_const_string& ahstr_url);
    void m_set_url       (struct dsd_unicode_string* ads_url);
    void m_set_authority (const dsd_const_string& ahstr_authority);
    void m_set_path      (const dsd_const_string& ahstr_path);

private:
    ds_hstring hstr_alias;     // tag <alias>
    ds_hstring hstr_url;       // tag <url>

    // Url was parse into the following parts.
    int in_protocol;           // Protocol of url; e.g. PROTO_HTTPS
    ds_hstring hstr_authority; // Authority of the url
    int in_port;               // Port of url
    ds_hstring hstr_path;      // Path of the url
};


#endif  // DS_VIRTUAL_LINK_H