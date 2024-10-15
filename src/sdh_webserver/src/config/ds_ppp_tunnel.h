#ifndef DS_PPP_TUNNEL_H
#define DS_PPP_TUNNEL_H

#include <ds_wsp_helper.h>
#include <ds_hstring.h>

/*! \brief PPP Tunnel Configuration class
 *
 * @ingroup configuration
 *
 * Class which stores information about the PPP Tunnel configuration
 * Example:
 * <HOB-PPP-Tunnel>
 *  <enabled>YES</enabled>
 *  <server-entry-name>PPP_Tunnel</server-entry-name>
 *  <address/>
 *  <localhost>127.0.0.2</localhost>
 *  <system-parameters>
 *    <windows>rasdial HOB-L2TP-01 %TEXT:username; %TEXT:password; /PHONEBOOK:HOB-PPP-T1-01.pbk</windows>
 *    <mac>-detach refuse-chap lock passive : ipcp-accept-local ipcp-accept-remote crtscts usepeerdns noccp novj idle 1800 mtu 1410 mru 1410 debug dump connect-delay 5000 nodefaultroute call hobppptunnel ipparam hob-%%TEXT:snw_ineta;-%%text:snw_mask; user %TEXT:username; password %TEXT:password;</mac>
 *    <freebsd>-detach refuse-chap lock passive : ipcp-accept-local ipcp-accept-remote crtscts noccp novj idle 1800 mtu 1410 mru 1410 debug nodefaultroute call hobppptunnel ipparam hob-%%TEXT:snw_ineta;-%%text:snw_mask; user %TEXT:username;</freebsd>
 *    <solaris>-detach refuse-chap lock passive : ipcp-accept-local ipcp-accept-remote crtscts usepeerdns noccp novj idle 1800 mtu 1410 mru 1410 debug dump connect-delay 5000 nodefaultroute call hobppptunnel ipparam hob-%%TEXT:snw_ineta;-%%text:snw_mask; user %TEXT:username; password %TEXT:password;</solaris>
 *    <linux>-detach refuse-chap refuse-eap lock passive : ipcp-accept-local ipcp-accept-remote crtscts usepeerdns noccp novj idle 1800 mtu 1410 mru 1410 debug dump connect-delay 5000 nodefaultroute call hobppptunnel ipparam hob-%%TEXT:snw_ineta;-%%text:snw_mask; user %TEXT:username; password %TEXT:password;</linux>
 *  </system-parameters>
 * </HOB-PPP-Tunnel>
 */
class ds_ppp_tunnel
{
public:
    ds_ppp_tunnel();
    ~ds_ppp_tunnel(void);

    void m_init(ds_wsp_helper* ads_wsp_helper);
    void m_setup(ds_wsp_helper* adsl_wsp_helper);

    int  m_get_id           (void) const;
    bool m_is_enabled       (void) const;

    const dsd_const_string m_get_address           (void) const;
    const dsd_const_string m_get_enabled           (void) const;
    const dsd_const_string m_get_localhost         (void) const;
    const dsd_const_string m_get_server_entry_name (void) const;
    const dsd_const_string m_get_system_parameters (void) const;

    void m_set_id           (int inl_id);

    void m_set_address              (const dsd_unicode_string& ahstr_address);
    void m_set_enabled              (const dsd_unicode_string& ahstr_enabled);
    void m_set_localhost            (const dsd_unicode_string& ahstr_localhost);
    void m_set_server_entry_name    (const dsd_unicode_string& ahstr_name);
    void m_set_system_parameters    (const dsd_const_string& ahstr_system_parameters);

private:
    bool bo_is_enabled;
    int in_id;

    ds_hstring hstr_address;           // tag <address>
    ds_hstring hstr_enabled;           // tag <enabled>
    ds_hstring hstr_localhost;         // tag <localhost>
    ds_hstring hstr_server_entry_name; // tag <server-entry-name>
    ds_hstring hstr_system_parameters; // tag <system-parameters>

    void m_set_enabled      (bool bo_enabled);
};


#endif  // DS_PPP_TUNNEL_H


