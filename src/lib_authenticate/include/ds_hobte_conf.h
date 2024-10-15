//#define BO_HOBTE_CONFIG 1

#ifndef _DS_HOBTE_CONF_H
#define _DS_HOBTE_CONF_H

#if BO_HOBTE_CONFIG


#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_xml.h>

#ifndef _IED_WEBTERM_SUBPROTOCOL
#define _IED_WEBTERM_SUBPROTOCOL
enum ied_webterm_subprotocol {
    ied_webterm_subprotocol_unknown,
    ied_webterm_subprotocol_rdp,
    ied_webterm_subprotocol_ssh,
    ied_webterm_subprotocol_vt525,
    ied_webterm_subprotocol_tn3270,
    ied_webterm_subprotocol_tn5250,
    ied_webterm_subprotocol_tedefault
};


struct dsd_subprotocol {
    int im_subprotocol_len;
    const char* ach_subprotocol_name;
    ied_webterm_subprotocol ie_subprotocol;    
};

static struct dsd_subprotocol dsrc_subprotocols[] = { 
    {sizeof("3270TELNET")-1,"3270TELNET",ied_webterm_subprotocol_tn3270},
    {sizeof("5250TELNET")-1,"5250TELNET",ied_webterm_subprotocol_tn5250},
    {sizeof("VTTELNET")-1,"VTTELNET",ied_webterm_subprotocol_vt525},
};
#define IM_SUBPROT_NUM 3
#endif





class ds_hobte_conf
{
	public:
        ds_hobte_conf();
		void			m_init( ds_wsp_helper* adsp_helper );
		void			m_set_name( const char* achp_name, int ip_len );
		bool			m_get_name( const char** aachp_name, int* aip_len )  const;
        void            m_set_connection( const char* achp_conn, int ip_len );

        void m_set_subprotocol(ied_webterm_subprotocol);
        void m_set_subprotocol(const char* achp_name, int imp_len);
        ied_webterm_subprotocol m_get_subprotocol() const;

		bool			m_from_xml( dsd_xml_tag* ads_pnode );
	private:
		ds_wsp_helper*	adsc_wsp_helper; /* helper class for interaction with WSP */
		ds_hstring		dsc_config_name; /* holds the name of a hobte config from LDAP*/
        ied_webterm_subprotocol iec_subprotocol;
};

#endif

#endif