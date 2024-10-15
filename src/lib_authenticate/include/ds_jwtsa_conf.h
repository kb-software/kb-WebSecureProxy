#ifndef _DS_JWTSA_CONF_H
#define _DS_JWTSA_CONF_H
/*! \file ds_jwtsa_conf header
 *+-------------------------------------------------------------------------+*
 *|                                                                         |*
 *| PROJECT-NAME:                                                           |*
 *| =============                                                           |*
 *|   ds_jwtsa_conf                                                         |*
 *|                                                                         |*
 *| AUTHOR:                                                                 |*
 *| =======                                                                 |*
 *|   Tobias Hofmann                                                        |*
 *|                                                                         |*
 *| DATE:                                                                   |*
 *| =====                                                                   |*
 *|   October 2012                                                          |*
 *|                                                                         |*
 *| VERSION:                                                                |*
 *| ========                                                                |*
 *|   0.1                                                                   |*
 *|                                                                         |*
 *| COPYRIGHT:                                                              |*
 *| ==========                                                              |*
 *|  HOB GmbH & Co. KG, Germany                                             |*
 *|                                                                         |*
 *| DESCRIPTION:                                                            |*
 *| ==========                                                              |*
 *|  This file containes the class ds_jwtsa_conf, which is needed to get    |*
 *|  information about the JWT standalone configurations out of the LDAP    |*
 *|  and store it in the CMA                                                |*
 *+-------------------------------------------------------------------------+*
 */

/* forward definitions */
class ds_hstring;
struct dsd_xml_tag;

/*! \brief Holds JWT Standalone Configuration name
 *
 * This class holds the JWT configuration name which is coming from the LDAP.
 * The name is then written in the CMA, and later the user gets these names displayed
 * on the RDVPN Overview site.
 */
class ds_jwtsa_conf
{
	public:
		void			m_init( ds_wsp_helper* adsp_helper );
		void			m_set_name( const char* achp_name, int ip_len );
		bool			m_get_name( const char** aachp_name, int* aip_len )  const;

		bool			m_from_xml( dsd_xml_tag* ads_pnode );
	private:
		ds_wsp_helper*	adsc_wsp_helper; /* helper class for interaction with WSP */
		ds_hstring		dsc_config_name; /* holds the name of a JWT config from LDAP*/
};

#endif