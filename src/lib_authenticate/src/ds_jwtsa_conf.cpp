#include <ds_hstring.h>
#include <ds_xml.h>
#include <ds_jwtsa_conf.h>

/*! \brief holds strings to compare with xml tag
*/
static const char* achrl_xml_tags[] =
{
	"session-entry",
	"name"
};

/*! \brief index for the xml tags in xml_tags[]
*/
enum ied_jwtsa_tags
{
	ied_session_entry,
	ied_name
};


/*! \brief Initialise the class
 *
 * Store a reference to the helper class, and use the helper
 * class to initialize the hob_string
 *
 * \param[in]	ds_wsp_helper* adsp_helper	The helper class
 */
void ds_jwtsa_conf::m_init( ds_wsp_helper* adsp_helper )
{
	adsc_wsp_helper = adsp_helper;
	dsc_config_name.m_init( adsp_helper );
}

/*! \brief Set the configuration name
 *
 * \param[in]	char* achp_name		This will be the name
 * \param[in]	int ip_len			The length of the name
 */
void ds_jwtsa_conf::m_set_name( const char* achp_name, int ip_len )
{
	dsc_config_name.m_set( achp_name, ip_len );
}

/*! \brief Get the configuration name
 *
 * \param[out]	char** aachp_name	This will be set to the name
 * \param[out]	int* aip_len		The length of the returned name
 * \return		bool				name is existing?
 */
bool ds_jwtsa_conf::m_get_name( const char** aachp_name, int* aip_len ) const
{
	*aachp_name	= dsc_config_name.m_get_ptr();
    *aip_len	= dsc_config_name.m_get_len();
    return ( *aip_len > 0 );
}

/*! \brief Get an xml chunk and extract the configname
 *
 * The incoming adsp_node has to be a <session-entry> from the jwt sa config.
 * This function searches for the <name> tag inside this entry, and fills the
 * dsl_jwtsa_conf class with data
 *
 * \param[in]	dsd_xml_tag* adsp_pnode		the XML chunk
 * \return		bool						value found
 */
bool ds_jwtsa_conf::m_from_xml( dsd_xml_tag* adsp_pnode )
{
	ds_xml          dsl_xml;							/* XML parsing									*/
	const char	    *achl_name;							/* the config name								*/
	int             inl_len_name;						/* len of the config name						*/
	dsd_xml_tag		*adsl_temp_tag;						/* check return value of the xml parser			*/

	dsl_xml.m_init( adsc_wsp_helper );

	adsl_temp_tag = dsl_xml.m_get_value(	adsp_pnode,
											"name",
											&achl_name,
											&inl_len_name );

	if( adsl_temp_tag == NULL || achl_name == NULL ){ return false; }

	dsc_config_name.m_set( achl_name, inl_len_name );

	return true;
}