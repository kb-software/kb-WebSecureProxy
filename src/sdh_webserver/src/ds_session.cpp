#include "ds_session.h"

ds_session::ds_session()
: av_storage(NULL)
#ifdef B20140805
, achc_username(NULL)
, inc_len_username(0)
, achc_domain(NULL)
, inc_len_domain(0)
, achc_userdn(NULL)
, inc_len_userdn(0)
#endif
, bo_nonce_already_printed(false)
, bo_nonce_url_already_printed(false)
, bog_nego_first_reply(true)
, bog_pipelining_detected(false)
, boc_watch_session(false)
, boc_fixed_login(false)
{
}

ds_session::~ds_session(void)
{
    in_state_auth_basic     = ien_st_auth_basic_not_active;
    in_state_auth_negotiate = ien_st_auth_nego_not_active;
}


/*! \brief Class Initializer function
 *
 * @ingroup webserver
 */
void ds_session::m_init(ds_wsp_helper* adsl_wsp_helper)
{
    ads_wsp_helper = adsl_wsp_helper;
    ds_v_sso_ids.m_init(adsl_wsp_helper);

#ifndef B20140805
    dsc_username.m_init(ads_wsp_helper);
    dsc_domain.m_init(ads_wsp_helper);
    dsc_userdn.m_init(ads_wsp_helper);
#endif

    hstr_data_last_request.m_init(ads_wsp_helper);

    hstr_prot_authority_ws.m_init(ads_wsp_helper);
	hstr_prot_authority_ws_ext.m_init(ads_wsp_helper);
	hstr_url_session_id.m_init(ads_wsp_helper);
    hstr_user_agent_last_req.m_init(ads_wsp_helper);
    hstr_conf_authority.m_init(ads_wsp_helper);

    hstr_authorization_basic.m_init(ads_wsp_helper);
    hstr_data_to_ext_ws_before_negotiate.m_init(ads_wsp_helper);

    dscv_kick_out.m_init( ads_wsp_helper );
}


/*! \brief Sets authority
 *
 * @ingroup webserver
 *
 * This method must be called after the class was constructed and initialized.
 */
void ds_session::m_set_conf_authority(ds_hstring* ahstr_conf_authority)
{
    hstr_conf_authority.m_write(ahstr_conf_authority);
}


/*! \brief Get SSO IDs
 *
 * @ingroup webserver
 */
const ds_hvector<ds_id>& ds_session::m_get_sso_ids(void) {
    return ds_v_sso_ids;
}


void ds_session::m_get_server_entry_name( ds_hstring * ahstrp_sen )
{
    
    if( ahstrp_sen == NULL )
        return;

    if ( this->dsc_http_hdr_in.dsc_url.hstr_query.m_get_len() < 4 ) {
        return;
    }

    // Read the ID number from the query.
    dsd_const_string hstrl_query(this->dsc_http_hdr_in.dsc_url.hstr_query);

    if (!hstrl_query.m_starts_with_ic("ID=")) // Query must start with "ID="
    { 
        this->ads_wsp_helper->m_log( ied_sdh_log_warning, "ds_session::m_get_server_entry_name querry does not started with \"ID=\"" );
        return;
    }

    dsd_const_string hstr_idx = hstrl_query.m_substring(3);
    int in_idx = -1;

    if (!hstr_idx.m_parse_int(&in_idx))  // Index number is no number.
    {
        this->ads_wsp_helper->m_log( ied_sdh_log_info, "ds_session::m_get_server_entry_name querry value is not a number." );
        return;
    }

    // Find the PPP-Tunnel-configuration according to this ID number.
    struct dsd_pppt* adsl_pppt = this->ads_config->adsl_pppt;
    while(adsl_pppt != NULL) 
    {
        if (adsl_pppt->in_id == in_idx) 
        {
            ahstrp_sen->m_write( adsl_pppt->ach_server_entry_name, adsl_pppt->in_len_server_entry_name );

            return;
        }
        adsl_pppt = adsl_pppt->adsc_next;
    }
    this->ads_wsp_helper->m_log( ied_sdh_log_warning, "ds_session::m_get_server_entry_name server_entry_name was not found." );

    return;
}

bool ds_session::m_ensure_url_cookie() {
	if(this->hstr_url_session_id.m_get_len() <= 0) {
		ds_hstring dsl_cookie(this->ads_wsp_helper);
		if(!this->dsc_auth.m_get_http_cookie(&dsl_cookie)) {
			return false;
		}
		this->hstr_url_session_id.m_write("/(HOB");
		this->hstr_url_session_id.m_write(dsl_cookie);
		this->hstr_url_session_id.m_write(")");

		this->hstr_prot_authority_ws_ext = this->hstr_prot_authority_ws;
		this->hstr_prot_authority_ws_ext.m_write(this->hstr_url_session_id);
	}
	return true;
}
