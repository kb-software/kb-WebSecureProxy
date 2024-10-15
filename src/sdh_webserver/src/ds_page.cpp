#include "ds_page.h"

ds_page::ds_page()
{
}

ds_page::~ds_page(void)
{
}

/*! \brief Initialize the class
 *
 * @ingroup webserver
 */
void ds_page::m_init(ds_wsp_helper* ads_wsp_helper) {
    ds_v_ids.m_init(ads_wsp_helper);
    hstr_name.m_init(ads_wsp_helper);
    hstr_url.m_init(ads_wsp_helper);
}

/*! \brief Add an ID
 *
 * @ingroup webserver
 */
void ds_page::m_add_id(const ds_id& dsl_id) {
    ds_v_ids.m_add(dsl_id);
}

/*! \brief Get IDs
 *
 * @ingroup webserver
 */
const ds_hvector<ds_id>& ds_page::m_get_ids(void) const {
    return ds_v_ids;
}

