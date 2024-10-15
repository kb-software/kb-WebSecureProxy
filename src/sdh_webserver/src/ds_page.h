#ifndef DS_PAGE_H
#define DS_PAGE_H

#include "./ds_id.h"
#include <ds_hvector.h>

/*! \brief Helper class
 *
 * @ingroup webserver
 *
 * Handels information about a webpage
 */
class ds_page
{
public:
    ds_page();
    ~ds_page(void);

    void m_init(ds_wsp_helper* ads_wsp_helper);

    inline void m_setup(ds_wsp_helper* adsl_wsp_helper) {
        hstr_name.m_setup(adsl_wsp_helper);
        hstr_url.m_setup(adsl_wsp_helper);
        ds_v_ids.m_setup(adsl_wsp_helper);
    };

    inline const ds_hstring& m_get_name(void) const {
        return hstr_name;
    }
    inline void m_set_name(const dsd_const_string& ahstr_name) {
        hstr_name.m_set(ahstr_name);
    }
    inline const ds_hstring& m_get_url(void) const {
        return hstr_url;
    }
    inline void m_set_url(const dsd_const_string& ahstr_url) {
        //hstr_url.m_reset();
		  //if(ahstr_url.m_starts_with("/"))
			//  ahstr_url = ahstr_url.m_substring(1);
		  hstr_url = ahstr_url;
    }

    void m_add_id(const ds_id& dsl_id);

    const ds_hvector<ds_id>& m_get_ids(void) const;
    ds_hvector<ds_id> ds_v_ids; // list of IDs


private:
    ds_hstring hstr_name; // name of this <page>
    ds_hstring hstr_url; // url of this <page>
};


#endif  // DS_PAGE_H

