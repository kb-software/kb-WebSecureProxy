#ifndef DS_ID_H
#define DS_ID_H

#include <ds_hstring.h>
#include <ds_wsp_helper.h>

/*! \brief Helper class
 *
 * @ingroup webserver
 *
 * Holds and manages an ID
 */
class ds_id
{
public:
    ds_id();
    ~ds_id(void);

    inline void m_setup(ds_wsp_helper* adsl_wsp_helper) {
        hstr_name.m_setup(adsl_wsp_helper);
        hstr_value.m_setup(adsl_wsp_helper);
        hstr_type.m_setup(adsl_wsp_helper);
    };

    inline void m_init(ds_wsp_helper* adsl_wsp_helper) {
        hstr_name.m_init(adsl_wsp_helper);
        hstr_value.m_init(adsl_wsp_helper);
        hstr_type.m_init(adsl_wsp_helper);
    };

    inline const ds_hstring& m_get_name(void) const    {
        return hstr_name;
    }
    inline void m_set_name(const dsd_const_string& ahstr_name) {
        hstr_name.m_set(ahstr_name);
    }
    inline const ds_hstring& m_get_value(void) const    {
        return hstr_value;
    }
    inline void m_set_value(const dsd_const_string& ahstr_value) {
        hstr_value.m_set(ahstr_value);
    }
    inline const ds_hstring& m_get_type(void) const    {
        return hstr_type;
    }
    inline void m_set_type(const dsd_const_string& ahstr_type) {
        hstr_type.m_set(ahstr_type);
    }

private:
    ds_hstring hstr_name;   // name of this ID
    ds_hstring hstr_value;  // value of this ID
    ds_hstring hstr_type;   // type of this ID
};

#endif // DS_ID_H
