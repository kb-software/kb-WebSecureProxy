#ifndef DS_ATTRIBUTE_STRING_H
#define DS_ATTRIBUTE_STRING_H

#include <ds_hstring.h>
#include <ds_hvector.h>
#include <ds_wsp_helper.h>

class ds_attribute_string
{
public:
    ds_attribute_string(void);
    ds_attribute_string(ds_wsp_helper* adsl_wsp_helper);
    ~ds_attribute_string(void);

private:
    ds_wsp_helper* ads_wsp_helper;
    ds_hvector<ds_hstring> ds_values;
    ds_hstring hstr_name;
    ds_hstring hstr_dn;
public:
    void m_init           (ds_wsp_helper* adsl_wsp_helper);
    void m_clear          ();

    const ds_hstring& m_get_name (void) const;
    const ds_hstring& m_get_dn   (void) const;

    void m_set_name       (const ds_hstring* ahstr_name);
    void m_set_name       (const char* ach_name, int in_len_name);
    void m_set_dn         (const ds_hstring* ahstr_dn);

    const ds_hvector<ds_hstring>&   m_get_values(void) const;
    void                     m_add_to_values  (const ds_hstring* ahstr_new_value);
    const ds_hstring&        m_get_value_at(int in_idx) const;
    size_t                   m_count_values() const;
};
#endif  // DS_ATTRIBUTE_STRING_H

