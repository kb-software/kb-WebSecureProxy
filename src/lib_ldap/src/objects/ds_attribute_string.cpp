#include "ds_attribute_string.h"

ds_attribute_string::ds_attribute_string() {
}

ds_attribute_string::ds_attribute_string(ds_wsp_helper* adsl_wsp_helper)
{
    m_init(adsl_wsp_helper);
}

ds_attribute_string::~ds_attribute_string(void)
{
}

void ds_attribute_string::m_init(ds_wsp_helper* adsl_wsp_helper) {
    ads_wsp_helper = adsl_wsp_helper;
    hstr_name.m_init(adsl_wsp_helper);
    hstr_dn.m_init(adsl_wsp_helper);
    ds_values.m_init(adsl_wsp_helper);
}

/**
 * public function ds_attribute_string::m_clear
 * clear all values inside this class
*/
void ds_attribute_string::m_clear()
{
    ds_values.m_clear();
    hstr_name.m_reset();
    hstr_dn.m_reset();
} // end of ds_attribute_string::m_clear

const ds_hstring& ds_attribute_string::m_get_name(void) const
{
    return hstr_name;
}

void ds_attribute_string::m_set_name(const ds_hstring* ahstr_name)
{
    hstr_name.m_set(ahstr_name);
}

void ds_attribute_string::m_set_name(const char* ach_name, int in_len_name)
{
    hstr_name.m_set(ach_name, in_len_name);
}


const ds_hstring& ds_attribute_string::m_get_dn(void) const
{
    return hstr_dn;
}

void ds_attribute_string::m_set_dn(const ds_hstring* ahstr_dn)
{
    hstr_dn.m_set(ahstr_dn);
}

const ds_hvector<ds_hstring>& ds_attribute_string::m_get_values(void) const
{
    return ds_values;
}

void ds_attribute_string::m_add_to_values(const ds_hstring* ahstr_new_value)
{
    ds_values.m_add(*ahstr_new_value);
}

const ds_hstring& ds_attribute_string::m_get_value_at(int in_idx) const
{
    return ds_values.m_get(in_idx);
}

size_t ds_attribute_string::m_count_values() const
{
    return ds_values.m_size();
}
