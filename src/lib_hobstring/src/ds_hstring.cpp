/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_hstring.h"
#include <ds_wsp_helper.h>

#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

#ifdef HL_UNIX
    #include <stdarg.h>
    #include <ctype.h>
#endif
#undef min
#undef max
#include <algorithm>

static const char CHRS_B64[]     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char CHRS_RFC3548[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static char chrs_b64_in_alphabet[256];
static char chrs_b64_decoder[256];
static char chrs_rfc3548_in_alphabet[256];
static char chrs_rfc3548_decoder[256];

static bool m_init_coder_tables() {
    //memset(chrs_b64_in_alphabet, 0, sizeof(chrs_b64_in_alphabet));
    //memset(chrs_b64_decoder, 0, sizeof(chrs_b64_decoder));
    for ( int i = (int)sizeof(CHRS_B64) - 1; i >= 0; i-- ) {
        chrs_b64_in_alphabet[CHRS_B64[i]] = 1;
        chrs_b64_decoder[CHRS_B64[i]]     = (char)i;
    }

    //memset(chrs_rfc3548_in_alphabet, 0, sizeof(chrs_rfc3548_in_alphabet));
    //memset(chrs_rfc3548_decoder, 0, sizeof(chrs_rfc3548_decoder));
    for ( int i = (int)sizeof(CHRS_RFC3548) - 1; i >= 0; i-- ) {
        chrs_rfc3548_in_alphabet[CHRS_RFC3548[i]] = 1;
        chrs_rfc3548_decoder[CHRS_RFC3548[i]]     = (char)i;
    }
    return true;
}

static bool bos_init = m_init_coder_tables();

static bool m_cmp_mem(const char* strp_s1, const char* strp_s2, size_t szp_len) {
    return memcmp(strp_s1, strp_s2, szp_len) == 0;
}

static unsigned char m_to_lower(unsigned char ucp_src)
{
    if(ucp_src >= 0x80)
        return ucp_src;
    return (unsigned char)tolower(ucp_src);
}

static unsigned char m_to_upper(unsigned char ucp_src)
{
    if(ucp_src >= 0x80)
        return ucp_src;
    return (unsigned char)toupper(ucp_src);
}

static int m_cmp_ic(const char* strp_s1, const char* strp_s2, size_t szp_len) {
    const char* strp_s1e = strp_s1 + szp_len;
    while(strp_s1 < strp_s1e) {
        unsigned char ucl_s1 = ((unsigned char*)strp_s1)[0];
        unsigned char ucl_s2 = ((unsigned char*)strp_s2)[0];
        strp_s1++;
        strp_s2++;
		int inl_diff = ((int)m_to_lower(ucl_s1)) - ((int)m_to_lower(ucl_s2));
        if(inl_diff != 0)
            return inl_diff;
    }
    return 0;
}

int dsd_const_string::m_index_of(int inp_pos, const dsd_const_string& rdsp_search) const
{
    if(this->inc_length < rdsp_search.inc_length)
        return -1;
    if(rdsp_search.inc_length <= 0)
        return -1;
    if(inp_pos < 0 || inp_pos >= this->inc_length)
        return -1;
    const char* achl_s1 = this->strc_ptr + inp_pos;
    const char* achl_s1e = this->m_get_end() - rdsp_search.inc_length;
    const char* achl_s2 = rdsp_search.m_get_start();
    while(achl_s1 <= achl_s1e) {
        if(m_cmp_mem(achl_s1, achl_s2, rdsp_search.inc_length))
            return (int)(achl_s1-this->strc_ptr);
        achl_s1++;
    }
    return -1;
}

int dsd_const_string::m_index_of(const dsd_const_string& rdsp_search) const
{
    return m_index_of(0, rdsp_search);
}

int dsd_const_string::m_last_index_of(int inp_pos, const dsd_const_string& rdsp_search) const
{
    if(this->inc_length < rdsp_search.inc_length)
        return -1;
    if(rdsp_search.inc_length <= 0)
        return -1;
    if(inp_pos < 0 || inp_pos > this->inc_length)
        return -1;
    const char* achl_s1 = this->strc_ptr + inp_pos - rdsp_search.inc_length;
    const char* achl_s1e = this->strc_ptr;
    const char* achl_s2 = rdsp_search.m_get_start();
    while(achl_s1 >= achl_s1e) {
        if(m_cmp_mem(achl_s1, achl_s2, rdsp_search.inc_length))
            return (int)(achl_s1-this->strc_ptr);
        achl_s1--;
    }
    return -1;
}
   

int dsd_const_string::m_last_index_of(const dsd_const_string& rdsp_search) const
{
    return this->m_last_index_of((int)this->inc_length, rdsp_search);
}

bool dsd_const_string::m_starts_with(const dsd_const_string& rdsp_search) const
{
    if(this->inc_length < rdsp_search.inc_length)
        return false;
    if(rdsp_search.inc_length <= 0)
        return true;
    return m_cmp_mem(this->strc_ptr, rdsp_search.m_get_start(), rdsp_search.inc_length);
}

bool dsd_const_string::m_ends_with(const dsd_const_string& rdsp_search) const
{
    if(this->inc_length < rdsp_search.inc_length)
        return false;
    if(rdsp_search.inc_length <= 0)
        return true;
    return m_cmp_mem(this->m_get_end()-rdsp_search.inc_length, rdsp_search.m_get_start(), rdsp_search.inc_length);
}

bool dsd_const_string::m_equals(const dsd_const_string& rdsp_search) const
{
    if(this->inc_length != rdsp_search.inc_length)
        return false;
    return m_cmp_mem(this->m_get_start(), rdsp_search.m_get_start(), this->inc_length);
}

bool dsd_const_string::m_equals(dsd_unicode_string& rdsp_other) const
{
    int inl_result;
    dsd_unicode_string dsl_self;
    dsl_self.ac_str = (void*)this->strc_ptr;
    dsl_self.imc_len_str = this->inc_length;
    dsl_self.iec_chs_str = ied_chs_utf_8;
    BOOL bol_res = m_cmp_ucs_ucs(&inl_result, &dsl_self, &rdsp_other);
    if(!bol_res)
        return false;
    return (inl_result == 0);
}

int dsd_const_string::m_compare(const dsd_const_string& rdsp_other) const
{
	size_t inl_len = std::min(this->inc_length, rdsp_other.inc_length);
	int inl_diff = memcmp(this->m_get_start(), rdsp_other.m_get_start(), inl_len);
	if(inl_diff != 0)
		return inl_diff;
	inl_diff = this->inc_length - rdsp_other.inc_length;
	return inl_diff;
}

int dsd_const_string::m_index_of_ic(const dsd_const_string& rdsp_search) const
{
    if(this->inc_length < rdsp_search.inc_length)
        return -1;
    if(rdsp_search.inc_length <= 0)
        return -1;
    const char* achl_s1 = this->strc_ptr;
    const char* achl_s1e = this->m_get_end() - rdsp_search.inc_length;
    const char* achl_s2 = rdsp_search.m_get_start();
    while(achl_s1 <= achl_s1e) {
        if(m_cmp_ic(achl_s1, achl_s2, rdsp_search.inc_length) == 0)
            return (int)(achl_s1-this->strc_ptr);
        achl_s1++;
    }
    return -1;
}

int dsd_const_string::m_last_index_of_ic(const dsd_const_string& rdsp_search) const
{
    if(this->inc_length < rdsp_search.inc_length)
        return false;
    if(rdsp_search.inc_length <= 0)
        return false;
    const char* achl_s1 = this->m_get_end() - rdsp_search.inc_length;
    const char* achl_s1e = this->strc_ptr;
    const char* achl_s2 = rdsp_search.m_get_start();
    while(achl_s1 >= achl_s1e) {
        if(m_cmp_ic(achl_s1, achl_s2, rdsp_search.inc_length) == 0)
            return (int)(achl_s1-this->strc_ptr);
        achl_s1--;
    }
    return -1;
}

bool dsd_const_string::m_starts_with_ic(const dsd_const_string& rdsp_search) const
{
    if(this->inc_length < rdsp_search.inc_length)
        return false;
    if(rdsp_search.inc_length <= 0)
        return true;
    return m_cmp_ic(this->strc_ptr, rdsp_search.m_get_start(), rdsp_search.inc_length) == 0;
}

bool dsd_const_string::m_ends_with_ic(const dsd_const_string& rdsp_search) const
{
    if(this->inc_length < rdsp_search.inc_length)
        return false;
    if(rdsp_search.inc_length <= 0)
        return true;
    return m_cmp_ic(this->m_get_end()-rdsp_search.inc_length, rdsp_search.m_get_start(), rdsp_search.inc_length) == 0;
}

bool dsd_const_string::m_equals_ic(const dsd_const_string& rdsp_search) const
{
    if(this->inc_length != rdsp_search.inc_length)
        return false;
    return m_cmp_ic(this->m_get_start(), rdsp_search.m_get_start(), this->inc_length) == 0;
}

bool dsd_const_string::m_equals_ic(dsd_unicode_string& rdsp_other) const
{
    int inl_result;
    dsd_unicode_string dsl_self;
    dsl_self.ac_str = (void*)this->strc_ptr;
    dsl_self.imc_len_str = this->inc_length;
    dsl_self.iec_chs_str = ied_chs_utf_8;
    BOOL bol_res = m_cmpi_ucs_ucs(&inl_result, &dsl_self, &rdsp_other);
    if(!bol_res)
        return false;
    return (inl_result == 0);
}

int dsd_const_string::m_compare_ic(dsd_unicode_string& rdsp_other) const
{
	int inl_result;
    dsd_unicode_string dsl_self;
    dsl_self.ac_str = (void*)this->strc_ptr;
    dsl_self.imc_len_str = this->inc_length;
    dsl_self.iec_chs_str = ied_chs_utf_8;
    BOOL bol_res = m_cmpi_ucs_ucs(&inl_result, &dsl_self, &rdsp_other);
	if(!bol_res) {
		int inl_len_bytes = m_len_bytes_ucs(&rdsp_other);
		// TODO: Get size of character to remove zero termination
		dsd_const_string dsl_other((const char*)rdsp_other.ac_str, inl_len_bytes-1);
		return this->m_compare(dsl_other);
	}
    return inl_result;
}

int dsd_const_string::m_compare_ic(const dsd_const_string& rdsp_other) const
{
    dsd_unicode_string dsl_other;
    dsl_other.ac_str = (void*)rdsp_other.strc_ptr;
    dsl_other.imc_len_str = rdsp_other.inc_length;
    dsl_other.iec_chs_str = ied_chs_utf_8;
	return this->m_compare_ic(dsl_other);
}

// trim function:
void dsd_const_string::m_trim( const dsd_const_string& rdsp_sign_list )
{
    this->m_trim_left(rdsp_sign_list);
    this->m_trim_right(rdsp_sign_list);
}

void dsd_const_string::m_trim_left( const dsd_const_string& rdsp_sign_list )
{
	if(this->inc_length <= 0)
		return;
    const char* achl_s1 = this->strc_ptr;
    const char* achl_s1e = this->m_get_end();
    while(achl_s1 < achl_s1e) {
        if(rdsp_sign_list.m_index_of(dsd_const_string(achl_s1, 1)) < 0)
            break;
        achl_s1++;
    }
    this->strc_ptr = achl_s1;
    this->inc_length = achl_s1e-achl_s1;
}

void dsd_const_string::m_trim_right( const dsd_const_string& rdsp_sign_list )
{
	if(this->inc_length <= 0)
		return;
    const char* achl_s1 = this->m_get_end();
    const char* achl_s1e = this->m_get_start();
    while(--achl_s1 >= achl_s1e) {
        if(rdsp_sign_list.m_index_of(dsd_const_string(achl_s1, 1)) < 0)
            break;
    }
    this->strc_ptr = achl_s1e;
    this->inc_length = achl_s1-achl_s1e+1;
}

dsd_const_string dsd_const_string::m_substring(int inp_start) const
{
    return this->m_substring(inp_start, (int)this->m_get_len());
}

dsd_const_string dsd_const_string::m_substring(int inp_start, int inp_end) const
{
    return dsd_const_string(this->m_get_start()+inp_start, inp_end-inp_start);
}

int dsd_const_string::m_find_first_of( const dsd_const_string& rdsp_sign_list, int inp_pos ) const
{
    // initialize some variables:
    size_t in_len_signs  = rdsp_sign_list.inc_length;
    for ( size_t in_pos = inp_pos; in_pos < this->inc_length; in_pos++ ) {
        for ( int in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
            if ( m_cmp_mem(&this->strc_ptr[in_pos], &rdsp_sign_list.strc_ptr[in_sign], 1) ) {
                return (int)in_pos;
            }
        }
    }
    return -1;
}

int dsd_const_string::m_find_first_of( const dsd_const_string& rdsp_sign_list ) const
{
    return m_find_first_of(rdsp_sign_list, 0);
}

int dsd_const_string::m_find_last_of( const dsd_const_string& rdsp_sign_list, int inp_pos ) const
{
    size_t in_len_signs = rdsp_sign_list.inc_length;
    for ( int in_pos = inp_pos-1; in_pos >= 0; in_pos-- ) {
        for ( size_t in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
            if ( m_cmp_mem(&this->strc_ptr[in_pos], &rdsp_sign_list.strc_ptr[in_sign], 1) ) {
                return in_pos;
            }
        }
    }
    return -1;
}

int dsd_const_string::m_find_last_of( const dsd_const_string& rdsp_sign_list ) const
{
    return m_find_last_of(rdsp_sign_list, this->m_get_len());
}
    
int dsd_const_string::m_find_first_not_of( const dsd_const_string& rdsp_sign_list, int inp_pos ) const
{
    // initialize some variables:
    size_t in_len_signs = rdsp_sign_list.inc_length;
    for ( size_t in_pos = inp_pos; in_pos < this->inc_length; in_pos++ ) {
        for ( size_t in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
            if ( m_cmp_mem(&this->strc_ptr[in_pos], &rdsp_sign_list.strc_ptr[in_sign], 1) ) {
                goto LBL_FOUND;
            }
        }
        return (int)in_pos;
LBL_FOUND:
        ;
    }
    return -1;
}

int dsd_const_string::m_find_first_not_of( const dsd_const_string& rdsp_sign_list ) const
{
    return m_find_first_not_of(rdsp_sign_list, 0);
}

int dsd_const_string::m_find_last_not_of( const dsd_const_string& rdsp_sign_list, int inp_pos ) const
{
    size_t in_len_signs = rdsp_sign_list.inc_length;
    for ( int in_pos = inp_pos-1; in_pos >= 0; in_pos-- ) {
        for ( size_t in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
            if ( m_cmp_mem(&this->strc_ptr[in_pos], &rdsp_sign_list.strc_ptr[in_sign], 1) ) {
                goto LBL_FOUND;
            }
        }
        return in_pos;
LBL_FOUND:
        ;
    }
    return -1;
}
    
dsd_const_string dsd_const_string::m_substr(int inp_start, int inp_len) const
{
    return this->m_substring(inp_start, inp_start+inp_len);
}

bool dsd_const_string::m_parse_int(int* ain_out) const
{
    char chrl_temp[16];
    if(this->inc_length >= sizeof(chrl_temp))
        return false;
    memcpy(chrl_temp, this->strc_ptr, this->inc_length);
    chrl_temp[this->inc_length] = 0;
    char* achl_end;
    long int inl_value = strtol (chrl_temp, &achl_end, 10);
    //int inl_value = atoi(chrl_temp);
    if ( achl_end != chrl_temp+this->inc_length ) {
        return false;
    }
    *ain_out = inl_value;
    return true;
}

bool dsd_const_string::m_parse_long(long long int* ailp_out) const
{
    char chrl_temp[16];
    if(this->inc_length >= sizeof(chrl_temp))
        return false;
    memcpy(chrl_temp, this->strc_ptr, this->inc_length);
    chrl_temp[this->inc_length] = 0;
    const char* achl_end;
    long long int inl_value = ds_hstring::m_str_to_ll(chrl_temp, &achl_end, 10);
    //int inl_value = atoi(chrl_temp);
    if ( achl_end != chrl_temp+this->inc_length ) {
        return false;
    }
    *ailp_out = inl_value;
    return true;
}

#if 0
static bool m_test_cmp() {
    dsd_const_string dsl_trim1(" aabmsjk ");
    if(!dsl_trim1.m_trim_left(" ").m_equals("aabmsjk "))
        throw 0;
    if(!dsl_trim1.m_trim_right(" ").m_equals(" aabmsjk"))
        throw 0;
    if(!dsl_trim1.m_trim(" ").m_equals("aabmsjk"))
        throw 0;
    dsd_const_string dsl_trim2("    ");
    if(!dsl_trim2.m_trim_right(" ").m_equals(""))
        throw 0;
    if(!dsl_trim2.m_trim_left(" ").m_equals(""))
        throw 0;

    dsd_const_string dsl_temp1("http://www.hob.de");
    if(dsl_temp1.m_index_of("hob.de") != 11)
        throw 0;
    if(dsl_temp1.m_index_of("http") != 0)
        throw 0;
    if(dsl_temp1.m_index_of("x") != -1)
        throw 0;
    if(!dsl_temp1.m_equals("http://www.hob.de"))
        throw 0;
    if(dsl_temp1.m_equals("http://WWW.HOB.DE"))
        throw 0;
    if(dsl_temp1.m_last_index_of(".") != 14)
        throw 0;
    if(!dsl_temp1.m_starts_with("http://"))
        throw 0;
    if(!dsl_temp1.m_ends_with("www.hob.de"))
        throw 0;

    if(dsl_temp1.m_index_of_ic("HOB.DE") != 11)
        throw 0;
    if(dsl_temp1.m_index_of_ic("HTTP") != 0)
        throw 0;
    if(dsl_temp1.m_index_of_ic("X") != -1)
        throw 0;
    if(!dsl_temp1.m_equals_ic("http://WWW.HOB.DE"))
        throw 0;
    if(dsl_temp1.m_last_index_of_ic("W") != 9)
        throw 0;
    if(!dsl_temp1.m_starts_with_ic("HTTP://"))
        throw 0;
    if(!dsl_temp1.m_ends_with_ic("www.HOB.de"))
        throw 0;
    return true;
}

static bool bos_test = m_test_cmp();
#endif

#if 0
bool m_equals(const dsd_const_string& rdsp_search) const;

    int m_index_of_ic(const dsd_const_string& rdsp_search) const;
    int m_last_index_of_ic(const dsd_const_string& rdsp_search) const;
    bool m_starts_with_ic(const dsd_const_string& rdsp_search) const;
    bool m_ends_with_ic(const dsd_const_string& rdsp_search) const;
    bool m_equals_ic(const dsd_const_string& rdsp_search) const;
#endif

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
ds_hstring::ds_hstring() :
    ads_wsp_helper(NULL),
    ach_data(NULL),
    in_len_data(0),
    in_memory_size(0),
    in_default_memory_size(0)
{
    m_setup( NULL );
}

ds_hstring::ds_hstring( ds_wsp_helper* ads_wsp_helper_in, int in_default_size_in ) :
    ads_wsp_helper(NULL),
    ach_data(NULL),
    in_len_data(0),
    in_memory_size(0),
    in_default_memory_size(0)
{
    m_setup( ads_wsp_helper_in, in_default_size_in );
}

ds_hstring::ds_hstring( ds_wsp_helper* ads_wsp_helper_in, const dsd_const_string& rdsp_string ) :
    ads_wsp_helper(NULL),
    ach_data(NULL),
    in_len_data(0),
    in_memory_size(0),
    in_default_memory_size(0)
{
    m_setup( ads_wsp_helper_in );
    m_write( rdsp_string );
}

ds_hstring::ds_hstring( ds_wsp_helper* ads_wsp_helper_in, const ds_hstring& rdsp_string ) :
    ads_wsp_helper(NULL),
    ach_data(NULL),
    in_len_data(0),
    in_memory_size(0),
    in_default_memory_size(0)
{
    m_setup( ads_wsp_helper_in );
    m_write( rdsp_string );
}

ds_hstring::ds_hstring( ds_wsp_helper* ads_wsp_helper_in, const ds_hstring* adsp_string ) :
    ads_wsp_helper(NULL),
    ach_data(NULL),
    in_len_data(0),
    in_memory_size(0),
    in_default_memory_size(0)
{
    m_setup( ads_wsp_helper_in );
    m_write( adsp_string );
}

#if 0
// JF
ds_hstring::ds_hstring( ds_wsp_helper* ads_wsp_helper_in, const char* ach_zero ) :
    ads_wsp_helper(NULL),
    ach_data(NULL),
    in_len_data(0),
    in_memory_size(0),
    in_default_memory_size(0)
{
    m_setup( ads_wsp_helper_in );
    m_write_zeroterm( ach_zero );
}
#endif

// JF
ds_hstring::ds_hstring( ds_wsp_helper* ads_wsp_helper_in, const char* ach, int in_len ) :
    ads_wsp_helper(NULL),
    ach_data(NULL),
    in_len_data(0),
    in_memory_size(0),
    in_default_memory_size(0)
{
    m_setup( ads_wsp_helper_in, in_len );
    m_write( ach, in_len );
}

/*+-------------------------------------------------------------------------+*/
/*| copy constructor:                                                       |*/
/*+-------------------------------------------------------------------------+*/
ds_hstring::ds_hstring( const ds_hstring& dc_copy ) :
    ads_wsp_helper(NULL),
    ach_data(NULL),
    in_len_data(0),
    in_memory_size(0),
    in_default_memory_size(0)
{
    m_copy( dc_copy );  
}

/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/
ds_hstring::~ds_hstring()
{
    m_free_memory();
}

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/**
 * function ds_hstring::m_setup
 *
 * @param[in]  ds_wsp_helper*       ads_wsp_helper_in
 * @param[in]  int                  in_default_size_in
*/
void ds_hstring::m_setup( ds_wsp_helper* ads_wsp_helper_in, int in_default_size_in )
{
    this->ads_wsp_helper         = ads_wsp_helper_in;
    this->in_default_memory_size = in_default_size_in;
    this->m_reset();
} // end of ds_hstring::m_setup

/**
 * function ds_hstring::m_setup
 *
 * @param[in]  int                  inp_min_size
*/
bool ds_hstring::m_ensure_size( int inp_min_size, bool bop_copy )
{
    if(this->in_memory_size >= inp_min_size)
        return true;
#if 1
	int inl_copy = bop_copy ? this->in_len_data : 0;
	return m_enlarge_memory(inp_min_size, inl_copy);
#else
    this->m_free_memory();
    // check for default entry:
    if ( inp_min_size <= HSTR_DEFAULT_MEM_SIZE ) {
        ach_data       = &rch_buffer[0];
        in_memory_size = HSTR_DEFAULT_MEM_SIZE;
        ach_data[0]    = 0;
        return true;
    }
    ach_data = m_get_mem(inp_min_size);
    if ( ach_data == NULL )
        return false;
    ach_data[0] = 0;
    in_memory_size = inp_min_size;
	return true;
#endif
} // end of ds_hstring::m_ensure_size

/**
 * function ds_hstring::m_init
 *
 * @param[in]  ds_wsp_helper*       ads_wsp_helper_in
*/
void ds_hstring::m_init( ds_wsp_helper* ads_wsp_helper_in )
{
    ads_wsp_helper = ads_wsp_helper_in;
} // end of ds_hstring::m_init


/**
 * operator = 
 *
 * @param[in]  const ds_hstring& dc_in
 *
 * @return     ds_hstring&
*/
ds_hstring& ds_hstring::operator = (const ds_hstring &dc_in)
{
    m_copy( dc_in );
    return *this;
} // end of ds_hstring::operator =


/**
 * operator +
 *
 * @param[in]   const ds_hstring& dc_in
 *
 * @return      ds_hstring
*/
ds_hstring ds_hstring::operator + (const ds_hstring &dc_in) const
{
    // initialize some variables:
    ds_hstring ds_ret( ads_wsp_helper, in_len_data + dc_in.in_len_data );

    ds_ret.m_write( ach_data, in_len_data, true );
    ds_ret.m_write( dc_in.ach_data, dc_in.in_len_data, true );

    return ds_ret;
} // end of ds_hstring::operator +


/**
 * operator +=
 *
 * @param[in]   const ds_hstring& dc_in
 *
 * @return      ds_hstring&
*/
ds_hstring& ds_hstring::operator += (const ds_hstring &dc_in)
{
    m_write( dc_in.ach_data, dc_in.in_len_data, true );
    return *this;
} // end if ds_hstring::operaot +=

ds_hstring& ds_hstring::operator =(const dsd_const_string &rdsp_in) {
    this->m_set(rdsp_in);
    return *this;
}

ds_hstring& ds_hstring::operator +=(const dsd_const_string &rdsp_in) {
    this->m_write(rdsp_in);
    return *this;
}

/**
 * operator =
 *
 * @param[in]   const char* ach_zero
 *
 * @return      ds_hstring&
*/
void ds_hstring::m_set_zeroterm(const char* ach_zero)
{
    if ( ach_zero == NULL ) {
        return;
    }

    m_write( ach_zero, (int)strlen(ach_zero), false );
    return;
} // end of ds_hstring::operator =

void ds_hstring::m_set(const dsd_const_string& rdsp_string) {
    m_write( rdsp_string.strc_ptr, rdsp_string.inc_length, false );
}

#if 0
/**
 * operator +
 *
 * @param[in]   const char* ach_zero
 *
 * @return      ds_hstring
*/
ds_hstring ds_hstring::operator + (const char* ach_zero) const
{
    // initialize some variables:
    ds_hstring ds_ret( ads_wsp_helper );

    if ( ach_zero == NULL ) {
        return ds_ret;
    }

    ds_ret.m_write( ach_data, in_len_data, true );
    ds_ret.m_write( ach_zero, (int)strlen(ach_zero), true );

    return ds_ret;
} // end of ds_hstring::operator +
#endif

#if 0
/**
 * operator +=
 *
 * @param[in]   const char* ach_zero
 *
 * @return      ds_hstring&
*/
ds_hstring& ds_hstring::operator += (const char* ach_zero)
{
    if ( ach_zero == NULL ) {
        return *this;
    }

    m_write( ach_zero, (int)strlen(ach_zero), true );
    return *this;
} // end of ds_hstring::operaot +=
#endif

/**
 * operator =
 *
 * @param[in]   char ch_in
 *
 * @return      ds_hstring&
*/
ds_hstring& ds_hstring::operator =  (char ch_in)
{
    m_write( &ch_in, 1, false ); // there is no need to play around with buffer and char is always 1 byte long.
    return *this;
} // end of ds_hstring::operator =


/**
 * operator +
 *
 * @param[in]   char ch_in
 *
 * @return      ds_hstring
*/
ds_hstring ds_hstring::operator +  (char ch_in) const
{
    // initialize some variables:
    ds_hstring ds_ret( ads_wsp_helper );

    ds_ret.m_write( ach_data, in_len_data, true );
    ds_ret.m_write( &ch_in, 1 );

    return ds_ret;
} // end of ds_hstring::operator +


/**
 * operator +=
 *
 * @param[in]   char ch_in
 *
 * @return      ds_hstring&
*/
ds_hstring& ds_hstring::operator += (char ch_in)
{
    m_write( &ch_in, 1, true );
    return *this;
} // end of ds_hstring::operaot +=


/**
 * operator =
 *
 * @param[in]   int in_in
 *
 * @return      ds_hstring&
*/
ds_hstring& ds_hstring::operator =  (int in_in)
{
    m_reset();
    m_writef( "%d", in_in );
    return *this;
} // end of ds_hstring::operator =


/**
 * operator +
 *
 * @param[in]   int in_in
 *
 * @return      ds_hstring
*/
ds_hstring ds_hstring::operator +  (int in_in) const
{
    // initialize some variables:
    ds_hstring ds_ret( ads_wsp_helper );

    ds_ret.m_write( ach_data, in_len_data, true );
    ds_ret.m_writef( "%d", in_in );

    return ds_ret;
} // end of ds_hstring::operator =


/**
 * operator +=
 *
 * @param[in]   int in_in
 *
 * @return      ds_hstring&
*/
ds_hstring& ds_hstring::operator += (int in_in)
{
    m_writef( "%d", in_in );
    return *this;
} // end of ds_hstring::operaot +=


/**
 * operator []
 *
 * @param[in]   unsigned int in_pos
 *
 * @return      char
*/
char ds_hstring::operator[] (unsigned int in_pos) const
{
    if ( (int)in_pos < in_len_data ) {
        return ach_data[in_pos];
    }
    return '0';
} // end of ds_hstring::operator[]


/**
 * public function ds_hstring::m_get
 *
 * @param[in]   unsigned int in_pos
 *
 * @return      char
*/
const char* ds_hstring::m_get_from( int in_pos ) const
{
    if ( in_pos < in_len_data ) {
        return &ach_data[in_pos];
    }
    return NULL;
} // end of ds_hstring::m_get

void ds_hstring::m_write_zeroterm( const char* ach_zero )
{
    if ( ach_zero == NULL ) {
        return;
    }
    return m_write( ach_zero, (int)strlen(ach_zero), true );
}

#if 0
/**
 * function ds_hstring::m_write
 *
 * @param[in]   const char* ach_zero         pointer to data should be saved (zero terminated!)
 * @param[in]   bool        bo_append        if true, data will be appended at end of memory
 *                                           otherwise, old memory will be overwritten
 *                                           default value = true
*/
void ds_hstring::m_write_zeroterm( const char* ach_zero, bool bo_append )
{
    if ( ach_zero == NULL ) {
        return;
    }
    return m_write( ach_zero, (int)strlen(ach_zero), bo_append );
} // end of ds_hstring::m_write
#endif

/**
 * function ds_hstring::m_write
 *
 * @param[in]   const char*   ach_input        pointer to data should be saved
 * @param[in]   int           in_len_input     length of ach_input
 * @param[in]   bool          bo_append        if true, data will be appended at end of memory
 *                                             otherwise, old memory will be overwritten
 *                                             default value = true
*/
void ds_hstring::m_write( const char* ach_input, int in_len_input, bool bo_append )
{
    // check input data:
    if ( ach_input == NULL || in_len_input < 0 ) {
        return;
    }

    if ( bo_append ) {
        int in_old_length  = in_len_data;
        in_len_data += in_len_input;
        // check if memory is large enough to put data in:
        if ( in_len_data >= in_memory_size ) {
            // enlarge memory:
            m_enlarge_memory( in_len_data + 1, in_old_length );
        }
        // copy data:
        memmove( (ach_data + in_old_length), ach_input, in_len_input );
    } else {
        // check if memory is large enough to put data in:
        if ( in_len_input >= in_memory_size ) {
            // enlarge memory:
            m_enlarge_memory( in_len_input + 1, 0 );
        }
        // copy data:
        memmove( ach_data, ach_input, in_len_input );
        in_len_data = in_len_input;
    }
    ach_data[in_len_data] = 0;
} // end of ds_hstring::m_write

/**
 * function ds_hstring::m_write
 *
 * @param[in]   const char*   ach_input        pointer to data should be saved
 * @param[in]   int           in_len_input     length of ach_input
 * @param[in]   bool          bo_append        if true, data will be appended at end of memory
 *                                             otherwise, old memory will be overwritten
 *                                             default value = true
*/
void ds_hstring::m_write( const char* ach_input, int in_len_input )
{
    this->m_write(ach_input, in_len_input, true);
}

/**
 * function ds_hstring::m_write
 *
 * @param[in]   const char*   ach_input        pointer to data should be saved
 * @param[in]   int           in_len_input     length of ach_input
 * @param[in]   bool          bo_append        if true, data will be appended at end of memory
 *                                             otherwise, old memory will be overwritten
 *                                             default value = true
*/
void ds_hstring::m_set( const char* ach_input, int in_len_input )
{
    this->m_write(ach_input, in_len_input, false);
}

void ds_hstring::m_set( const ds_hstring& rdsp_input ) {
    this->m_write(rdsp_input.m_get_ptr(), rdsp_input.m_get_len(), false);
}

void ds_hstring::m_set( const ds_hstring* adsp_input ) {
    this->m_write(adsp_input->m_get_ptr(), adsp_input->m_get_len(), false);
}

void ds_hstring::m_set( const struct dsd_unicode_string* ads_input ) 
{
    this->m_write( ads_input, false );
}

void ds_hstring::m_set( const struct dsd_unicode_string& ads_input ) 
{
    this->m_write( &ads_input, false );
}

#if 0
void ds_hstring::m_write( const ds_hstring& rdsp_input, bool bo_append ) {
    this->m_write(rdsp_input.m_get_ptr(), rdsp_input.m_get_len(), bo_append);
}
#endif

void ds_hstring::m_write ( const ds_hstring& rdsp_input ) {
    this->m_write(rdsp_input.m_get_ptr(), rdsp_input.m_get_len(), true);
}

void ds_hstring::m_write(const dsd_const_string& rdsp_string) {
    this->m_write(rdsp_string.strc_ptr, rdsp_string.inc_length, true);
}

#if 0
void ds_hstring::m_write(const dsd_const_string& rdsp_string, bool bo_append) {
    this->m_write(rdsp_string.strc_ptr, rdsp_string.inc_length, bo_append);
}
#endif

void ds_hstring::m_write(const ds_hstring* adsp_input) {
    this->m_write(adsp_input->m_get_ptr(), adsp_input->m_get_len(), true);
}

#if 0
void ds_hstring::m_write(const ds_hstring* adsp_input, bool bo_append) {
    this->m_write(adsp_input->m_get_ptr(), adsp_input->m_get_len(), bo_append);
}
#endif

int ds_hstring::m_write( const struct dsd_unicode_string* ads_input, enum ied_charset iep_target, bool bo_append )
{
    // initialize some variables:
    int in_needed;
    
    // evaluate needed length:
    // TODO: Get length in bytes!!!!
    in_needed = m_len_vx_ucs( iep_target, ads_input );
    if ( in_needed < 1 ) {
        return in_needed;
    }

    if ( bo_append == true ) {
        int in_old_length  = in_len_data;
        int in_new_length = in_old_length + in_needed;
        // check if memory is large enough to put data in:
        if ( in_new_length >= in_memory_size ) {
            m_enlarge_memory( in_new_length + 1, in_old_length );
        }
        // copy data:
        in_needed = m_cpy_vx_vx( (void*)&ach_data[in_old_length],
                     in_memory_size - in_old_length,
                     iep_target,
                     ads_input->ac_str, ads_input->imc_len_str,
                     ads_input->iec_chs_str );
        if ( in_needed < 0 ) {
            return in_needed;
        }
        this->in_len_data += in_needed;
    } else {
        // check if memory is large enough to put data in:
        if ( in_needed >= in_memory_size ) {
            m_enlarge_memory( in_needed + 1, 0 );
        }

        // copy data:
        in_needed = m_cpy_vx_vx( (void*)ach_data, in_memory_size, iep_target,
                     ads_input->ac_str, ads_input->imc_len_str,
                     ads_input->iec_chs_str );
        if ( in_needed < 0 ) {
            return in_needed;
        }
        // set length and zero terminate:
        this->in_len_data = in_needed;
    }
    ach_data[in_len_data] = 0;
    return in_needed;
}

/**
 * function ds_hstring::m_write
 *
 * @param[in]   dsd_unicode_string* ads_input
 * @param[in]   bool                bo_append  if true, data will be appended at end of memory
 *                                             if false, old memory will be overwritten
 *                                             default value = true
*/
int ds_hstring::m_write( const struct dsd_unicode_string* ads_input, bool bo_append )
{
    return this->m_write(ads_input, ied_chs_utf_8, bo_append);
} // end of ds_hstring::m_write

int ds_hstring::m_write( const struct dsd_unicode_string* ads_input )
{
    return this->m_write(ads_input, true);
}

int ds_hstring::m_write( const struct dsd_unicode_string* ads_input, enum ied_charset iep_target )
{
    return this->m_write(ads_input, iep_target, true);
}

void ds_hstring::m_write_char( char chp_value )
{
    m_write( &chp_value, 1 );
}

void ds_hstring::m_write_int( int inp_value )
{
    m_writef( "%d", inp_value );
}

void ds_hstring::m_write_concat(const dsd_const_string& rdsp_str1, const dsd_const_string& rdsp_str2, const dsd_const_string& rdsp_str3)
{
    this->m_write(rdsp_str1);
    this->m_write(rdsp_str2);
    this->m_write(rdsp_str3);
}

void ds_hstring::m_write_xml_open_tag(const dsd_const_string& rdsp_name)
{
    this->m_write("<", 1, true);
    this->m_write(rdsp_name);
    this->m_write(">", 1, true);
}

void ds_hstring::m_write_xml_open_tag(const dsd_unicode_string& rdsp_name)
{
    this->m_write("<", 1, true);
    this->m_write(&rdsp_name);
    this->m_write(">", 1, true);
}

void ds_hstring::m_write_xml_open_tag(const char* ach_input, int in_len_input)
{
    this->m_write("<", 1, true);
    this->m_write(ach_input, in_len_input, true);
    this->m_write(">", 1, true);
}

void ds_hstring::m_write_xml_close_tag(const dsd_const_string& rdsp_name)
{
    this->m_write("</", 2, true);
    this->m_write(rdsp_name);
    this->m_write(">", 1, true);
}

void ds_hstring::m_write_xml_close_tag(const dsd_unicode_string& rdsp_name)
{
    this->m_write("</", 2, true);
    this->m_write(&rdsp_name);
    this->m_write(">", 1, true);
}

void ds_hstring::m_write_xml_close_tag(const char* ach_input, int in_len_input)
{
    this->m_write("</", 2, true);
    this->m_write(ach_input, in_len_input, true);
    this->m_write(">", 1, true);
}

void ds_hstring::m_write_xml_text(const dsd_unicode_string& rdsp_text)
{
    this->m_write(&rdsp_text, ied_chs_xml_utf_8, true);
}

void ds_hstring::m_write_xml_text(const dsd_const_string& rdsp_text)
{
    dsd_unicode_string dsl_text;
    dsl_text.ac_str = (void*)rdsp_text.m_get_ptr();
    dsl_text.imc_len_str = rdsp_text.m_get_len();
    dsl_text.iec_chs_str = ied_chs_utf_8; 
    this->m_write_xml_text(dsl_text);
}

void ds_hstring::m_write_html_text(const dsd_unicode_string& rdsp_text)
{
    this->m_write(&rdsp_text, ied_chs_html_1, true);
}

void ds_hstring::m_write_html_text(const dsd_const_string& rdsp_text)
{
    dsd_unicode_string dsl_text;
    dsl_text.ac_str = (void*)rdsp_text.m_get_ptr();
    dsl_text.imc_len_str = rdsp_text.m_get_len();
    dsl_text.iec_chs_str = ied_chs_utf_8; 
    this->m_write_html_text(dsl_text);
}

void ds_hstring::m_write_html_text(const ds_hstring& rdsp_text)
{
    this->m_write_html_text(rdsp_text.m_const_str());
}

void ds_hstring::m_write_html_text(const char* achp_text, int inp_len)
{
    this->m_write_html_text(dsd_const_string(achp_text, inp_len));
}

void ds_hstring::m_write_uri1(const dsd_const_string& rdsp_text)
{
	dsd_unicode_string dsl_text;
    dsl_text.ac_str = (void*)rdsp_text.m_get_ptr();
    dsl_text.imc_len_str = rdsp_text.m_get_len();
    dsl_text.iec_chs_str = ied_chs_utf_8; 
	this->m_write(&dsl_text, ied_chs_uri_1, true);
}

/**
 * function ds_hstring::m_reset
*/
void ds_hstring::m_reset()
{
    this->m_free_memory();
    this->in_memory_size         = 0;
    this->in_len_data            = 0;

    // check for default entry:
    if ( in_default_memory_size <= HSTR_DEFAULT_MEM_SIZE ) {
        this->ach_data       = &rch_buffer[0];
        this->in_memory_size = HSTR_DEFAULT_MEM_SIZE;
    } else {
        this->ach_data = m_get_mem( in_default_memory_size );
        if(this->ach_data == NULL)
            return;
        this->in_memory_size = in_default_memory_size;
    }
    this->ach_data[0] = 0;
    this->in_len_data = 0;
} // end of ds_hstring::m_reset

int ds_hstring::m_search(const dsd_const_string& rdsp_search) const
{
    return this->m_const_str().m_index_of(rdsp_search);
}

int ds_hstring::m_search(int inp_offset, const dsd_const_string& rdsp_search) const
{
    return this->m_const_str().m_index_of(inp_offset, rdsp_search);
}

int ds_hstring::m_search_ic(const dsd_const_string& rdsp_search) const
{
    return this->m_const_str().m_index_of_ic(rdsp_search);
}

int ds_hstring::m_search_ic(int inp_offset, const dsd_const_string& rdsp_search) const
{
    int inl_res = this->m_substring(inp_offset).m_index_of_ic(rdsp_search);
    if(inl_res < 0)
        return inl_res;
    return inl_res + inp_offset;
}

int ds_hstring::m_search(int inp_offset, const dsd_const_string& rdsp_search, bool bop_ignore_case) const {
	if(bop_ignore_case)
		return m_search_ic(inp_offset, rdsp_search);
	return m_search(inp_offset, rdsp_search);
}

int ds_hstring::m_search(const ds_hstring& rdsp_search) const
{
    return this->m_search(rdsp_search.m_const_str());
}

int ds_hstring::m_search_ic(const ds_hstring& rdsp_search) const
{
    return this->m_search_ic(rdsp_search.m_const_str());
}

int ds_hstring::m_search( const char* ach_search, int in_len_search ) const
{
    return this->m_search(dsd_const_string(ach_search, in_len_search));
}

int ds_hstring::m_search_ic( const char* ach_search, int in_len_search ) const
{
    return this->m_search_ic(dsd_const_string(ach_search, in_len_search));
}

#if 0
/**
 * function ds_hstring::m_search
 *
 * @param[in]   char*   ach_search          string to search for
 * @param[in]   int     in_len_search       length of search string
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 * @param[in]   int     in_offset           start position of search
 * @param[in]   bool    bo_ret_absolut      true:  return position is absolut (in case of offset > 0)
 *                                          false: return position is relativ (in case of offset > 0)
 *                                          default value is true
 *
 * @return      int                         position of found string
 *                                          -1 if not found
*/
int ds_hstring::m_search( const char* ach_search, int in_len_search,
                         bool bo_ignore_case, int in_offset, bool bo_ret_absolut ) const
{
    // initialize some variables:
    int in_found = -1;              // found position
    int in_pos   = in_offset;       // working position
    int in_comp  =  0;              // compare position in ach_search

    // check incoming data:
    if (    ach_search == NULL || in_len_search < 1 
         || in_offset < 0 || in_offset > in_len_data ) {
        return -1;
    }

    if ( bo_ignore_case == true ) {
        //---------------
        // ignore case
        //---------------
        for ( ; ((in_pos < in_len_data) && (in_comp < in_len_search)); in_pos++ ) {
            if ( tolower(ach_data[in_pos]) == tolower(ach_search[in_comp]) ) {
                // compare next sign:
                in_comp++;
                // set found pos:
                if ( in_found == -1 ) {
                    if ( bo_ret_absolut == true ) {
                        in_found = in_pos;
                    } else {
                        in_found = in_pos - in_offset;
                    }
                }
            } else {
                // start search from beginning:
                in_comp = 0;
                // reset found pos:
                in_found = -1;
            }
        }
    } else {
        //---------------
        // keep case
        //---------------
        for ( ; ((in_pos < in_len_data) && (in_comp < in_len_search)); in_pos++ ) {
            if ( ach_data[in_pos] == ach_search[in_comp] ) {
                // compare next sign:
                in_comp++;
                // set found pos:
                if ( in_found == -1 ) {
                    if ( bo_ret_absolut == true ) {
                        in_found = in_pos;
                    } else {
                        in_found = in_pos - in_offset;
                    }
                }
            } else {
                // start search from beginning:
                in_comp = 0;
                // reset found pos:
                in_found = -1;
            }
        }
    }

    // check if hole string was compared:
    if ( in_comp < in_len_search ) {
        in_found = -1;
    }

    return in_found;
} // end of ds_hstring::m_search
#endif

#if 0
/**
 * function ds_hstring::m_search_last
 *
 * @param[in]   char*   ach_zero            string to search for
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 * @param[in]   int     in_offset           start position of search
 *
 * @return      int                         position of found string
 *                                          -1 if not found
*/
int ds_hstring::m_search_last( const char* ach_zero,
                               bool bo_ignore_case, int in_offset ) const
{
    if ( ach_zero == NULL ) {
        return -1;
    }
    return m_search_last( ach_zero, (int)strlen(ach_zero), bo_ignore_case, in_offset );
} // end of ds_hstring::m_search_last
#endif

#if 0
/**
 * function ds_hstring::m_search_last
 *
 * @param[in]   char*   ach_search          string to search for
 * @param[in]   int     in_len_search       length of search string
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 * @param[in]   int     in_offset           start position of search
 *
 * @return      int                         position of found string
 *                                          -1 if not found
*/
int ds_hstring::m_search_last( const char* ach_search, int in_len_search,
                               bool bo_ignore_case, int in_offset ) const
{
    // initialize some variables:
    int in_found = -1;              // found position
    int in_pos;                     // working position
    int in_comp  =  0;              // compare position in ach_search

    if ( in_offset < 0 ) {
        in_pos = /*in_len_data  - 1;*/ in_len_data;
    } else {
        in_pos = in_offset;
    }

    // check incoming data:
    if ( ach_search == NULL || in_len_search < 1 ) {
        return -1;
    }
    in_pos -= in_len_search;

    if ( bo_ignore_case == true ) {
        //---------------
        // ignore case
        //---------------
        while ( (in_pos < in_len_data) && (in_pos >= 0) && (in_comp < in_len_search) ) {
            if ( tolower(ach_data[in_pos]) == tolower(ach_search[in_comp]) ) {
                // compare next sign:
                in_comp++;
                // set found pos:
                if ( in_found == -1 ) {
                    in_found = in_pos;
                }
                // go one sign forward:
                in_pos++;
            } else {
                if ( in_found == -1 ) {
                    // go one sign back:
                    in_pos--;
                } else {
                    // go back to old position:
                    in_pos = in_found - 1;
                    // reset found pos:
                    in_found = -1;

                }
                // start search from beginning:
                in_comp = 0;
            }
        } // end of while
    } else {
        //---------------
        // keep case
        //---------------
        while ( (in_pos < in_len_data) && (in_pos >= 0) && (in_comp < in_len_search) ) {
            if ( ach_data[in_pos] == ach_search[in_comp] ) {
                // compare next sign:
                in_comp++;
                // set found pos:
                if ( in_found == -1 ) {
                    in_found = in_pos;
                }
                // go one sign forward:
                in_pos++;
            } else {
                if ( in_found == -1 ) {
                    // go one sign back:
                    in_pos--;
                } else {
                    // go back to old position:
                    in_pos = in_found - 1;
                    // reset found pos:
                    in_found = -1;

                }
                // start search from beginning:
                in_comp = 0;
            }
        } // end of while
    }

    // check if hole string was compared:
    if ( in_comp < in_len_search ) {
        in_found = -1;
    }

    return in_found;
} // end of ds_hstring::m_search_last
#endif

int ds_hstring::m_search_last( const dsd_const_string& rdsp_string ) const
{
    return this->m_const_str().m_last_index_of(rdsp_string);
}

int ds_hstring::m_search_last_ic( const dsd_const_string& rdsp_string ) const
{
    return this->m_const_str().m_last_index_of_ic(rdsp_string);
}

int ds_hstring::m_search_last( int inp_offset, const dsd_const_string& rdsp_string ) const
{
    return this->m_const_str().m_last_index_of(inp_offset, rdsp_string);
}

int ds_hstring::m_search_last(const ds_hstring& rdsp_search) const
{
    return m_search_last(rdsp_search.m_const_str());
}

int ds_hstring::m_search_last_ic(const ds_hstring& rdsp_search) const
{
    return m_search_last_ic(rdsp_search.m_const_str());
}
    
#if 0
int ds_hstring::m_search_last(
    const dsd_const_string& rdsp_string, bool bo_ignore_case ) const
{
    return m_search_last(
        rdsp_string.strc_ptr, rdsp_string.inc_length, bo_ignore_case, -1);
}
#endif

#if 0
int ds_hstring::m_search_last(
    const dsd_const_string& rdsp_string, bool bo_ignore_case, int in_offset ) const
{
    return m_search_last(
        rdsp_string.strc_ptr, rdsp_string.inc_length, bo_ignore_case, in_offset);
}
#endif

#if 0
int ds_hstring::m_search_last(
    const ds_hstring& rdsp_search, bool bo_ignore_case ) const
{
    return m_search_last(
        rdsp_search.m_get_ptr(), rdsp_search.m_get_len(), bo_ignore_case, -1);
}
#endif

bool ds_hstring::m_starts_with( const dsd_const_string& rdsp_search ) const
{
    return this->m_const_str().m_starts_with(rdsp_search);
}

bool ds_hstring::m_starts_with_ic( const dsd_const_string& rdsp_search ) const
{
    return this->m_const_str().m_starts_with_ic(rdsp_search);
}

bool ds_hstring::m_starts_with( int inp_offset, const dsd_const_string& rdsp_search ) const
{
    return this->m_substring(inp_offset).m_starts_with(rdsp_search);
}

bool ds_hstring::m_starts_with_ic( int inp_offset, const dsd_const_string& rdsp_search ) const
{
    return this->m_substring(inp_offset).m_starts_with_ic(rdsp_search);
}


bool ds_hstring::m_starts_with_zeroterm( const char* ach_zero ) const
{
    if(ach_zero == NULL)
        return false;
    return this->m_starts_with(dsd_const_string(ach_zero, strlen(ach_zero)));
}

bool ds_hstring::m_starts_with_ic_zeroterm( const char* ach_zero ) const
{
    if(ach_zero == NULL)
        return false;
    return this->m_starts_with_ic(dsd_const_string(ach_zero, strlen(ach_zero)));
}

bool ds_hstring::m_starts_with( const char* ach_search, int in_len_search ) const
{
    return this->m_starts_with(dsd_const_string(ach_search, in_len_search));
}

bool ds_hstring::m_starts_with( int inp_offset, const char* ach_search, int in_len_search ) const
{
    return this->m_starts_with(inp_offset, dsd_const_string(ach_search, in_len_search));
}

bool ds_hstring::m_starts_with_ic( const char* ach_search, int in_len_search ) const
{
    return this->m_starts_with_ic(dsd_const_string(ach_search, in_len_search));
}

bool ds_hstring::m_starts_with_ic( int inp_offset, const char* ach_search, int in_len_search ) const
{
    return this->m_starts_with_ic(inp_offset, dsd_const_string(ach_search, in_len_search));
}

bool ds_hstring::m_starts_with( int inp_offset, const ds_hstring& rdsp_search ) const
{
    return this->m_starts_with(inp_offset, rdsp_search.m_const_str());
}

bool ds_hstring::m_starts_with( const ds_hstring& rdsp_search ) const
{
    return this->m_starts_with(rdsp_search.m_const_str());
}

bool ds_hstring::m_starts_with_ic( int inp_offset, const ds_hstring& rdsp_search ) const
{
    return this->m_starts_with_ic(inp_offset, rdsp_search.m_const_str());
}

bool ds_hstring::m_starts_with_ic( const ds_hstring& rdsp_search ) const
{
    return this->m_starts_with_ic(rdsp_search.m_const_str());
}

#if 0
/**
 * function ds_hstring::m_starts_with
 *
 * @param[in]   char*   ach_zero            string to search for
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 *
 * @return      bool
*/
bool ds_hstring::m_starts_with_zeroterm( const char* ach_zero, bool bo_ignore_case ) const
{
    if ( ach_zero == NULL ) {
        return false;
    }
    return m_starts_with( ach_zero, (int)strlen(ach_zero), bo_ignore_case );
} // end of ds_hstring::m_starts_with


/**
 * function ds_hstring::m_starts_with
 *
 * @param[in]   char*   ach_search          string to search for
 * @param[in]   int     in_len_search       length of search string
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 *
 * @return      bool
*/
bool ds_hstring::m_starts_with( const char* ach_search, int in_len_search, bool bo_ignore_case, int inp_offset ) const
{
    // TODO: Optimize and use own implementation
    return ( m_search( ach_search, in_len_search, bo_ignore_case, inp_offset ) == inp_offset );
} // end of ds_hstring::m_starts_with

/**
 * function ds_hstring::m_starts_with
 *
 * @param[in]   char*   ach_search          string to search for
 * @param[in]   int     in_len_search       length of search string
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 *
 * @return      bool
*/
bool ds_hstring::m_starts_with( const char* ach_search, int in_len_search, bool bo_ignore_case ) const
{
    return m_starts_with(ach_search, in_len_search, bo_ignore_case, 0);
} // end of ds_hstring::m_starts_with

bool ds_hstring::m_starts_with( const dsd_const_string& rdsp_search ) const
{
    return this->m_starts_with(rdsp_search.strc_ptr, rdsp_search.inc_length, false);
}

bool ds_hstring::m_starts_with( const dsd_const_string& rdsp_search, bool bo_ignore_case ) const
{
    return this->m_starts_with(rdsp_search.strc_ptr, rdsp_search.inc_length, bo_ignore_case);
}

bool ds_hstring::m_starts_with( const dsd_const_string& rdsp_search, bool bo_ignore_case, int inp_offset ) const
{
    return this->m_starts_with(rdsp_search.strc_ptr, rdsp_search.inc_length, bo_ignore_case, inp_offset);
}   

bool ds_hstring::m_starts_with( const ds_hstring& rdsp_search, bool bo_ignore_case, int inp_offset ) const
{
    return this->m_starts_with(rdsp_search.m_get_ptr(), rdsp_search.m_get_len(), bo_ignore_case, inp_offset );
}

bool ds_hstring::m_starts_with( const ds_hstring& rdsp_search, bool bo_ignore_case ) const
{
    return this->m_starts_with(rdsp_search.m_get_ptr(), rdsp_search.m_get_len(), bo_ignore_case);
}

bool ds_hstring::m_starts_with( const ds_hstring& rdsp_search ) const
{
    return this->m_starts_with(rdsp_search.m_get_ptr(), rdsp_search.m_get_len(), false);
}
#endif

bool ds_hstring::m_ends_with( const dsd_const_string& rdsp_search ) const
{
    return this->m_const_str().m_ends_with(rdsp_search);
}

bool ds_hstring::m_ends_with_ic( const dsd_const_string& rdsp_search ) const
{
    return this->m_const_str().m_ends_with_ic(rdsp_search);
}

bool ds_hstring::m_ends_with( const char* ach_search, int in_len_search ) const
{
    return this->m_ends_with(dsd_const_string(ach_search, in_len_search));
}

bool ds_hstring::m_ends_with_ic( const char* ach_search, int in_len_search ) const
{
    return this->m_ends_with_ic(dsd_const_string(ach_search, in_len_search));
}

bool ds_hstring::m_ends_with( const ds_hstring& rdsp_search ) const
{
    return this->m_ends_with(rdsp_search.m_const_str());
}

bool ds_hstring::m_ends_with_ic( const ds_hstring& rdsp_search ) const
{
    return this->m_ends_with_ic(rdsp_search.m_const_str());
}

#if 0
/**
 * function ds_hstring::m_ends_with
 *
 * @param[in]   char*   ach_zero            string to search for
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 *
 * @return      bool
*/
bool ds_hstring::m_ends_with( const char* ach_zero, bool bo_ignore_case ) const
{
    if ( ach_zero == NULL ) {
        return false;
    }
    return m_ends_with( ach_zero, (int)strlen(ach_zero), bo_ignore_case );
} // end of ds_hstring::m_ends_with


/**
 * function ds_hstring::m_ends_with
 *
 * @param[in]   char*   ach_search          string to search for
 * @param[in]   int     in_len_search       length of search string
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 *
 * @return      bool
*/
bool ds_hstring::m_ends_with( const char* ach_search, int in_len_search, bool bo_ignore_case ) const
{
    if(bo_ignore_case)
        return this->m_const_str().m_ends_with_ic(dsd_const_string(ach_search, in_len_search));
    return this->m_const_str().m_ends_with(dsd_const_string(ach_search, in_len_search));
} // end of ds_hstring::m_ends_with

bool ds_hstring::m_ends_with( const ds_hstring& rdsp_search, bool bo_ignore_case ) const
{
    return m_ends_with(rdsp_search.m_get_ptr(), rdsp_search.m_get_len(), bo_ignore_case);
}

bool ds_hstring::m_ends_with( const ds_hstring& rdsp_search ) const
{
    return m_ends_with(rdsp_search.m_get_ptr(), rdsp_search.m_get_len(), false);
}

bool ds_hstring::m_ends_with( const dsd_const_string& rdsp_search ) const
{
    return m_ends_with(rdsp_search.strc_ptr, rdsp_search.inc_length, false);
}

bool ds_hstring::m_ends_with( const dsd_const_string& rdsp_search, bool bo_ignore_case ) const
{
    return m_ends_with(rdsp_search.strc_ptr, rdsp_search.inc_length, bo_ignore_case);
}
#endif

/**
 * ds_hstring::m_find_first_of
 *
 * @param[in]   const char  chr_sign_list
 * @param[in]   bool        bo_ignore_case      ignore case (default is false)
*/
int ds_hstring::m_find_first_of( const dsd_const_string& rdsp_sign_list, bool bo_ignore_case, int in_offset) const
{
    // initialize some variables:
    int  in_len_signs  = (int)rdsp_sign_list.inc_length;
 
    if ( bo_ignore_case == false ) {
        for ( int in_pos = in_offset; in_pos < in_len_data; in_pos++ ) {
            for ( int in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
                if ( m_cmp_mem(&ach_data[in_pos], &rdsp_sign_list.strc_ptr[in_sign], 1) ) {
                    return in_pos;
                }
            }
        }
    } else {
        for ( int in_pos = in_offset; in_pos < in_len_data; in_pos++ ) {
            for ( int in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
                if ( m_cmp_ic(&ach_data[in_pos], &rdsp_sign_list.strc_ptr[in_sign], 1) == 0 ) {
                    return in_pos;
                }
            }
        }
    }
    return -1;
} // end of ds_hstring::m_find_first_of


/**
 * ds_hstring::m_find_first_not_of
 *
 * @param[in]   const char  chr_sign_list
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
*/
int ds_hstring::m_find_first_not_of( const dsd_const_string& rdsp_sign_list, bool bo_ignore_case, int in_offset ) const
{
    // initialize some variables:
    int  in_len_signs  = (int)rdsp_sign_list.inc_length;
    int  in_sign;
    int  in_pos;

    if ( in_offset < 0 ) {
        return -1;
    }

    if ( bo_ignore_case == false ) {
        for ( in_pos = in_offset; in_pos < in_len_data; in_pos++ ) {
            for ( in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
                if ( m_cmp_mem(&ach_data[in_pos], &rdsp_sign_list.strc_ptr[in_sign], 1) ) {
                    goto LBL_FOUND1;
                }
            }
            return (int)in_pos;
LBL_FOUND1:
            ;
        }
    } else {
        for ( in_pos = in_offset; in_pos < in_len_data; in_pos++ ) {
            for ( in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
                if ( m_cmp_ic(&ach_data[in_pos], &rdsp_sign_list.strc_ptr[in_sign], 1) == 0 ) {
                    goto LBL_FOUND2;
                }
            }
            return (int)in_pos;
LBL_FOUND2:
            ;
        }
    }
    return -1;
} // end of ds_hstring::m_find_first_not_of

#if 0
bool ds_hstring::m_equals( const dsd_const_string& rdsp_string, bool bo_ignore_case ) const
{
    return m_equals( rdsp_string.strc_ptr, rdsp_string.inc_length, bo_ignore_case );
}
#endif

bool ds_hstring::m_equals( const dsd_const_string& rdsp_string ) const
{
    return this->m_const_str().m_equals(rdsp_string);
}

bool ds_hstring::m_equals_ic( const dsd_const_string& rdsp_string ) const
{
    return this->m_const_str().m_equals_ic(rdsp_string);
}

bool ds_hstring::m_equals( const char* ach_search, int in_len_search ) const
{
    return this->m_equals(dsd_const_string(ach_search, in_len_search));
}

bool ds_hstring::m_equals_ic( const char* ach_search, int in_len_search ) const
{
    return this->m_equals_ic(dsd_const_string(ach_search, in_len_search));
}

#if 0
/**
 * function ds_hstring::m_equals
 *
 * @param[in]   char*   ach_search          string to search for
 * @param[in]   int     in_len_search       length of search string
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 *
 * @return      bool
*/
bool ds_hstring::m_equals( const char* ach_search, int in_len_search,
                          bool bo_ignore_case ) const
{
    if (    ( in_len_search == in_len_data )
         && ( m_search(ach_search, in_len_search, bo_ignore_case) == 0 ) ) {
        return true;
    } else {
        return false;
    }
} // end of ds_hstring::m_equals
#endif

#if 0
bool ds_hstring::m_equals( const ds_hstring& rdsp_string, bool bo_ignore_case ) const
{
    return m_equals( rdsp_string.m_get_ptr(), rdsp_string.m_get_len(), bo_ignore_case );
}
#endif

bool ds_hstring::m_equals( const ds_hstring& rdsp_string ) const
{
    return this->m_equals(rdsp_string.m_const_str());
}

bool ds_hstring::m_equals_ic( const ds_hstring& rdsp_string ) const
{
    return this->m_equals_ic(rdsp_string.m_const_str());
}

/**
 * function ds_hstring::m_equals_zeroterm
 *
 * @param[in]   char*   ach_zero            string to search for
 * @param[in]   bool    bo_ignore_case      ignore case (default is false)
 *
 * @return      bool
*/
bool ds_hstring::m_equals_zeroterm( const char* ach_zero ) const
{
    if ( ach_zero == NULL )
        return false;
    return this->m_equals(dsd_const_string(ach_zero, strlen(ach_zero)));
} // end of ds_hstring::m_equals

bool ds_hstring::m_equals_ic_zeroterm( const char* ach_zero ) const
{
    if ( ach_zero == NULL )
        return false;
    return this->m_equals_ic(dsd_const_string(ach_zero, strlen(ach_zero)));
}

/**
 * function ds_hstring::m_erase
 *
 * remove in_signs signs starting at in_offset from memory
 *
 * @param[in]   int  in_offset      position where to remove a sign
 * @param[in]   int  in_signs       number of signs to remove
 *
 * @return      bool                true  = all signs are removed
 *                                  false = not all signs are removed
 *                                          or error occured
*/
bool ds_hstring::m_erase( int in_offset, int in_signs )
{
    // check input data:
    if (    in_offset < 0 
         || in_signs  < 1
         || in_offset > in_len_data ) {
        return false;
    }

    // remove signs:
    for ( int in_pos = in_offset; ((in_pos + in_signs) < in_len_data); in_pos++ ) {
        ach_data[in_pos] = ach_data[in_pos + in_signs];
    }

    // change length information:
    in_len_data -= in_signs;

    // zero terminations:
    ach_data[in_len_data] = 0;

    return true;  
} // end of ds_hstring::m_erase

/**
 * function ds_hstring::m_insert
 *
 * @param[in]   int   in_offset     position where to remove a sign
 * @param[in]   char* ach_zero      zero terminated string to insert
*/
void ds_hstring::m_insert_zeroterm( int in_offset, const char* ach_zero )
{
    if ( ach_zero == NULL ) {
        return;
    }
    return m_insert( in_offset, ach_zero, (int)strlen(ach_zero) );
} // end of ds_hstring::m_insert

/**
 * function ds_hstring::m_insert
 *
 * @param[in]   int   in_offset     position where to remove a sign
 * @param[in]   char* ach_zero      zero terminated string to insert
*/
void ds_hstring::m_insert_const_str( int in_offset, const dsd_const_string& rdsp_insert )
{
    return m_insert( in_offset, rdsp_insert.m_get_start(), rdsp_insert.m_get_len() );
} // end of ds_hstring::m_insert

void ds_hstring::m_insert( int in_offset, const ds_hstring& rdsp_insert )
{
    return m_insert( in_offset, rdsp_insert.m_get_ptr(), rdsp_insert.m_get_len() );
}

/**
 * function ds_hstring::m_insert
 *
 * @param[in]   int   in_offset     position where to remove a sign
 * @param[in]   char* ach_insert    string to insert
 * @param[in]   int   in_len        length of ach_insert
*/
void ds_hstring::m_insert( int in_offset, const char* ach_insert, int in_len )
{
    // initialize some variables:
    int in_old_len = 0;             // old length
    int in_pos     = 0;             // working position in data

    // check input data:
    if (    ach_insert == NULL || in_len < 1
         || in_offset < 0 || in_offset > in_len_data ) {
        return;
    }

    // evaluate new length:
    in_old_len   = in_len_data;
    in_len_data += in_len;

    if ( in_len_data >= in_memory_size ) {
        // enlarge memory:
        m_enlarge_memory( in_len_data + 1, in_old_len );
    }

    // move data:
    for ( in_pos = in_old_len - 1; in_pos >= in_offset; in_pos-- ) {
        ach_data[in_pos + in_len] = ach_data[in_pos];
    }

    // insert data:
    for ( in_pos = in_offset; in_pos < in_offset + in_len; in_pos++ ) {
        ach_data[in_pos] = ach_insert[in_pos - in_offset];
    }

    // zero termination:
    ach_data[in_len_data] = 0;

    return;
} // end of ds_hstring::m_insert


/**
 * function ds_hstring::m_free_memory
 *
 * delete memory!
*/
void ds_hstring::m_free_memory()
{
    if ( in_memory_size > 0 ) {
        m_free( ach_data, in_memory_size );
        ach_data = NULL;
    }
    if ( ach_data != &rch_buffer[0] ) {
        in_memory_size = 0;
    }
    in_len_data = 0;
} // end of ds_hstring::m_free_memory


/**
 * function ds_hstring::m_get_ptr
 *
 * @return char*        pointer to saved data
*/
const char* ds_hstring::m_get_ptr() const 
{
    return ach_data;
} // end of ds_hstring::m_get_ptr()

#if 0
/**
 * function ds_hstring::m_get_ptr
 *
 * @return char*        pointer to saved data
*/
char* ds_hstring::m_get_ptr() 
{
    return ach_data;
} // end of ds_hstring::m_get_ptr()
#endif

/**
 * function ds_hstring::m_get_len
 *
 * @return int          length of saved data
*/
int ds_hstring::m_get_len() const
{
    return in_len_data;
} // end of ds_hstring::m_get_len


/**
 * function ds_hstring::m_to_int
 *
 * @param[in]   int*    ain_out     output integer
 * @param[in]   int     in_offset   start converting at this position
 *                                  default value is 0
 * @param[in]   int     in_base     base of converting
 *                                  default value is 10
 *
 * @return      bool                false if converting failed
 *                                  true otherwise
*/
bool ds_hstring::m_to_int( int* ain_out, int in_offset, int in_base ) const
{
    // initialize some variables:
    errno  = 0;
    bool  bo_ret;

    // check input data:
    if (    in_offset < 0
         || in_offset >= in_len_data 
         || ain_out == NULL ) {
        return false;
    }

    if ( in_base == 10 ) {
        *ain_out = atoi( &ach_data[in_offset] );
        if ( errno != 0 ) {
            return false;
        }
    } else {
        long int il_temp;
        bo_ret = m_to_long( &il_temp, in_offset, in_base );
        if (    il_temp > INT_MAX
             || il_temp < INT_MIN ) {
            return false;
        }
        *ain_out = (int)il_temp;
        return bo_ret;
    }
   
    return true;
} // end of ds_hstring::m_to_int


/**
 * function ds_hstring::m_to_long
 *
 * @param[in]   long int*   ail_out     output long long
 * @param[in]   int         in_offset   start converting at this position
 *                                      default value is 0
 * @param[in]   int         in_base     base of converting
 *                                      default value is 10
 *
 * @return      bool                    false if converting failed
 *                                      true otherwise
*/
bool ds_hstring::m_to_long( long int* ail_out, int in_offset, int in_base ) const
{
    // initialize some variables:
    errno = 0;
    char* ach_endptr;

    // check input data:
    if (    in_offset < 0
         || in_offset >= in_len_data 
         || ail_out == NULL ) {
        return false;
    }

    *ail_out = strtol( &ach_data[in_offset], &ach_endptr, in_base );
    if ( errno != 0 ) {
        return false;
    }
   
    return true;
} // end of ds_hstring::m_to_long


/**
 * function ds_hstring::m_conv_int
 * convert this string to a int
 *
 * ATTENTION:
 *   will return false if some invalid signs are found
 *   (80p will return false, 801 will return true)
 *
 * @param[in]   int*        ail_out     output int
 * @param[in]   int         in_base     base of converting
 *                                      default value is 10
 *
 * @return      bool                    false if converting failed
 *                                      true otherwise
*/
bool ds_hstring::m_conv_int( int* ain_out, int in_base )
{
    long int ill_temp;
    bool     bol_ret;

    bol_ret = m_conv_long( &ill_temp, in_base );
    if ( bol_ret == true ) {
        *ain_out = (int)ill_temp;
    }
    return bol_ret;
} // end of ds_hstring::m_conv_int


/**
 * function ds_hstring::m_conv_long
 * convert this string to a long int
 *
 * ATTENTION:
 *   will return false if some invalid signs are found
 *   (80p will return false, 801 will return true)
 *
 * @param[in]   long int*   ail_out     output long
 * @param[in]   int         in_base     base of converting
 *                                      default value is 10
 *
 * @return      bool                    false if converting failed
 *                                      true otherwise
*/
bool ds_hstring::m_conv_long( long int* ail_out, int in_base )
{
    // initialize some variables:
    errno = 0;
    char* ach_endptr;

    // check input data:
    if ( ail_out == NULL ) {
        return false;
    }

    *ail_out = strtol( ach_data, &ach_endptr, in_base );
    if (    errno != 0
         || ach_endptr != (ach_data + in_len_data) ) {
        return false;
    }   
    return true;
} // end of ds_hstring::m_conv_long


/**
 * function ds_hstring::m_to_longlong
 *
 * @param[in]   long long*  aill_out    output long long
 * @param[in]   int         in_offset   start converting at this position
 *                                      default value is 0
 * @param[in]   int         in_base     base of converting
 *                                      default value is 10
 *
 * @return      bool                    false if converting failed
 *                                      true otherwise
*/
bool ds_hstring::m_to_longlong( long long int* aill_out, int in_offset, int in_base ) const
{
    // initialize some variables:
    errno = 0;
    const char* ach_endptr;

    // check input data:
    if (    in_offset < 0
         || in_offset >= in_len_data 
         || aill_out == NULL ) {
        return false;
    }

    *aill_out = m_str_to_ll( &ach_data[in_offset], &ach_endptr, in_base );
    if ( errno != 0 ) {
        return false;
    }
   
    return true;
} // end of ds_hstring::m_to_longlong

/**
 * function ds_hstring::m_replace
 *
 * @param[in]   const char* ach_old         zero terminated string that should be replaced
 * @param[in]   const char* ach_new         zero terminated string that should be inserted
 * @param[in]   bool        bo_ignore_case  ignore case when search for ach_old
 *                                          default value is false
 * @param[in]   int         in_offset       start replacing at offset
 *                                          default value is 0
*/
void ds_hstring::m_replace_char( char chp_old, char chp_new, int inp_offset )
{
	return m_replace_same_length(&chp_old, &chp_new, 1, false, inp_offset);
} // end of ds_hstring::m_replace

/**
 * function ds_hstring::m_replace
 *
 * @param[in]   const char* ach_old         string that should be replaced
 * @param[in]   int         in_len_old      length of ach_old
 * @param[in]   const char* ach_new         string that should be inserted
 * @param[in]   int         in_len_new      length of ach_new
 * @param[in]   bool        bo_ignore_case  ignore case when search for ach_old
 *                                          default value is false
 * @param[in]   int         in_offset       start replacing at offset
 *                                          default value is 0
*/
void ds_hstring::m_replace_same_length( const char* ach_old, const char* ach_new, 
					       int in_len_old_new,
                           bool bo_ignore_case, int in_offset )
{
    // intialize some variables:
    int in_found = 0;           // position where ach_old is found

    // check input data:
    if (    ach_old == NULL || in_len_old_new < 1 
         || ach_new == NULL
         || in_offset < 0   || in_offset  > in_len_data ) {
        return;
    }

    // search for ach_old:
    in_found = m_search( in_offset, dsd_const_string(ach_old, in_len_old_new), bo_ignore_case  );

    while ( in_found >= 0 ) {
		memcpy(&ach_data[in_found], ach_new, in_len_old_new);
        // change working position:
        in_found += in_len_old_new;
        // search for ach_old once again:
        in_found = m_search( in_found, dsd_const_string(ach_old, in_len_old_new), bo_ignore_case );
    }
    return;
} // end of ds_hstring::m_replace

/**
 * function ds_hstring::m_replace
 *
 * @param[in]   const char* ach_old         zero terminated string that should be replaced
 * @param[in]   const char* ach_new         zero terminated string that should be inserted
 * @param[in]   bool        bo_ignore_case  ignore case when search for ach_old
 *                                          default value is false
 * @param[in]   int         in_offset       start replacing at offset
 *                                          default value is 0
*/
void ds_hstring::m_replace( const dsd_const_string& rdsp_old, const dsd_const_string& rdsp_new,
                           bool bo_ignore_case, int in_offset )
{
    return m_replace( rdsp_old.m_get_start(), (int)rdsp_old.m_get_len(),
                      rdsp_new.m_get_start(), (int)rdsp_new.m_get_len(),
                      bo_ignore_case, in_offset     );
} // end of ds_hstring::m_replace

void ds_hstring::m_replace( const dsd_const_string& rdsp_old, const dsd_const_string& rdsp_new )
{
    return m_replace( rdsp_old.m_get_start(), (int)rdsp_old.m_get_len(),
                      rdsp_new.m_get_start(), (int)rdsp_new.m_get_len(),
                      false, 0 );
}

void ds_hstring::m_replace( const dsd_const_string& rdsp_old, const dsd_const_string& rdsp_new,
                          int in_offset )
{
    return m_replace( rdsp_old.m_get_start(), (int)rdsp_old.m_get_len(),
                      rdsp_new.m_get_start(), (int)rdsp_new.m_get_len(),
                      false, in_offset );
}

void ds_hstring::m_replace_ic( const dsd_const_string& rdsp_old, const dsd_const_string& rdsp_new )
{
    return m_replace( rdsp_old.m_get_start(), (int)rdsp_old.m_get_len(),
                      rdsp_new.m_get_start(), (int)rdsp_new.m_get_len(),
                      true, 0 );
}

/**
 * function ds_hstring::m_replace
 *
 * @param[in]   const char* ach_old         string that should be replaced
 * @param[in]   int         in_len_old      length of ach_old
 * @param[in]   const char* ach_new         string that should be inserted
 * @param[in]   int         in_len_new      length of ach_new
 * @param[in]   bool        bo_ignore_case  ignore case when search for ach_old
 *                                          default value is false
 * @param[in]   int         in_offset       start replacing at offset
 *                                          default value is 0
*/
void ds_hstring::m_replace( const char* ach_old, int in_len_old,
                           const char* ach_new, int in_len_new,
                           bool bo_ignore_case, int in_offset )
{
	if( in_len_old == in_len_new )
		return this->m_replace_same_length(ach_old, ach_new, in_len_old, bo_ignore_case, in_offset);

    // intialize some variables:
    int in_found = 0;           // position where ach_old is found

    // check input data:
    if (    ach_old == NULL || in_len_old < 1 
         || ach_new == NULL || in_len_new < 0
         || in_offset < 0   || in_offset  > in_len_data ) {
        return;
    }

    if(bo_ignore_case) {
        // search for ach_old:
        in_found = m_search_ic( in_offset, dsd_const_string(ach_old, in_len_old)  );

        while ( in_found > -1 ) {
            // delete ach_old at found position:
            m_erase( in_found, in_len_old );

            // insert ach_new:
            m_insert( in_found, ach_new, in_len_new );
            
            // change working position:
            in_found += in_len_new;
            // search for ach_old once again:
            in_found = m_search_ic( in_found, dsd_const_string(ach_old, in_len_old)  );
        }
    }
    else {
        // search for ach_old:
        in_found = m_search( in_offset, dsd_const_string(ach_old, in_len_old) );

        while ( in_found > -1 ) {
            // delete ach_old at found position:
            m_erase( in_found, in_len_old );

            // insert ach_new:
            m_insert( in_found, ach_new, in_len_new );
            
            // change working position:
            in_found += in_len_new;
            // search for ach_old once again:
            in_found = m_search( in_found, dsd_const_string(ach_old, in_len_old) );
        }
    }
    return;
} // end of ds_hstring::m_replace

dsd_const_string ds_hstring::m_substring(int inp_start, int inp_end) const
{
    return dsd_const_string(this->m_get_ptr()+inp_start, inp_end-inp_start);
}

dsd_const_string ds_hstring::m_substring(int inp_start) const
{
    return this->m_substring(inp_start, this->m_get_len());
}

/**
 * function ds_hstring::m_substr
 *
 * @param[in]   int         in_offset
 * @param[in]   int         in_signs
 *                          default = -1 (means until end)
 * @return      ds_hstring
*/
ds_hstring ds_hstring::m_substr( int in_offset, int in_signs ) const
{
    // initialize some variables:
    ds_hstring ds_ret( ads_wsp_helper );

    // check input data:
    if ( in_offset < 0 || in_offset >= in_len_data ) {
        return ds_ret;
    }
    if ( in_signs == -1 || in_signs > in_len_data - in_offset ) {
        in_signs = in_len_data - in_offset;
    }
    if ( in_signs < 1 ) {
        return ds_ret;
    }

    ds_ret.m_write( ach_data + in_offset, in_signs, false );
    return ds_ret;
} // end of ds_hstring::m_substr


/**
 * function ds_hstring::m_trim
 * remove given signs until another signs is found from string
 *
 * @param[in]   const char  chr_sign_list[]     list of signs to remove
 * @param[in]   bool        bo_forward          trim signs from beginning
 * @param[in]   bool        bo_backward         trim signs from end
*/
bool ds_hstring::m_trim( const dsd_const_string& rdsp_sign_list,
                         bool bo_forward, bool bo_backward )
{
    // initialize some variables:
    int  in_len_signs  = (int)rdsp_sign_list.inc_length;
    bool bo_sign_found;
    int  in_sign;

    if ( bo_forward == true ) {
        do {
            bo_sign_found = false;
            for ( in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
                if ( ach_data[0] == rdsp_sign_list.strc_ptr[in_sign] ) {
                    m_erase( 0, 1 );
                    bo_sign_found = true;
                    break;
                }
            }
        } while ( bo_sign_found == true );
    }

    if ( bo_backward == true ) {
        do {
            bo_sign_found = false;
            for ( in_sign = 0; in_sign < in_len_signs; in_sign++ ) {
                if ( ach_data[in_len_data - 1] == rdsp_sign_list.strc_ptr[in_sign] ) {
                    m_erase( in_len_data - 1, 1 );
                    bo_sign_found = true;
                    break;
                }
            }
        } while ( bo_sign_found == true );
    }

    return ( bo_forward || bo_backward );
} // end of ds_hstring::m_trim


/**
 * function ds_hstring::m_enlarge_memory
 *
 * @param[in]   int in_enlarge      enlarge to size value
 * @param[in]   int in_copy         number of byte to copy from old buffer
*/
bool ds_hstring::m_enlarge_memory( int in_enlarge, int in_copy ) {
    // initialize some variables:
    int in_old_size = in_memory_size;
    if(in_enlarge <= in_old_size) {
        return true;
    }
    int in_new_size1 = in_enlarge;
    int in_new_size2 = in_old_size * 2;
    int inl_new_size = in_new_size2;
    if(inl_new_size < in_new_size1) {
        inl_new_size = in_new_size1; 
    }

    in_memory_size = inl_new_size;
    //this->ads_wsp_helper->m_logf(ied_sdh_log_warning, "m_enlarge_memory: enlarge=%d old=%d new1=%d new2=%d",
    //    in_enlarge, in_old_size, in_new_size1, in_new_size2);
    
    // get new memory:
    char* ach_temp = m_get_mem( in_memory_size );
	if(ach_temp == NULL)
		return false;

    if ( in_old_size > 0 ) {
        // copy data:
        memcpy( ach_temp, ach_data, in_copy );
        // free old memory:
        m_free( ach_data, in_old_size );
    }

    // set pointer to new memory:
    ach_data = ach_temp;
	return true;
} // end of ds_hstring::m_enlarge_memory


/**
 * function ds_hstring::m_writef
 * 
 * append data in printf style
 *
 * @param[in]   const char* ach_format
 *
 * @return number of bytes written or -1 if an encoding error has occurred.
*/
int ds_hstring::m_writef( HL_FORMAT_STRING const char* ach_format, ...  )
{
    // evalute free memory:
    int in_free_mem = in_memory_size - in_len_data;
    if ( in_free_mem <= 0 ) {
        m_enlarge_memory( in_memory_size<<1, in_len_data );
        in_free_mem = in_memory_size - in_len_data;
    }
    for ( ; ; ) {
        va_list args;                   // argument list
        va_start( args, ach_format );
        // try to print in our memory (function will give us needed mem size)
        errno = 0;
        int in_used_size = vsnprintf( &ach_data[in_len_data], in_free_mem, ach_format, args );
        int in_error = errno;
        va_end( args );

        // some versions of vsnprintf return -1 as a generic error and and put exact information
        // about the error in errno (from errno.h).
        // other versions use -1 as encoding error and numbers >= buffer size as "number of characters
        // that would be written if buffer were sufficiently large" (needed buffer size).
        if (in_used_size < 0 && !(in_error == ENOMEM || in_error == ERANGE)) {
            this->ads_wsp_helper->m_log(ied_sdh_log_warning, "ds_hstring::m_writef: encoding error");
            return in_used_size;
        }
        if (in_used_size >= in_free_mem || in_used_size < 0) {
            m_enlarge_memory( ((in_used_size > (in_memory_size<<1)) ? in_used_size : in_memory_size<<1), in_len_data );
            in_free_mem = in_memory_size - in_len_data;
            continue;
        }
        // copy was successful
        in_len_data += in_used_size;
        return in_used_size;
    }
} // end of ds_hstring::m_writef


/**
 * function ds_hstring::m_write_nhasn
 * write int as nhasn
 *
 * @param[in]   int     in_input
*/
void ds_hstring::m_write_nhasn( int in_input )
{
    // initialize some variables:
    int            in_bytenum  = m_count_nhasn_len( in_input );
    int            in_work_len = in_bytenum;
    unsigned char* ach_work    = (unsigned char*)&ach_data[in_len_data];

	int inl_old_length = in_len_data;
    in_len_data += in_bytenum;
    if ( in_len_data >= in_memory_size ) {
        m_enlarge_memory( in_len_data + 1, inl_old_length );
    }
                
    for ( int in_1 = 0; (in_1 < in_bytenum && in_work_len) ; in_1++ ) { 
        *ach_work = (unsigned char)((in_input >> ((in_bytenum - in_1 - 1)*7)) & 0x0000007F);
        if (in_1 < in_bytenum - 1) {
            *ach_work |= 0x80;
        }
        in_work_len--;
        ach_work++;
    }
    ach_data[in_len_data] = 0;
    return;
} // end of ds_hstring::m_write_nhasn


/**
 * function ds_hstring::m_write_lower
 * write input in lower case
 *
 * @param[in]   const char* ach_input
 * @param[in]   int         in_len_input
 * @param[in]   bool        bo_append
*/
void ds_hstring::m_write_lower( const char* ach_input, int in_len_input, bool bo_append )
{
    // check input data:
    if ( ach_input == NULL || in_len_input < 0 ) {
        return;
    }

    if ( bo_append ) {
        int in_old_length = in_len_data;
        in_len_data += in_len_input;
        // check if memory is large enough to put data in:
        if(in_len_data >= in_memory_size) {
            // enlarge memory:
            m_enlarge_memory( in_len_data + 1, in_old_length );
        }
        m_copy_lower( (ach_data + in_old_length), ach_input, in_len_input );
    } else {
        // check if memory is large enough to put data in:
        if(in_len_data >= in_memory_size) {
            // enlarge memory:
            m_enlarge_memory( in_len_input + 1, 0 );
        }
        // check if memory is large enough to put data in:
        m_copy_lower( ach_data, ach_input, in_len_input );
        in_len_data = in_len_input;
    }
    ach_data[in_len_data] = 0;
} // end of d_hstring::m_write_lower

void ds_hstring::m_write_lower( const char* ach_input, int in_len_input ) {
    return m_write_lower(ach_input, in_len_input, true);
}

#if 0
/**
 * function ds_hstring::m_write_lower
 * write input in lower case
 *
 * @param[in]   const char* ach_zero
 * @param[in]   bool        bo_append
*/
void ds_hstring::m_write_lower_zeroterm( const char* ach_zero, bool bo_append )
{
    if ( ach_zero == NULL ) {
        return;
    }
    return m_write_lower( ach_zero, (int)strlen(ach_zero), bo_append );
} // end of ds_hstring::m_write_lower
#endif

/**
 * function ds_hstring::m_to_lower
 * convert string content to lower case
*/
void ds_hstring::m_to_lower()
{
    // initialize some variables:
    int inl_pos;
    // TODO: Use Unicode library
    for ( inl_pos = 0; inl_pos < in_len_data; inl_pos++ ) {
        ach_data[inl_pos] = (char)::m_to_lower(((unsigned char*)ach_data)[inl_pos]);
    }
} // end of ds_hstring::m_to_lower

/**
 * static private function ds_usercma::m_to_b64
 *
 * @param[in]   const char  *achp_in        input data
 * @param[in]   int         inp_ilen        input length
 * @param[in]   char        *achp_out       pointer to output buffer
 * @param[in]   int         inp_olen        length of output buffer
 * @return      int
*/
int ds_hstring::m_to_b64_internal( const char *achp_in, int inp_ilen,
                           char *achp_out, int inp_olen,
						   const char chrs_b64_encoder[64+1])
{
	// initialize some variables:
    int inl_bits       = 0;         // number of bits
    int inl_char_count = 0;         // count number of read in chars
    int inl_char;                   // current character
    int inl_pos;                    // working position in input
    int inl_offset = 0;             // working position in output

    // do the encoding:
    for ( inl_pos = 0; inl_pos < inp_ilen; inl_pos++ ) {
        inl_char = (unsigned char)achp_in[inl_pos];

        inl_bits += inl_char;
        inl_char_count++;
        if ( inl_char_count == 3 ) {
            if(inl_offset+4 > inp_olen)
                return -1;
            achp_out[inl_offset++] = chrs_b64_encoder[inl_bits >> 18];
            achp_out[inl_offset++] = chrs_b64_encoder[(inl_bits >> 12) & 0x3f];
            achp_out[inl_offset++] = chrs_b64_encoder[(inl_bits >> 6) & 0x3f];
            achp_out[inl_offset++] = chrs_b64_encoder[inl_bits & 0x3f];
            inl_bits       = 0;
            inl_char_count = 0;
        } else {
            inl_bits <<= 8;
        }
    }

    // fill with "=":
    if ( inl_char_count != 0 ) {
        inl_bits <<= 16 - (8 * inl_char_count);
        if(inl_offset+4 > inp_olen)
            return -1;
        achp_out[inl_offset++] = chrs_b64_encoder[inl_bits >> 18];
        achp_out[inl_offset++] = chrs_b64_encoder[(inl_bits >> 12) & 0x3f];
        if ( inl_char_count == 1 ) {
            achp_out[inl_offset++] = '=';
            achp_out[inl_offset++] = '=';
        } else {
            achp_out[inl_offset++] = chrs_b64_encoder[(inl_bits >> 6) & 0x3f];
            achp_out[inl_offset++] = '=';
        }
    }

    return inl_offset;
}

/**
 * static private function ds_usercma::m_to_b64
 *
 * @param[in]   const char  *achp_in        input data
 * @param[in]   int         inp_ilen        input length
 * @param[in]   char        *achp_out       pointer to output buffer
 * @param[in]   int         inp_olen        length of output buffer
 * @return      int
*/
int ds_hstring::m_to_b64( const char *achp_in, int inp_ilen,
                           char *achp_out, int inp_olen )
{
	return m_to_b64_internal(achp_in, inp_ilen, achp_out, inp_olen, CHRS_B64);
} // end of ds_hstring::m_to_b64

/**
 * static private function ds_hstring::m_to_rfc3548
 *
 * @param[in]   const char  *achp_in        input data
 * @param[in]   int         inp_ilen        input length
 * @param[in]   char        *achp_out       pointer to output buffer
 * @param[in]   int         inp_olen        length of output buffer
 * @return      int
*/
int ds_hstring::m_to_rfc3548( const char *achp_in, int inp_ilen,
                           char *achp_out, int inp_olen )
{
	return m_to_b64_internal(achp_in, inp_ilen, achp_out, inp_olen, CHRS_RFC3548);
} // end of ds_hstring::m_to_b64

/**
 * function ds_hstring::m_write_b64
 * write string as base64
 *
 * @param[in]   const char* ach_input
 * @param[in]   int         in_len_input
*/
bool ds_hstring::m_write_b64( const char* ach_input, int in_len_input )
{
	int inl_len_padded = ((in_len_input+2)/3)*3;
	int in_len_out = (inl_len_padded*4)/3;
	int in_len_needed = this->in_len_data + in_len_out;
	if(!this->m_ensure_size(in_len_needed + 1, true))
		return false;
	int inl_free_mem = this->in_memory_size - this->in_len_data;
	int inl_res = m_to_b64(ach_input, in_len_input, &this->ach_data[this->in_len_data], inl_free_mem-1);
	if(inl_res < 0)
		return false;
	this->in_len_data += inl_res;
    ach_data[in_len_data] = 0;
	return true;
} // end of ds_hstring::m_write_b64


/**
 * function ds_hstring::m_write_rfc3548
 * write string as rfc3548 (compare to b64)
 *
 * @param[in]   const char* ach_input
 * @param[in]   int         in_len_input
*/
bool ds_hstring::m_write_rfc3548( const char* ach_input, int in_len_input )
{
    int inl_len_padded = ((in_len_input+2)/3)*3;
	int in_len_out = (inl_len_padded*4)/3;
	int in_len_needed = this->in_len_data + in_len_out;
	if(!this->m_ensure_size(in_len_needed + 1, true))
		return false;
	int inl_free_mem = this->in_memory_size - this->in_len_data;
	int inl_res = m_to_rfc3548(ach_input, in_len_input, &this->ach_data[this->in_len_data], inl_free_mem-1);
	if(inl_res < 0)
		return false;
	this->in_len_data += inl_res;
    ach_data[in_len_data] = 0;
	return true;
} // end of ds_hstring::m_write_rfc3548

/**
 * static private function ds_usercma::m_from_b64
 *
 * @param[in]   const char  *achp_in        input data
 * @param[in]   int         inp_ilen        input length
 * @param[in]   char        *achp_out       pointer to output buffer
 * @param[in]   int         inp_olen        length of output buffer
 * @return      int
*/
int ds_hstring::m_from_b64_internal(
	const char *achp_in, int inp_ilen, char *achp_out, int inp_olen,
	const char chrp_in_alphabet[256], const char chrp_b64_decoder[256])
{
	// initialize some variables:
    int  inl_bits       = 0;        // number of bits
    int  inl_char_count = 0;        // count number of read in chars
    int  inl_pos;                   // working position in input
    int  inl_offset     = 0;        // working position in output
    
    // do the decoding:
	int inl_num_eq = 0;
    for ( inl_pos = 0; inl_pos < inp_ilen; inl_pos++ ) {
        unsigned char inl_char = (unsigned char)achp_in[inl_pos];

        if ( inl_char == '=' ) {
            inl_num_eq = 1;
			while(++inl_pos < inp_ilen) {
				if(achp_in[inl_pos] != '=')
					return -1;
				inl_num_eq++;
			}
            break;
		}

        if ( !chrp_in_alphabet[inl_char] ) {
            return -1;
        }
        
        inl_bits += chrp_b64_decoder[inl_char];
        inl_char_count++;
        if ( inl_char_count == 4 ) {
            if ( inl_offset+3 > inp_olen )
                return -1;
            achp_out[inl_offset++] = (char)(inl_bits >> 16);
            achp_out[inl_offset++] = (char)((inl_bits >> 8) & 0xff);
            achp_out[inl_offset++] = (char)(inl_bits & 0xff);
            inl_bits = 0;
            inl_char_count = 0;
        } else {
            inl_bits <<= 6;
        }
    }

	switch (inl_char_count) {
      case 1:
		  if(inl_num_eq == 0)
			break;
		  if(inl_num_eq != 0)
			return -1;
          break;
      case 2:
        if ( inl_offset+1 > inp_olen )
            return -1;
        achp_out[inl_offset++] = (char)(inl_bits >> 10);
		if(inl_num_eq == 0)
			break;
		if(inl_num_eq != 2)
			return -1;
        break;
      case 3:
        if ( inl_offset+2 > inp_olen )
            return -1;
        achp_out[inl_offset++] = (char)(inl_bits >> 16);
        achp_out[inl_offset++] = (char)((inl_bits >> 8) & 0xff);
		if(inl_num_eq == 0)
			break;
		if(inl_num_eq != 1)
			return -1;
        break;
    }
    return inl_offset;
}

/**
 * static private function m_from_b64
 *
 * @param[in]   const char  *achp_in        input data
 * @param[in]   int         inp_ilen        input length
 * @param[in]   char        *achp_out       pointer to output buffer
 * @param[in]   int         inp_olen        length of output buffer
 * @return      int
*/
int ds_hstring::m_from_b64( const char *achp_in, int inp_ilen,
                            char *achp_out, int inp_olen )
{
	return m_from_b64_internal(achp_in, inp_ilen, achp_out, inp_olen,
		chrs_b64_in_alphabet, chrs_b64_decoder);
} // end of ds_hstring::m_from_b64

/**
 * static private function ds_usercma::m_from_rfc3548
 *
 * @param[in]   const char  *achp_in        input data
 * @param[in]   int         inp_ilen        input length
 * @param[in]   char        *achp_out       pointer to output buffer
 * @param[in]   int         inp_olen        length of output buffer
 * @return      int
*/
int ds_hstring::m_from_rfc3548( const char *achp_in, int inp_ilen,
                            char *achp_out, int inp_olen )
{
	return m_from_b64_internal(achp_in, inp_ilen, achp_out, inp_olen,
		chrs_rfc3548_in_alphabet, chrs_rfc3548_decoder);
} // end of ds_hstring::m_from_rfc3548

/**
 * function ds_hstring::m_from_b64
 * rewrite string from base64
 *
 * @param[in]   const char* ach_input
 * @param[in]   int         in_len_input
*/
bool ds_hstring::m_from_b64( const char* ach_input, int in_len_input )
{
	int inl_len_padded = ((in_len_input+3)/4)*4;
	int in_len_out = ((inl_len_padded * 3)/4);
	int in_len_needed = this->in_len_data + in_len_out;
	if(!this->m_ensure_size(in_len_needed + 1, true))
		return false;
	int inl_free_mem = this->in_memory_size - this->in_len_data;
	int inl_res = m_from_b64(ach_input, in_len_input, &this->ach_data[this->in_len_data], inl_free_mem-1);
	if(inl_res < 0)
		return false;
	this->in_len_data += inl_res;
    ach_data[in_len_data] = 0;
    return true;
} // end of ds_hstring::m_from_b64


/**
 * function ds_hstring::m_from_rfc3548 (base64 URL)
 * rewrite string from rfc3548
 *
 * @param[in]   const char* ach_input
 * @param[in]   int         in_len_input
*/
bool ds_hstring::m_from_rfc3548( const char* ach_input, int in_len_input )
{
    int inl_len_padded = ((in_len_input+3)/4)*4;
	int in_len_out = ((inl_len_padded * 3)/4);
	int in_len_needed = this->in_len_data + in_len_out;
	if(!this->m_ensure_size(in_len_needed + 1, true))
		return false;
	int inl_free_mem = this->in_memory_size - this->in_len_data;
	int inl_res = m_from_rfc3548(ach_input, in_len_input, &this->ach_data[this->in_len_data], inl_free_mem-1);
	if(inl_res < 0)
		return false;
	this->in_len_data += inl_res;
    ach_data[in_len_data] = 0;
    return true;
} // end of ds_hstring::m_from_rfc3548


/**
 * function ds_hstring::m_count_nhasn_len
 * get neede buffer length for in_input in nhasn format
 *
 * @param[in]   int     in_input
 * @return      int                 needed buffer len
 *                                  or error code
*/
int ds_hstring::m_count_nhasn_len( int in_input )
{
    int in_bytenum = 0;

    do {  //get the number of bytes needed for nhasn number encoded
        in_input >>= 7;
        in_bytenum++;
    } while (in_input);

    return in_bytenum;
} // end of ds_hstring::m_count_nhasn_len


/**
 * function ds_hstring::m_copy
 *
 * @param[in]   const ds_hstring& dc_copy
*/
void ds_hstring::m_copy( const ds_hstring& dc_copy )
{
    this->m_free_memory();
    ads_wsp_helper         = dc_copy.ads_wsp_helper;
    in_len_data            = dc_copy.in_len_data;
    in_memory_size         = dc_copy.in_memory_size;
    in_default_memory_size = dc_copy.in_default_memory_size;
    if ( in_memory_size > 0 ) {
        if ( in_memory_size <= HSTR_DEFAULT_MEM_SIZE ) {
            ach_data       = &rch_buffer[0];
            in_memory_size = HSTR_DEFAULT_MEM_SIZE;
        } else {
            ach_data = m_get_mem( in_memory_size );
            if(ach_data == NULL)
                return;
        }
        memcpy( ach_data, dc_copy.ach_data, in_len_data );
        ach_data[in_len_data] = 0;
    } else {
        ach_data = NULL;
    }
} // end of ds_hstring::m_copy


/**
 * function ds_hstring::m_get_mem
 *
 * @param[in]   int in_size
*/
char* ds_hstring::m_get_mem( int in_size )
{
#ifdef NDEBUG
    if ( ads_wsp_helper == NULL ) {
        char* ach_ptr = (char*)malloc(in_size);
        if ( ach_ptr != NULL ) {
            memset( ach_ptr, 0, in_size );
        }
        return ach_ptr;
    } else {
#endif
        return ads_wsp_helper->m_cb_get_memory( in_size, false );
#ifdef NDEBUG
    }
#endif
} // end of ds_hstring::m_get_mem


/**
 * function ds_hstring::m_free
 *
 * @param[in]   char* ach_ptr
 * @param[in]   int in_size
*/
void ds_hstring::m_free( char* ach_ptr, int in_size )
{
    if ( ach_ptr == &rch_buffer[0] ) {
        //memset( rch_buffer, 0, HSTR_DEFAULT_MEM_SIZE );
        return;
    }
#ifdef NDEBUG
    if ( ads_wsp_helper == NULL ) {
        free( ach_ptr );
    } else {
#endif
        ads_wsp_helper->m_cb_free_memory( ach_ptr, in_size );
#ifdef NDEBUG
    }
#endif
} // end of ds_hstring::m_free


/**
 * function ds_hstring::m_copy_lower
 *
 * @param[in]   char*       ach_dest
 * @param[in]   const char* ach_src
 * @param[in]   int in_size
*/
void ds_hstring::m_copy_lower( char* ach_dest, const char* ach_src, int in_size )
{
    // initialize some variables:
    int in_pos = 0;
    // TODO: Use Unicode library
    for ( ; in_pos < in_size; in_pos++ ) {
        ach_dest[in_pos] = (char)::m_to_lower(((const unsigned char*)ach_src)[in_pos]);
    }
} // end of ds_hstring::m_copy_lower


/**
 * function ds_hstring::m_get_cvalue
 * get char value
 *
 * @param[in]   char    ch_in
 * @param[in]   int     in_base
*/
int ds_hstring::m_get_cvalue( char ch_in, int in_base )
{
    // initialize some variables:
    int in_value;

    if ( ch_in < '0' ) {
        return -1;
    }

    if ( '0' <= ch_in && ch_in <= '9' ) {
        in_value = (int)(ch_in - '0');
    } else if ( 'a' <= ch_in && ch_in <= 'z' ) {
        in_value = (int)(ch_in - 'a' + 10);
    } else if ( 'A' <= ch_in && ch_in <= 'Z' ) {
        in_value = (int)(ch_in - 'A' + 10);
    } else {
        return -1;
    }

    if ( in_value >= in_base ) {
        in_value = -1;
    }
    return in_value;
} // end of ds_hstring::m_get_cvalue


/**
 * function ds_hstring::m_str_to_ll
 *
 * @param[in]   const char* ach_ptr
 * @param[in]   char**      aach_endptr
 * @param[in]   int         in_base
 * @return      long long
*/
long long ds_hstring::m_str_to_ll( const char* ach_ptr, const char** aach_endptr, int in_base )
{
    // initialize some variables:
    long long ill_result = 0;
    long long ill_temp;
    bool      bo_negative;
    int       in_value;

    // check incoming data:
    if (    in_base != 0 
         && (in_base < 2 || in_base > 36) ) {
        errno = EINVAL;
        return 0;
    }

    // pass whitespaces:
    while (    *ach_ptr == ' '
            || *ach_ptr == '\t' ) {
        ach_ptr++;
    }

    // check if positiv or negativ:
    if ( *ach_ptr == '-' ) {
        bo_negative = true;
        ach_ptr++;
    } else if ( *ach_ptr == '+' ) {
        bo_negative = false;
        ach_ptr++;
    } else {
        bo_negative = false;
    }

    /*
        get base:
            -> If base is 0, determine the real base based on the beginning on
                the number; octal numbers begin with "0", hexadecimal with "0x",
                and the others are considered octal.
    */
    if ( *ach_ptr == '0' ) {
        if (    ( in_base == 0 || in_base == 16 )
             && ( *(ach_ptr + 1) == 'x' || *(ach_ptr + 1) == 'X' ) ) {
            in_base = 16;
            ach_ptr += 2;
        } else if ( in_base == 0 ) {
            in_base = 8;
        }
    } else if ( in_base == 0 ) {
        in_base = 10;
    }

    if ( bo_negative == false ) {
        // read positive number:
        for ( ; (in_value = m_get_cvalue( *ach_ptr, in_base )) != -1; ach_ptr++ ) {
            ill_temp = in_base * ill_result + in_value;
            // check for overflow:
            if ( ill_temp < ill_result ) {
                errno = ERANGE;
                break;  // -> quit
            }
            ill_result = ill_temp;
        }
    } else {
        // read negative number:
        for ( ; (in_value = m_get_cvalue( *ach_ptr, in_base )) != -1; ach_ptr++ ) {
            ill_temp = in_base * ill_result - in_value;
            // check for overflow:
            if ( ill_temp > ill_result ) {
                errno = ERANGE;
                break;  // -> quit
            }
            ill_result = ill_temp;
        }
    }

    if ( aach_endptr != NULL ) {
        *aach_endptr = (char*)ach_ptr;
    }
    return ill_result;
} // end of ds_hstring::m_str_to_ll
