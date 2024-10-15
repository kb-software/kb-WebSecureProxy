#ifndef DS_HSTRING_H
#define DS_HSTRING_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_hstring                                                            |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   November 2007                                                         |*/
/*|                                                                         |*/
/*| VERSION:                                                                |*/
/*| ========                                                                |*/
/*|   0.9                                                                   |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| includes:                                                               |*/
/*+-------------------------------------------------------------------------+*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <new>
#include <types_defines.h>
#if defined WIN32 || defined WIN64
    #include <windows.h>
#else
#include <string.h>
#endif
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H


/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define HSTR_DEFAULT_MEM_SIZE  128

class ds_wsp_helper;

struct dsd_const_string {
    const char* strc_ptr;
    size_t inc_length;

    static dsd_const_string m_from_zeroterm(const char* strp_text) {
        if(strp_text == NULL)
            return dsd_const_string();
        return dsd_const_string(strp_text, strlen(strp_text));
    }

    static dsd_const_string m_null() {
        return dsd_const_string();
    }

    dsd_const_string()
        : strc_ptr(NULL), inc_length(0)
    {}

    dsd_const_string(const dsd_const_string& rdsp_src)
        : strc_ptr(rdsp_src.strc_ptr), inc_length(rdsp_src.inc_length)
    {}

    dsd_const_string(const char* strp_data, size_t inp_length)
        : strc_ptr(strp_data), inc_length(inp_length)
    {}

    template<size_t SZ_SIZE> dsd_const_string(const char (&chrp_cstring)[SZ_SIZE])
        : strc_ptr(chrp_cstring), inc_length(SZ_SIZE-1)
    {}

	bool m_is_null() const {
		return this->strc_ptr == NULL;
	}

	int m_get_len() const {
        return (int)this->inc_length;
    }

    size_t m_get_size() const {
        return this->inc_length;
    }

    const char* m_get_start() const {
        return this->strc_ptr;
    }

    const char* m_get_ptr() const {
        return this->strc_ptr;
    }

    const char* m_get_end() const {
        return this->strc_ptr + inc_length;
    }

    const char& operator[](int inp_index) const {
        return this->strc_ptr[inp_index];
    }

    dsd_const_string& operator=(const dsd_const_string& rdsp_rhs) {
        new(this) dsd_const_string(rdsp_rhs);
        return *this;
    }

    void m_reset() {
        this->strc_ptr = NULL;
        this->inc_length = 0;
    }
    
    int m_index_of(int inp_pos, const dsd_const_string& rdsp_search) const;
    int m_index_of(const dsd_const_string& rdsp_search) const;
    int m_last_index_of(int inp_pos, const dsd_const_string& rdsp_search) const;
    int m_last_index_of(const dsd_const_string& rdsp_search) const;
    bool m_starts_with(const dsd_const_string& rdsp_search) const;
    bool m_ends_with(const dsd_const_string& rdsp_search) const;
    bool m_equals(const dsd_const_string& rdsp_other) const;
    bool m_equals(dsd_unicode_string& rdsp_other) const;
    int m_compare(const dsd_const_string& rdsp_other) const;

    int m_index_of_ic(const dsd_const_string& rdsp_search) const;
    int m_last_index_of_ic(const dsd_const_string& rdsp_search) const;
    bool m_starts_with_ic(const dsd_const_string& rdsp_search) const;
    bool m_ends_with_ic(const dsd_const_string& rdsp_search) const;
    bool m_equals_ic(const dsd_const_string& rdsp_search) const;
    bool m_equals_ic(dsd_unicode_string& rdsp_other) const;
	int m_compare_ic(dsd_unicode_string& rdsp_other) const;
	int m_compare_ic(const dsd_const_string& rdsp_other) const;

    // trim function:
    void m_trim( const dsd_const_string& rdsp_sign_list );
    void m_trim_left( const dsd_const_string& rdsp_sign_list );
    void m_trim_right( const dsd_const_string& rdsp_sign_list );

    dsd_const_string m_substring(int inp_start) const;
    dsd_const_string m_substring(int inp_start, int inp_end) const;

private:
    int m_find_first_of( const dsd_const_string& rdsp_sign_list, bool, int inp_pos = 0 ) const;
    int m_find_first_not_of( const dsd_const_string& rdsp_sign_list, bool, int inp_pos = 0 ) const;
public:
    int m_find_first_of( const dsd_const_string& rdsp_sign_list, int inp_pos ) const;
    int m_find_first_of( const dsd_const_string& rdsp_sign_list ) const;
    int m_find_last_of( const dsd_const_string& rdsp_sign_list, int inp_pos ) const;
    int m_find_last_of( const dsd_const_string& rdsp_sign_list ) const;
    int m_find_first_not_of( const dsd_const_string& rdsp_sign_list ) const;
    int m_find_first_not_of( const dsd_const_string& rdsp_sign_list, int inp_pos ) const;
    int m_find_last_not_of( const dsd_const_string& rdsp_sign_list, int inp_pos ) const;
    dsd_const_string m_substr(int inp_start, int inp_len) const;
    bool m_parse_int(int* ain_out) const;
    bool m_parse_long(long long int* ailp_out) const;
};

struct dsd_tokenizer {
    dsd_const_string dsc_src;
    dsd_const_string dsc_sep;

    dsd_tokenizer(const dsd_const_string& rdsp_src,
        const dsd_const_string& rdsp_sep)
        : dsc_src(rdsp_src), dsc_sep(rdsp_sep)
    {}

    bool m_next(dsd_const_string& rdsp_token) {
        int inl_pos = this->dsc_src.m_index_of(this->dsc_sep);
        if(inl_pos < 0) {
            rdsp_token = dsc_src;
            return false;
        }
        rdsp_token = this->dsc_src.m_substring(0, inl_pos);
        this->dsc_src = this->dsc_src.m_substring(inl_pos+this->dsc_sep.m_get_len());
        return true;
    }
};

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class ds_hstring {
public:
    // constructor/destructor:
    ds_hstring();
    ds_hstring( ds_wsp_helper* ads_wsp_helper_in,
                int in_default_size_in = HSTR_DEFAULT_MEM_SIZE  );
    ds_hstring( ds_wsp_helper* ads_wsp_helper_in, const dsd_const_string& rdsp_string ); // JF
public:
    ds_hstring( ds_wsp_helper* ads_wsp_helper_in, const char* ach, int in_len ); // JF
    ds_hstring( ds_wsp_helper* ads_wsp_helper_in, const ds_hstring& rdsp_copy );  // copy constructor
    ds_hstring( ds_wsp_helper* ads_wsp_helper_in, const ds_hstring* adsp_copy );  // copy constructor
    ds_hstring( const ds_hstring& dc_copy );  // copy constructor
    ~ds_hstring();

    // setup function:
    void m_setup( ds_wsp_helper* ads_wsp_helper_in, 
                  int in_default_size_in = HSTR_DEFAULT_MEM_SIZE );
    void m_init ( ds_wsp_helper* ads_wsp_helper_in );
    bool m_ensure_size(int inp_min_size, bool bop_copy);

    // operators:
    ds_hstring& operator =  (const ds_hstring &dc_in);
    ds_hstring& operator += (const ds_hstring &dc_in);
    ds_hstring& operator =  (const dsd_const_string &rdsp_in);
    ds_hstring& operator += (const dsd_const_string &rdsp_in);
#if 0
    ds_hstring& operator =  (const char* ach_zero);
    ds_hstring  operator +  (const char* ach_zero) const;
    ds_hstring& operator += (const char* ach_zero);
#endif
    ds_hstring& operator =  (char ch_in);
    ds_hstring& operator += (char ch_in);
    ds_hstring& operator =  (int in_in);
    ds_hstring& operator += (int in_in);
    char        operator [] (unsigned int in_pos) const;
private:
    ds_hstring  operator +  (const ds_hstring &dc_in) const;
    ds_hstring  operator +  (int in_in) const;
    ds_hstring  operator +  (char ch_in) const;
public:

    // write functions:
private:
    void  m_write ( const char* ach_input, int in_len_input, bool bo_append );
    int   m_write( const struct dsd_unicode_string* ads_input, bool bo_append );
    int   m_write( const struct dsd_unicode_string* ads_input, enum ied_charset iep_target, bool bo_append );
    void  m_write_lower( const char* ach_input, int in_len_input, bool bo_append );
public:
#if 0
private:
    void  m_write ( const char* ach_input, bool bo_append );
    void  m_write ( const ds_hstring& rdsp_input, bool bo_append );
    void  m_write_zeroterm ( const char* ach_zero, bool bo_append );
    void  m_write_lower_zeroterm( const char* ach_zero, bool bo_append );
    void  m_write_lower_zeroterm( const char* ach_zero );
    void  m_write ( const ds_hstring* adsp_input, bool bo_append );
    void  m_write(const dsd_const_string&, bool bo_append);
public:
#endif
    void  m_write ( const char* ach_input, int in_len_input );
    void  m_write ( const ds_hstring& rdsp_input );
    void  m_write_zeroterm ( const char* ach_zero );
    int   m_writef( HL_FORMAT_STRING const char* ach_format, ...  ) HL_FUNC_FORMAT_PRINTF(2, 3);
    void  m_write_nhasn( int in_input );
    void  m_write_lower( const char* ach_input, int in_len_input );
    
    // write with different characterset:
    int   m_write( const struct dsd_unicode_string* ads_input );
    int   m_write( const struct dsd_unicode_string* ads_input, enum ied_charset iep_target );
    void  m_write(const dsd_const_string& rdsp_string);
    void  m_write ( const ds_hstring* adsp_input );
    void  m_write_char ( char chp_value );
    void  m_write_int ( int inp_value );
    void m_write_concat(
        const dsd_const_string& rdsp_str1,
        const dsd_const_string& rdsp_str2);
    void m_write_concat(
        const dsd_const_string& rdsp_str1,
        const dsd_const_string& rdsp_str2,
        const dsd_const_string& rdsp_str3);

    template<size_t NUM> void m_write_concat_n(const dsd_const_string (&rdsp_list)[NUM]) {
        for(size_t szl_i=0; szl_i<NUM; szl_i++) {
            this->m_write(rdsp_list[szl_i]);
        }
    }

    void m_write_xml_open_tag(const dsd_const_string& rdsp_name);
    void m_write_xml_open_tag(const dsd_unicode_string& rdsp_name);
    void m_write_xml_open_tag(const char* ach_input, int in_len_input);
    void m_write_xml_close_tag(const dsd_const_string& rdsp_name);
    void m_write_xml_close_tag(const dsd_unicode_string& rdsp_name);
    void m_write_xml_close_tag(const char* ach_input, int in_len_input);
    void m_write_xml_text(const dsd_const_string& rdsp_text);
    void m_write_xml_text(const dsd_unicode_string& rdsp_text);
    void m_write_html_text(const dsd_const_string& rdsp_text);
    void m_write_html_text(const dsd_unicode_string& rdsp_text);
    void m_write_html_text(const ds_hstring& rdsp_text);
    void m_write_html_text(const char* achp_text, int inp_len);
	void m_write_uri1(const dsd_const_string& rdsp_text);

    void m_set( const char* ach_input, int in_len_input );
    void m_set( const ds_hstring& rdsp_input );
    void m_set( const ds_hstring* adsp_input );
    void m_set( const struct dsd_unicode_string* ads_input );
    void m_set( const struct dsd_unicode_string& ads_input );
    void m_set_zeroterm(const char* ach_zero);
    void m_set(const dsd_const_string& rdsp_string);
public:    

    // base 64 like functions:
    bool  m_write_b64    ( const char* ach_input, int in_len_input );
    bool  m_write_rfc3548( const char* ach_input, int in_len_input );
    static int m_to_b64( const char *achp_in, int inp_ilen, char *achp_out, int inp_olen );
	static int m_to_rfc3548( const char *achp_in, int inp_ilen, char *achp_out, int inp_olen );
    static int m_from_b64( const char *achp_in, int inp_ilen, char *achp_out, int inp_olen );
	static int m_from_rfc3548( const char *achp_in, int inp_ilen, char *achp_out, int inp_olen );
    bool  m_from_b64     ( const char* ach_input, int in_len_input );
    bool  m_from_rfc3548 ( const char* ach_input, int in_len_input );

    // case functions:
    void m_to_lower();

    // getter functions:
    const char* m_get_ptr() const;
private:
    //char* m_get_ptr();
public:
    int   m_get_len() const;
    const char* m_get_from( int in_pos ) const;
    bool  m_to_int     ( int* ain_out,            int in_offset = 0, int in_base = 10 ) const;
    bool  m_to_long    ( long int* ail_out,       int in_offset = 0, int in_base = 10 ) const;
    bool  m_to_longlong( long long int* aill_out, int in_offset = 0, int in_base = 10 ) const;

    // "hard" convertion:
    bool  m_conv_int ( int* ain_out,      int in_base = 10 );
    bool  m_conv_long( long int* ail_out, int in_base = 10 );

    // reset function:
    void  m_reset();

    // search functions:
private:
	static int m_from_b64_internal(
		const char *achp_in, int inp_ilen, char *achp_out, int inp_olen,
		const char chrs_b64_in_alphabet[256], const char chrs_b64_decoder[256]);
	static int m_to_b64_internal( const char *achp_in, int inp_ilen, char *achp_out, int inp_olen,
		const char chrs_b64_encoder[64+1]);
	int  m_search(int inp_offset, const dsd_const_string& rdsp_search, bool bop_ignore_case) const;
    int  m_search(const char* ach_search, int in_len_search) const;
    int  m_search_ic(const char* ach_search, int in_len_search) const;
public:
    int  m_search(int inp_offset, const dsd_const_string& rdsp_string) const;
    int  m_search(const dsd_const_string& rdsp_search) const;
    int  m_search_ic(const dsd_const_string& rdsp_search) const;
    int  m_search_ic(int inp_offset, const dsd_const_string& rdsp_search) const;
    int  m_search(const ds_hstring& rdsp_search) const;
    int  m_search_ic(const ds_hstring& rdsp_search) const;

    int  m_search_last(const dsd_const_string& rdsp_string) const;
    int  m_search_last(int inp_offset, const dsd_const_string& rdsp_string) const;
    int  m_search_last_ic(const dsd_const_string& rdsp_string) const;
    int  m_search_last(const ds_hstring& rdsp_search) const;
    int  m_search_last_ic(const ds_hstring& rdsp_search) const;
    int  m_search_last(const char* ach_search, int in_len_search) const;
    int  m_search_last_ic(const char* ach_search, int in_len_search) const;

    bool m_equals(const char* ach_search, int in_len_search) const;
    bool m_equals_ic(const char* ach_search, int in_len_search) const;
    bool m_equals(const ds_hstring& rdsp_string) const;
    bool m_equals_ic(const ds_hstring& rdsp_string) const;
    bool m_equals(const dsd_const_string& rdsp_string) const;
    bool m_equals_ic(const dsd_const_string& rdsp_string) const;
    bool m_equals_zeroterm(const char* ach_zero) const;
    bool m_equals_ic_zeroterm(const char* ach_zero) const;

    bool m_starts_with_zeroterm(const char* ach_zero) const;
    bool m_starts_with_ic_zeroterm(const char* ach_zero) const;
    bool m_starts_with(const char* ach_search, int in_len_search) const;
    bool m_starts_with_ic( const char* ach_search, int in_len_search ) const;
    bool m_starts_with( int inp_offset, const char* ach_search, int in_len_search  ) const;
    bool m_starts_with_ic( int inp_offset, const char* ach_search, int in_len_search ) const;
    bool m_starts_with( int inp_offset, const ds_hstring& rdsp_search ) const;
    bool m_starts_with( const ds_hstring& rdsp_search ) const;
    bool m_starts_with_ic( int inp_offset, const ds_hstring& rdsp_search ) const;
    bool m_starts_with_ic( const ds_hstring& rdsp_search ) const;
    bool m_starts_with( const dsd_const_string& rdsp_search ) const;
    bool m_starts_with_ic( const dsd_const_string& rdsp_search ) const;
    bool m_starts_with( int inp_offset, const dsd_const_string& rdsp_search ) const;
    bool m_starts_with_ic( int inp_offset, const dsd_const_string& rdsp_search ) const;

    bool m_ends_with( const char* ach_search, int in_len_search ) const;
    bool m_ends_with_ic( const char* ach_search, int in_len_search ) const;
    bool m_ends_with( const ds_hstring& rdsp_search ) const;
    bool m_ends_with_ic( const ds_hstring& rdsp_search ) const;
    bool m_ends_with( const dsd_const_string& rdsp_search ) const;
    bool m_ends_with_ic( const dsd_const_string& rdsp_search ) const;

    int m_find_first_of    ( const dsd_const_string& rdsp_sign_list, bool bo_ignore_case = false, int in_offset = 0 ) const;
    int m_find_first_not_of( const dsd_const_string& rdsp_sign_list, bool bo_ignore_case = false, int in_offset = 0 ) const;

    // insert/remove functions:
    bool       m_erase  ( int in_offset = 0, int in_signs = 1 );
    void       m_insert_zeroterm ( int in_offset, const char* ach_zero );
    void       m_insert_const_str ( int in_offset, const dsd_const_string& rdsp_insert );
    void       m_insert ( int in_offset, const ds_hstring& rdsp_insert );
    void       m_insert ( int in_offset, const char* ach_insert, int in_len );
private:
    void       m_replace( const dsd_const_string& rdsp_old, const dsd_const_string& rdsp_new,
                          bool bo_ignore_case, int in_offset = 0 );
	void       m_replace_same_length( const char* ach_old, const char* ach_new, 
					       int in_len_old_new, bool bo_ignore_case, int in_offset );
public:
    void       m_replace( const dsd_const_string& rdsp_old, const dsd_const_string& rdsp_new );
    void       m_replace_ic( const dsd_const_string& rdsp_old, const dsd_const_string& rdsp_new );
    void       m_replace( const dsd_const_string& rdsp_old, const dsd_const_string& rdsp_new,
                          int in_offset );
	void       m_replace_char( char chp_old, char chp_new, int inp_offset );
private:
    void       m_replace( const char* ach_old, int in_len_old,
                          const char* ach_new, int in_len_new,
                          bool bo_ignore_case = false, int in_offset = 0 );
public:
    ds_hstring m_substr ( int in_offset, int in_signs = -1 ) const;
    dsd_const_string m_substring(int inp_start) const;
    dsd_const_string m_substring(int inp_start, int inp_end) const;

    // trim function:
    bool m_trim( const dsd_const_string& rdsp_sign_list, bool bo_forward = true, bool bo_backward = true );
    
    dsd_const_string m_const_str() const {
        return dsd_const_string(this->ach_data, this->in_len_data);
    }

private:
    // variables: 
    class ds_wsp_helper* ads_wsp_helper;        // needed for geting memory from WSP
    char* ach_data;                             // pointer to saved data
    int   in_len_data;                          // actual length of saved data
    int   in_memory_size;                       // actual size of data_memory
    int   in_default_memory_size;               // default memory size 
    char  rch_buffer[HSTR_DEFAULT_MEM_SIZE];    // default buffer

    // functions:
    void m_free_memory();
    bool m_enlarge_memory( int in_enlarge, int in_copy );
    void m_copy( const ds_hstring& dc_copy );
    int  m_count_nhasn_len( int in_input );

    inline char* m_get_mem( int in_size );
    inline void  m_free   ( char* ach_ptr, int in_size );
    
    inline void  m_copy_lower( char* ach_dest, const char* ach_src, int in_size );
    static int  m_get_cvalue( char ch_in, int in_base );
public:
    static long long m_str_to_ll ( const char* ach_ptr, const char** aach_endptr, int in_base );
};

struct dsd_string_tools {
	static void m_write_uint32_le(void* achp_out, unsigned int unp_value) {
		((unsigned char*)achp_out)[0] = (unsigned char)(unp_value);
		((unsigned char*)achp_out)[1] = (unsigned char)(unp_value>>8);
		((unsigned char*)achp_out)[2] = (unsigned char)(unp_value>>16);
		((unsigned char*)achp_out)[3] = (unsigned char)(unp_value>>24);
	}

	static void m_write_uint64_le(void* achp_out, HL_LONGLONG ullp_value) {
		((unsigned char*)achp_out)[0] = (unsigned char)ullp_value;
		((unsigned char*)achp_out)[1] = (unsigned char)(ullp_value>>8);
		((unsigned char*)achp_out)[2] = (unsigned char)(ullp_value>>16);
		((unsigned char*)achp_out)[3] = (unsigned char)(ullp_value>>24);
		((unsigned char*)achp_out)[4] = (unsigned char)(ullp_value>>32);
		((unsigned char*)achp_out)[5] = (unsigned char)(ullp_value>>40);
		((unsigned char*)achp_out)[6] = (unsigned char)(ullp_value>>48);
		((unsigned char*)achp_out)[7] = (unsigned char)(ullp_value>>56);
	}

	static unsigned int m_read_uint32_le(const void* achp_src) {
		return ((const unsigned char*)achp_src)[0]
			| (((const unsigned char*)achp_src)[1]<<8)
			| (((const unsigned char*)achp_src)[2]<<16)
			| (((const unsigned char*)achp_src)[3]<<24);
	}

	static HL_LONGLONG m_read_uint64_le(const void* achp_src) {
		return m_read_uint32_le(achp_src)
			| (((HL_LONGLONG)m_read_uint32_le((const unsigned char*)achp_src+4))<<32);
	}
};

struct dsd_buffered_writer {
	char* achc_cur;
	char* achc_end;

	bool m_write_uint32_le(unsigned int unp_value) {
		if(achc_cur + 4 > achc_end)
			return false;
		dsd_string_tools::m_write_uint32_le(achc_cur, unp_value);
		achc_cur += 4;
		return true;
	}

	bool m_write_uint64_le(HL_LONGLONG ullp_value) {
		if(achc_cur + 8 > achc_end)
			return false;
		dsd_string_tools::m_write_uint64_le(achc_cur, ullp_value);
		achc_cur += 8;
		return true;
	}

	bool m_write_uint8(unsigned char ucp_value) {
		if(achc_cur + 1 > achc_end)
			return false;
		*achc_cur++ = ucp_value;
		return true;
	}

	bool m_write_bytes(const void* avop_src, int inp_len) {
		if(achc_cur + inp_len > achc_end)
			return false;
		memcpy(achc_cur, avop_src, inp_len);
		achc_cur += inp_len;
		return true;
	}

	bool m_write_const_string_with_len(const dsd_const_string& rdsp_value) {
		if(!m_write_uint32_le(rdsp_value.m_get_len()))
			return false;
		return m_write_bytes(rdsp_value.m_get_ptr(), rdsp_value.m_get_len());
	}
};

struct dsd_buffered_reader {
	const char* achc_cur;
	const char* achc_end;

#if 1
	bool m_read_uint32_le(unsigned int& unp_value) {
		if(achc_cur + 4 > achc_end)
			return false;
		unp_value = dsd_string_tools::m_read_uint32_le(achc_cur);
		achc_cur += 4;
		return true;
	}

	bool m_read_uint64_le(HL_LONGLONG& ullp_value) {
		if(achc_cur + 8 > achc_end)
			return false;
		ullp_value = dsd_string_tools::m_read_uint64_le(achc_cur);
		achc_cur += 8;
		return true;
	}

	bool m_read_uint8(unsigned char& ucp_value) {
		if(achc_cur + 1 > achc_end)
			return false;
		ucp_value = *achc_cur++;
		return true;
	}

	bool m_read_bytes(void* avop_dst, int inp_len) {
		if(achc_cur + inp_len > achc_end)
			return false;
		memcpy(avop_dst, achc_cur, inp_len);
		achc_cur += inp_len;
		return true;
	}

	bool m_read_const_string_with_len(dsd_const_string& rdsp_out) {
		unsigned int unl_len_out;
		if(!m_read_uint32_le(unl_len_out))
			return false;
		if(achc_cur + unl_len_out > achc_end)
			return false;
		rdsp_out = dsd_const_string(achc_cur, unl_len_out);
		achc_cur += unl_len_out;
		return true;
	}
#endif
};

#endif // DS_HSTRING_H
