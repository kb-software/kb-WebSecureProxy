/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_interpret                                                          |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|   this class contains several functions, that the three interpreter     |*/
/*|   (html, css, script) use                                               |*/
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
/*|                                                                         |*/
/*| design of messages:                                                     |*/
/*|                                                                         |*/
/*| format of message identifier: HWSGE000E                                 |*/
/*|                                                                         |*/
/*| HWSG        = HOBWebServerGate                                          |*/
/*| next letter = type of information (I=Information, W=Warning, E=Error)   |*/
/*| 000         = 3-digit-number                                            |*/
/*|               first digit 0 -> messages from ds_interpret               |*/
/*|               first digit 1 -> messages from ds_interpret_html          |*/
/*|               first digit 2 -> messages from ds_interpret_script        |*/
/*|               first digit 3 -> messages from ds_interpret_css           |*/
/*| last letter = type of information (I=Information, W=Warning, E=Error)   |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

#ifndef DS_INTERPRET_H
#define DS_INTERPRET_H

#define SM_USE_WSG_V2	1
#define SM_INTERPRET_PUSH_SINGLE  0
#define SM_INTERPRET_SCRIPT_V2  (SM_USE_WSG_V2 && 0)
#define SM_INTERPRET_SCRIPT_V3  (SM_USE_WSG_V2 && 1)
#define SM_USE_BASEURL_SUPPORT	  1

/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#include <assert.h>

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "states.h"
#include <ds_hstring.h>

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class ds_session; // forward definition
class ds_attributes; // forward defintion

/*! \brief Interprets any data.
 *
 * @ingroup dataprocessor
 *
 * This class contains several functions to be used by all the interpreters
 * (html, css, script and xml)
 */
class ds_interpret
{
public:
	struct dsd_string_data {
		const char* achc_data;
		int inc_len_data;
		int inc_position;
public:
		bool m_has_more() {
			return this->inc_position < this->inc_len_data;
		}

		char m_next() {
			return this->achc_data[this->inc_position++];
		}

		char m_peek() {
			return this->achc_data[this->inc_position];
		}
	};

	struct dsd_hobtype_data {
		dsd_const_string dsc_hobtype;
		dsd_const_string dsc_charset;
		dsd_const_string dsc_origin;
	};

	enum ied_change_url_flags {
		ied_change_url_flag_absolute = 0x1,
		ied_change_url_flag_human_readable = 0x2,
		ied_change_url_flag_prevent_immediate = 0x4,
		ied_change_url_flags_default = 0,
	};

	enum ied_change_url_result {
		ied_change_url_error = -1,
		ied_change_url_unchanged = 0,
		ied_change_url_other_protocol = 1,
		ied_change_url_changed,
		ied_change_url_prevent_immediate,
	};

	struct dsd_change_url_params {
		dsd_const_string dsc_src;
		enum ied_change_url_flags iec_flags;
	};

    //! Constructor.
    ds_interpret(void);
    //! Destructor.
    ~ds_interpret(void);
    //functions:
    virtual int m_process_data();
	virtual int m_parse_data( const char* ach_data, int in_len_data, bool bo_data_complete = false,
                      ds_hstring* ads_output = NULL );
	//! Setup strings
    virtual bool m_setup( ds_session* ads_session_in );

	//! Changes the url to the new required format.
    int    m_change_url_old       ( ds_hstring* ads_url, bool bo_absolute_mode = false, int in_offset = 0 );
	ied_change_url_result m_change_url( const dsd_const_string& rdsp_src, enum ied_change_url_flags, ds_hstring& rdsp_tmp );
	ied_change_url_result m_change_url_ex( const dsd_const_string& rdsp_src, enum ied_change_url_flags, const dsd_const_string& dsp_hob_type, ds_hstring& rdsp_tmp );
	int    m_add_hobtype      (ds_hstring& rdsp_url, const dsd_hobtype_data& rdsp_data);
	//! Sets the bo_write_data_chunked flag to TRUE if data should be written in chunks.
    void   m_set_write_mode   ( bool bo_write_as_chunked );
	void   m_cdata_active(bool bop_state);
	void   m_set_skip_output(bool bop_skip);
	//! Resets the in_ret variable to 0.
    //void   m_reset_return     ();
    void m_write_hob_initialize(ds_hstring& dc_insert, const dsd_const_string& dsp_unique_id, const dsd_const_string& dsp_function_name, const dsd_const_string& dsp_html_charset, const dsd_const_string& dsp_worker_type);
	static const dsd_const_string m_escape_js_string(const dsd_const_string& rdsp_src, ds_hstring& rdsp_dst);
	
protected:
    //variables:
    class  ds_session* ads_session;		//!< Reference to ds_session class
    const class  ds_attributes* ads_attr;		//!< Reference to ds_attributes class
    bool   boc_cdata_active;            //!< true, if we are in a CDATA section
    bool   boc_skip_output;
#if !SM_USE_BASEURL_SUPPORT
	int    in_num_directories;          //!< number of directories in extern path
#endif
    
    //functions:
	//! Send data.
    int   m_send_data        ( const char* ach_data, int in_len_data, ds_hstring* ads_output = NULL );
    int   m_send_data2       ( const dsd_const_string& rdsp_const, ds_hstring* ads_output = NULL );

	//! Moves the pointer aach_data to the position specified by ain_position.
    void  m_move_char_pointer( const char** aach_data, int* ain_len_data, int* ain_position );
	//! Print the address (a_address) and data length (in_len_data) to a file. The file depends on the bo_free_memory flag.
    void  m_trace_memory     ( void* a_address, int in_len_data, bool bo_free_memory );
	//! Count the number of directories within the specified path (ach_path).
   static int   m_count_directories( const dsd_const_string& ach_path, int inp_depth, bool& rbop_negative, ds_hstring* adsp_normalized );
	 //! Search for a string (ach_search) within another string (ach_org).
	int   m_search_ic           ( const char* ach_org, int in_len_org, const char* ach_search, int in_len_search );
	//! Search for a string (ach_search) within another string (ach_org).
    int   m_search_ic           ( const char* ach_org, int in_len_org, const dsd_const_string& ach_search );
    //! Comparte two strings together. Returns TRUE if the strings match.
	bool  m_equals_ic           ( const char* ach_org, int in_len_org, const char* ach_comp, int in_len_comp );
    //! Comparte two strings together. Returns TRUE if the strings match.
    bool  m_equals_ic           ( const char* ach_org, int in_len_org, const dsd_const_string& ach_comp );
    
private:
    //! Search for a string (ach_search) within another string (ach_org).
    int   m_search           ( const char* ach_org, int in_len_org, const dsd_const_string& ach_search, bool );
    //! Search for a string (ach_search) within another string (ach_org).
	int   m_search_ic           ( const char* ach_org, int in_len_org, const char* ach_search, bool );
	//! Comparte two strings together. Returns TRUE if the strings match.
	bool  m_equals           ( const char* ach_org, int in_len_org, const char* ach_comp, bool );
    //! Comparte two strings together. Returns TRUE if the strings match.
	bool  m_equals_ic           ( const char* ach_org, int in_len_org, const char* ach_comp, bool );
public:
    //! Search for a string (ach_search) within another string (ach_org).
	int   m_search           ( const char* ach_org, int in_len_org, const char* ach_search, int in_len_search );
    //! Search for a string (ach_search) within another string (ach_org).
    int   m_search           ( const char* ach_org, int in_len_org, const dsd_const_string& ach_search );
    //! Comparte two strings together. Returns TRUE if the strings match.
	bool  m_equals           ( const char* ach_org, int in_len_org, const char* ach_comp, int in_len_comp );
	//! Comparte two strings together. Returns TRUE if the strings match.
    bool  m_equals           ( const char* ach_org, int in_len_org, const dsd_const_string& ach_comp );
    
	//! Looks for one of the signs in chr_sign_list within the string in ach_data.
   static void m_pass_signs( const char* ach_data, int in_len_data,
                       int* ain_position, const dsd_const_string& chr_sign_list,
                       bool bo_forward = true );
	static bool m_normalize_path( const dsd_const_string& ach_path, ds_hstring& rdsp_normalized );

    // rewritten functions:
	//! Removing first sign from string
    int m_remove_first_sign     ( dsd_const_string& rdsp_to_change, char ch_to_remove );
    //! Removing last sign from string
	int m_remove_last_sign      ( dsd_const_string& rdsp_to_change, char ch_to_remove );
    //! Removing first and last signs from string
	int m_remove_first_last_sign( dsd_const_string& rdsp_to_change, char ch_to_remove );

	//! Returns the number of "../" within the given path (ads_path).
    int m_count_dotdotslash( const dsd_const_string& ads_path );
};
#endif //DS_INTERPRET_H
