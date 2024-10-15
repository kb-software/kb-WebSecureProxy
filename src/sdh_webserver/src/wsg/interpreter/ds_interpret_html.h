/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT WSG:                                                            |*/
/*| =============                                                           |*/
/*|   ds_interpret_html                                                     |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|   this class gets html data from webserver, changes all links, css and  |*/
/*|   javascript content (with help of the css and script interpreter) and  |*/
/*|   gives data back to webserver                                          |*/
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

#ifndef DS_INTERPRET_HTML_H
#define DS_INTERPRET_HTML_H
/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_interpret.h"
#include <ds_hstring.h>

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define HTML_MEMORY_SIZE        1024
#define HTML_DEFAULT_TAG_SIZE    256
#define HOB_EVAL                "HOB_eval("
#define SSO_USERNAME            "#{username}"
#define SSO_PASSWORD            "#{password}"

#define HOB_TYPE                "HOB_type="
/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Interprets HTML data.
*
* @ingroup dataprocessor
*
* This class gets html data from the webserver, changes all links, css and 
* javascript content (with help of the css and script interpreter) and
* gives data back to the webserver.
*/
class ds_interpret_html : public ds_interpret
{
public:
	enum ied_html_doctype {
		iec_html_doctype_not_set,
		iec_html_doctype_invalid,
		iec_html_doctype_other,
		iec_html_doctype_html_5,
		iec_html_doctype_html_4_01_strict,
		iec_html_doctype_html_4_01_transitional,
		iec_html_doctype_html_4_01_frameset,
		iec_html_doctype_html_4_01_other,
		iec_html_doctype_xhtml_1_0_strict,
		iec_html_doctype_xhtml_1_0_transitional,
		iec_html_doctype_xhtml_1_0_frameset,
		iec_html_doctype_xhtml_1_0_other,
		iec_html_doctype_xhtml_1_1,
		iec_html_doctype_xhtml_other,
	};

	//! Constructor.
	ds_interpret_html(void);
	//! Destructor.
	~ds_interpret_html(void);

	//functions:
	//! Processes HTML data.
	int  m_process_data( );
	//! Parse the received data.
	int  m_parse_data  ( const char* ach_data, int in_len_data, bool bo_data_complete = false, ds_hstring* ads_output = NULL );
	// take care: m_setup overwrite ds_interpret::m_setup!
	//! Setup strings.
	void m_init();
	bool m_setup       (ds_session* ads_session_in);
	void m_set_ica( bool bop_is_ica );
	void m_set_content_type( ds_http_header::content_types iep_content_type );
	//! Identifies the charset being used for input.
	void m_set_charset( ied_charset iep_charset );
	//! Sets bo_change_data flag to false.
	void m_not_change_data();
	void m_set_iframe_depth( int inp_iframe_depth );

	static ied_html_doctype m_get_doctype(const dsd_const_string& rdsp_doctype);
	static void m_filter_xua_compatible(const dsd_const_string& dsl_value2, ds_hstring& ads_out);
	
private:
	struct dsd_attr_info {
		int inc_tag_key;
		bool boc_is_style;
		bool boc_is_meta_refresh;
		bool boc_is_meta_xua_compatible;
		bool boc_is_crossorigin;
		dsd_const_string dsc_crossorigin;
		bool boc_is_form_method_get;
		dsd_const_string dsc_charset;
		ds_http_header::content_types iec_script_content_type;
		ied_charset iec_script_charset;
		int inc_unique_id;
	};

	enum ied_html_tag_states {
		HTML_NO_TAG,             // no tag is found in data
		HTML_TAG_PARTIAL,        // tag is found partial
		HTML_TAG_COMPLETE,       // tag is found complete
		HTML_TAG_CDATA_START,    // CDATA start
		HTML_TAG_CDATA_END,      // CDATA end
		HTML_TAG_COMMENT_PARTIAL,
		HTML_TAG_COMMENT_COMPLETE,
	};

	enum ied_unescape_html_states {
		iec_unescape_html_default,
		iec_unescape_html_findend,
		iec_unescape_html_collect,
	};

	// variables:
	int    in_state;                        // status of algorithm
	int    in_get_tag_state;                // status of tag getting function
	int    in_old_tag_state;                // previous state of tag getting function
	bool   bo_back_slash_ending;            // cut data ended with backslash '\'
	class  ds_hstring ds_tag;               // memory for saving cut tags
	bool   bo_icon_found;                   // favicon in page found?
	bool   bo_head_found;
	bool   boc_xua_compatible_found;
	bool   bo_hobscript_added;
	bool   bo_change_data;
	bool   bo_in_comments;
	int    inc_iframe_depth;
	int    imc_uniqueid_counter;
	int    inc_head_depth;
	int    inc_body_depth;
#if 0
	const char*  ach_start_comment;         // start point of comments
#endif
	char   ch_last_sign;                    // last sign in tag search
	bool   boc_is_ica_srv;                  // current srv is ica srv
	bool   boc_insert_ica_call;             // insert ica activation call
	bool   boc_is_xhtml;
	bool   boc_is_cdata;
	ied_unescape_html_states iec_unescape_state;
	class  ds_hstring dsc_unescape_tag;     // memory for saving cut tags

	ied_charset iec_page_charset;           // Page charset
	ied_charset iec_meta_charset;           // Meta charset
	ds_interpret* adsc_interpreter;

	ied_html_doctype iec_doctype;

	ied_charset m_get_charset();

	// functions:
	int    m_process_tag        ( const char* ach_tag, int in_len_tag, struct dsd_attr_info& rdsp_info, ds_hstring* ads_changed_tag );
	dsd_const_string m_unescape_attr_value(const dsd_const_string& rdsp_value, ds_hstring& rdsp_replaced);
	dsd_const_string m_escape_attr_value(const dsd_const_string& rdsp_value, ds_hstring& rdsp_replaced);
	void   m_put_tag_together   ( ds_hstring* ads_out, const char* ach_tag, int in_len_tag, const char* ach_new_value, int in_len_new_val, int in_start_insert, int in_end_insert );
	bool   m_change_attr_value  ( ds_hstring* ads_out, const dsd_const_string& dsl_value, int in_attr_number, const dsd_attr_info& rdsp_info/* int in_tag_key, bool bo_is_style, const dsd_const_string& rdsp_charset_req*/ );
	bool   m_check_for_empty_tag( const char* ach_tag, int in_len_tag );

	// getter functions:    
	ied_html_tag_states    m_get_tag         ( const char* ach_data, int in_len_data, int *ain_position, int* ain_tag_start, const char** aach_tag,  int *ain_len_tag );
	ied_html_tag_states    m_get_end_tag     ( const char* ach_data, int in_len_data, int *ain_position, int* ain_tag_start, const char** aach_tag,  int *ain_len_tag, bool bop_parse_html_comments );
	static void   m_get_tag_name( const char* ach_tag, int in_len_tag, int* ain_position, const char** aach_name, int* ain_len_name );
	static void   m_get_attribute   ( const char* ach_tag, int in_len_tag, int *ain_position, const char** aach_attr, int* ain_len_attr );
	static void   m_get_attr_value  ( const char* ach_tag, int in_len_tag, int *ain_position, int* ain_value_start, const char** aach_value, int* ain_len_val );

	// special sign handlers:
	static int    m_handle_single_quote  ( const char* ach_data, int in_len_data, int* ain_position );
	static int    m_handle_double_quote  ( const char* ach_data, int in_len_data, int* ain_position );
	static int    m_handle_round_bracket ( const char* ach_data, int in_len_data, int* ain_position );
	static int    m_handle_square_bracket( const char* ach_data, int in_len_data, int* ain_position );
	static int    m_handle_curly_bracket ( const char* ach_data, int in_len_data, int* ain_position );

	// last sign in tag search:
	void m_save_sign( char ch_sign );

	// in list watching functions:
	int    m_is_tag_in_list       ( const char* ach_name,  int in_len );
	int    m_is_attribute_in_list ( const char* ach_attr,  int in_len );
	int    m_is_name_value_in_list( const dsd_const_string& rdsp_value );
	int    m_is_rel_in_list       ( const char* ach_value, int in_len );
	int    m_is_type_in_list      ( const char* ach_type,  int in_len );

	// inserting functions:
	void   m_insert_HOB_script    ( bool bo_insert_head, ds_hstring* astr_output = NULL );
	void   m_insert_HOB_write     ( ds_hstring* astr_output = NULL );
	void   m_insert_HOB_nav_init  ( ds_hstring* astr_output = NULL );
	void   m_insert_HOB_login_init( ds_hstring* astr_output );
	void   m_insert_favicon       ( ds_hstring* ads_output );

	// ica inserting functions:
	void   m_insert_ica_decl      ( ds_hstring* adsp_output );
	void   m_insert_ica_call      ( ds_hstring* adsp_output );

	int    m_interpreter_parse_data(const char* ach_data, int in_len_data, bool bo_data_complete, ds_hstring* ads_output);
};
#endif // DS_INTERPRET_HTML_H
