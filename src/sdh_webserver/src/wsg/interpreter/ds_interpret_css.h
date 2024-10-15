/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_interpret_css                                                      |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|   this class gets css data from webserver, changes all links and gives  |*/
/*|   data back to webserver                                                |*/
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

#ifndef DS_INTERPRET_CSS_H
#define DS_INTERPRET_CSS_H

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_interpret.h"
#include <ds_hstring.h>

/*+-------------------------------------------------------------------------+*/
/*| defines                                                                 |*/
/*+-------------------------------------------------------------------------+*/
#define CSS_MEMORY_SIZE    8
#define CSS_ARGUMENT_SIZE 64

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Interprets css data
 *
 * @ingroup dataprocessor
 *
 * This class gets css data from webserver, changes all links and gives 
 * data back to webserver
 */
class ds_interpret_css : public ds_interpret
{
public:
    //! Constructor.
    ds_interpret_css(void);
    //! Destructor.
    ~ds_interpret_css(void);
    // functions:
	//! Processes css data.
    int m_process_data();
	//! Parse the received data.
    int m_parse_data  ( const char* ach_data, int in_len_data, bool bo_data_complete = false, ds_hstring* ads_output = NULL );
    // take care: m_setup overwrite ds_interpret::m_setup!
	//! Setup strings.
    bool m_setup( ds_session* ads_session_in );
private:
#if 0
	enum ied_word_state {
		ied_ws_start,
		ied_ws_comment1,
		ied_ws_comment2,
		ied_ws_comment3,
		ied_ws_comment4,
		ied_ws_comment5,
		ied_ws_no_comment
	};

	enum ied_char_result {
		iec_error,
		iec_pending,
		iec_no_more_data,
		iec_comment_start,
		iec_commented_char,
		iec_comment_end,
		iec_char_found
	};
#endif
	enum ied_word_function {
		iec_word_function_invalid = 0,
		iec_word_function_url = 1,
		iec_word_function_src = 2,
		iec_word_function_import = 3,
	};

    // variables: 
    int    in_state;
    class  ds_hstring ds_word;
    class  ds_hstring ds_argument;
	 ied_word_function iec_word_function1;
	 ied_word_function iec_word_function2;
#if 0
	enum   ied_word_state iec_word_state;
    class  ds_hstring dsc_comment;
#endif
    char   ch_symbol;
	 char   ch_in_string;
    // functions:
#if 0
	enum ied_char_result  m_get_next_char(struct dsd_string_data& rdsp_data, char& rchp_next);
#endif
	int  m_get_next_word  ( const char* ach_data, int in_len_data, int* ain_position, const char** aach_word, int* ain_len_word, int* ain_word_start, bool bo_get_cut_word = false );
    int  m_get_argument   ( const char* ach_data, int in_len_data, int *ain_position, int *ain_arg_start, bool bo_get_cut_arg = false );
    ds_interpret_css::ied_word_function  m_is_word_in_list( const char* ach_word, int in_len_word );
    ds_interpret_css::ied_word_function  m_is_word_in_list( const dsd_const_string& rdsp_word );
    int  m_remove_signs   ( dsd_const_string& rdsp_argument );
    bool m_arg_starts_with_url (const dsd_const_string& rdsp_argument);
};

#endif // DS_INTERPRET_CSS_H
