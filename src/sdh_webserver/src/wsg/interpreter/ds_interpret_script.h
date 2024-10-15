/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_interpret_script                                                   |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|   this class gets script data from webserver, inserts our script func-  |*/
/*|   tions and gives data back to webserver                                |*/
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

#ifndef DS_INTERPRET_SCRIPT_H
#define DS_INTERPRET_SCRIPT_H
/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/

#define SM_USE_PARSE_SCRIPT_PARAMS2		1
#define SM_USE_INTERPRET_SCRIPT_SHA256	(1 && SM_USE_PARSE_SCRIPT_PARAMS2)

#ifdef _DEBUG
    #ifndef TRACE_MEMORY
//        #define TRACE_MEMORY
    #endif // TRACE_MEMORY
#endif // DEBUG
#ifdef TRACE_MEMORY
    #define FILE_GET  "interpreter.getmem"      // file handles for memory overview
    #define FILE_FREE "interpreter.freemem"
#endif //TRACE_MEMORY

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_interpret.h"
#include <ds_hstring.h>
#include "ds_scriptvariables.h"

/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_hvector.h>
#include <hob-encry-1.h>

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Interprets script data
 *
 * @ingroup dataprocessor
 *
 * This class gets script data from the webserver, inserts our script functions 
 * and gives data back to the webserver
 */
class ds_interpret_script : public ds_interpret
{
public:
    static const int IMC_FLAG_TOP_LEVEL = 0x1;
    static const int IMC_FLAG_HTML_ENTITIES = 0x2;
    static const int IMC_FLAG_HTML_SCRIPT = 0x4;
	static const int IMC_FLAG_HTML_XHTML = 0x8;
	static const int IMC_FLAG_HTML_EVENT = 0x10;
	static const int IMC_FLAG_HTML_ATTRIBUTE = 0x20;

    //! Constructor.
    ds_interpret_script(void);
    //! Destructor.
    ~ds_interpret_script(void);
    // functions:   
	//! Processes script data.
    int m_process_data( );
	//! Parse the received data.
    int m_parse_data( const char* ach_data, int in_len_data, bool bo_data_complete = false,
                      ds_hstring* ads_output = NULL );
	 void m_init( ied_charset iep_charset, const char* achp_quote, int imp_flags );
	 void m_set_unique_id( int imp_id );
private:
#if SM_USE_WSG_V2
#if SM_INTERPRET_SCRIPT_V2
    enum ied_parser_state {
        ied_parser_state_init,
        ied_parser_state_default,
        ied_parser_state_escape,
        ied_parser_state_escape_x,
        ied_parser_state_escape_u,
        ied_parser_state_string
    };
    enum ied_parser_state iec_parser_state; 
#endif
#if SM_INTERPRET_SCRIPT_V3
    enum ied_parser_state {
        ied_parser_state_init,
        ied_parser_state_default
    };
	 int inc_elem_size;
	 int inc_elem_size_mask;
    unsigned char chrc_bom[8];
	 int inc_bom_rest;
    char chrc_input[8];
    int inc_input_rest;
    char chrc_output[1024*3];
    int inc_output_rest;
    enum ied_parser_state iec_parser_state;
    BYTE chrc_triplet[3];
    int inc_triplet_rest;
#if SM_USE_INTERPRET_SCRIPT_SHA256
	 int inrc_sha256_state[SHA256_ARRAY_SIZE];
#endif

    template<bool BO_ESCAPE_HTML> int m_convert_to_utf8(const char* achp_in_cur, const char* achp_in_end);
#endif
#else
    ds_hvector_p<ds_scriptvariables*> dsc_variables;
    ds_scriptvariables*               adsc_var_cur;
#endif /*SM_USE_WSG_V2*/
    
    /*
        MJ 16.09.10, Ticket [20581]:
          if we are called by html interpreter, we have to know
          in which kind of quotes we are (means " or ').
          Example:
            onclick="this.getAttribute('src');" vs
            onclick='this.getAttribute("src");'

          We have to replace the both examples with
            onclick="HOB_func(this,'getAttribute','src');" and
                                   ==============
            onclick='HOB_func(this,"getAttribute","src");'
                                   ==============

    */
    enum ied_in_quotes {
        ied_in_no_quotes,
        ied_in_single_quotes,
        ied_in_double_quotes
    } ienc_in_quotes;

    ied_charset iec_charset;
    int imc_flags;
	 int imc_unique_id;

	 void m_set_charset(ied_charset iep_charset);
    
	// functions:
#if !SM_USE_WSG_V2
	int    m_get_next_word        ( const char* ach_data, int in_len_data, int* ain_position, int in_word_key, const char** aach_word, int* ain_len_word, int* ain_word_start, bool bo_get_cut_word = false );
    int    m_get_next_sign        ( const char* ach_data, int in_len_data, int* ain_position, const char** aach_sign, int* ain_len_sign, int* ain_sign_position, const char** aach_white_spaces, int* ain_len_white_spaces );
    int    m_get_argument         ( const char* ach_data, int in_len_data, int* ain_position, char ch_sign, const char** aach_argument, int* ain_len_arg );
    bool   m_check_for_reg_exp    ( const char* ach_data, int in_len_data, int in_position );
    bool   m_get_last_sign_before_newline( const char* ach_data, int in_position, char* ach_last_sign );
    int    m_get_last_sign        ( const char* ach_data, int in_position, char* ach_last_sign );
    bool   m_get_following_sign   ( const char* ach_data, int in_len_data, int in_position, char* ach_next_sign );
    bool   m_last_word_equals     ( const char* ach_data, int in_position, const dsd_const_string& rdsp_compare );
    int    m_is_word_in_list      ( const char* ach_word, int in_len_word );
    int    m_is_argument_in_attr_list( const char* ach_argument, int in_len_argument );
    bool   m_is_word_attribute    ( int in_word_key );
    bool   m_is_word_object       ( int in_word_key, const char* ach_argument = NULL, int in_len_argument = -1 );
    bool   m_is_word_function     ( int in_word_key, char ch_sign );
    bool   m_is_sign_bracket      ( char ch_sign );
    bool   m_is_newline_in_spaces ( const char* ach_white_spaces, int in_len_white_spaces );
    int    m_handle_double_quotes ( const char* ach_data, int in_len_data, int* ain_position );
    int    m_handle_single_quotes ( const char* ach_data, int in_len_data, int* ain_position );
    int    m_is_slash_comment     ( const char* ach_data, int in_len_data, int* ain_position );
    int    m_handle_c_comment     ( const char* ach_data, int in_len_data, int* ain_position );
    int    m_handle_cpp_comment   ( const char* ach_data, int in_len_data, int* ain_position );
    int    m_handle_regexp        ( const char* ach_data, int in_len_data, int* ain_position );
    int    m_get_last_argument    ( const char* ach_argument, int in_len_argument );
    bool   m_append_space         ( const char* ach_data, const char* ach_object );
    bool   m_rec_attribute        ( int in_word_key );
    bool   m_rec_object           ( int in_word_key );
    void   m_free_all_data  ();
    void   m_free_vars      ();
    bool   m_is_word_cc_on( const char* ach_word, int in_len_word );
	bool   m_handle_funny_cases( const char* achp_data, int inp_len, int* ainp_pos );
	bool   m_skip_comments( const char* achp_data, int inp_len, int* ainp_pos );
	bool   m_skip_strings( const char* achp_data, int inp_len, int* ainp_pos );

    // rewrite of m_set* functions:
    void m_build_HOB_set_attr( ds_hstring* ads_out, 
                               int in_append_data,
                               const char* ach_object,   int in_len_object,
                               const char* ach_word,     int in_len_word, 
                               int in_word_key, 
                               const char* ach_argument, int in_len_argument );
    void m_build_HOB_get_attr( ds_hstring* ads_out,
                               const char* ach_object, int in_len_object, 
                               const char* ach_word,   int in_len_word,
                               const char* ach_sign,   int in_len_sign );
    void m_build_HOB_function( ds_hstring* ads_out,
                               const char* ach_data,
                               const char* ach_object,   int in_len_object,
                               const char* ach_word,     int in_len_word,
                               int in_word_key, 
                               const char* ach_argument, int in_len_argument );
    void m_build_HOB_object  ( ds_hstring* ads_out,
                               const char* ach_object, int in_len_object,
                               const char* ach_word,   int in_len_word,
                               const char* ach_sign,   int in_len_sign );
    void m_build_HOB_style   ( ds_hstring* ads_out,
                               const char* ach_object,   int in_len_object,
                               const char* ach_word,     int in_len_word,
                               const char* ach_argument, int in_len_argument );
    void m_build_string      ( ds_hstring* ads_out,
                               const char* ach_input1, int in_len_input1, 
                               const char* ach_input2, int in_len_input2,
                               const char* ach_input3 = NULL, int in_len_input3 = 0, 
                               const char* ach_input4 = NULL, int in_len_input4 = 0,
                               const char* ach_input5 = NULL, int in_len_input5 = 0 );

    void       m_add_withobject( char* ach_add, int in_len, bool bo_bracket );
    void       m_free_withobject( ds_with_variables* ads_free );

    // MJ, Ticket[17965]
    bool m_build_HOB_check_property( ds_hstring* ads_out,
                                     const char* ach_object, int in_len_object,
                                     const char* ach_property, int in_len_property );
#endif /*!SM_USE_WSG_V2*/
};
#endif // DS_INTERPRET_SCRIPT_H
