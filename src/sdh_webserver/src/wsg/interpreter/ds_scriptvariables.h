/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_scriptvariables                                                    |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|   this class contains all variables must be saved for ds_interpret_-    |*/
/*|   script. So, if ds_interpret_script calls m_parse_data recursiv        |*/
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

#ifndef DS_SCRIPTVARIABLES_H
#define DS_SCRIPTVARIABLES_H

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_hstring.h>
#include <ds_hvector.h>

/*+-------------------------------------------------------------------------+*/
/*| defines                                                                 |*/
/*+-------------------------------------------------------------------------+*/
// default memory sizes:
#define SCRIPT_WORD_MEMORY           32
#define SCRIPT_SIGN_MEMORY            2
#define SCRIPT_OBJECT_MEMORY        256
#define SCRIPT_ARGUMENT_MEMORY      512  
#define SCRIPT_WHITE_SPACES_MEMORY    4

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class ds_wsp_helper;    // forward definition


/*! \brief Contains info for with(...) cases
 *
 * @ingroup dataprocessor
 * 
 */
struct ds_with_variables {
    ds_hstring ds_object;
    int    in_brackets;
};

/*! \brief Contains info (word key, position and length) of a word in a word key
 *
 * @ingroup dataprocessor
 * 
 */
struct ds_word_key {
    int in_key;				
    int in_pos_in_object;
    int in_length;
};


enum ied_funny_states
{
	iec_normal,
	iec_comment_slash,
	iec_comment_asterisk,
	iec_string_single,
	iec_string_double
};



/*! \brief Contains all scriptvariables used for the script interpreter.
 *
 * @ingroup dataprocessor
 *
 * This class contains all variables that must be saved for ds_interpret_script.
 * 
 */
class ds_scriptvariables {
private:
    class ds_wsp_helper* ads_wsp_helper;
public:
    // variables:
    int                                  in_state;                  //!< global status variable
    ds_hvector_btype<int>                dsc_arg_state;             //!< argument search status variable
    ds_hvector_btype<ds_with_variables*> dsc_vwith;                 //!< variable for with(...) cases
    bool                                 bo_not_read_next_sign;     //!< in case of quotes, we don't want to read a sign after "\"
//    int                                  iml_question_mark_ocurred;  //!< if in argument serach a "?" occures, ":" will not end arguments search
    bool                                 bo_comment;                //!< will be set to ture if we are in an "/*...*/" comment
    bool                                 bo_cc_on;                  //!< true = conditional compilation is activated!
    char                                 ch_last_sign;              //!< save last sign in case of cut data
    char                                 ch_with_sign;              //!< save sign that mark the beginning of command chain in case of with command
    struct ds_word_key                   ds_last_pos_key;           //!< saving word key (and position) of last found word in a word key (i.e. document.location.href)
    class  ds_hstring                    ds_word;                   //!< memory class for word
    class  ds_hstring                    ds_sign;                   //!< memory class for sign
    class  ds_hstring                    ds_object;                 //!< memory class for object
    class  ds_hstring                    ds_argument;               //!< memory class for argument
    class  ds_hstring                    ds_arg_sign;               //!< memory class for sign following the argument
    class  ds_hstring                    ds_spaces;                 //!< memory class for spaces
    class  ds_hstring                    ds_arg_spaces;             //!< memory class for spaces following the argument
    int                                  in_sign_pos;               //!< position of sign in ch_sign (rememeber: sign can be "==" i.e.)
    int                                  in_append_data;            //!< in case of HOB_set_attr( in_append_data, object, 'attribute', value )
                                                                    //!<  0 means sign was "=",
                                                                    //!<  1 means sign was "+=",
                                                                    //!< -1 means sign was "-="
	enum ied_funny_states					iec_funny_states;
	bool									boc_funny_resume;
    //! Constructor.
    ds_scriptvariables( ds_wsp_helper* adsl_wsp_helper );
    //! Destructor.
    ~ds_scriptvariables();
    
    // functions:
	//! Overloading the 'new' function
    void* operator new( size_t, void* a_loc );
    // avoid warning: 
	//! Overloading the 'delete' function
    void operator delete( void*, void* ) {};


	//! Setup the ds_hstring structs within this structure.
    void m_setup( ds_wsp_helper* adsl_wsp_helper );

	//! Init the ds_hstring structs.
    void m_init ( ds_wsp_helper* adsl_wsp_helper );
};
#endif // DS_SCRIPTVARIABLES_H
