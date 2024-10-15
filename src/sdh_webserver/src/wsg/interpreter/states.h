#ifndef STATES_H
#define STATES_H

// html states:
enum ie_html_states {
    // global states:
    HTML_NORMAL,             // normal state
    HTML_CUT_TAG,            // cut tag
    HTML_STYLE_DATA,         // style data
    HTML_CUT_TAG_STYLE_DATA, // cut tag in style data
    HTML_SCRIPT_DATA,        // script data
	//HTML_SCRIPT_DATA_OTHER,  // script data (other language)
    HTML_CUT_TAG_SCRIPT_DATA,// cut tag in script data#
    HTML_HEAD_TAG,           // head tag occured ( insert HOB_script )
    HTML_BODY_TAG,           // body tag occured ( insert HOB_nav )
    HTML_NO_HTML_DATA,       // if no html data is send to html interpreter ...
    HTML_NOT_DECIDED,        // it is not yet decided, if data is html data.
    // m_get_tag returns:
    // m_process_data returns:
    HTML_NOT_CHANGED,        // tag is not changed
    HTML_CHANGED,            // tag is changed
    // m_get_tag / m_get_tag_end states:
    HTML_GET_TAG,            // normal state in m_get_tag
    HTML_GET_TAG_END,        // get tag end
    HTML_GET_ABS_TAG_END,    // get tag end (not restart at '<')
    HTML_IN_SINGLE_QUOTES,   // a tag is cut in single quotes
    HTML_IN_DOUBLE_QUOTES,   // a tag is cut in double quotes
    HTML_AFTER_QUOTES,       // state after quotes, to insure that no error like """ occured
    HTML_CHECK_COMMENT,      // a tag starts with !, check for comment or CDATA
    HTML_IN_COMMENTS,        // we are between a <!-- --> tag
    HTML_END_COMMENTS,       // we found '-' and will check for end of comment
    HTML_CHECK_COMMENT_TAG_0,
    HTML_CHECK_COMMENT_TAG_1,
    HTML_CHECK_COMMENT_TAG_2,
    HTML_CHECK_COMMENT_TAG_3,
    HTML_CHECK_COMMENT_TAG_4,
    HTML_CHECK_END_TAG,
	HTML_IN_CDATA_0,
	HTML_IN_CDATA_1,
	HTML_IN_CDATA_2,
	HTML_IN_CDATA_3,
	HTML_IN_CDATA_4,
	HTML_IN_CDATA_5,
    //HTML_IN_CDATA,           // we are between <![CDATA[ ]]> tag
	HTML_END_CDATA_0,
	HTML_END_CDATA_1,
	HTML_END_CDATA_2,
    //HTML_END_CDATA           // we found ']' and will check for end of CDATA
};

// css states:
enum ie_css_states {
    // global states:
    CSS_NORMAL,             // normal state
    CSS_WORD_CUT,           // cut word
    CSS_ARGUMENT_CUT,       // cut argument
    // m_get_next_word returns:
    CSS_NO_WORD,            // no word is found in data
    CSS_WORD_PARTIAL,       // word is found partial
    CSS_WORD_COMPLETE,      // word is found complete
    // m_get_argument returns:
    CSS_NO_ARG,             // no argument is found in data
    CSS_ARG_PARTIAL,        // argument is found partial
    CSS_ARG_COMPLETE        // argument is found complete
};

// script states:
enum ie_script_states {
    // global states:
    SCRIPT_NORMAL,              // normal state
    SCRIPT_CUT_WORD,            // get cut word
    SCRIPT_CUT_SIGN,            // cut sign after word
    SCRIPT_SAVED_OBJECT,        // handle saved object (formally cut word!)
    SCRIPT_CUT_ARGUMENT,        // get cut argument
    SCRIPT_CUT_ARG_SIGN,        // cut sign after argument
    SCRIPT_CUT_AFTER_SLASH,     // cut after slash "/"
    SCRIPT_C_COMMENT_1,         // handle "/*...*/" comment
    SCRIPT_C_COMMENT_2,         // handle "/*...*/" comment
    SCRIPT_CPP_COMMENT,         // handle "//..." comment
    SCRIPT_COND_COMP,           // handle "/*@cc_on ... @*/" conditional compilation (only IE)
    SCRIPT_CUT_COND_COMP,       // handle cut conditional compilation
    SCRIPT_REG_EXP,             // handle regular expression "/..../"
    SCRIPT_SINGLE_QUOTES,       // handle single quote
    SCRIPT_DOUBLE_QUOTES,       // handle double quote
    SCRIPT_SPEC_STYLE,          // handle expressions like "object.style[var1]='value'"
    SCRIPT_CUT_SPEC_STYLE,      // cut special style
    // m_get_next_word returns:
    SCRIPT_NO_WORD,             // no word found
    SCRIPT_WORD_PARTIAL,        // word found partial
    SCRIPT_WORD_COMPLETE,       // word found complete
    // m_get_next_sign returns:
    SCRIPT_NO_SIGN,             // no sign found
    SCRIPT_SIGN_FOUND,          // sign found
    // m_get_argument states:
    SCRIPT_ARG_NORMAL,          // normal state
    SCRIPT_ARG_NEWLINE,         // check newline ( end of command ?)
    SCRIPT_ARG_ROUND_BRACKET,   // handle round brackets
    SCRIPT_ARG_SQUARE_BRACKET,  // handle square brackets
    SCRIPT_ARG_CURLY_BRACKET,   // handle curly brackets
    SCRIPT_ARG_SINGLE_QUOTE,    // handle single quotes
    SCRIPT_ARG_DOUBLE_QUOTE,    // handle double quotes
    SCRIPT_ARG_AMPERS_AND,      // handle ampersand "&"
    SCRIPT_ARG_AMPERS_AND_A,    // handle &amp;
    SCRIPT_ARG_AMPERS_AND_AM,   // handle &amp;
    SCRIPT_ARG_AMPERS_AND_Q,    // handle &quot;
    SCRIPT_ARG_AMPERS_AND_QU,   // handle &quot;
    SCRIPT_ARG_AMPERS_AND_QUO,  // handle &quot;
    SCRIPT_ARG_AMPERS_AND_END,  // handle end of character entities; skip ";", if there
                                // (for backwards compatibility, some entities, e.g. &amp, &quot and
                                //  &auml, are rendered correctly even without the trailing ";")
    SCRIPT_ARG_GET_SEMICOLON,   // if an "&" with following "#" is found, we will search for ";"
    SCRIPT_ARG_C_COMMENT_1,     // handle "/*....*/" comment
    SCRIPT_ARG_C_COMMENT_2,     // handle "/*....*/" comment
    SCRIPT_ARG_CPP_COMMENT,     // handle "// ..." comment
    SCRIPT_ARG_CUT_AFTER_SLASH, // cut after slash "/"
    SCRIPT_ARG_REG_EXP,         // handle regular expression
	SCRIPT_ARG_QUESTIONMARK,    // SH: handle ?/: and case: correctly
    // m_get_argument returns:
    SCRIPT_NO_ARG,              // no argument found
    SCRIPT_ARG_PARTIAL,         // argument found partial
    SCRIPT_ARG_COMPLETE,        // argument found complete
    // m_handle_double/single_quotes returns:
    SCRIPT_QUOTE_END_FOUND,     // end of quotes found
    SCRIPT_QUOTE_NO_END_FOUND,  // end of quotes not found
    // m_is_slash_comment returns:
    SCRIPT_NOT_DECIDED,         // no sign after slash, no decision yet
    SCRIPT_NO_COMMENT,          // slash is no comment
    SCRIPT_ASTERISK_COMMENT,    // slash mark the start of asterisk comment "/* ... */"
    SCRIPT_SLASH_COMMENT,       // slash mark the start of slash comment "// ...."
    // m_handle_c/cpp_comment returns:
    SCRIPT_COMMENT_NO_END_FOUND,// end of comment not found
    SCRIPT_COMMENT_END_FOUND,   // end of comment found
    // m_handle_regexp returns:
    SCRIPT_REGEXP_NO_END_FOUND, // end of regexp not found
    SCRIPT_REGEXP_END_FOUND,    // end of regexp found    

    // Ticket [19108], "delete"
    SCRIPT_IGNORE_COMMAND,      // don't interpret this command line

	// hofmants: ignore funny case statements
	SCRIPT_CASE_STATEMENT
};

// html states:
enum ie_xml_states {
    // global states:
    XML_NORMAL,             // normal state
    XML_CUT_TAG,            // cut tag
    XML_CUT_DATA,           // cut data between brackets
    // m_get_tag returns:
    XML_NO_TAG,             // no tag is found in data
    XML_TAG_PARTIAL,        // tag is found partial
    XML_TAG_COMPLETE,       // tag is found complete
    // m_process_tags returns:
    XML_NOT_CHANGED,        // tag is not changed
    XML_CHANGED,            // tag is changed
    // m_process_data_between_tags returns:
    XML_DATA_NOTCHANGED,    // data is not changed
    XML_DATA_CHANGED,       // data is changed
    XML_DATA_CUT            // data is cut
};

#endif // STATES_H
