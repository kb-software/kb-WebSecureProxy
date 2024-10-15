/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|   xs-json-parser                                                    |*/
/*|   parses events coming from the browser                             |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|   Tobias Hofmann, March 2012                                        |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| global includes:                                                    |*/
/*+---------------------------------------------------------------------+*/
#ifndef HL_UNIX
    #include <windows.h>
#endif //HL_UNIX
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

/*+---------------------------------------------------------------------+*/
/*| local includes:                                                     |*/
/*+---------------------------------------------------------------------+*/
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

#include <hob-xs-html5.h>
#include "hob-http-processor.h"
#include "hob-xs-html5-priv.h"


/* browser events keywords                                              */
/* sort this by incoming amount of events. most used eved should be     */
/* the first in the struct ( because of loop to identify event )        */
static const struct dsd_string_const dsg_be_keys[] = {
    { NULL,     -1 },
    { "type",    4 },                           /* type of event         */
	{ "x",       1 },                           /* mouse x pos           */
    { "y",       1 },                           /* mouse y pos           */
    { "char",    4 },                           /* character key         */
	{ "button",  6 },                           /* mouse button          */
	{ "wheel",   5 },                           /* mouse wheel           */
    { "func",    4 },                           /* function key          */    
    { "time",    4 },                           /* timestamp             */
    { "width",   5 },                           /* canvas width          */
    { "height",  6 },                           /* canvas height         */
    { "context", 7 },                           /* canvas draw context   */
	{ "server",  6 },							/* server to connect to  */
	{ "port",    4 },							/* port of server        */
	{ "user",    4 },                           /* connect as this user  */
	{ "password",8 },                           /* with this password    */
    { NULL,     0 }
};

typedef enum ied_be_keys {
    ied_be_key_unknown = -1,
    ied_be_key_dummy   = 0,
    ied_be_key_type,
    ied_be_key_x,
    ied_be_key_y,
	ied_be_key_char,
    ied_be_key_button,
	ied_be_key_wheel,
	ied_be_key_func,    
    ied_be_key_time,
    ied_be_key_width,
    ied_be_key_height,
    ied_be_key_context,
	ied_be_key_server,
	ied_be_key_port,
	ied_be_key_user,
	ied_be_key_password
} ied_be_keys;


typedef enum ied_json_values
{
    JSON_NULL      = 1,
    JSON_BOOL      = 2,
    JSON_NUMBER    = 4,
    JSON_STRING    = 8,
    JSON_ARRAY     = 16,
    JSON_OBJECT    = 32
} ied_json_values;

/* following structure is related to ied_be_keys! it must have the same order! */
/* it shows, which values are valid for this type */
static int inrg_valid_values[] =
{
    /* -1 */                                            /* ied_be_key_unknown */
    JSON_NULL + JSON_BOOL + JSON_NUMBER + JSON_STRING,  /* ied_be_key_dummy   */
    JSON_NUMBER,                                        /* ied_be_key_type    */
    JSON_NUMBER,                                        /* ied_be_key_x       */
    JSON_NUMBER,                                        /* ied_be_key_y       */
	JSON_STRING,                                        /* ied_be_key_char    */
    JSON_NUMBER,                                        /* ied_be_key_button  */
    JSON_NUMBER,                                        /* ied_be_key_wheel   */
	JSON_NUMBER,                                        /* ied_be_key_func    */
    JSON_NUMBER,                                        /* ied_be_key_time    */
    JSON_NUMBER,                                        /* ied_be_key_width   */
    JSON_NUMBER,                                        /* ied_be_key_height  */
    JSON_STRING,                                        /* ied_be_key_context */
	JSON_STRING,										/* ied_be_key_server  */
	JSON_NUMBER + JSON_STRING,							/* ied_be_key_port    */
	JSON_STRING,										/* ied_be_key_user    */
	JSON_STRING											/* ied_be_key_password*/
};

static BOOL						m_jp_is_json_obj		( struct dsd_gather_i_1**, unsigned long long int );
PRIVATE BOOL					m_jp_has_valid_format	( struct dsd_gather_i_1**, struct dsd_browser_event* );
PRIVATE int						m_jp_switch_value		( struct dsd_gather_i_1**, char*, int, int );
PRIVATE int						m_jp_get_number			( struct dsd_gather_i_1**, char*, int );
PRIVATE int						m_jp_get_null			( struct dsd_gather_i_1** );
PRIVATE int						m_jp_get_boolean		( struct dsd_gather_i_1**, char* );
PRIVATE int						m_jp_get_string			( struct dsd_gather_i_1**, char*, int );
PRIVATE BOOL					m_jp_get_array			( struct dsd_gather_i_1**, char*, int );
static enum ied_be_keys			m_jp_json_key_type		( char*, int );
static BOOL						m_jp_fill_event			( struct dsd_browser_event*, enum ied_be_keys, char*, int );
PRIVATE char					m_get_byte				( struct dsd_gather_i_1** );
static char						m_read_byte				( struct dsd_gather_i_1** );
static long long				m_atoll					( const char*, int, char**, int );
static int						m_get_cvalue			( char, int );

/**
 * extern function m_jp_parse_event
 *
 * @param[in]   dsd_gather_i_1    *adsp_data    input data
 * @param[out]  dsd_browser_event *adsp_evt     received event
 * @return      BOOL                            TRUE = success
 *                                              FALSE = otherwise
 *
 * 15.07.2011 hofmants:
 * | Check if keywords are in correct quotes (eg: "keyword"), reject otherwise
 * | Check if values are valid, JSON knows following data types:
 * | - Null:        a keyword called null, without quotes.  (eg "nullexample":null)
 * | - Boolean:     true or false, also without quotes      (eg "boolexample":true)
 * | - Number:      character 0-9, possibly with a +/- sign (eg "number":-1234)
 * |                also possible with a dot for floats     (eg "float":+3.14)
 * |                can be followed by an exponent          (eg "exponent":2e+32)
 * | - Strings:     starts/ends with a quote "              (eg "name":"hofmants")
 * |                default UTF-8 encoding
 * |                can contain unicode chars
 * |                can contain escape sequences
 * | - Array:       starts/ends with '[' and ']'            (eg "array":[null, "circle", 3.14])
 * |                null values and empty arrays are valid
 * | - Objects:     starts/ends with { and }
 * |                contains other "key":value pairs
 * |                empty objects are valid
*/
BOOL m_jp_parse_event( struct dsd_gather_i_1 *adsp_data, unsigned long long int ulli_event_len, struct dsd_browser_event *adsp_evt )
{
    BOOL             bol_ret;                   /* return for some funcs */

    bol_ret = m_jp_is_json_obj( &adsp_data, ulli_event_len );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }

    /* own function for recursion */
    bol_ret = m_jp_has_valid_format( &adsp_data, adsp_evt );
    if ( bol_ret == FALSE ) {
        return FALSE;
    }
    
    return TRUE;
} /* end of m_jp_parse_event */


						   
/**
 * private function m_jp_is_json_obj
 * check if data is an json object, this means starting with '{'
 * and ending with '}'
 *
 * @param[in]   dsd_gather_i_1  **adsp_data    input data
 * @return      BOOL
 */

static BOOL m_jp_is_json_obj( struct dsd_gather_i_1 **aadsp_data, unsigned long long int ullip_len )
{
    struct dsd_gather_i_1	*adsl_temp;
	char					*achl_temp;

    char chl_byte = m_get_byte( aadsp_data );
    if ( chl_byte != '{' ) {
        return FALSE;
    }
	
	/* get last gather in chain */
    adsl_temp = *aadsp_data;
	achl_temp = adsl_temp->achc_ginp_cur;

	while( ullip_len > 2 )
	{
		if(adsl_temp->achc_ginp_cur == adsl_temp->achc_ginp_end)
		{
			if(adsl_temp->adsc_next == NULL)
			{
				return FALSE;
			}

			adsl_temp = adsl_temp->adsc_next;
			achl_temp = adsl_temp->achc_ginp_cur;
		}
		else
		{
			achl_temp++;
		}
		--ullip_len;
	}
	return (*achl_temp == '}') ? TRUE : FALSE;
} /* end of m_jp_is_json_obj */


/**
 * private function m_jp_has_valid_format
 * check if the format is correct and parses the key/value pairs:
 * keyword: value pairs, seperated by comma
 * Like this:
 * {
 *   "abc" : value1,
 *   "..." : value2
 * }
 *
 * @param[in]        dsd_gather_i_1                *adsp_data    input data
 * @param[in,out]    struct dsd_browser_event    *adsp_evt    where to store the parsed data
 * @return            BOOL
*/
PRIVATE BOOL m_jp_has_valid_format(struct dsd_gather_i_1 **aadsp_data, struct dsd_browser_event *adsp_evt)
{
    char chl_cur;

    BOOL bl_keyword = TRUE;            /* indicates, that we are parsing a keyword */
    BOOL bl_parsing_done = FALSE;      /* return value for the value parsing functions */
    BOOL bl_ret;
    
    char             chrl_key[8];               /* keyword buffer        */
    int              inl_key;                   /* length of cur keyword */
    char             chrl_value[128];            /* value buffer          */
    int              inl_value;                 /* length of cur value   */
    enum ied_be_keys ienl_ktype;                /* key type              */

    if(*aadsp_data == NULL){ return FALSE; }

    while(*aadsp_data)
    {
        chl_cur = m_read_byte(aadsp_data);

        if(bl_keyword)
        {
            switch(chl_cur)
            {
                case ' ': break;
                case '"':
                    if(bl_parsing_done) { return FALSE; }
                    inl_key = m_jp_get_string( aadsp_data, chrl_key, (int)sizeof(chrl_key) );
                    if(inl_key == -1) { return FALSE; }
                    bl_parsing_done = TRUE;
                    ienl_ktype = m_jp_json_key_type( chrl_key, inl_key );
                    if ( ienl_ktype == ied_be_key_unknown ) return FALSE;                     
                    break;
                case ':':
                    if(bl_parsing_done)
                    {
                        bl_keyword = FALSE;
                        bl_parsing_done = FALSE;
                    }
                    else { return FALSE; }
                    break;
                default:
                    /* every chars, except those above, are invalid outside a string! */
                    return FALSE;
                    break;
            }
        }
        else /* value follows */
        {
            switch(chl_cur)
            {
                case ' ': break;
                case '[':
                    /* definition: if u want to parse an array, set        */
                    /* the pointer to the char behind the opening '['    */
                    if(bl_parsing_done) return FALSE;
                    if( !(inrg_valid_values[(int)ienl_ktype] & JSON_ARRAY) ) return FALSE;
                    m_get_byte(aadsp_data); /* step one char */
                    bl_parsing_done = m_jp_get_array( aadsp_data, chrl_value, (int)sizeof(chrl_value) );
                    break;
                case '{':
                    /* definition: if u want to parse an object, set    */
                    /* the pointer to the char behind the opening '{'    */
                    /* ATTENTION: Recursion not fully implemented,        */
                    /* because generic object creation not supported    */
                    if(bl_parsing_done) return FALSE;
                    if( !(inrg_valid_values[(int)ienl_ktype] & JSON_OBJECT) ) return FALSE;
                    m_get_byte(aadsp_data); /* step one char */
                    bl_parsing_done = m_jp_has_valid_format(aadsp_data, NULL); /* insert pointer to memory if recursion */
                    break;
                case '}':
                    if(bl_parsing_done)
                    {
                        bl_ret = m_jp_fill_event( adsp_evt, ienl_ktype, chrl_value, inl_value );
                        if( !bl_ret ){ return FALSE; }
                        m_get_byte(aadsp_data);
                        return TRUE;
                    }
                    return FALSE;
                case ',':
                    if(bl_parsing_done)
                    {
                        bl_keyword = TRUE;
                        bl_parsing_done = FALSE;
                        bl_ret = m_jp_fill_event( adsp_evt, ienl_ktype, chrl_value, inl_value );
                        if( !bl_ret ) return FALSE;
                    }
                    break;
                default:
                    if(bl_parsing_done) return FALSE;
                    inl_value = m_jp_switch_value( aadsp_data, chrl_value, (int)sizeof(chrl_value), (int)ienl_ktype );
                    if(inl_value == -1) return FALSE;
                    bl_parsing_done = TRUE;
                    break;
            }
        }
        if( (*aadsp_data) != NULL )
            m_get_byte(aadsp_data);
    }

    return FALSE;
}

/* ToDo: Add Description + Tests */
PRIVATE int m_jp_switch_value(struct dsd_gather_i_1 **aadsp_data, char *achp_buffer, int inp_bsize, int ienp_ktype )
{
    /* when we parse a value, we should take care of following rules. it can be:    */
    /* a number, with + or - as indicator, floating point or exponent                */
    /* 'null'                                                                        */
    /* 'true' or 'false'                                                            */
    /* a string like the keyword string                                                */
    switch( *(((struct dsd_gather_i_1*)(*aadsp_data))->achc_ginp_cur) )
    {
        case '+':
        case '-':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            if( !(inrg_valid_values[ienp_ktype] & JSON_NUMBER) ) return -1;
            return( m_jp_get_number( aadsp_data, achp_buffer, inp_bsize ) );
        case 'n':
            if( !(inrg_valid_values[ienp_ktype] & JSON_NULL) ) return -1;
            return( m_jp_get_null( aadsp_data ) );
        case 't':
        case 'f':
            if( !(inrg_valid_values[ienp_ktype] & JSON_BOOL) ) return -1;
            return( m_jp_get_boolean( aadsp_data, achp_buffer ) );
        case '"':
            if( !(inrg_valid_values[ienp_ktype] & JSON_STRING) ) return -1;
            return( m_jp_get_string( aadsp_data, achp_buffer, inp_bsize ) );
        default:
            return -1;
    }
}


/**
 * private function m_jp_get_number
 * parses a number in a JSON object. modifies the caller pointer!
 * number can have 0-9, a point '.', '+' and '-', and the char 'e' as exponent
 *
 * @param[in, out]    dsd_gather_i_1  **aadsp_data        input data
 * @param[out]        char            *achp_buffer        buffer for the number found
 * @param[in]        dsd_gather_i_1  **aadsp_data        length of the buffer
 *
 * @return            int                length of found number
*/
PRIVATE int m_jp_get_number(struct dsd_gather_i_1 **aadsp_data, char *achp_buffer, int inp_bsize )
{
    BOOL bl_sign_allowed    = TRUE;         /* sign can be the first char             */
    BOOL bl_point_allowed   = FALSE;        /* not allowed to be the first char         */
    BOOL bl_expo_allowed    = FALSE;        /* also not allowed to be the first char */
    
    int inl_sign_pos        = 2;            /* remember the last position of the sign, so that it cant occur twice like '++4' */
    int inl_expo_pos        = 2;            /* remember pos of 'e', so that it cant be the last char like '232e' */
    int inl_point_pos       = 2;            /* remember pos of '.', so that we cant have it as last char like '342.' */

    int inl_expo_count      = 0;            /* counts, how often exponent 'e' occurs */
    int inl_point_count     = 0;            /* counts '.' */
    
    int inl_str_len         = 0;

    char *achl_cur;                            /* use temporary pointers because we have */
    char *achl_last_element;                /* to reset the original pointer position */
    struct dsd_gather_i_1* adsl_temp = *aadsp_data;

    while( adsl_temp )
    {
        achl_cur = adsl_temp->achc_ginp_cur;

        while(achl_cur != adsl_temp->achc_ginp_end)
        {
            switch( *achl_cur )
            {
                case 'e':
                    if( !bl_expo_allowed ) return -1; /* error */
                    if( inl_expo_count == 1 ) return -1;
                    bl_expo_allowed = FALSE;
                    bl_point_allowed = FALSE;
                    bl_sign_allowed = TRUE;
                    inl_expo_pos = 0;
                    inl_expo_count++;
                    break;
                case '+':
                case '-':
                    if( !bl_sign_allowed ) return -1;
                    bl_expo_allowed = FALSE;
                    bl_sign_allowed = FALSE;
                    bl_point_allowed = FALSE;
                    inl_sign_pos = 0;
                    break;
                case '.':
                    if( !bl_point_allowed ) return -1;
                    if( inl_point_count == 1 ) return -1;
                    bl_expo_allowed = FALSE;
                    bl_point_allowed = FALSE;
                    bl_sign_allowed = FALSE;
                    inl_point_pos = 0;
                    inl_point_count++;
                    break;
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    bl_expo_allowed = TRUE;
                    bl_point_allowed = TRUE;
                    bl_sign_allowed = FALSE;
                    break;
                case ' ':
                case ',':
                case ']':
                case '}':
                    if(inl_expo_pos == 1)    return -1;    /* last sign was an exponent     */
                    if(inl_point_pos == 1)    return -1;    /* last sign was a point         */
                    if(inl_sign_pos == 1)    return -1;    /* last sign was a plus or minus */
                    /* set pointer to last element of the number */
                    while( (*aadsp_data)->achc_ginp_cur != achl_last_element ) m_get_byte(aadsp_data);
                    return inl_str_len;    /* remember that this function is only called when a number    */
                                        /* or a +/- sign is found, so empty numbers can't occur        */
                default:
                    return -1;
            }

            achp_buffer[inl_str_len++] = *achl_cur;
            if(inl_str_len == inp_bsize) return -1; /* error */

            inl_sign_pos++;
            inl_expo_pos++;
            inl_point_pos++;

            achl_last_element = achl_cur;
            achl_cur++;
        }

        adsl_temp = adsl_temp->adsc_next;
    }
    return -1;
}

/**
 * private function m_jp_get_null
 * looks for the keyword 'null' as value
 *
 * @param[in, out]    dsd_gather_i_1  **aadsp_data        input data
 * @return            int                                     0 for success
 *                                                        -1 for error
*/
PRIVATE int m_jp_get_null( struct dsd_gather_i_1 **aadsp_data )
{
    char chl_cur;
    int inl_wordcounter = 0;

    while(*aadsp_data)
    {
        chl_cur = m_read_byte(aadsp_data);
        switch(chl_cur)
        {
            case 'n':
                if(inl_wordcounter++ != 0) return -1;
                break;
            case 'u':
                if(inl_wordcounter++ != 1) return -1;
                break;
            case 'l':
                if(inl_wordcounter++ < 2) return -1;
                if(inl_wordcounter == 4) return 0;
                break;
            default:
                return -1;
        }
        m_get_byte(aadsp_data);
    }
    return -1;
}

/**
 * private function m_jp_get_boolean
 * parses, if we have a boolean value in the JSON Object
 *
 * @param[in, out]    dsd_gather_i_1  **aadsp_data        input data
 * @return            int
*/
PRIVATE int m_jp_get_boolean(struct dsd_gather_i_1 **aadsp_data, char *achp_buffer)
{
    char chl_cur;
    BOOL bl_collect_true = TRUE; /* shows, that we want to parse the word 'true' */
    int inl_wordcount = 0;

    while(*aadsp_data)
    {
        chl_cur = m_read_byte(aadsp_data);
        switch(chl_cur)
        {
            case 't':
                if( inl_wordcount++ != 0 ) return -1; /* if its not the first char */
                break;
            case 'r':
                if(!bl_collect_true) return -1;
                if( inl_wordcount++ != 1 ) return -1; /* if its not the second char */
                break;
            case 'u':
                if(!bl_collect_true) return -1;
                if( inl_wordcount++ != 2 ) return -1;
                break;
            case 'f':
                if( inl_wordcount++ != 0 ) return -1; /* when its not the first char */
                bl_collect_true = FALSE;
                break;
            case 'a':
                if(bl_collect_true) return -1;
                if( inl_wordcount++ != 1 ) return -1;
                break;
            case 'l':
                if(bl_collect_true) return -1;
                if( inl_wordcount++ != 2 ) return -1;
                break;
            case 's':
                if(bl_collect_true) return -1;
                if( inl_wordcount++ != 3 ) return -1;
                break;
            case 'e':
                if(bl_collect_true && inl_wordcount == 3)
                {
                    achp_buffer[0] = '1';
                    return 1;
                }
                if(!bl_collect_true && inl_wordcount == 4)
                {
                    achp_buffer[0] = '0';
                    return 1;
                }
            default:
                return -1;
        }
        m_get_byte(aadsp_data);
    }
    return -1;
}

/**
 * private function m_jp_get_string
 * parses a string in a JSON object
 *
 * @param[in, out]  dsd_gather_i_1  **aadsp_data        input data
 * @param[out]      char            *achp_buffer        storage for the keyword
 * @param[in]       int             inp_bsize           size of the buffer
 * @return          int                                 length of found word
 *                                                      0 if nothing found
 *                                                      -1 in error cases
*/
PRIVATE int m_jp_get_string(struct dsd_gather_i_1 **aadsp_data, char *achp_buffer, int inp_bsize )
{
    char chl_cur;                   /* contains current char */
    
    int inl_count_quotes = 0;       /* counts the quotes */
    int inl_esc_position = 2;       /* counts, how many positions the last escape sign '\' was away */
                                    /* is set to 2, because otherwise an empty string will be ignored */

    int inl_str_len = 0;            /* counts the length of the keyword */

    while(*aadsp_data)
    {
        chl_cur = m_read_byte(aadsp_data);

        switch(chl_cur)
        {
            case '"':
                /* check, if it is escaped. if not, we have to count it    */
                /* if we have the second quotation mark, string is done    */
                if(inl_esc_position != 1)
                {    
                    inl_count_quotes++;
                    if(inl_count_quotes == 2) return inl_str_len;
                }
                else achp_buffer[inl_str_len++] = chl_cur;
                break;
            case '\\':
                /* if its inside a string, set the escape flag to zero,   */
                /*  so if we have a quotation mark, we know it is escaped */
                inl_esc_position = 0;
                break;
            default:
                achp_buffer[inl_str_len++] = chl_cur;
                break;
        }
        inl_esc_position++;
        m_get_byte(aadsp_data);
    }
    return -1;
}

/**
 * private function m_jp_get_array
 * parses all the values of an JSON array. Empty Arrays are valid!
 *
 * ATTENTION: Currently not fully implemented, because generic creation
 * of JSON structures are not possible. if you need to store an array,
 * rewrite the part where you parse the values!
 * i think also the parameters must be changed (from charbuffer to another pointer)
 * Currently, there is no data stored in this function!
 * hofmants 26.07.11
 *
 * @param[in, out]    dsd_gather_i_1  **aadsp_data        input data
 * @param[out]        char            *achp_buffer        buffer
 * @param[in]         int             inp_bsize           length of buffer
 * @return            BOOL
*/
PRIVATE BOOL m_jp_get_array(struct dsd_gather_i_1 **aadsp_data, char *achp_buffer, int inp_bsize )
{
    char chl_cur;

    BOOL bl_parsing_done = FALSE;
    BOOL bl_array_empty = TRUE;

    int inl_value_length = 0;

    if(achp_buffer == NULL || inp_bsize == 0 ) return FALSE;

    while(*aadsp_data)
    {
        chl_cur = m_read_byte(aadsp_data);
        switch(chl_cur)
        {
            case ' ':
                break;
            case '[':
                /* definition: if u want to parse an array, set        */
                /* the pointer to the char behind the opening '['    */
                if(bl_parsing_done) return FALSE;
                bl_array_empty = FALSE;
                m_get_byte(aadsp_data);
                bl_parsing_done = m_jp_get_array(aadsp_data, NULL, 0); /* insert pointer for recursion */
                break;
            case '{':
                if(bl_parsing_done) return FALSE;
                bl_array_empty = FALSE;
                m_get_byte(aadsp_data);
                bl_parsing_done = m_jp_has_valid_format(aadsp_data, NULL); /* add storage area for recursion */
                break;
            case ',':
                if(bl_parsing_done) bl_parsing_done = FALSE;
                else{ return FALSE; }
                break;
            case ']':
                if(bl_parsing_done || bl_array_empty) return TRUE;
                return FALSE;
            default:
                if(bl_parsing_done) return FALSE;
                bl_array_empty = FALSE;
                inl_value_length = m_jp_switch_value(aadsp_data, achp_buffer, inp_bsize, 0 ); /* 0 enables primitive datatype*/
                if(inl_value_length == -1) return FALSE;
                bl_parsing_done = TRUE;
                /* value is in the buffer now, store it where u want */
                break;
        }
        m_get_byte(aadsp_data);
    }
    return FALSE;
}



/**
 * private function m_jp_json_key_type
 * get json key type
 *
 * @param[in]   char        *achp_key           pointer to keyword
 * @param[in]   int         inp_len             length of keyword
 * @return      ied_be_keys                     type
 *                                              -1 if unknown
*/
static enum ied_be_keys m_jp_json_key_type( char *achp_key, int inp_len )
{
    struct dsd_string_const *adsl_cur;          /* current constant      */
    int                     inl_type;           /* current type          */

    inl_type = 1;
    adsl_cur = (struct dsd_string_const*)&dsg_be_keys[1];
    while ( adsl_cur->inc_length > 0 ) {
        if (    adsl_cur->inc_length == inp_len
             && strncmp(adsl_cur->achc_str, achp_key, inp_len) == 0 ) {
            return (enum ied_be_keys)inl_type;
        }
        inl_type++;
        adsl_cur++;
    }
    return ied_be_key_unknown;
} /* end of m_jp_json_key_type */


/**
 * private function m_jp_fill_event
 * fill event structure with given key/value pair
 *
 * @param[in/out] dsd_brower_event *adsp_evt    event structure
 * @param[in]     ied_be_keys      ienp_type    key type
 * @param[in]     char             *achp_value  value
 * @param[in]     int              inp_length   length of value
 * @return        BOOL
*/
static BOOL m_jp_fill_event( struct dsd_browser_event *adsp_evt,
                          enum ied_be_keys ienp_type,
                          char *achp_value, int inp_length )
{
    long long int ill_temp;                     /* temp value            */
    char          *achl_end;                    /* end pointer           */

    switch( ienp_type ) {
        case ied_be_key_type:
            ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if (    achl_end == achp_value
                 || ill_temp  < ied_be_control
                 || ill_temp  > ied_be_mouse_wheel     ) {
                return FALSE;
            }
            adsp_evt->iec_type = (enum ied_browser_event)ill_temp;
            break;
        case ied_be_key_char:
            m_cpy_vx_vx( adsp_evt->rchc_key, 1, ied_chs_utf_32,
                         achp_value, inp_length, ied_chs_utf_8 );
            break;
        case ied_be_key_func:
            ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if (    achl_end == achp_value
                 || ill_temp  < 0
                 || ill_temp  > 255 ) {
                return FALSE;
            }
            adsp_evt->uchc_function = (unsigned char)ill_temp;
            break;
        case ied_be_key_x:
            ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if (    achl_end == achp_value
                 || ill_temp  < 0
                 || ill_temp  > UINT_MAX ) {
                return FALSE;
            }
            adsp_evt->uinc_x = (unsigned int)ill_temp;
            break;
        case ied_be_key_y:
            ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if (    achl_end == achp_value
                 || ill_temp  < 0
                 || ill_temp  > UINT_MAX ) {
                return FALSE;
            }
            adsp_evt->uinc_y = (unsigned int)ill_temp;
            break;
        case ied_be_key_button:
            ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if (    achl_end == achp_value
                 || ill_temp  < 0
                 || ill_temp  > USHRT_MAX ) {
                return FALSE;
            }
            adsp_evt->uisc_button = (unsigned short)ill_temp;
            break;
        case ied_be_key_wheel:
            ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if (    achl_end == achp_value
                 || ill_temp  < INT_MIN
                 || ill_temp  > INT_MAX ) {
                return FALSE;
            }
            adsp_evt->inc_wheel = (int)ill_temp;
            break;
        case ied_be_key_time:
            ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if ( achl_end == achp_value ) {
                return FALSE;
            }
            adsp_evt->ill_timestamp = ill_temp;
            break;
        case ied_be_key_width:
            ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if (    achl_end == achp_value
                 || ill_temp  < 0
                 || ill_temp  > UINT_MAX ) {
                return FALSE;
            }
            adsp_evt->uinc_width = (unsigned short)ill_temp;
            break;
        case ied_be_key_height:            
            ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if (    achl_end == achp_value
                 || ill_temp  < 0
                 || ill_temp  > UINT_MAX ) {
                return FALSE;
            }
            adsp_evt->uinc_height = (unsigned short)ill_temp;
            break;
        case ied_be_key_context:
            if (    inp_length == 2
                 && strncmp( achp_value, "2d", 2 ) == 0 ) {
                adsp_evt->ienc_ctx_type = ied_ct_2d;
            }
			/* todo */
            break;
		case ied_be_key_server:
			strncpy( adsp_evt->dsc_rdp_srv_infos.chrc_rdp_srv, achp_value, inp_length );
			adsp_evt->dsc_rdp_srv_infos.inc_srv_len = inp_length;
			break;
		case ied_be_key_port:
			ill_temp = m_atoll( achp_value, inp_length, &achl_end, 10 );
            if (    achl_end == achp_value
                 || ill_temp  < 0
                 || ill_temp  > UINT_MAX ) {
                return FALSE;
            }
			adsp_evt->dsc_rdp_srv_infos.inc_port = (unsigned short)ill_temp;
			break;
		case ied_be_key_user:
			m_cpy_vx_vx(adsp_evt->dsc_rdp_srv_infos.chrc_user, inp_length, ied_chs_utf_16,
						achp_value, inp_length, ied_chs_utf_8 );
			adsp_evt->dsc_rdp_srv_infos.inc_user_len = inp_length;
			break;
		case ied_be_key_password:
			m_cpy_vx_vx(adsp_evt->dsc_rdp_srv_infos.chrc_password, inp_length, ied_chs_utf_16,
						achp_value, inp_length, ied_chs_utf_8 );
			adsp_evt->dsc_rdp_srv_infos.inc_password_len = inp_length;
			break;
		default:
			break;
    }
    return TRUE;
} /* end of m_jp_fill_event */


/**
 * private function m_get_byte
 *
 * reads and moves the pointer one char
 *
 * @param[in/out]   dsd_gather_i_1  **aadsp_data
 * @return          char
*/
PRIVATE char m_get_byte( struct dsd_gather_i_1 **aadsp_data )
{
    char chl_byte = *((*aadsp_data)->achc_ginp_cur);
    ((*aadsp_data)->achc_ginp_cur)++;
    while (    (*aadsp_data) != NULL
            && (*aadsp_data)->achc_ginp_cur >= (*aadsp_data)->achc_ginp_end ) {
        *aadsp_data = (*aadsp_data)->adsc_next;
    }
    return chl_byte;
} /* end of m_get_byte */

/**
 * private function m_read_byte
 *
 * reads one byte, doesnt modify the pointer
 *
 * @param[in/out]   dsd_gather_i_1  **aadsp_data
 * @return          char
*/
static char m_read_byte( struct dsd_gather_i_1 **aadsp_data )
{
    char chl_byte = *((*aadsp_data)->achc_ginp_cur);
    return chl_byte;
} /* end of m_read_byte */



/**
 * private function m_atoll
 *    transform given string to number
 *
 * @param[in]   const char  *achp_ptr           pointer to data
 * @param[in]   int         inp_length          length of data
 * @param[out]  char        **aachp_endptr      if given, point to end of number
 * @param[in]   int         inp_base            base
 * @return      long long
*/
static long long m_atoll( const char *achp_ptr, int inp_length,
                          char **aachp_endptr,  int inp_base    )
{
    // initialize some variables:
    long long illl_result = 0;
    int       inl_off     = 0;
    BOOL      bol_negative;
    int       inl_value;

    // check incoming data:
    if (    inp_base      != 0 
         && (    inp_base  < 2
              || inp_base  > 36 ) ) {
        if ( aachp_endptr != NULL ) {
            *aachp_endptr = (char*)achp_ptr;
        }
        return 0;
    }

    // check if positiv or negativ:
    switch ( achp_ptr[inl_off] ) {
        case '-':
            bol_negative = TRUE;
            inl_off++;
            break;
        case '+':
            bol_negative = FALSE;
            inl_off++;
            break;
        default:
            bol_negative = FALSE;
            break;
    }
    if ( inl_off >= inp_length ) {
        if ( aachp_endptr != NULL ) {
            *aachp_endptr = (char*)achp_ptr;
        }
        return 0;
    }

    /*
        get base:
            -> If base is 0, determine the real base based on the beginning on
                the number; octal numbers begin with "0", hexadecimal with "0x",
                and the others are considered octal.
    */
    if ( achp_ptr[inl_off] == '0' ) {
        if (    ( inp_base == 0 || inp_base == 16 )
             && inl_off + 2 < inp_length
             && ( achp_ptr[inl_off + 1] == 'x' || achp_ptr[inl_off + 1] == 'X' ) ) {
            /* hexadecimal */
            inp_base = 16;
            inl_off += 2;
        } else if ( inp_base == 0 ) {
            /* octal */
            inp_base = 8;
        }
    } else if ( inp_base == 0 ) {
        inp_base = 10;
    }

    if ( bol_negative == FALSE ) {
        // read positive number:
        for ( ; inl_off < inp_length; inl_off++ ) {
            inl_value = m_get_cvalue( achp_ptr[inl_off], inp_base );
            if ( inl_value == -1 ) {
                break;
            }
            illl_result = inp_base * illl_result + inl_value;
        }
    } else {
        // read negative number:
        for ( ; inl_off < inp_length; inl_off++ ) {
            inl_value = m_get_cvalue( achp_ptr[inl_off], inp_base );
            if ( inl_value == -1 ) {
                break;
            }
            illl_result = inp_base * illl_result - inl_value;
        }
    }

    if ( aachp_endptr != NULL ) {
        *aachp_endptr = (char*)&achp_ptr[inl_off];
    }
    return illl_result;
} // end of m_atoll


/**
 * private function m_get_cvalue
 *    get char value
 *
 * @param[in]   char    chp_sign
 * @param[in]   int     inp_base
*/
static int m_get_cvalue( char chp_sign, int inp_base )
{
    // initialize some variables:
    int inl_value;

    if ( chp_sign < '0' ) {
        return -1;
    }

    if ( '0' <= chp_sign && chp_sign <= '9' ) {
        inl_value = (int)(chp_sign - '0');
    } else if ( 'a' <= chp_sign && chp_sign <= 'z' ) {
        inl_value = (int)(chp_sign - 'a' + 10);
    } else if ( 'A' <= chp_sign && chp_sign <= 'Z' ) {
        inl_value = (int)(chp_sign - 'A' + 10);
    } else {
        return -1;
    }

    if ( inl_value >= inp_base ) {
        inl_value = -1;
    }
    return inl_value;
} // end of m_get_cvalue
