/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|   xs-json                                                           |*/
/*|   TH: parses events coming from the browser                         |*/
/*|   JF: Reusing parser but without the use of browser events          |*/
/*|       The JSON object has a generic key name and value rather than  |*/
/*|       a fixed set of possible event keys.                           |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|   Tobias Hofmann, March 2012                                        |*/
/*|   James Farrugia, June/July 2012                                    |*/
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
#include <hob-arraylist.h>

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

#include "hob-json.h"


static BOOL						m_jp_is_json_obj		( struct dsd_gather_i_1**, unsigned long long int );
PRIVATE BOOL					m_jp_has_valid_format	( struct dsd_gather_i_1**, struct dsd_json_object* );
PRIVATE int						m_jp_switch_value		( struct dsd_gather_i_1**, char*, int );
PRIVATE int						m_jp_get_number			( struct dsd_gather_i_1**, char*, int );
PRIVATE int						m_jp_get_null			( struct dsd_gather_i_1** );
PRIVATE int						m_jp_get_boolean		( struct dsd_gather_i_1**, char* );
PRIVATE int						m_jp_get_string			( struct dsd_gather_i_1**, char*, int );
PRIVATE BOOL					m_jp_get_array			( struct dsd_gather_i_1**, char*, int , int*);
static BOOL						m_add_pair			    ( struct dsd_json_object*, char*, int, char*, int );
PRIVATE char					m_get_byte				( struct dsd_gather_i_1** );
static char						m_read_byte				( struct dsd_gather_i_1** );
static long long				m_atoll					( const char*, int, char**, int );
static int						m_get_cvalue			( char, int );

/**
* Create a new JSON object by allocating memory and returning the pointer to it.  The arraylist is also created, 
* therefore memory has also been allocated for it.
*
* @param[in] *adsp_hlclib the pointer to the dsd_hl_clib_1 struct which is used for memory allocation.
*/
dsd_json_object* m_new_json_obj(struct dsd_hl_clib_1 *adsp_hlclib)
{
    dsd_json_object *dsl_object;
    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &dsl_object, sizeof(dsd_json_object) );
    dsl_object->adsc_arraylist = m_new_arraylist(10, adsp_hlclib);
    return dsl_object;
}

/**
* Create a new key-value pair by allocating memory and copying.  The reason is that the source is normally a series
* of gather structures which might not be in sequential order.
*
* @param[in] *adsp_hlclib the pointer to the dsd_hl_clib_1 struct which is used for memory allocation.
* @param[in] *achrp_key the key charachter buffer to be used.
* @param[in] szp_key_len the length of the key String
* @param[in] *achrp_value the value charachter buffer to be used.
* @param[in] szp_val_len the length of the value String
*/
dsd_json_kv_pair* m_new_json_kv_pair(struct dsd_hl_clib_1 *adsp_hlclib, char* achrp_key, size_t szp_key_len, 
                                     char* achrp_value, size_t szp_val_len)
{
    dsd_json_kv_pair *dsl_pair;
    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &dsl_pair, sizeof(dsd_json_kv_pair) );

    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &dsl_pair->achrc_key, szp_key_len );
    memcpy(dsl_pair->achrc_key, achrp_key, szp_key_len);
    dsl_pair->szc_key_len = szp_key_len;

    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &dsl_pair->achrc_value, szp_val_len );
    memcpy(dsl_pair->achrc_value, achrp_value, szp_val_len);
    dsl_pair->szc_val_len = szp_val_len;

    dsl_pair->szc_key_len = szp_key_len;
    dsl_pair->szc_val_len = szp_val_len;

    return dsl_pair;
}

/**
* Frees all the memory used by the given JSON object pointer.
*
* @param[in] *json_obj the object to be destroyed
*/
void m_destroy_json_obj(dsd_json_object* json_obj)
{
    if (json_obj == NULL)
        return;

    struct dsd_hl_clib_1 *adsp_hlclib_tmp;
    size_t szl_counter = 0;
    struct dsd_json_kv_pair *dsl_curr_kv;

    for (;szl_counter < json_obj->adsc_arraylist->szc_size; szl_counter++)
    {
        dsl_curr_kv = (struct dsd_json_kv_pair*)(m_get_element(json_obj->adsc_arraylist, szl_counter));
        m_destroy_json_kv_pair (json_obj->adsc_arraylist->adsp_hlclib, dsl_curr_kv);
    }
    adsp_hlclib_tmp = json_obj->adsc_arraylist->adsp_hlclib;

    m_destory_arraylist(json_obj->adsc_arraylist);
    adsp_hlclib_tmp->amc_aux( adsp_hlclib_tmp->vpc_userfld, DEF_AUX_MEMFREE, &json_obj, 0 );
}

/**
* Frees all the memory used by the given key-value pair pointer.
*
* @param[in] *adsp_hlclib the memory allocation struct
* @param[in] *adsp_json_kv the key-value pair to be destroyed
*/
void m_destroy_json_kv_pair(struct dsd_hl_clib_1 *adsp_hlclib, dsd_json_kv_pair *adsp_json_kv)
{
    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMFREE, &adsp_json_kv->achrc_key, 0 );
    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMFREE, &adsp_json_kv->achrc_value, 0 );
    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMFREE, &adsp_json_kv, 0 );
}

/**
* Returns a pointer to a key-value pair object in the json object provided.  The pair is found by comparing
* the given key, and the keys in the JSON object
*
* @param[in] *json_obj the object to be searched
* @param[in] *achrp_key the key of the object to be retrieved
* @return *dsd_json_kv_pair pointer to the found pair or NULL if not found
*/
dsd_json_kv_pair *m_get_kv_pair(dsd_json_object *adsp_json_obj, const char *achrp_key)
{
    size_t szl_counter = 0;
    struct dsd_json_kv_pair *dsl_curr_kv;
    int inl_key_len = strlen(achrp_key);
    char achrc_tmp_str[256];

    for (; szl_counter < adsp_json_obj->adsc_arraylist->szc_size; szl_counter++)
    {
        dsl_curr_kv = (struct dsd_json_kv_pair*)(m_get_element(adsp_json_obj->adsc_arraylist, szl_counter));
        if ((size_t)inl_key_len != dsl_curr_kv->szc_key_len )
            continue;

        memcpy(achrc_tmp_str, dsl_curr_kv->achrc_key, dsl_curr_kv->szc_key_len);
        achrc_tmp_str[dsl_curr_kv->szc_key_len] = 0;
        if ( strcmp (achrc_tmp_str, achrp_key) == 0)
            return dsl_curr_kv;
    }
    return NULL;
}

/**
* Serialises a key-value pair to a string.  The string is ready to be added to a JSON object serialisation.
*
* @param[in] *adsp_kv_pair the pair to serialise
* @param[in] *achrp_buffer the buffer to which to write the string
* @param[in] ie_type the type of data to be written, used to determine the opening and closing characters of the value
* @return size_t the size of the finished string
*/
size_t m_seralise_kv(dsd_json_kv_pair *adsp_kv_pair, char *achrp_buffer, enum ied_json_data_type ie_type)
{
    size_t szl_offset = 0;
    size_t szl_tmp_c;

    achrp_buffer[0] = '"';
    szl_offset ++;
    for (szl_tmp_c = 0; szl_tmp_c < adsp_kv_pair->szc_key_len; szl_tmp_c ++)
    {
        achrp_buffer[szl_offset] = adsp_kv_pair->achrc_key[szl_tmp_c];
        szl_offset ++;
    }

    achrp_buffer[szl_offset] = '"';
    szl_offset ++;
    achrp_buffer[szl_offset] = ':';
    szl_offset ++;
    achrp_buffer[szl_offset] = (ie_type == IE_JT_STRING)?'"' : (ie_type == IE_JT_ARRAY)?'[' : (ie_type == IE_JT_MAP)?'{':' ';
    szl_offset ++;
    
    for (szl_tmp_c = 0; szl_tmp_c < adsp_kv_pair->szc_val_len; szl_tmp_c ++)
    {
        achrp_buffer[szl_offset] = adsp_kv_pair->achrc_value[szl_tmp_c];
        szl_offset ++;
    }

    achrp_buffer[szl_offset] = (ie_type == IE_JT_STRING)?'"' : (ie_type == IE_JT_ARRAY)?']' : (ie_type == IE_JT_MAP)?'}':' ';

    return szl_offset;
}

//=====================================================================================================================

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
BOOL m_parse_json( struct dsd_gather_i_1* adsp_data, unsigned long long int ulli_event_len, struct dsd_json_object* adsp_evt)
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
		if( ((char*)(&adsl_temp->achc_ginp_cur[1])) == adsl_temp->achc_ginp_end)
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
PRIVATE BOOL m_jp_has_valid_format(struct dsd_gather_i_1 **aadsp_data, struct dsd_json_object *adsp_evt)
{
    char chl_cur;

    BOOL bl_keyword = TRUE;            /* indicates, that we are parsing a keyword */
    BOOL bl_parsing_done = FALSE;      /* return value for the value parsing functions */
    BOOL bl_ret;
    
    char             chrl_key[8];               /* keyword buffer        */
    int              inl_key;                   /* length of cur keyword */
    char             chrl_value[512];            /* value buffer          */
    int              inl_value;                 /* length of cur value   */

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

                    if ( (int)sizeof(chrl_key) < 1 ) return FALSE;
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
                    //if( !(inrg_valid_values[(int)ienl_ktype] & JSON_ARRAY) ) return FALSE;   //###HERE
                    m_get_byte(aadsp_data); /* step one char */
                    bl_parsing_done = m_jp_get_array( aadsp_data, chrl_value, (int)sizeof(chrl_value), &inl_value);
                    break;
                case '{':
                    /* definition: if u want to parse an object, set    */
                    /* the pointer to the char behind the opening '{'    */
                    /* ATTENTION: Recursion not fully implemented,        */
                    /* because generic object creation not supported    */
                    if(bl_parsing_done) return FALSE;
                    //if( !(inrg_valid_values[(int)ienl_ktype] & JSON_OBJECT) ) return FALSE;   //###HERE
                    m_get_byte(aadsp_data); /* step one char */
                    bl_parsing_done = m_jp_has_valid_format(aadsp_data, NULL); /* insert pointer to memory if recursion */
                    break;
                case '}':
                    if(bl_parsing_done)
                    {
                        bl_ret = m_add_pair( adsp_evt, chrl_key, inl_key, chrl_value, inl_value );   //###HERE  //###FILL_EVT
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
                        bl_ret = m_add_pair( adsp_evt, chrl_key, inl_key, chrl_value, inl_value );   //###HERE  //###FILL_EVT
                        if( !bl_ret ) return FALSE;
                    }
                    break;
                default:
                    if(bl_parsing_done) return FALSE;
                    inl_value = m_jp_switch_value( aadsp_data, chrl_value, (int)sizeof(chrl_value));   //###HERE
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

/**
* Determines the type of data of the provided char buffer.
* 
* @param[in] *achrp_data the data buffer to analyse
* @return ied_json_data_type the type of data
*/
ied_json_data_type m_determine_type (const char *achrp_data)
{
    switch( achrp_data[0] )
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
            return IE_JT_NUMBER;
        case 'n':
            return IE_JT_NULL;
        case 't':
        case 'f':
            return IE_JT_BOOLEAN;
        case '"':
            return IE_JT_STRING;
        case '[' :
            return IE_JT_ARRAY;
        case '{' :
            return IE_JT_MAP;
        default:
            return IE_JT_UNKNOWN;
    }
}

/* ToDo: Add Description + Tests */
PRIVATE int m_jp_switch_value(struct dsd_gather_i_1 **aadsp_data, char *achp_buffer, int inp_bsize )
{
    /* when we parse a value, we should take care of following rules. it can be:    */
    /* a number, with + or - as indicator, floating point or exponent                */
    /* 'null'                                                                        */
    /* 'true' or 'false'                                                            */
    /* a string like the keyword string                                                */

    switch( m_determine_type( (((struct dsd_gather_i_1*)(*aadsp_data))->achc_ginp_cur) ) )
    {
        case IE_JT_NUMBER   : return( m_jp_get_number( aadsp_data, achp_buffer, inp_bsize ) );
        case IE_JT_NULL     : return( m_jp_get_null( aadsp_data ) );
        case IE_JT_BOOLEAN  : return( m_jp_get_boolean( aadsp_data, achp_buffer ) );
        case IE_JT_STRING   : return( m_jp_get_string( aadsp_data, achp_buffer, inp_bsize ) );
        case IE_JT_UNKNOWN  : default: return -1;
    }
}

//------- T Y P E   P A R S E R S -----------------------------------
/*
* The type parsers all have a similar system.  The first input is the data to be parsed, the sencond argument
* is the length of this data while the last one varies.  It is always the type of which the output is expected,
* and it is always a pointer.
*/

/**
* Parses the data into a numeric value.
*/
void m_get_as_number(const char *achrp_data, size_t szp_data_len, long long *allp_out_num)
{
    *allp_out_num = m_atoll( achrp_data, szp_data_len, NULL, 10 );
}

/**
* Parses the data into a boolean value.
*/
void m_get_as_bool(const char *achrp_data, size_t szp_data_len, BOOL *abop_out)
{
    struct dsd_gather_i_1 dsl_hlclib_tmp;
    struct dsd_gather_i_1 *adsl_gath_ptr;
    char   achrl_tmp_buf[2];

    adsl_gath_ptr = &dsl_hlclib_tmp;

    dsl_hlclib_tmp.achc_ginp_cur = (char*)achrp_data;
    dsl_hlclib_tmp.achc_ginp_end = (char*)achrp_data + szp_data_len;
    dsl_hlclib_tmp.adsc_next = NULL;

    if ( m_jp_get_boolean(&adsl_gath_ptr, (char*)achrl_tmp_buf) )
    {
        *abop_out = (achrl_tmp_buf[0] == '1')? TRUE : FALSE;
        return;
    }

    *abop_out = FALSE;
}

/**
* Parses the data into a string value.
*/
void m_get_as_string(const char *achrp_data, size_t szp_data_len, char *achrp_out)
{
    size_t szl_t = 1;
    size_t szl_o = 0;

    for (; szl_t < szp_data_len - 1; szl_t ++, szl_o ++)
        achrp_out[szl_o] = achrp_data[szl_t];
}

/**
* Parses the data into an arraylist.
*/
void m_get_as_arraylist(const char *achrp_data, size_t szp_data_len, dsd_arraylist *adsp_out, char chp_c1_b)
{
    m_parse_array(achrp_data, szp_data_len, adsp_out, chp_c1_b);
}

/**
* Parses the data into a JSON object
*/
void m_get_as_jsonobject(const char *achrp_data, size_t szp_data_len, dsd_json_object *adsl_json_obj)
{
    dsd_gather_i_1 dsl_tmp = {NULL, (char *)achrp_data, (char *)(achrp_data + szp_data_len)};
    m_parse_json(&dsl_tmp, szp_data_len, adsl_json_obj);
}

//------- [ E N D ]   T Y P E   P A R S E R S -----------------------------------

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
PRIVATE BOOL m_jp_get_array(struct dsd_gather_i_1 **aadsp_data, char *achp_buffer, int inp_bsize, int *inp_len)
{
    char chl_cur;
    int inl_bracket_count = 1;

    *inp_len = 0;
    if(achp_buffer == NULL || inp_bsize == 0 ) return FALSE;

    while(*aadsp_data)
    {
        chl_cur = m_read_byte(aadsp_data);

        if ( chl_cur == '[' )
            inl_bracket_count ++;
        else if ( chl_cur == ']' )
            inl_bracket_count --;

        if (inl_bracket_count > 0)
        {
            achp_buffer [ *inp_len ] = chl_cur;
            (*inp_len) ++;
        }


        if (inl_bracket_count == 0)
            return TRUE;

        m_get_byte(aadsp_data);
    }
    return FALSE;
}

/**
* Parses an array string into individual elements.  The original string remains unmodified (and must remain so)
* while pointers to the end of each parameters are added to the formal list.  In order to get a particualr
* parameter, one must start at the end of the one before it (or the beginning of the string in it's the first
* one) and move up to the next pointer.  This essentially works much like the gather structure.
*
* @param[in] *achrp_data the main array char buffer
* @param[in] szp_data_len the length of the data buffer
* @param[in/out] *adsp_formal_list the arraylist to fill with pointers
*/
void m_parse_array (const char *achrp_data, size_t szp_data_len, dsd_arraylist *adsp_formal_list, char chp_c1_b)
{
    size_t szl_g_count = 0;
    size_t szl_offset = 0;
    int iml_bracket_count = 0;
    char chrl_current[512];

    for ( ; szl_g_count < szp_data_len; szl_g_count++ )
    {
        if ( achrp_data[szl_g_count] == '[' || achrp_data[szl_g_count] == '{' )
            iml_bracket_count ++;
        else if ( achrp_data[szl_g_count] == ']' || achrp_data[szl_g_count] == '}' )
            iml_bracket_count --;

        if ( achrp_data[szl_g_count] == ',' && (chp_c1_b == 1? 1:iml_bracket_count == 0) )
        {
            //Add to arraylist, reset offset
            m_add_element( adsp_formal_list, (void*)(&(achrp_data[szl_g_count])));
            szl_offset = 0;
            continue;
        }

        chrl_current[szl_offset] = achrp_data[szl_g_count];

        szl_offset ++;
    }
    m_add_element( adsp_formal_list, (void*)(&(achrp_data[szl_g_count])));//ADD a pointer to the end of last elem
}

/**
 * private function m_add_pair
 * fill event structure with given key/value pair
 *
 * @param[in/out] dsd_brower_event *adsp_evt    event structure
 * @param[in]     ied_be_keys      ienp_type    key type
 * @param[in]     char             *achp_value  value
 * @param[in]     int              inp_length   length of value
 * @return        BOOL
*/  //WAS:m_jp_fill_event
static BOOL m_add_pair( struct dsd_json_object *adsp_evt,
                          char *achp_key, int inp_key_len, char *achp_value, int inp_length )
{
    dsd_json_kv_pair *dsl_pair = m_new_json_kv_pair(adsp_evt->adsc_arraylist->adsp_hlclib, achp_key, inp_key_len, achp_value, inp_length);
    m_add_element(adsp_evt->adsc_arraylist, dsl_pair);

    return TRUE;
} /* end of m_add_pair */


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
