#ifndef _HOB_JSON_RPC_H
#define _HOB_JSON_RPC_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE:                                                               |*/
/*| -----                                                               |*/
/*|  hob-json.h                                                         |*/
/*|                                                                     |*/
/*| Description:                                                        |*/
/*| ------------                                                        |*/
/*|  defines the JSON objects and key-value pairs and function to       |*/
/*|  work with them.                                                    |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|  James Farrugia, June/July 2012                                     |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

#include <hob-arraylist.h>

/** An enum containing the possible types of data transferred using JSON */
enum ied_json_data_type {IE_JT_NUMBER, IE_JT_BOOLEAN, IE_JT_STRING, IE_JT_ARRAY, IE_JT_MAP, IE_JT_NULL, IE_JT_UNKNOWN, IE_JT_ERROR};

/**
* A struct describing a key-value pair.  A JSON object is made up on one or more of these.
* The value is always stored as a char array and only parsed to its value only when needed
* to avoid complicated code and unecessary processing and memory.
*/
typedef struct dsd_json_kv_pair {
    char *achrc_key;
    char *achrc_value;
    
    size_t szc_key_len;
    size_t szc_val_len;

} dsd_json_kv_pair;

/**
* The JSON object is only a wrapper for a list of key-value pairs.  This array list stores
* pointers to a number of key-value pairs.
*/
typedef struct dsd_json_object {
    dsd_arraylist *adsc_arraylist;
} dsd_json_object;

/**
* Create a new JSON object by allocating memory and returning the pointer to it.  The arraylist is also created, 
* therefore memory has also been allocated for it.
*
* @param[in] *adsp_hlclib the pointer to the dsd_hl_clib_1 struct which is used for memory allocation.
*/
dsd_json_object* m_new_json_obj(struct dsd_hl_clib_1 *adsp_hlclib);

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
dsd_json_kv_pair* m_new_json_kv_pair(struct dsd_hl_clib_1 *adsp_hlclib, const char* achrp_key, size_t szp_key_len, 
                                     const char* achrp_value, size_t szp_val_len);

/**
* Frees all the memory used by the given JSON object pointer.
*
* @param[in] *json_obj the object to be destroyed
*/
void m_destroy_json_obj(dsd_json_object* json_obj);

/**
* Frees all the memory used by the given key-value pair pointer.
*
* @param[in] *adsp_hlclib the memory allocation struct
* @param[in] *adsp_json_kv the key-value pair to be destroyed
*/
void m_destroy_json_kv_pair(struct dsd_hl_clib_1 *adsp_hlclib, dsd_json_kv_pair *adsp_json_kv);

/**
* Returns a pointer to a key-value pair object in the json object provided.  The pair is found by comparing
* the given key, and the keys in the JSON object
*
* @param[in] *json_obj the object to be searched
* @param[in] *achrp_key the key of the object to be retrieved
* @return *dsd_json_kv_pair pointer to the found pair or NULL if not found
*/
dsd_json_kv_pair *m_get_kv_pair(dsd_json_object *adsp_json_obj, const char *achrp_key);

/**
* Serialises a key-value pair to a string.  The string is ready to be added to a JSON object serialisation.
*
* @param[in] *adsp_kv_pair the pair to serialise
* @param[in] *achrp_buffer the buffer to which to write the string
* @param[in] ie_type the type of data to be written, used to determine the opening and closing characters of the value
* @return size_t the size of the finished string
*/
size_t m_seralise_kv(dsd_json_kv_pair *adsp_kv_pair, char *achrp_buffer, enum ied_json_data_type ie_type);

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
void m_parse_array (const char *achrp_data, size_t szp_data_len, dsd_arraylist *adsp_formal_list, char chp_c1_b);

/**
* Determines the type of data of the provided char buffer.
* 
* @param[in] *achrp_data the data buffer to analyse
* @return ied_json_data_type the type of data
*/
ied_json_data_type m_determine_type (const char *achrp_data);

//------- T Y P E   P A R S E R S -----------------------------------
/*
* The type parsers all have a similar system.  The first input is the data to be parsed, the sencond argument
* is the length of this data while the last one varies.  It is always the type of which the output is expected,
* and it is always a pointer.
*/

/**
* Parses the data into a numeric value.
*/
void m_get_as_number(const char*, size_t szp_data_len, long long int*);

/**
* Parses the data into a boolean value.
*/
void m_get_as_bool(const char*, size_t szp_data_len, BOOL *);

/**
* Parses the data into a string value.
*/
void m_get_as_string(const char*, size_t szp_data_len, char *);

/**
* Parses the data into an arraylist.
*/
void m_get_as_arraylist(const char*, size_t szp_data_len, struct dsd_arraylist *, char chp_c1_b);

/**
* Parses the data into a JSON object
*/
void m_get_as_jsonobject(const char*, size_t szp_data_len, struct dsd_json_object *);

//------- [ E N D ]   T Y P E   P A R S E R S -----------------------------------

#ifdef __cplusplus
     extern "C"
#endif
BOOL m_parse_json( struct dsd_gather_i_1*, unsigned long long int, struct dsd_json_object* );

#ifdef _TEST
	#define PRIVATE extern
#else
	#define PRIVATE static
#endif

#endif