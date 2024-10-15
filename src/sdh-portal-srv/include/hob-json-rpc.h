#ifndef HOB_JSON_RPC_H
#define HOB_JSON_RPC_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE:                                                               |*/
/*| -----                                                               |*/
/*|  hob-json-rpc.h                                                     |*/
/*|                                                                     |*/
/*| Description:                                                        |*/
/*| ------------                                                        |*/
/*|  Declare the functions and structs which represent the formal json  |*/
/*|  rpc request and response.                                          |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|  James Farrugia, June/July 2012                                     |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

#include "hob-json.h"
#include "hob-arraylist.h"

/**
* The JSON structure which represents a formal JSON RPC request.  The params is a char buffer 
* representing the full parameter array as a string as it was received from the client while
* the formal parameter list is an arraylist with pointers to the end of every parameter (which
* are separated by commas, as in the jsonrpc spec).
*/
typedef struct dsd_jsonrpc_request
{
    char *achrc_jsonrpc;
    char *achrc_method;
    char *achrc_params;
    char *achrc_id;

    size_t szl_len_jsonrpc;
    size_t szl_len_method;
    size_t szl_len_params;
    size_t szl_len_id;

    dsd_arraylist *adsc_formal_param_list;

    struct dsd_hl_clib_1 *adsc_hlc_lib;
} dsd_jsonrpc_request;

/**
* A JSON struct represents the request object.  This is according to the spec.  Only one of
* the error or result is sent.  An error is sent if and only if after the parsing, it has a
* code of any vlue except -1.  (some negative values are used as standard error codes and only -1 is sensible)
* Error code -1 basically means uninitialised error struct, therefore no error
*/
typedef struct dsd_jsonrpc_response
{
    char *achrc_jsonrpc;
    char *achrc_result;
    char *achrc_error;
    char *achrc_id;

    size_t szc_len_jsonrpc;
    size_t szc_len_result;
    size_t szc_len_error;
    size_t szc_len_id;

    ied_json_data_type iec_result_type;

    struct dsd_hl_clib_1 *adsc_hlc_lib;
} dsd_jsonrpc_response;

/**
* Represents a formal JSON-RPC error.  This contains the code number, a pointer to the message string and a pointer
* to the (optional) data element.
*/
typedef struct dsd_json_error_structure
{
    int inc_code;
    char *achrc_message;
    dsd_json_object *adsc_data;
} dsd_json_error_structure;


//-------------------------------------------R E Q U E S T

/**
* Create a new JSON-RPC request object.  This allocates memory and initialises all the fields
* which it can retrieve from the passed json object.
*
* @param[in] *adsp_hlclib the memory allocation struct
* @param[in] *dsd_json_object the json object
* @return the pointer to the allocated memory
*/
dsd_jsonrpc_request *m_new_json_request(struct dsd_hl_clib_1 *adsp_hlclib, dsd_json_object *adsp_json);

/**
* Destroy the request object.  Free up the memory it occupied.
* @param[in] *adsp_json_rq the request to destroy.
*/
void m_destroy_json_request(dsd_jsonrpc_request *adsp_json_rq);

//-------------------------------------------R E S P O N S E

/**
* Create a new JSON-RPC response object.  This allocates memory and initialises all the fields
* which it can retrieve from the passed request object.  The main RPC is performed in this
* part and the contents are filled depending on the result of the executed function.
*
* @param[in] *adsp_hlclib the memory allocation struct
* @param[in] *dsd_json_object the json object
* @return the pointer to the allocated memory
*/
dsd_jsonrpc_response *m_new_json_response(dsd_jsonrpc_request *adsp_json_rq);

/**
* Create a new JSON-RPC response object.  This allocates memory and initialises all the fields
* which it can retrieve from the passed request object.  The main RPC is performed in this
* part and the contents are filled depending on the result of the executed function.
*
* @param[in] *adsp_hlclib the memory allocation struct
* @param[in] *dsd_json_object the json object
* @return the pointer to the allocated memory
*/
dsd_jsonrpc_response *m_new_json_error_response(dsd_hl_clib_1 *adsp_hlc_lib, char* achrp_error_msg, int inp_error_code, char* achrp_id, size_t szp_id_len);

/**
* Destroy the json response object by freeing up the memoey it used.
*
* @param[in] *adsp_json_rp the pointer to the memory to free
*/
void m_destroy_json_response(dsd_jsonrpc_response *adsp_json_rp);

/**
* Serlialise the response object to string.  The serialised string is put in the provided buffer and the length
* is set in the lenght pointer.
*
* @param[in] *adsp_json_resp the response object to serialise
* @param[in/out] *achrp_buffer the buffer to fill with the string
* @param[in/out] *szl_resp_len the length pointer to be set as the size of the string
*/
void m_serialise_to_string(dsd_jsonrpc_response *adsp_json_resp, char* achrp_buffer, size_t *szl_resp_len);

//------E R R O R
/**
* Allocate memory for a new error object and set the details with the provided values.
* 
* @param[in] *adsp_hlclib the memory allocation function
* @param[in] inp_code the error code to set
* @param[in] *achrp_message the error message
* @param[in] *adsp_data the data object or NULL
*/
dsd_json_error_structure *m_new_jsonrpc_error(struct dsd_hl_clib_1 *adsp_hlclib, int inp_code, char* achrp_message, dsd_json_object *adsp_data);

/**
* Destroys the error object by freeing up the memory it was taking.
*
* @param[in] *adsp_json_error the error to destroy
* @param[in] *adsp_hlclib the allocation function
*/
void m_destroy_json_error(dsd_json_error_structure *adsp_json_error, struct dsd_hl_clib_1 *adsp_hlclib);

/**
* Serialise the error to string.  The data is put in the provided buffer and the length is set in the
* given number pointer.
*
* @param[in] *adsp_json_error the error to serialise
* @param[in] *achrp_buffer the buffer where to store the serialised string
* @param[in] *szl_resp_len the length of the string
*/
void m_serialise_error(dsd_json_error_structure *adsp_json_error, char* achrp_buffer, size_t *szl_resp_len);

#endif