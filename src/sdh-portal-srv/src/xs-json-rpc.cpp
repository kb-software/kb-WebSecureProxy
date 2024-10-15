/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|   xs-json-rpc                                                       |*/
/*|   JF: Parses and process the JSON request and responses.            |*/
/*|       This will request the function caller to process the          |*/
/*|       requested method using the given parameters and return        |*/
/*|       the result.                                                   |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
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
#include "hob-json-rpc.h"
#include "hob-func-runner.h"

#define MAX_JSON_ERR_MSG_LEN 1024 //1K

//------R E Q U E S T

/**
* Create a new JSON-RPC request object.  This allocates memory and initialises all the fields
* which it can retrieve from the passed json object.
*
* @param[in] *adsp_hlclib the memory allocation struct
* @param[in] *dsd_json_object the json object
* @return the pointer to the allocated memory
*/
dsd_jsonrpc_request *m_new_json_request(struct dsd_hl_clib_1 *adsp_hlclib, dsd_json_object *adsp_json)
{
    dsd_jsonrpc_request *adsl_request;
    dsd_json_kv_pair *adsc_current_kv;

    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &adsl_request, sizeof(dsd_jsonrpc_request) );

    adsc_current_kv = m_get_kv_pair(adsp_json, "id");
    adsl_request->achrc_id = adsc_current_kv->achrc_value;
    adsl_request->szl_len_id = adsc_current_kv->szc_val_len;

    /*adsl_request->achrc_jsonrpc = m_get_kv_pair(adsp_json, "jsonrpc");*/
    adsc_current_kv = m_get_kv_pair(adsp_json, "jsonrpc");
    adsl_request->achrc_jsonrpc = adsc_current_kv->achrc_value;
    adsl_request->szl_len_jsonrpc = adsc_current_kv->szc_val_len;

    /*adsl_request->achrc_method = m_get_kv_pair(adsp_json, "method");*/
    adsc_current_kv = m_get_kv_pair(adsp_json, "method");
    adsl_request->achrc_method = adsc_current_kv->achrc_value;
    adsl_request->szl_len_method = adsc_current_kv->szc_val_len;

    /*adsl_request->achrc_params = m_get_kv_pair(adsp_json, "params");*/
    adsc_current_kv = m_get_kv_pair(adsp_json, "params");
    adsl_request->achrc_params = adsc_current_kv->achrc_value;
    adsl_request->szl_len_params = adsc_current_kv->szc_val_len;

    adsl_request->adsc_formal_param_list = m_new_arraylist(5, adsp_hlclib);

    m_parse_array(adsl_request->achrc_params, adsl_request->szl_len_params, adsl_request->adsc_formal_param_list, 0);

    adsl_request->adsc_hlc_lib = adsp_hlclib;

    return adsl_request;
}

/**
* Destroy the request object.  Free up the memory it occupied.
* @param[in] *adsp_json_rq the request to destroy.
*/
void m_destroy_json_request(dsd_jsonrpc_request *adsp_json_rq)
{
    if (adsp_json_rq == NULL)
        return;

    struct dsd_hl_clib_1 *adsp_hlclib_tmp = adsp_json_rq->adsc_hlc_lib;

    m_destory_arraylist(adsp_json_rq->adsc_formal_param_list);

    adsp_hlclib_tmp->amc_aux( adsp_hlclib_tmp->vpc_userfld, DEF_AUX_MEMFREE, &adsp_json_rq, 0 );
}


//------R E S P O N S E

/**
* Create a new JSON-RPC response object.  This allocates memory and initialises all the fields
* which it can retrieve from the passed request object.  The main RPC is performed in this
* part and the contents are filled depending on the result of the executed function.
*
* @param[in] *adsp_hlclib the memory allocation struct
* @param[in] *dsd_json_object the json object
* @return the pointer to the allocated memory
*/
dsd_jsonrpc_response *m_new_json_response(dsd_jsonrpc_request *adsp_json_rq)
{
    dsd_jsonrpc_response *adsl_response;
    struct dsd_hl_clib_1 *adsp_hlclib = adsp_json_rq->adsc_hlc_lib;

    //Alloc. for response
    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &adsl_response, sizeof(dsd_jsonrpc_response) );

    //Set HLCLIB
    adsl_response->adsc_hlc_lib = adsp_hlclib;

    //Init JSONRPC version
    adsl_response->achrc_jsonrpc = adsp_json_rq->achrc_jsonrpc;
    adsl_response->szc_len_jsonrpc = adsp_json_rq->szl_len_jsonrpc;

    //Init ID
    adsl_response->achrc_id = adsp_json_rq->achrc_id;
    adsl_response->szc_len_id = adsp_json_rq->szl_len_id;

    //--------------------R E S P O N S E   G E N E R A T I O N-----------
    m_rpc_run(adsp_json_rq, adsl_response);
    //--------------------------------------------------------------------

    return adsl_response;
}

/**
* Create a new JSON-RPC response object.  This allocates memory and initialises all the fields
* which it can retrieve from the passed request object.  The main RPC is performed in this
* part and the contents are filled depending on the result of the executed function.
*
* @param[in] *adsp_hlclib the memory allocation struct
* @param[in] *dsd_json_object the json object
* @return the pointer to the allocated memory
*/
dsd_jsonrpc_response *m_new_json_error_response(dsd_hl_clib_1 *adsp_hlc_lib, char* achrp_error_msg, int inp_error_code, char* achrp_id, size_t szp_id_len)
{
    dsd_json_error_structure *adsl_error;
    dsd_jsonrpc_response *adsl_response;

    //Alloc. for response
    adsp_hlc_lib->amc_aux( adsp_hlc_lib->vpc_userfld, DEF_AUX_MEMGET, &adsl_response, sizeof(dsd_jsonrpc_response) );

    //Set HLCLIB
    adsl_response->adsc_hlc_lib = adsp_hlc_lib;

    //Init JSONRPC version
    adsl_response->achrc_jsonrpc = "2.0";
    adsl_response->szc_len_jsonrpc = 3;

    //Init ID
    adsl_response->achrc_id = achrp_id;
    adsl_response->szc_len_id = szp_id_len;

    //Init Err Msg
    adsp_hlc_lib->amc_aux( adsp_hlc_lib->vpc_userfld, DEF_AUX_MEMGET, &(adsl_response->achrc_error), MAX_JSON_ERR_MSG_LEN );

    adsl_error = m_new_jsonrpc_error(adsp_hlc_lib, inp_error_code, achrp_error_msg, NULL); 
    m_serialise_error(adsl_error, adsl_response->achrc_error, &(adsl_response->szc_len_error));
    m_destroy_json_error(adsl_error, adsp_hlc_lib);

    return adsl_response;
}

/**
* Destroy the json response object by freeing up the memoey it used.
*
* @param[in] *adsp_json_rp the pointer to the memory to free
*/
void m_destroy_json_response(dsd_jsonrpc_response *adsp_json_rp)
{
    if (adsp_json_rp == NULL)
        return;

    struct dsd_hl_clib_1 *adsp_hlclib_tmp = adsp_json_rp->adsc_hlc_lib;

    adsp_hlclib_tmp->amc_aux( adsp_hlclib_tmp->vpc_userfld, DEF_AUX_MEMFREE, &(adsp_json_rp->achrc_error), 0 );
    adsp_hlclib_tmp->amc_aux( adsp_hlclib_tmp->vpc_userfld, DEF_AUX_MEMFREE, &adsp_json_rp, 0 );
}

/**
* Serlialise the response object to string.  The serialised string is put in the provided buffer and the length
* is set in the lenght pointer.
*
* @param[in] *adsp_json_resp the response object to serialise
* @param[in/out] *achrp_buffer the buffer to fill with the string
* @param[in/out] *szl_resp_len the length pointer to be set as the size of the string
*/
void m_serialise_to_string(dsd_jsonrpc_response *adsp_json_resp, char* achrp_buffer, size_t *szp_resp_len)
{
    //TODO Ensure length is not too much
    size_t szl_offset = 0;
    size_t szl_tmp;

    char achrl_tmp[1024];

    dsd_json_kv_pair adsl_kv_jsonrpc = {"jsonrpc", adsp_json_resp->achrc_jsonrpc, (size_t)7, (size_t)adsp_json_resp->szc_len_jsonrpc};
    dsd_json_kv_pair adsl_kv_id = {"id", adsp_json_resp->achrc_id, (size_t)2, (size_t)adsp_json_resp->szc_len_id};

    dsd_json_kv_pair dsl_kv_resp;

    //----------
    //RPC Version
    achrp_buffer[szl_offset] = '{';
    szl_offset++;
    for ( szl_tmp = 0; szl_tmp <= m_seralise_kv(&adsl_kv_jsonrpc, (char*)achrl_tmp, IE_JT_STRING); szl_tmp ++ )
    {
        achrp_buffer[szl_offset] = achrl_tmp[szl_tmp];
        szl_offset ++;
    }

    //RESULT OR ERROR
    if ( adsp_json_resp->achrc_error != NULL)
    {
        dsl_kv_resp.achrc_key = "error";
        dsl_kv_resp.achrc_value = adsp_json_resp->achrc_error;
        dsl_kv_resp.szc_key_len = (size_t)5;
        dsl_kv_resp.szc_val_len = (size_t)adsp_json_resp->szc_len_error;
    }
    else
    {
        dsl_kv_resp.achrc_key = "result";
        dsl_kv_resp.achrc_value = adsp_json_resp->achrc_result;
        dsl_kv_resp.szc_key_len = (size_t)6;
        dsl_kv_resp.szc_val_len = (size_t)adsp_json_resp->szc_len_result;
    }

    achrp_buffer[szl_offset] = ',';
    szl_offset++;
    for ( szl_tmp = 0; szl_tmp <= m_seralise_kv(&dsl_kv_resp, (char*)achrl_tmp, adsp_json_resp->iec_result_type); szl_tmp ++ )
    {
        achrp_buffer[szl_offset] = achrl_tmp[szl_tmp];
        szl_offset ++;
    }

    //ID
    if (adsp_json_resp->achrc_id != NULL)
    {
        achrp_buffer[szl_offset] = ',';
        szl_offset++;
        for ( szl_tmp = 0; szl_tmp <= m_seralise_kv(&adsl_kv_id, (char*)achrl_tmp, IE_JT_STRING); szl_tmp ++ )
        {
            achrp_buffer[szl_offset] = achrl_tmp[szl_tmp];
            szl_offset ++;
        }
    }

    achrp_buffer[szl_offset] = '}';
    szl_offset++;

    *szp_resp_len = szl_offset;
}

//-------------------------------E R R O R

/**
* Allocate memory for a new error object and set the details with the provided values.
* 
* @param[in] *adsp_hlclib the memory allocation function
* @param[in] inp_code the error code to set
* @param[in] *achrp_message the error message
* @param[in] *adsp_data the data object or NULL
*/
dsd_json_error_structure *m_new_jsonrpc_error(struct dsd_hl_clib_1 *adsp_hlclib,int inp_code, char* achrp_message, 
                                              dsd_json_object *adsp_data)
{
    dsd_json_error_structure *adsl_error;

    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &adsl_error, sizeof(dsd_json_error_structure) );

    adsl_error->inc_code = inp_code;
    adsl_error->achrc_message = achrp_message;
    adsl_error->adsc_data = adsp_data;

    return adsl_error;
}

/**
* Destroys the error object by freeing up the memory it was taking.
*
* @param[in] *adsp_json_error the error to destroy
* @param[in] *adsp_hlclib the allocation function
*/
void m_destroy_json_error(dsd_json_error_structure *adsp_json_error, dsd_hl_clib_1 *adsp_hlclib)
{
    if (adsp_json_error->adsc_data != NULL)
        m_destroy_json_obj(adsp_json_error->adsc_data);

    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMFREE, &adsp_json_error, 0 );
}

/**
* Serialise the error to string.  The data is put in the provided buffer and the length is set in the
* given number pointer.
*
* @param[in] *adsp_json_error the error to serialise
* @param[in] *achrp_buffer the buffer where to store the serialised string
* @param[in] *szl_resp_len the length of the string
*/
void m_serialise_error(dsd_json_error_structure *adsp_json_error, char* achrp_buffer, size_t *szl_resp_len)
{
    size_t szl_offset = 0;
    size_t szl_tmp;
    size_t szl_tmpc;
    size_t szl_dat_c;
    char achrl_data_buf[768];

    char achrl_num_tmp[10];
    char achrl_tmp[1024];
    
    ltoa(adsp_json_error->inc_code, achrl_num_tmp, 10);

    dsd_json_kv_pair adsl_kv_cod = {"code", achrl_num_tmp, (size_t)4, strlen(achrl_num_tmp)};
    dsd_json_kv_pair adsl_kv_msg = {"message", adsp_json_error->achrc_message, (size_t)7, strlen(adsp_json_error->achrc_message)};
    dsd_json_kv_pair adsl_kv_dat = {"data", "", (size_t)4, 0};

    dsd_json_kv_pair *adsl_tmp_kv;
    //----------

    //Fill the Data Object
    if (adsp_json_error->adsc_data != NULL)
    {
        for (szl_tmpc = 0; szl_tmpc < adsp_json_error->adsc_data->adsc_arraylist->szc_size; szl_tmpc ++)
        {
            adsl_tmp_kv = (dsd_json_kv_pair*)(m_get_element(adsp_json_error->adsc_data->adsc_arraylist ,szl_tmpc));

            for ( szl_tmp = 0; szl_tmp <= m_seralise_kv(adsl_tmp_kv, (char*)achrl_tmp, IE_JT_STRING); szl_tmp ++ )
            {
                achrl_data_buf[szl_dat_c] = achrl_tmp[szl_tmp];
                szl_dat_c ++;
            }

            achrl_data_buf[szl_dat_c] = ',';
            szl_dat_c++;
        }
    }

    //fill the normal buffer

    achrp_buffer[szl_offset] = '{';
    szl_offset++;
    for ( szl_tmp = 0; szl_tmp <= m_seralise_kv(&adsl_kv_cod, (char*)achrl_tmp, IE_JT_STRING); szl_tmp ++ )
    {
        achrp_buffer[szl_offset] = achrl_tmp[szl_tmp];
        szl_offset ++;
    }

    achrp_buffer[szl_offset] = ',';
    szl_offset++;
    for ( szl_tmp = 0; szl_tmp <= m_seralise_kv(&adsl_kv_msg, (char*)achrl_tmp, IE_JT_STRING); szl_tmp ++ )
    {
        achrp_buffer[szl_offset] = achrl_tmp[szl_tmp];
        szl_offset ++;
    }

    if (adsp_json_error->adsc_data != NULL)
    {
        achrp_buffer[szl_offset] = ',';
        szl_offset++;
        for ( szl_tmp = 0; szl_tmp <= m_seralise_kv(&adsl_kv_dat, (char*)achrl_tmp, IE_JT_MAP); szl_tmp ++ )
        {
            achrp_buffer[szl_offset] = achrl_tmp[szl_tmp];
            szl_offset ++;
        }
    }

    achrp_buffer[szl_offset] = '}';
    szl_offset++;

    *szl_resp_len = szl_offset;
}