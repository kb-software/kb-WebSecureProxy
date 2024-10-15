/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE                                                                |*/
/*| =======                                                             |*/
/*|   xs-func-runner                                                    |*/
/*|   The function caller for the RPC                                   |*/
/*|                                                                     |*/
/*| Author                                                              |*/
/*| ======                                                              |*/
/*|   James Farrugia June/July 2012                                     |*/
/*|                                                                     |*/
/*| Copyright                                                           |*/
/*| =========                                                           |*/
/*|   HOB GmbH 2012                                                     |*/
/*|                                                                     |*/ 
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes                                                            |*/
/*+---------------------------------------------------------------------+*/
#include <stdio.h>
#include "hob-func-runner.h"
#include "hob-json-func-service.h"
#include "hob-json-rpc.h"

/*+---------------------------------------------------------------------+*/
/*| Defines                                                             |*/
/*+---------------------------------------------------------------------+*/
#define MAX_RESULT_LENGTH 4608 //4.5Kb
#define MAX_METHOD_NAME_LENGTH 1024 //1k

/**
* Calls a function by name.  This function has to know all the rpc-callable function in the function service
* file.  If there is no mathcing function, an error is set in the response object.
*
* @param[in] *adsp_json_rq the request object
* @param[in] *achrp_m_name the name of the function
* @param[in] *achrp_result_buffer the buffer where to place the result
* @param[in] *adsp_error_struct the error structure to be set if there is an error
*/
static ied_json_data_type m_call (dsd_jsonrpc_request *adsp_json_rq, char *achrp_m_name, 
                    char *achrp_result_buffer, dsd_json_error_structure *adsp_error_struct);

//================================================================

/**
* Run an RPC request.  The response is built during the run of this process.
*
* @param[in] adsp_json_rq the RPC request object pointer
* @param[in/out] adsp_json_rp the RPC response object pointer
*/
void m_rpc_run (dsd_jsonrpc_request *adsp_json_rq, dsd_jsonrpc_response *adsp_json_rp)
{
    char chrl_result_buff[MAX_RESULT_LENGTH];
    char chrl_method[MAX_METHOD_NAME_LENGTH];
    dsd_json_error_structure *adsl_error;
    size_t szl_count = 0;

    adsl_error = m_new_jsonrpc_error(adsp_json_rq->adsc_hlc_lib, -1, "", NULL); //ERROR CODE -1 = NO ERROR

    for (; szl_count < adsp_json_rq->szl_len_method; szl_count ++)
        chrl_method[szl_count] = adsp_json_rq->achrc_method[szl_count];

    chrl_method[szl_count] = 0;
    adsp_json_rp->iec_result_type   = m_call (adsp_json_rq, chrl_method, chrl_result_buff, adsl_error);
    adsp_json_rp->achrc_result      = chrl_result_buff;
    adsp_json_rp->szc_len_result    = strlen(chrl_result_buff);

    if (adsl_error != NULL && adsl_error->inc_code != -1)//DO NOT set it as '< 0'because standard rpc errors are negative numbers, so -1 is 'alone'
    {
        m_serialise_error(adsl_error, chrl_result_buff, &(adsp_json_rp->szc_len_error));
        adsp_json_rp->achrc_error = chrl_result_buff;
    }
    else
        adsp_json_rp->achrc_error = NULL;

    m_destroy_json_error(adsl_error, adsp_json_rq->adsc_hlc_lib);
}

/**
* Run an RPC request.  The response is built during the run of this process.
*
* @param[in] adsp_json_rq the RPC request object pointer
* @param[in/out] adsp_json_rp the RPC response object pointer
*/
static ied_json_data_type m_call (dsd_jsonrpc_request *adsp_json_rq, char *achrp_m_name, 
                    char *achrp_result_buffer, dsd_json_error_structure *adsp_error_struct)
{
    if (strcmp(achrp_m_name, "m_rpcs_ping") == 0)
    {
        return m_rpcs_ping(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_echo") == 0)
    {
        return m_rpcs_echo(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_add") == 0)
    {
        return m_rpcs_add(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_bool_test") == 0)
    {
        return m_rpcs_bool_test(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_max_num") == 0)
    {
        return m_rpcs_max_num(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_get_session") == 0)
    {
        return m_rpcs_get_session(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_get_user_settings") == 0)
    {
        return m_rpcs_get_user_settings(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_get_timestamp") == 0)
    {
        return m_rpcs_get_timestamp(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_get_wsg_bookmarks") == 0)
    {
        return m_rpcs_get_wsg_bookmarks(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_add_wsg_bookmark") == 0)
    {
        return m_rpcs_add_wsg_bookmark(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_remove_wsg_bookmark") == 0)
    {
        return m_rpcs_remove_wsg_bookmark(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_get_language") == 0)
    {
        return m_rpcs_get_language(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_get_wfa_bookmarks") == 0)
    {
        return m_rpcs_get_wfa_bookmarks(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_add_wfa_bookmark") == 0)
    {
        return m_rpcs_add_wfa_bookmark(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_remove_wfa_bookmark") == 0)
    {
        return m_rpcs_remove_wfa_bookmark(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else if (strcmp(achrp_m_name, "m_rpcs_change_password") == 0)
    {
        return m_rpcs_change_password(adsp_json_rq, achrp_result_buffer, adsp_error_struct);
    }
    else
    {
        adsp_error_struct->achrc_message    = "Function does not exist";
        adsp_error_struct->inc_code         = -32601;
        adsp_error_struct->adsc_data        = NULL;
        return IE_JT_ERROR;
    }
}