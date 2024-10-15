#ifndef HOB_JSON_FUNC_SRVC_H
#define HOB_JSON_FUNC_SRVC_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE:                                                               |*/
/*| -----                                                               |*/
/*|  hob-json-func-runner.h                                             |*/
/*|                                                                     |*/
/*| Description:                                                        |*/
/*| ------------                                                        |*/
/*|  Declare the functions which will be called by the srpc service.    |*/
/*|  If the function does not exist an error is sent.                   |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|  James Farrugia, June/July 2012                                     |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

#ifndef HL_UNIX
    #include <windows.h>
#endif //HL_UNIX
#include <hob-arraylist.h>

#include "hob-json-rpc.h"

/*
* The inputs of all these methods are a json_rpc request object and a result buffer.  Thier return value
* is the type of response variable (enum).
*/

/**
* The ping service returns 'Server Online'.  This is used mainly to check if the server is online.  The Emulator will return
* also that is is the emulator, so this can also be used to ensure that the real server or the emulator is in use.
*/
ied_json_data_type m_rpcs_ping               (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* Simple echo service.
*/
ied_json_data_type m_rpcs_echo               (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* ---------------------------------------------------------------------------------------------------------------------
* Testing Functions
* ---------------------------------------------------------------------------------------------------------------------
**/

/**
* Simple adder service.
*/
ied_json_data_type m_rpcs_add                (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* Simple boolean tester service.
*/
ied_json_data_type m_rpcs_bool_test          (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* Simple max number finder service (array param tester).
*/
ied_json_data_type m_rpcs_max_num            (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* ---------------------------------------------------------------------------------------------------------------------
* Session & Settings Functions
* ---------------------------------------------------------------------------------------------------------------------
**/

/**
* Simple session testing over rpc
*/
ied_json_data_type m_rpcs_get_session        (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* A service to get the session of a user by passing the session id acquired from the WSP cookie
*/
ied_json_data_type m_rpcs_get_user_settings  (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* A service to change the user's password
*/
ied_json_data_type m_rpcs_change_password    (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* ---------------------------------------------------------------------------------------------------------------------
* WSG Functions
* ---------------------------------------------------------------------------------------------------------------------
**/

/**
* A service to send the user's bookmarks of the WebServerGate.
*/
ied_json_data_type m_rpcs_get_wsg_bookmarks  (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* A service to add a WebServerGate bookmark.
*/
ied_json_data_type m_rpcs_add_wsg_bookmark   (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* A service to remove a WebServerGate bookmark.
*/
ied_json_data_type m_rpcs_remove_wsg_bookmark   (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* ---------------------------------------------------------------------------------------------------------------------
* WFA Functions
* ---------------------------------------------------------------------------------------------------------------------
**/

/**
* A service to send the user's bookmarks of the WebFileAccess.
*/
ied_json_data_type m_rpcs_get_wfa_bookmarks   (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* A service to add a WebFileAccess bookmark.
*/
ied_json_data_type m_rpcs_add_wfa_bookmark    (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* A service to remove a WebFileAccess bookmark.
*/
ied_json_data_type m_rpcs_remove_wfa_bookmark (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);


/**
* ---------------------------------------------------------------------------------------------------------------------
* Generic Functions
* ---------------------------------------------------------------------------------------------------------------------
**/

/**
* A service to get the user's language setting
*/
ied_json_data_type m_rpcs_get_language       (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

/**
* A service to send a simple server timestamp to the client.  Second precision.
*/
ied_json_data_type m_rpcs_get_timestamp      (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error);

#endif