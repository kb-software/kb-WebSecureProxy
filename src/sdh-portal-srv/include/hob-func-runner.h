#ifndef HOB_FUNC_RUNNER_H
#define HOB_FUNC_RUNNER_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE:                                                               |*/
/*| -----                                                               |*/
/*|  hob-func-runner.h                                                  |*/
/*|                                                                     |*/
/*| Description:                                                        |*/
/*| ------------                                                        |*/
/*|  Declare the functions which will be used to call and run an rpc    |*/
/*|  function                                                           |*/
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

/**
* Run an RPC request.  The response is built during the run of this process.
*
* @param[in] adsp_json_rq the RPC request object pointer
* @param[in/out] adsp_json_rp the RPC response object pointer
*/
void m_rpc_run (dsd_jsonrpc_request *adsp_json_rq, dsd_jsonrpc_response *adsp_json_rp);

#endif