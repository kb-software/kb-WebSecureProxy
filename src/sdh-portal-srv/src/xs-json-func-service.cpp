
#include <stdio.h>
#include <time.h>

//#include "ds_session.h"
#include "hob-json-func-service.h"
#include "hob-json-rpc.h"
#include <ds_wsp_helper.h>
#include <ds_hstring.h>
#include <ds_hvector.h>
#include <ds_usercma.h>
#include <ds_authenticate.h>
#include <ds_portlet.h>
#include <ds_bookmark.h>
#include <dsd_wfa_bmark.h>

#define MAX_ARRAY_STR_LEN 3072 //3K
#define MAX_MAP_STR_LEN 3072 //3K
#define MAX_STR_PAR_LENGTH 1024

#define MAX_PORTLET_NAME_LEN 256
#define MAX_PORTLIST_LEN 1024
#define MAX_PAGELIST_LEN 1024

#define MAX_WSG_BK_URL_LEN 256
#define MAX_WSG_BK_NAME_LEN 256
#define MAX_WSG_BK_LIST_LEN 1024

#define MAX_WFA_BK_USER_LEN 256
#define MAX_WFA_BK_PASS_LEN 256
#define MAX_WFA_BK_DOMN_LEN 256
#define MAX_WFA_BK_LIST_LEN 1024

#define MAX_PASS_LEN 512

//A struct to group the 4 necessary items for auth
typedef struct ds_auth_unit
{
    ds_wsp_helper dsl_wsp_helper;     // wsp helper class
    dsd_auth_t dsl_auth_t;
    ds_authenticate ds_ident;   // authentication class
    ds_usercma dsl_usr_details;
} ds_auth_unit;

/**
* Gets a particualr item from an array string.  The String is "tokenised" at pointers stored in the
* formal parameter list.  The retrieved parameter is then stored in the passed buffer pointer.
*
* @param[in] *adsp_alist the pointer array
* @param[in/out] *achrp_buffer the buffer where to place the aqcuired string
* @param[in] szp_max_len the maximum expected/allowed length of the paramter
* @param[in] szp_param_index the index of the parameter in the param array (NOT the index of the pointer in the formal arraylist)
* @return the size of the acquired string
*/
static size_t m_get_item_from_arr_str(char *achrp_arr_str, dsd_arraylist *adsp_alist, char *achrp_buffer, size_t szp_max_len, size_t szp_param_index);

/**
* Gets a particualr parameter from the parameter array string.  The String is "tokenised" at pointers stored in the
* formal parameter list.  The retrieved parameter is then stored in the passed buffer pointer.
*
* @param[in] *adsp_json_rq the request object which has the array string and pointer array
* @param[in/out] *achrp_buffer the buffer where to place the aqcuired string
* @param[in] szp_max_len the maximum expected/allowed length of the paramter
* @param[in] szp_param_index the index of the parameter in the param array (NOT the index of the pointer in the formal arraylist)
* @return the size of the acquired string
*/
static size_t m_get_param(dsd_jsonrpc_request *adsp_json_rq, char *achrp_buffer, size_t szp_max_len, size_t szp_param_index);

/**
* Get the parameter from the array by index, parse to boolean and place in the output.
*
* @param[in] *adsp_json_rq the request object
* @param[in/out] *abop_out the boolean output pointer
* @param[in] szp_param_index the parameter index.
*/
static void m_get_par_bool(dsd_jsonrpc_request *adsp_json_rq, BOOL *abop_out, size_t szp_param_index);

/**
* Get the parameter from the array by index, parse to long and place in the output.
*
* @param[in] *adsp_json_rq the request object
* @param[in/out] *allp_out the numeric output pointer
* @param[in] szp_param_index the parameter index.
*/
static void m_get_par_num(dsd_jsonrpc_request *adsp_json_rq, long long *allp_out, size_t szp_param_index);

/**
* Get the parameter from the array by index, parse to char* and place in the output.
* Unlike the others, there is no real parsing here.  What is done is simply removing the first and last
* inverted commas.
* 
* @param[in] *adsp_json_rq the request object
* @param[in/out] *allp_out the charachter buffer
* @param[in] szp_param_index the parameter index.
*/
static void m_get_par_str(dsd_jsonrpc_request *adsp_json_rq, char *allp_out, size_t szp_param_index);

/**
* Get the parameter from the array by index, parse to arraylist and place in the output.
*
* @param[in] *adsp_json_rq the request object
* @param[in/out] *adsp_out the arraylist output pointer
* @param[in] szp_param_index the parameter index.
*/
static void m_get_par_array(dsd_jsonrpc_request *adsp_json_rq, dsd_arraylist *adsp_out, size_t szp_param_index);

/**
* Get the parameter from the array by index, parse to arraylist and place in the output.
*
* @param[in] *adsp_json_rq the request object
* @param[in/out] *adsp_out the json object output pointer
* @param[in] szp_param_index the parameter index.
*/
static void m_get_par_map(dsd_jsonrpc_request *adsp_json_rq, dsd_json_object *adsp_out, size_t szp_param_index);

/**
* Authenitcates a session.  The variables (session data) are taken from the JSON-RPC request struct, where the order must
* be: SID, DOMAIN, USER, PASSWORD/TICKET.
*
* @param[in] *adsp_json_rq the pointer to the JSON-RPC Request
* @return HL_UINT result from the authenticator or -1 for invalid data
*/
static HL_UINT m_authenticate_session(dsd_jsonrpc_request *adsp_json_rq, ds_auth_unit *adsl_auth_unit);

//---------------

/**
* Gets a particualr parameter from the parameter array string.  The String is "tokenised" at pointers stored in the
* formal parameter list.  The retrieved parameter is then stored in the passed buffer pointer.
*
* @param[in] *adsp_json_rq the request object which has the array string and pointer array
* @param[in/out] *achrp_buffer the buffer where to place the aqcuired string
* @param[in] szp_max_len the maximum expected/allowed length of the paramter
* @param[in] szp_param_index the index of the parameter in the param array (NOT the index of the pointer in the formal arraylist)
* @return the size of the acquired string
*/
static size_t m_get_item_from_arr_str(char *achrp_arr_str, dsd_arraylist *adsp_alist, char *achrp_buffer, size_t szp_max_len, size_t szp_param_index)
{
    if (szp_param_index >= adsp_alist->szc_size)
        return (size_t)-1;

    size_t szl_offset = 0;
    char *achl_current = szp_param_index == 0? achrp_arr_str : (char*)(m_get_element(adsp_alist, szp_param_index - 1 ));

    //move 1 byte, to skip comma.  Do this if we are more than index 0.
    if ( szp_param_index > 0)
        achl_current ++;

    while ( (achl_current < (char*)(m_get_element(adsp_alist, szp_param_index ))) 
            && szl_offset < szp_max_len )
    {
        achrp_buffer[szl_offset] = *achl_current;
        achl_current ++;
        szl_offset   ++;
    }

    return szl_offset;
}

/**
* Gets a particualr parameter from the parameter array string.  The String is "tokenised" at pointers stored in the
* formal parameter list.  The retrieved parameter is then stored in the passed buffer pointer.
*
* @param[in] *adsp_json_rq the request object which has the array string and pointer array
* @param[in/out] *achrp_buffer the buffer where to place the aqcuired string
* @param[in] szp_max_len the maximum expected/allowed length of the paramter
* @param[in] szp_param_index the index of the parameter in the param array (NOT the index of the pointer in the formal arraylist)
* @return the size of the acquired string
*/
static size_t m_get_param(dsd_jsonrpc_request *adsp_json_rq, char *achrp_buffer, size_t szp_max_len, size_t szp_param_index)
{
    return m_get_item_from_arr_str(adsp_json_rq->achrc_params, adsp_json_rq->adsc_formal_param_list, achrp_buffer, szp_max_len, szp_param_index);
}

/**
* [See definition]
*/
static void m_get_par_bool(dsd_jsonrpc_request *adsp_json_rq, BOOL *abop_out, size_t szp_param_index)
{
    char chrl_buffer[6];
    size_t szl_len = 0;
    szl_len = m_get_param(adsp_json_rq, chrl_buffer, 6, szp_param_index);
    if (szl_len == -1)
        *abop_out = 0;
    else
        m_get_as_bool(chrl_buffer, szl_len, abop_out);
}

/**
* [See definition]
*/
static void m_get_par_num(dsd_jsonrpc_request *adsp_json_rq, long long *allp_out, size_t szp_param_index)
{
    char chrl_buffer[32];
    size_t szl_len = 0;
    szl_len = m_get_param(adsp_json_rq, chrl_buffer, 32, szp_param_index);
    if (szl_len == -1)
        *allp_out = 0;
    else
        m_get_as_number(chrl_buffer, szl_len, allp_out);
}

/**
* [See definition]
*/
static void m_get_par_str(dsd_jsonrpc_request *adsp_json_rq, char *allp_out, size_t szp_param_index)
{
    size_t szl_param_len;

    szl_param_len = m_get_param(adsp_json_rq, allp_out, MAX_STR_PAR_LENGTH, szp_param_index);
    if (szl_param_len == -1)
        allp_out = NULL;
    else
    {
        m_get_as_string(allp_out, szl_param_len, allp_out);
        allp_out[szl_param_len - 2] = 0;
    }
}

/**
* [See definition]
*/
static void m_get_par_array(dsd_jsonrpc_request *adsp_json_rq, dsd_arraylist *adsp_out, size_t szp_param_index)
{
    char chrl_buffer[MAX_ARRAY_STR_LEN];
    size_t szl_len = 0;
    szl_len = m_get_param(adsp_json_rq, chrl_buffer, MAX_ARRAY_STR_LEN, szp_param_index);
    if (szl_len == -1)
        return;
    m_get_as_arraylist(chrl_buffer, szl_len, adsp_out, 1);
}

/**
* [See definition]
*/
static void m_get_par_map(dsd_jsonrpc_request *adsp_json_rq, dsd_json_object *adsp_out, size_t szp_param_index)
{
    char chrl_buffer[MAX_MAP_STR_LEN];
    size_t szl_len = 0;
    szl_len = m_get_param(adsp_json_rq, chrl_buffer, MAX_MAP_STR_LEN, szp_param_index);
    if (szl_len == -1)
        return;
    m_get_as_jsonobject(chrl_buffer, szl_len, adsp_out);
}

/**
* Authenitcates a session.  The variables (session data) are taken from the JSON-RPC request struct, where the order must
* be: SID, DOMAIN, USER, PASSWORD/TICKET.
*
* @param[in] *adsp_json_rq the pointer to the JSON-RPC Request
* @return HL_UINT result from the authenticator or -1 for invalid data
*/
static HL_UINT m_authenticate_session(dsd_jsonrpc_request *adsp_json_rq, ds_auth_unit *adsp_auth_unit)
{
    //String RPC Parameters
    char chrl_wsp_sid[128];
    char chrl_wsp_domain[128];
    char chrl_wsp_user[128];
    char chrl_wsp_password[128];

    //Auth
    HL_UINT uin_auth;

    //get parameters and put in relevant vars
    m_get_par_str(adsp_json_rq, chrl_wsp_sid, 0);
    m_get_par_str(adsp_json_rq, chrl_wsp_domain, 1);
    m_get_par_str(adsp_json_rq, chrl_wsp_user, 2);
    m_get_par_str(adsp_json_rq, chrl_wsp_password, 3);

    if (strlen(chrl_wsp_sid) == 0 || strlen(chrl_wsp_domain) == 0 || 
        strlen(chrl_wsp_user) == 0 || strlen(chrl_wsp_password) == 0 ||
        chrl_wsp_sid == NULL || chrl_wsp_domain == NULL || chrl_wsp_user == NULL ||
        chrl_wsp_password == NULL ) //err
    {
        return (HL_UINT)-1;
    }

    adsp_auth_unit->dsl_auth_t.achc_domain = chrl_wsp_domain;
    adsp_auth_unit->dsl_auth_t.inc_len_domain = strlen(chrl_wsp_domain);
    
    adsp_auth_unit->dsl_auth_t.achc_user = chrl_wsp_user;
    adsp_auth_unit->dsl_auth_t.inc_len_user = strlen(chrl_wsp_user);

    adsp_auth_unit->dsl_auth_t.achc_password = chrl_wsp_password;
    adsp_auth_unit->dsl_auth_t.inc_len_password = strlen(chrl_wsp_password);

    adsp_auth_unit->dsl_auth_t.adsc_out_usr = &(adsp_auth_unit->dsl_usr_details);

    uin_auth = adsp_auth_unit->ds_ident.m_auth_session(&(adsp_auth_unit->dsl_auth_t));

    return uin_auth;
}
//==========================F U N C T I O N   S E R V I C E========================================

/**
* A simple echo service.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_ping (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    adsp_json_rq->szl_len_params;
    adsp_error = NULL;
    sprintf(achrp_result_buffer, "Server Online");
    return IE_JT_STRING;
}

/**
* A simple echo service.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_echo (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    adsp_error = NULL;
    m_get_par_str(adsp_json_rq, achrp_result_buffer, 0);
    return IE_JT_STRING;
}

/**
* A simple adder service.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_add (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    long long inl_num1 = 0, inl_num2 = 0;
    int inl_len;
    m_get_par_num(adsp_json_rq, &inl_num1, 0);
    m_get_par_num(adsp_json_rq, &inl_num2, 1);

    inl_num1 += inl_num2;

    inl_len = sprintf(achrp_result_buffer, "%lld", inl_num1);

    adsp_error = NULL;
    return IE_JT_NUMBER;
}

/**
* A simple boolean test service.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_bool_test (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    BOOL bool1;
    BOOL bool2;

    m_get_par_bool(adsp_json_rq, &bool1, 0);
    m_get_par_bool(adsp_json_rq, &bool2, 1);

    sprintf(achrp_result_buffer, "%s", (bool1 && bool2)?"true":"false" );

    adsp_error = NULL;
    return IE_JT_BOOLEAN;
}

/**
* A simple numeric test service
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_max_num (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    dsd_arraylist *adsl_arr = m_new_arraylist(10, adsp_json_rq->adsc_hlc_lib);
    size_t szl_c;
    char chrl_tmp_buffer[32];
    size_t szl_tmp_len = 0;
    long long allp_out;
    long long lll_max = 0;

    m_get_par_array(adsp_json_rq, adsl_arr, 0);

    for (szl_c = 0; szl_c < adsl_arr->szc_size; szl_c ++)
    {
        szl_tmp_len = m_get_item_from_arr_str(adsp_json_rq->achrc_params, adsl_arr, chrl_tmp_buffer, 32, szl_c);
        m_get_as_number(chrl_tmp_buffer, szl_tmp_len, &allp_out);
        if (allp_out > lll_max)
            lll_max = allp_out;
    }

    sprintf(achrp_result_buffer, "%lld", lll_max );

    adsp_error = NULL;
    return IE_JT_NUMBER;
}

/**
* Maybe a session getter?  Buq...
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_get_session (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    /*ds_session* ads_session = (ds_session*) adsp_json_rq->adsc_hlc_lib->ac_ext;*/

    sprintf(achrp_result_buffer, "%d", 0 );
    adsp_error = NULL;
    return IE_JT_NUMBER;
}

/**
* A service to get the session of a user by passing the session id acquired from the WSP cookie
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_get_user_settings  (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    //String RPC Parameters
    char chrl_wsp_sid[128];
    char chrl_wsp_domain[128];
    char chrl_wsp_user[128];
    char chrl_wsp_password[128];
    char chrl_user_role[128];

    char chrl_portlet_list[MAX_PORTLIST_LEN];
    char chrl_page_list[MAX_PAGELIST_LEN];
    size_t szl_portlet_index;
    size_t szl_portlet_count;

    //Auth systems
    ds_wsp_helper dsl_wsp_helper;     // wsp helper class
    dsd_auth_t dsl_auth_t;
    ds_usercma dsl_usr_details;
    ds_authenticate ds_ident;   // authentication class

    //Auth
    HL_UINT uin_auth;

    //Portlet list
    ds_portlet dsl_current_portlet;
    int iml_cur_portlet_len;
    int iml_port_name_c;

    adsp_error = NULL;

    dsl_wsp_helper.m_init_trans( adsp_json_rq->adsc_hlc_lib );
    ds_ident.m_init( &dsl_wsp_helper );
    dsl_usr_details.m_init( &dsl_wsp_helper );
    memset( &dsl_auth_t, 0, sizeof(dsd_auth_t) );

    //get parameters and put in relevant vars
    m_get_par_str(adsp_json_rq, chrl_wsp_sid, 0);
    m_get_par_str(adsp_json_rq, chrl_wsp_domain, 1);
    m_get_par_str(adsp_json_rq, chrl_wsp_user, 2);
    m_get_par_str(adsp_json_rq, chrl_wsp_password, 3);

    if (strlen(chrl_wsp_sid) == 0 || strlen(chrl_wsp_domain) == 0 || 
        strlen(chrl_wsp_user) == 0 || strlen(chrl_wsp_password) == 0 ) //err
    {
        sprintf(achrp_result_buffer, "{\\\"jsonmsg\\\":\\\"error\\\", \\\"data\\\":\\\"Invalid session data.\\\"}");
        return IE_JT_STRING;
    }

    dsl_auth_t.achc_domain = chrl_wsp_domain;
    dsl_auth_t.inc_len_domain = strlen(chrl_wsp_domain);
    
    dsl_auth_t.achc_user = chrl_wsp_user;
    dsl_auth_t.inc_len_user = strlen(chrl_wsp_user);

    dsl_auth_t.achc_password = chrl_wsp_password;
    dsl_auth_t.inc_len_password = strlen(chrl_wsp_password);

    dsl_auth_t.adsc_out_usr = &dsl_usr_details;

    uin_auth = ds_ident.m_auth_session(&dsl_auth_t);

    if ( (uin_auth & AUTH_SUCCESS) != AUTH_SUCCESS )
    {
        sprintf(achrp_result_buffer, "{\\\"jsonmsg\\\":\\\"error\\\", \\\"data\\\":\\\"Authentication failure.\\\"}");
        return IE_JT_STRING;
    }

    chrl_page_list[0] = 0;

    szl_portlet_count = dsl_usr_details.m_count_portlets();
    if ( szl_portlet_count > 0 ) 
    {
        int iml_portlist_index = 0;
        int iml_pagelist_index = sprintf(chrl_page_list, "{\\\"name\\\":\\\"Portal Index\\\", \\\"portlets\\\":[");

        iml_portlist_index = sprintf(&(chrl_portlet_list[iml_portlist_index]), 
                        "{\\\"id\\\":\\\"paF1\\\", \\\"context\\\":\\\"/HOBPortlets\\\", \\\"name\\\":\\\"current_user\\\"},");
        iml_pagelist_index += sprintf(&(chrl_page_list[iml_pagelist_index]), "\\\"paF1\\\",");
        for ( szl_portlet_index = 0; szl_portlet_index < szl_portlet_count; szl_portlet_index++ ) 
        {
            //Get the next portlet
            if ( dsl_usr_details.m_get_portlet( szl_portlet_index, &dsl_current_portlet ) )
            {
                //check the name
                const char *chrl_cur_portlet_name;
                if (&dsl_current_portlet != NULL && 
                    dsl_current_portlet.m_get_name(&chrl_cur_portlet_name, &iml_cur_portlet_len))
                {
                    //add to allowed list
                    iml_port_name_c = sprintf(&(chrl_portlet_list[iml_portlist_index]), 
                        "{\\\"id\\\":\\\"pa%d\\\", \\\"context\\\":\\\"/HOBPortlets\\\", \\\"name\\\":\\\"%s\\\"}", (int)szl_portlet_index, chrl_cur_portlet_name);
                    iml_portlist_index += iml_port_name_c;
                    sprintf(&(chrl_portlet_list[iml_portlist_index]), ",");
                    iml_portlist_index++;

                    //add to page  (as of 16-Aug-12, there is just one default page)
                    iml_pagelist_index += sprintf(&(chrl_page_list[iml_pagelist_index]), "\\\"pa%d\\\",", (int)szl_portlet_index);
                }
            }
            if (iml_portlist_index > MAX_PORTLIST_LEN)
                break;
        } // end of loop through all portlets

		if (iml_portlist_index > 0)
		   sprintf(&(chrl_portlet_list[iml_portlist_index - 1]), " ");
		if (iml_pagelist_index > 0)
		   sprintf(&(chrl_page_list[iml_pagelist_index - 1]), " ");
	    sprintf(&(chrl_page_list[iml_pagelist_index]), "]}, {\\\"name\\\":\\\"Test Page\\\", \\\"portlets\\\":[]}");
    }

    sprintf(&(chrl_user_role[0]), "%s", dsl_usr_details.m_get_userrole().m_get_ptr());
    //dsl_usr_details.m_get_userrole().m_get_ptr();
    //chrl_user_role[dsl_usr_details.m_get_userrole().m_get_len()] = 0;

    sprintf(achrp_result_buffer, "{\\\"jsonmsg\\\":\\\"ok\\\", \\\"settings\\\":{\\\"user\\\":\\\"%s\\\","
           "\\\"portlets\\\":[%s], \\\"pages\\\":[%s]}, \\\"role\\\":\\\"%s\\\", \\\"wspsid\\\":\\\"%s\\\"}", 
           chrl_wsp_user, chrl_portlet_list, chrl_page_list, chrl_user_role, chrl_wsp_sid);

    return IE_JT_STRING;
}

/**
* A service to send the user's bookmarks of the WebServerGate.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_get_wsg_bookmarks  (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    size_t szl_bookmark_count;
    size_t szl_bookamrk_index;
    ds_bookmark dsl_current_bookmark;

    int   iml_bklist_index;
    char  chrl_bookmark_list[MAX_WSG_BK_LIST_LEN];

    ds_auth_unit dsl_auth_unit;
    dsl_auth_unit.dsl_wsp_helper.m_init_trans( adsp_json_rq->adsc_hlc_lib );
    dsl_auth_unit.ds_ident.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    dsl_auth_unit.dsl_usr_details.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    memset( &(dsl_auth_unit.dsl_auth_t), 0, sizeof(dsd_auth_t) );

    HL_UINT uin_auth = m_authenticate_session(adsp_json_rq, &dsl_auth_unit);

    if ( (uin_auth & AUTH_SUCCESS) != AUTH_SUCCESS )
    {
        adsp_error->achrc_message = "Authentication failure";
        adsp_error->inc_code = 1;
        adsp_error->adsc_data = NULL;

        return IE_JT_ERROR; //Add no enclosing characters such as '"' or '{'
    }
    
    iml_bklist_index = 0;

    szl_bookmark_count = dsl_auth_unit.dsl_usr_details.m_count_wsg_bookmarks();
    for (szl_bookamrk_index = 0; szl_bookamrk_index < szl_bookmark_count; szl_bookamrk_index++)
    {
        const char* achrl_cur_bk_url = NULL;
        const char* achrl_cur_bk_name = NULL;
        int inl_cur_bk_url_len = 0;
        int inl_cur_bk_name_len = 0;
        if (dsl_auth_unit.dsl_usr_details.m_get_wsg_bookmark(szl_bookamrk_index, &dsl_current_bookmark))
        {
            dsl_current_bookmark.m_get_url(&achrl_cur_bk_url, &inl_cur_bk_url_len);

            dsl_current_bookmark.m_get_name(&achrl_cur_bk_name, &inl_cur_bk_name_len);
        }
        
        iml_bklist_index += sprintf(&(chrl_bookmark_list[iml_bklist_index]), 
            "{\\\"url\\\":\\\"%.*s\\\", \\\"name\\\":\\\"%.*s\\\"} ,",
            inl_cur_bk_url_len, achrl_cur_bk_url, inl_cur_bk_name_len, achrl_cur_bk_name);
    }

    chrl_bookmark_list [iml_bklist_index > 0? (iml_bklist_index - 1):0] = 0;

    sprintf(achrp_result_buffer, "{\\\"wsgbookmarks\\\":[%s]}", chrl_bookmark_list);

    return IE_JT_STRING;
}

/**
* A service to send the user's bookmarks of the WebServerGate.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_add_wsg_bookmark   (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    ds_bookmark dsl_new_bookmark;

    char chrl_cur_bk_url[MAX_WSG_BK_URL_LEN];
    char chrl_cur_bk_name[MAX_WSG_BK_NAME_LEN];

    ds_auth_unit dsl_auth_unit;
    dsl_auth_unit.dsl_wsp_helper.m_init_trans( adsp_json_rq->adsc_hlc_lib );
    dsl_auth_unit.ds_ident.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    dsl_auth_unit.dsl_usr_details.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    memset( &(dsl_auth_unit.dsl_auth_t), 0, sizeof(dsd_auth_t) );

    HL_UINT uin_auth = m_authenticate_session(adsp_json_rq, &dsl_auth_unit);

    if ( (uin_auth & AUTH_SUCCESS) != AUTH_SUCCESS )
    {
        adsp_error->achrc_message = "Authentication failure";
        adsp_error->inc_code = 1;
        adsp_error->adsc_data = NULL;

        return IE_JT_ERROR; //Add no enclosing characters such as '"' or '{'
    }

    m_get_par_str(adsp_json_rq, chrl_cur_bk_name, 4); //0-3 used for auth
    m_get_par_str(adsp_json_rq, chrl_cur_bk_url,  5);

    dsl_new_bookmark.m_init(&(dsl_auth_unit.dsl_wsp_helper));
    dsl_new_bookmark.m_set_url(chrl_cur_bk_url, strlen(chrl_cur_bk_url));
    dsl_new_bookmark.m_set_name(chrl_cur_bk_name, strlen(chrl_cur_bk_name));
    dsl_new_bookmark.m_set_own(true);

    if (dsl_auth_unit.dsl_usr_details.m_add_wsg_bookmark(&dsl_new_bookmark))
    {
        // save settings in ldap
        if (dsl_auth_unit.ds_ident.m_save_settings( &(dsl_auth_unit.dsl_auth_t) ) )
            sprintf(achrp_result_buffer, "true");
        else
            sprintf(achrp_result_buffer, "false");
    }

    return IE_JT_BOOLEAN;
}

/**
* A service to remove a WebServerGate bookmark.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_remove_wsg_bookmark   (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    ds_bookmark dsl_current_bookmark;
    ds_hvector<ds_bookmark>     dsl_vwsg_bmarks;

    size_t szl_bookmark_count;
    size_t szl_bookamrk_index;

    char chrl_rem_url[MAX_WSG_BK_URL_LEN];
    char chrl_rem_name[MAX_WSG_BK_NAME_LEN];

    ds_auth_unit dsl_auth_unit;
    dsl_auth_unit.dsl_wsp_helper.m_init_trans( adsp_json_rq->adsc_hlc_lib );
    dsl_auth_unit.ds_ident.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    dsl_auth_unit.dsl_usr_details.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    memset( &(dsl_auth_unit.dsl_auth_t), 0, sizeof(dsd_auth_t) );

    HL_UINT uin_auth = m_authenticate_session(adsp_json_rq, &dsl_auth_unit);

    if ( (uin_auth & AUTH_SUCCESS) != AUTH_SUCCESS )
    {
        adsp_error->achrc_message = "Authentication failure";
        adsp_error->inc_code = 1;
        adsp_error->adsc_data = NULL;

        return IE_JT_ERROR; //Add no enclosing characters such as '"' or '{'
    }

    dsl_vwsg_bmarks.m_setup( &(dsl_auth_unit.dsl_wsp_helper) );
    m_get_par_str(adsp_json_rq, chrl_rem_name, 4); //0-3 used for auth
    m_get_par_str(adsp_json_rq, chrl_rem_url,  5);

    szl_bookmark_count = dsl_auth_unit.dsl_usr_details.m_count_wsg_bookmarks();
    for (szl_bookamrk_index = 0; szl_bookamrk_index < szl_bookmark_count; szl_bookamrk_index++)
    {
        if (dsl_auth_unit.dsl_usr_details.m_get_wsg_bookmark(szl_bookamrk_index, &dsl_current_bookmark))
        {
            const char *achrl_cur_bk_url;
            int inl_cur_bk_url_len;
            dsl_current_bookmark.m_get_url(&achrl_cur_bk_url, &inl_cur_bk_url_len);
            const char *achrl_cur_bk_name;
            int inl_cur_bk_name_len;
            dsl_current_bookmark.m_get_name(&achrl_cur_bk_name, &inl_cur_bk_name_len);

            if (! ( strcmp(achrl_cur_bk_url, chrl_rem_url) == 0 && strcmp(achrl_cur_bk_name, chrl_rem_name) == 0) )
                dsl_vwsg_bmarks.m_add(dsl_current_bookmark);
        }
    }

    if (dsl_auth_unit.dsl_usr_details.m_set_own_wsg_bookmarks(&dsl_vwsg_bmarks))
    {
        // save settings in ldap
        if (dsl_auth_unit.ds_ident.m_save_settings( &(dsl_auth_unit.dsl_auth_t) ) )
            sprintf(achrp_result_buffer, "true");
        else
            sprintf(achrp_result_buffer, "false");
    }

    return IE_JT_BOOLEAN;
}

/**
* A service get the user's language
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_get_language (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    ds_auth_unit dsl_auth_unit;
    dsl_auth_unit.dsl_wsp_helper.m_init_trans( adsp_json_rq->adsc_hlc_lib );
    dsl_auth_unit.ds_ident.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    dsl_auth_unit.dsl_usr_details.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    memset( &(dsl_auth_unit.dsl_auth_t), 0, sizeof(dsd_auth_t) );

    HL_UINT uin_auth = m_authenticate_session(adsp_json_rq, &dsl_auth_unit);

    if ( (uin_auth & AUTH_SUCCESS) != AUTH_SUCCESS )
    {
        adsp_error->achrc_message = "Authentication failure";
        adsp_error->inc_code = 1;
        adsp_error->adsc_data = NULL;

        return IE_JT_ERROR; //Add no enclosing characters such as '"' or '{'
    }

    sprintf(achrp_result_buffer, "%d", dsl_auth_unit.dsl_usr_details.m_get_lang());

    return IE_JT_NUMBER;
}


/**
* A service get the user's language
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_get_wfa_bookmarks (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    size_t szl_bookmark_count;
    size_t szl_bookamrk_index;
    dsd_wfa_bmark dsl_current_bookmark;

    int   iml_cur_bk_pos;

    int   iml_bklist_index;
    char  chrl_bookmark_list[MAX_WFA_BK_LIST_LEN];

    ds_auth_unit dsl_auth_unit;
    dsl_auth_unit.dsl_wsp_helper.m_init_trans( adsp_json_rq->adsc_hlc_lib );
    dsl_auth_unit.ds_ident.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    dsl_auth_unit.dsl_usr_details.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    memset( &(dsl_auth_unit.dsl_auth_t), 0, sizeof(dsd_auth_t) );

    HL_UINT uin_auth = m_authenticate_session(adsp_json_rq, &dsl_auth_unit);

    if ( (uin_auth & AUTH_SUCCESS) != AUTH_SUCCESS )
    {
        adsp_error->achrc_message = "Authentication failure";
        adsp_error->inc_code = 1;
        adsp_error->adsc_data = NULL;

        return IE_JT_ERROR; //Add no enclosing characters such as '"' or '{'
    }

    iml_bklist_index = 0;

    iml_cur_bk_pos = -1; //initial value
    szl_bookmark_count = dsl_auth_unit.dsl_usr_details.m_count_wfa_bookmarks();
    for (szl_bookamrk_index = 0; szl_bookamrk_index < szl_bookmark_count; szl_bookamrk_index++)
    {
        const char* achrl_cur_bk_user = NULL;
        const char* achrl_cur_bk_pass = NULL;
        const char* achrl_cur_bk_domn = NULL;
        int inl_cur_bk_user_len = 0;
        int inl_cur_bk_pass_len = 0;
        int inl_cur_bk_domn_len = 0;
        if (dsl_auth_unit.dsl_usr_details.m_get_wfa_bookmark(szl_bookamrk_index, &dsl_current_bookmark))
        {
            dsl_current_bookmark.m_get_user(&achrl_cur_bk_user, &inl_cur_bk_user_len);
            dsl_current_bookmark.m_get_pwd(&achrl_cur_bk_pass, &inl_cur_bk_pass_len);
            dsl_current_bookmark.m_get_domain(&achrl_cur_bk_domn, &inl_cur_bk_domn_len);
            iml_cur_bk_pos = dsl_current_bookmark.m_get_position();
        }
        
        iml_bklist_index += sprintf(&(chrl_bookmark_list[iml_bklist_index]), 
            "{\\\"user\\\":\\\"%.*s\\\", \\\"pass\\\":\\\"%.*s\\\", \\\"domn\\\":\\\"%.*s\\\", \\\"posn\\\":%d} ,", 
            inl_cur_bk_user_len, achrl_cur_bk_user, inl_cur_bk_pass_len, achrl_cur_bk_pass,
            inl_cur_bk_domn_len, achrl_cur_bk_domn, iml_cur_bk_pos);
    }

    chrl_bookmark_list [iml_bklist_index > 0? (iml_bklist_index - 1):0] = 0;

    sprintf(achrp_result_buffer, "{\\\"wfabookmarks\\\":[%s]}", chrl_bookmark_list);

    return IE_JT_STRING;
}

/**
* A service to send the user's bookmarks of the WebServerGate.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_add_wfa_bookmark   (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    dsd_wfa_bmark dsl_new_bookmark;

    char chrl_cur_bk_user[MAX_WFA_BK_USER_LEN];
    char chrl_cur_bk_pass[MAX_WFA_BK_PASS_LEN];
    char chrl_cur_bk_domn[MAX_WFA_BK_DOMN_LEN];

    ds_auth_unit dsl_auth_unit;
    dsl_auth_unit.dsl_wsp_helper.m_init_trans( adsp_json_rq->adsc_hlc_lib );
    dsl_auth_unit.ds_ident.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    dsl_auth_unit.dsl_usr_details.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    memset( &(dsl_auth_unit.dsl_auth_t), 0, sizeof(dsd_auth_t) );

    HL_UINT uin_auth = m_authenticate_session(adsp_json_rq, &dsl_auth_unit);

    if ( (uin_auth & AUTH_SUCCESS) != AUTH_SUCCESS )
    {
        adsp_error->achrc_message = "Authentication failure";
        adsp_error->inc_code = 1;
        adsp_error->adsc_data = NULL;

        return IE_JT_ERROR; //Add no enclosing characters such as '"' or '{'
    }

    m_get_par_str(adsp_json_rq, chrl_cur_bk_user, 4); //0-3 used for auth
    m_get_par_str(adsp_json_rq, chrl_cur_bk_pass, 5);
    m_get_par_str(adsp_json_rq, chrl_cur_bk_domn, 6);

    dsl_new_bookmark.m_init(&(dsl_auth_unit.dsl_wsp_helper));
    dsl_new_bookmark.m_set_user(chrl_cur_bk_user, strlen(chrl_cur_bk_user));
    dsl_new_bookmark.m_set_pwd(chrl_cur_bk_pass, strlen(chrl_cur_bk_pass));
    dsl_new_bookmark.m_set_domain(chrl_cur_bk_domn, strlen(chrl_cur_bk_domn));
    dsl_new_bookmark.m_set_position( dsl_auth_unit.dsl_usr_details.m_count_wfa_bookmarks() + 1);

    if (dsl_auth_unit.dsl_usr_details.m_add_wfa_bookmark(&dsl_new_bookmark))
    {
        // save settings in ldap
        if (dsl_auth_unit.ds_ident.m_save_settings( &(dsl_auth_unit.dsl_auth_t) ) )
            sprintf(achrp_result_buffer, "true");
        else
            sprintf(achrp_result_buffer, "false");
    }

    return IE_JT_BOOLEAN;
}

/**
* A service to remove a WebServerGate bookmark.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_remove_wfa_bookmark   (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    dsd_wfa_bmark dsl_current_bookmark;
    ds_hvector<dsd_wfa_bmark> dsl_vwsg_bmarks;

    size_t szl_bookmark_count;
    size_t szl_bookamrk_index;

    long long illl_pos_to_remove;

    ds_auth_unit dsl_auth_unit;
    dsl_auth_unit.dsl_wsp_helper.m_init_trans( adsp_json_rq->adsc_hlc_lib );
    dsl_auth_unit.ds_ident.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    dsl_auth_unit.dsl_usr_details.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    memset( &(dsl_auth_unit.dsl_auth_t), 0, sizeof(dsd_auth_t) );

    HL_UINT uin_auth = m_authenticate_session(adsp_json_rq, &dsl_auth_unit);

    if ( (uin_auth & AUTH_SUCCESS) != AUTH_SUCCESS )
    {
        adsp_error->achrc_message = "Authentication failure";
        adsp_error->inc_code = 1;
        adsp_error->adsc_data = NULL;

        return IE_JT_ERROR; //Add no enclosing characters such as '"' or '{'
    }

    dsl_vwsg_bmarks.m_setup( &(dsl_auth_unit.dsl_wsp_helper) );
    m_get_par_num(adsp_json_rq, &illl_pos_to_remove, 4); //0-3 used for auth

    szl_bookmark_count = dsl_auth_unit.dsl_usr_details.m_count_wsg_bookmarks();

    if (szl_bookmark_count < illl_pos_to_remove)
    {
        sprintf(achrp_result_buffer, "false");
        return IE_JT_BOOLEAN;
    }

    for (szl_bookamrk_index = 0; szl_bookamrk_index < szl_bookmark_count; szl_bookamrk_index++)
    {
        if (dsl_auth_unit.dsl_usr_details.m_get_wfa_bookmark(szl_bookamrk_index, &dsl_current_bookmark))
        {
            if (dsl_current_bookmark.m_get_position() != illl_pos_to_remove)
                dsl_vwsg_bmarks.m_add(dsl_current_bookmark);
        }
    }

    if (dsl_auth_unit.dsl_usr_details.m_set_own_wfa_bookmarks(&dsl_vwsg_bmarks))
    {
        // save settings in ldap
        if (dsl_auth_unit.ds_ident.m_save_settings( &(dsl_auth_unit.dsl_auth_t) ) )
            sprintf(achrp_result_buffer, "true");
        else
            sprintf(achrp_result_buffer, "false");
    }

    return IE_JT_BOOLEAN;
}

/**
* A service to change the user's password.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_change_password (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    bool bol_ret;
    struct dsd_getuser dsl_user; 

    char chrl_old_password[MAX_PASS_LEN];
    char chrl_new_password[MAX_PASS_LEN];

    ds_auth_unit dsl_auth_unit;
    dsl_auth_unit.dsl_wsp_helper.m_init_trans( adsp_json_rq->adsc_hlc_lib );
    dsl_auth_unit.ds_ident.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    dsl_auth_unit.dsl_usr_details.m_init( &(dsl_auth_unit.dsl_wsp_helper) );
    memset( &(dsl_auth_unit.dsl_auth_t), 0, sizeof(dsd_auth_t) );

    HL_UINT uin_auth = m_authenticate_session(adsp_json_rq, &dsl_auth_unit);

    if ( (uin_auth & AUTH_SUCCESS) != AUTH_SUCCESS )
    {
        adsp_error->achrc_message = "Authentication failure";
        adsp_error->inc_code = 1;
        adsp_error->adsc_data = NULL;

        return IE_JT_ERROR; //Add no enclosing characters such as '"' or '{'
    }

    bol_ret = dsl_auth_unit.dsl_usr_details.m_get_user( &dsl_user );
    if (bol_ret == false || dsl_user.dsc_username.m_get_len() < 1 ) 
    {
        sprintf(achrp_result_buffer, "false");
        return IE_JT_BOOLEAN;
    }

    m_get_par_str(adsp_json_rq, chrl_old_password, 4); //0-3 used for auth
    m_get_par_str(adsp_json_rq, chrl_new_password, 5);

    /*
        try to change the password
    */
    memset( &(dsl_auth_unit.dsl_auth_t), 0, sizeof(dsd_auth_t) );
    dsl_auth_unit.dsl_auth_t.achc_user        = dsl_user.dsc_username.m_get_ptr();
    dsl_auth_unit.dsl_auth_t.inc_len_user     = dsl_user.dsc_username.m_get_len();
    dsl_auth_unit.dsl_auth_t.achc_domain      = dsl_user.dsc_userdomain.m_get_ptr();
    dsl_auth_unit.dsl_auth_t.inc_len_domain   = dsl_user.dsc_userdomain.m_get_len();
    dsl_auth_unit.dsl_auth_t.achc_old_pwd     = (char*)chrl_old_password;
    dsl_auth_unit.dsl_auth_t.inc_len_old_pwd  = strlen(chrl_old_password);
    dsl_auth_unit.dsl_auth_t.achc_password    = (char*)chrl_new_password;
    dsl_auth_unit.dsl_auth_t.inc_len_password = strlen(chrl_new_password);
    dsl_auth_unit.dsl_auth_t.adsc_out_usr     = &dsl_auth_unit.dsl_usr_details;

    uin_auth = dsl_auth_unit.ds_ident.m_change_password( &dsl_auth_unit.dsl_auth_t );
    
    if ((uin_auth & AUTH_SUCCESS) == AUTH_SUCCESS)
        sprintf(achrp_result_buffer, "true");
    else
        sprintf(achrp_result_buffer, "false");

    return IE_JT_BOOLEAN;
}

/**
* A service to send a simple server timestamp to the client.  Second precision.
*
* @param[in] *adsp_json_rq the rpc request object
* @param[in/out] *achrp_result_buffer the buffer where to place the result string
* @param[in/out] *adsp_error the error structure to fill on error
* @return ied_json_data_type the type of result data
*/
ied_json_data_type m_rpcs_get_timestamp (dsd_jsonrpc_request *adsp_json_rq, char *achrp_result_buffer, dsd_json_error_structure *adsp_error)
{
    adsp_error = NULL;
    sprintf(achrp_result_buffer, "%lld", (LONGLONG)time(NULL));
    return IE_JT_NUMBER;
}
