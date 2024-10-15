/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program                                                             |*/
/*| =======                                                             |*/
/*|   sdh_echo                                                          |*/
/*|   The main portal and portlet WSP servicing Server Data Hook        |*/
/*|                                                                     |*/
/*| Author                                                              |*/
/*| ======                                                              |*/
/*|   Michael Jakobs, James Farrugia May 2012                           |*/
/*|                                                                     |*/
/*| Copyright                                                           |*/
/*| =========                                                           |*/
/*|   HOB GmbH 2012                                                     |*/
/*|                                                                     |*/ 
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes                                                            |*/
/*+---------------------------------------------------------------------+*/
#include <windows.h>
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/dom/impl/DOMElementImpl.hpp>
#ifndef _IBIPGW08_X1_HPP
    #define _IBIPGW08_X1_HPP
    #include <IBIPGW08-X1.hpp>
#endif // _IBIPGW08_X1_HPP
#define DEF_HL_INCL_DOM
#include <hob-xsclib01.h>
#include <stdio.h>
#include <types_defines.h>

/*+---------------------------------------------------------------------+*/
/*| includes                                                            |*/
/*+---------------------------------------------------------------------+*/
#include <sdh-portal-srv.h>
#include <hob-json.h>
#include <hob-json-rpc.h>
#include <hob-arraylist.h>
//#include <ds_wsp_helper.h>
//#include <ds_session.h>
#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

/*+---------------------------------------------------------------------+*/
/*| Defines                                                             |*/
/*+---------------------------------------------------------------------+*/
#define MAX_RESP_LENGHT 5120 //5Kb

/*+---------------------------------------------------------------------+*/
/*| structs                                                             |*/
/*+---------------------------------------------------------------------+*/

typedef struct dsd_my_session 
{
    char chc_opened;
    int inc_brackets;
    int inc_msg_len;
    struct dsd_gather_i_1 *dsc_last_gather;
} dsd_my_session;

/*+---------------------------------------------------------------------+*/
/*| public functions                                                    |*/
/*+---------------------------------------------------------------------+*/


/*+---------------------------------------------------------------------+*/
/*| private functions                                                   |*/
/*+---------------------------------------------------------------------+*/

static void m_v_check_json(struct dsd_gather_i_1 *dsa_first_gather, struct dsd_my_session * adsp_session, int* imc_close);

static void m_v_check_json(struct dsd_gather_i_1 *dsa_first_gather, struct dsd_my_session * adsp_session, int* imc_close)
{
    int im_c;
    int im_blk_read_ptr;
    struct dsd_gather_i_1 *ds_gather_current;
    struct dsd_gather_i_1 *ds_tmp_gather;

    im_blk_read_ptr = 0;
    //-------
    //Sessioning the gathers

    ds_gather_current = adsp_session->dsc_last_gather;

    if (ds_gather_current == NULL)                      //Starting to get the first gather, so no next
        ds_gather_current = dsa_first_gather;
    else
        ds_gather_current = ds_gather_current->adsc_next;

    adsp_session->dsc_last_gather = ds_gather_current;  //set the last access gather in the session as the one we have now.

    if (ds_gather_current == NULL)
        return;
    //-------
    //Working with the input

    while(ds_gather_current->achc_ginp_cur + im_blk_read_ptr < ds_gather_current->achc_ginp_end)
    {
        if (ds_gather_current->achc_ginp_cur[im_blk_read_ptr] == '{')
        {
            adsp_session->inc_brackets ++;
            adsp_session->chc_opened = 1;   //notify that we have entered within brackets at least once, otherwise finding 
            //bracket count to 0 could immedietly prompt the system to start discarding 
            //any new gather structures.
        }
        else if (ds_gather_current->achc_ginp_cur[im_blk_read_ptr] == '}')
            adsp_session->inc_brackets --;

        im_blk_read_ptr ++;
    }

    //--------
    //Finalising

    //Got last '}' and we have been in the text already (opened at least once)
    if (adsp_session->inc_brackets == 0 && adsp_session->chc_opened == 1)
    {
        *imc_close = 1;

        im_c = 0;
        ds_tmp_gather = dsa_first_gather;
        while (ds_tmp_gather != NULL)
        {
            while(ds_tmp_gather->achc_ginp_cur + im_c < ds_tmp_gather->achc_ginp_end)
                im_c ++;

            ds_tmp_gather = ds_tmp_gather->adsc_next;
        }
        adsp_session->inc_msg_len = im_c;
    }
}

/**
 * function m_hlclib_conf
 *  read our configuration from xml file
 *
 * @param[in]   struct dsd_hl_clib_dom_conf*    ads_conf
 * @return      BOOL                                        TRUE = success
*/
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *adsp_conf )
{
    *(adsp_conf->aac_conf) = NULL;
    return TRUE;
}

/**
 * function m_hlclib01
 *  working function
 *
 * @param[in]   struct dsd_hl_clib1     *adsp_hlclib
*/
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hlclib )
{
    int im_close;
    int inc_offset;
    size_t szl_resp_len;
    char chrc_msg[MAX_RESP_LENGHT];
    struct dsd_gather_i_1 *ds_gather_current;
    struct dsd_my_session *adsl_my_session;
    BOOL bol_ret;

    im_close        = 0;
    inc_offset      = 0;

    dsd_json_object *dsl_json_obj;
    dsd_jsonrpc_request *dsl_json_rq;
    dsd_jsonrpc_response *dsl_json_rp;

    /*--------------------*/
    /* setup helper class */
    /*--------------------*/
    /*ds_session* ads_session;
    ds_wsp_helper dsc_wsp_helper;
    dsc_wsp_helper.m_init_trans( adsp_hlclib );*/
    
   // ds_session* ads_session = (ds_session*)adsp_hlclib->ac_ext;
    //-----------------------

    switch ( adsp_hlclib->inc_func ) 
    {
        // START SESSION-------------------------------
        case DEF_IFUNC_START:
            adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_CONSOLE_OUT,
                                  "DEF_IFUNC_START called", (int)sizeof("DEF_IFUNC_START called") - 1 );

            adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, 
                                    &adsp_hlclib->ac_ext, (int)sizeof(struct dsd_my_session) );
            
            adsl_my_session = (struct dsd_my_session *)adsp_hlclib->ac_ext;

            if ( adsl_my_session == NULL ) 
            {
                adsp_hlclib->inc_return = DEF_IRET_END;
                return;
            }
            memset( adsl_my_session, 0, sizeof(struct dsd_my_session) );
            break;

        // REFLECT/WORK ON SESSION-------------------------------
        case DEF_IFUNC_REFLECT:
            adsl_my_session = (struct dsd_my_session *)adsp_hlclib->ac_ext;
            if ( adsp_hlclib->adsc_gather_i_1_in != NULL )
            {
                adsp_hlclib->adsc_gai1_out_to_client = (struct dsd_gather_i_1*)adsp_hlclib->achc_work_area;
                inc_offset += (int)sizeof(struct dsd_gather_i_1);
                m_v_check_json( adsp_hlclib->adsc_gather_i_1_in, adsl_my_session, &im_close);

                adsp_hlclib->adsc_gai1_out_to_client->achc_ginp_cur = &adsp_hlclib->achc_work_area[inc_offset];
                adsp_hlclib->adsc_gai1_out_to_client->achc_ginp_end = 0;

                adsp_hlclib->adsc_gai1_out_to_client->adsc_next = NULL;

                if (im_close == 1)
                {
                    dsl_json_obj = m_new_json_obj(adsp_hlclib);
                    if (m_parse_json(adsp_hlclib->adsc_gather_i_1_in, adsl_my_session->inc_msg_len, dsl_json_obj))
                    {
                        dsl_json_rq = m_new_json_request(adsp_hlclib, dsl_json_obj);
                        dsl_json_rp = m_new_json_response(dsl_json_rq);
                        m_serialise_to_string(dsl_json_rp, chrc_msg, &szl_resp_len);

                        //----------- CLEAN ------------------
                        m_destroy_json_obj(dsl_json_obj);
                        m_destroy_json_request(dsl_json_rq);
                        m_destroy_json_response(dsl_json_rp);
                        //------------------------------------
                    }
                    else
                    {
                        dsl_json_rp = m_new_json_error_response(adsp_hlclib, "Invalid JSON.", -32700, NULL, 1);
                        //issue with unknown ID.  (How will you get it if you got the wrong json?)
                        m_serialise_to_string(dsl_json_rp, chrc_msg, &szl_resp_len);
                        m_destroy_json_response(dsl_json_rp);
                    }

                    ds_gather_current = adsp_hlclib->adsc_gather_i_1_in;
                    while (ds_gather_current != NULL) 
                    {
                        ds_gather_current->achc_ginp_cur = ds_gather_current->achc_ginp_end;
                        ds_gather_current = ds_gather_current->adsc_next;
                    }
                    im_close = 0;

                    adsp_hlclib->adsc_gai1_out_to_client->achc_ginp_end = 
                                                adsp_hlclib->adsc_gai1_out_to_client->achc_ginp_cur + szl_resp_len ;

                    memcpy(&adsp_hlclib->achc_work_area[inc_offset], chrc_msg, szl_resp_len);
                    inc_offset += szl_resp_len;

                    //reset the session
                    adsl_my_session->chc_opened     = 0;
                    adsl_my_session->inc_brackets   = 0;
                    adsl_my_session->inc_msg_len    = 0;
                    adsl_my_session->dsc_last_gather = NULL;
                }
            }
            break;

        //END SESSION-------------------------------
        case DEF_IFUNC_CLOSE:
            adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_CONSOLE_OUT,
                                  "DEF_IFUNC_CLOSE called", (int)sizeof("DEF_IFUNC_CLOSE called") - 1 );
            
            bol_ret = adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMFREE,
                                            &adsp_hlclib->ac_ext, 0 );
            adsp_hlclib->ac_ext = NULL;            
            break;

        default:
            adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_CONSOLE_OUT,
                                  "invalid work mode", (int)sizeof("invalid work mode") - 1 );
            adsp_hlclib->inc_return = DEF_IRET_END;
            break;

    }
} /* end of m_hlclib01 */