/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program                                                             |*/
/*| =======                                                             |*/
/*|   sdh_echo                                                          |*/
/*|   the simplest SDH ever                                             |*/
/*|                                                                     |*/
/*| Author                                                              |*/
/*| ======                                                              |*/
/*|   Michael Jakobs, May 2012                                          |*/
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
#include <hob-xsclib01.h>

/*+---------------------------------------------------------------------+*/
/*| public functions                                                    |*/
/*+---------------------------------------------------------------------+*/
/**
 * function m_hlclib01
 *  working function
 *
 * @param[in]   struct dsd_hl_clib1     *adsp_hlclib
*/
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hlclib )
{
    switch ( adsp_hlclib->inc_func ) {
        case DEF_IFUNC_START:
            adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_CONSOLE_OUT,
                                  "DEF_IFUNC_START called", (int)sizeof("DEF_IFUNC_START called") - 1 );
            break;
        case DEF_IFUNC_TOSERVER:
            if ( adsp_hlclib->adsc_gather_i_1_in != NULL ) {
                adsp_hlclib->adsc_gai1_out_to_server = (struct dsd_gather_i_1*)adsp_hlclib->achc_work_area;
                adsp_hlclib->adsc_gai1_out_to_server->achc_ginp_cur =
                                      adsp_hlclib->adsc_gather_i_1_in->achc_ginp_cur;
                adsp_hlclib->adsc_gai1_out_to_server->achc_ginp_end =
                                      adsp_hlclib->adsc_gather_i_1_in->achc_ginp_end;
                adsp_hlclib->adsc_gai1_out_to_server->adsc_next = NULL;
                adsp_hlclib->adsc_gather_i_1_in->achc_ginp_cur =
                            adsp_hlclib->adsc_gather_i_1_in->achc_ginp_end;
            }
            break;
        case DEF_IFUNC_FROMSERVER:
            if ( adsp_hlclib->adsc_gather_i_1_in != NULL ) {
                adsp_hlclib->adsc_gai1_out_to_client = (struct dsd_gather_i_1*)adsp_hlclib->achc_work_area;
                adsp_hlclib->adsc_gai1_out_to_client->achc_ginp_cur =
                                      adsp_hlclib->adsc_gather_i_1_in->achc_ginp_cur;
                adsp_hlclib->adsc_gai1_out_to_client->achc_ginp_end =
                                      adsp_hlclib->adsc_gather_i_1_in->achc_ginp_end;
                adsp_hlclib->adsc_gai1_out_to_client->adsc_next = NULL;
                adsp_hlclib->adsc_gather_i_1_in->achc_ginp_cur =
                            adsp_hlclib->adsc_gather_i_1_in->achc_ginp_end;
            }
            break;

        case DEF_IFUNC_REFLECT:
            if ( adsp_hlclib->adsc_gather_i_1_in != NULL ) {
                adsp_hlclib->adsc_gai1_out_to_client = (struct dsd_gather_i_1*)adsp_hlclib->achc_work_area;
                adsp_hlclib->adsc_gai1_out_to_client->achc_ginp_cur =
                                      adsp_hlclib->adsc_gather_i_1_in->achc_ginp_cur;
                adsp_hlclib->adsc_gai1_out_to_client->achc_ginp_end =
                                      adsp_hlclib->adsc_gather_i_1_in->achc_ginp_end;
                adsp_hlclib->adsc_gai1_out_to_client->adsc_next = NULL;
                adsp_hlclib->adsc_gather_i_1_in->achc_ginp_cur =
                            adsp_hlclib->adsc_gather_i_1_in->achc_ginp_end;
            }
            break;
        case DEF_IFUNC_CLOSE:
            adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_CONSOLE_OUT,
                                  "DEF_IFUNC_CLOSE called", (int)sizeof("DEF_IFUNC_CLOSE called") - 1 );
            break;
    }
} /* end of m_hlclib01 */