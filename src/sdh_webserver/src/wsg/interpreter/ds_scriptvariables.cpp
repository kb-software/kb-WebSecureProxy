/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "states.h"
#include <ds_wsp_helper.h>
#include "ds_scriptvariables.h"

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/

/**
 * @ingroup dataprocessor
*/
ds_scriptvariables::ds_scriptvariables( ds_wsp_helper* adsl_wsp_helper )
{
    m_setup( adsl_wsp_helper );
}

/*+-------------------------------------------------------------------------+*/
/*| destructor                                                              |*/
/*+-------------------------------------------------------------------------+*/
/**
 * @ingroup dataprocessor
*/
ds_scriptvariables::~ds_scriptvariables()
{
}

/*+-------------------------------------------------------------------------+*/
/*| functions:                                                              |*/
/*+-------------------------------------------------------------------------+*/
/**
 * @ingroup dataprocessor
 *
 * @param [in]	size_t	size of requested memory
 * @param [in]	a_loc	
 *
 * @return pointer to the newly allocated memory chunk
*/
void* ds_scriptvariables::operator new(size_t, void* a_loc) {
    return a_loc;
}

/**
 * @ingroup dataprocessor
 *
 * @param [in]	adsl_wsp_helper A pointer to a ds_wsp_helper class
 *
*/
void ds_scriptvariables::m_init( ds_wsp_helper* adsl_wsp_helper )
{
    ads_wsp_helper = adsl_wsp_helper;
    ds_word.m_init      ( ads_wsp_helper );
    ds_sign.m_init      ( ads_wsp_helper );
    ds_object.m_init    ( ads_wsp_helper );
    ds_argument.m_init  ( ads_wsp_helper );
    ds_arg_sign.m_init  ( ads_wsp_helper );
    ds_spaces.m_init    ( ads_wsp_helper );
    ds_arg_spaces.m_init( ads_wsp_helper );
    dsc_arg_state.m_init( ads_wsp_helper );
    dsc_vwith.m_init    ( ads_wsp_helper );
} // end of ds_scriptvariables::m_init

/**
 * @ingroup dataprocessor
 *
 * @param [in]	adsl_wsp_helper A pointer to a ds_wsp_helper class
 *
*/
void ds_scriptvariables::m_setup( ds_wsp_helper* adsl_wsp_helper )
{
    ads_wsp_helper                   = adsl_wsp_helper;
    in_state                         = SCRIPT_NORMAL;
    bo_not_read_next_sign            = false;
    bo_comment                       = false;
    bo_cc_on                         = false;
    ch_last_sign                     = 'e';
    ch_with_sign                     = 'e';
    in_sign_pos                      =  0;
    in_append_data                   =  0;
    ds_last_pos_key.in_key           = -2;
    ds_last_pos_key.in_pos_in_object = -1;
    ds_last_pos_key.in_length        =  0;

    
    ds_word.m_setup      ( ads_wsp_helper, SCRIPT_WORD_MEMORY );
    ds_sign.m_setup      ( ads_wsp_helper, SCRIPT_SIGN_MEMORY );
    ds_object.m_setup    ( ads_wsp_helper, SCRIPT_OBJECT_MEMORY );
    ds_argument.m_setup  ( ads_wsp_helper, SCRIPT_ARGUMENT_MEMORY );
    ds_arg_sign.m_setup  ( ads_wsp_helper, SCRIPT_SIGN_MEMORY );
    ds_spaces.m_setup    ( ads_wsp_helper, SCRIPT_WHITE_SPACES_MEMORY );
    ds_arg_spaces.m_setup( ads_wsp_helper, SCRIPT_WHITE_SPACES_MEMORY );
    dsc_arg_state.m_setup( ads_wsp_helper );
    dsc_vwith.m_setup    ( ads_wsp_helper );
}
