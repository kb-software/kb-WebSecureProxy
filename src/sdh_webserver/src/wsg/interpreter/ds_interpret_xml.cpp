/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "../../ds_session.h"
#include "ds_interpret_xml.h"

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/

/**
 * @ingroup dataprocessor
*/
ds_interpret_xml::ds_interpret_xml(void) : ds_interpret()
{
} //end of ds_interpret_xml::ds_interpret_xml

/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/

/**
 * @ingroup dataprocessor
*/
ds_interpret_xml::~ds_interpret_xml(void)
{
} //end of ds_interpret_xml::~ds_interpret_xml

/*+-------------------------------------------------------------------------+*/
/*| functions:                                                              |*/
/*+-------------------------------------------------------------------------+*/

/**
 * @ingroup dataprocessor
 *
 * @return      1 if some data is written, 0 otherwise
 *
*/
int ds_interpret_xml::m_process_data( )
{
    // initialize some variables:
    const char* ach_data;
    int   in_len_data      = 0;
    int   in_data_complete = 0;
    int   in_data_written  = 0;
    int   in_return        = 0;
    
    while ( in_data_complete == 0 && in_len_data > -1 ) {
        // reset ach_data, in_len_data
        ach_data    = NULL;
        in_len_data = -1;
        // get data
        in_data_complete = ads_session->dsc_transaction.m_get_data( &ach_data, &in_len_data );
		if(in_data_complete < 0)
			return in_data_complete;
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "xml-interpreter: m_get_data() returned %d",
                                             in_len_data );
        
        // for the moment, don't change data, just send it:
        in_data_written = m_send_data( ach_data, in_len_data );
        if ( in_data_written == 1 ) {
            in_return = 1;
        }
    }    
    return in_return;    
} // end of m_process_data
