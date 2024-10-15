/*+---------------------------------------------------------------------+*/
/*| include local headers                                               |*/
/*+---------------------------------------------------------------------+*/
#include "../../ds_session.h"
#include "dsd_interpret_ica.h"

/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/

/**
 *
 * @ingroup dataprocessor
 *
*/
dsd_interpret_ica::dsd_interpret_ica(void) : ds_interpret()
{
    ienc_state = ied_st_normal;
} //end of dsd_interpret_ica::dsd_interpret_ica


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/

/**
 *
 * @ingroup dataprocessor
 *
*/
dsd_interpret_ica::~dsd_interpret_ica(void)
{
} //end of dsd_interpret_ica::~dsd_interpret_ica



/*+---------------------------------------------------------------------+*/
/*| functions:                                                          |*/
/*+---------------------------------------------------------------------+*/

/**
 * @ingroup dataprocessor
 *
 * @return      1 if data was sent, 0 otherwise                 
 * 
*/
int dsd_interpret_ica::m_process_data()
{
    // initialize some variables:
    const char* achl_data;
    int   inl_len_data      = 0;
    int   inl_data_complete = false;
    int   inl_data_written;
    int   inl_return        = 0;

    while ( inl_data_complete == 0 && inl_len_data > -1 ) {
        // reset ach_data, in_len_data
        achl_data    = NULL;
        inl_len_data = -1;
        // get data:
        inl_data_complete = ads_session->dsc_transaction.m_get_data( &achl_data, &inl_len_data );
		if(inl_data_complete < 0)
			return inl_data_complete;
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "ica-interpreter: m_get_data() returned %d.",
                                             inl_len_data );
        // parse data:
        inl_data_written = m_parse_data( achl_data, inl_len_data, inl_data_complete > 0 );
        if ( inl_data_written == 1 ) {
            inl_return = 1;
        }
    }    
    return inl_return;
} // end of dsd_interpret_ica::m_process_data


/**
 * @ingroup dataprocessor
 *
 * @param[in]   achp_data			A pointer to the input data
 * @param[in]   inp_len_data		The length of the input data
 * @param[in]   bop_data_complete	A bool flag to indicate whether data is complete
 *									(default value = false)
 * @param[out]  adsp_output			If this pointer is NOT NULL, data will be written 
 *                                  in this buffer instead of being send to browser
 *                                  (default value = NULL)
 *
 * @return      1 if data was sent, 0 otherwise
 * 
*/
int dsd_interpret_ica::m_parse_data( const char *achp_data, int inp_len_data,
                                     bool bop_data_complete, ds_hstring *adsp_output )
{
    const char     *achl_line;                  /* found line            */
    int            inl_line;                    /* length of found line  */
    bool           bol_ret;                     /* return for some funcs */
    int in_ret = 0;                             /* signal for trans      */

    do {
        inl_line = m_get_line( achp_data, inp_len_data );
        if ( inl_line > 0 ) {
            if (    achp_data[inl_line - 1] != '\n'
                 && achp_data[inl_line - 1] != '\r' ) {
                /*
                    we have found a not complete line
                */
                if ( bop_data_complete == true ) {
                    m_send_data( achp_data, inl_line, adsp_output );
                    break;
                }
                dsc_line.m_write( achp_data, inl_line );
                return in_ret;
            } else if ( dsc_line.m_get_len() > 0 ) {
                dsc_line.m_write( achp_data, inl_line );
                achl_line = dsc_line.m_get_ptr();
                inl_line  = dsc_line.m_get_len();
            } else {
                achl_line = achp_data;
            }
            switch ( ienc_state ) {
                case ied_st_normal:
                    bol_ret = m_is_line_prefix( achl_line, inl_line, "Address=" );
                    if ( bol_ret == true ) {
                        ienc_state = ied_st_address_found;
                    }
                    break;
                case ied_st_address_found:
                    if ( this->inc_port > 0 ) {
                        m_insert_proxy( this->inc_port );
                    }
                    ienc_state = ied_st_proxy_inserted;
                    // break is missing on purpose!
                case ied_st_proxy_inserted:
                    /* ignore all proxy settings except ProxyTimeout */
                    if (    m_is_line_prefix( achl_line, inl_line, "Proxy"        ) == true
                         && m_is_line_prefix( achl_line, inl_line, "ProxyTimeout" ) == false ) {
                        m_move_char_pointer( &achp_data, &inp_len_data, &inl_line );
                    }
                    break;
            }

            m_send_data( achl_line, inl_line, adsp_output );
            m_move_char_pointer( &achp_data, &inp_len_data, &inl_line );
        }
    } while ( inp_len_data > 0 );

    if(bop_data_complete) {
        ienc_state = ied_st_normal;
    }
    return in_ret;
} // end of dsd_interpret_ica::m_parse_data


/**
 * private function dsd_interpret_ica::m_insert_proxy
 *
 * @param[in]   unsigned short  uisp_port   socksv5 listen port
*/
void dsd_interpret_ica::m_insert_proxy( int inp_port )
{
    char chrl_port[6];

    sprintf( chrl_port, "%d", inp_port );
    m_send_data( (char*)"ProxyType=socksv5\r\n", strlen("ProxyType=socksv5\r\n") );
    m_send_data( (char*)"ProxyHost=127.0.0.1:",  strlen("ProxyHost=127.0.0.1:")  );
    m_send_data( chrl_port,                      strlen(chrl_port)               );
    m_send_data( (char*)"\r\n",                  strlen("\r\n")                  );
} /* end of dsd_interpret::m_insert_proxy */


void dsd_interpret_ica::m_set_port(int inp_port)
{
	this->inc_port = inp_port;
} /* end of dsd_interpret_ica::m_set_port */


/**
 * private function dsd_interpret_ica::m_is_line_prefix
 *  check whether give line starts with prefix
 *
 * @param[in]   const char  *achp_line          ptr to line
 * @param[in]   int         inp_length          length of line
 * @param[in]   const char  *achp_prefix        prefix to check 
 *
 * @return      bool
*/
bool dsd_interpret_ica::m_is_line_prefix( const char *achp_line,
                                          int inp_length,
                                          const char *achp_prefix )
{
    int inl_pref = (int)strlen( achp_prefix );
    if ( inl_pref > inp_length ) {
        return false;
    }

    return ( memcmp(achp_line,achp_prefix,(size_t)inl_pref) == 0);
} /* end of dsd_interpret_ica::m_is_line_prefix


/**
 * private function dsd_interpret_ica::m_get_line
 *
 * @param[in]       const char  *achp_data      input data
 * @param[in]       int         inp_len_data    length of input data
 *
 * @return          int                         length of found line
*/
int dsd_interpret_ica::m_get_line( const char *achp_data, int inp_len_data )
{
    int inl_length = 0;

    while ( inl_length < inp_len_data ) {
        switch( achp_data[inl_length] ) {
            case '\r':
            case '\n':
                inl_length++;
                while (    achp_data[inl_length] == '\r'
                        || achp_data[inl_length] == '\n' ) {
                    inl_length++;
                }
                break;
            default:
                inl_length++;
                continue;
        }
        break;
    }
    return inl_length;
} /* end of dsd_interpret_ica::m_get_line

/**
 * @ingroup dataprocessor
 *
 * @param[in]   ads_session_in		A pointer to the ds_session class
 * @param[in]   ach_address_wsp_in	A const char pointer
 * @param[in]   ach_address_ext_in	A const char pointer
 * @param[in]   ach_path_ext_in		A const char pointer
 *
 * @return      bool    
 *
*/
bool dsd_interpret_ica::m_setup( ds_session* ads_session_in )
{
    dsc_line.m_setup( ads_session_in->ads_wsp_helper );
	this->inc_port = 0;
    return ds_interpret::m_setup( ads_session_in );
} // end of ds_interpret_css::m_setup
