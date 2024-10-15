#ifndef _DSD_INTERPRET_ICA_H_
#define _DSD_INTERPRET_ICA_H_
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program                                                             |*/
/*| -------                                                             |*/
/*|   dsd_interpret_ica                                                 |*/
/*|   class to modify Citrix ICA Configuration Files on the Fly         |*/
/*|                                                                     |*/
/*| Author                                                              |*/
/*| ------                                                              |*/
/*|   Michael Jakobs, Okt. 2011                                         |*/
/*|                                                                     |*/
/*| Copyright                                                           |*/
/*| ---------                                                           |*/
/*|   HOB GmbH Germany 2011                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| include local headers                                               |*/
/*+---------------------------------------------------------------------+*/
#include "ds_interpret.h"
#include <ds_hstring.h>

/*+---------------------------------------------------------------------+*/
/*| class definition:                                                   |*/
/*+---------------------------------------------------------------------+*/
/*! \brief Interprets ICA data.
 *
 * @ingroup dataprocessor
 *
 * This class modifies Citrix ICA Configuration Files on the Fly.
 */
class dsd_interpret_ica : public ds_interpret
{
public:
    //! Constructor.
    dsd_interpret_ica(void);
    //! Destructor.
    ~dsd_interpret_ica(void);
    // functions:
	//! Processes ica data.
    int m_process_data();
	//! Parse the received data.
    int m_parse_data  ( const char *achp_data, int inp_len_data,
                        bool bop_data_complete = false,
                        ds_hstring *adsp_output = NULL );
    // take care: m_setup overwrite ds_interpret::m_setup!
	//! Setup strings.
    bool m_setup      ( ds_session* ads_session_in );

private:
    ds_hstring dsc_line;
    enum ied_state {
        ied_st_normal = 0,      /* normal parsing state */
        ied_st_address_found,   /* address field found  */
        ied_st_proxy_inserted   /* proxy hase inserted  */
    } ienc_state;
	int inc_port;

    int  m_get_line      ( const char *achp_data, int inp_len_data );
    bool m_is_line_prefix( const char *achp_line, int inp_length, const char *achp_prefix );
    void m_insert_proxy  ( int inp_port );
public:
    void m_set_port(int inp_port);
};

#endif /* _DSD_INTERPRET_ICA_H_ */
