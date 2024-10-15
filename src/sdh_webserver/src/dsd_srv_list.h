#ifndef _DSD_SRV_LIST_H
#define _DSD_SRV_LIST_H
/*+---------------------------------------------------------------------+*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|  holds temporary configuration of webserver serverlists             |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|  Michael Jakobs, Mai 2012                                           |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| forward declarations                                                |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;
template <class T> class ds_hvector;
class ds_hstring;
struct dsd_unicode_string;

#ifndef BOOL
    #define BOOL int
#endif

//extern "C" BOOL m_cmpi_vx_vx( int*, void*, int, enum ied_charset,
//                                    void*, int, enum ied_charset );

/*+---------------------------------------------------------------------+*/
/*| definitions:                                                        |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achg_srv_ent_func[] = {
    "ICA"
};
enum ied_ws_srv_entry_func;

/*+---------------------------------------------------------------------+*/
/*| class definition:                                                   |*/
/*+---------------------------------------------------------------------+*/
/*! \brief Server entry class
 *
 * @ingroup configuration
 *
 * holds temporary configuration of webserver serverlists
 */
class dsd_srv_entry {
public:
    /**
     * constructor dsd_srv_entry
    */
    dsd_srv_entry()
    {
        iec_func = ied_ws_srv_func_invalid;
    } /* end of dsd_srv_entry::dsd_srv_entry */

	
	/*! \brief Class initializer function
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_entry::m_init
     *  initialize wsp helper object
     *
     * @param[in]   ds_wsp_helper   *adsp_wsp_helper
     * @return      nothing
    */
    void m_init( ds_wsp_helper *adsp_wsp_helper )
    {
        dsc_name.m_init( adsp_wsp_helper );
        dsc_url.m_init( adsp_wsp_helper );
    } /* end of dsd_srv_entry::m_init */

    /*! \brief Sets the name of a server entry
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_entry::m_set_name
     *  set name of server-entry
     *
     * @param[in]   dsd_unicode_string  *adsp_name
     * @return      bool                        true = successful
     *                                          false = name already set
    */ 
    bool m_set_name( struct dsd_unicode_string *adsp_name )
    {
        if ( dsc_name.m_get_len() > 0 ) {
            return false;
        }
        dsc_name.m_set( adsp_name );
        return true;
    } /* end of dsd_srv_entry::m_set_name */

	/*! \brief Set URL
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_entry::m_set_url
     *  set url of server-entry
     *
     * @param[in]   dsd_unicode_string  *adsp_url
     * @return      bool                        true = successful
     *                                          false = name already set
    */ 
    bool m_set_url( struct dsd_unicode_string *adsp_url )
    {
        if ( dsc_url.m_get_len() > 0 ) {
            return false;
        }
        dsc_url.m_set( adsp_url );
        if (    dsc_url.m_starts_with("http://")  == false
             && dsc_url.m_starts_with("https://") == false ) {
            dsc_url.m_insert_const_str( 0, "http://" );
        }
        return true;
    } /* end of dsd_srv_entry::m_set_url */

	/*! \brief Set function
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_entry::m_set_func
     *  set function
     *
     * @param[in]   dsd_unicode_string  *adsp_url
     * @return      bool                            true = valid function
     *                                              false otherwise
    */
    bool m_set_func( struct dsd_unicode_string *adsp_url )
    {
        this->iec_func = ds_wsp_helper::m_search_equals_ic2(achg_srv_ent_func, *adsp_url, ied_ws_srv_func_invalid);
        return (iec_func != ied_ws_srv_func_invalid);
    } /* end of dsd_srv_entry::m_set_func */

	/*! \brief Check if the server list is complete
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_entry::m_is_complete
     *  check of server list is complete
     *
     * @return  bool
    */
    bool m_is_complete()
    {
        return (    (dsc_name.m_get_len() > 0)
                 && (dsc_url.m_get_len()  > 0)
                 && (iec_func != ied_ws_srv_func_invalid) );
    } /* end of dsd_srv_entry::m_is_complete */

    /*! \brief Reset the class
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_entry::m_reset
     *  reset this server entry
     *
     * @return      nothing
    */
    void m_reset()
    {
        dsc_name.m_reset();
        dsc_url.m_reset();
        iec_func = ied_ws_srv_func_invalid;
    } /* end of dsd_srv_entry::m_reset */

    ds_hstring                 dsc_name;        /* name of server-entry  */
    enum ied_ws_srv_entry_func iec_func;        /* function              */
    ds_hstring                 dsc_url;         /* url of server entry   */
};


/*! \brief Server list class
 *
 * @ingroup configuration
 *
 * Holds a server list
 */
class dsd_srv_list {
public:
    /*! \brief Class initializer function
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_list::m_init
     *  initialize wsp helper object
     *
     * @param[in]   ds_wsp_helper   *adsp_wsp_helper
     * @return      nothing
    */
    void m_init( ds_wsp_helper *adsp_wsp_helper )
    {
        dsc_name.m_init( adsp_wsp_helper );
        dsc_srv_entries.m_init( adsp_wsp_helper );
    } /* end of dsd_srv_list::m_init */

    /*! \brief Sets a name for the server list
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_list::m_set_name
     *  set name of server list
     *
     * @param[in]   dsd_unicode_string  *adsp_name
     * @return      bool                        true = successful
     *                                          false = name already set
    */
    bool m_set_name( struct dsd_unicode_string *adsp_name )
    {
        if ( dsc_name.m_get_len() > 0 ) {
            return false;
        }
        dsc_name.m_set( adsp_name );
        return true;
    } /* end of dsd_srv_list::m_set_name */

    /*! \brief Add an entry
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_list::m_add_srv_entry
     *  add server entry
     *
     * @param[in]   dsd_srv_entry   dsp_srv_entry
     * @return      nothing
    */
    void m_add_srv_entry( dsd_srv_entry dsp_srv_entry )
    {
        dsc_srv_entries.m_add( dsp_srv_entry );
    } /* end of dsd_srv_list::m_add_srv_entry */

    /*! \brief Check if the list is complete
	 *
	 * @ingroup configuration
	 *
     * public method dsd_srv_list::m_is_complete
     *  check of server list is complete
     *
     * @return  bool
    */
    bool m_is_complete()
    {
        return ((dsc_name.m_get_len() > 0) && (!dsc_srv_entries.m_empty()));
    } /* end of dsd_srv_list::m_is_complete */

    ds_hstring                dsc_name;         /* name of server-list   */
    ds_hvector<dsd_srv_entry> dsc_srv_entries;  /* server entries        */ 
};

#endif /* _DSD_SRV_LIST_H */
