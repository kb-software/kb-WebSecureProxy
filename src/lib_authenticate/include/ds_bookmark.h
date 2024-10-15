#ifndef _DS_BOOKMARK_H
#define _DS_BOOKMARK_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_bookmark                                                           |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   January 2010                                                          |*/
/*|                                                                         |*/
/*| VERSION:                                                                |*/
/*| ========                                                                |*/
/*|   0.9                                                                   |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| forward defintions:                                                     |*/
/*+-------------------------------------------------------------------------+*/
class  ds_wsp_helper;
class  ds_hstring;
struct dsd_xml_tag;


/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Stores Information about the bookmarks in the WebServerGate
 *
 * \ingroup authlib
 *
 *  Details follow
 */
class ds_bookmark {
public:
    // functions:
    void         m_init    ( ds_wsp_helper* ads_wsp_helper );
    virtual void m_reset   ();
    bool         m_from_xml( const char* ach_xml, int in_len );
    virtual bool m_from_xml( dsd_xml_tag* ads_pnode );
    virtual bool m_to_xml  ( ds_hstring* ads_xml ) const;

    bool m_get_url ( const char** aach_url,  int* ain_len ) const;
    bool m_get_name( const char** aach_name, int* ain_len ) const;
    bool m_is_own  () const;

    void m_set_url ( const char* ach_url,  int in_len );
    void m_set_name( const char* ach_name, int in_len );
    void m_set_own ( bool bo_own );

    virtual bool m_is_complete();
protected:
    // variables:
    ds_wsp_helper*  adsc_wsp_helper;
    ds_hstring      dsc_name;
    ds_hstring      dsc_url;
    bool            boc_is_own;
};

#endif // _DS_BOOKMARK_H
