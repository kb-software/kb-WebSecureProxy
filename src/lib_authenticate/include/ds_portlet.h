#ifndef _DS_PORLTET_H
#define _DS_PORLTET_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_portlet                                                            |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   March 2010                                                            |*/
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
/*| helper class:                                                           |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief class which handles the configured portlets
 *
 * \ingroup authlib
 *
 *  Details follow
 */
class ds_portlet {
public:
    // functions:
    void m_init    ( ds_wsp_helper* ads_wsp_helper );
    bool m_from_xml( const char* ach_xml, int in_len );
    bool m_from_xml( dsd_xml_tag* ads_pnode );
    bool m_to_xml  ( ds_hstring* ads_xml ) const;

    bool m_get_name ( const char** aach_name,  int* ain_len ) const;
    bool m_is_open  () const;

    void m_set_name ( const char* ach_name,  int in_len );
    void m_set_open ( bool bo_open );

    bool m_is_complete() const;
    void m_reset();

private:
    // variables:
    ds_wsp_helper* adsc_wsp_helper;
    ds_hstring     dsc_name;
    bool           boc_open;
};

#endif // _DS_PORLTET_H
