#ifndef _DS_WORKSTATION_H
#define _DS_WORKSTATION_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_workstation                                                        |*/
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
/*| helper class:                                                           |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief stores network information about the workstations
 *
 * \ingroup authlib
 *
 *  Details follow
 */
class ds_workstation {
public:
    // functions:
    void m_init    ( ds_wsp_helper* ads_wsp_helper );
    bool m_from_xml( const char* ach_xml, int in_len );
    bool m_from_xml( dsd_xml_tag* ads_pnode );
    bool m_to_xml  ( ds_hstring* ads_xml ) const;

    bool           m_get_name ( const char** aach_name,  int* ain_len ) const;
    bool           m_get_ineta( const char** aach_ineta, int* ain_len ) const;
    const unsigned char* m_get_mac  () const;
    void           m_get_mac  ( unsigned char chr_mac[6] ) const;
    void           m_write_mac( ds_hstring* ads_out );
    unsigned short m_get_port () const;
    int            m_get_wait () const;

    void m_set_name ( const char* ach_name,  int in_len );
    void m_set_ineta( const char* ach_ineta, int in_len );
    void m_set_mac  ( unsigned char chr_mac[6] );
    bool m_set_mac  ( const char* ach_mac,   int in_len );
    bool m_set_port ( int in_port );
    void m_set_wait ( int in_wait );

    bool m_is_complete();
    void m_reset();

private:
    // variables:
    ds_wsp_helper* adsc_wsp_helper;
    ds_hstring     dsc_name;
    ds_hstring     dsc_ineta;
    unsigned char  chrc_mac[6];
    unsigned short uisc_port;
    int            inc_wait;

    bool m_string_to_mac( const char* ach_str, int in_len, unsigned char chr_mac[6] );
};

#endif // _DS_WORKSTATION_H
