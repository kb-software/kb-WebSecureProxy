#ifndef _DSD_WFA_BMARK_H
#define _DSD_WFA_BMARK_H
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
class  ds_bookmark;

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Derived bookmark class for the WebFileAccess
 *
 * \ingroup authlib
 *
 *  Details follow
 */
class dsd_wfa_bmark : public ds_bookmark {
public:
    // functions:
    void         m_init    ( ds_wsp_helper* ads_wsp_helper );
    virtual void m_reset   ();
    virtual bool m_from_xml( dsd_xml_tag* ads_pnode );
    virtual bool m_to_xml  ( ds_hstring* ads_xml ) const;

    void m_set_user    ( const char *achp_user, int inp_length );
    void m_set_pwd     ( const char *achp_pwd,  int inp_length );
    void m_set_domain  ( const char *achp_domain, int inp_length );
    void m_set_position( int inp_pos );

    bool m_get_user    ( const char **aachp_user,   int *ainp_length ) const;
    bool m_get_pwd     ( const char **aachp_pwd,    int *ainp_length ) const;
    bool m_get_domain  ( const char **aachp_domain, int *ainp_length ) const;
    int  m_get_position() const;

    virtual bool m_is_complete();
protected:
    // variables:
    ds_hstring  dsc_user;
    ds_hstring  dsc_pwd;
    ds_hstring  dsc_domain;
    int         inc_position;
};

#endif // _DSD_WFA_BMARK_H
