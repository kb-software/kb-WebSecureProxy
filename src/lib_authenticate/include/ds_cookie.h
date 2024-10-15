#ifndef _DS_COOKIE_H
#define _DS_COOKIE_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| PROGRAM:                                                            |*/
/*| =======                                                             |*/
/*|  ds_cookie - class to handle http cookies centralized in wsg        |*/
/*|                                                                     |*/
/*| AUTHOR:                                                             |*/
/*| ======                                                              |*/
/*|  Michael Jakobs, Okt. 2009                                          |*/
/*|                                                                     |*/
/*| VERSION:                                                            |*/
/*| =======                                                             |*/
/*|  0.1                                                                |*/
/*|                                                                     |*/
/*| COPYRIGHT:                                                          |*/
/*| =========                                                           |*/
/*|  HOB GmbH Germany                                                   |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/** 
 * http://de.wikipedia.org/wiki/HTTP-Cookie
 * Ein Cookie besteht aus einem Namen und einem Wert sowie mehreren erforderlichen oder optionalen Attributen mit oder ohne Wert. Einige Attribute sowie deren Einschließen in Hochkommas werden empfohlen.
 *
 *   Name       | erforderlich | Beliebiger Name und Wert aus ASCII-Zeichen die vom Server übergeben werden
 *   Version    | erforderlich | Gibt die Cookie-Management-Spezifikation in einer Dezimalzahl an (derzeit immer 1).
 *   Expires    | optional     | Ablaufdatum, Zeitpunkt der automatischen Löschung in UTC für HTTP/1.0
 *   Max-age    | optional     | Ablaufzeit in Sekunden - 0 für sofortige Löschung. Der Client darf den Cookie auch nach dieser Zeit benutzen, der Server kann sich also nicht darauf verlassen, dass der Cookie nach dieser Ablaufzeit gelöscht wird.
 *   Domain     | optional     | Domain oder Bestandteil des Domainnamens, für den der Cookie gilt
 *   Path       | optional     | Gültigkeits-Pfad (Teil der Anfrage-URI), um die Gültigkeit des Cookies auf einen bestimmten Pfad zu beschränken
 *   Port       | optional     | Beschränkung des Ports auf den aktuell verwendeten oder auf eine Liste von Ports
 *   Comment    | optional     | Kommentar zur näheren Beschreibung des Cookies
 *   CommentURL | optional     | URL unter welcher eine Beschreibung zur Funktionsweise zu finden ist
 *   Secure     | optional     | Rücksendung des Cookie nur „geschützt“ (wie ist nicht weiter spezifiziert). Die meisten HTTP-Clients senden einen „sicheren“ Cookie nur über eine HTTPS-Verbindung. Das Attribut hat keinen Wert.
 *   Discard    | optional     | Unbedingt Löschung des Cookies bei Beendigung des Webbrowsers.
*/

#define SM_COOKIE_PATH_CASE_SENSITIVE	1

/*+---------------------------------------------------------------------+*/
/*| forward defintions:                                                 |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;
class ds_hstring;

/*+---------------------------------------------------------------------+*/
/*| class defintion:                                                    |*/
/*+---------------------------------------------------------------------+*/
/*! \brief Cookie handling class
 *
 * \ingroup authlib
 *
 *  Details follow
 */
class ds_cookie {
public:
	static bool m_matches_path(const dsd_const_string& rdsp_cookie_path, const dsd_const_string& rdsp_req_path);

    // constructor:
    ds_cookie();
    ds_cookie( ds_wsp_helper* ads_wsp_helper );
    ds_cookie( const ds_cookie& ds_copy );

    void m_init( ds_wsp_helper* ads_wsp_helper );

    // parsing functions:
    void m_set_req_host( const dsd_const_string& rdsp_domain, const dsd_const_string& rdsp_path );
    bool m_parse_cookie( const dsd_const_string& rdsp_cookie );

    // xml functions:
    bool m_to_xml  ( ds_hstring* ads_out ) const;
    bool m_from_xml( const char* ach_xml, int in_len );

    // reset function:
    void m_reset();

    // working functions:
    bool m_check_lifetime() const;
    bool m_name_equals  ( ds_cookie* ads_compare );
    bool m_domain_equals( ds_cookie* ads_compare );

    // getter functions:
    const dsd_const_string    m_get_cookie() const;
    void           m_get_name      ( const char** aach_name,  int *ain_len ) const;
    void           m_get_value     ( const char** aach_value, int *ain_len ) const;
    int            m_get_version   () const;
    hl_time_t      m_get_expires   () const;
    const dsd_const_string    m_get_domain    () const;
    const dsd_const_string    m_get_path      () const;
    unsigned short m_get_port      () const;
    const dsd_const_string    m_get_comment   () const;
    const dsd_const_string    m_get_commenturl() const;
    bool           m_is_secure     () const;
    bool           m_is_httponly   () const;
    bool           m_is_discard    () const;
	bool           m_is_domain     () const;
    int            m_get_stor_pos  () const;
	bool m_matches_path (const dsd_const_string& rdsp_path) const;

    // setter functions:
    void m_set_cookie    ( const char* ach_add, int in_len );
    void m_set_version   ( int in_version );
    void m_set_expires   ( hl_time_t il_expires );
    void m_set_domain    ( const char* ach_add, int in_len );
    void m_set_path      ( const char* ach_add, int in_len );
    void m_set_port      ( unsigned short uis_port );
    void m_set_comment   ( const char* ach_add, int in_len );
    void m_set_commenturl( const char* ach_add, int in_len );
    void m_set_secure    (bool bop_value);
    void m_set_httponly  (bool bop_value);
    void m_set_discard   (bool bop_value);
	void m_set_domain    (bool bop_value);
    void m_set_stor_pos  ( int in_pos );

private:
    // variables:
    ds_wsp_helper*  adsc_wsp_helper;        // wsp callback class
    ds_hstring      dsc_cookie;             // name=value
    int             inc_version;            // cookie version
    hl_time_t       ilc_expires;            // expire data in seconds since 1.1.1970
    ds_hstring      dsc_domain;             // domain (or part of domain) cookie is valid for
    ds_hstring      dsc_path;               // path cookie is valid for
    unsigned short  uisc_port;              // port cookie is valid for
    ds_hstring      dsc_comment;            // better cookie description
    ds_hstring      dsc_commenturl;         // url to better cookie description
    bool            boc_secure;             // send cookie only over secure connection
    bool            boc_http_only;          // cookie not reachable over javascript
    bool            boc_discard;            // delete cookie at logout
	bool            boc_domain;             // has domain attribute

    ds_hstring      dsc_req_domain;         // requested domain
    ds_hstring      dsc_req_path;           // requested path

    int             in_stor_pos;            // position in storage

    // functions:
    void m_get_next_word  ( const char* ach_cookie, int in_len_cookie,
                            int* ain_position, char** aach_word, int* ain_len_word );
    void m_get_value      ( const char* ach_cookie, int in_len_cookie, 
                            int* ain_position, char** aach_value, int* ain_len_value );
    void m_pass_signs     ( const char* ach_data, int in_len_data,
                            int* ain_position, const dsd_const_string& chr_sign_list );
    void m_get_quote_end  ( const char* ach_cookie, int in_len_cookie, int* ain_position );
    int  m_is_word_in_list( const char* ach_word, int in_len_word );
    bool m_set_expires    ( const char* ach_expires, int in_len_expires );
    bool m_set_max_age    ( const char* ach_max_age, int in_len_max_age );
};

#endif // _DS_COOKIE_H
