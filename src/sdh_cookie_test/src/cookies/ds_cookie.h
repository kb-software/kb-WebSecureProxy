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


/*+---------------------------------------------------------------------+*/
/*| forward defintions:                                                 |*/
/*+---------------------------------------------------------------------+*/
class ds_wsp_helper;
class ds_hstring;

/*+---------------------------------------------------------------------+*/
/*| class defintion:                                                    |*/
/*+---------------------------------------------------------------------+*/
class ds_cookie {
public:
    // constructor:
    ds_cookie();
    ds_cookie( ds_wsp_helper* ads_wsp_helper );
    ds_cookie( const ds_cookie& ds_copy );

    void m_init( ds_wsp_helper* ads_wsp_helper );

    // parsing functions:
    void m_set_req_host( const char* ach_domain, int in_len_domain,
                         const char* ach_path,   int in_len_path   );
    bool m_parse_cookie( const char* ach_cookie, int in_len_cookie );


    // reset function:
    void m_reset();

    // working functions:
    bool m_check_lifetime();
    bool m_name_equals( ds_cookie* ads_compare );

    // getter functions:
    char*          m_get_cookie    ();
    int            m_get_version   ();
    time_t         m_get_expires   ();
    char*          m_get_domain    ();
    char*          m_get_path      ();
    unsigned short m_get_port      ();
    char*          m_get_comment   ();
    char*          m_get_commenturl();
    bool           m_is_secure     ();
    bool           m_is_httponly   ();
    bool           m_is_discard    ();

    // setter functions:
    void m_set_cookie    ( const char* ach_add, int in_len );
    void m_set_version   ( int in_version );
    void m_set_expires   ( time_t il_expires );
    void m_set_domain    ( const char* ach_add, int in_len );
    void m_set_path      ( const char* ach_add, int in_len );
    void m_set_port      ( unsigned short uis_port );
    void m_set_comment   ( const char* ach_add, int in_len );
    void m_set_commenturl( const char* ach_add, int in_len );
    void m_set_secure    ();
    void m_set_httponly  ();
    void m_set_discard   ();

private:
    // variables:
    ds_wsp_helper*  adsc_wsp_helper;        // wsp callback class
    ds_hstring      dsc_cookie;             // name=value
    int             inc_version;            // cookie version
    time_t          ilc_expires;            // expire data in seconds since 1.1.1970
    ds_hstring      dsc_domain;             // domain (or part of domain) cookie is valid for
    ds_hstring      dsc_path;               // path cookie is valid for
    unsigned short  uisc_port;              // port cookie is valid for
    ds_hstring      dsc_comment;            // better cookie description
    ds_hstring      dsc_commenturl;         // url to better cookie description
    bool            boc_secure;             // send cookie only over secure connection
    bool            boc_http_only;          // cookie not reachable over javascript
    bool            boc_discard;            // delete cookie at logout

    ds_hstring      dsc_req_domain;         // requested domain
    ds_hstring      dsc_req_path;           // requested path

    // functions:
    void m_get_next_word  ( const char* ach_cookie, int in_len_cookie,
                            int* ain_position, char** aach_word, int* ain_len_word );
    void m_get_value      ( const char* ach_cookie, int in_len_cookie, 
                            int* ain_position, char** aach_value, int* ain_len_value );
    void m_pass_signs     ( const char* ach_data, int in_len_data,
                            int* ain_position, const char chr_sign_list[] );
    void m_get_quote_end  ( const char* ach_cookie, int in_len_cookie, int* ain_position );
    int  m_is_word_in_list( char* ach_word, int in_len_word );
    bool m_set_expires    ( char* ach_expires, int in_len_expires );
    bool m_set_max_age    ( char* ach_max_age, int in_len_max_age );
};

#endif // _DS_COOKIE_H
