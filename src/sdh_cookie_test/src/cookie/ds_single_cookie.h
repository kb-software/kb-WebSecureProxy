/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_single_cookie                                                      |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   April/Mai 2008                                                        |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

#ifndef DS_SINGLE_COOKIE_H
#define DS_SINGLE_COOKIE_H

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define NUM_COOKIE_WORDS     7
#define NUM_COOKIE_XMLS      5
#define CK_MAX_SIZE        256
#define CK_VALUE_SIZE     4096

// states:
#define CK_ST_NAME      1
#define CK_ST_VALUE     2
/*+-------------------------------------------------------------------------+*/
/*| include global headers                                                  |*/
/*+-------------------------------------------------------------------------+*/
#include <time.h>
#include <cstring>
#include <string>
using namespace std;

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "../utils/hob-xsltime1.h"

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
class ds_wsp_helper;
class ds_single_cookie
{
public:
    // constructor:
    ds_single_cookie( ds_wsp_helper* adsl_wsp_helper );

    void m_setup( string str_host );
    void m_parse_cookie( char* ach_cookie, int in_len_cookie );
    void m_parse_xml( char* ach_xml, int in_len );

    // getter functions:
    string m_get_cookie();
    string m_get_host();
    string m_get_domain();
    string m_get_path();
    time_t m_get_lifetime();
    string m_get_name();
    string m_get_value();
    bool   m_get_secure();
private:
    // working variables:
    int in_state;
    ds_wsp_helper* adsc_wsp_helper;

    // cookie variables:
    char    rch_name[CK_MAX_SIZE];
    char    rch_value[CK_VALUE_SIZE];
    char    rch_domain[CK_MAX_SIZE];
    char    rch_path[CK_MAX_SIZE];
    char    rch_comment[CK_MAX_SIZE];
    time_t  t_expires;
    bool    bo_secure;
    bool    bo_delete_at_logout;
    int     in_version;
    

    // functions:
    int  m_is_word_in_list( char* ach_word, int in_len_word );
    void m_get_next_word( char* ach_cookie, int in_len_cookie, int* ain_position, char** aach_word, int* ain_len_word );
    void m_get_value( char* ach_cookie, int in_len_cookie, int* ain_position, char** aach_value, int* ain_len_value );
    void m_pass_signs( char* ach_data, int in_len_data, int* ain_position, const char chr_sign_list[] );
    void m_get_quote_end( char* ach_cookie, int in_len_cookie, int* ain_position );
    int  m_remove_std_port( char* ach_domain, int in_len_domain );

    // setter functions:
    bool m_set_name   ( char* ach_name,    int in_len_name    );
    bool m_set_value  ( char* ach_value,   int in_len_value   );
    bool m_set_domain ( char* ach_domain,  int in_len_domain  );
    bool m_set_path   ( char* ach_path,    int in_len_path    );
    bool m_set_comment( char* ach_comment, int in_len_comment );
    bool m_set_expires( char* ach_expires, int in_len_expires );
    bool m_set_max_age( char* ach_max_age, int in_len_max_age );
    bool m_set_version( char* ach_version, int in_len_version );
    bool m_set_secure ();

    // xml functions:
    void   m_get_tag( char* ach_xml, int in_len, int* ain_pos, char** aach_tag, int* ain_len_tag );
    string m_get_value( char* ach_xml, int in_len, int* ain_pos, char* ach_tag, int in_len_tag );
    int    m_is_tag_in_list( char* ach_tag, int in_len_tag );

    // cookie attributes:
    string cookie_words[NUM_COOKIE_WORDS];
    void m_set_cookie_words() {
        cookie_words[0] = "comment";
        cookie_words[1] = "domain";
        cookie_words[2] = "expires";
        cookie_words[3] = "max-age";
        cookie_words[4] = "path";
        cookie_words[5] = "secure";
        cookie_words[6] = "version";
    }
    enum ie_cookie_attributes {
        CK_COMMENT,
        CK_DOMAIN,
        CK_EXPIRES,
        CK_MAX_AGE,
        CK_PATH,
        CK_SECURE,
        CK_VERSION
    };

    // xml words:
    string cookie_xmls[NUM_COOKIE_XMLS];
    void m_set_cookie_xmls() {
        cookie_xmls[0] = "<name>";
        cookie_xmls[1] = "<value>";
        cookie_xmls[2] = "<expires>";
        cookie_xmls[3] = "<secure>";
        cookie_xmls[4] = "<host>";
    }

    enum ie_cookie_xmls {
        XML_NAME,
        XML_VALUE,
        XML_EXPIRES,
        XML_SECURE,
        XML_HOST
    };
};
#endif //DS_SINGLE_COOKIE_H
