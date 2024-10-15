
#include "ds_url.h"

class ds_session; //forward-definition!!

/*! \brief Parses URL
 *
 * @ingroup webserver
 *
 * Just parses an URL
 */
class ds_url_parser
{
    
public:
    enum url_types {
        ien_url_type_abs_path,                // ('folder/file.html')
        ien_url_type_asterisk,                // asterisk ('*')
        ien_url_type_authority,                // not supported !!
        ien_url_type_abs_path_for_wsg,        // ('/http://www.google.de')
        //ien_url_type_abs_path_for_wsg_ssl    // ('/https://sparkasse.de')
    };

    ds_url_parser(ds_session* ads_session_in);
    ~ds_url_parser(void);

    int m_parse(ds_url& ds_url, const dsd_const_string& ahstr_url); // parse the URL; if something fails, the return value is negative

private:
    ds_session* ads_session;
};
