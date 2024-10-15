#ifndef _DS_WPAT_H
#define _DS_WPAT_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   ds_wspat                                                          |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|   Michael Jakobs, July 2009                                         |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH Germany 2009                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#include <ds_hstring.h>
#ifndef HL_UINT
    typedef unsigned int HL_UINT;
#endif

/*+---------------------------------------------------------------------+*/
/*| constants:                                                          |*/
/*+---------------------------------------------------------------------+*/
// allowed keywords: (compare to achr_wspat_keywords in source file)
enum ied_wspat_keyword {
    ied_wspat_key_unknown  = -1,
    ied_wspat_key_language =  0,
    ied_wspat_key_userid       ,
    ied_wspat_key_password     ,
    ied_wspat_key_server
};              

// supported languages:
enum ied_wspat_language {
    ied_wspat_lang_en = (('e' << 8) | 'n'),       // en English
    ied_wspat_lang_es = (('e' << 8) | 's'),       // es Spanish
    ied_wspat_lang_fr = (('f' << 8) | 'r'),       // fr French
    ied_wspat_lang_de = (('d' << 8) | 'e'),       // de German
    ied_wspat_lang_it = (('i' << 8) | 't'),       // it Italian
    ied_wspat_lang_nl = (('n' << 8) | 'l'),       // nl Dutch
    ied_wspat_lang_zh = (('z' << 8) | 'h')        // zh Chinese
};

enum ied_wspat_state {
    /*
        states for each incoming packet:
    */
    ied_wspat_firstbyte          =   0,       // first byte of packet
    ied_wspat_secondbyte         =   1,       // second byte of packet
    ied_wspat_response           =   2,       // create response
    
    /*
        states for first client request:
    */
    ied_wspat_proto_first         = 100,      // first packet of client request
    ied_wspat_first_protocol      = 101,      // read protocol
    ied_wspat_first_keyword       = 102,      // read keyword
    ied_wspat_first_keyvalue      = 103,      // read keyvalue
    ied_wspat_first_method_length = 104,      // read length of methods
    ied_wspat_first_methods       = 105,      // read methods itself

    /*
        states for do authentication request:
    */
    ied_wspat_proto_auth         = 200,       // start of authentication request
    ied_wspat_auth_len           = 201,       // read length in NHASN
    ied_wspat_auth_input         = 202,       // read input field

    /*
        states for display server / do connect request:
    */
    ied_wspat_disp_server        = 300,       // display server
    ied_wspat_srv_state          = 301,       // read status field
    ied_wspat_srv_len            = 302,       // read length in NHASN
    ied_wspat_srv_srv            = 303,       // read server field

    /*
        state for desktop demand
    */
    ied_wspat_dod                = 400        // desktop on demand
};

/*+---------------------------------------------------------------------+*/
/*| helper structures:                                                  |*/
/*+---------------------------------------------------------------------+*/
// first client request structure:
struct dsd_wspat_first_packet {
    bool             bo_meth_no_auth;       // method no auth supported
    bool             bo_meth_auth;          // method auth supported
    bool             bo_meth_disp_serv;     // method display server supported

    // helper vars (needed just while parsing)
    ied_wspat_keyword  ien_keyword;           // current keyword
    int              in_meth_len;           // number of method fields
    ied_wspat_state  ien_state;             // parsing state variable
};

struct dsd_wspat_auth_packet {
    // helper vars (needed just while parsing)
    int              in_length;             // current length of input field
    ied_wspat_state  ien_state;             // parsing state variable
};

struct dsd_wspat_srv_packet {
    // helper vars (needed just while parsing)
    int              in_length;             // current length of input field
    ied_wspat_state  ien_state;             // parsing state variable
};

/*+---------------------------------------------------------------------+*/
/*| class definition:                                                   |*/
/*+---------------------------------------------------------------------+*/
class  ds_wsp_helper;           // forward definition
class  ds_usercma;              // forward definition
struct dsd_wspat_config;        // forward definition
enum ied_cert_auth_result;

class ds_wspat {

public:
    // contructor/destructor:
    ds_wspat();
    ~ds_wspat();

	bool done;

    // operator new:
    void* operator new(size_t, void* av_location) {
        return av_location;
    }
    // avoid warning:
    void operator delete( void*, void* ) {};

    // functions:
    void m_init( ds_wsp_helper* adsp_wsp_helper );
    void m_run ();
    
    // variables:
    void* av_storage;                       // storage container handle

private:
    // variables:
    ds_wsp_helper*       adsc_wsp_helper;   // wsp helper class
    dsd_wspat_config*    adsc_config;       // our configuration
    dsd_wspat3_conn*     adsc_connect;      // wsp connection structure
    ds_hstring           dsc_rad_state;     // buffer for radius state
    ds_hstring           dsc_rad_mess;      // buffer for radius message
    void*                avc_usergroup;     // usergroup entry (will be filled while auth call)
    void*                avc_userentry;     // user entry (will be filled while auth call)
    HL_UINT              uinc_auth;         // return from authentication
    bool                 boc_kick_out;      // this user will kick out another session
    ds_usercma           dsc_ucma;          // usercma class
    bool                 boc_expires;       // password expires

    // status variables:
    ied_wspat_state      ienc_gstate;       // global state variable
    int                  inc_processed;     // processed start position
    int                  inc_offset;        // working position in data

    // desktop on demand stuff:
    ds_hstring           dsc_dod_ineta;     // desktop on demand ineta

    // variables, that can be used in all packets:
    ied_wspat_language   ienc_language;     // selected language
    ds_hstring           dsc_userid;        // send userid
    ds_hstring           dsc_password;      // send password
    ds_hstring           dsc_new_pwd;       // buffer for new password (case of changing)
    ds_hstring           dsc_save_pwd;      // buffer for old password (case of changing)
    ds_hstring           dsc_server;        // selected server
    ds_hstring           dsc_proto;         // selected protocol
    ied_scp_def          ienc_proto;        // type of protocol

    // packet variables:
    dsd_wspat_first_packet dsc_fpacket;       // first client packet
    dsd_wspat_auth_packet  dsc_apacket;       // authentication packet
    dsd_wspat_srv_packet   dsc_spacket;       // display server packet

#if SM_USE_CERT_AUTH
	enum ied_cert_auth_result iec_certificate_auth;
	const struct dsd_certificate_auth_entry* adsc_cert_auth_entry;  // certificate entry
	ds_hstring           dsc_cert_userid;        // send userid
#endif

    // functions:
    int m_handle_data( dsd_gather_i_1* ads_input );

    // first packet functions:
    int             m_parse_fpacket( dsd_gather_i_1* ads_input, int in_length );
    ied_wspat_keyword m_get_keytype  ( dsd_gather_i_1* ads_input, int in_start, int in_end );
    bool            m_save_keyvalue( dsd_gather_i_1* ads_input, int in_start, int in_end );

    // auth packet functions:
    int  m_parse_authpacket( dsd_gather_i_1* ads_input, int in_length );
    bool m_save_auth_input ( dsd_gather_i_1* ads_input, int in_start, int in_end );

    // select server packet functions:
    int  m_parse_srvpacket( dsd_gather_i_1* ads_input, int in_length );
    bool m_save_server    ( dsd_gather_i_1* ads_input, int in_start, int in_end );

    // dod functions:
    bool m_fill_dod( const char* ach_wstat, int in_len_wstat );

    // response functions:
    int m_create_response  ();
	 int m_request_auth     ( int in_message, const dsd_const_string& rdsp_message );
    int m_pwd_expires      ( int inp_expire_days );
    int m_request_challenge();
    int m_send_server_list ();
    int m_prepare_connect  ();
    int m_send_dod         ();
};

#endif // _DS_WPAT_H
