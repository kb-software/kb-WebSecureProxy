#ifndef __socks5
#define __socks5


#include <ds_hstring.h>
#include <ds_wsp_helper.h>

class socks5
{
private:
    int in_client_suggest_methods;

    ds_wsp_helper* ads_wsp_helper;
    struct dsd_hl_clib_1 * ads_trans;

    const static int in_maxlen_username_password   = 256;
    const static int in_maxlen_domain   = 256;

    const static int in_meth_no_auth   = 0x00; // NO AUTHENTICATION REQUIRED
    const static int in_meth_gssapi    = 0x01; // GSSAPI
    const static int in_meth_user_pwd  = 0x02; // USERNAME/PASSWORD
    const static int in_meth_no_accept = 0xFF; // NO ACCEPTABLE METHODS

    // address/port to which we shall connect (we replied to client, too)
    unsigned char auch_port_to_connect_to[2];
    unsigned char auch_address_ipv4[5];
    unsigned char auch_address_ipv6[17];
    unsigned char auch_address_domain[in_maxlen_domain];

    // for Socks4/4A
    unsigned char auch_user_id[in_maxlen_username_password];
    unsigned char auch_4_domain[in_maxlen_domain];

    // distinguish between Socks4A and Socks5
    bool bo_socks4;
    bool bo_socks_4a;

    // Address type, which is delivered in client's request.
    int in_atyp_request;

public:
    socks5() {
        in_client_suggest_methods = 0;
        memset(&auch_port_to_connect_to[0], 0, 2);
        memset(&auch_address_ipv4[0], 0, 5);
        memset(&auch_address_ipv6[0], 0, 17);
        memset(&auch_user_id[0], 0, in_maxlen_username_password);
        memset(&auch_4_domain[0], 0, in_maxlen_domain);
        bo_socks4 = false;
        bo_socks_4a = false;
    }

  void* operator new(size_t, void* location) {
    return location;
  }
    // avoid warning:
    void operator delete( void*, void* ) {};

    void m_setup(ds_wsp_helper* adsl_wsp_helper, dsd_hl_clib_1 * ads_trans_in);
    void Handle();
    
protected:    

private:
    const static bool bo_no_auth_allowed = true;
    const static bool bo_radius_on = false;

enum states {
   ien_st_first_byte,                   // first byte of Socks5-communication must be 0x05
   ien_st_second_byte,                  // second byte: number of authentication methods, which the client supports (allowed: 1-255)
   ien_st_read_client_meth,             // read in the authentication methods, which the client supports
   ien_st_first_byte_userpw,            // Socks5-protocol states: first byte of username/password-authentication must be 0x01
   ien_st_len_username,                 // second byte of username/password-authentication is the length of the username
   ien_st_read_username,                // read in the username
   ien_st_len_password,                 // length of the password
   ien_st_read_password,                // read in the password
   ien_st_first_byte_request,           // first byte of client's request must be 0x05
   ien_st_command_request,              // command byte; we support only 0x01=CONNECT
   ien_st_reserved_request,             // reserved byte (must be 0x00)
   ien_st_address_type,                 // read address type; we support only 0x01=IPv4
   ien_st_read_address_ipv4,            // read the address (format IPv4; 4 octets)
   ien_st_read_address_ipv6,            // read the address (format IPv6; 16 octets)
   ien_st_read_address_domain,          // read the address (which is a domain  name)
   ien_st_read_port,                    // read the port (2 bytes)
   ien_st_copy_in_to_out,               // normal processing; just copy incoming data to output
   ien_st_4_first_byte,                 // Socks4: first byte of Socks4-communication must be 0x04
   ien_st_4_second_byte,                // Socks4: command code must be 0x01 for CONNECT
   ien_st_4_read_dest_port,
   ien_st_4_read_address,
   ien_st_4_read_user_id,
   ien_st_4_read_domain,                // Socks4A
   ien_st_4_do_connect                  // Socks4: establish connection to server
};

    void m_mark_as_processed(char* ach_processed_til_here, struct dsd_gather_i_1 * adsl_current_gather);
    // socks server must select one of the authentication methods, which the client suggested
    int m_select_auth_method(int in_suggested_by_client);
    // Send data to client or server.
    int m_send(char* ach_output, int in_len_output, bool bo_terminate_connection, enum ied_sdh_data_direction ienp_direction /*= ied_sdh_dd_auto*/);
    // authenticate the delivered username and password
    bool m_authenticate(char* ach_username, char* ach_password);
    // establish the TCP connection
    // JF 19.12.06  bool m_connect_to_server();
    bool m_connect_to_server(char* ach_server_address, int* in_detailled_error);

    bool m_auth_radius(char* ach_username, char* ach_password);
};

#endif
