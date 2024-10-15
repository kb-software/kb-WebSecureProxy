/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define MIN_INTERVAL            10      // minimal keep alive interval in secs
#define WSP_INTERVAL_FACTOR      1.5    // our wsp timer interval multiplier

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#if defined WIN32 || defined WIN64
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#endif

#include <time.h>
#include <rdvpn_globals.h>
#include <ds_wsp_helper.h>
#include <ds_xml.h>

#include "ds_ea_ldap.h"
#include "sdh_ea_ldap.h"
#include <ds_attribute_string.h>
#ifndef HOB_XSLUNIC1_H
	#define HOB_XSLUNIC1_H
	#include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

#include <ds_usercma.h>
#include <ds_authenticate.h>
#include <hob-libwspat.h>

// MG include is needed to use ldap requests 15.10.2012
//#include "ds_ldap.h"

// For the time being there exist hardcoded variables
#define HARDCODED_INSERT_OC true

#define EA_STORAGE_SIZE         32*1024

#define WRITING_BLOCKED_NO_ADMIN     1313  // If the user is not 'administrator', he will not be allowed to write to other items than itself.
#define WRITING_BLOCKED_ACI          1314  // The attribute 'aci' cannot be written. So we avoid, tat a user gives himself writes.

//AK DEFINE-----------------------------------------
#define WRITING_BLOCKED_NO_DOMAIN_ADMIN  1315  //it is not allowed for an user to write an attribute of another user
#define WRITING_BLOCKED_NO_ATTR      1316
//end define AK-------------------------------------

#define HOB_LITTLE_ENDIAN            1
#define HOB_BIG_ENDIAN               2

/*+---------------------------------------------------------------------+*/
/*| protocol nodes:                                                     |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_proto_nodes[] = {
    "__."         , "user"      , "password"     , "secure"    ,
    "message"     , "dn"        , "fn"           , "id"        ,
    "issuperadmin", "isadmin"   , "ishostip"     , "memberof"  ,
    "cmd"         , "dnn"       , "xml"          , "root"      ,
    "conn_state"
};



static const char chrg_msg_mgmt[] = "Response: ok\r\n\r\n";



/*+---------------------------------------------------------------------+*/
/*| constructor:                                                        |*/
/*+---------------------------------------------------------------------+*/
ds_ea_ldap::ds_ea_ldap()
{
    adsc_wsp_helper = NULL;
    adsc_config     = NULL;
    av_storage      = NULL;
    ienc_state      = ien_read_header;
    adsc_domain     = NULL;

    dsc_payload.ach_ptr      = NULL;
    dsc_payload.in_expected  = -1;
    dsc_payload.in_received  = 0;

    m_set_ea_hdr(dsc_ea_hdr_in, NULL, -1, -1, -1, -1, -1, -1, -1); // Reset the in-header

    boc_insert_oc = HARDCODED_INSERT_OC;
    boc_to_server = false;
    boc_callagain = FALSE;
} // end of ds_ea_ldap::ds_ea_ldap


/*+---------------------------------------------------------------------+*/
/*| destructor:                                                         |*/
/*+---------------------------------------------------------------------+*/
ds_ea_ldap::~ds_ea_ldap()
{
} // end of ds_ea_ldap::~ds_ea_ldap



/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/

/**
 * function ds_ea_ldap::m_init
 * initialise all classes, global ds_hstring, etc.
 *
 * @param[in]   ds_wsp_helper*  ads_wsp_helper_in
*/
void ds_ea_ldap::m_init( ds_wsp_helper* ads_wsp_helper_in ) {
    adsc_wsp_helper = ads_wsp_helper_in;

    adsc_config     = (dsd_ea_config*)adsc_wsp_helper->m_get_config();

    dsc_ldap.m_init( adsc_wsp_helper );
    dsc_crypt.m_init(adsc_wsp_helper);
    dsc_not_allowed_attr.m_init( adsc_wsp_helper );

    hstrc_ldap_address.m_init(adsc_wsp_helper);
    hstrc_ldap_base.m_init(adsc_wsp_helper);
    hstrc_ldap_userprefix.m_init(adsc_wsp_helper);
    hstrc_ldap_groupmembers.m_init(adsc_wsp_helper);
    hstrc_ldap_groupmembersin.m_init(adsc_wsp_helper);
    hstrc_ldap_searchuser.m_init(adsc_wsp_helper);

    dsc_group_dns_of_logged_user.m_init(adsc_wsp_helper);
    dsc_tree_dns_of_logged_user.m_init(adsc_wsp_helper);
}

/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_ea_ldap::m_run
 * our start entry as sdh working class
 *
 * @return      int                                    0 = success
*/
int ds_ea_ldap::m_run()
{
    // initialize some variables:
    int                    in_ret       = SUCCESS;  // our return value
    struct dsd_gather_i_1* ads_gather   = NULL;  // input data


    //----------------------------------------------------
    // log incoming data:
    //----------------------------------------------------
    adsc_wsp_helper->m_log_input();


    //----------------------------------------------------
    // initialise variables LDAP module
    //----------------------------------------------------
    dsc_ldap.m_init_ldap(boc_insert_oc);

    //----------------------------------------------------
    // handle data:
    //----------------------------------------------------
    ads_gather = adsc_wsp_helper->m_get_input();
    if ( ads_gather != NULL ) {
        in_ret = m_handle_data( ads_gather );
    }

    //----------------------------------------------------
    // log outgoing data:
    //----------------------------------------------------
    adsc_wsp_helper->m_log_output();


    return in_ret;
} // end of ds_ea_ldap::m_run


/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * function ds_ea_ldap::m_handle_data
 * general data handling
 * 
 * @param[in]   struct dsd_gather_i_1*  ads_gather      input data
 * @return      int                                    0 = success
*/
int ds_ea_ldap::m_handle_data( struct dsd_gather_i_1* ads_gather )
{
    // initialize some variables:
    int        in_length    = 0;        // total length of incoming data
    int        in_offset    = 0;        // reading position in data
    int        in_read      = 0;        // read bytes (for m_get_buf)
    int        in_ret       = SUCCESS;  // return value
    ds_hstring hstr_response( adsc_wsp_helper );             // buffer for our response


    /*
        our protocol looks like this
        +-------+-------+-------+-------+-------+-------+-------+-------+--------
        |length |status |version|element|excepti|command|param1 |param2 = data
        +-------+-------+-------+-------+-------+-------+-------+-------+--------
        |4 bytes|4 bytes|4 bytes|4 bytes|4 bytes|4 bytes|4 bytes|...

        all data are always in little endian
    */


    //---------------------------------------------
    // evalute input gather length:
    //---------------------------------------------
    in_length = adsc_wsp_helper->m_get_gather_len( ads_gather );


    //---------------------------------------------
    // loop through the data:
    //---------------------------------------------
    while ( in_offset < in_length ) {
        switch ( ienc_state ) {
            //-------------------------------------
            // Read protocol header: 28 bytes
            //-------------------------------------
            case ien_read_header: {
                // We wait until the header is complete
                if ( in_length - in_offset < LEN_EA_HEADER ) {
                    return SUCCESS; // We must wait for more data
                }

                dsc_ea_hdr_in.in_total_len = (int)m_to_number( ads_gather, &in_offset, 4, HOB_LITTLE_ENDIAN );
                dsc_ea_hdr_in.in_state     = (int)m_to_number( ads_gather, &in_offset, 4, HOB_LITTLE_ENDIAN );
                dsc_ea_hdr_in.in_version   = (int)m_to_number( ads_gather, &in_offset, 4, HOB_LITTLE_ENDIAN );
                dsc_ea_hdr_in.in_element   = (int)m_to_number( ads_gather, &in_offset, 4, HOB_LITTLE_ENDIAN );
                dsc_ea_hdr_in.in_exception = (int)m_to_number( ads_gather, &in_offset, 4, HOB_LITTLE_ENDIAN );
                dsc_ea_hdr_in.in_command   = (int)m_to_number( ads_gather, &in_offset, 4, HOB_LITTLE_ENDIAN );
                dsc_ea_hdr_in.in_param1    = (int)m_to_number( ads_gather, &in_offset, 4, HOB_LITTLE_ENDIAN );                

                if (dsc_ea_hdr_in.in_total_len <= 0) { // Length 0 or less is senseless.
                    return -1;
                }

                if (dsc_ea_hdr_in.in_total_len > LEN_EA_HEADER) { // There are additional data
                    dsc_payload.in_expected = dsc_ea_hdr_in.in_total_len - LEN_EA_HEADER;
                    ienc_state = ien_read_data;
                }
                else {
                    ienc_state = ien_handle_input;
                }

                continue;
            }

            //-------------------------------------
            // Read data
            //-------------------------------------
            case ien_read_data: {
                //---------------------------------
                // get buffer from gather:
                //---------------------------------
                dsc_payload.ach_ptr = m_get_buf( ads_gather, in_offset,
                                                   dsc_payload.in_expected - dsc_payload.in_received,
                                                   &in_read );
                if ( dsc_payload.ach_ptr == NULL ) {
                    break;
                }
                dsc_payload.in_received += in_read;

                //---------------------------------
                // check if we have presaved data:
                //---------------------------------
                if ( dsc_xmlbuf.ach_ptr != NULL ) {
                    memcpy( &dsc_xmlbuf.ach_ptr[dsc_xmlbuf.in_received], dsc_payload.ach_ptr, in_read );
                    dsc_xmlbuf.in_received = dsc_payload.in_received;
                    dsc_payload.ach_ptr = dsc_xmlbuf.ach_ptr;
                }

                //---------------------------------
                // check if everything is received:
                //---------------------------------
                if ( dsc_payload.in_expected == dsc_payload.in_received ) {
                    // set new state:
                    ienc_state = ien_handle_input;
                } else if ( dsc_xmlbuf.ach_ptr == NULL ) {
                    // get receive buffer:
                    dsc_xmlbuf.ach_ptr = adsc_wsp_helper->m_cb_get_memory( dsc_payload.in_expected, false );
                    if ( dsc_xmlbuf.ach_ptr == NULL ) {
                        return -2;
                    }
                    memcpy( dsc_xmlbuf.ach_ptr, dsc_payload.ach_ptr, in_read );
                    dsc_payload.ach_ptr = dsc_xmlbuf.ach_ptr;
                    dsc_xmlbuf.in_expected = dsc_payload.in_expected;
                    dsc_xmlbuf.in_received = dsc_payload.in_received;
                }

                // update offset:
                in_offset += in_read;
                continue;
            }

            //-------------------------------------
            // handle input:
            //   If we come here, there are more  than one packet in gather.
            //   We break the loop, handle the data and don't mark apppended
            //   data as processed, so WSP will give us this packet again
            //-------------------------------------
            case ien_handle_input:
                ienc_state = ien_read_header;
                break;

        } // end of switch
        break;
    } // end of while( in_offset < in_length )


    //---------------------------------------------
    // mark data as processed until offset:
    //---------------------------------------------
    m_mark_processed( ads_gather, &in_offset, &in_length );


    //---------------------------------------------
    // handle read data:
    //---------------------------------------------
    ds_hstring hstr_err_msg(adsc_wsp_helper);
    if (dsc_payload.in_expected == dsc_payload.in_received) {
        switch (dsc_ea_hdr_in.in_command) {
        //-------------------------------------
        // Connect
        //-------------------------------------
        case ien_cmd_connect: { // 0x01
            ds_hstring hstr_domain_username(adsc_wsp_helper);
            ds_hstring hstr_pw_enc(adsc_wsp_helper);
            int inl_ret = m_connect(&hstr_domain_username, &hstr_pw_enc, &hstr_err_msg);
            if (inl_ret != SUCCESS) {
                ds_hstring hstr_msg(adsc_wsp_helper, "HEALDE700E: Connect to LDAP server failed with error ");
                hstr_msg.m_writef("%d. Details: %.*s", inl_ret, hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
				adsc_wsp_helper->m_log(ied_sdh_log_error, hstr_msg.m_const_str());
                in_ret = -10;
                m_send_response(ien_cmd_connect, ien_sts_neg, 1, hstr_msg.m_get_ptr());
                break;
            }

            // Create and send response PNode.
            ds_hstring dsl_resp_pnode(adsc_wsp_helper);
            m_create_resp_connect(&dsl_resp_pnode, &hstr_domain_username, &hstr_pw_enc, &dsc_group_dns_of_logged_user);
            m_send_response(ien_cmd_connect, ien_sts_resp, 1, dsl_resp_pnode.m_get_ptr(), dsl_resp_pnode.m_get_len());

            // Everything is ok
            in_ret = SUCCESS;
            break;
        }
        case ien_cmd_getfiles: { // 0x02
            int ain_count_written_elements = 0;
            int inl_ret = m_getfiles(&hstr_response, &ain_count_written_elements, &hstr_err_msg);
            if (inl_ret != SUCCESS) { // Error
                ds_hstring hstr_msg(adsc_wsp_helper, "HEALDE602E: Reading files from LDAP server failed with error ");
                hstr_msg.m_writef("%d. Details: %.*s", inl_ret, hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
                adsc_wsp_helper->m_log(ied_sdh_log_error, hstr_msg.m_const_str());
                in_ret = -20;
                m_send_response(ien_cmd_getfiles, ien_sts_neg, 1, hstr_msg.m_get_ptr());
                break;
            }

            // Send response
            m_send_response(ien_cmd_getfiles, ien_sts_resp, ain_count_written_elements, hstr_response.m_get_ptr(), hstr_response.m_get_len());

            // All is ok
            in_ret = SUCCESS;
            break;
        }
        case ien_cmd_putfiles: { // 0x03
            int inl_ret = m_putfiles(&hstr_err_msg);
            if (inl_ret != SUCCESS) { // Error
                ds_hstring hstr_msg(adsc_wsp_helper, "HEALDE603E: Writing files to LDAP server failed with error ");
                hstr_msg.m_writef("%d. Details: %.*s", inl_ret, hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
                adsc_wsp_helper->m_log(ied_sdh_log_error, hstr_msg.m_const_str());
                in_ret = -30;
                m_send_response(ien_cmd_putfiles, ien_sts_neg, 1, hstr_msg.m_get_ptr(), hstr_msg.m_get_len() );
                break;
            }

            // Send response
            m_send_response(ien_cmd_putfiles, ien_sts_resp, 1, NULL, 0);

            // Everything is ok
            in_ret = SUCCESS;
            break;
        }
        case ien_cmd_createnode: { // 0x06
            ds_hstring hstr_created_dn(adsc_wsp_helper, "", 0);
            int inl_ret = m_createnode(&hstr_created_dn, &hstr_err_msg);
            if (inl_ret != SUCCESS) { // Error
                ds_hstring hstr_msg(adsc_wsp_helper, "HEALDE655E: Creating an item failed with error ");
                hstr_msg.m_writef("%d. Details: %.*s", inl_ret, hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
                adsc_wsp_helper->m_log(ied_sdh_log_error, hstr_msg.m_const_str());
                in_ret = -60;
                m_send_response(ien_cmd_createnode, ien_sts_neg, 1, hstr_msg.m_get_ptr());
                break;
            }

            // Send response: str_created_dn holds the DN of the created item
            m_send_response(ien_cmd_createnode, ien_sts_resp, 1, hstr_created_dn.m_get_ptr(), hstr_created_dn.m_get_len());

            // All is ok
            in_ret = SUCCESS;
            break;
        }
        case ien_cmd_deletenode: { // 0x07
            int inl_ret = m_deletenode(&hstr_err_msg);
            if (inl_ret != SUCCESS) { // Error
                ds_hstring hstr_msg(adsc_wsp_helper, "HEALDE613E: Deleting item failed with error ");
                hstr_msg.m_writef("%d. Details: %.*s", inl_ret, hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
                adsc_wsp_helper->m_log(ied_sdh_log_error, hstr_msg.m_const_str());
                in_ret = -40;
                m_send_response(ien_cmd_deletenode, ien_sts_neg, 1, hstr_msg.m_get_ptr());
                break;
            }

            // Send response
            m_send_response(ien_cmd_deletenode, ien_sts_resp, 1, NULL, 0);

            // All is ok
            in_ret = SUCCESS;
            break;
        }
        case ien_cmd_generic: { // 0x10
            int inl_ret = m_generic(&hstr_response, &hstr_err_msg);
            if (inl_ret != SUCCESS) { // Error
                ds_hstring hstr_msg(adsc_wsp_helper, "HEALDE616E: Generic command failed with error ");
                hstr_msg.m_writef("%d. Details: %.*s", inl_ret, hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
                adsc_wsp_helper->m_log(ied_sdh_log_error, hstr_msg.m_const_str());
                in_ret = -1600;
                m_send_response(ien_cmd_generic, ien_sts_neg, 1, hstr_msg.m_get_ptr());
                break;
            }

            // Send response
            m_send_response(ien_cmd_generic, ien_sts_resp, 1, hstr_response.m_get_ptr(), hstr_response.m_get_len());

            // All is ok
            in_ret = SUCCESS;
            break;
        }
        default: {
            ds_hstring hstr_msg(adsc_wsp_helper, "HEALDE611E: Unknown generic command ");
            hstr_msg += dsc_ea_hdr_in.in_command;
            adsc_wsp_helper->m_log(ied_sdh_log_error, hstr_msg.m_const_str());
            in_ret = -50;
            m_send_response(dsc_ea_hdr_in.in_command, ien_sts_neg, 1, hstr_msg.m_get_ptr());
            break;
        }
        } // switch (dsc_ea_hdr_in.in_command)


        if ( dsc_xmlbuf.ach_ptr != NULL ) {
            adsc_wsp_helper->m_cb_free_memory( dsc_xmlbuf.ach_ptr, dsc_xmlbuf.in_expected );
            dsc_xmlbuf.ach_ptr     = NULL;
            dsc_xmlbuf.in_expected = 0;
            dsc_xmlbuf.in_received = 0;
        }

        //-----------------------------------------
        // reset state and read length:
        //-----------------------------------------
        ienc_state = ien_read_header;
        dsc_payload.in_received  =  0;
    }

    return SUCCESS;
} // end of ds_ea_ldap::m_handle_data


/**Read the PNode (xml format) of the EA-connect-command. Then connect with this informations to a LDAP server.
 * If the LDAP server can be dynamically selected, the LDAP server is defined by the domain.
 *
 * private
 *
 * @param[out]  ahstr_domain_username This string will be filled with the content of the tag 'user'. It has the format <domain>\<user name>.
 * @param[out]  ahstr_pw_enc This string will be filled with the session ticket, which was created at RDVPN logon. (versions <= 2.3.04: This string will be filled with the content of the tag 'password').
 * @param[out]  ahstr_err_msg This string will be filled with an error message.
*/
int ds_ea_ldap::m_connect(ds_hstring* ahstr_domain_username, ds_hstring* ahstr_pw_enc, ds_hstring* ahstr_err_msg) {
    ahstr_err_msg->m_reset();

    // Reset global variables
    dsc_group_dns_of_logged_user.m_clear();
    dsc_tree_dns_of_logged_user.m_clear();

    // The pay load data contain a PNode (in xml format) -> read it.
    int in_len_data = dsc_ea_hdr_in.in_param1;
    if (in_len_data != dsc_payload.in_received) {
        ahstr_err_msg->m_set("HEALDE500E: Length of payload data is not as announced.");
        return 5;
    }

    //-----------------------------------------
    // Read user name (which in deed is <domain>\<user name>) and password from xml data.
    //-----------------------------------------
    ds_hstring hstr_domain(adsc_wsp_helper);
    ds_hstring hstr_username(adsc_wsp_helper);
    int inl_ret = m_read_xml_connect(dsc_payload.ach_ptr, dsc_payload.in_expected, ahstr_domain_username, &hstr_domain, &hstr_username, ahstr_pw_enc);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_reset();
        ahstr_err_msg->m_writef("HEALDE501E: error while reading xml data: %d", inl_ret);
        return 6;
    }

    adsc_wsp_helper->m_logf( ied_sdh_log_info, "HEALDI460I: hstr_domain_username %s", ahstr_domain_username->m_get_ptr());
    adsc_wsp_helper->m_logf( ied_sdh_log_info, "HEALDI461I: hstr_domain %s"         , hstr_domain.m_get_ptr());
    adsc_wsp_helper->m_logf( ied_sdh_log_info, "HEALDI462I: hstr_username %s"       , hstr_username.m_get_ptr());

    // JF 30.11.10 Return the session ticket instead of the password.
    //adsc_wsp_helper->m_logf( ied_sdh_log_info, "HEALDI463I: hstr_pw_enc %s", ahstr_pw_enc->m_get_ptr());

    // The password is encrypted (using hstr_domain_username) -> decrypt it.
    ds_hstring hstr_pw_clear_utf8(adsc_wsp_helper);
    inl_ret = m_decrypt_password(ahstr_pw_enc->m_get_ptr(), ahstr_domain_username->m_get_ptr(), &hstr_pw_clear_utf8);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_reset();
        ahstr_err_msg->m_writef("HEALDE502E: Logon to LDAP server failed with error %d. Password could not be decrypted.", inl_ret);
        return (inl_ret+500);
    }


    //-------------------------------
    // If the LDAP server can be dynamically selected, we must tell WSP, which LDAP server to select.
    // Hereto we must resolve the LDAP server, which belongs to our domain.
    //-------------------------------

    ds_usercma ds_usr_cma;
    bool bo_ret = ds_usercma::m_get_usercma( adsc_wsp_helper, &ds_usr_cma );
    if (!bo_ret) {
        ahstr_err_msg->m_set("HEALDE705E: Logon to LDAP server failed, because m_get_usercma() failed.");
        return 71;
    }

    // JF 30.11.10 Return the session ticket instead of the password in the connect-PNode.
    ds_hstring hstr_sticket = ds_usr_cma.m_get_sticket(); // Session ticket (similar to PassTicket in EA).
    // Encrypt the session ticket, so the client software needs not to be changed.
    ds_hstring hstr_hobsocks_name = ds_usr_cma.m_get_hobsocks_name();
    inl_ret = m_encrypt_password(hstr_sticket.m_get_ptr(), hstr_hobsocks_name.m_get_ptr(), ahstr_pw_enc);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_reset();
        ahstr_err_msg->m_writef("HEALDE509E: Logon to LDAP server failed with error %d. Session ticket could not be encrypted.", inl_ret);
        return (inl_ret+600);
    }
    // JF 21.04.11 Do ot print the (enrypted) password:   adsc_wsp_helper->m_logf( ied_sdh_log_info, "HEALDI463I: hstr_pw_enc %s", ahstr_pw_enc->m_get_ptr());

    //// TEST: revert encryption
    //ds_hstring hstr_st(adsc_wsp_helper);
    //ahstr_pw_enc->m_write("vb3oWd2xqFY9syhafbyoV321yFodvchZ3bCIXr2+SF79tChavbeIXl2xKFyds+hd/bNoVp29qFj9tWhY3bUIXw==", false);
    //hstr_socks.m_write("KDC-hobc01p\\galea", false);
    //inl_ret = m_decrypt_password(ahstr_pw_enc->m_get_ptr(), hstr_hobsocks_name.m_get_ptr(), &hstr_st);

    bo_ret = ds_usr_cma.m_select_config_ldap();
    if (!bo_ret) {
        ahstr_err_msg->m_set("HEALDE708E: Logon to LDAP server failed, because ds_usercma.m_select_config_ldap() failed.");
        return 74;
    }


    //---------------------
    // Bind to LDAP server
    //---------------------
    /*
        TODO (1.8.11): use own user/password!

        1.) check if auth ldap equals config ldap
        2.) if equal: use own username/password
        3.) a) switch to "domain admin"
            b) if user is not "domain admin" let him just write his own attributes
               get user rights from role and allow write just to the configured attributes

    */
    // begin -- AK ----------------------------------------------------------------        
    struct dsd_role             *adsl_role;
    adsl_role                   = ds_usr_cma.m_get_role();
    //check roles
    ds_hstring hstr_attr;
    if ( !(adsl_role->inc_allowed_conf & DEF_UAC_WSG_BMARKS) ) {       //wsg bm not allowed
        hstr_attr.m_set("hobrdvpnbmwsg");
        dsc_not_allowed_attr.m_add(hstr_attr);
    }
    if ( !(adsl_role->inc_allowed_conf & DEF_UAC_WFA_BMARKS) ) {       //wfa bm not allowed
        hstr_attr.m_set("hobrdvpnbmwfa");
        dsc_not_allowed_attr.m_add(hstr_attr);
    }
    if ( !(adsl_role->inc_allowed_conf & DEF_UAC_DOD) ) {              //dod not allowed
        hstr_attr.m_set("hobrdvpndod");
        dsc_not_allowed_attr.m_add(hstr_attr);
    }
    if ( !(adsl_role->inc_allowed_conf & DEF_UAC_OTHERS) ) {           //others not allowed
        hstr_attr.m_set("hobrdvpnuser");
        dsc_not_allowed_attr.m_add(hstr_attr);
    }//end check roles 

    hstrc_real_user_dn          = ds_usr_cma.m_get_userdn();                //user dn before binding, which is the real dn
    boc_auth_equals_config_ldap = ds_usr_cma.m_auth_equals_config_ldap();   //check if auth ldap equals config ldap 

    adsc_domain = ds_usr_cma.m_get_domain();            //check for the root tree                     

    if ( boc_auth_equals_config_ldap == true ) {        //auth lpdap = config ldap 
        ds_hstring hstrl_user_pw = ds_usr_cma.m_get_password(); 
        inl_ret                  = dsc_ldap.m_bind(&hstrc_real_user_dn, &hstrl_user_pw, ied_auth_dn);
        //inl_ret         = dsc_ldap.m_bind(&hstr_username, &hstr_pw_clear_utf8, ied_auth_admin);
    } 
    else {                                              //case: auth ldap != conf ldap --> log in as domain admin
        char *achl_admin_dn;        
        int  inl_len_dn;
        char *achl_admin_pwd;
        int  inl_len_pwd;
        ds_usr_cma.m_get_domain_admin( &achl_admin_dn, &inl_len_dn, &achl_admin_pwd, &inl_len_pwd ); //define domain admin
        if ( inl_len_dn > 0 && inl_len_pwd > 0 ) {
            inl_ret     = dsc_ldap.m_bind( achl_admin_dn, inl_len_dn, achl_admin_pwd, inl_len_pwd, ied_auth_dn );
        } else {
            hstr_pw_clear_utf8.m_set("");
            inl_ret = dsc_ldap.m_simple_bind();
            //inl_ret = dsc_ldap.m_bind( &hstr_username, &hstr_pw_clear_utf8, ied_auth_user );
        }
        //hstr_pw_clear_utf8 = "";
        //inl_ret = dsc_ldap.m_bind(&hstr_username, &hstr_pw_clear_utf8, ied_auth_admin);
    }
    // end -- AK ------------------------------------------------------------------

    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_reset();
        ahstr_err_msg->m_writef("HEALDE503E: Bind to LDAP server failed with error %d.", inl_ret);
        adsc_wsp_helper->m_logf( ied_sdh_log_error, "%s Details: %s", ahstr_err_msg->m_get_ptr(), dsc_ldap.m_get_last_error().m_get_ptr());
        if (inl_ret == LDAP_USER_MUST_CHANGE_PW) {
            return LDAP_USER_MUST_CHANGE_PW;
        }
        return 16;
    }

    // Get DN of the logged user.
    //hstrc_bind_dn = dsc_ldap.m_get_user_dn();           //user dn after binding


    // Read some settings from LDAP module. This must be done after m_bind(), because m_bind() calls ds_ldap.m_get_sysinfo().
    inc_ldap_srv_type = dsc_ldap.m_get_srv_type();
    dsc_ldap.m_get_address(&hstrc_ldap_address);
    dsc_ldap.m_get_base(&hstrc_ldap_base);
    dsc_ldap.m_get_searchuser(&hstrc_ldap_searchuser);
    dsc_ldap.m_get_userprefix(&hstrc_ldap_userprefix);
    dsc_ldap.m_get_groupmembers(&hstrc_ldap_groupmembers);
    dsc_ldap.m_get_groupmembersin(&hstrc_ldap_groupmembersin);


    //----------------------------------
    // Get our memberships.
    //----------------------------------
    //inl_ret = dsc_ldap.m_get_membership(&dsc_group_dns_of_logged_user, NULL, true);
    inl_ret = dsc_ldap.m_get_membership(&dsc_group_dns_of_logged_user, &hstrc_real_user_dn, true);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_reset();
        ahstr_err_msg->m_writef("HEALDE504E: Retrieving group memberships failed with error %d.", inl_ret);
        adsc_wsp_helper->m_logf( ied_sdh_log_error, "%s Details: %s", ahstr_err_msg->m_get_ptr(), dsc_ldap.m_get_last_error().m_get_ptr());
        dsc_ldap.m_close();
        return 17;
    }

    //----------------------------------
    // Get our tree-DNs.
    //----------------------------------
    inl_ret = dsc_ldap.m_get_tree_dns(&hstrc_real_user_dn, &dsc_tree_dns_of_logged_user, false, true);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_reset();
        ahstr_err_msg->m_writef("HEALDE506E: Detection of tree-DNs failed with error %d.", inl_ret);
        adsc_wsp_helper->m_logf( ied_sdh_log_error, "%s Details: %s", ahstr_err_msg->m_get_ptr(), dsc_ldap.m_get_last_error().m_get_ptr());
        dsc_ldap.m_close();
        return 19;
    }
    return SUCCESS;
}

/**Handles the EA command 'GetFiles'.
 * Parse the received data, read attributes/files from a LDAP server with inheritance and compose the response (inclusive HOBEA header).
 *
 * private
 *
 * @param[out]  ahstr_resp This string contains the response data.
 * @param[out]  ain_count_written_elements is the count of requested files, for which a response was written (may be an empty response in case of OWN!).
 * @param[out]  ahstr_err_msg This string will be filled with an error message.
*/
int ds_ea_ldap::m_getfiles(ds_hstring* ahstr_resp, int* ain_count_written_elements, ds_hstring* ahstr_err_msg) {
    ahstr_err_msg->m_reset();

    // The pay load data contain the DN of the user, the files to be loaded and the according inheritance-methods.
    // Format:
    // Header.in_element: count of files + 1 (the 1 represents the user's DN, which is included in this request)
    // Header.in_param1:  length of the user's DN (delivered in UTF8)
    // Then follow the data:
    // User's DN (delivered in UTF8) | 4bytes request-method | 4bytes length of filename | filename | 4bytes request-method | 4bytes length of filename | filename | ... (until count of files is reached)

    // Get count of files
    int in_count_files = dsc_ea_hdr_in.in_element - 1; // Count of the requested files
    if (in_count_files <= 0) { // Invalid request
        ahstr_err_msg->m_set("Invalid count of files.");
        return 1;
    }

    // Setup variables for reading the data.
    int inl_unread = dsc_payload.in_received; // Unread data
    char* achl_curr = dsc_payload.ach_ptr;    // Current pointer for reading data

    //----------------
    // Read user's DN
    //----------------
    int inl_len_dn = dsc_ea_hdr_in.in_param1;
    if (inl_len_dn > inl_unread) { // Invalid request
        ahstr_err_msg->m_writef("Announced length is too large: %d.", inl_len_dn);
        return 2;
    }
    ds_hstring hstr_dn_requested_utf8(adsc_wsp_helper, achl_curr, inl_len_dn);
    bool bo_requested_dn_is_logged_user = false;
    if (hstr_dn_requested_utf8.m_get_len() == 0) {
        // empty DN means: use DN of logged user
        bo_requested_dn_is_logged_user = true;
        hstr_dn_requested_utf8 = hstrc_real_user_dn;
    }
    else {
        int in_ret_cmp = -1;
        BOOL bo = m_cmpi_vx_vx(&in_ret_cmp, (void*)hstrc_real_user_dn.m_get_ptr(), hstrc_real_user_dn.m_get_len(), ied_chs_utf_8,
                                            (void*)achl_curr, inl_len_dn, ied_chs_utf_8);
        if (bo == FALSE) {
            ahstr_err_msg->m_writef("Cannot compare delivered DN '%.*s'.",
                hstrc_real_user_dn.m_get_len(), hstrc_real_user_dn.m_get_ptr());
            return 5;
        }
        if (in_ret_cmp == 0) {
            bo_requested_dn_is_logged_user = true;
        }
    }

    // Move pointers...
    achl_curr = achl_curr + inl_len_dn;
    inl_unread = inl_unread - inl_len_dn;


    //----------------
    // Read request-methods and file names
    //----------------
    int in_method_req = ien_inh_req_own; // use 'own' as default
    while (in_count_files > 0) {
        in_method_req = (int)m_read_int(achl_curr, 0);

        ds_hvector<ds_attribute_string> dsl_v_attributes_own(adsc_wsp_helper);
        ds_hvector<ds_attribute_string> dsl_v_attr_inherited(adsc_wsp_helper);

        int in_len_filename = (int)m_read_int(achl_curr, 4);
        if (in_len_filename > inl_unread-8) {
            ahstr_err_msg->m_writef("Announced length is too large: %d.", in_len_filename);
            return 17;
        }
        ds_hstring hstr_filename(adsc_wsp_helper, achl_curr+8, in_len_filename);

        // TODO
        if ( (hstr_filename[0] == '/') || (hstr_filename[0] == '\\') ) {
            ahstr_err_msg->m_writef("File names, which start with a path separator, are not supported: %.*s.",
                hstr_filename.m_get_len(), hstr_filename.m_get_ptr());
            return 4;
        }

        hstr_filename = m_get_ldap_filename(&hstr_filename);

        if ((in_method_req == ien_inh_req_own) || (in_method_req == ien_inh_req_all)) {
            // Read at OWN
            ds_hstring hstr_filter(adsc_wsp_helper, "");
            int inl_ret = dsc_ldap.m_read_attributes(&hstr_filename, &hstr_filter, &hstr_dn_requested_utf8,
                                                        ied_sear_baseobject, &dsl_v_attributes_own);
            if (inl_ret != SUCCESS) {
                ahstr_err_msg->m_writef("HEALDE456E: m_read_attributes() failed with error %d.", inl_ret);
                adsc_wsp_helper->m_logf( ied_sdh_log_error, "%s Details: %s", ahstr_err_msg->m_get_ptr(), dsc_ldap.m_get_last_error().m_get_ptr());
                return inl_ret+100;
            }

            //----------------------
            // For OWN always create a response, even if no attribute was found for OWN.
            //----------------------
            if (dsl_v_attributes_own.m_size() == 0) { // No attribute found -> create one with a empty value
                ds_attribute_string dsl_attr(adsc_wsp_helper);
                ds_hstring hstr_empty(adsc_wsp_helper);
                dsl_attr.m_add_to_values(&hstr_empty);
                dsl_attr.m_set_dn(&hstr_dn_requested_utf8);
                dsl_v_attributes_own.m_add(dsl_attr);
            }
            else if (dsl_v_attributes_own.m_size() > 1) { // Too many entries: OWN has only 1 or 0
                ahstr_err_msg->m_writef("Too many entries found for OWN: %.*s.", hstr_filename.m_get_len(), hstr_filename.m_get_ptr());
                return 81;
            }
        }
        else if (in_method_req != ien_inh_req_other) {
            ahstr_err_msg->m_writef("Invalid inherit-request method %d for file '%.*s'.",
                in_method_req, hstr_filename.m_get_len(), hstr_filename.m_get_ptr());
            return 6;
        }


        // Method is OTHER or ALL -> collect the inherited files
        // MJ: why do we ignore requested mode from client?
        // org: switch( adsc_config->in_inherit_mode ) {
        switch( adsc_config->in_inherit_mode & in_method_req ) {
           case ien_inh_mode_group:  // Inherit from groups
           case ien_inh_mode_both: { // Inherit from groups and tree
               ds_hvector<ds_hstring> dsl_v_dns(adsc_wsp_helper);

               // 26.02.10: Attention: hstr_dn_requested_utf8 may be not a user. Therefore we must check, whether the item is a user. 
               bool bo_is_user = false;
               int inl_ret = dsc_ldap.m_is_user(&hstr_dn_requested_utf8, &bo_is_user);
               if (inl_ret != SUCCESS) {
                   ahstr_err_msg->m_writef("HEALDE354E: m_is_user() failed with error %d.", inl_ret);
                   adsc_wsp_helper->m_logf( ied_sdh_log_error, "%s Details: %s", ahstr_err_msg->m_get_ptr(), dsc_ldap.m_get_last_error().m_get_ptr());
                   return inl_ret+800;
               }
               if (bo_is_user) {
                   // The item is no user -> it can inherit from groups.

                   const ds_hvector<ds_hstring>* adsl_vec_dn = &dsc_group_dns_of_logged_user;
                   if (!bo_requested_dn_is_logged_user) {
                       int inl_ret = dsc_ldap.m_get_membership(&dsl_v_dns, &hstr_dn_requested_utf8, true); // Get the groups, where the item hstr_dn_requested_utf8 is member in.
                       if (inl_ret != SUCCESS) {
                           ahstr_err_msg->m_writef("HEALDE454E: m_get_membership() failed with error %d.", inl_ret);
                           adsc_wsp_helper->m_logf( ied_sdh_log_error, "%s Details: %s", ahstr_err_msg->m_get_ptr(), dsc_ldap.m_get_last_error().m_get_ptr());
                           return inl_ret+400;
                       }
                       adsl_vec_dn = &dsl_v_dns;
                   }

                   for ( HVECTOR_FOREACH(ds_hstring, adsl_cur, *adsl_vec_dn) ) {
                       ds_hstring* adsl_group_dn = const_cast<ds_hstring*>(&HVECTOR_GET(adsl_cur));
                       ds_hstring hstr_filter(adsc_wsp_helper, "", 0);
                       int inl_ret = dsc_ldap.m_read_attributes(&hstr_filename, &hstr_filter, adsl_group_dn, ied_sear_baseobject, &dsl_v_attr_inherited);
                       if (inl_ret != SUCCESS) {
                           ahstr_err_msg->m_writef("HEALDE453E: m_read_attributes() failed with error %d.", inl_ret);
                           adsc_wsp_helper->m_logf( ied_sdh_log_error, "%s Details: %s", ahstr_err_msg->m_get_ptr(), dsc_ldap.m_get_last_error().m_get_ptr());
                           return inl_ret+300;
                       }
                   }
               } // bo_is_user

               if (adsc_config->in_inherit_mode == ien_inh_mode_group) {
                   break; // Only inherit from groups -> we are done
               }
           }
           case ien_inh_mode_tree: { // Inherit from tree (or if both)
               ds_hvector<ds_hstring> dsl_v_dns(adsc_wsp_helper);
               const ds_hvector<ds_hstring>* adsl_vec_dn = &dsc_tree_dns_of_logged_user;
               if (!bo_requested_dn_is_logged_user) {
                   // get the tree items for the DN
                   int inl_ret = dsc_ldap.m_get_tree_dns(&hstr_dn_requested_utf8, &dsl_v_dns, false, true);
                   if (inl_ret != SUCCESS) {
                       ahstr_err_msg->m_writef("HEALDE452E: m_get_tree_dns() failed with error %d.", inl_ret);
                       const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
                        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
                       return inl_ret+800;
                   }

                   adsl_vec_dn = &dsl_v_dns;
               }

               // start at index 1, because at 0 is our DN, which was already investigated
               const dsd_hvec_elem<ds_hstring>* adsl_cur_dn = adsl_vec_dn->m_get_first_element();
               if(adsl_cur_dn != NULL)
                   adsl_cur_dn = adsl_cur_dn->ads_next;
               for ( ; adsl_cur_dn != NULL; adsl_cur_dn=adsl_cur_dn->ads_next ) {
                   ds_hstring hstr_filter(adsc_wsp_helper, "", 0);
                   int inl_ret = dsc_ldap.m_read_attributes(&hstr_filename, &hstr_filter, &adsl_cur_dn->dsc_element, ied_sear_baseobject, &dsl_v_attr_inherited);
                   if (inl_ret != SUCCESS) {
                       ahstr_err_msg->m_writef("HEALDE451E: m_read_attributes() failed with error %d.", inl_ret);
                       const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
                        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
                       return inl_ret+400;
                   }
               }
           }
        }

        // Construct output for this file.
        // Format for EACH REQUESTED file: 4byte count entries | <entry> | <entry> |...
        // <entry>:  4byte len(ID) | ID | 4byte len(DN) | DN | 4byte len(value) | value
        ds_hstring hstr_resp_this_file(adsc_wsp_helper);

        // Write count of responses for this file
        int in_count = 0; // This placeholder will be overwritten later.
        m_write_int(&hstr_resp_this_file, in_count);

        // MJ: this is not an error (if in_method_req != ien_inh_req_own )!
        //// Just for sure; size must now be 1 or greater
        //if ( dsl_v_attributes_own.m_size() == 0) {
        //    ahstr_err_msg->m_writef("HEALDE370E: Size of OWN vector is invalid %u.", dsl_v_attributes_own.m_size());
        //    return 61;
        //}

        if ( dsl_v_attributes_own.m_size() > 0 ) {
            //----------------------
            // For OWN always create a response, even if no attribute was found for OWN.
            //----------------------
            // Write the attribute itself (Format: 4byte len | ID | 4byte len | DN | 4byte len | value)
            const ds_attribute_string& dsl_att_str = dsl_v_attributes_own.m_get_first();
            int inl_ret = m_write_singlevalue_attr_to_resp(&hstr_resp_this_file, &dsl_att_str, true);
            if (inl_ret < 0) {
                ahstr_err_msg->m_writef("HEALDE371E: m_write_singlevalue_attr_to_resp failed with error %d.", inl_ret);
                return 60;
            }
            if (inl_ret > 0) {
                in_count++;
            }
        }


        //----------------------
        // Write inherited attributes (Format: 4byte len | ID | 4byte len | DN | 4byte len | value)
        //----------------------
        if (dsl_v_attr_inherited.m_size() > 0) {
            for (HVECTOR_FOREACH(ds_attribute_string, adsl_cur, dsl_v_attr_inherited)) {
                const ds_attribute_string& dsl_attr = HVECTOR_GET(adsl_cur);
                int inl_ret = m_write_singlevalue_attr_to_resp(&hstr_resp_this_file, &dsl_attr, false);
                if (inl_ret < 0) {
                    ahstr_err_msg->m_writef("HEALDE372E: m_write_singlevalue_attr_to_resp failed with error %d.", inl_ret);
                    return 62;
                }
                if (inl_ret > 0) {
                    in_count++;
                }
            }
        }

        if (in_count > 0) { // For this file at least one entry was written
            (*ain_count_written_elements)++; // this will be used  for header-field 'Elements'

            // Overwrite the placeholder (the first 4 bytes)
            m_write_int_to_hob_header(const_cast<char*>(hstr_resp_this_file.m_get_ptr()), in_count, 0);
        }

        // Append this file to the response
        ahstr_resp->m_write(hstr_resp_this_file.m_get_ptr(), hstr_resp_this_file.m_get_len());

        // Move pointers...
        int in_move = 8 + in_len_filename;
        achl_curr = achl_curr + in_move;
        inl_unread = inl_unread - in_move;

        in_count_files--;
    } // while

    return SUCCESS;
}

int ds_ea_ldap::m_putfiles(ds_hstring* ahstr_err_msg) {
    ahstr_err_msg->m_reset();

    // The pay load data contain the DN of the user and the files (name and data) to be saved.
    // Format:
    // Header.in_element: count of files + 1 (the 1 represents the user's DN, which is included in this request)
    // Header.in_param1:  length of the user's DN (delivered in UTF8)
    // Then follow the data:
    // User's DN (delivered in UTF8) | 4bytes length of filename | filename | 4bytes data-len | 4bytes length of filename | filename | 4bytes data-len | ... (until count of files is reached)


    // Get count of files
    int in_count_files = dsc_ea_hdr_in.in_element - 1; // Count of files to save.
    if (in_count_files <= 0) { // Invalid request
        ahstr_err_msg->m_set("HEALDE373E: Invalid count of files.");
        return 1;
    }

    // Setup variables for reading the data.
    int inl_unread = dsc_payload.in_received; // Unread data
    char* achl_curr = dsc_payload.ach_ptr;    // Current pointer for reading data

    //----------------
    // Read user's DN
    //----------------
    int inl_len_dn = dsc_ea_hdr_in.in_param1;
    if (inl_len_dn > inl_unread) { // Invalid request
        ahstr_err_msg->m_writef("HEALDE374E: Announced length is too large: %d.", inl_len_dn);
        return 2;
    }
    ds_hstring hstr_dn_requested_utf8(adsc_wsp_helper, achl_curr, inl_len_dn);
    if (hstr_dn_requested_utf8.m_get_len() == 0) {
        // empty DN means -> use DN of logged user
        hstr_dn_requested_utf8.m_write(hstrc_real_user_dn);
    }

    // Move pointers...
    achl_curr = achl_curr + inl_len_dn;
    inl_unread = inl_unread - inl_len_dn;


    //----------------
    // Read file names/data and write these to LDAP (attributes with data-length will be deleted)
    //----------------
    while (in_count_files > 0) {
        int in_len_filename = (int)m_read_int(achl_curr, 0);
        if (in_len_filename > inl_unread-4) {
            ahstr_err_msg->m_writef("HEALDE375E: Announced length is too large: %d.", in_len_filename);
            return 7;
        }
        ds_hstring hstr_filename(adsc_wsp_helper, achl_curr+4, in_len_filename);

        // TODO
        if ( (hstr_filename[0] == '/') || (hstr_filename[0] == '\\') ) {
            ahstr_err_msg->m_writef("HEALDE376E: File names, which start with a path separator, are not supported: %.*s.",
                hstr_filename.m_get_len(), hstr_filename.m_get_ptr());
            return 4;
        }
        // Convert to LDAP-file name; example: hobte.hxml -> hobhobte
        hstr_filename = m_get_ldap_filename(&hstr_filename);

        // Move pointers...
        achl_curr = achl_curr + 4 + in_len_filename;
        inl_unread = inl_unread - 4 - in_len_filename;

        // Length of data and data itself
        int in_len_data = (int)m_read_int(achl_curr, 0);
        if (in_len_data > inl_unread-4) {
            ahstr_err_msg->m_writef("HEALDE377E: Announced length is too large: %d.", in_len_data);
            return 8;
        }

        // For simpleness we send only one attribute at a time. This might be improved later...
        // A length of 0 means, that the attribute shall be deleted.
        dsd_ldap_attr dsl_attr;
        dsl_attr.adsc_next_attr = NULL;
        dsl_attr.ac_attr        = const_cast<char*>(hstr_filename.m_get_ptr());
        dsl_attr.imc_len_attr   = hstr_filename.m_get_len();
        dsl_attr.iec_chs_attr   = ied_chs_utf_8;
        dsl_attr.dsc_val.adsc_next_val = NULL;
        dsl_attr.dsc_val.ac_val        = achl_curr + 4; // point directly to the data
        dsl_attr.dsc_val.imc_len_val   = in_len_data;
        dsl_attr.dsc_val.iec_chs_val   = ied_chs_utf_8;

        int inl_ret = m_write_attributes(&hstr_dn_requested_utf8, dsl_attr, (in_len_data == 0), ahstr_err_msg); // (in_len_data=0) means 'delete'
        if (inl_ret != SUCCESS) {
            const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
            adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
            return 9;
        }

        // Move pointers...
        achl_curr = achl_curr + 4 + in_len_data;
        inl_unread = inl_unread - 4 - in_len_data;

        in_count_files--;
    }

    return SUCCESS;
}

int ds_ea_ldap::m_createnode(ds_hstring* hstr_created_dn, ds_hstring* ahstr_err_msg) {
    ahstr_err_msg->m_reset();

    // The pay load data contain in PNode-xml-format the nodes: user, uid, password, context and # (# holds the type)
    // Format:
    // Header.in_element: 1
    // Header.in_param1:  length of the xml (delivered in UTF8)

    char* ach_pnode = dsc_payload.ach_ptr;    // Current pointer for reading data

    // The pay load data contain a PNode (in xml format) -> read it.
    int in_len_data = dsc_ea_hdr_in.in_param1;
    if (in_len_data != dsc_payload.in_received) {
        ahstr_err_msg->m_set("HEALDE534E: Length of payload data is not as announced.");
        return 1;
    }

    //-----------------------------------------
    // Read infos (e.g. user name) from xml data
    //-----------------------------------------
    ds_xml dsc_xml; // xml parser class
    dsc_xml.m_init(adsc_wsp_helper);
    dsd_xml_tag* ads_pnode = dsc_xml.m_from_xml(ach_pnode, in_len_data);
    if (ads_pnode == NULL) {
        ahstr_err_msg->m_set("HEALDE634E: xml parser returned error.");
        return 2;
    }

    // Get a chain of all node-names at the first level
    dsd_xml_key* dsl_key_chain = dsc_xml.m_get_keys(ads_pnode);
    if (dsl_key_chain == NULL) { // error
        ahstr_err_msg->m_set("HEALDE434E: Chain of keys for PNode (createnode) is NULL.");
        return 3;
    }

    // Read passed information
    ds_hstring hstr_name    = dsc_xml.m_read_string(ads_pnode, TAG_USER, (int)strlen(TAG_USER), HOB_DEF_USER, (int)strlen(HOB_DEF_USER));
    ds_hstring hstr_uid     = dsc_xml.m_read_string(ads_pnode, TAG_UID, (int)strlen(TAG_UID), "", 0);
    ds_hstring hstr_pwd     = dsc_xml.m_read_string(ads_pnode, TAG_PASSWORD, (int)strlen(TAG_PASSWORD), "", 0);
    ds_hstring hstr_context = dsc_xml.m_read_string(ads_pnode, TAG_CONTEXT, (int)strlen(TAG_CONTEXT), "", 0);
    char ch_type            = (char)dsc_xml.m_read_int(ads_pnode, TAG_TYPE, (int)strlen(TAG_TYPE), HOB_DEF_TYPE_C);

	////======start convert to utf-8=============
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== name in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_name.m_get_ptr(),	hstr_name.m_get_len(),	ied_chs_html_1 );

	if ( iml_vxlen > 0 ) {
		hstr_name.m_reset();
		hstr_name.m_write( chrl_vxbuffer, iml_vxlen);
	}
	//==== uid in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_uid.m_get_ptr(),	hstr_uid.m_get_len(),	ied_chs_html_1 );

	if ( iml_vxlen > 0 ) {
		hstr_uid.m_reset();
		hstr_uid.m_write( chrl_vxbuffer, iml_vxlen);
	}
	//==== context in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_context.m_get_ptr(),	hstr_context.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_context.m_reset();
		hstr_context.m_write( chrl_vxbuffer, iml_vxlen);
	}
	////======end convert to utf-8=============

    // The password is encrypted -> decrypt it.
    ds_hstring hstr_pw_clear_utf8(adsc_wsp_helper, "");
    if (hstr_pwd.m_get_len() > 0) {
        int in_ret = m_decrypt_password(hstr_pwd.m_get_ptr(), hstr_name.m_get_ptr(), &hstr_pw_clear_utf8);
        if (in_ret != SUCCESS) {
            ahstr_err_msg->m_reset();
            ahstr_err_msg->m_writef("HEALDE402E: Password could not be decrypted. Error: %d.", in_ret);
            return 6;
        }
    }
    ds_hstring hstr_pw_clear(adsc_wsp_helper, hstr_pw_clear_utf8);

    // Create the item
    int inl_ret = dsc_ldap.m_createnode(ch_type, &hstr_name, &hstr_context, &hstr_uid, &hstr_pw_clear, hstr_created_dn);

    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE408E: m_createnode() failed with error %d.", inl_ret);
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        return 7;
    }
    //inception AK 30.05.2012
    /*
     *  If we want to create a new domain, we also have to create a new Organization Unit with the group
     *  domainAdministrators
     */
    if ( ch_type == C_DOMAIN ) {

        bool bol_ret = m_is_new_subdomain( hstr_created_dn, &hstr_name );

        if (bol_ret == true) {
            inl_ret = m_write_domain_aci( hstr_created_dn ); //now we are under dc=root and in OpenDS, so write the defined ACIs
            if (inl_ret != SUCCESS) {
                //ahstr_err_msg->m_writef("HEALDE409E: m_write_domain_aci() failed with error %d.", inl_ret);
                //adsc_wsp_helper->m_logf(ied_sdh_log_error, "%s Details: %s", ahstr_err_msg->m_get_ptr(), dsc_ldap.m_get_last_error().m_get_ptr());
                //return 8;
            }
            if ( adsc_config->boc_domadmin_create == true ) { //now we have to create the defined RDN
                bol_ret = m_create_dadmin_group( hstr_created_dn );
                if ( bol_ret == false ) {
                    ahstr_err_msg->m_writef("HEALDE410E: m_create_dadmin_group() failed with error %d.", inl_ret);
                    const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
                    adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                        ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                        rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
                    return 9;
                }
            }
        }
    }

    return SUCCESS;
}


int ds_ea_ldap::m_deletenode(ds_hstring* ahstr_err_msg) {
    ahstr_err_msg->m_reset();

    // The pay load data contain in PNode-xml-format the nodes: user, context and # (# holds the type; is not needed here)
    // Format:
    // Header.in_element: 1
    // Header.in_param1:  length of the xml (delivered in UTF8)

    char* ach_pnode = dsc_payload.ach_ptr;    // Current pointer for reading data

    // The pay load data contain a PNode (in xml format) -> read it.
    int in_len_data = dsc_ea_hdr_in.in_param1;
    if (in_len_data != dsc_payload.in_received) {
        ahstr_err_msg->m_set("HEALDE544E: Length of payload data is not as announced.");
        return 1;
    }

    //-----------------------------------------
    // Read infos (e.g. user name) from xml data
    //-----------------------------------------
    ds_xml dsc_xml; // xml parser class
    dsc_xml.m_init(adsc_wsp_helper);
    dsd_xml_tag* ads_pnode = dsc_xml.m_from_xml(ach_pnode, in_len_data);
    if (ads_pnode == NULL) {
        ahstr_err_msg->m_set("HEALDE433E: xml parser returned error.");
        return 2;
    }

    // Get a chain of all node-names at the first level
    dsd_xml_key* dsl_key_chain = dsc_xml.m_get_keys(ads_pnode);
    if (dsl_key_chain == NULL) { // error
        ahstr_err_msg->m_set("HEALDE432E: Chain of keys for PNode (deletenode) is NULL.");
        return 3;
    }

    // Read passed information
    ds_hstring hstr_name    = dsc_xml.m_read_string(ads_pnode, TAG_USER, (int)strlen(TAG_USER), "", 0);
    ds_hstring hstr_context = dsc_xml.m_read_string(ads_pnode, TAG_CONTEXT, (int)strlen(TAG_CONTEXT), "", 0);
    if (hstr_name.m_get_len() == 0) {
        ahstr_err_msg->m_set("HEALDE431E: Item name is missing (deletenode).");
        return 6;
    }

	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== name in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_name.m_get_ptr(),	hstr_name.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_name.m_reset();
		hstr_name.m_write( chrl_vxbuffer, iml_vxlen);	
	}
	//=== context in utf-8
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_context.m_get_ptr(),	hstr_context.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_context.m_reset();
		hstr_context.m_write( chrl_vxbuffer, iml_vxlen);	
	}
	//end convert

    ds_hstring hstr_dn(adsc_wsp_helper, hstr_name.m_get_ptr(), hstr_name.m_get_len());
    hstr_dn.m_write(",");
    hstr_dn.m_write(hstr_context);

    // Delete the item
    int inl_ret = dsc_ldap.m_deletenode(&hstr_dn);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE407E: m_deletenode() failed with error %d.", inl_ret);
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        return 7;
    }

    return SUCCESS;
}


int ds_ea_ldap::m_generic(ds_hstring* ahstr_resp, ds_hstring* ahstr_err_msg) {
    ahstr_err_msg->m_reset();

    // Count of elements must be 1 or 2
    if ( (dsc_ea_hdr_in.in_element != 1) && (dsc_ea_hdr_in.in_element != 2) ) {
        ahstr_err_msg->m_writef("HEALDE437E: Elements count is invalid: %d.", dsc_ea_hdr_in.in_element);
        return 1;
    }

    // The pay load data contain a PNode (in xml format) -> read it.
    int in_len_pnode = dsc_ea_hdr_in.in_param1;
    if ( (in_len_pnode == 0) || (in_len_pnode > dsc_payload.in_received) ) {
        ahstr_err_msg->m_writef("HEALDE438E: Invalid length info for payload: %d.", in_len_pnode);
        return 2;
    }
    char* ach_pnode = dsc_payload.ach_ptr;

    // Move pointers
    int in_payload_unread = dsc_payload.in_received - in_len_pnode; // count of unread bytes in payload
    char* ach_curr_payload = dsc_payload.ach_ptr + in_len_pnode; // current position in payload

    // Sometimes additional data are delivered (elements is 2 in this case!)
    ds_hstring hstr_data(adsc_wsp_helper, "");
    if (dsc_ea_hdr_in.in_element == 2) { // There are additional data
        // Format: 4byte len | data

        // At least 4 bytes must be unread
        if (in_payload_unread < 4) {
            ahstr_err_msg->m_writef("HEALDE439E: Not enough data: %d.", in_payload_unread);
            return 3;
        }

        // Read length of data
        int in_len_data = (int)m_read_int(ach_curr_payload, 0);

        // Move pointers...
        ach_curr_payload = ach_curr_payload + 4;
        in_payload_unread = in_payload_unread - 4;

        if (in_len_data != in_payload_unread) { // The remaining bytes must have the announced length
            ahstr_err_msg->m_writef("HEALDE454E: Invalid length info: %d.", in_len_data);
            return 4;
        }

        hstr_data.m_write(ach_curr_payload, in_len_data);
    }


    //-----------------------------------------
    // Read infos (e.g. command number) from xml data of generic structure
    //-----------------------------------------
    ds_xml dsc_xml; // xml parser class
    dsc_xml.m_init(adsc_wsp_helper);
    dsd_xml_tag* ads_pnode = dsc_xml.m_from_xml(ach_pnode, in_len_pnode);
    if (ads_pnode == NULL) {
        ahstr_err_msg->m_set("HEALDE455E: xml parser returned error.");
        return 5;
    }

    // Get a chain of all node-names at the first level
    dsd_xml_key* dsl_key_chain = dsc_xml.m_get_keys(ads_pnode);
    if (dsl_key_chain == NULL) { // error
        ahstr_err_msg->m_set("HEALDE414E: Chain of keys for generic PNode is NULL.");
        return 6;
    }

    // At least the key 'cmd' must exist -> read it
    int in_gen_cmd =  dsc_xml.m_read_int(ads_pnode, achr_proto_nodes[ien_pnode_cmd].m_get_start(), (int)achr_proto_nodes[ien_pnode_cmd].m_get_len(), HOB_DEF_GENERIC_CMD);

    //-----------------------------------------
    // Process the generic commands
    //-----------------------------------------
    ds_hstring hstr_err_msg(adsc_wsp_helper, "");
    switch (in_gen_cmd) {
    case ien_gen_cmd_copy:             //  0
    case ien_gen_cmd_move: {           //  1
        int inl_ret = m_modify_dn( &dsc_xml, ads_pnode, &hstr_err_msg, (in_gen_cmd == ien_gen_cmd_move));
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE422E: m_modify_dn() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_copy_set: {       // 10
        int inl_ret = m_copy_move(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg, (in_gen_cmd == ien_gen_cmd_move));
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE415E: m_copy_move() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_tree: { // 3
        int inl_ret = m_get_tree(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE411E: m_get_tree() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_member:{       //  4
        int inl_ret = m_members(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE416E: m_members() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_memberof: {       //  5
        int inl_ret = m_membership(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE416E: m_membership() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_ldapa: {          //  8
        int inl_ret = m_ldapa(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE417E: m_ldapa() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_idfromdn:         // 11
    case ien_gen_cmd_dnfromid: {       // 12
        int inl_ret = m_dn_id(ahstr_resp, &dsc_xml, ads_pnode, in_gen_cmd, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE418E: m_dn_id() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_gettype: {        // 13
        int inl_ret = m_gettype(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE419E: m_gettype() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_isuserintree:  // 15
    case ien_gen_cmd_getparent: {   // 16
        int inl_ret = m_isuserintree(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg, in_gen_cmd);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE424E: m_isuserintree() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_search: {         // 34
        int inl_ret = m_search(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE425E: m_search() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_verify: {         // 35
        int inl_ret = m_verify(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE425E: m_verify() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_put_attr: {       // 36
        int inl_ret = m_put_attr(ahstr_resp, &dsc_xml, ads_pnode, &hstr_data, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE435E: m_put_attr() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_put_ldap_attr: {  // 38
        int inl_ret = m_put_ldap_attr(ahstr_resp, &dsc_xml, ads_pnode, &hstr_err_msg);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE426E: m_put_ldap_attr() failed with error %d.", inl_ret);
            if (hstr_err_msg.m_get_len() > 0) {
                ahstr_err_msg->m_writef(" Details: %.*s.", hstr_err_msg.m_get_len(), hstr_err_msg.m_get_ptr());
            }
            return inl_ret + in_gen_cmd*100;
        }
        return SUCCESS;
    }
    case ien_gen_cmd_gethls: {         // 91
        // -> send only an EA-header back to client (=EA Admin). The client will construct an empty PNode.
        return SUCCESS;
    }

    default: {
        ahstr_err_msg->m_writef("HEALDE427E: Unknown generic command found: %d.", in_gen_cmd);
        return 8;
    }
    }
}

// used by HOBCOm (P.Eckmann)
int ds_ea_ldap::m_put_attr(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_data, ds_hstring* ahstr_err_msg)
{
    ds_hstring hstr_dn = adsl_xml->m_read_string(ads_pnode, TAG_ID, (int)strlen(TAG_ID), "", 0);
    if (hstr_dn.m_get_len() == 0) {
        return 1;
    }

	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dn.m_get_ptr(),	hstr_dn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dn.m_reset();
		hstr_dn.m_write( chrl_vxbuffer, iml_vxlen);	
	}
	//end convert

    int in_write_mode = adsl_xml->m_read_int(ads_pnode, TAG_WRITE_MODE, (int)strlen(TAG_WRITE_MODE), HOB_DEF_WRITE_MODE);
    if ( (in_write_mode < 1) && (in_write_mode > 3) ) { // 1=ADD, 2=DELETE, 3=EDIT
        ahstr_err_msg->m_writef("HEALDE488E: Unknown write mode: %d", in_write_mode);
        return 30;
    }

    // Search specified object class and insert if not yet there.
    // Attention: don't insert the object class into MSActiveDirectory or Siemens DirX.
    ds_hstring hstr_oc = adsl_xml->m_read_string(ads_pnode, TAG_OBJECTCLASS, (int)strlen(TAG_OBJECTCLASS), "", 0);
    if (hstr_oc.m_get_len() == 0) {
        return 3;
    }
    int inl_ret = dsc_ldap.m_insert_objectclass(&hstr_oc, &hstr_dn, true);
    if (inl_ret != SUCCESS) {
        return (inl_ret + 100);
    }
   
    ds_hstring hstr_binary = adsl_xml->m_read_string(ads_pnode, TAG_BINARY, (int)strlen(TAG_BINARY), "", 0);
    if (hstr_binary.m_get_len() < 1) { // Attribute is not binary; investigate subnode HLS.ATTRIBUTES; it contains attributes to be written
        ds_hstring hstr_attr(adsc_wsp_helper, "attributes");
        const char* ach_value;
        int in_len_value;
        dsd_xml_tag* adsl_node_attributes = adsl_xml->m_get_value(ads_pnode, hstr_attr.m_get_ptr(), hstr_attr.m_get_len(), &ach_value, &in_len_value );
        if (adsl_node_attributes == NULL) { // error
            ahstr_err_msg->m_set("HEALDE932E: adsl_node_attributes is NULL.");
            return 4;
        }

        // Get a chain of all node-names inside the tag 'attributes'
        dsd_xml_key* dsl_key_chain = adsl_xml->m_get_keys(adsl_node_attributes);
        if (dsl_key_chain == NULL) { // error
            ahstr_err_msg->m_set("HEALDE933E: dsl_key_chain is NULL.");
            return 40;
        }

        // Loop over the chain and store the attributes to LDAP server.
        dsd_xml_key* dsl_key_curr = dsl_key_chain;
        while (dsl_key_curr) {
            ds_hstring hstr_attr_val = adsl_xml->m_read_string(adsl_node_attributes, dsl_key_curr->ach_name, dsl_key_curr->in_len_name, "", 0);

            // Write this attribute (multi-valued attributes are NOT supported).
            dsd_ldap_attr dsl_attr;
            dsl_attr.adsc_next_attr = NULL;
            dsl_attr.ac_attr        = (char*)dsl_key_curr->ach_name; // name of the attribute
            dsl_attr.imc_len_attr   = dsl_key_curr->in_len_name; // length of name of the attribute
            dsl_attr.iec_chs_attr   = ied_chs_utf_8;
            dsl_attr.dsc_val.adsc_next_val = NULL;
            if (in_write_mode == 2) { // delete
                dsl_attr.dsc_val.ac_val        = NULL;
                dsl_attr.dsc_val.imc_len_val   = 0;
            }
            else { // add/edit
                dsl_attr.dsc_val.ac_val        = const_cast<char*>(hstr_attr_val.m_get_ptr());
                dsl_attr.dsc_val.imc_len_val   = hstr_attr_val.m_get_len();
            }
            dsl_attr.dsc_val.iec_chs_val   = ied_chs_utf_8;

            int inl_ret = m_write_attributes(&hstr_dn, dsl_attr, false, ahstr_err_msg);
            if (inl_ret != SUCCESS) {
                const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
                adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                    ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                    rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
                return 28;
            }

            dsl_key_curr = dsl_key_curr->ads_next;
        }
    }
    else { // There is only one attribute. Its name is hstr_binary. Its binary content is in ahstr_data.
        dsd_ldap_attr dsl_attr;
        dsl_attr.adsc_next_attr = NULL;
        dsl_attr.ac_attr        = const_cast<char*>(hstr_binary.m_get_ptr()); // name of the attribute
        dsl_attr.imc_len_attr   = hstr_binary.m_get_len(); // length of name of the attribute
        dsl_attr.iec_chs_attr   = ied_chs_utf_8;
        dsl_attr.dsc_val.adsc_next_val = NULL;
        if (in_write_mode == 2) { // delete
            dsl_attr.dsc_val.ac_val        = NULL;
            dsl_attr.dsc_val.imc_len_val   = 0;
        }
        else { // add/edit
            dsl_attr.dsc_val.ac_val        = const_cast<char*>(ahstr_data->m_get_ptr());
            dsl_attr.dsc_val.imc_len_val   = ahstr_data->m_get_len();
        }
        dsl_attr.dsc_val.iec_chs_val   = ied_chs_utf_8;

        int inl_ret = m_write_attributes(&hstr_dn, dsl_attr, false, ahstr_err_msg);
        if (inl_ret != SUCCESS) {
            const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
            adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
            return 25;
        }

    }

    // similar to JAVA nothing is returned.
    ahstr_resp->m_set("");

    return SUCCESS;
}


/**
 * Method supports writing of binary- or String-format attributes, which may
 * be multi-valued. As agreed with E.Galea only one attribute's value at a
 * time can be modified! If more modifications at one time shall be
 * supported there must be a timing-order between sub-pnodes when
 * ADD/DEL/REPLACE are mixed!!
 * 
 *  example:
 *  <__.>
 *    <name>userCertificate</name>
 *    <writemode>1<writemode>
 *    <objectclass>hoboc</objectclass>
 *    <value>(String or byte[] according to attribute 'binary')</value>
 *    <cmd>38</cmd>
 *    <binary>Y</binary>
 *    <id>(userID)</id>
 *  </__.>
 */
int ds_ea_ldap::m_put_ldap_attr(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg)
{
    ds_hstring hstr_dn = adsl_xml->m_read_string(ads_pnode, TAG_ID, (int)strlen(TAG_ID), "", 0);
    if (hstr_dn.m_get_len() == 0) {
        return 1;
    }


    // Name of the attribute to write.
    ds_hstring hstr_name = adsl_xml->m_read_string(ads_pnode, TAG_NAME, (int)strlen(TAG_NAME), "", 0);
    if (hstr_name.m_get_len() == 0) {
        return 2;
    }

	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dn.m_get_ptr(),	hstr_dn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dn.m_reset();
		hstr_dn.m_write( chrl_vxbuffer, iml_vxlen);	
	}
	//==== hstr_name in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_name.m_get_ptr(),	hstr_name.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_name.m_reset();
		hstr_name.m_write( chrl_vxbuffer, iml_vxlen);	
	}
	//end convert

    // Read the value of the attribute
    ds_hstring hstr_val;
    ds_hstring hstr_old_val;
    bool bo_value_is_binary = adsl_xml->m_read_bool(ads_pnode, TAG_BINARY, (int)strlen(TAG_BINARY), HOB_DEF_BINARY);
    if (bo_value_is_binary) {
        hstr_val = adsl_xml->m_read_array(ads_pnode, TAG_VALUE, (int)strlen(TAG_VALUE));
        hstr_old_val = adsl_xml->m_read_array(ads_pnode, TAG_OLDVALUE, (int)strlen(TAG_OLDVALUE));
    }
    else {
        hstr_val = adsl_xml->m_read_string(ads_pnode, TAG_VALUE, (int)strlen(TAG_VALUE), "", 0);
        hstr_old_val = adsl_xml->m_read_string(ads_pnode, TAG_OLDVALUE, (int)strlen(TAG_OLDVALUE), "", 0);
    }
	//==== hstr_val in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_val.m_get_ptr(),	hstr_val.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_val.m_reset();
		hstr_val.m_write( chrl_vxbuffer, iml_vxlen);	
	}
	//end convert

	//==== hstr_old_val in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_old_val.m_get_ptr(),	hstr_old_val.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_old_val.m_reset();
		hstr_old_val.m_write( chrl_vxbuffer, iml_vxlen);	
	}
	//end convert

    // MJ 14.01.2012: adding change of userPassword
    if ( hstr_name.m_equals("userPassword") ) {
        bool bol_ret = m_reset_password( hstr_dn.m_get_ptr(), hstr_dn.m_get_len(),
                                         hstr_val.m_get_ptr(), hstr_val.m_get_len() );
        if ( bol_ret == false ) {
            ahstr_err_msg->m_write( "Reset password failed" );
            return 12;
        }

        // similar to JAVA nothing is returned.
        ahstr_resp->m_set("");
        return SUCCESS;
    }

    // ATTENTION: The PNode encodes the character 0x0a (='\n'), which is used as a separator in attribute 'hobcert', to "&#x76a;".
    //            When we read in such a PNode with adsl_xml->m_read_string, this encode is not reverted. Therefore we do it here.
    int inl_ret = m_decode_xml(&hstr_val);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE328E: m_decode_xml() failed with error %d.", inl_ret);
        return 80;
    }

    dsd_ldap_attr dsl_attr;
    memset(&dsl_attr, 0, sizeof(dsd_ldap_attr));
    dsl_attr.ac_attr        = const_cast<char*>(hstr_name.m_get_ptr());
    dsl_attr.imc_len_attr   = hstr_name.m_get_len();
    dsl_attr.iec_chs_attr   = ied_chs_utf_8;
    int in_write_mode = adsl_xml->m_read_int(ads_pnode, TAG_WRITE_MODE, (int)strlen(TAG_WRITE_MODE), HOB_DEF_WRITE_MODE);
    switch (in_write_mode) {
    case 1: { // ADD
        if ( (hstr_val.m_get_ptr() == NULL) || (hstr_val.m_get_len() == 0) ) {
            return 4;
        }
        dsl_attr.dsc_val.ac_val      = const_cast<char*>(hstr_val.m_get_ptr());
        dsl_attr.dsc_val.imc_len_val = hstr_val.m_get_len();
        dsl_attr.dsc_val.iec_chs_val = ied_chs_utf_8;
        break;
    }
    case 2: { // DELETE
        if (hstr_val.m_get_len() > 0) { // The value is explicit specified (e.g. if one value of a multi-valued attribute shall be deleted).
            dsl_attr.dsc_val.ac_val_old      = const_cast<char*>(hstr_val.m_get_ptr());
            dsl_attr.dsc_val.imc_len_val_old = hstr_val.m_get_len();
            dsl_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;
        }
        // If the value is NOT explicit specified, all values of this attribute (when multi-valued) or the attribute (when single-valued) will be deleted.
        break;
    }
    case 3: { // EDIT
        // New value
        if ( (hstr_val.m_get_ptr() == NULL) || (hstr_val.m_get_len() == 0) ) {
            return 7;
        }
        dsl_attr.dsc_val.ac_val      = const_cast<char*>(hstr_val.m_get_ptr());
        dsl_attr.dsc_val.imc_len_val = hstr_val.m_get_len();
        dsl_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

        // Old value
        if ( (hstr_old_val.m_get_ptr() == NULL) || (hstr_old_val.m_get_len() == 0) ) {
            return 9;
        }
        dsl_attr.dsc_val.ac_val_old      = const_cast<char*>(hstr_old_val.m_get_ptr());
        dsl_attr.dsc_val.imc_len_val_old = hstr_old_val.m_get_len();
        dsl_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;
        break;
    }
    default: {
        ahstr_err_msg->m_writef("HEALDE428E: Unknown write mode: %d", in_write_mode);
        return 3;
    }
    }

    dsl_attr.dsc_val.iec_chs_val   = ied_chs_utf_8;

    inl_ret = m_write_attributes(&hstr_dn, dsl_attr, false, ahstr_err_msg);
    if (inl_ret != SUCCESS) {
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        if (inl_ret == ied_ldap_attr_or_val_exist) {
            // The value already exists. LDAPSet throws an AttributeInUseException, to which JDImpExpCert reacts in a certain way.
            ahstr_err_msg->m_write("AttributeInUseException");
            return ied_ldap_attr_or_val_exist;
        }
        return 5;
    }
    //inception AK 14.06.2012
    //this has to be done after m_write_attributes, because otherwise the check
    //if a user is in the special domainAdmin group would always be negative
    ds_hstring dsl_uniquemember ( adsc_wsp_helper );
    int inl_ldap_sin = dsc_ldap.m_get_groupmembers( &dsl_uniquemember );
    if ( hstr_name.m_equals_ic(dsl_uniquemember) ) { //in that case hstr_dn is the dn of the group

        int inl_ldap_server = dsc_ldap.m_get_srv_type();
        bool bol_ret = hstr_dn.m_starts_with_ic( adsc_config->achc_dom_admin_rdn, adsc_config->inc_len_dom_admin_rdn ); 
        if (    (inl_ldap_server == ied_sys_ldap_opends) //Ldap == OpenDS
             && (bol_ret == true) ) {   // in that case a user has been created within the domainAdmin group
            if ( in_write_mode == 1 ) { //add user to domainAdmin group
                bol_ret = m_set_add_rights( &hstr_val );
                if ( bol_ret == false ) {
                    adsc_wsp_helper->m_logf(ied_sdh_log_error, "m_set_add_rights failed. Details: %s",  dsc_ldap.m_get_last_error().m_get_ptr());
                }
            }
            if ( in_write_mode == 2 ) { //delete user from a group
                bol_ret = m_del_add_rights ( &hstr_val );   
                if ( bol_ret == false ) { //it could be that some rights are not existent anymore, so don´t interrupt
                    adsc_wsp_helper->m_logf(ied_sdh_log_error, "m_del_add_rights failed. Details: %s",  dsc_ldap.m_get_last_error().m_get_ptr());
                }
            }
        }
    }
    //end inception AK

    // similar to JAVA nothing is returned.
    ahstr_resp->m_set("");

    return SUCCESS;
}
#define DSL_PRIV_NAME   "ds-privilege-name"
#define DSL_PWD_POLICY  "ds-pwp-password-policy-dn"
#define DSL_RLIM_IDLE   "ds-rlim-idle-time-limit"
#define DSL_LOOKTHROUGH "ds-rlim-lookthrough-limit"
#define DSL_RLIM_SIZE   "ds-rlim-size-limit"
#define DSL_RLIM_TIME   "ds-rlim-time-limit"
#define DSL_PWD_RESET   "password-reset"
#define DSL_PRIV_CHANGE "privilege-change"
#define DSL_PRIV_DN     "cn=Root Password Policy,cn=Password Policies,cn=config"

/**
 * private function ds_ea_ldap::m_set_add_rights
 *  set additional rights for the domainAdministrators if a user
 *  is added to the domainadministrators group in a domain
 *  in ldif syntax
 *
 * @param[in]   ds_hstring*  dsl_user_dn     dn of the user
 * @return      bool                         true = success
*/
bool ds_ea_ldap::m_set_add_rights( ds_hstring* dsl_user_dn ) {

    //add rights
    //Initialize the additional user rights in ldif syntax

    int inl_ret;
    int inl_sum = 0; //sum the return codes, because we do not want to get out of 
                     //the fuction after invalid m_write_attribute call, so we have 
                     //to store the return code in this variable   
    dsd_ldap_attr dsl_priv_attr;

    //write entry: ds-privilege-name: password-reset
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr             = (char*)DSL_PRIV_NAME;
    dsl_priv_attr.imc_len_attr        = sizeof(DSL_PRIV_NAME)-1;
    dsl_priv_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val      = (char*)DSL_PWD_RESET;
    dsl_priv_attr.dsc_val.imc_len_val = sizeof(DSL_PWD_RESET)-1;
    dsl_priv_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/

    //write entry: ds-privilege-name: privilege-change
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr             = (char*)DSL_PRIV_NAME;
    dsl_priv_attr.imc_len_attr        = sizeof(DSL_PRIV_NAME)-1;
    dsl_priv_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val      = (char*)DSL_PRIV_CHANGE;
    dsl_priv_attr.dsc_val.imc_len_val = sizeof(DSL_PRIV_CHANGE)-1;
    dsl_priv_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/

    //write entry: ds-pwp-password-policy-dn: cn=Root Password Policy,cn=Password Policies,cn=config
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr             = (char*)DSL_PWD_POLICY;
    dsl_priv_attr.imc_len_attr        = sizeof(DSL_PWD_POLICY)-1;
    dsl_priv_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val      = (char*)DSL_PRIV_DN;
    dsl_priv_attr.dsc_val.imc_len_val = sizeof(DSL_PRIV_DN)-1;
    dsl_priv_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //write entry: ds-rlim-idle-time-limit: 0
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr             = (char*)DSL_RLIM_IDLE;
    dsl_priv_attr.imc_len_attr        = sizeof(DSL_RLIM_IDLE)-1;
    dsl_priv_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val      = (char*)"0";
    dsl_priv_attr.dsc_val.imc_len_val = sizeof("0")-1;
    dsl_priv_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //write entry: ds-rlim-lookthrough-limit: 0
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr             = (char*)DSL_LOOKTHROUGH;
    dsl_priv_attr.imc_len_attr        = sizeof(DSL_LOOKTHROUGH)-1;
    dsl_priv_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val      = (char*)"0";
    dsl_priv_attr.dsc_val.imc_len_val = sizeof("0")-1;
    dsl_priv_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //write entry: ds-rlim-size-limit: 0
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr             = (char*)DSL_RLIM_SIZE;
    dsl_priv_attr.imc_len_attr        = sizeof(DSL_RLIM_SIZE)-1;
    dsl_priv_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val      = (char*)"0";
    dsl_priv_attr.dsc_val.imc_len_val = sizeof("0")-1;
    dsl_priv_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //write entry: ds-rlim-time-limit: 0
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr             = (char*)DSL_RLIM_TIME;
    dsl_priv_attr.imc_len_attr        = sizeof(DSL_RLIM_TIME)-1;
    dsl_priv_attr.iec_chs_attr        = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val      = (char*)"0";
    dsl_priv_attr.dsc_val.imc_len_val = sizeof("0")-1;
    dsl_priv_attr.dsc_val.iec_chs_val = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    if ( inl_sum != 0 ) {
        return false;

    }
    return true;
}
/**
 * private function ds_ea_ldap::m_del_add_rights
 *  delete additional rights for the domainAdministrators if a user
 *  is removed from the domainAdmins
 *  in ldif syntax
 *
 * @param[in]   ds_hstring*  dsl_user_dn     dn of the user
 * @return      bool                         true = success
*/
bool ds_ea_ldap::m_del_add_rights( ds_hstring* dsl_user_dn ) {

    int inl_ret;
    int inl_sum = 0; //sum the return codes, because we do not want to get out of 
                     //the fuction after invalid m_write_attribute call, so we have 
                     //to store the return code in this variable
    dsd_ldap_attr dsl_priv_attr;


    //delete ds-privilege-name (value: password-reset)
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr                 = (char*)DSL_PRIV_NAME;
    dsl_priv_attr.imc_len_attr            = sizeof(DSL_PRIV_NAME)-1;
    dsl_priv_attr.iec_chs_attr            = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.iec_chs_val     = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val_old      = (char*)DSL_PWD_RESET;
    dsl_priv_attr.dsc_val.imc_len_val_old = sizeof(DSL_PWD_RESET)-1;
    dsl_priv_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //delete ds-privilege-name (value: privilege-change)
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr                 = (char*)DSL_PRIV_NAME;
    dsl_priv_attr.imc_len_attr            = sizeof(DSL_PRIV_NAME)-1;
    dsl_priv_attr.iec_chs_attr            = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.iec_chs_val     = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val_old      = (char*)DSL_PRIV_CHANGE;
    dsl_priv_attr.dsc_val.imc_len_val_old = sizeof(DSL_PRIV_CHANGE)-1;
    dsl_priv_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //delete ds-pwp-password-policy-dn
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr                 = (char*)DSL_PWD_POLICY;
    dsl_priv_attr.imc_len_attr            = sizeof(DSL_PWD_POLICY)-1;
    dsl_priv_attr.iec_chs_attr            = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.iec_chs_val     = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val_old      = (char*)DSL_PRIV_DN;
    dsl_priv_attr.dsc_val.imc_len_val_old = sizeof(DSL_PRIV_DN)-1;
    dsl_priv_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //delete ds-rlim-idle-time-limit
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr                 = (char*)DSL_RLIM_IDLE;
    dsl_priv_attr.imc_len_attr            = sizeof(DSL_RLIM_IDLE)-1;
    dsl_priv_attr.iec_chs_attr            = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.iec_chs_val     = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val_old      = (char*)"0";
    dsl_priv_attr.dsc_val.imc_len_val_old = sizeof("0")-1;
    dsl_priv_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //delete ds-rlim-lookthrough-limit
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr                 = (char*)DSL_LOOKTHROUGH;
    dsl_priv_attr.imc_len_attr            = sizeof(DSL_LOOKTHROUGH)-1;
    dsl_priv_attr.iec_chs_attr            = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.iec_chs_val     = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val_old      = (char*)"0";
    dsl_priv_attr.dsc_val.imc_len_val_old = sizeof("0")-1;
    dsl_priv_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //delete ds-rlim-size-limit
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr                 = (char*)DSL_RLIM_SIZE;
    dsl_priv_attr.imc_len_attr            = sizeof(DSL_RLIM_SIZE)-1;
    dsl_priv_attr.iec_chs_attr            = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.iec_chs_val     = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val_old      = (char*)"0";
    dsl_priv_attr.dsc_val.imc_len_val_old = sizeof("0")-1;
    dsl_priv_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    //delete ds-rlim-time-limit
    memset(&dsl_priv_attr, 0, sizeof(dsd_ldap_attr));
    dsl_priv_attr.ac_attr                 = (char*)DSL_RLIM_TIME;
    dsl_priv_attr.imc_len_attr            = sizeof(DSL_RLIM_TIME)-1;
    dsl_priv_attr.iec_chs_attr            = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.iec_chs_val     = ied_chs_utf_8;
    dsl_priv_attr.dsc_val.ac_val_old      = (char*)"0";
    dsl_priv_attr.dsc_val.imc_len_val_old = sizeof("0")-1;
    dsl_priv_attr.dsc_val.iec_chs_val_old = ied_chs_utf_8;

    inl_ret = dsc_ldap.m_write_attributes(dsl_user_dn, dsl_priv_attr);
    inl_sum += inl_ret;
    /*if (inl_ret != 0) {
        return false;
    }*/
    if (inl_sum != 0) {
        return false;
    }
    return true;

}
#undef DSL_PRIV_NAME
#undef DSL_PWD_POLICY
#undef DSL_RLIM_IDLE
#undef DSL_LOOKTHROUGH
#undef DSL_RLIM_SIZE
#undef DSL_RLIM_TIME
#undef DSL_PWD_RESET
#undef DSL_PRIV_CHANGE
#undef DSL_PRIV_DN

/**
 * private function ds_ea_ldap::m_reset_password
 *  reset dns password
 *
 * @param[in]   const char  *achp_dn        pointer to dn
 * @param[in]   int         inp_len_dn      length of dn
 * @param[in]   const char  *achp_npwd      new password
 * @param[in]   int         inp_len_npwd    length of new password
 * @return      bool                        true = success
*/
bool ds_ea_ldap::m_reset_password( const char *achp_dn,   int inp_len_dn,
                                   const char *achp_npwd, int inp_len_npwd )
{
    struct dsd_co_ldap_1 dsl_ldap;              /* ldap command struct   */
    bool                 bol_ret;               /* return from ldap call */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap        = ied_co_ldap_bind;
    dsl_ldap.iec_ldap_auth      = ied_auth_user_pwd_change;
    dsl_ldap.ac_userid          = (char*)achp_dn;
    dsl_ldap.imc_len_userid     = inp_len_dn;
    dsl_ldap.iec_chs_userid     = ied_chs_utf_8;
    dsl_ldap.ac_passwd_new      = (char*)achp_npwd;
    dsl_ldap.imc_len_passwd_new = inp_len_npwd;
    dsl_ldap.iec_chs_passwd_new = ied_chs_utf_8;

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret == false 
         || dsl_ldap.iec_ldap_resp != ied_ldap_success ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %s.", dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %.*s.", dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        return false;
    }
    return true;
} // end of m_reset_password


int ds_ea_ldap::m_get_tree(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg)
{
    const char* nodename = "dnn";
    ds_hstring hstr_dn_node_to_explore = adsl_xml->m_read_string(ads_pnode, nodename, (int)strlen(nodename), "", 0);
    if (hstr_dn_node_to_explore.m_get_len() == 0) {

//#ifdef JF_ORG
        hstr_dn_node_to_explore.m_set(hstrc_ldap_base);
//#else
//        // TODO: check if we really need to use the domain!
//        if (    adsc_domain              != NULL
//             && adsc_domain->inc_len_base > 0    ) {
//            hstr_dn_node_to_explore.m_writef( "%.*s,%.*s", adsc_domain->inc_len_base, adsc_domain->achc_base,
//                                                           hstrc_ldap_base.m_get_len(), hstrc_ldap_base.m_get_ptr() );
//        } else {
//            hstr_dn_node_to_explore.m_write(hstrc_ldap_base.m_get_ptr(), false);
//        }
//#endif
    }
	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dn_node_to_explore in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dn_node_to_explore.m_get_ptr(),	hstr_dn_node_to_explore.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dn_node_to_explore.m_reset();
		hstr_dn_node_to_explore.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

// TODO 1 (see LDAPext.getTree())
//String str_root_dot = HLS.LDAP_OVERALL_ROOT; // JF 07.03.08 "..."
//String str_root_dot_with_separartor = "," + str_root_dot;
//if (sDN_NodeToExplore.endsWith(str_root_dot_with_separartor)) {
//    sDN_NodeToExplore = sDN_NodeToExplore.substring(0, sDN_NodeToExplore.length() - str_root_dot_with_separartor.length());
//}

// TODO 2 (see LDAPext.getTree())
//if ((su.ldaproot.length() == 0) && ((sDN_NodeToExplore.length() == 0) || sDN_NodeToExplore.equals(str_root_dot))) {
//attributes = ctx.getAttributes("", new String[] { "namingContexts" });


    // Get object classes for this item (the OWN one)
    ds_hvector<ds_attribute_string> dsl_v_objectclass(adsc_wsp_helper);
    ds_hstring hstr_filter(adsc_wsp_helper, "", 0);
    ds_hstring hstr_attrname(adsc_wsp_helper, "objectclass", (int)strlen("objectclass"));
    /* Inception AKre */
    /* decode  hstr_dn_node_to_explore */
    m_decode_xml ( &hstr_dn_node_to_explore);
    /* end inception AKre */
    int inl_ret = dsc_ldap.m_read_attributes(&hstr_attrname, &hstr_filter, &hstr_dn_node_to_explore, ied_sear_baseobject, &dsl_v_objectclass);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE445E: m_read_attributes() failed with error %d.", inl_ret);
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        return 1;
    }
    if (dsl_v_objectclass.m_size() != 1) {
        return 2;
    }
    // Determine the HOB-class-character

    const ds_attribute_string& dsl_att_str = dsl_v_objectclass.m_get_first();
    char ch_hoboc = dsc_ldap.m_get_oc_id(&dsl_att_str);
    ds_hstring hstr_cdn(adsc_wsp_helper);
    hstr_cdn += ch_hoboc;
    hstr_cdn += hstr_dn_node_to_explore;
    /* inception AKre */
    /*escape hstr_cdn again*/
    m_esc_chars_tree ( &hstr_cdn );
    /* end AKre */
    // create own item
    dsd_item_gettree dsl_item_own;
    dsl_item_own.hstr_tag_name.m_setup(adsc_wsp_helper);
    dsl_item_own.hstr_tag_name.m_set(TAG_OWN);
    dsl_item_own.hstr_name.m_setup(adsc_wsp_helper);
    dsl_item_own.hstr_name = hstr_dn_node_to_explore;
    /* inception AKre */
    /*escape dsl_item_own.hstr_name again*/
    m_esc_chars_tree ( &dsl_item_own.hstr_name );
    /* end AKre */
    dsl_item_own.hstr_id.m_setup(adsc_wsp_helper);
    dsl_item_own.hstr_id = hstr_cdn;

    // setup a vector which holds the data, which must be written to return-xml
    ds_hvector_btype<dsd_item_gettree> ds_v_items(adsc_wsp_helper);
    ds_v_items.m_add(dsl_item_own); // add own item


    // Read all included items and add to vector
    inl_ret = m_get_tree_elements(&hstr_dn_node_to_explore, &ds_v_items);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE429E: m_get_tree_elements failed with error %d.", inl_ret);
        return 3;
    }

    inl_ret = m_create_resp_gettree(ahstr_resp, &ds_v_items);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE421E: m_create_resp_gettree failed with error %d.", inl_ret);
        return 4;
    }

    return SUCCESS;
}

// Write an int as 4 bytes
int ds_ea_ldap::m_write_int(ds_hstring* ahstr_target, int in_to_write) {
    char ch_int[4];
    m_write_int_to_hob_header(ch_int, in_to_write, 0);
    ahstr_target->m_write(ch_int, 4);
    return SUCCESS;
}


// Format: 4byte len(ID) | ID | 4byte len(DN) | DN | 4byte len(value) | value
// return negative, if error; 0, if nothing was written; positive, if something was written;
int ds_ea_ldap::m_write_singlevalue_attr_to_resp(ds_hstring* ahstr_target, const ds_attribute_string* adsl_attr, bool bo_own) {
    if (adsl_attr->m_get_values().m_size() != 1) {
        // error: we expect only one value; this method is only for single-value attribute
        return -1;
    }
    const ds_hstring& hstr_val = adsl_attr->m_get_value_at(0);
    int in_len_val = hstr_val.m_get_len();

    //----------------------
    // For OWN always create a response, even if no attribute was found for OWN.
    //----------------------
    if ( (!bo_own) && (in_len_val == 0) ) {
        return 0; // nothing to save...
    }

    // Write ID (in LDAP ID=DN); Format: 4byte length | String
    const ds_hstring& hstr_dn = adsl_attr->m_get_dn();
    int in_len_dn = hstr_dn.m_get_len();
    m_write_int(ahstr_target, in_len_dn);
    ahstr_target->m_write(hstr_dn);
    
    // Write DN
    m_write_int(ahstr_target, in_len_dn);
    ahstr_target->m_write(hstr_dn);

    // Write the value
    m_write_int(ahstr_target, in_len_val);
    if (in_len_val > 0) {
        ahstr_target->m_write(hstr_val);
    }

    return 1;
}

/** Get the name of the file in the notation of LDAP server: if file name ends with
 * ".hxml" cut off ending and set prefix "hob"; otherwise return unchanged
 * @param str_filename Name of the file
 * @return string how the file is declared in HOB object class
 */
ds_hstring ds_ea_ldap::m_get_ldap_filename(ds_hstring* ahstr_filename) {
    ds_hstring hstr_ret(adsc_wsp_helper);

    // TODO: This algorithm must be refined, because file names like abc.hxmlefg, shall not be changed!!
    if (ahstr_filename->m_ends_with_ic(".hxml")) {
        hstr_ret.m_set("hob");
        hstr_ret.m_write(ahstr_filename->m_substring(0, ahstr_filename->m_get_len()-5));
    }
    else {
        hstr_ret.m_set(ahstr_filename);
    }
    return hstr_ret;
}



/**
 * ds_ea_ldap::m_read_xml_connect
 * read xml data and get our command structure back
 *
 * @param[in]   char*               ach_xml             pointer to xml data
 * @param[in]   int                 in_len              length of xml data
 * @return      int                                     SUCCESS = successful
*/
int ds_ea_ldap::m_read_xml_connect(const char* ach_xml, int in_len,
                                   ds_hstring* ahstr_domain_username, ds_hstring* ahstr_domain,
                                   ds_hstring* ahstr_username, ds_hstring* hstr_pw_enc)
{
    // initialize some variables:
    ds_xml          dsc_xml;            // xml parser class
    dsd_xml_tag*    ads_pnode;          // xml parent node
    const char*           ach_node;           // node name
    int             in_len_node;        // length of node name
    const char*           ach_value;          // node value
    int             in_len_val;         // length of node value
    ied_charset     ien_xml_encoding;   // encoding of xml data
    ied_proto_nodes ien_key;            // node key

    //--------------------------------------
    // parse xml data:
    //--------------------------------------
    dsc_xml.m_init( adsc_wsp_helper );
    ads_pnode = dsc_xml.m_from_xml( ach_xml, in_len );
    ien_xml_encoding = dsc_xml.m_get_encoding();

    //--------------------------------------
    // read our commands from xml:
    //--------------------------------------
    if ( ads_pnode == NULL ) {
        adsc_wsp_helper->m_log(ied_sdh_log_warning, "HEALDW032W: xml parser returned error" );
        return 1;
    }
    dsc_xml.m_get_node_name( ads_pnode, &ach_node, &in_len_node );
    if ( ach_node == NULL || in_len_node == 0 ) {
        adsc_wsp_helper->m_log(ied_sdh_log_warning, "HEALDW033W: error while reading xml" );
        return 2;
    }
    ien_key = m_get_node_key( ach_node, in_len_node, ien_xml_encoding );
    if ( (ien_key != ien_pnode_root) && (ien_key != ien_pnode_root_uscore) ) {
        adsc_wsp_helper->m_log(ied_sdh_log_warning, "HEALDW034W: first tag must be <root> or <__.>" );
        return 3;
    }
    ads_pnode = dsc_xml.m_get_firstchild( ads_pnode );

    //--------------------------------------
    // loop through the nodes
    //--------------------------------------
    bool bo_tag_xml_found = false;
    while ( ads_pnode != NULL ) {
        if ( dsc_xml.m_get_node_type( ads_pnode ) == ied_tag ) {
            //------------------------------
            // get node name:
            //------------------------------
            dsc_xml.m_get_node_name( ads_pnode, &ach_node, &in_len_node );
            if ( ach_node == NULL || in_len_node == 0 ) {
                ads_pnode = dsc_xml.m_get_nextsibling( ads_pnode );
                continue;
            }

            //------------------------------
            // get node value:
            //------------------------------
            ds_xml::m_get_node_value( ads_pnode, &ach_value, &in_len_val );
            if ( ach_value == NULL || in_len_val < 1 ) {
                ads_pnode = ds_xml::m_get_nextsibling( ads_pnode );
                continue;
            }

            //------------------------------
            // get node key:
            //------------------------------
            ien_key = m_get_node_key( ach_node, in_len_node, ien_xml_encoding );
            switch ( ien_key ) {
                case ien_pnode_xml: { // The PNode must contain the 'xml'-tag, to signal that the version is high enough
                    if (!dsc_xml.m_is_yes(ach_value, in_len_val)) {
                        return 4;
                    }
                    bo_tag_xml_found = true;
                    break;
                }
                case ien_pnode_user: {
                    // The tag <username> contains a string of the format <domain>\<username>. The backslash is the separator.
                    // Attention: 1) The user name or the domain can contain backslashes. In this each backslash is escaped by another backslash.
                    //            2) The domain part my be empty.
                    ahstr_domain_username->m_set(ach_value, in_len_val);
                    // JF 17.03.10: If only one domain exists, the user needs not to enter a seperating '\'.
                    //int in_pos_backslash = ahstr_domain_username->m_find_first_of("\\");
                    //if (in_pos_backslash == -1) { // Error; at least one backslash must be included.
                    //    return 20;
                    //}

                    const char* ach_userid  = ahstr_domain_username->m_get_ptr();
                    int in_len_userid = ahstr_domain_username->m_get_len();
                    for ( int in_offset = 0; in_offset < in_len_userid - 1; in_offset++ ) {
                        if (    ach_userid[in_offset]   == '\\'
                             && ach_userid[in_offset+1] != '\\' ) {
                            ahstr_domain->m_write( ach_userid, in_offset );
                            ahstr_username->m_write ( &ach_userid[in_offset + 1], in_len_userid - in_offset - 1 );
                            break;
                        }
                    }
                    if (ahstr_username->m_get_len() < 1 ) {
                        ahstr_username->m_set(ahstr_domain_username);
                    }
                    ahstr_domain->m_replace( "\\\\", "\\" );
                    ahstr_username->m_replace ( "\\\\", "\\" );
                    break;
                }
                case ien_pnode_password: {
                    hstr_pw_enc->m_write(ach_value, in_len_val);
                    break;
                }
                case ien_pnode_conn_state: {
                    ds_hstring hstr_conn_state(adsc_wsp_helper, ach_value, in_len_val);
                    inc_conn_state = 0;
                    hstr_conn_state.m_to_int(&inc_conn_state);
                    break;
                }

                default: {
                    adsc_wsp_helper->m_logf( ied_sdh_log_details, "HEALDD035D: unknown tag <%.*s> found - ignored", in_len_node , ach_node );
                    break;
                }
            }
        }
        ads_pnode = dsc_xml.m_get_nextsibling( ads_pnode );
    }

    if (!bo_tag_xml_found) {
        return 7;
    }

    return SUCCESS;
} // end of ds_ea_ldap::m_read_xml_connect




bool ds_ea_ldap::m_get_int(const char* ach, int in_offset, int* ain_out)
{
    // initialize some variables:
    errno  = 0;

    // check input data:
    if ( (ach == NULL) || (in_offset < 0) || (ain_out == NULL) ) {
        return false;
    }

    *ain_out = atoi( &ach[in_offset] );
    if ( errno != 0 ) {
        return false;
    }
   
    return true;
} // end of ds_memory::m_to_int


/**
 * function ds_ea_ldap::m_get_node_key
 * get node key by name
 *
 * @param[in]   char*           ach_node            node name
 * @param[in]   int             in_len_node         length of node name
 * @param[in]   ied_charset     ien_encoding        encoding of node name
 * @return      ied_proto_nodes                     node key
*/
ied_proto_nodes ds_ea_ldap::m_get_node_key( const char* ach_node, int in_len_node,
                                            ied_charset ien_encoding )
{
    dsd_unicode_string dsl_key;
    dsl_key.ac_str = (void*)ach_node;
    dsl_key.imc_len_str = in_len_node;
    dsl_key.iec_chs_str = ien_encoding;
    return ds_wsp_helper::m_search_equals_ic2(achr_proto_nodes, dsl_key, ien_pnode_unknown);
} // end of ds_ea_ldap::m_get_node_key


/**Create the PNode (xml format), which will be sent to client.
 *
 * @param[out]  ahstr_resp    output buffer
 * @param[in]   ahstr_domain_username  This string will be written into tag 'user'. It has the format <domain>\<user name>.
 * @param[in]   ahstr_pw_enc This string will be written into tag 'password'.
 * @param[in]   adsl_v_dn The vector contains the DNs, where the user is member of.
*/
void ds_ea_ldap::m_create_resp_connect(ds_hstring* ahstr_resp, ds_hstring* ahstr_domain_username, ds_hstring* ahstr_pw_enc,
                                       ds_hvector<ds_hstring>* adsl_v_dn)
{
// Format:  <?xml version=\"1.0\" encoding=\"UTF-8\"?>
//   <__.>
//      <user>administrator</user>
//      <dn>CN=Administrator,DC=hobadstest,DC=de</dn>
//      <fn>CN=Administrator,DC=hobadstest,DC=de</fn>
//      <id>CN=Administrator,DC=hobadstest,DC=de</id>
//      <ldapkeymembership>uniqueMember</ldapkeymembership>
//      <ldapkeymember></ldapkeymember>
//      <password>1n9XC5Z+</password>
//      <issuperadmin>Y</issuperadmin>
//      <isadmin>Y</isadmin>
//      <eatype>1</eatype>
//      <ldap>Y</ldap>
//      <secure>Y</secure>
//      <ctype>1</ctype>    
//      <ishostip>SERVERADDRESS</ishostip>
//      <memberof>
//          <dn0>CN=TrueWindows,OU=Einsatz,DC=hobadstest,DC=de</dn0>
//          <dn1>CN=Group Policy Creator Owners,CN=Users,DC=hobadstest,DC=de</dn1>
//          <dn2>CN=Domain Admins,CN=Users,DC=hobadstest,DC=de</dn2>
//      </memberof>
//   </__.> 

    // initialize some variables:
    const char*  ach_y           = "Y";
    ds_xml       dsc_xml;                   // xml class (for xml to string)
    dsc_xml.m_init(adsc_wsp_helper);

    // Attention: Because pointers get lost/are overwritten when going thru the items in the vector, we must do the writing to
    // the output in several steps. Then the problem arises that the node '__.', is closed much prior than expected. Therefore we write
    // the node '__.' by hand.

    // create tag for doctype
    const char* ach_tag = "?xml";
    dsd_xml_tag* adsl_tag_doctype = dsc_xml.m_create_tag( ach_tag, (int)strlen(ach_tag), ied_xmltype );
    dsc_xml.m_add_attr(adsl_tag_doctype, "version", (int)strlen("version"), "\"1.0\"", (int)strlen("\"1.0\"") );
    dsc_xml.m_add_attr(adsl_tag_doctype, "encoding", (int)strlen("encoding"), "\"UTF-8\"", (int)strlen("\"UTF-8\"") );
    dsc_xml.m_to_xml(adsl_tag_doctype, ahstr_resp);

    // create main tag '__.' (it is 'next' to doctype-tag, therefore use m_add_next)
    ach_tag = TAG_ESCAPED_ROOT;
    dsd_xml_tag* adsl_tag_gettree = dsc_xml.m_add_next(adsl_tag_doctype, ach_tag, (int)strlen(ach_tag), ied_tag);
    // write opening node '__.' by hand
    ahstr_resp->m_write("<__.>");

    // create tag 'user' (it is a child of '__.') and add the value of the item
    ach_tag = "user";
    dsd_xml_tag* adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, ahstr_domain_username->m_get_ptr(), ahstr_domain_username->m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'dn' (it is a child of '__.') and add the value of the item
    // Attention: Because we write the tag immediatelly to output, we can reuse the pointer adsl_tag_curr!
    ach_tag = "dn";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, hstrc_real_user_dn.m_get_ptr(), hstrc_real_user_dn.m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'fn' (it is a child of '__.') and add the value of the item
    ach_tag = "fn";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, hstrc_real_user_dn.m_get_ptr(), hstrc_real_user_dn.m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'id' (it is a child of '__.') and add the value of the item
    ach_tag = "id";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, hstrc_real_user_dn.m_get_ptr(), hstrc_real_user_dn.m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'ldapkeymembership' (it is a child of '__.') and add the value of the item
    ach_tag = "ldapkeymembership";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, hstrc_ldap_groupmembers.m_get_ptr(), hstrc_ldap_groupmembers.m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'ldapkeymember' (it is a child of '__.') and add the value of the item
    ach_tag = "ldapkeymember";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, hstrc_ldap_groupmembersin.m_get_ptr(), hstrc_ldap_groupmembersin.m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'password' (it is a child of '__.') and add the value of the item
    if (ahstr_pw_enc->m_get_len() > 0) {
        ach_tag = "password";
        adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
        dsc_xml.m_add_value(adsl_tag_curr, ahstr_pw_enc->m_get_ptr(), ahstr_pw_enc->m_get_len());
        dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);
    }
    
    // create tag 'issuperadmin' (it is a child of '__.') and add the value of the item
    ach_tag = "issuperadmin";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, ach_y, (int)strlen(ach_y));
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'isadmin' (it is a child of '__.') and add the value of the item
    ach_tag = "isadmin";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, ach_y, (int)strlen(ach_y));
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'ldap' (it is a child of '__.') and add the value of the item
    ach_tag = "ldap";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, ach_y, (int)strlen(ach_y));
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'secure' (it is a child of '__.') and add the value of the item
    ach_tag = "secure";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, ach_y, (int)strlen(ach_y));
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'srvtype' (it is a child of '__.') and add the value of the item
    ach_tag = "srvtype";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    ds_hstring hstr_srv_type(adsc_wsp_helper, "");
    hstr_srv_type += inc_ldap_srv_type;
    dsc_xml.m_add_value(adsl_tag_curr, hstr_srv_type.m_get_ptr(), hstr_srv_type.m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // JF 07.12.10 create tag 'eatype' (it is a child of '__.') and add the value of the item
    // 'eatype' signals to the client, to which type of EA Server it is connected. In case of real EA Server this
    // value is 0 (default). In case of sdh_ea_ldap (simulated EA Server) this value is 1.
    ach_tag = "eatype";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    ds_hstring hstr_eatype(adsc_wsp_helper, "1");
    dsc_xml.m_add_value(adsl_tag_curr, hstr_eatype.m_get_ptr(), hstr_eatype.m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'ctype' (it is a child of '__.') and add the value of the item
    ach_tag = "ctype";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    ds_hstring hstr_ctype(adsc_wsp_helper, "1");
    dsc_xml.m_add_value(adsl_tag_curr, hstr_ctype.m_get_ptr(), hstr_ctype.m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);
    
    // create tag 'ishostip' (it is a child of '__.') and add the value of the item
    ach_tag = "ishostip";
    adsl_tag_curr = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_curr, hstrc_ldap_address.m_get_ptr(), hstrc_ldap_address.m_get_len());
    dsc_xml.m_to_xml(adsl_tag_curr, ahstr_resp);

    // create tag 'memberof' (it is a child of '__.') and add the value of the item
    // Loop thru the vector and add each item as tag 'dn0', 'dn1', 'dn2', etc
    ahstr_resp->m_write("<memberof>");
    int i = 0;
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, *adsl_v_dn)) {
        const ds_hstring& rdsl_str = HVECTOR_GET(adsl_cur);
        ds_hstring hstr(adsc_wsp_helper, "");
        hstr.m_writef("<dn%d>%.*s</dn%d>", i, rdsl_str.m_get_len(), rdsl_str.m_get_ptr(), i);
        ahstr_resp->m_write(hstr);
        i++;
    }
    ahstr_resp->m_write("</memberof>");

    // write closing node '__.' by hand
    ahstr_resp->m_write("</__.>");

    return;
} // end of ds_ea_ldap::m_create_resp_connect


/**Create response packet in ahstr_resp
 *
 * @param[in]   ds_hstring* ads_response    output buffer
*/
int ds_ea_ldap::m_create_resp_gettree(ds_hstring* ahstr_resp, ds_hvector_btype<dsd_item_gettree>* adsl_v_items)
{
       // Format:  <?xml version=\"1.0\" encoding=\"UTF-8\"?>
//        <gettree>
//            <own>
//                <name>dc=hobadstest,dc=de</name>
//                <id>zdc=hobadstest,dc=de</id>
//            </own>
//            <dn0>
//                <name>ou=Testgruppe</name>
//                <id>dou=Testgruppe,dc=hobadstest,dc=de</id>
//            </dn0>
//            <dn1>
//                <name>cn=as170</name>
//                <id>ucn=as170,dc=hobadstest,dc=de</id>
//            </dn1>
//        </gettree> 

    ds_xml       dsc_xml;                   // xml class (for xml to string)
    dsc_xml.m_init(adsc_wsp_helper);

    // Attention: Because pointers get lost/are overwritten when going thru the items in the vector, we must do the writing to
    // the output in several steps. Then the problem arises that the node 'gettree', is closed much prior than expected. Therefore we write
    // the node 'gettree' by hand.

    // create tag for doctype
    const char* ach_tag = "?xml";
    dsd_xml_tag* adsl_tag_doctype = dsc_xml.m_create_tag( ach_tag, (int)strlen(ach_tag), ied_xmltype );
    dsc_xml.m_add_attr(adsl_tag_doctype, "version", (int)strlen("version"), "\"1.0\"", (int)strlen("\"1.0\"") );
    dsc_xml.m_add_attr(adsl_tag_doctype, "encoding", (int)strlen("encoding"), "\"UTF-8\"", (int)strlen("\"UTF-8\"") );
    dsc_xml.m_to_xml(adsl_tag_doctype, ahstr_resp);

    // create main tag 'gettree' (it is 'next' to doctype-tag, therefore use m_add_next)
    ach_tag = TAG_GETTREE;
    dsd_xml_tag* adsl_tag_gettree = dsc_xml.m_add_next(adsl_tag_doctype, ach_tag, (int)strlen(ach_tag), ied_tag);
    // write opening node 'gettree' by hand
    ahstr_resp->m_write("<gettree>");

    // write item at index 0 to the output
    if (adsl_v_items->m_size() == 0) { // first item in vector is 'OWN'
        return 1;
    }
    
    dsd_hvec_elem<dsd_item_gettree>* adsl_cur_item = adsl_v_items->m_get_first_element2();
    dsd_item_gettree& dsl_item = adsl_cur_item->dsc_element;
    adsl_cur_item = adsl_cur_item->ads_next;
    if (!dsl_item.hstr_tag_name.m_equals(TAG_OWN)) {
        return 2;
    }

    // create tag 'own' (it is a child of 'gettree')
    ach_tag = TAG_OWN;
    dsd_xml_tag* adsl_tag_own = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);

    // create tag 'name' (it is a child of 'own') and add the value of the item
    ach_tag = TAG_NAME;
    dsd_xml_tag* adsl_tag_name = dsc_xml.m_add_child(adsl_tag_own, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_name, dsl_item.hstr_name.m_get_ptr(), dsl_item.hstr_name.m_get_len());

    // create tag 'id' (it is a child of 'own') and add the value of the item
    ach_tag = TAG_ID;
    dsd_xml_tag* adsl_tag_id = dsc_xml.m_add_child(adsl_tag_own, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_id, dsl_item.hstr_id.m_get_ptr(), dsl_item.hstr_id.m_get_len());

    // write node 'own'
    dsc_xml.m_to_xml(adsl_tag_own, ahstr_resp);


    // Loop thru the vector and at each item as tag 'dn0', 'dn1', 'dn2', etc
    while (adsl_cur_item != NULL) {
        dsd_item_gettree& dsl_item = adsl_cur_item->dsc_element;

        // create tag 'dn{count}' (it is a child of 'gettree')
        ach_tag = dsl_item.hstr_tag_name.m_get_ptr();
        if ( (ach_tag[0] != 'd') || (ach_tag[1] != 'n') ) { // must start with 'dn' (e.g. dn12)
            adsc_wsp_helper->m_logf(ied_sdh_log_error, "HEALDE699E: Invalid tag name of item: %s.", dsl_item.hstr_tag_name.m_get_ptr());
            return 3;
        }
        dsd_xml_tag* adsl_tag_dn = dsc_xml.m_add_child(adsl_tag_gettree, ach_tag, (int)strlen(ach_tag), ied_tag);

        // create tag 'name' (it is a child of 'dn{count}') and add the value of the item
        ach_tag = TAG_NAME;
        adsl_tag_name = dsc_xml.m_add_child(adsl_tag_dn, ach_tag, (int)strlen(ach_tag), ied_tag);
        dsc_xml.m_add_value(adsl_tag_name, dsl_item.hstr_name.m_get_ptr(), dsl_item.hstr_name.m_get_len());

        // create tag 'id' (it is a child of 'dn{count}' and a next to 'name') and add the value of the item
        ach_tag = TAG_ID;
        adsl_tag_id = dsc_xml.m_add_child(adsl_tag_dn, ach_tag, (int)strlen(ach_tag), ied_tag);
        dsc_xml.m_add_value(adsl_tag_id, dsl_item.hstr_id.m_get_ptr(), dsl_item.hstr_id.m_get_len());

        dsc_xml.m_to_xml( adsl_tag_dn, ahstr_resp );

        adsl_cur_item = adsl_cur_item->ads_next;
    }

    // write closing node 'gettree' by hand
    ahstr_resp->m_write("</gettree>");

    return SUCCESS;
} // end of ds_ea_ldap::m_create_resp_gettree



/**Create response packet in ahstr_resp
 *
 * @param[in]   ds_hstring* ahstr_resp    output buffer
*/
int ds_ea_ldap::m_create_resp_member(ds_hstring* ahstr_resp, ds_hvector<ds_hstring>* adsl_v_dns)
{
       // Format:  <?xml version=\"1.0\" encoding=\"UTF-8\"?>
       //          <Member>
	   //            <dn1>
	   //              <dn>cn=g1,ou=groups,dc=hob,dc=de</dn>
	   //              <id>cn=g1,ou=groups,dc=hob,dc=de</id>
	   //            </dn1>
       //            <dn0>
	   //              <dn>cn=grp1,ou=groups,dc=hob,dc=de</dn>
	   //              <id>cn=grp1,ou=groups,dc=hob,dc=de</id>
	   //            </dn0>
	   //          </Member> 

    ds_xml       dsc_xml;                   // xml class (for xml to string)
    dsc_xml.m_init(adsc_wsp_helper);

    // Attention: Because pointers get lost/are overwritten when going thru the items in the vector, we must do the writing to
    // the output in several steps. Then the problem arises that the node 'Member', is closed much prior than expected. Therefore we write
    // the node 'Member' by hand.

    // create tag for doctype
    const char* ach_tag = "?xml";
    dsd_xml_tag* adsl_tag_doctype = dsc_xml.m_create_tag( ach_tag, (int)strlen(ach_tag), ied_xmltype );
    dsc_xml.m_add_attr(adsl_tag_doctype, "version", (int)strlen("version"), "\"1.0\"", (int)strlen("\"1.0\"") );
    dsc_xml.m_add_attr(adsl_tag_doctype, "encoding", (int)strlen("encoding"), "\"UTF-8\"", (int)strlen("\"UTF-8\"") );
    dsc_xml.m_to_xml(adsl_tag_doctype, ahstr_resp);

    // create main tag 'Member' (it is 'next' to doctype-tag, therefore use m_add_next)
    ach_tag = TAG_MEMBER;
    dsd_xml_tag* adsl_tag_member = dsc_xml.m_add_next(adsl_tag_doctype, ach_tag, (int)strlen(ach_tag), ied_tag);
    // write opening node 'Member' by hand
    ahstr_resp->m_write("<Member>");

    // No membership relations found -> return an empty PNode
    if (adsl_v_dns->m_size() == 0) { 
        // write closing node 'Member' by hand
        ahstr_resp->m_write("</Member>");
        return SUCCESS;
    }

    // Loop thru the vector and at each membership relation as tag 'dn0', 'dn1', 'dn2', etc
    int i = 0;
    for (HVECTOR_FOREACH2(ds_hstring, adsl_cur, *adsl_v_dns)) {
        ds_hstring& hstr_dn_to_write = HVECTOR_GET(adsl_cur);

        // create tag 'dn{count}' (it is a child of 'Member')
        ds_hstring hstr_dn_number(adsc_wsp_helper, TAG_DN);
        hstr_dn_number.m_writef("%d", i);
        dsd_xml_tag* adsl_tag_dn_number = dsc_xml.m_add_child(adsl_tag_member, hstr_dn_number.m_get_ptr(), hstr_dn_number.m_get_len(), ied_tag);

        // create tag 'dn' (it is a child of 'dn{count}') and add the value of the item
        ach_tag = TAG_DN;
        dsd_xml_tag* adsl_tag_dn = dsc_xml.m_add_child(adsl_tag_dn_number, ach_tag, (int)strlen(ach_tag), ied_tag);
        dsc_xml.m_add_value(adsl_tag_dn, hstr_dn_to_write.m_get_ptr(), hstr_dn_to_write.m_get_len());

        // create tag 'id' (it is a child of 'dn{count}' and a next to 'dn') and add the value of the item
        ach_tag = TAG_ID;
        dsd_xml_tag* adsl_tag_id = dsc_xml.m_add_child(adsl_tag_dn_number, ach_tag, (int)strlen(ach_tag), ied_tag);
        dsc_xml.m_add_value(adsl_tag_id, hstr_dn_to_write.m_get_ptr(), hstr_dn_to_write.m_get_len());

        dsc_xml.m_to_xml( adsl_tag_dn_number, ahstr_resp );
        i++;
    }

    // write closing node 'Member' by hand
    ahstr_resp->m_write("</Member>");

    return SUCCESS;
} // end of ds_ea_ldap::m_create_resp_member


/**
 * function ds_ea_ldap::m_to_number
 * convert in_len chars from gather at position to a number
 * with in_type you select wether input is big or little endian
 *
 * @param[in]   struct dsd_gather_i_1*  ads_gather
 * @param[in]   int*                    ain_offset      working position in gather
 * @param[in]   int                     in_len          how many chars should be read
 * @param[in]   int                     in_type         set HOB_LITTLE_ENDIAN or HOB_BIG_ENDIAN
 * @return      uint64_t                                number
*/
uint64_t ds_ea_ldap::m_to_number( struct dsd_gather_i_1* ads_gather, int* ain_offset,
                                  int in_len, int in_type )
{
    // initialize some variables:
    uint64_t      il_num   = 0;
    uint64_t      il_tmp   = 0;
    int           in_count = 0;
    unsigned char uch_sign = 0;
    
    for ( ; in_count < in_len; in_count++ ) {
        il_tmp = 0;
        if ( in_type == HOB_LITTLE_ENDIAN ) {
            uch_sign = m_get_ptr( ads_gather, (*ain_offset) + in_count )[0];
        } else if ( in_type == HOB_BIG_ENDIAN ) {
            uch_sign = m_get_ptr( ads_gather, (*ain_offset) + (in_len - in_count - 1) )[0];
        }
        il_tmp = uch_sign;
        il_num |= (il_tmp << ((in_count & 7) << 3));
    }
    
    (*ain_offset) += in_len;
    return il_num;
} // end of ds_ea_ldap::m_to_number


/**
 * function ds_ea_ldap::m_from_number
 * write a number to char array in type given byte order
 * if input number need more bytes than buffer, data will be cut off
 *
 * @param[in]   uint64_t        il_num              number to convert
 * @param[in]   unsigned char*  ach_buffer          output buffer
 * @param[in]   int             in_len              length of output
 * @param[in]   int             in_type             set HOB_LITTLE_ENDIAN or HOB_BIG_ENDIAN
*/
void ds_ea_ldap::m_from_number( uint64_t il_num,
                                unsigned char* ach_buffer, int in_len,
                                int in_type )
{
    // initialize some variables:
    int in_count          = 0;
    unsigned char uch_tmp = 0;

    for ( ; in_count < in_len; in_count++ ) {
        uch_tmp = (unsigned char)((il_num >> ((in_count & 7) << 3)) & 0xFF);
        if ( in_type == HOB_LITTLE_ENDIAN ) {
            ach_buffer[in_count] = uch_tmp;
        } else if ( in_type == HOB_BIG_ENDIAN ) {
            ach_buffer[in_len - in_count - 1] = uch_tmp;
        }
    }
} // end of ds_ea_ldap::m_from_number



/**
 * function ds_ea_ldap::m_get_gather_len
 *
 * @param[in]       dsd_gather_i_1*  ads_gather
 * @return          int                             length
*/
int ds_ea_ldap::m_get_gather_len( struct dsd_gather_i_1* ads_gather )
{
    // initialize some variables:
    int in_return = 0;

    do {
        in_return += (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
        ads_gather = ads_gather->adsc_next;
    } while ( ads_gather != NULL );

    return in_return;
} // end of ds_ea_ldap::m_get_gather_len


/**
 * function ds_ea_ldap::m_get_ptr
 *
 * @param[in]       dsd_gather_i_1*  ads_gather
 * @param[in/out]   int              in_offset
 * @return          char* 
*/
char* ds_ea_ldap::m_get_ptr( struct dsd_gather_i_1* ads_gather, int in_offset )
{
    //initialize some variables:
    char* ach_ptr = NULL;
    int   in_len  = 0;

    if ( ads_gather == NULL ) {
        return NULL;
    }

    in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    while ( in_offset >= in_len ) {
        in_offset  -= in_len;
        ads_gather  = ads_gather->adsc_next;
        if ( ads_gather == NULL ) {
            return NULL;
        }
        in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    }
    
    ach_ptr = ads_gather->achc_ginp_cur + in_offset;
    return ach_ptr;
} // end of ds_ea_ldap::m_get_ptr


/**
 * function ds_ea_ldap::m_mark_processed
 *
 * mark gather as processed until offset and get new length
 * @param[in]   struct dsd_gather_i_1*  ads_gather
 * @param[in]   int*                    ain_offset
 * @param[in]   int*                    ain_length
*/
void ds_ea_ldap::m_mark_processed( struct dsd_gather_i_1* ads_gather,
                                   int* ain_offset, int* ain_length )
{
    //initialize some variables:
    int in_len = 0;

    if ( ads_gather == NULL ) {
        *ain_offset = 0;
        *ain_length = 0;
        return;
    }

    in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    while ( (*ain_offset) >= in_len ) {
        (*ain_offset) -= in_len;
        (*ain_length) -= in_len;
        ads_gather->achc_ginp_cur = ads_gather->achc_ginp_end;
        ads_gather = ads_gather->adsc_next;
        if ( ads_gather == NULL ) {
            *ain_offset = 0;
            *ain_length = 0;
            return;
        }
        in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    }

    ads_gather->achc_ginp_cur = ads_gather->achc_ginp_cur + *ain_offset;
    (*ain_length) -= *ain_offset;
    (*ain_offset)  = 0;
    return;
} // end of ds_ea_ldap::m_mark_processed


/**
 * function ds_ea_ldap::m_get_buf
 * request a buffer from length in_wanted from gather
 * if in_wanted is not available at once, *ain_get will give you 
 * the received data length
 *
 * @param[in]   struct dsd_gather_i_1*  ads_gather
 * @param[in]   int                     in_offset           offset in gather
 * @param[in]   int                     in_requested        requested length
 * @param[out]  int*                    ain_received        returned length
 * @return      char*                                       pointer to data
*/
char* ds_ea_ldap::m_get_buf( struct dsd_gather_i_1* ads_gather, int in_offset,
                             int in_requested, int* ain_received )
{
    // initialize some variables:
    char* ach_ptr = NULL;
    int   in_len  = 0;

    in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    while ( in_offset >= in_len ) {
        in_offset -= in_len;
        ads_gather = ads_gather->adsc_next;
        if ( ads_gather == NULL ) {
            return NULL;
        }
        in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    }

    ach_ptr = ads_gather->achc_ginp_cur + in_offset;
    if ( in_len - in_offset < in_requested ) {
        *ain_received = (in_len - in_offset);
    } else {
        *ain_received = in_requested;
    }

    return ach_ptr;
} // end of ds_ea_ldap::m_get_buf


int ds_ea_ldap::m_send_response(int in_command, int in_state, int in_element, const char* ach_data_zero_terminated) {
    int in_len_msg = 0;
    if (ach_data_zero_terminated != NULL) {
        in_len_msg = (int)strlen(ach_data_zero_terminated);
    }
    return m_send_response(in_command, in_state, in_element, ach_data_zero_terminated, in_len_msg);
}

int ds_ea_ldap::m_send_response(int in_command, int in_state, int in_element, const char* ach_data, int in_len_msg) {
    if (ach_data == NULL) {
        in_len_msg = 0;
    }

    int in_offset = 0;
    if (((in_state & ien_sts_neg) != ien_sts_neg) && (in_command == ien_cmd_getfiles)) {
        // In case of getfiles-success the payload-data start at position PARAM1, which is the last 4 bytes of header !
        in_offset = 4;
    }

    char ch_header[LEN_EA_HEADER];
    m_set_ea_hdr(dsc_ea_hdr_out, &ch_header[0], LEN_EA_HEADER - in_offset + in_len_msg, in_state, EA_VERSION, in_element, 0, in_command, in_len_msg);
    ds_hstring hstr_to_send(adsc_wsp_helper);
    hstr_to_send.m_write(&ch_header[0], LEN_EA_HEADER - in_offset);

    if (in_len_msg != 0) { // Write error message or other data as payload data to return-string.
        hstr_to_send.m_write(ach_data, in_len_msg);
    }

    // Send header and data.
    adsc_wsp_helper->m_send_data(hstr_to_send.m_get_ptr(), hstr_to_send.m_get_len(), ied_sdh_dd_toclient );

    return SUCCESS;
}

int ds_ea_ldap::m_set_ea_hdr(dsd_ea_header& dsl_ea_hdr, char* ach_buf, int in_total_len, int in_state, int in_version, int in_element, int in_exception, int in_command, int in_param1)
{
    dsl_ea_hdr.in_total_len    = in_total_len;
    dsl_ea_hdr.in_state        = in_state;
    dsl_ea_hdr.in_version      = in_version;
    dsl_ea_hdr.in_element      = in_element;
    dsl_ea_hdr.in_exception    = in_exception;
    dsl_ea_hdr.in_command      = in_command;
    dsl_ea_hdr.in_param1       = in_param1;

    if (ach_buf != NULL) {
        m_hdr_to_array(dsl_ea_hdr, ach_buf);
    }

    return SUCCESS;
} // end of ds_ea_ldap::m_set_ea_hdr

bool ds_ea_ldap::m_hdr_to_array(dsd_ea_header dsl_ea_hdr, char* ach_buf) {
    m_write_int_to_hob_header(ach_buf, dsl_ea_hdr.in_total_len,  0);
    m_write_int_to_hob_header(ach_buf, dsl_ea_hdr.in_state    ,  4);
    m_write_int_to_hob_header(ach_buf, dsl_ea_hdr.in_version  ,  8);
    m_write_int_to_hob_header(ach_buf, dsl_ea_hdr.in_element  , 12);
    m_write_int_to_hob_header(ach_buf, dsl_ea_hdr.in_exception, 16);
    m_write_int_to_hob_header(ach_buf, dsl_ea_hdr.in_command  , 20);
    m_write_int_to_hob_header(ach_buf, dsl_ea_hdr.in_param1   , 24);
    return true;
}


void ds_ea_ldap::m_write_int_to_hob_header(char* ach, int in_insert, int in_pos) {
    ach[in_pos    ] = (byte)( in_insert        & 0xFF);
    ach[in_pos + 1] = (byte)((in_insert >> 8 ) & 0xFF);
    ach[in_pos + 2] = (byte)((in_insert >> 16) & 0xFF);
    ach[in_pos + 3] = (byte)((in_insert >> 24) & 0xFF);
}

int ds_ea_ldap::m_read_int(char* ach, int in_pos) {
    int in_ret = ((ach[in_pos + 3] << 24) & 0xFF000000) +
                 ((ach[in_pos + 2] << 16) & 0x00FF0000) +
                 ((ach[in_pos + 1] << 8 ) & 0x0000FF00) +
                  (ach[in_pos    ]        & 0x000000FF) ;
    return in_ret;
}


int ds_ea_ldap::m_encrypt_password(const char* ach_pw_clear_utf8, const char* ach_username_utf8, ds_hstring* ahstr_pw_encrypted) {
    if (ach_username_utf8 == NULL) {
        return 1;
    }
    if (ach_pw_clear_utf8 == NULL) {
        return 2;
    }
    //-----------------------------------
    // Encrypt the password
    //-----------------------------------
    int in_len_pw_buf = (int)strlen(ach_pw_clear_utf8);
    in_len_pw_buf += 2;
    in_len_pw_buf = in_len_pw_buf << 2;
    in_len_pw_buf += 1;
    char* ach_pw_iso8859_1 = adsc_wsp_helper->m_cb_get_memory(in_len_pw_buf, true); // ISO_8859_1 is Ansi_819
    if (ach_pw_iso8859_1 == NULL) {
        return 3;
    }
    int in_ret_len_iso8859_1 = 0;
    if (!dsc_crypt.AUrps1(ach_pw_clear_utf8, ach_username_utf8, in_len_pw_buf, ach_pw_iso8859_1, (PINT)(&in_ret_len_iso8859_1))) {
        adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
        return 4; //Something went wrong.
    }
    if (in_ret_len_iso8859_1 >= in_len_pw_buf) {
        adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
        return 5; // The password did not fit into the buffer!!!
    }
    //-----------------------------------
    // The password now is in ISO_8859_1 (similar to Ansi_819). Convert it to UTF8.
    //-----------------------------------
    int in_len_utf8 = m_len_vx_vx(ied_chs_utf_8, ach_pw_iso8859_1, in_ret_len_iso8859_1, ied_chs_ansi_819);
    if (in_len_utf8 < 0) { // Error
        adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
        return 6;
    }
    // Get memory
    in_len_utf8++; // for zero-termination
    char* ach_pw_utf8 = adsc_wsp_helper->m_cb_get_memory(in_len_utf8, true); // ISO_8859_1 is Ansi_819
    if (ach_pw_utf8 == NULL) {
        adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
        return 7;
    }
    // The conversion: 
    int in_ret = m_cpy_vx_vx(ach_pw_utf8, in_len_utf8, ied_chs_utf_8, ach_pw_iso8859_1, in_ret_len_iso8859_1, ied_chs_ansi_819);
    adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
    if (in_ret < 0) { // Error
        adsc_wsp_helper->m_cb_free_memory(ach_pw_utf8, in_len_utf8);
        return 8;
    }

    ahstr_pw_encrypted->m_set(ach_pw_utf8, in_len_utf8-1);

    adsc_wsp_helper->m_cb_free_memory(ach_pw_utf8, in_len_utf8);

    return SUCCESS;
}


int ds_ea_ldap::m_decrypt_password(const char* ach_pw_encrypted, const char* ach_username_utf8, ds_hstring* ahstr_pw_clear_utf8) {
    if (ach_username_utf8 == NULL) {
        return 1;
    }
    if (ach_pw_encrypted == NULL) {
        return 2;
    }
    //-----------------------------------
    // Decrypt the password
    //-----------------------------------
    int in_len_pw_buf = (int)strlen(ach_pw_encrypted);
    in_len_pw_buf += 2;
    in_len_pw_buf += 1;
    char* ach_pw_iso8859_1 = adsc_wsp_helper->m_cb_get_memory(in_len_pw_buf, true); // ISO_8859_1 is Ansi_819
    if (ach_pw_iso8859_1 == NULL) {
        return 3;
    }
    int in_ret_len_iso8859_1 = 0;
    if (!dsc_crypt.AUrps2(ach_pw_encrypted, ach_username_utf8, in_len_pw_buf, ach_pw_iso8859_1, (PINT)(&in_ret_len_iso8859_1))) {
        adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
        return 4; //Something went wrong.
    }
    if (in_ret_len_iso8859_1 >= in_len_pw_buf) {
        adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
        return 5; // The password did not fit into the buffer!!!
    }
    //-----------------------------------
    // The password now is in ISO_8859_1 (similar to Ansi_819). Convert it to UTF8.
    //-----------------------------------
    int in_len_utf8 = m_len_vx_vx(ied_chs_utf_8, ach_pw_iso8859_1, in_ret_len_iso8859_1, ied_chs_ansi_819);
    if (in_len_utf8 < 0) { // Error
        adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
        return 6;
    }
    // Get memory
    in_len_utf8++; // for zero-termination
    char* ach_pw_utf8 = adsc_wsp_helper->m_cb_get_memory(in_len_utf8, true); // ISO_8859_1 is Ansi_819
    if (ach_pw_utf8 == NULL) {
        adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
        return 7;
    }
    // The conversion: 
    int in_ret = m_cpy_vx_vx(ach_pw_utf8, in_len_utf8, ied_chs_utf_8, ach_pw_iso8859_1, in_ret_len_iso8859_1, ied_chs_ansi_819);
    adsc_wsp_helper->m_cb_free_memory(ach_pw_iso8859_1, in_len_pw_buf);
    if (in_ret < 0) { // Error
        adsc_wsp_helper->m_cb_free_memory(ach_pw_utf8, in_len_utf8);
        return 8;
    }

    ahstr_pw_clear_utf8->m_set(ach_pw_utf8, in_len_utf8-1);

    adsc_wsp_helper->m_cb_free_memory(ach_pw_utf8, in_len_utf8);

    return SUCCESS;
}


// similar to LDAPSet.getTreeElements
int ds_ea_ldap::m_get_tree_elements(ds_hstring* hstr_dn_parent, ds_hvector_btype<dsd_item_gettree>* ads_v_items) {
    ds_hvector<ds_attribute_string> dsl_v_objectclass(adsc_wsp_helper);
    ds_hstring hstr_attrname(adsc_wsp_helper, "objectclass", (int)strlen("objectclass"));
    ds_hstring hstr_filter(adsc_wsp_helper, "", 0);
    int inl_ret = dsc_ldap.m_read_attributes(&hstr_attrname, &hstr_filter, hstr_dn_parent, ied_sear_onelevel, &dsl_v_objectclass);
    if (inl_ret != SUCCESS) {
        adsc_wsp_helper->m_logf( ied_sdh_log_error, "HEALDE583E: m_read_attributes failed with error %d. Details: %s", inl_ret, dsc_ldap.m_get_last_error().m_get_ptr()); // duplicate HEALDE503E
        return inl_ret+10;
    }

    // create a dsd_item_gettree for each DN and add it to the vector
    int i = 0;
    for (HVECTOR_FOREACH(ds_attribute_string, adsl_cur, dsl_v_objectclass)) {
        const ds_attribute_string& dsl_attr = HVECTOR_GET(adsl_cur);
        // Determine the HOB-class-character (e.g. u for an user)
        char ch_hoboc = dsc_ldap.m_get_oc_id(&dsl_attr);

        // The name of the item is the DN subtracted by the base
        ds_hstring hstr_dn_item = dsl_attr.m_get_dn();
        ds_hstring hstr_comma_parent(adsc_wsp_helper, ",");
        hstr_comma_parent.m_write(hstr_dn_parent);
        int in_pos = hstr_dn_item.m_search_last_ic(hstr_comma_parent);
        if (in_pos == -1) {
            adsc_wsp_helper->m_logf(ied_sdh_log_error, "HEALDE617E: DN of item '%s' does not match parent DN '%s'.", hstr_dn_item.m_get_ptr(), hstr_dn_parent->m_get_ptr());
            return 2;
        }
        
        dsd_item_gettree dsl_item;
        dsl_item.hstr_tag_name.m_setup(adsc_wsp_helper);
        dsl_item.hstr_tag_name.m_write(TAG_DN);
        dsl_item.hstr_tag_name.m_write_int(i);
        hstr_dn_item = hstr_dn_item.m_substr(0, in_pos);

        /* AKRE - 11.04.2013 */
        m_esc_chars_tree( &hstr_dn_item );
        /* check if we have a special character */

        dsl_item.hstr_name.m_setup(adsc_wsp_helper);
        dsl_item.hstr_name = hstr_dn_item;
        dsl_item.hstr_id.m_setup(adsc_wsp_helper);
        dsl_item.hstr_id += ch_hoboc;
        //AKREdsl_item.hstr_id += dsl_attr.m_get_dn().m_get_ptr();

        /* AKRE - 11.04.2013 */
        ds_hstring hstrl_tmp = dsl_attr.m_get_dn();
        m_esc_chars_tree( &hstrl_tmp );
        dsl_item.hstr_id += hstrl_tmp;
        /* check if we have a special character */
        
        ads_v_items->m_add(dsl_item);
        i++;
    }

    return SUCCESS;
}

// Get the members of the groups hstr_dn 
int ds_ea_ldap::m_members(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg) {
    ds_hstring hstr_dn = adsl_xml->m_read_string(ads_pnode, TAG_DNN, (int)strlen(TAG_DNN), "", 0);
    if (hstr_dn.m_get_len() == 0) {
        return 1;
    }

	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dn.m_get_ptr(),	hstr_dn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dn.m_reset();
		hstr_dn.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Get the groups, where the item hstr_dn is member in OR the users, which are member in the item hstr_dn.
    ds_hvector<ds_hstring> dsl_v_dns(adsc_wsp_helper);
    int inl_ret = dsc_ldap.m_get_members(&dsl_v_dns, &hstr_dn);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE444E: m_get_members() failed with error %d.", inl_ret);
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        return 2;
    }

    inl_ret = m_create_resp_member(ahstr_resp, &dsl_v_dns);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE618E: m_create_resp_member failed with error %d.", inl_ret);
        return 3;
    }

    return SUCCESS;
}


// Get the groups, where the item hstr_dn is member in OR the users, which are member in the item hstr_dn.
int ds_ea_ldap::m_membership(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg) {
    ds_hstring hstr_dn = adsl_xml->m_read_string(ads_pnode, TAG_DNN, (int)strlen(TAG_DNN), "", 0);
    if (hstr_dn.m_get_len() == 0) {
        return 1;
    }

	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dn.m_get_ptr(),	hstr_dn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dn.m_reset();
		hstr_dn.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Get the groups, where the item hstr_dn is member in OR the users, which are member in the item hstr_dn.
    ds_hvector<ds_hstring> dsl_v_dns(adsc_wsp_helper);
    int inl_ret = dsc_ldap.m_get_membership(&dsl_v_dns, &hstr_dn, false);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE444E: m_get_membership() failed with error %d.", inl_ret);
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        return 2;
    }

    inl_ret = m_create_resp_member(ahstr_resp, &dsl_v_dns);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE618E: m_create_resp_member failed with error %d.", inl_ret);
        return 3;
    }

    return SUCCESS;
}

// similar to Java hlGenIsUserInTree()
int ds_ea_ldap::m_isuserintree(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg, int in_cmd) {
    ahstr_err_msg->m_reset();

    ds_hstring hstr_dn_item = adsl_xml->m_read_string(ads_pnode, TAG_ID, (int)strlen(TAG_ID), "", 0);
    if (hstr_dn_item.m_get_len() < 1) {
        ahstr_err_msg->m_writef("HEALDE619E: No parameter '%s' specified.", TAG_ID);
        return 1;
    }
	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dn_item in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dn_item.m_get_ptr(),	hstr_dn_item.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dn_item.m_reset();
		hstr_dn_item.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    ds_hstring hstr_parent(adsc_wsp_helper, "");
    bool bo_is_in_tree = false;
    switch (in_cmd) {
        case ien_gen_cmd_getparent: {
            int inl_ret = dsc_ldap.m_get_parent(&hstr_dn_item, &hstr_parent);
            if (inl_ret != SUCCESS) {
                ahstr_err_msg->m_writef("HEALDE443E: m_get_parent() failed with error %d.", inl_ret);
                const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
                adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                    ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                    rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
                return 2;
            }
            break;
        }
        case ien_gen_cmd_isuserintree: {
            ds_hstring hstr_dn_tree = adsl_xml->m_read_string(ads_pnode, TAG_TREE, (int)strlen(TAG_TREE), "", 0);
            if (hstr_dn_tree.m_get_len() < 1) {
                ahstr_err_msg->m_writef("HEALDE219E: No parameter '%s' specified.", TAG_TREE);
                return 3;
            }
			//convert in utf-8
			char chrl_vxbuffer[1024];
			int iml_vxlen;

			//==== hstr_dn_tree in utf-8==========
			memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
			iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
									hstr_dn_tree.m_get_ptr(),	hstr_dn_tree.m_get_len(),	ied_chs_html_1 );
			if ( iml_vxlen > 0 ) {
				hstr_dn_tree.m_reset();
				hstr_dn_tree.m_write( chrl_vxbuffer, iml_vxlen);		
			}
			//end convert

            int inl_ret = dsc_ldap.m_is_item_in_tree(&hstr_dn_item, &hstr_dn_tree, &bo_is_in_tree);
            if (inl_ret != SUCCESS) {
                ahstr_err_msg->m_writef("HEALDE238E: m_is_item_in_tree() failed for user '%.*s' and tree '%.*s' with error %d.",
                    hstr_dn_item.m_get_len(), hstr_dn_item.m_get_ptr(), hstr_dn_tree.m_get_len(), hstr_dn_tree.m_get_ptr(), inl_ret);
                const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
                adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                    ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                    rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
                return 4;
            }

            bool bo_is_user = false;
            inl_ret = dsc_ldap.m_is_user(&hstr_dn_item, &bo_is_user);
            if ((inl_ret != SUCCESS) || (!bo_is_user) ) {
                ahstr_err_msg->m_writef("HEALDE687E: Item is not a user: %.*s.",
                    hstr_dn_item.m_get_len(), hstr_dn_item.m_get_ptr());
                const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
                adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                    ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                    rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
                return 5;
            }

            break;
        }  
        default: {
            ahstr_err_msg->m_writef("HEALDE239E: Invalid mode '%d'.", in_cmd);
            return 6;
        }
    } // switch

    // Create the response PNode.
    ds_xml dsc_xml;
    dsc_xml.m_init(adsc_wsp_helper);

    // create tag for doctype
    const char* ach_tag = "?xml";
    dsd_xml_tag* adsl_tag_doctype = dsc_xml.m_create_tag( ach_tag, (int)strlen(ach_tag), ied_xmltype );
    dsc_xml.m_add_attr(adsl_tag_doctype, "version", (int)strlen("version"), "\"1.0\"", (int)strlen("\"1.0\"") );
    dsc_xml.m_add_attr(adsl_tag_doctype, "encoding", (int)strlen("encoding"), "\"UTF-8\"", (int)strlen("\"UTF-8\"") );
    dsc_xml.m_to_xml(adsl_tag_doctype, ahstr_resp);

    // create main tag '__.' (it is 'next' to doctype-tag, therefore use m_add_next)
    dsd_xml_tag* adsl_tag_root = dsc_xml.m_add_next(adsl_tag_doctype, TAG_ESCAPED_ROOT, (int)strlen(TAG_ESCAPED_ROOT), ied_tag);

    if (in_cmd == ien_gen_cmd_getparent) {
        dsd_xml_tag* adsl_tag_id = dsc_xml.m_add_child(adsl_tag_root, TAG_ID, (int)strlen(TAG_ID), ied_tag);
        dsc_xml.m_add_value(adsl_tag_id, hstr_parent.m_get_ptr(), hstr_parent.m_get_len());
    }
    else { // ien_gen_cmd_isuserintree
        dsd_xml_tag* adsl_tag_ret = dsc_xml.m_add_child(adsl_tag_root, TAG_P_RET, (int)strlen(TAG_P_RET), ied_tag);
        dsc_xml.m_add_value(adsl_tag_ret, (bo_is_in_tree? "Y": "N"), 1);
    }

    dsc_xml.m_to_xml( adsl_tag_root, ahstr_resp );

    return SUCCESS;
}

int ds_ea_ldap::m_ldapa(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg)
{
    ds_hstring hstr_dn = adsl_xml->m_read_string(ads_pnode, TAG_DNN, (int)strlen(TAG_DNN), "", 0);
    if (hstr_dn.m_get_len() == 0) {
        return 1;
    }

	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dn.m_get_ptr(),	hstr_dn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dn.m_reset();
		hstr_dn.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Return data
    ds_hvector<ds_attribute_string> dsl_v_attr(adsc_wsp_helper);

    // JF 16.04.10 TAG_ATTRIBUTES holds the name of a special attribute. If TAG_ATTRIBUTES is set, return values of this single attribute. If not set,
    // all attributes for the specified DN will be returned.
    ds_hstring hstr_attribute = adsl_xml->m_read_string(ads_pnode, TAG_ATTRIBUTES, (int)strlen(TAG_ATTRIBUTES), "", 0); // if the string is empty -> get all available attributes
    if (hstr_attribute.m_get_len() > 0) {
        ds_hstring hstr_filter(adsc_wsp_helper, "");
        int inl_ret = dsc_ldap.m_read_attributes(&hstr_attribute, &hstr_filter, &hstr_dn, ied_sear_baseobject, &dsl_v_attr);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE472E: m_get_attr_list() failed with error %d for attribute %.*s.",
                inl_ret, hstr_attribute.m_get_len(), hstr_attribute.m_get_ptr());
            const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
            adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
            return 10;
        }
    }
    else {
        int inl_ret = dsc_ldap.m_get_attr_list(&dsl_v_attr, &hstr_dn, true);
        if (inl_ret != SUCCESS) {
            ahstr_err_msg->m_writef("HEALDE442E: m_get_attr_list() failed with error %d.", inl_ret);
            const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
            adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
            return 2;
        }
    }

/* Example:
<?xml version="1.0" encoding="UTF-8"?>
<__.>
<objectClass>
<value>
<__4>top</__4>
<__3>hoboc</__3>
<__2>inetOrgPerson</__2>
<__1>organizationalPerson</__1>
<__0>person</__0>
</value>
</objectClass>
<hobm>
<value>
<__0>....</__0></value></hobm>
<hobl>
<value>
... */

    // xml class (for xml to string)
    ds_xml dsc_xml;
    dsc_xml.m_init(adsc_wsp_helper);

    // create tag for doctype
    const char* ach_tag = "?xml";
    dsd_xml_tag* adsl_tag_doctype = dsc_xml.m_create_tag( ach_tag, (int)strlen(ach_tag), ied_xmltype );
    dsc_xml.m_add_attr(adsl_tag_doctype, "version", (int)strlen("version"), "\"1.0\"", (int)strlen("\"1.0\"") );
    dsc_xml.m_add_attr(adsl_tag_doctype, "encoding", (int)strlen("encoding"), "\"UTF-8\"", (int)strlen("\"UTF-8\"") );
    dsc_xml.m_to_xml(adsl_tag_doctype, ahstr_resp);

    // The rest will be written by hand
    ahstr_resp->m_write("\n", 1); //LineFeed

    // write main tag '.' (escaped '__.')
    ahstr_resp->m_write_xml_open_tag(TAG_ESCAPED_ROOT);
    ahstr_resp->m_write("\n", 1); //LineFeed

    // write the atrributes
    for (HVECTOR_FOREACH(ds_attribute_string, adsl_cur, dsl_v_attr)) {
        const ds_attribute_string& dsl_attr = HVECTOR_GET(adsl_cur);
        ds_hstring hstr_name = dsl_attr.m_get_name();

        // write attribute name as tag
        m_esc_chars_xml(&hstr_name, false);
        ahstr_resp->m_write_xml_open_tag( hstr_name.m_get_ptr(), hstr_name.m_get_len());
        ahstr_resp->m_write("\n", 1); //LineFeed

        // JF 16.04.10 Write a flag for binary, if attribute is a binary attribute.
        bool bo_attr_is_binary = dsc_ldap.m_is_binary(&hstr_name);
        if (bo_attr_is_binary) {
            ahstr_resp->m_write("<binary>Y</binary>");
        }

        // write the values of this attribute
        ahstr_resp->m_write("<value>\n"); // opening tag
        const ds_hvector<ds_hstring>& dsl_values = dsl_attr.m_get_values();
        int a = 0;
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur2, dsl_values)) {
            // number
            ds_hstring hstr_number(adsc_wsp_helper);
            hstr_number = a;
            m_esc_chars_xml(&hstr_number, false);
            ahstr_resp->m_write_xml_open_tag(hstr_number.m_get_ptr(), hstr_number.m_get_len());
            ahstr_resp->m_write("\n", 1); //LineFeed
            // the value itself
            ds_hstring hstr_val = HVECTOR_GET(adsl_cur2);
            if (bo_attr_is_binary) { // JF 16.04.10
                ahstr_resp->m_write_b64(hstr_val.m_get_ptr(), hstr_val.m_get_len());
            }
            else {
                m_esc_chars_xml(&hstr_val, true);
                ahstr_resp->m_write(hstr_val);
            }
            // close number
            ahstr_resp->m_write_xml_close_tag(hstr_number.m_get_ptr(), hstr_number.m_get_len());
            ahstr_resp->m_write("\n", 1); //LineFeed
            a++;
        }
        ahstr_resp->m_write("</value>\n"); // close tag

        // close tag of attribute name
        ahstr_resp->m_write_xml_close_tag(hstr_name.m_get_ptr(), hstr_name.m_get_len());
        ahstr_resp->m_write("\n", 1); //LineFeed
    }

    // close main tag '__.'
    ahstr_resp->m_write_xml_close_tag(TAG_ESCAPED_ROOT);
    ahstr_resp->m_write("\n", 1); //LineFeed

    return SUCCESS;
}

// similar to LDAPSet.hlGenNode()
int ds_ea_ldap::m_copy_move(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg, bool bo_move)
{
    // Destination node name
    ds_hstring hstr_dnn = adsl_xml->m_read_string(ads_pnode, TAG_DNN, (int)strlen(TAG_DNN), "", 0);
    if (hstr_dnn.m_get_len() == 0) {
        ahstr_err_msg->m_set("HEALDE686E: Missing parameter: Destination node name");
        return 1;
    }
	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dnn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dnn.m_get_ptr(),	hstr_dnn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dnn.m_reset();
		hstr_dnn.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Destination context
    ds_hstring hstr_dctx = adsl_xml->m_read_string(ads_pnode, TAG_DCN, (int)strlen(TAG_DCN), "", 0);
	//convert in utf-8

	//==== hstr_dctx in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dctx.m_get_ptr(),	hstr_dctx.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dctx.m_reset();
		hstr_dctx.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Source node name
    ds_hstring hstr_snn = adsl_xml->m_read_string(ads_pnode, TAG_RNN, (int)strlen(TAG_RNN), "", 0);
    if (hstr_snn.m_get_len() == 0) {
        ahstr_err_msg->m_set("HEALDE685E: Missing parameter: Source node name");
        return 2;
    }
	//convert in utf-8

	//==== hstr_snn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_snn.m_get_ptr(),	hstr_snn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_snn.m_reset();
		hstr_snn.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Source context
    ds_hstring hstr_sctx = adsl_xml->m_read_string(ads_pnode, TAG_RCN, (int)strlen(TAG_RCN), "", 0);
	//convert in utf-8

	//==== hstr_snn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_sctx.m_get_ptr(),	hstr_sctx.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_sctx.m_reset();
		hstr_sctx.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Source id
    ds_hstring hstr_sid = adsl_xml->m_read_string(ads_pnode, TAG_RID, (int)strlen(TAG_RID), "", 0);
	//convert in utf-8

	//==== hstr_sid in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_sid.m_get_ptr(),	hstr_sid.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_sid.m_reset();
		hstr_sid.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Check and compose source DN
    if (hstr_sid.m_get_len() == 0) {
        if (hstr_snn.m_get_len() == 0) {
            ahstr_err_msg->m_set("HEALDE684E: Missing parameter: Source id and source node name");
            return 3;
        }
        hstr_sid.m_set(hstr_snn);
        if (hstr_sctx.m_get_len() > 0) {
            hstr_sid.m_set(hstr_snn);
            hstr_sid.m_write(DN_SEPARATOR);
            hstr_sid += hstr_sctx;
        }
    }

    // Compose the DN of the target
    if (hstr_dctx.m_get_len() > 0) {
        hstr_dnn.m_write(",");
        hstr_dnn += hstr_dctx;
    }

    // get all attributes of the source item
    ds_hvector<ds_attribute_string> dsl_v_attr(adsc_wsp_helper);
    int inl_ret = dsc_ldap.m_get_attr_list(&dsl_v_attr, &hstr_sid, true);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE441E: m_get_attr_list() failed with error %d.", inl_ret);
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        return 5;
    }

    // Loop over all objects, find HOB-objects and copy/move these
    if (dsl_v_attr.m_size()== 0) {
        return SUCCESS; // there is nothing to copy/move -> we are done
    }

    // Copy values of all attributes, which have a name starting with "hob".
    for (HVECTOR_FOREACH(ds_attribute_string, adsl_cur, dsl_v_attr)) {
        const ds_attribute_string& dsl_attr = HVECTOR_GET(adsl_cur);
        const ds_hstring& hstr_name = dsl_attr.m_get_name();
        if (!hstr_name.m_starts_with("hob")) {
            continue;
        }

        const ds_hvector<ds_hstring>& dsl_values = dsl_attr.m_get_values();
        if (dsl_values.m_size() != 1) {
            // the attribute is not single-valued
            ahstr_err_msg->m_set("HEALDE683E: Copying of data failed; the attribute is not single-valued.");
            return 6;
        }

        const ds_hstring& hstr_val = dsl_attr.m_get_value_at(0);

        dsd_ldap_attr dsl_attr_to_write;
        dsl_attr_to_write.adsc_next_attr = NULL;
        dsl_attr_to_write.ac_attr        = const_cast<char*>(hstr_name.m_get_ptr());
        dsl_attr_to_write.imc_len_attr   = hstr_name.m_get_len();
        dsl_attr_to_write.iec_chs_attr   = ied_chs_utf_8;
        dsl_attr_to_write.dsc_val.adsc_next_val = NULL;
        dsl_attr_to_write.dsc_val.ac_val        = const_cast<char*>(hstr_val.m_get_ptr());
        dsl_attr_to_write.dsc_val.imc_len_val   = hstr_val.m_get_len();
        dsl_attr_to_write.dsc_val.iec_chs_val   = ied_chs_utf_8;

        int inl_ret = m_write_attributes(&hstr_dnn, dsl_attr_to_write, false, ahstr_err_msg);
        if (inl_ret != SUCCESS) {
            const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
            adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
            return 7;
        }

        if (bo_move) {
            // Delete the attribute at the resource item.
            dsl_attr_to_write.dsc_val.ac_val        = NULL;
            dsl_attr_to_write.dsc_val.imc_len_val   = 0; // A length of 0 means, that the attribute shall be deleted.
            int inl_ret = m_write_attributes(&hstr_sid, dsl_attr_to_write, true, ahstr_err_msg);
            if (inl_ret != SUCCESS) {
                const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
                adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                    ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                    rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
                return 8;
            }
        }
    }

    // Return the DN of the target (similar to JAVA).
    ahstr_resp->m_set(hstr_dnn); // weiter

    return SUCCESS;
}

/**Cutting objects from one point and pasting it to another one.
 * LDAP needs the source and the destination DN to modify the object DN. 
 *
 * @param adsl_xml [in] 
 * @param ads_pnode [in] 
 * @param ahstr_err_msg [in] 
 * @param bo_move [in]
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ea_ldap::m_modify_dn( ds_xml *adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring *ahstr_err_msg, bool bo_move){
    
    bool bo_ret = false;
    dsd_co_ldap_1 dsl_ldap;

    // Destination node name
    ds_hstring hstr_dnn = adsl_xml->m_read_string(ads_pnode, TAG_DNN, (int)strlen(TAG_DNN), "", 0);
    if (hstr_dnn.m_get_len() == 0) {
        ahstr_err_msg->m_set("HEALDE686E: Missing parameter: Destination node name");
        return 1;
    }
	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dnn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dnn.m_get_ptr(),	hstr_dnn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dnn.m_reset();
		hstr_dnn.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Source node name
    ds_hstring hstr_snn = adsl_xml->m_read_string(ads_pnode, TAG_RNN, (int)strlen(TAG_RNN), "", 0);
    if (hstr_snn.m_get_len() == 0) {
        ahstr_err_msg->m_set("HEALDE685E: Missing parameter: Source node name");
        return 2;
    }
	//convert in utf-8

	//==== hstr_snn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_snn.m_get_ptr(),	hstr_snn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_snn.m_reset();
		hstr_snn.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Destination node name + Destination context
    hstr_dnn.m_write(",");
    hstr_dnn += adsl_xml->m_read_string(ads_pnode, TAG_DCN, (int)strlen(TAG_DCN), "", 0);

    // Source node name + Source context
    hstr_snn.m_write(",");
    hstr_snn += adsl_xml->m_read_string(ads_pnode, TAG_RCN, (int)strlen(TAG_RCN), "", 0);

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap = ied_co_ldap_modify_dn;

    dsl_ldap.iec_chs_dn  = ied_chs_utf_8;
    dsl_ldap.imc_len_dn  = hstr_snn.m_get_len();
    dsl_ldap.ac_dn       = const_cast<char*>(hstr_snn.m_get_ptr());

    dsl_ldap.iec_chs_newrdn = ied_chs_utf_8;
    dsl_ldap.imc_len_newrdn = hstr_dnn.m_get_len();
    dsl_ldap.ac_newrdn      = const_cast<char*>(hstr_dnn.m_get_ptr());

    bo_ret = adsc_wsp_helper->m_cb_ldap_request ( &dsl_ldap );
    if ( bo_ret == false
        || dsl_ldap.iec_ldap_resp != ied_ldap_success ) {
		if ((bo_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %s.", dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %.*s.", dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        ahstr_err_msg->m_set("HEALDE683E: Copying of data failed; the attribute is not single-valued.");
        return 9;
    }

    return 0;
}

// similar to LDAPSet.hlGenSearch()
int ds_ea_ldap::m_search(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg)
{
    // Search string
    ds_hstring hstr_search = adsl_xml->m_read_string(ads_pnode, TAG_RNN, (int)strlen(TAG_RNN), "", 0);
    if (hstr_search.m_get_len() == 0) {
        ahstr_err_msg->m_set("HEALDE682E: Missing parameter: Search string.");
        return 1;
    }
	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_search in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_search.m_get_ptr(),	hstr_search.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_search.m_reset();
		hstr_search.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // DN, where to start the search
    ds_hstring hstr_dn_start = adsl_xml->m_read_string(ads_pnode, TAG_RCN, (int)strlen(TAG_RCN), "", 0);
    if (hstr_dn_start.m_get_len() == 0) {
        ahstr_err_msg->m_set("HEALDE681E: Missing parameter: DN, where to start search.");
        return 2;
    }
	//convert in utf-8

	//==== hstr_dn_start in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dn_start.m_get_ptr(),	hstr_dn_start.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dn_start.m_reset();
		hstr_dn_start.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // Ticket[8563]: if there is no attribute specified (e.g. sSearchString is 'mayer')
    // then we put the user-prefix in front, leading to cn=mayer
    if (hstr_search.m_search("=") == -1) {
        hstr_search.m_insert_const_str(0, "=");
        hstr_search.m_insert_const_str(0, hstrc_ldap_userprefix.m_const_str());
    }

    // This code is copied from LDAPSet, where it was implemented by AW -> JF does not know the reason for it
    if (hstr_dn_start.m_ends_with(",.")) {
        ds_hstring hstr = hstr_dn_start.m_substr(0, hstr_dn_start.m_get_len() - 2);
        hstr_dn_start = hstr;
    }

    // Search scope
    bool bo_subtree_scope = adsl_xml->m_read_bool(ads_pnode, TAG_RID, (int)strlen(TAG_RID), true);

    // get all attributes of the source item
    ds_hvector<ds_attribute_string> dsl_v_attributes(adsc_wsp_helper);
    ds_hstring hstr_attrname(adsc_wsp_helper, "objectclass");
    ds_hstring hstr_filter(adsc_wsp_helper, "");
    hstr_filter.m_writef("(%.*s)", hstr_search.m_get_len(), hstr_search.m_get_ptr());
    int inl_ret = dsc_ldap.m_read_attributes(&hstr_attrname, &hstr_filter, &hstr_dn_start, (bo_subtree_scope?ied_sear_sublevel:ied_sear_onelevel), &dsl_v_attributes);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE438E: m_read_attributes() failed with error %d.", inl_ret);
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        return 3;
    }

    // Loop over all objects
    if (dsl_v_attributes.m_size()== 0) {
        return SUCCESS; // there is nothing to copy/move -> we are done
    }

    // Create response-xml-PNode
    // Format:  <?xml version=\"1.0\" encoding=\"UTF-8\"?>
    //        <__.>
    //            <xml>Y</xml>      // JF 16.04.10
    //            <dn0>dou=Testgruppe,dc=hobadstest,dc=de</dn0>
    //            <dn1>ucn=as170,dc=hobadstest,dc=de</dn1>
    //        </__.> 

    ds_xml       dsc_xml;                   // xml class (for xml to string)
    dsc_xml.m_init(adsc_wsp_helper);

    // Attention: Because pointers get lost/are overwritten when going thru the items in the vector, we must do the writing to
    // the output in several steps. Then the problem arises that the node 'gettree', is closed much prior than expected. Therefore we write
    // the node '__.' by hand.

    // create tag for doctype
    const char* ach_tag = "?xml";
    dsd_xml_tag* adsl_tag_doctype = dsc_xml.m_create_tag( ach_tag, (int)strlen(ach_tag), ied_xmltype );
    dsc_xml.m_add_attr(adsl_tag_doctype, "version", (int)strlen("version"), "\"1.0\"", (int)strlen("\"1.0\"") );
    dsc_xml.m_add_attr(adsl_tag_doctype, "encoding", (int)strlen("encoding"), "\"UTF-8\"", (int)strlen("\"UTF-8\"") );
    dsc_xml.m_to_xml(adsl_tag_doctype, ahstr_resp);

    // create main tag '__.' ->  write opening node '__.' by hand
    ahstr_resp->m_write("<__.>");
    // JF 16.04.10: write a tag, which signals EA Admin, that the answer is xml-formatted
    ahstr_resp->m_write("<xml>Y</xml>");

    int in_pos = 0;
    for (HVECTOR_FOREACH(ds_attribute_string, adsl_cur, dsl_v_attributes)) {
        const ds_attribute_string& dsl_attr = HVECTOR_GET(adsl_cur);
        // Determine the HOB-class-character (e.g. u for an user)
        char ch_hoboc = dsc_ldap.m_get_oc_id(&dsl_attr);

        // create tag 'dn{count}'
        dsc_xml.m_clear(); // clear the xml
        ds_hstring hstr_dn_counter(adsc_wsp_helper, "dn");
        hstr_dn_counter += in_pos;
        dsd_xml_tag* adsl_tag_dn = dsc_xml.m_create_tag(hstr_dn_counter.m_get_ptr(), hstr_dn_counter.m_get_len(), ied_tag);
        ds_hstring hstr_type_dn(adsc_wsp_helper, &ch_hoboc, 1);
        hstr_type_dn += dsl_attr.m_get_dn();
        dsc_xml.m_add_value(adsl_tag_dn, hstr_type_dn.m_get_ptr(), hstr_type_dn.m_get_len());

        dsc_xml.m_to_xml( adsl_tag_dn, ahstr_resp );
        in_pos++;
    }

    // write closing node '__.' by hand
    ahstr_resp->m_write("</__.>");

    return SUCCESS;
}


// similar to LDAPSet.hlGenSearch()
int ds_ea_ldap::m_verify(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg)
{
    ahstr_resp->m_reset();

    // Get user DN.
    ds_hstring hstr_dn = adsl_xml->m_read_string(ads_pnode, TAG_DN, (int)strlen(TAG_DN), "", 0);
    if (hstr_dn.m_get_len() < 1) {
        ahstr_err_msg->m_set("HEALDE630E: Missing parameter: DN.");
        return 1;
    }
	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_dn in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_dn.m_get_ptr(),	hstr_dn.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_dn.m_reset();
		hstr_dn.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    int in_verify_mode = adsl_xml->m_read_int(ads_pnode, TAG_VERIFY, (int)strlen(TAG_VERIFY), HOB_DEF_VERIFY);

    //----------------------------
    // We shall not check the password -> we must start a search to verify, whether the item exists.
    //----------------------------
    if (in_verify_mode == HOB_VERIFY_NOPWD) {
        ds_hstring hstr_dn_resolved(adsc_wsp_helper, "");
        int inl_ret = dsc_ldap.m_lookup(&hstr_dn, &hstr_dn_resolved);
        if (inl_ret != SUCCESS) { // Item not found.
            ahstr_resp->m_write_int(HOB_RET_VERIFY_NOT_FOUND);
            ahstr_err_msg->m_writef("HEALDE743E: m_lookup() failed with error %d.", inl_ret);
            const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
            adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
                ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
                rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        }
        else { // Item exists and no password check is required.
            ahstr_resp->m_write_int(HOB_RET_VERIFY_OK);
        }
        return SUCCESS;  
    }

    //----------------------------
    // We shall not check the password -> we try to bind with user name and deliverd password.
    //----------------------------

    // Read the password from input data.
    ds_hstring hstr_pw_enc = adsl_xml->m_read_string(ads_pnode, TAG_PASSWORD, (int)strlen(TAG_PASSWORD), "", 0);
    if (hstr_pw_enc.m_get_len() < 1) {
        // Ticket[15228]: give an error, when password is empty.
        ahstr_resp->m_write_int(HOB_RET_VERIFY_INVALID_PW);
        ahstr_err_msg->m_set("HEALDE631E: Missing parameter: password.");
        return SUCCESS;
    }

    // The password is encrypted (using the first token of DN!) -> decrypt it.
    // First we must get the first token of the DN
    ds_hstring hstr_first_token(adsc_wsp_helper, "");
    int inl_ret = dsc_ldap.m_get_first_token_of_dn(&hstr_dn, &hstr_first_token);
    if (inl_ret != SUCCESS) {
        ahstr_resp->m_write_int(HOB_RET_VERIFY_INVALID_PW);
        ahstr_err_msg->m_writef("HEALDE744E: m_get_first_token_of_dn() failed with error %d.", inl_ret);
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        return 4;
    }

    ds_hstring hstr_pw_clear(adsc_wsp_helper);
    inl_ret = m_decrypt_password(hstr_pw_enc.m_get_ptr(), hstr_first_token.m_get_ptr(), &hstr_pw_clear);
    if (inl_ret != SUCCESS) {
        ahstr_resp->m_write_int(HOB_RET_VERIFY_INVALID_PW);
        ahstr_err_msg->m_reset();
        ahstr_err_msg->m_writef("HEALDE702E: Password could not be decrypted (%d).", inl_ret);
        return 5;
    }


    // JF 04.03.10: Up to now it is not possible to do a temporary bind on this connection!
    // Idea: 1) Do the temporary connect,
    //       2) recreate the original bind: In case of SearchUser this might be easy. But when we want to bind with our password, I do not know the password here!
    // We must stop here!
    ahstr_resp->m_write_int(HOB_RET_VERIFY_INVALID_PW);
    ahstr_err_msg->m_reset();
    ahstr_err_msg->m_writef("HEALDE807E: Verification is not supported.");
    return 6;


    //return SUCCESS;
}


// We only reflect the input id/dn as ouput dn/id
// No validation of the delivered input is done !!
int ds_ea_ldap::m_dn_id(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, int in_cmd, ds_hstring* ahstr_err_msg)
{
    const char* ach_to_read = TAG_DN;
    if (in_cmd == ien_gen_cmd_dnfromid) {
        ach_to_read = TAG_ID;
    }
    ds_hstring hstr_org = adsl_xml->m_read_string(ads_pnode, ach_to_read, (int)strlen(ach_to_read), "", 0);
    if (hstr_org.m_get_len() == 0) {
        ahstr_err_msg->m_set("HEALDE677E: ");
        ahstr_err_msg->m_write((in_cmd == ien_gen_cmd_dnfromid)
            ? dsd_const_string("No ID specified.") : dsd_const_string("No DN specified."));
        return 1;
    }
	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_org in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_org.m_get_ptr(),	hstr_org.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_org.m_reset();
		hstr_org.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // xml class (for xml to string)
    ds_xml dsc_xml;
    dsc_xml.m_init(adsc_wsp_helper);

    // create tag for doctype
    const char* ach_tag = "?xml";
    dsd_xml_tag* adsl_tag_doctype = dsc_xml.m_create_tag( ach_tag, (int)strlen(ach_tag), ied_xmltype );
    dsc_xml.m_add_attr(adsl_tag_doctype, "version", (int)strlen("version"), "\"1.0\"", (int)strlen("\"1.0\"") );
    dsc_xml.m_add_attr(adsl_tag_doctype, "encoding", (int)strlen("encoding"), "\"UTF-8\"", (int)strlen("\"UTF-8\"") );
    dsc_xml.m_to_xml(adsl_tag_doctype, ahstr_resp);

    // create main tag '__.' (it is 'next' to doctype-tag, therefore use m_add_next)
    ach_tag = TAG_ESCAPED_ROOT;
    dsd_xml_tag* adsl_tag_root = dsc_xml.m_add_next(adsl_tag_doctype, ach_tag, (int)strlen(ach_tag), ied_tag);

    ach_tag = TAG_DN;
    dsd_xml_tag* adsl_tag_dn = dsc_xml.m_add_child(adsl_tag_root, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_dn, hstr_org.m_get_ptr(), hstr_org.m_get_len());

    ach_tag = TAG_ID;
    dsd_xml_tag* adsl_tag_id = dsc_xml.m_add_child(adsl_tag_root, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_id, hstr_org.m_get_ptr(), hstr_org.m_get_len());

    dsc_xml.m_to_xml( adsl_tag_doctype, ahstr_resp );

    return SUCCESS;
}


int ds_ea_ldap::m_gettype(ds_hstring* ahstr_resp, ds_xml* adsl_xml, dsd_xml_tag* ads_pnode, ds_hstring* ahstr_err_msg)
{
    ds_hstring hstr_id = adsl_xml->m_read_string(ads_pnode, TAG_ID, (int)strlen(TAG_ID), "", 0);
    if (hstr_id.m_get_len() == 0) {
        ahstr_err_msg->m_set("HEALDE680E: No ID specified.");
        return 1;
    }
	//convert in utf-8
	char chrl_vxbuffer[1024];
	int iml_vxlen;

	//==== hstr_id in utf-8==========
	memset( chrl_vxbuffer, 0, sizeof( chrl_vxbuffer ) );
	iml_vxlen = m_cpy_vx_vx(	chrl_vxbuffer,			sizeof(chrl_vxbuffer),			ied_chs_utf_8,
							hstr_id.m_get_ptr(),	hstr_id.m_get_len(),	ied_chs_html_1 );
	if ( iml_vxlen > 0 ) {
		hstr_id.m_reset();
		hstr_id.m_write( chrl_vxbuffer, iml_vxlen);		
	}
	//end convert

    // get the objectclasses of this DN
    ds_hvector<ds_attribute_string> dsl_v_objectclass(adsc_wsp_helper);
    ds_hstring hstr_attrname(adsc_wsp_helper, "objectclass");
    ds_hstring hstr_filter(adsc_wsp_helper, "", 0);
    int inl_ret = dsc_ldap.m_read_attributes(&hstr_attrname, &hstr_filter, &hstr_id, ied_sear_baseobject, &dsl_v_objectclass);
    if (inl_ret != SUCCESS) {
        ahstr_err_msg->m_writef("HEALDE437E: m_read_attributes() failed with error %d.", inl_ret);
        const ds_hstring& rdsl_last_err = dsc_ldap.m_get_last_error();
        adsc_wsp_helper->m_logf(ied_sdh_log_error, "%.*s Details: %.*s",
            ahstr_err_msg->m_get_len(), ahstr_err_msg->m_get_ptr(),
            rdsl_last_err.m_get_len(), rdsl_last_err.m_get_ptr());
        return 2;
    }

    if (dsl_v_objectclass.m_size() != 1) {
        ahstr_err_msg->m_set("HEALDE676E: No ID specified.");
        return 3;
    }

    // Determine the type for this item
    const ds_attribute_string& dsl_attr = dsl_v_objectclass.m_get_first();
    // Determine the HOB-class-character (e.g. u for an user)
    char ch_hoboc = dsc_ldap.m_get_oc_id(&dsl_attr);

    // Create response
    // xml class (for xml to string)
    ds_xml dsc_xml;
    dsc_xml.m_init(adsc_wsp_helper);

    // create tag for doctype
    const char* ach_tag = "?xml";
    dsd_xml_tag* adsl_tag_doctype = dsc_xml.m_create_tag( ach_tag, (int)strlen(ach_tag), ied_xmltype );
    dsc_xml.m_add_attr(adsl_tag_doctype, "version", (int)strlen("version"), "\"1.0\"", (int)strlen("\"1.0\"") );
    dsc_xml.m_add_attr(adsl_tag_doctype, "encoding", (int)strlen("encoding"), "\"UTF-8\"", (int)strlen("\"UTF-8\"") );
    dsc_xml.m_to_xml(adsl_tag_doctype, ahstr_resp);

    // create main tag '__.' (it is 'next' to doctype-tag, therefore use m_add_next)
    ach_tag = TAG_ESCAPED_ROOT;
    dsd_xml_tag* adsl_tag_root = dsc_xml.m_add_next(adsl_tag_doctype, ach_tag, (int)strlen(ach_tag), ied_tag);

    ach_tag = TAG_TYPE;
    dsd_xml_tag* adsl_tag_dn = dsc_xml.m_add_child(adsl_tag_root, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_dn, &ch_hoboc, 1);

    ach_tag = TAG_ID;
    dsd_xml_tag* adsl_tag_id = dsc_xml.m_add_child(adsl_tag_root, ach_tag, (int)strlen(ach_tag), ied_tag);
    dsc_xml.m_add_value(adsl_tag_id, hstr_id.m_get_ptr(), hstr_id.m_get_len());

    dsc_xml.m_to_xml( adsl_tag_doctype, ahstr_resp );

    return SUCCESS;
}


// This method does only parts of JAVA PNode.decodeXML!
int ds_ea_ldap::m_decode_xml(ds_hstring* ahstr) {
    if (ahstr == NULL) {
        return 1;
    }
    if (ahstr->m_get_len() == 0) {
        return SUCCESS; // nothing to do
    }

    // The length of the string, on which we are working, can be changed.
    // So we must copy the data to a new string.
    // To avoid internal copying in hstr_ret, we setup to a twice length.
    ds_hstring hstr_tmp(adsc_wsp_helper, ahstr->m_get_len()*2);

    int in_len = ahstr->m_get_len();
    int i = 0;
    char ch;
    while (i < in_len) {
        ch = (*ahstr)[i];

        if (ch >= 0x30) {
            hstr_tmp += ch;
            i++;
            continue;
        }

        // Remove white space
        if ((ch == '\n') || (ch == '\t') || (ch == '\r')) {
            i++;
            continue;
        }

        if (ch == '&') { // is it escape
            int in_semi = ahstr->m_find_first_of(";", true, i);
            if (in_semi == -1) {
                return 2; // Error
            }

            if ((*ahstr)[i+1] != '#') {
                // Example: &lt; will be decoded to <

                ds_hstring hstr_esc = ahstr->m_substr(i+1, in_semi-i-1);
                char ch_escaped = ds_ea_ldap::m_check_escape(&hstr_esc);
                if (ch_escaped == 0) {
                    return 3; // Error
                }
                hstr_tmp += ch_escaped;
                i = in_semi + 1;
                continue;
            }

            // Example: &#x26;
            // Parse the string until the ';' into an integer.
            // The third character signals the radix of the number, which then follows. If this character is x, it is radix 16; all other characters mean radix 10.
            ds_hstring hstr_esc = ahstr->m_substr(i+2, in_semi-i-2);
            if (hstr_esc.m_get_len() < 1) {
                return 4; // Error
            }
            bool bol_radix_16 = false;
            if ( (hstr_esc[0] == 'x') || (hstr_esc[0] == 'X') ) {
                bol_radix_16 = true;
                if (hstr_esc.m_get_len() < 2) {
                    return 5; // Error
                }
                hstr_esc = hstr_esc.m_substr(1);

            }
            int in_val = 0;
            hstr_esc.m_to_int(&in_val, 0, (bol_radix_16?16:10));
            if ((in_val > INVCHAR_ESCAPE) && (in_val < INVCHAR_ESCAPE + 0x20)) {
                in_val -= INVCHAR_ESCAPE;
            }
			ch = ((char) in_val);

            hstr_tmp += ch;
            i = in_semi + 1;
            continue;
        }

        hstr_tmp += ch;
        i++;
        continue;
    }

    // copy data to output-string
    ahstr->m_set(hstr_tmp);

    return SUCCESS;
}


char ds_ea_ldap::m_check_escape(ds_hstring* ahstr) {
    // TODO: Why is "lt" checked case-insensitive???
    if (ahstr->m_equals_ic("lt")) {
		return '<';
	}
    else if (ahstr->m_equals("gt")) {
		return '>';
	}
    else if (ahstr->m_equals("quot")) {
		// TODO: This is wrong!!! - should be '\"';
        return '\'';
	}
    else if (ahstr->m_equals("amp")) {
		return '&';
	}
    else if(ahstr->m_equals("apos")) {
        return '\'';
    }
	return 0;
}


// similar to JAVA PNode.escCharsXML
int ds_ea_ldap::m_esc_chars_xml(ds_hstring* ahstr, bool bo_value) {
    if (ahstr == NULL) {
        return 1;
    }
    if (ahstr->m_get_len() == 0) {
        return SUCCESS; // nothing to do
    }

    char ch;    
    if (bo_value == false) { // it is a tag name
        ch = (*ahstr)[0];
        if  ((ch == '-') || (ch == '.') || ((ch >= '0') && (ch <= '9'))) {    // preceed double underscore for certain chars
            ahstr->m_insert_const_str(0, "__");
        }
    }

    // The length of the string, on which we are working, can be changed.
    // So we must copy the data to a new string.
    // To avoid internal copying in hstr_ret, we setup to a twice length.
    ds_hstring hstr_tmp(adsc_wsp_helper, ahstr->m_get_len()*2);

    for (int i = 0; i < ahstr->m_get_len(); i++) {
        ch = (*ahstr)[i];

        if (ch >= 0x40) {
            hstr_tmp += ch;
            continue;
        }

        if (bo_value) {
            // 
            if (ch < 0x20 && ch >= 0 &&    // HOB Extension for characters lower than < 20
                !(ch == '\t'  ||           // TAB
                  ch == '\n' ||            // \n
                  ch == '\r' ))            // \r (\t,\n and \r are ok in XML. so we sould not change them)
            {    
                hstr_tmp.m_writef("&#x%x;", ((int)ch + INVCHAR_ESCAPE));
                continue;
            }

            switch (ch) {
                case '&':
                    hstr_tmp.m_write("&#x26;");
                    break;
                case '\"':
                    hstr_tmp.m_write("&#x22;");
                    break;
                case '\'':
                    hstr_tmp.m_write("&#x27;");
                    break;
                case '>':
                    hstr_tmp.m_write("&#x3e;");
                    break;
                case '<':
                    hstr_tmp.m_write("&#x3c;");
                    break;
                case '?':
                    hstr_tmp.m_write("&#x3f;");
                    break;

                default:
                    hstr_tmp += ch;
                    break;
            }
            continue;
        }

        // Not a value.
        switch (ch) {
            case ' ':
                hstr_tmp.m_write("_-_20");  //32
                break;
            case '&':
                hstr_tmp.m_write("_-_26");  //38
                break;
            case '\"':
                hstr_tmp.m_write("_-_22");  //34
                break;
            case '\'':
                hstr_tmp.m_write("_-_27");  //39
                break;
            case '>':
                hstr_tmp.m_write("_-_3E");  //62
                break;
            case '<':
                hstr_tmp.m_write("_-_3C");  //60
                break;
            case '#':
                hstr_tmp.m_write("_-_23");  //35
                break;
            case '?':
                hstr_tmp.m_write("_-_3F");
                break;                            
            case '(':
                hstr_tmp.m_write("_-_28");
                break;    
            case ')':
                hstr_tmp.m_write("_-_29");
                break;                            
            default:
                hstr_tmp += ch;
                break;
        }
    }

    // copy data to output-string
    ahstr->m_set(hstr_tmp);

    return SUCCESS;
}


int ds_ea_ldap::m_esc_chars_tree(ds_hstring* ahstr) {
    if (ahstr == NULL) {
        return 1;
    }
    if (ahstr->m_get_len() == 0) {
        return SUCCESS; // nothing to do
    }

    char ch;    
    
    ch = (*ahstr)[0];
    if  ((ch == '-') || (ch == '.') || ((ch >= '0') && (ch <= '9'))) {    // preceed double underscore for certain chars
        ahstr->m_insert_const_str(0, "__");
    }
    

    // The length of the string, on which we are working, can be changed.
    // So we must copy the data to a new string.
    // To avoid internal copying in hstr_ret, we setup to a twice length.
    ds_hstring hstr_tmp(adsc_wsp_helper, ahstr->m_get_len()*2);

    for (int i = 0; i < ahstr->m_get_len(); i++) {
        ch = (*ahstr)[i];

        if (ch >= 0x40) {
            hstr_tmp += ch;
            continue;
        }

        switch (ch) {
            case '&':
                hstr_tmp.m_write("&#x26;");
                break;
            case '\"':
                hstr_tmp.m_write("&#x22;");
                break;
            case '\'':
                hstr_tmp.m_write("&#x27;");
                break;
            case '>':
                hstr_tmp.m_write("&#x3e;");
                break;
            case '<':
                hstr_tmp.m_write("&#x3c;");
                break;
            case '?':
                hstr_tmp.m_write("&#x3f;");
                break;

            default:
                hstr_tmp += ch;
                break;
        }
        continue;
    
    }

    // copy data to output-string
    ahstr->m_set(hstr_tmp);

    return SUCCESS;
}
/**
 * private function ds_ea_ldap::m_explode_dn
 *
 * @param[in]   const char          *achp_dn    ptr to orginal dn
 * @param[in]   int                 inp_length  length of dn
 * @return      dsd_ldap_attr_desc*             exploded dn
 *                                              null in error cases
*/
struct dsd_ldap_attr_desc* ds_ea_ldap::m_explode_dn( const char *achp_dn, int inp_length )
{
    bool                      bol_ret;          /* return for sev. funcs */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap          = ied_co_ldap_explode_dn;
    dsl_ldap.iec_chs_dn           = ied_chs_utf_8;
    dsl_ldap.imc_len_dn           = inp_length;
    dsl_ldap.ac_dn                = (char*)achp_dn;
    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                 == false
         || dsl_ldap.adsc_attr_desc == NULL
         || dsl_ldap.iec_ldap_resp  != ied_ldap_success ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %s.", dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %.*s.", dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        adsc_wsp_helper->m_logf( ied_sdh_log_error,
                                 "HEALDE671: clone dn failed - cannot explode dn '%.*s'",
                                 inp_length, achp_dn );
        return NULL;
    }
    return dsl_ldap.adsc_attr_desc;
} // end of ds_authenticate::m_explode_dn

/**
 * private function ds_ea_ldap::m_clone_dn
 *  clone a given dn to our configuration ldap
 *
 * @param[in]   dsd_ldap_attr_desc  *adsp_exploded  exploded dn to clone
 * @param[in]   const char          *achp_base      additional base
 * @param[in]   int                 inp_length      length of add. base
 * @return      bool                                true = success
 *                                                  false otherwise
*/

bool ds_ea_ldap::m_clone_dn( struct dsd_ldap_attr_desc *adsp_exploded,
                             const char *achp_base, int inp_length )
{
    bool                      bol_ret;          /* return for sev. funcs */
    struct dsd_co_ldap_1      dsl_ldap;         /* ldap structure        */

    memset( &dsl_ldap, 0, sizeof(struct dsd_co_ldap_1) );
    dsl_ldap.iec_co_ldap          = ied_co_ldap_clone_dn;
    dsl_ldap.adsc_attr_desc       = adsp_exploded;
    dsl_ldap.iec_objectclass      = ied_objectclass_group;
    if ( inp_length > 0 ) {
        dsl_ldap.iec_chs_dn       = ied_chs_utf_8;
        dsl_ldap.imc_len_dn       = inp_length;
        dsl_ldap.ac_dn            = (char*)achp_base;
    }
    dsl_ldap.ac_attrlist          = (char*)"hoboc,hobphone";
    dsl_ldap.imc_len_attrlist     = (int)sizeof("hoboc,hobphone") - 1;
    dsl_ldap.iec_chs_attrlist     = ied_chs_utf_8;

    bol_ret = adsc_wsp_helper->m_cb_ldap_request( &dsl_ldap );
    if (    bol_ret                == false
         || dsl_ldap.iec_ldap_resp != ied_ldap_success ) {
		if ((bol_ret != false) && (dsl_ldap.ac_errmsg != NULL)) {
			if (dsl_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %s.", dsl_ldap.ac_errmsg);
			}
			else {
				adsc_wsp_helper->m_logf( ied_sdh_log_warning, " LDAP message: %.*s.", dsl_ldap.imc_len_errmsg, dsl_ldap.ac_errmsg);
			}
		}
        return false;
    }
    return true;
} // end of ds_authenticate::m_clone_dn
/**
 * private function ds_ea_ldap::m_is_new_subdomain
 *  checks if the a given dn is a subdomain of dc=root
 *  and checks if ldap server is OpenDS
 *  
 *
 * @param[in]   ds_hstring*  hstr_dn         created dn (e.g. "dc=newdomain,dc=root")
 * @param[in]   ds_hstring*  hstr_name       name of the domain (e.g. "newdomain")
 * @return      bool                         true if yes
 *                                           false otherwise
*/
bool ds_ea_ldap::m_is_new_subdomain( ds_hstring* ahstr_dn, ds_hstring* ahstr_name ) {

    int inl_ldap_server;
    int inl_ret;
    ds_hstring hstrl_base         ( adsc_wsp_helper );
    ds_hstring hstrl_check_domain ( adsc_wsp_helper );

    inl_ldap_server = dsc_ldap.m_get_srv_type();
    inl_ret         = dsc_ldap.m_get_base( &hstrl_base );
    hstrl_check_domain.m_writef( "dc=%.*s,%.*s", ahstr_name->m_get_len(), ahstr_name->m_get_ptr(),
                                                 hstrl_base.m_get_len(), hstrl_base.m_get_ptr() );

    if ( (( inl_ldap_server == ied_sys_ldap_opends ) || 
          ( inl_ldap_server == ied_sys_ldap_opendj ) )
        &&  (hstrl_check_domain.m_equals(ahstr_dn->m_get_ptr(), ahstr_dn->m_get_len()) ) ) { //we are under dc=root
        return true;
    }

    return false;
}
/**
 * private function ds_ea_ldap::m_create_dom_admin_group
 *  reads the rdn from the config file and creates the organziation unit
 *  and group
 *
 *
 * @param[in]   ds_hstring*  hstr_dn         created dn (e.g. "dc=newdomain,dc=root")
 * @return      bool bo_ret                  true  creating was successfull
 *                                           false couldn´t create domainadmin group (m_clone_dn failed)
 *
*/
bool ds_ea_ldap::m_create_dadmin_group( ds_hstring* ahstr_dn ) {

    int                         inl_ret;
    bool                        bo_ret;
    struct dsd_ldap_attr_desc   *adsl_rdn; //the exploded dn
    ds_hstring                  dsl_dn      ( adsc_wsp_helper ); //rdn from config
    ds_hstring                  dsl_addbase ( adsc_wsp_helper ); //additional base (without ",dc=root")
    ds_hstring                  hstrl_base  ( adsc_wsp_helper );

    inl_ret = dsc_ldap.m_get_base( &hstrl_base );

    if (  inl_ret != SUCCESS ) {
        return false;
    }

    dsl_dn.m_writef( "%.*s,dc=root", adsc_config->inc_len_dom_admin_rdn, adsc_config->achc_dom_admin_rdn ); //dc=root is just a dummy entry
                                                                                                            //because m_explode_dn ignores the last entry

    dsl_addbase = ahstr_dn->m_substr(0, ahstr_dn->m_get_len() - (hstrl_base.m_get_len() + 1) ); //cut ",dc=root", +1 means don´t forget the comma

    adsl_rdn    = m_explode_dn( dsl_dn.m_get_ptr(), dsl_dn.m_get_len() );
    bo_ret      = m_clone_dn( adsl_rdn, dsl_addbase.m_get_ptr(), dsl_addbase.m_get_len() );

    return bo_ret;
}

/**
 * private function ds_ea_ldap::m_write_aci
 *  write the attribute ACI after creating a new domain
 *
 *
 * @param[in]   ds_hstring*  hstr_dn         created dn where the aci has to be written
 * @return      int                          0 writing was successfull
 *                                           otherwise no success
*/
int ds_ea_ldap::m_write_domain_aci( ds_hstring* hstr_dn ) {

    int inl_ret1;
    int inl_ret2;
    ds_hstring hstr_dom_admin_rdn (adsc_wsp_helper);
    ds_hstring dsl_value_aci (adsc_wsp_helper);

    hstr_dom_admin_rdn.m_set_zeroterm(adsc_config->achc_dom_admin_rdn);
    hstr_dom_admin_rdn = hstr_dom_admin_rdn.m_substr(0, adsc_config->inc_len_dom_admin_rdn); //complete entry of the tag

    //create the first aci
    dsl_value_aci.m_writef("(targetattr=\"*\")(version 3.0; acl \"domainAdministrators\"; allow(all) groupdn=\"ldap:///%.*s,%.*s\";)", 
                        hstr_dom_admin_rdn.m_get_len(), hstr_dom_admin_rdn.m_get_ptr(), hstr_dn->m_get_len(), hstr_dn->m_get_ptr());
                        //the first aci

    dsd_ldap_attr dsl_attr_aci;
    memset(&dsl_attr_aci, 0, sizeof(dsd_ldap_attr));
    dsl_attr_aci.ac_attr             = (char*)"aci";
    dsl_attr_aci.imc_len_attr        = sizeof("aci")-1;
    dsl_attr_aci.iec_chs_attr        = ied_chs_utf_8;
    dsl_attr_aci.dsc_val.ac_val      = const_cast<char*>(dsl_value_aci.m_get_ptr());
    dsl_attr_aci.dsc_val.imc_len_val = dsl_value_aci.m_get_len();
    dsl_attr_aci.dsc_val.iec_chs_val = ied_chs_utf_8;

    inl_ret1 = dsc_ldap.m_write_attributes(hstr_dn, dsl_attr_aci);

    //create the second aci
    dsl_value_aci.m_reset();
    dsl_value_aci.m_writef("(targetattr=\"*\")(version 3.0; acl \"restrictAccess\"; deny(all) userdn!=\"ldap:///%.*s??sub?\" and  groupdn!=\"ldap:///cn=globalAdministrators,ou=groups,dc=internal,dc=root\" and userdn!=\"ldap:/// cn=WebSecureProxy,ou=servers,dc=internal,dc=root\" and userdn!=\"ldap:///self\";)",
                               hstr_dn->m_get_len(), hstr_dn->m_get_ptr());
                            //the second aci
    dsl_attr_aci.dsc_val.ac_val         = const_cast<char*>(dsl_value_aci.m_get_ptr()); //overwrite the first aci
    dsl_attr_aci.dsc_val.imc_len_val    = dsl_value_aci.m_get_len();

    inl_ret2 = dsc_ldap.m_write_attributes(hstr_dn, dsl_attr_aci);

    return inl_ret1 + inl_ret2;
}

/**
 * private function ds_ea_ldap::m_is_attribute_not_allowed
 *  check if given attribute is in our allowed list
 *  use this function to check write access to all ldap attributes
 *
 * @param[in]   const char  *achp_attr      name of attribute to check
 * @param[in]   int         inp_length      length of name
 * @return      bool                        true = allowed
 *                                          false otherwise
*/
bool ds_ea_ldap::m_is_attribute_not_allowed( const char *achp_attr, int inp_length )
{
    for ( HVECTOR_FOREACH(ds_hstring, adsl_cur, dsc_not_allowed_attr) ) {
        const ds_hstring& dsl_cur = HVECTOR_GET(adsl_cur);
        if ( dsl_cur.m_equals( achp_attr, inp_length ) ) {
            return true;
        }
    }
    return false;
} // end of ds_ea_ldap::m_is_attribute_not_allowed


/**
 * function ds_ea_ldap::m_get_mgmt_port
 * reads ip and port from management service file
 *
 * 
 * @param[out]  ds_hstring*     adsp_ineta          ip-adress
 * @param[out]  int*            ainp_port           port
 * @return      bool                                true = got ip/port successfully
 *                                                  false otherwise
 */
bool ds_ea_ldap::m_get_mgmt_port (ds_hstring* adsp_ineta, int* ainp_port) {

    bool                            bol_read_file;
    ds_hstring                      hstrl_port_ip;
    char*                           achl_cur;
    char*                           achl_endptr;
    struct dsd_hl_aux_diskfile_1    ds_file;
    memset ( &ds_file, 0, sizeof(struct dsd_hl_aux_diskfile_1) );

    if ( adsc_config->inc_len_rpath == 0) {
        return false;
    }
    ds_file.ac_name         = (void*)adsc_config->achc_rpath;
    ds_file.inc_len_name    = (int)adsc_config->inc_len_rpath;
    ds_file.iec_chs_name    = ied_chs_utf_8;
    bol_read_file = adsc_wsp_helper->m_cb_file_access ( &ds_file );
    if ( bol_read_file == false ) {
        return false;
    }

    achl_cur = ds_file.adsc_int_df1->achc_filecont_end;

    while (    achl_cur > ds_file.adsc_int_df1->achc_filecont_start
           && *achl_cur!= ':' ) {
        achl_cur--;
    }
    if ( *achl_cur == ':' ) {
        adsp_ineta->m_write( ds_file.adsc_int_df1->achc_filecont_start, 
                            (int) (achl_cur - (ds_file.adsc_int_df1->achc_filecont_start) ) );
    
        *ainp_port  = (int) strtol(achl_cur+1, &achl_endptr, 10);

        adsc_wsp_helper->m_cb_file_release( &ds_file );
        return true;
    } else {
        return false;
    }
}

void ds_ea_ldap::m_send_msg_to_mgmt( ) {
    if ( boc_to_server == true ) {
        /*
            we are connected to mgmt server
            -> send message to it
        */
        adsc_wsp_helper->m_log_input();
        adsc_wsp_helper->m_send_data( "Command: reload \r\n\r\n",
                                      sizeof("Command: reload \r\n\r\n") - 1,
                                      ied_sdh_dd_toserver );
        adsc_wsp_helper->m_log_output();
        boc_to_server = false;
    } else {
        /*
            this point can be just reached, if we are not receiving any
            response from mgmt server. We don't know his state, therefore
            we just close the connection and set callagain.
            -> wsp will call us again in REFLECT mode.
        */
        adsc_wsp_helper->m_cb_tcp_close();
        ((struct dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure())->boc_callagain = TRUE;
    }
}

void ds_ea_ldap::m_recv_msg_from_mgmt() {
    /*
        Receive anwser from mgmt server
          -> check for response code (and give a nice message)
          -> mark input data as read
          -> close tcp connection
    */
    adsc_wsp_helper->m_log_input();

    if ( boc_to_server == false ) {
        /*
            message might be incomplete!
            message should be:
                "Response: ok\r\n\r\n"
            => line base protocol
               -> wait until a line is terminated (i.e. with "\n")
               -> read the line (if starting with "Response" everything is fine ...)
               -> empty line (\n) is eof sign!
        */
        struct dsd_gather_i_1 *adsl_gather;
        struct dsd_gather_i_1 *adsl_temp;
        char                  *achl_cur;
        size_t                uinl_pos = 0;
        adsl_gather = adsc_wsp_helper->m_get_input();

        while ( adsl_gather != NULL ) {
            achl_cur = adsl_gather->achc_ginp_cur;
            while ( achl_cur < adsl_gather->achc_ginp_end ) {
                if ( *achl_cur != chrg_msg_mgmt[uinl_pos] ) {
                    /*
                        unexpected data:
                            -> close tcp connection
                    */
                    /* mark data as processed and return */
                    adsl_gather = adsc_wsp_helper->m_get_input();
                    while ( adsl_gather != NULL ) {
                        adsl_gather->achc_ginp_cur = adsl_gather->achc_ginp_end;
                        adsl_gather = adsl_gather->adsc_next;
                    }
                    adsc_wsp_helper->m_cb_tcp_close();
                    adsc_wsp_helper->m_logf(ied_sdh_log_error, 
                        "HEALDE670: error while receiving response from mgmt server, therefore connection will be closed");
                    return;
                }
                uinl_pos++;
                if ( uinl_pos == sizeof(chrg_msg_mgmt) -1 ) {
                    /*
                        mark data as processed
                        close tcp connection
                        we are ready!
                    */
                    adsl_temp = adsc_wsp_helper->m_get_input();
                    while ( adsl_temp != adsl_gather ) {
                        adsl_temp->achc_ginp_cur = adsl_temp->achc_ginp_end;
                        adsl_temp = adsl_temp->adsc_next;
                    }
                    adsl_gather->achc_ginp_cur = achl_cur;
                    /*
                        mark one more sign!
                    */
                    if ( adsl_gather->achc_ginp_cur < adsl_gather->achc_ginp_end ) {
                        adsl_gather->achc_ginp_cur++;
                    } else {
                        do {
                            adsl_gather = adsl_gather->adsc_next;
                            if (    adsl_gather
                                 && adsl_gather->achc_ginp_cur < adsl_gather->achc_ginp_end ) {
                                adsl_gather->achc_ginp_cur++;
                                break;
                            }
                        } while ( adsl_gather != NULL );

                    }
                    adsc_wsp_helper->m_cb_tcp_close();
                    adsc_wsp_helper->m_log(ied_sdh_log_warning, 
                                    "Response from Management Server is okay, configuration has been reloaded");
                    return;
                }
                achl_cur++;
            }
            adsl_gather = adsl_gather->adsc_next;
        }
        adsc_wsp_helper->m_log_output();
        return;
    }
}

int ds_ea_ldap::m_start_communic_mgmt(  ) {

    struct dsd_aux_tcp_conn_1   ds_tcp;
    memset(&ds_tcp, 0, sizeof(struct dsd_aux_tcp_conn_1));

    ds_hstring adsp_ineta;
    int inp_port;
    bool bo_ret;
    bo_ret = m_get_mgmt_port( &adsp_ineta, &inp_port);
    if (bo_ret) {
        ds_tcp.dsc_aux_tcp_def.ibc_ssl_client = 0;
        ds_tcp.dsc_target_ineta.ac_str        = const_cast<char*>(adsp_ineta.m_get_ptr());
        ds_tcp.dsc_target_ineta.imc_len_str   = adsp_ineta.m_get_len();
        ds_tcp.dsc_target_ineta.iec_chs_str   = ied_chs_utf_8;
        ds_tcp.imc_server_port                = inp_port;
        bo_ret = adsc_wsp_helper->m_cb_tcp_connect(&ds_tcp);
        if ( bo_ret == true ) {
            adsc_wsp_helper->m_logf(ied_sdh_log_warning, "Connection to Management Server: %s:%d successful", adsp_ineta.m_get_ptr(), inp_port);
            boc_to_server = true;
            ((struct dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure())->boc_callagain = TRUE;
        } else {
            adsc_wsp_helper->m_logf(ied_sdh_log_warning, "HEALDE668: Could not connect to Management Server: %s:%d", adsp_ineta.m_get_ptr(), inp_port );
            return 1;
        }
        return 0;
    } else {
        adsc_wsp_helper->m_logf (ied_sdh_log_warning, "HEALDE669: could not read the ip or port from management file" );
        return 1;    
    }
}

/**Write one or more attributes to a DN. Attention: As agreed with E.Galea, we write only one attribute at a time!!
 *<br>This method centralizes the writing and therefore allows checkings at a certain single place.
 * @param[in] ahstr_dn DN of the item, where to write.
 * @param[in] dsl_attr_chain Chain of attributes to be stored at the DN.
 * @param[in] bo_delete true, if this attribute shall be deleted (Attention: only an attribute can be deleted at a time).
 * @param[out] ahstr_err_msg A certain error message is written into.
 * @return 0 if successful. In case of error an explicit error number is returned.
 */
int ds_ea_ldap::m_write_attributes(ds_hstring* ahstr_dn, dsd_ldap_attr dsl_attr_chain,
                                    bool bo_delete, ds_hstring* ahstr_err_msg) {
    //inception AK
    //we just have to check the writing rights in the present case; for the case (auth ldap == conf ldap) ldap is regulating everything
    if ( boc_auth_equals_config_ldap == false) { //auth ldap != conf ldap
        bool bo_user_in_admin_group;
        dsc_ldap.m_is_member( hstrc_real_user_dn.m_get_ptr(), hstrc_real_user_dn.m_get_len(),
                              adsc_domain->achc_admin_group, adsc_domain->inc_len_admin_group, 
                              &bo_user_in_admin_group);

        if (    !ahstr_dn->m_equals_ic(hstrc_real_user_dn)
             && (bo_user_in_admin_group == false)) { //in that case a user wants to write not his own attributes
                                                     //and is also not in the admin group
            ahstr_err_msg->m_writef ( "HEALDE688: User is not allowed to write attributes from %.*s",
                ahstr_dn->m_get_len(), ahstr_dn->m_get_ptr() );
            return WRITING_BLOCKED_NO_DOMAIN_ADMIN;
        }
        bool bo_attr_is_not_allowed = m_is_attribute_not_allowed(dsl_attr_chain.ac_attr, dsl_attr_chain.imc_len_attr );
        if ( bo_attr_is_not_allowed == true ) { //user is not allowed to write this attribute
            ahstr_err_msg->m_writef("HEALDE689: User is not allowed to write the attribute %.*s",
                dsl_attr_chain.imc_len_attr, dsl_attr_chain.ac_attr);
            return WRITING_BLOCKED_NO_ATTR;
        }
    } //if auth ldap != conf ldap and we did return so far, then an user wants to write his own attributes where is allowed to do that
    //end AK

    // JF: The attribute "aci" must NEVER been written, otherwisea user could change his state (e.g. "all is allowed for me").
    ds_hstring hstr_aci(adsc_wsp_helper, "aci");
    if (hstr_aci.m_equals_ic(dsl_attr_chain.ac_attr, dsl_attr_chain.imc_len_attr)) {
        ahstr_err_msg->m_write("HEALDE658E: Writing of attribute 'aci' was blocked.");
        return WRITING_BLOCKED_ACI;
    }
    int inl_ret = dsc_ldap.m_write_attributes(ahstr_dn, dsl_attr_chain);
    if (inl_ret != SUCCESS) {
        // JF 26.11.10 If we want to delete an attribute, which does not exist, LDAP responds a NoSuchAttributeError. Ignore it and go on.
        if (bo_delete) {
            adsc_wsp_helper->m_logf(ied_sdh_log_info, "HEALDI475I: m_write_attributes() failed: Could not delete non-existing attribute. Details: %s",
                                                     dsc_ldap.m_get_last_error().m_get_ptr());
            //inception AK
            //if sb. wants to delete an attribute without the essential rights, we have to output an error message
            ahstr_err_msg->m_writef("HEALDE777E: m_write_attributes() failed with error %d for attribute %.*s of user %.*s.",
                inl_ret, dsl_attr_chain.imc_len_attr, dsl_attr_chain.ac_attr, ahstr_dn->m_get_len(), ahstr_dn->m_get_ptr());
            return WRITING_BLOCKED_NO_ATTR;
            //end AK
            //AK  return SUCCESS;
        }

        ahstr_err_msg->m_writef("HEALDE747E: m_write_attributes() failed with error %d for attribute %.*s of user %.*s. ", inl_ret,
            dsl_attr_chain.imc_len_attr, dsl_attr_chain.ac_attr, ahstr_dn->m_get_len(), ahstr_dn->m_get_ptr());
        return inl_ret;
    }
    /*
           check if one attribute in list (!) is "hobgwwsp"
           and dn is search user of ldap
           if false -> do nothing!
           if true  -> start communication with 
                       managementservice

    */
    //inception AK

    /** Managment Service is doing this by hisself - so the communication between
        EA LDAP and Management Service is obsolete **/

    /**ds_hstring hstr_hobgwwsp(adsc_wsp_helper, "hobgwwsp");

    if (   ( hstr_hobgwwsp.m_equals( dsl_attr_chain.ac_attr, dsl_attr_chain.imc_len_attr, true ) ) 
        && ( hstrc_ldap_searchuser.m_equals(ahstr_dn->m_get_ptr(), ahstr_dn->m_get_len(), true)) ) {
        inl_ret = m_start_communic_mgmt();
        if ( inl_ret != 0) {
            adsc_wsp_helper->m_logf(ied_sdh_log_error, "HEALDE667: Unable to reload WSP configuration ");
        }
    }
    //end AK*/

    return SUCCESS;
}
