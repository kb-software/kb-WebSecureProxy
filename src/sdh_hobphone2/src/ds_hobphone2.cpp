#include <time.h>
#include <rdvpn_globals.h>
#include <ds_ldap.h>
#include <ds_wsp_helper.h>
#include <ds_attribute_string.h>
#include <ds_hstring.h>
#include <ds_hashtable.h>
#include <ds_xml.h>
#include "ds_hobphone2.h"
#include "sdh_hobphone2.h"
#include <ds_usercma.h>
#include <ds_authenticate.h>
#include <ds_wsp_admin.h>
#ifndef HOB_XSLUNIC1_H
	#define HOB_XSLUNIC1_H
	#include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
#ifndef _HOB_XSCLIB01_H
#define _HOB_XSCLIB01_H
#include <hob-xsclib01.h>
#endif

#include <hob-tab-ascii-ansi-1.h>
#include <hob-tab-mime-base64.h>

#ifdef DUMP
#include <fstream>
#include <sstream>
#endif

//#define DEBUGTRACE
//#define NOTIMEOUT   



#if defined WIN32 || defined WIN64
#include <windows.h>
#include <direct.h>
#ifdef DEBUGTRACE
#include <stdio.h>
#endif
#else
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>
#endif

#ifdef DEBUGTRACE


struct dsd_sdh_call_1 {                     /* structure call in SDH   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

/** subroutine for output to console                                   */
static int m_sdh_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512] = "HOBPHONE - ";

   va_start( dsl_argptr, achptext );
  // iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   iml1 = vsnprintf_s( &chrl_out1[11], sizeof(chrl_out1)-11,_TRUNCATE, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1+11 );
   return iml1;
} /* end m_sdh_printf()                                                */
#endif

/* ds_gather_iterator*/
ds_gather_iterator::ds_gather_iterator(dsd_gather_i_1 *adsp_gather, int imp_max_length) 
: ads_anchor(adsp_gather), ads_current(ads_anchor), im_max_length(imp_max_length),
im_remaining(imp_max_length), ach_last(NULL){
    if (ads_anchor != NULL) {
        ach_current = ads_current->achc_ginp_cur;
    }
    else
    {
        ach_current = NULL;
    }
}

dsd_gather_i_1 * ds_gather_iterator::m_duplicate(ds_wsp_helper * const adsp_wsp_helper) {
    // assertions
    if (im_max_length == 0) {
        return NULL;
    }
    if (adsp_wsp_helper == NULL) {
        return NULL;
    }
    // the actual gather in the original chain
    dsd_gather_i_1 *ads_loop = ads_anchor;
    // the first gather in the duplicate chain
    dsd_gather_i_1 *ads_return = NULL;
    // the actual gather in the duplicate chain
    dsd_gather_i_1 *ads_gather = NULL;
    // the previous gather in the duplicate chain or NULL
    dsd_gather_i_1 *ads_last = NULL;
    // the number of characters to read
    int im_max_chars = im_max_length;
    do {
        // if the gather is empty continue with the next
        if (ads_loop->achc_ginp_cur != ads_loop->achc_ginp_end) {
            // create a new gather duplicate
            ads_gather = reinterpret_cast<dsd_gather_i_1 *>(adsp_wsp_helper->m_cb_get_memory(sizeof(dsd_gather_i_1), FALSE));
            // copy the beginning of the gather to the duplicate
            ads_gather->achc_ginp_cur = ads_loop->achc_ginp_cur;
            // calculate the length of the gather's content
            int im_gather_length = ads_loop->achc_ginp_end - ads_loop->achc_ginp_cur;
            // if all content should be duplicated
            if (im_gather_length <= im_max_chars) {
                // copy the end of the gather to the duplicate
                ads_gather->achc_ginp_end = ads_loop->achc_ginp_end;
            }
            // only a part should be duplicated
            else {
                // copy the remaining elements
                ads_gather->achc_ginp_end = ads_loop->achc_ginp_cur + im_max_chars;
            }
            // recalculate the remaining characters
            im_max_chars -= im_gather_length;
            // if there was a previous duplicate link the actual duplicate
            if (ads_last) {
                ads_last->adsc_next = ads_gather;
            }
            // if no previous this becomes the first
            else {
                ads_return = ads_gather;
            }
            // now this is the previous
            ads_last = ads_gather;
        }
        // get the next element in the chain
        ads_loop = ads_loop->adsc_next;
        // loop until no more elements
    } while (ads_loop);
    // the last element has NULL as next
    if (ads_gather)
        ads_gather->adsc_next = NULL;
    // return the first element of the duplicate chain
    return ads_return;
}

char * ds_gather_iterator::m_next() {
    // has more will point to the next valid character
    if (m_has_more()) {
        --im_remaining;
        ach_last = ach_current;
        return ach_current++;
    }
    return NULL;
}

char * ds_gather_iterator::m_recall() {
    return ach_last;
}

BOOL ds_gather_iterator::m_has_more() {
    if (im_remaining == 0) {
        return FALSE;
    }
    if (ads_current == NULL) {
        return FALSE;
    }
    // if the current pointer is less than the beginning or more than the end it was modified - return FALSE and set all other parameters
    if ( ach_current < ads_current->achc_ginp_cur || ads_current->achc_ginp_end < ach_current) {
        im_remaining = 0;
        im_max_length = 0;
        return FALSE;
    }
    // loop until we are sure
    // if we are at the end look for another one
    while (ach_current >= ads_current->achc_ginp_end) {
        // if we have no more gathers
        if (ads_current->adsc_next == NULL) {
            return FALSE;
        }
        // set the next active
        ads_current = ads_current->adsc_next;
        ach_current = ads_current->achc_ginp_cur;
    }
    return TRUE;
}

void ds_gather_iterator::m_mark_used() {
    // get the anchor
    dsd_gather_i_1 *adsl_current = ads_anchor;
    // go to the current
    while (adsl_current != ads_current) {
        // set the beginning to the end - mark as used
        adsl_current->achc_ginp_cur = adsl_current->achc_ginp_end;
        // get the next gather
        adsl_current = adsl_current->adsc_next;
    }
    // the beginning of the gather is set to the current char
    adsl_current->achc_ginp_cur = ach_current;
    // set the maximum length readable
    im_max_length = im_remaining;
}

void ds_gather_iterator::m_reset() {
    // set the remaining back to the maximum readable
    im_remaining = im_max_length;
    // the anchor is the current gather
    ads_current = ads_anchor;
    // the current char is the beginning of the current gather
    ach_current = ads_current->achc_ginp_cur;
    // the last character is set to NULL
    ach_last = NULL;
}

void ds_gather_iterator::m_split(dsd_gather_i_1 *adsp_return) {
    // clear the return gather
    memset(adsp_return, 0, sizeof(dsd_gather_i_1));
    // build an iterator using the anchor and the maximum length
    ds_gather_iterator ds_it(ads_anchor, im_max_length);
    // initialize
    ds_it.m_has_more();
    // skip the valid length for the first chain
    for (int im_i = 0; im_i < im_max_length; ++im_i) {
        ds_it.m_next();
    }
    // now we are at the last valid gather pointing to the first invalid char
    // get the gather
    dsd_gather_i_1 *ads_current = ds_it.ads_current;
    // get the char
    char *ach_current = ds_it.ach_current;
    // are we at the end of the gather?
    if (ach_current == ads_current->achc_ginp_end) {
        // do we have another gather?
        if (ads_current->adsc_next == NULL) {
            // if not we are done
            return;
        }
        // we have more data, so we have to attach
        // our result points to the next
        adsp_return->adsc_next = ads_current->adsc_next;
        // and we clear the next pointer
        ads_current->adsc_next = NULL;
        // we can point to NULL as we are at the gather border
        adsp_return->achc_ginp_cur = NULL;
        adsp_return->achc_ginp_end = NULL;
        return;
    }
    // we have to split
    adsp_return->adsc_next = ads_current->adsc_next;
    adsp_return->achc_ginp_cur = ach_current;
    adsp_return->achc_ginp_end = ads_current->achc_ginp_end;
    // terminate the old gather
    ads_current->achc_ginp_end = ach_current;
    ads_current->adsc_next = NULL;
}

dsd_gather_i_1 *ds_gather_iterator::m_get_current_gather() {
    return ads_current;
}

int ds_gather_iterator::m_get_remaining_length() {
    return im_remaining;
}

void ds_gather_iterator::m_get_line(ds_hstring &hstrp_line) {
    char *ach_char = NULL;
    char *ach_last_char = NULL;
    // continue for all chars in the iterator
    while (m_has_more()) {
        // keep the last character (we look for cr/lf so we have to compare both
        ach_last_char = ach_char;
        // get the next
        ach_char = m_next();
        // if both are valid and hit cr/lf mark the data and return
        if (ach_char != NULL && ach_last_char != NULL && *ach_last_char == 0xd && *ach_char == 0xa) {
            m_mark_used();
            return;
        }
        // if the last char is valid and cr we have to add it to the result
        // (at this point we did not hit cr/lf so we have to add cr)
        if (ach_last_char != NULL && *ach_last_char == 0xd) {
            hstrp_line.m_write(ach_last_char, 1);
        }
        // add every char except cr
        if (ach_char != NULL && *ach_char != 0xd) {
            hstrp_line.m_write(ach_char, 1);
        }
    }
    // the last character might be cr so we have to add it
    if (ach_char != NULL && *ach_char == 0xd) {
        hstrp_line.m_write(ach_char, 1);
    }
    // we reached the end, so mark and return
    m_mark_used();
}

void ds_gather_iterator::m_get_line_nomark(ds_hstring &hstrp_line) {
    char *ach_char = NULL;
    char *ach_last_char = NULL;
    // continue for all chars in the iterator
    while (m_has_more()) {
        // keep the last character (we look for cr/lf so we have to compare both
        ach_last_char = ach_char;
        // get the next
        ach_char = m_next();
        // if both are valid and hit cr/lf mark the data and return
        if (ach_char != NULL && ach_last_char != NULL && *ach_last_char == 0xd && *ach_char == 0xa) {
            //m_mark_used();
            return;
        }
        // if the last char is valid and cr we have to add it to the result
        // (at this point we did not hit cr/lf so we have to add cr)
        if (ach_last_char != NULL && *ach_last_char == 0xd) {
            hstrp_line.m_write(ach_last_char, 1);
        }
        // add every char except cr
        if (ach_char != NULL && *ach_char != 0xd) {
            hstrp_line.m_write(ach_char, 1);
        }
    }
    // the last character might be cr so we have to add it
    if (ach_char != NULL && *ach_char == 0xd) {
        hstrp_line.m_write(ach_char, 1);
    }
    // we reached the end, so mark and return
    //m_mark_used();
}
/* ds_gather_iterator */

/* ds_pbx_entry */
ds_pbx_entry::ds_pbx_entry(ds_wsp_helper *adsp_wsp_helper) 
: ads_wsp_helper(adsp_wsp_helper), ach_name(NULL), im_name_len(0), ach_comment(NULL),
im_comment_len(0), ach_pbx_ineta(NULL), im_pbx_ineta_len(0), ach_pbx_port(NULL), 
im_pbx_port_len(0), ach_proxy_ineta(NULL), im_proxy_ineta_len(0), ach_proxy_port(NULL), 
im_proxy_port_len(0), im_max_sessions(0), ach_protocolid(NULL), im_protocolid_len(0),
ach_protocolname(NULL), im_protocolname_len(0), ach_udp_gw_name(NULL), im_udp_gw_name_len(0) {
}

ds_pbx_entry::~ds_pbx_entry() {
    // when the entry is terminated the associated memory has to be freed
    ads_wsp_helper->m_cb_free_memory(ach_name, im_name_len);
    ads_wsp_helper->m_cb_free_memory(ach_comment, im_comment_len);
    ads_wsp_helper->m_cb_free_memory(ach_pbx_ineta, im_pbx_ineta_len);
    ads_wsp_helper->m_cb_free_memory(ach_pbx_port, im_pbx_port_len);
    ads_wsp_helper->m_cb_free_memory(ach_proxy_ineta, im_proxy_ineta_len);
    ads_wsp_helper->m_cb_free_memory(ach_proxy_port, im_proxy_port_len);
	ads_wsp_helper->m_cb_free_memory(ach_protocolid, im_protocolid_len);
    ads_wsp_helper->m_cb_free_memory(ach_protocolname, im_protocolname_len);
    ads_wsp_helper->m_cb_free_memory(ach_udp_gw_name, im_udp_gw_name_len);
}

const char * ds_pbx_entry::m_get_name() {
    return ach_name;
}

int ds_pbx_entry::m_get_name_len() {
    return im_name_len;
}

const char * ds_pbx_entry::m_get_pbx_ineta() {
    return ach_pbx_ineta;
}

int ds_pbx_entry::m_get_pbx_ineta_len() {
    return im_pbx_ineta_len;
}
const char * ds_pbx_entry::m_get_pbx_port() {
    return ach_pbx_port;
}

int ds_pbx_entry::m_get_pbx_port_len() {
    return im_pbx_port_len;
}

const char * ds_pbx_entry::m_get_proxy_ineta() {
    return ach_proxy_ineta;
}

int ds_pbx_entry::m_get_proxy_ineta_len() {
    return im_proxy_ineta_len;
}
const char * ds_pbx_entry::m_get_proxy_port() {
    return ach_proxy_port;
}

int ds_pbx_entry::m_get_proxy_port_len() {
    return im_proxy_port_len;
}

const char * ds_pbx_entry::m_get_protocolid() {
    return ach_protocolid;
}

int ds_pbx_entry::m_get_protocolid_len() {
    return im_protocolid_len;
}

const char * ds_pbx_entry::m_get_protocolname() {
    return ach_protocolname;
}

int ds_pbx_entry::m_get_protocolname_len() {
    return im_protocolname_len;
}


const char * ds_pbx_entry::m_get_udp_gw_name() {
    return ach_udp_gw_name;
}

int ds_pbx_entry::m_get_udp_gw_name_len() {
    return im_udp_gw_name_len;
}

void ds_pbx_entry::m_replace(char **aachp_target, int *aimp_target_len, const char * const achp_text, int imp_len) {
    // if the pointer is existing the old value has to be freed
    if (*aachp_target != NULL) {
        ads_wsp_helper->m_cb_free_memory(*aachp_target, *aimp_target_len);
    }
    // get new memory and set values
    if (imp_len!=0) {
        *aachp_target = ads_wsp_helper->m_cb_get_memory(imp_len, FALSE);
        *aimp_target_len = imp_len;
        memcpy(*aachp_target, achp_text, imp_len);
    }
    else {
        *aachp_target = NULL;
        *aimp_target_len= 0;
    }
}

void ds_pbx_entry::m_set_comment(const char *const achp_comment, int imp_len) {
    m_replace(&ach_comment, &im_comment_len, achp_comment, imp_len);
}

void ds_pbx_entry::m_set_max_sessions(int imp_max_sessions) {
    im_max_sessions = imp_max_sessions;
}

void ds_pbx_entry::m_set_name(const char *const achp_name, int imp_len) {
    m_replace(&ach_name, &im_name_len, achp_name, imp_len);
}

void ds_pbx_entry::m_set_pbx_ineta(const char *const achp_pbx_ineta, int imp_len) {
    m_replace(&ach_pbx_ineta, &im_pbx_ineta_len, achp_pbx_ineta, imp_len);
}

void ds_pbx_entry::m_set_pbx_port(const char *const achp_pbx_port, int imp_len) {
    m_replace(&ach_pbx_port, &im_pbx_port_len, achp_pbx_port, imp_len);
}

void ds_pbx_entry::m_set_proxy_ineta(const char *const achp_proxy_ineta, int imp_len) {
    m_replace(&ach_proxy_ineta, &im_proxy_ineta_len, achp_proxy_ineta, imp_len);
}

void ds_pbx_entry::m_set_proxy_port(const char *const achp_proxy_port, int imp_len) {
    m_replace(&ach_proxy_port, &im_proxy_port_len, achp_proxy_port, imp_len);
}

void ds_pbx_entry::m_set_protocolid(const char * const achp_protocolid, int imp_len) {
    m_replace(&ach_protocolid, &im_protocolid_len, achp_protocolid, imp_len);
}

void ds_pbx_entry::m_set_protocolname(const char * const achp_protocolname, int imp_len) {
    m_replace(&ach_protocolname, &im_protocolname_len, achp_protocolname, imp_len);
}

void ds_pbx_entry::m_set_udp_gw_name(const char *const achp_udp_gw_name, int imp_len) {
    m_replace(&ach_udp_gw_name, &im_udp_gw_name_len, achp_udp_gw_name, imp_len);
}
/* ds_pbx_entry */

/* ds_hobphone2 */
const dsd_const_string ds_hobphone2::astr_protocol_greeting = "HOBJVOIP V01\r\n";
/*const char * const ds_hobphone2::astr_protocol_greeting2 = "HOBJVOIP V02\r\n";
#define IM_GREETING_LEN 11*/
const dsd_const_string ds_hobphone2::astr_greeting_response = "HOB WSP JVOIP V01\r\n";
//const char * const ds_hobphone2::astr_greeting_response2 = "HOB WSP JVOIP V02.06651\r\n";
const dsd_const_string ds_hobphone2::astr_server_version =  "2.2.7449\r\n";
const char * const ds_hobphone2::astr_get_version = "GET VERSION\r\n";
const char * const ds_hobphone2::astr_client_version = "VERSION\r\n";
const char * const ds_hobphone2::astr_save_sdh = "SAVE SDH\r\n";
const char * const ds_hobphone2::astr_get_config = "GET CONFIG\r\n";
const char * const ds_hobphone2::astr_create_channel = "CREATE CHANNEL\r\n";
const char * const ds_hobphone2::astr_set_channel = "SET CHANNEL\r\n";
const char * const ds_hobphone2::astr_remove_channel = "REMOVE CHANNEL\r\n";
const char * const ds_hobphone2::astr_shutdown = "SHUTDOWN\r\n";
const char * const ds_hobphone2::astr_username ="username:";
const char * const ds_hobphone2::astr_channel_type = "channel-type:";
const char * const ds_hobphone2::astr_call_id = "call-id:";
const char * const ds_hobphone2::astr_enable_udp_gate = "ENABLE UDP GATE\r\n";
const char * const ds_hobphone2::astr_enabled_yes = "enable:YES\r\n";
const char * const ds_hobphone2::astr_enabled_no = "enable:NO\r\n";
const char * const ds_hobphone2::astr_srtp_no = "srtp:NO\r\n";


const dsd_const_string ds_hobphone2::astr_protocol_reconnect = "HOBJVOIP SDH RELOAD\r\n";
const char * const ds_hobphone2::astr_reload_response_ok = "HOB WSP JVOIP RELOAD Y\r\n";
const char * const ds_hobphone2::astr_reload_response_fail= "HOB WSP JVOIP RELOAD N\r\n";

const char * const ds_hobphone2::astr_keepalive = "PING\r\n";       
const char * const ds_hobphone2::astr_search_number = "SEARCH NUMBER\r\n";


ds_hobphone2::ds_hobphone2() : ads_wsp_helper(NULL), ads_config(NULL), av_storage(NULL),
ie_state(SDH_HOBPHONE_STATE_GREETING), bo_use_udp_gate(FALSE) {
    // initialize the arrays of the requests
    memset(adsr_sip_requests, 0, sizeof(adsr_sip_requests));
    memset(adsr_udp_requests, 0, sizeof(adsr_udp_requests));
    memset(adsr_udp_subchannels, 0, sizeof(adsr_udp_subchannels));
    memset(&ds_udp_gate, 0, sizeof(dsd_aux_cmd_udp_gate));
    memset(adsc_sipreply, 0, sizeof(adsc_sipreply));

}

ds_hobphone2::~ds_hobphone2() {
    // all sip and udp requests have to be closed
    m_shutdown();
}

void ds_hobphone2::m_shutdown() {
    for (int im_i = 0; im_i < im_max_account_count; ++im_i) {
        m_set_sip_request(im_i, NULL);
    }
    for (int im_i = 0; im_i < im_max_channel_count; ++im_i) {
        m_set_udp_request(im_i, NULL);
    }

    if (bo_use_udp_gate) {
        // return and status are ignored - anyway we shut down
        ds_udp_gate.iec_cmd_ug = ied_cmd_udp_gate_delete;
        ads_wsp_helper->m_cb_udp_gate(&ds_udp_gate);
    }
    // clear the cma fingerprint
    void *avo_data;
    int im_len;
    // get the cma
    if (hstr_cma_name.m_get_len() > 0)
    {
        void *avo_cma = ads_wsp_helper->m_cb_open_cma(hstr_cma_name.m_get_ptr(), hstr_cma_name.m_get_len(), &avo_data, &im_len, TRUE);
        // got it
        if (avo_cma != NULL) {
            // is this instance the owner of the cma
            ds_wsp_admin dsl_admin(ads_wsp_helper);
            int im_comp = memcmp(dsl_admin.m_get_cluster_info()->ds_main.chrc_wsp_fingerprint, avo_data, im_len);
            if (im_comp == 0) {
                // match - clear the data
                memset(avo_data, 0, im_len);
            }
            ads_wsp_helper->m_cb_close_cma(&avo_cma);
        }
    }
}

void ds_hobphone2::m_init(ds_wsp_helper* ads_wsp_helper_in) {
    // keep a reference to the wsp helper
    ads_wsp_helper = ads_wsp_helper_in;
    // initialize ldap component
    ds_ldap_instance.m_init(ads_wsp_helper);
    // initialize xml component
    dsc_xml.m_init(ads_wsp_helper);
    // initialize hashtable containing the pbx entries
    dsc_pbx_table.m_init(ads_wsp_helper);
    // initialize the exception message
    hstr_exception_message.m_init(ads_wsp_helper);
    // initialize the cma name
    hstr_cma_name.m_init(ads_wsp_helper);
    hstrc_config.m_init(ads_wsp_helper);
    hstrc_devid.m_init(ads_wsp_helper);

    /*{
        ds_hashtable<ds_pbx_entry*> dsl_test;
        dsl_test.m_init(ads_wsp_helper);
    }*/


    for (int i = 0; i < im_max_account_count;i++)
    {
        (hstr_sipcontact[i]).m_init(ads_wsp_helper);
    }
} // end of ds_hobphone2::m_init

void ds_hobphone2::m_set_aux( BOOL (* amp_aux) ( void *, int, void *, int ), void* vpp_userfld )
{
    amc_aux = amp_aux;
    vpc_userfld = vpp_userfld;
    //ads_config = (dsd_sdh_config_t*)ads_wsp_helper->m_get_config();
//////    amc_aux(vpc_userfld, DEF_AUX_TIMER1_SET, NULL, ads_config->im_tcp_keepalive);
}

int ds_hobphone2::m_run() {
    // return value
    int iml_ret = SDH_HOBPHONE_RUNSTATE_OK_NODATA;
    // init helper class and config pointer:
    ads_config = (dsd_sdh_config_t*)ads_wsp_helper->m_get_config();
    
    // input gather
    struct dsd_gather_i_1* ads_gather;
    // get the input gather
    ads_gather = ads_wsp_helper->m_get_input();

    

    // get the length of the received data
    int im_length = 0;
    if (ads_gather) {
        im_length = ads_wsp_helper->m_get_gather_len(ads_gather);
        iml_ret = SDH_HOBPHONE_RUNSTATE_OK;
    }


    ds_gather_iterator ds_it(ads_gather, im_length);
    if (m_check_reconnect(ds_it))
    {    
        //if we got a reconnect from the client stop processing and signal to SDH 
        //this instance will be freed and the original instance will take over
#if DEBUG_RECONNECT
        ads_wsp_helper->m_cb_printf_out("HOBPHONE SDH RELOAD: attempting reload, this: %x",this);
#endif          
        if (m_isclientnewer(2,2,1642))
            return SDH_HOBPHONE_RUNSTATE_RELOAD2;
        return SDH_HOBPHONE_RUNSTATE_RELOAD;
    }

//     maybe sip data was received - do not send SIP data while disconnected (but do not discard this data)
    ied_sdh_hobphone_status ie_status = SDH_HOBPHONE_STATUS_OK;

    if (ie_state != SDH_HOBPHONE_STATE_DISCONNECTED)
        /*ied_sdh_hobphone_status*/ ie_status = m_redirect_sip_to_client();  //BUGFIX - return wasn't being checked (but fn always returns OK)

    if (ie_status != SDH_HOBPHONE_STATUS_OK) {
        //m_log_error(ie_status, hstr_exception_message);
        m_send_exception(ie_status, hstr_exception_message);
        return SDH_HOBPHONE_RUNSTATE_ERROR;
    }
    // maybe udp data was received (while disconnected any UDP data can be discarded - done in m_redirect_udp_to_client())
    ie_status = m_redirect_udp_to_client();
    if (ie_status != SDH_HOBPHONE_STATUS_OK) {
        //m_log_error(ie_status, hstr_exception_message);
        m_send_exception(ie_status, hstr_exception_message);
        return SDH_HOBPHONE_RUNSTATE_ERROR;
    }

   

    // proceed according to state
    switch (ie_state) {
        // if in the state of ie_state_greeting check for expected greeting
        case SDH_HOBPHONE_STATE_DISCONNECTED:
         
#if DEBUG_RECONNECT
        ads_wsp_helper->m_cb_printf_out("HOBPHONE SDH RELOAD: SDH state was disconnected, this: %x",this);
#endif
        case SDH_HOBPHONE_STATE_GREETING: 
           {
#if DEBUG_RECONNECT
                ads_wsp_helper->m_cb_printf_out("HOBPHONE SDH RELOAD: SDH state GREETING, this: %x",this);
#endif
                if(im_length > astr_protocol_reconnect.inc_length) //greeting is also allowed since it is shorter than reconnect
                {
                    m_mark_used(ads_gather,im_length);
                }
                // create an iterator with maximum 'received length' iterations
                //ds_gather_iterator ds_it(ads_gather, im_length);			
                // check expected greeting
                if (m_check_greeting(ds_it)) {
                    // if greeting was received reply
                    BOOL bol_send = ads_wsp_helper->m_send_data(astr_greeting_response.strc_ptr, astr_greeting_response.inc_length);
                    // change state
                    if (bol_send)
                    {
                        ie_state = SDH_HOBPHONE_STATE_NORMAL;
#if NO_DEVID
                        iml_ret = SDH_HOBPHONE_RUNSTATE_SAVESDH; //we can save the SDH for reload
#else
                        iml_ret = SDH_HOBPHONE_RUNSTATE_HELLO;
#endif

#if DEBUG_RECONNECT
                        ads_wsp_helper->m_cb_printf_out("HOBPHONE SDH RELOAD: Greeting received, SDH state set to normal, this: %x",this);
#endif
                    }
                }
            }
            // if greeting did not succeed break
            if (ie_state != SDH_HOBPHONE_STATE_NORMAL) {
                // FIXME somehow the amount should be limited - remove old data?
                //m_mark_used(ads_gather,im_length);
                break;
            }
            // remove the greeting from the length - on success the iterator is marked
            im_length -= astr_protocol_greeting.inc_length;

            // ensure session uniqueness
            {
                // get user data
                dsd_sdh_ident_set_1 ds_ident;
                ads_wsp_helper->m_cb_get_ident(&ds_ident);
                ds_usercma dsl_ucma;
                if (!ds_usercma::m_get_usercma( ads_wsp_helper, &dsl_ucma )) {
                    m_update_exception_message(SDH_HOBPHONE_STATUS_NO_USER_CONFIG, __LINE__, NULL);
                    m_send_exception(SDH_HOBPHONE_STATUS_NO_USER_CONFIG, hstr_exception_message, TRUE);
                    return SDH_HOBPHONE_RUNSTATE_ERROR;
                }
                // keep the name of the cma 'domain/username'
                ds_hstring hstr_username = dsl_ucma.m_get_username();
                ds_hstring hstr_domain = dsl_ucma.m_get_userdomain();
                hstr_cma_name += hstr_domain;
                hstr_cma_name.m_write("/");
                hstr_cma_name += hstr_username;
                // get fingerprint
                ds_wsp_admin dsl_wsp_admin(ads_wsp_helper);
                dsd_cluster *ads_cluster = dsl_wsp_admin.m_get_cluster_info();
                void *avo_data;
                int im_length;
                void *avo_cma = ads_wsp_helper->m_cb_open_cma(hstr_cma_name.m_get_ptr(), hstr_cma_name.m_get_len(),                
                    &avo_data, &im_length, TRUE);
                if (avo_cma != NULL) {
                    // cma found             
                    // compare the fingerprints
                    int im_comp;
                    // own server?
                    im_comp = memcmp(avo_data, ads_cluster->ds_main.chrc_wsp_fingerprint, im_length);
                    if (im_comp == 0) {
                        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_ACTIVE_INSTANCE_ON_CLUSTER,__LINE__, NULL);
                        m_send_exception(SDH_HOBPHONE_STATUS_ERROR_ACTIVE_INSTANCE_ON_CLUSTER, hstr_exception_message, TRUE);
                        ads_wsp_helper->m_cb_close_cma(&avo_cma);
                        return SDH_HOBPHONE_RUNSTATE_ERROR;
                    }
                    // other servers in cluster
                    dsd_cluster_remote_01 *ads_remote = ads_cluster->ads_next;
                    while (ads_remote != NULL) {
                        // server still running
                        if (ads_remote->ds_remote.imc_pid != 0) {
                            // identify the server
                            im_comp = memcmp(avo_data, ads_remote->ds_remote.chrc_wsp_fingerprint, im_length);
                            if (im_comp == 0) {
                                m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_ACTIVE_INSTANCE_ON_CLUSTER,__LINE__, NULL);
                                m_send_exception(SDH_HOBPHONE_STATUS_ERROR_ACTIVE_INSTANCE_ON_CLUSTER, hstr_exception_message, TRUE);
                                ads_wsp_helper->m_cb_close_cma(&avo_cma);
                                return SDH_HOBPHONE_RUNSTATE_ERROR;
                            }
                        }
                        ads_remote = ads_remote->ads_next;
                    }
                    // found a cma of a dead server
                    memcpy(avo_data, ads_cluster->ds_main.chrc_wsp_fingerprint, im_length);
                    ads_wsp_helper->m_cb_close_cma(&avo_cma);   
                }
                else {
                    // create a cma
                    BOOL bo_create = ads_wsp_helper->m_cb_create_cma(hstr_cma_name.m_get_ptr(), hstr_cma_name.m_get_len(), 
                        ads_cluster->ds_main.chrc_wsp_fingerprint, DEF_LEN_FINGERPRINT, 0);
                    if (!bo_create) {
                         m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CREATING_CMA,__LINE__, NULL);
                         m_send_exception(SDH_HOBPHONE_STATUS_ERROR_CREATING_CMA, hstr_exception_message, TRUE);
                         return SDH_HOBPHONE_RUNSTATE_ERROR;
                    }
                }

            }
            // FALLTHROUGH
            // the most common case
        case SDH_HOBPHONE_STATE_NORMAL: 
            {
                // maybe the client sent something, so check the data
                while (im_length > 0) {
                    // the length of the nhasn for marking
                    int im_nhasn_length = 0;
                    // the packet length decoded
                    int im_packet_length = 0;
                    // first try to decode the nhasn length
                    ied_sdh_hobphone_status ie_status =
                        m_decode_nhasn(*ads_gather, im_nhasn_length, im_length, im_max_buffer_size, im_packet_length);

                    // if the packet is not complete break
                    if (im_length < im_packet_length) {
                        break;
                    }
                    // if a complete packet was received
                    switch (ie_status)
                    {
                    case SDH_HOBPHONE_STATUS_OK: 
                        {
                            // mark the nhasn length
                            m_mark_used(ads_gather, im_nhasn_length);
                            // create an iterator with the packet length
                            // the channel_type and the channel_id are included in the packet length
                            ds_gather_iterator ds_it(ads_gather, im_packet_length);
                            // get the channel-type
                            ied_sdh_hobphone_channel_type ie_channel_type = m_get_channel_type(ds_it);
                            // process the data according to the channel type
                            switch (ie_channel_type)
                            {
                            case SDH_HOBPHONE_CHANNEL_TYPE_SYSTEM:
                                // process system message like 'get_config' or 'create_channel'
                                ie_status = m_handle_system_message(ds_it);
                                if (ie_status == SDH_HOBPHONE_STATUS_SHUTDOWN)
                                {
                                    iml_ret = SDH_HOBPHONE_RUNSTATE_SHUTDOWN;
                                }
                                else if (ie_status == SDH_HOBPHONE_STATUS_SAVESDH_SAVE)
                                {
#if NO_DEVID
                                    //do nothing
#else
                                    iml_ret = SDH_HOBPHONE_RUNSTATE_SAVESDH;                                
#endif
                                }
                                else if (ie_status == SDH_HOBPHONE_STATUS_INVALID_SYSTEM_MESSAGE)
                                {
                                    //either the client is sending incorrect data or there was an error in the previous message
                                    //discard the client data received so far to attempt recovery
                                    m_mark_used(ads_gather,-1);
                                    m_send_exception(ie_status, hstr_exception_message);
                                    return SDH_HOBPHONE_RUNSTATE_ERROR;
                                }
                                else if (ie_status != SDH_HOBPHONE_STATUS_OK 
                                    && ie_status != SDH_HOBPHONE_STATUS_ERROR_REMOVING_CHANNEL_NO_CHANNEL) {
                                        //m_log_error(ie_status, hstr_exception_message);
                                        m_send_exception(ie_status, hstr_exception_message);
                                        m_mark_used(ads_gather,im_packet_length - 2); //mark the bytes in the packet (minus channel id and type since they are already marked)
                                        return SDH_HOBPHONE_RUNSTATE_ERROR;
                                }

                                break;
                            case SDH_HOBPHONE_CHANNEL_TYPE_UDP_SIP:
                                // a sip message was received                               
                                ie_status = m_redirect_sip_to_pbx(ds_it);
                                if (ie_status != SDH_HOBPHONE_STATUS_OK && ie_status != SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_SIP_TO_PBX_NO_REQUEST) {
                                    //m_log_error(ie_status, hstr_exception_message);
                                    m_send_exception(ie_status, hstr_exception_message);
                                    return SDH_HOBPHONE_RUNSTATE_ERROR;
                                }
                                if (ie_status == SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_SIP_TO_PBX_NO_REQUEST) {
                                    m_log_warning(SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_SIP_TO_PBX_NO_REQUEST, hstr_exception_message);
                                }
                                break;
                            case SDH_HOBPHONE_CHANNEL_TYPE_UDP:
                                // a udp packet was received
                                ie_status = m_redirect_udp_to_pbx(ds_it);
                                if (ie_status != SDH_HOBPHONE_STATUS_OK && ie_status != SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_UDP_TO_PBX_NO_REQUEST) {
                                    //m_log_error(ie_status, hstr_exception_message);
                                    m_send_exception(ie_status, hstr_exception_message);
                                    return SDH_HOBPHONE_RUNSTATE_ERROR;
                                }
                                if (ie_status == SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_UDP_TO_PBX_NO_REQUEST) {
                                    m_log_warning(SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_UDP_TO_PBX_NO_REQUEST, hstr_exception_message);
                                }
                                break;
                            default:
                                // an unknown channel was received - show exception and terminate SDH
                                m_update_exception_message(SDH_HOBPHONE_STATUS_UNKNOWN_CHANNEL_TYPE,__LINE__, ds_it.m_recall(),&im_packet_length);
                                m_mark_used(ads_gather,im_packet_length - 2); //mark the bytes in the packet (minus channel id and type since they are already marked)
                                //m_log_error(SDH_HOBPHONE_STATUS_UNKNOWN_CHANNEL_TYPE, hstr_exception_message);
                                m_send_exception(ie_status, hstr_exception_message, TRUE);
                                return SDH_HOBPHONE_RUNSTATE_ERROR;
                            }
                            // remove the processed data
                            im_length -= (im_packet_length + im_nhasn_length);
                        }
                        break;
                        // we did not receive enough data - wait
                    case SDH_HOBPHONE_STATUS_EMPTY_NHASN:
                        m_log_warning(ie_status, hstr_exception_message);
                        break;
                    case SDH_HOBPHONE_STATUS_INCOMPLETE_NHASN:
                        //m_log_info(ie_status, hstr_exception_message);
                        //XXX MS20121002 - set the length to 0 otherwise we have an infinite loop
                        //
                        //We can get here due to the packet being split into 2: first part only 
                        //contains 1 byte (1st part of NHASN length), the rest is in the
                        //next structure - This is done by java (1.7 update 6 or later) 
                        //on the client to counter plaintext issues in SSLv3/TLS1.0 
                        //see 7064341: jsse/runtime security problem and 
                        //7157903: JSSE client sockets are very slow.
                        //The packet is processed in the next call.
                        im_length=0;                                                                                 
                        break;
                        // invalid data received - disregard
                    case SDH_HOBPHONE_STATUS_NHASN_OUT_OF_RANGE:
                        // mark the whole buffer as used
                        m_mark_used(ads_gather, im_length);
                        //m_log_error(ie_status, hstr_exception_message);
                        m_send_exception(ie_status, hstr_exception_message);
                        break;
                    default:
                        // unknown return value
                        //m_log_error(ie_status, hstr_exception_message);
                        m_send_exception(ie_status, hstr_exception_message);
                        break;
                    }
                }
                // that is all
            }
            break;
        default:
            // unknown state
            //m_log_error(SDH_HOBPHONE_ILLEGAL_STATE, hstr_exception_message);
            m_send_exception(SDH_HOBPHONE_ILLEGAL_STATE, hstr_exception_message, TRUE);
    }
    return iml_ret;
} // end of ds_hobphone::m_run

BOOL ds_hobphone2::m_isclientnewer(int imp_vmaj, int imp_vmin, int imp_rev)
{
    if ((imc_clientversion >> 24) < imp_vmaj)
        return FALSE;
    if ((imc_clientversion >> 16) & 0xFF < imp_vmin)
        return FALSE;
    if ((imc_clientversion & 0xFFFF) < imp_rev)
        return FALSE;

    return TRUE;
}
void ds_hobphone2::m_send_exception(const ied_sdh_hobphone_status iep_status, ds_hstring& hstrp_ex_message, BOOL bop_fatal) {
    m_log_error(iep_status, hstrp_ex_message);
    // create a return string
    ds_hstring hstr_text(ads_wsp_helper);
    hstr_text.m_writef("00EXCEPTION\r\ntag:%u\r\nmessage: ", iep_status);
    hstr_text += hstrp_ex_message;
    hstr_text.m_write("\r\n");
    if (bop_fatal) {
        hstr_text.m_write("fatal:YES\r\n");
    }
    // prepend the length NHASN
    ds_hstring hstr_buffer(ads_wsp_helper);
    hstr_buffer.m_write_nhasn(hstr_text.m_get_len());
    hstr_buffer += hstr_text;
    // send the exception
    BOOL bol_send = ads_wsp_helper->m_send_data(hstr_buffer.m_get_ptr(), hstr_buffer.m_get_len());
    //if we fail to send the exception there is no point trying to send a failure message
    if (!bol_send)
    {
        m_update_exception_message(SDH_HOBPHONE_STATUS_SEND_FAILED, __LINE__, 0);
    }

}

BOOL ds_hobphone2::m_compare(const char* strp_expected, ds_gather_iterator &dsp_it) {
    // assertions
    if (strp_expected == NULL) {
        return FALSE;
    }
    // if the text is empty return TRUE
    if (*strp_expected == 0) {
        return TRUE;
    }
    // if the iterator is empty return FALSE
    if (!dsp_it.m_has_more()) {
        return FALSE;
    }
    // a working copy
    const char *ach_text = strp_expected;
    char *ach_cur = NULL;
    do {
        // get a character character
        ach_cur = dsp_it.m_next();
        // if the text and the character are not equal return FALSE
        if (*ach_text != *ach_cur) {
            break;
        }
        // go to the next text character
        ++ach_text;
        // if the next char is zero we compared everything and can return TRUE
        if (*ach_text == 0) {
            dsp_it.m_mark_used();
            return TRUE;
        }
    } while(dsp_it.m_has_more());
    // did not succeed
    dsp_it.m_reset();
    return FALSE;
}

BOOL ds_hobphone2::m_compare(const char* strp_expected, ds_gather_iterator &dsp_it, int imp_maxlen) {
    // assertions
    if (strp_expected == NULL) {
        return FALSE;
    }
    // if the text is empty return TRUE
    if (*strp_expected == 0) {
        return TRUE;
    }
    // if the iterator is empty return FALSE
    if (!dsp_it.m_has_more()) {
        return FALSE;
    }

    if (imp_maxlen <= 0) {
        return FALSE;
    }
    // a working copy
    const char *ach_text = strp_expected;
    char *ach_cur = NULL;
    do {
        // get a character character
        ach_cur = dsp_it.m_next();
        // if the text and the character are not equal return FALSE
        if (*ach_text != *ach_cur) {
            break;
        }
        // go to the next text character
        ++ach_text;
        // if the next char is zero we compared everything and can return TRUE
        if (*ach_text == 0) {
            dsp_it.m_mark_used();
            return TRUE;
        }
        imp_maxlen--;
    } while(dsp_it.m_has_more() && imp_maxlen > 0);

    if (imp_maxlen == 0) //matched succesfully till maxlen
    {
        dsp_it.m_mark_used();
        return TRUE;
    }
    // did not succeed
    dsp_it.m_reset();
    return FALSE;
}

ied_sdh_hobphone_status ds_hobphone2::m_decode_nhasn(struct dsd_gather_i_1 &dsp_gather,
                                                     int &imp_nhasn_length, int imp_max_length, 
                                                     int imp_max_value, int &imp_ret_length) {
     // if nothing to decode return empty
     if (imp_max_length < 1) {
         imp_nhasn_length = 0;
         imp_ret_length = 0;
         m_update_exception_message(SDH_HOBPHONE_STATUS_EMPTY_NHASN,__LINE__, &imp_max_length);
         return SDH_HOBPHONE_STATUS_EMPTY_NHASN;
     }
     // create an iterator - this is not to be marked!
     ds_gather_iterator ds_it(&dsp_gather, imp_max_length);
     // create a handle for the current pointer
     char* ach_cur;
     // initialize the value
     int im_value = 0;
     // the current nhasn digit in focus
     int im_digit;
     // the length working with
     int im_nhasn_length = 0;
     // do this until error or parsed the last number
     do {
         // if the gather is empty return error
         if (!ds_it.m_has_more()) {
             ds_it.m_reset();
             //m_update_exception_message(SDH_HOBPHONE_STATUS_INCOMPLETE_NHASN,__LINE__, &imp_nhasn_length);
             imp_nhasn_length = 0;
             imp_ret_length = 0;
             return SDH_HOBPHONE_STATUS_INCOMPLETE_NHASN;
         }
         // get the value
         ach_cur = ds_it.m_next();
         // increase the nhasn length;
         ++im_nhasn_length;
         // get the digit
         im_digit = *ach_cur;
         // calculate the new value
         im_value = (im_value << 7) | (im_digit & 0x7f);
         // if max value is set and value is larger than max value we exception
         if (imp_max_value != 0 && im_value >= imp_max_value) {
             imp_ret_length = im_value;
             imp_nhasn_length = 0;
             m_update_exception_message(SDH_HOBPHONE_STATUS_NHASN_OUT_OF_RANGE,__LINE__, &imp_nhasn_length);
             return SDH_HOBPHONE_STATUS_NHASN_OUT_OF_RANGE;
         }
         // loop until the digits msb is not set
     } while ((im_digit & 0x80) != 0);
     // set the return values
     imp_nhasn_length = im_nhasn_length;
     imp_ret_length = im_value;
     return SDH_HOBPHONE_STATUS_OK;
}

void ds_hobphone2::m_add_pbx_entry(const char * const achp_key, int imp_key_len, ds_pbx_entry *adsp_pbx_entry) {
    ds_pbx_entry *ads_local_entry;
    // look for the specified entry
    BOOL bo_found = dsc_pbx_table.m_get(achp_key, imp_key_len, &ads_local_entry);
    // replace any existing value
    dsc_pbx_table.m_add(achp_key, imp_key_len, adsp_pbx_entry);
    // if a value existed free memory
    if (bo_found) {
        // delete can not be used as it tries to free the memory   TODO add error message
        ds_hstring ds_temp(ads_wsp_helper);
        ds_temp.m_writef("Multiple PBX entries with same name %s (previous entry ignored)",achp_key);
        m_log_warning(SDH_HOBPHONE_STATUS_OK,ds_temp);
        ads_local_entry->~ds_pbx_entry();
        ads_wsp_helper->m_cb_free_memory(ads_local_entry, sizeof(ds_pbx_entry));
    }
}

BOOL ds_hobphone2::m_check_greeting(ds_gather_iterator &dsp_it) {
    // assertions
    if (!dsp_it.m_has_more()) {
        return FALSE;
    }
    return m_compare(ds_hobphone2::astr_protocol_greeting.strc_ptr, dsp_it);    
}

BOOL ds_hobphone2::m_check_reconnect(ds_gather_iterator &dsp_it)
{
    if (!dsp_it.m_has_more()) {
        return FALSE;
    }
#if NO_DEVID
    BOOL bol_result = m_compare(ds_hobphone2::astr_protocol_reconnect.strc_ptr, dsp_it);
#else
    BOOL bol_result = m_compare(ds_hobphone2::astr_protocol_reconnect.strc_ptr, dsp_it, ds_hobphone2::astr_protocol_reconnect.inc_length);
    if (bol_result)
    {       
        char* ach_cur = NULL;
        BOOL bo_done = FALSE;
        hstrc_devid.m_reset();
        while(dsp_it.m_has_more() && !bo_done)
        {
            // get a character
            ach_cur = dsp_it.m_next();      
            hstrc_devid += *ach_cur;

            //check for \r\n
            if (*ach_cur == '\r')
            {
                ach_cur = dsp_it.m_next();
                hstrc_devid += *ach_cur;
                if (*ach_cur == '\n')
                {
                    //finish
                    bo_done = TRUE;
                }
            }
        
        };
        dsp_it.m_mark_used();
    }
#endif
    return bol_result;
}

int ds_hobphone2::m_getdevid(const char** aachp_devid)
{
    *aachp_devid = hstrc_devid.m_get_ptr();
    return hstrc_devid.m_get_len();
}

void ds_hobphone2::m_mark_used(struct dsd_gather_i_1 *adsp_gather, const size_t ds_size)
{
    // assertions
    if (adsp_gather == NULL || ds_size == 0) {
        return;
    }
    dsd_gather_i_1 *ads_cur = adsp_gather;
    size_t ds_count = ds_size;
    // loop ds_count times to remove a single character each time
    do {
        // if no characters remaining in gather
        if (ads_cur->achc_ginp_cur == ads_cur->achc_ginp_end) {
            // get the next gather
            if (ads_cur->adsc_next != NULL) {
                ads_cur = ads_cur->adsc_next;
            }
            // if none, return
            else {
                return;
            }
        }
        // move the begin one character up
        else {
            ++ads_cur->achc_ginp_cur;
            --ds_count;
        }
    } while  (ds_count > 0);
}

ied_sdh_hobphone_channel_type ds_hobphone2::m_get_channel_type(ds_gather_iterator &dsp_it) {
    // assertions
    if (!dsp_it.m_has_more()) {
        return SDH_HOBPHONE_CHANNEL_TYPE_UNDEFINED;
    }
    ied_sdh_hobphone_channel_type ie_type;
    switch (*dsp_it.m_next()) {
        // ASCII 0 - system
        case SDH_HOBPHONE_CHAR_CHANNEL_TYPE_SYSTEM:
            ie_type = SDH_HOBPHONE_CHANNEL_TYPE_SYSTEM;
            break;
            // ASCII 1 - udp_sip
        case SDH_HOBPHONE_CHAR_CHANNEL_TYPE_UDP_SIP:
            ie_type = SDH_HOBPHONE_CHANNEL_TYPE_UDP_SIP;
            break;
            // ASCII 2 - udp
        case SDH_HOBPHONE_CHAR_CHANNEL_TYPE_UDP:
            ie_type = SDH_HOBPHONE_CHANNEL_TYPE_UDP;
            break;
            // ASCII 3 - udp direct
        case SDH_HOBPHONE_CHAR_CHANNEL_TYPE_UDP_DIRECT:
            ie_type = SDH_HOBPHONE_CHANNEL_TYPE_UDP_DIRECT;
            break;
        default:
            ie_type = SDH_HOBPHONE_CHANNEL_TYPE_UNDEFINED;
            break;
    }
    dsp_it.m_mark_used();
    return ie_type;
}

char ds_hobphone2::m_get_channel_id(ds_gather_iterator &dsp_it) {
    if (!dsp_it.m_has_more()) {
        return 0;
    }
    char ch_id = *dsp_it.m_next();
    dsp_it.m_mark_used();
    return ch_id;
}

ied_sdh_hobphone_status ds_hobphone2::m_handle_system_message(ds_gather_iterator &dsp_it) {
    // id not needed so skip it
    m_get_channel_id(dsp_it);
    // GET CONFIG
    if (m_compare(astr_get_config, dsp_it)) {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - GET CONFIG");      
#endif
        ied_sdh_hobphone_status ie_status;
        
        BOOL bol_reload = (hstrc_config.m_get_len() > 0) ? TRUE : FALSE;
        if (bol_reload)
        {
            //config was already processed => reload (in this case skip initialising UDP gate
            BOOL bol_ret = ads_wsp_helper->m_send_data(hstrc_config.m_get_ptr(), hstrc_config.m_get_len());
            if (!bol_ret)
            {
                m_update_exception_message(SDH_HOBPHONE_STATUS_SEND_FAILED, __LINE__, 0);
                return SDH_HOBPHONE_STATUS_SEND_FAILED;
            }
            //return SDH_HOBPHONE_STATUS_OK;
        }
        else
        {
            ie_status = m_system_message_get_config();
            if (ie_status != SDH_HOBPHONE_STATUS_OK) {
                return ie_status;
            }
        }
        // this happens only once, so this is the right place to initialize wsp udp - MS 05.2015 - happens on every reload
        ie_status = m_system_initialize_wsp_udp(bol_reload);
        if (ie_status != SDH_HOBPHONE_STATUS_OK && ie_status != SDH_HOBPHONE_STATUS_UDP_GATE_NOT_CONFIGURED) {
            //m_log_error(ie_status, hstr_exception_message);
            m_send_exception(ie_status, hstr_exception_message);
        }
        return SDH_HOBPHONE_STATUS_OK;
    }

    // ENABLE UDP GATE
    else if (m_compare(astr_enable_udp_gate, dsp_it)) {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - ENABLE UDP GATE");      
#endif
        return m_system_message_enable_udp_gate(dsp_it);
    }
    // CREATE CHANNEL
    else if (m_compare(astr_create_channel, dsp_it)) {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - CREATE CHANNEL");      
#endif
        return m_system_message_create_channel(dsp_it);
    }
    // SET CHANNEL
    else if (m_compare(astr_set_channel, dsp_it)) {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - SET CHANNEL");      
#endif
        return m_system_message_set_channel(dsp_it);
    }
    // REMOVE CHANNEL
    else if (m_compare(astr_remove_channel, dsp_it)) {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - REMOVE CHANNEL");      
#endif
        return m_system_message_remove_channel(dsp_it);
    }
    // SHUTDOWN
    else if (m_compare(astr_shutdown, dsp_it)) {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - SHUTDOWN");      
#endif
        //m_shutdown();
        return SDH_HOBPHONE_STATUS_SHUTDOWN;
    }
    else if (m_compare(astr_keepalive, dsp_it)) {
        return m_system_message_keepalive(dsp_it);
    }
    else if (m_compare(astr_search_number, dsp_it)) {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - NUMBER SEARCH");      
#endif
        return m_system_message_search_number(dsp_it);
    }
    else if (m_compare(astr_get_version, dsp_it))
    {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - GET VERSION");      
#endif
        return m_system_message_get_version(dsp_it,false);
    }
    else if (m_compare(astr_client_version, dsp_it))
    {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - GET CVERSION");      
#endif
        return m_system_message_get_version(dsp_it,true);
    }
    else if (m_compare(astr_save_sdh, dsp_it))
    {
#if DEBUG_SYSMSG
        m_log_warning("SDH SYSMSG - SAVE SDH");      
#endif
        return m_system_message_save_sdh(dsp_it);

    }
    m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_SYSTEM_MESSAGE,__LINE__, dsp_it);
    return SDH_HOBPHONE_STATUS_INVALID_SYSTEM_MESSAGE;
}

ied_sdh_hobphone_status ds_hobphone2::m_system_message_get_version(ds_gather_iterator &dsp_it, BOOL bo_clientv)
{
    imc_clientversion = 1503; //earliest version possible if we got the GET VERSION request
    BOOL bol_sendreply = TRUE;
    if (bo_clientv)
    {
        imc_clientversion = 1555; //earliest version possible if we got the VERSION request
        ds_hstring hstr_version(ads_wsp_helper);
        dsp_it.m_get_line(hstr_version);

        const char* achl_version = hstr_version.m_get_ptr();
        const char* achl_vcur = achl_version;
        int iml_vlen = hstr_version.m_get_len();

        int iml_vmaj;
        int iml_vmin;
        int iml_vrev;

        int iml_i = 0;
        for (; iml_i < iml_vlen; iml_i++)
        {
            if (*achl_vcur++ == '.')
            {
                hstr_version.m_to_int(&iml_vmaj,0);
                break;
            }
        }
        for (iml_i++; iml_i < iml_vlen; iml_i++)
        {
            if (*achl_vcur++ == '.')
            {
                hstr_version.m_to_int(&iml_vmin,iml_i-1);
                break;
            }
        }
        
        hstr_version.m_to_int(&iml_vrev,iml_i+1);
        
        if (iml_vmaj > 1 && iml_vmin > 0)
        {                       
            //do not send reply to VERSION unless the client is a newer version that requires this
            //bol_sendreply = FALSE;
            /*if (iml_vmaj > 1 && iml_vmin > 2 && iml_vrev > 0)
                bol_sendreply = TRUE;*/

            //allows version numbers up to 256.256.65535
            imc_clientversion = iml_vmaj << 24 | iml_vmin << 16 | iml_vrev;
        }
        if (imc_clientversion < 1554) 
        {
            //else print error and ignore message
            m_update_exception_message_l(SDH_HOBPHONE_STATUS_VERSION_ERROR, __LINE__,hstr_version.m_get_ptr(),hstr_version.m_get_len());
        }
    }

    if (bol_sendreply)
    {
        ds_hstring hstr_version(ads_wsp_helper);    
        hstr_version.m_write("00VERSION\r\n");
        hstr_version.m_write(astr_server_version);

        ds_hstring hstr_send(ads_wsp_helper);
        hstr_send.m_write_nhasn(hstr_version.m_get_len());
        hstr_send.m_write(hstr_version);

        BOOL bol_send = ads_wsp_helper->m_send_data(hstr_send.m_get_ptr(), hstr_send.m_get_len());
        if (!bol_send)
            return SDH_HOBPHONE_STATUS_VERSION_ERROR;
    }
    return SDH_HOBPHONE_STATUS_OK;
}

ied_sdh_hobphone_status ds_hobphone2::m_system_message_save_sdh(ds_gather_iterator &dsp_it)
{
    char* ach_cur = NULL;
    BOOL bo_done = FALSE;
    hstrc_devid.m_reset();    
    while(dsp_it.m_has_more() && !bo_done) 
    {
        // get a character
        ach_cur = dsp_it.m_next();      
        hstrc_devid += *ach_cur;

        //check for \r\n
        if (*ach_cur == '\r')
        {
            ach_cur = dsp_it.m_next();
            hstrc_devid += *ach_cur;
            if (*ach_cur == '\n')
            {
                //finish
                bo_done = TRUE;
            }
        }

    };
    if (!bo_done)
    {
        return SDH_HOBPHONE_STATUS_SAVESDH_NAMEERROR;
    }
    dsp_it.m_mark_used();
    return SDH_HOBPHONE_STATUS_SAVESDH_SAVE;
}

void ds_hobphone2::m_write_addressbook_config(dsd_sdh_addressbook_config *adsp_addressbook_config,
                                              ds_hstring &hstr_target,
                                              ds_hstring &achp_domainname
                                              ) 
{
    dsd_sdh_addressbook_config* adsl_current_addressbook = adsp_addressbook_config;
    if (achp_domainname.m_get_len() > 0)
    {
        dsd_sdh_addressbook_config* adsl_default_addressbook = NULL;
        BOOL bol_continue = TRUE;
        do
        {
            //is a domain not specified?
            if (adsl_current_addressbook->im_domain_len == 0){
                //if not and this is the first addressbook without a domain set as the default addressbook
                if (adsl_default_addressbook == NULL){ 
                    adsl_default_addressbook = adsl_current_addressbook; 
                }
            }
            else if (achp_domainname.m_equals(adsl_current_addressbook->ach_domain, adsl_current_addressbook->im_domain_len))
            {  
                //domain specified and matches - stop here and use this addressbook
                bol_continue = FALSE;
            }
            if (bol_continue)
            {
                //if the domains did not match check if there is another addressbook config
                if (adsl_current_addressbook->ads_next){                    
                    adsl_current_addressbook = adsl_current_addressbook->ads_next;
                }else{
                    //if no more configurations and we did not find a match:
                    //if a default addressbook was set use that, otherwise use the first addressbook in the chain
                    adsl_current_addressbook = adsl_default_addressbook != NULL ? adsl_default_addressbook : adsp_addressbook_config;
                    bol_continue = FALSE;
                }
            }
        }while(bol_continue);
    }
    // TODO some kind of lookup has to be performed to get the addressbook configuration
    // for now the first configuration from the server config file is used
    if (adsl_current_addressbook->ach_type != NULL && adsl_current_addressbook->im_type_len != 0) {
        hstr_target.m_write("addressbook-type:");
        hstr_target.m_write(adsl_current_addressbook->ach_type, adsl_current_addressbook->im_type_len);
        hstr_target.m_write("\r\n");
    }
    if (adsl_current_addressbook->ach_url != NULL && adsl_current_addressbook->im_url_len!= 0) {
        hstr_target.m_write("addressbook-url:");
        hstr_target.m_write(adsl_current_addressbook->ach_url, adsl_current_addressbook->im_url_len);
        hstr_target.m_write("\r\n");
    }
    if (adsl_current_addressbook->ach_authentication_mode != NULL && adsl_current_addressbook->im_authentication_mode_len != 0) {
        hstr_target.m_write("addressbook-authentication-mode:");
        hstr_target.m_write(adsl_current_addressbook->ach_authentication_mode, adsl_current_addressbook->im_authentication_mode_len);
        hstr_target.m_write("\r\n");
    }
    if (adsl_current_addressbook->ach_username != NULL && adsl_current_addressbook->im_username_len!= 0) {
        hstr_target.m_write("addressbook-username:");
        hstr_target.m_write(adsl_current_addressbook->ach_username, adsl_current_addressbook->im_username_len);
        hstr_target.m_write("\r\n");
    }
    if (adsl_current_addressbook->ach_connection_mode != NULL && adsl_current_addressbook->im_connection_mode_len != 0) {
        hstr_target.m_write("addressbook-connection-mode:");
        hstr_target.m_write(adsl_current_addressbook->ach_connection_mode, ads_config->ads_addressbook_config->im_connection_mode_len);
        hstr_target.m_write("\r\n");
    }
    if (ads_config->ads_addressbook_config->ach_gate_url != NULL && ads_config->ads_addressbook_config->im_gate_url_len != 0) {
        hstr_target.m_write("addressbook-gate-url:");
        hstr_target.m_write(ads_config->ads_addressbook_config->ach_gate_url, ads_config->ads_addressbook_config->im_gate_url_len);
        hstr_target.m_write("\r\n");
    }
    if (ads_config->ads_addressbook_config->ach_gate_username != NULL && ads_config->ads_addressbook_config->im_gate_username_len != 0) {
        hstr_target.m_write("addressbook-gate-username:");
        hstr_target.m_write(ads_config->ads_addressbook_config->ach_gate_username, ads_config->ads_addressbook_config->im_gate_username_len);
        hstr_target.m_write("\r\n");
    }
}

ied_sdh_hobphone_status ds_hobphone2::m_system_message_get_config() {
    // get user data
    dsd_sdh_ident_set_1 ds_ident;
    ads_wsp_helper->m_cb_get_ident(&ds_ident);
    ds_usercma dsl_ucma;
    if (!ds_usercma::m_get_usercma( ads_wsp_helper, &dsl_ucma )) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_NO_USER_CONFIG,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_NO_USER_CONFIG;
    }
    struct dsd_getuser dsl_user;
    dsl_ucma.m_get_user( &dsl_user );
    int inl_domain_auth = dsl_user.inc_auth_method;
    // build configuration container
    // all configurations + channel info
    ds_hstring hstr_config0(ads_wsp_helper);
    // single configuration
    ds_hstring hstr_config1(ads_wsp_helper);
    // complete with nhasn
    //ds_hstring hstr_config2(ads_wsp_helper);
    // write the header
    hstr_config0.m_write("00CONFIG\r\n");
    // temporary variable used for return values
    BOOL bol_ret = FALSE;
    // switch by authentication type
#ifndef B110318
    bol_ret = dsl_ucma.m_select_config_ldap();
    if ( bol_ret == FALSE ) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_LDAP_SRV,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_INVALID_LDAP_SRV;
    }
#endif
    //switch ( inl_domain_auth )
    //{
    //case DEF_CLIB1_CONF_DYN_LDAP:
    //    // select the right ldap and get settings from this one
    //    bol_ret = ads_wsp_helper->m_set_ldap_srv( dsl_user.dsc_userdomain.m_get_ptr(),
    //                                              dsl_user.dsc_userdomain.m_get_len() );
    //    if ( bol_ret == FALSE ) {
    //       
    //    }
    //    // FALLTHROUGH
    //case DEF_CLIB1_CONF_KRB5:
    //case DEF_CLIB1_CONF_DYN_KRB5:
    //    // each krb5 has it's own ldap server configured,
    //    // just take settings from this one.
    //    // (there is no selection needed, wsp will handle this)
    //    // FALLTHROUGH
    //case DEF_CLIB1_CONF_LDAP:
    //    {
    /*
    old code above
    */
    // read settings from the one and only ldap
    // bind with user rights
    //int inl_ret = ds_ldap_instance.m_bind(&(dsl_user.dsc_username), NULL, ied_auth_admin );
    int inl_ret = ds_ldap_instance.m_simple_bind();
    if (inl_ret != SUCCESS) {
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_ACCESSING_LDAP,__LINE__, hstr.m_get_ptr());
        return SDH_HOBPHONE_STATUS_ERROR_ACCESSING_LDAP;
    }
    // get the dn
    ds_hstring hstr_our_dn = dsl_user.dsc_userdn;
    // read the global pbx configuration from ldap
    // the attribute as hstring
    ds_hstring hstr_pbx_list(ads_wsp_helper, "hobphonepbx");
    // a return vector
    ds_hvector<ds_attribute_string> dsl_pbx_attributes(ads_wsp_helper);
    // read the pbx config
    // TODO should be replaced by ds_ldap.m_collect_attributes
    // therefore a priority and exception algorithm needs to be found
    int im_pbx_ret = ds_ldap_instance.m_read_attributes(&hstr_pbx_list, NULL, &hstr_our_dn, ied_sear_superlevel,
        &dsl_pbx_attributes);
    // if pbx config could not be fetched
    if (im_pbx_ret != SUCCESS) {
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_GETTING_PBX_CONFIG,__LINE__, hstr.m_get_ptr());
        return SDH_HOBPHONE_STATUS_ERROR_GETTING_PBX_CONFIG;
    }
    // if more or less than 1 attributes found return exception
    int im_pbx_size = dsl_pbx_attributes.m_size();
    if (im_pbx_size == 0 || im_pbx_size > 1) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_NO_PBX_CONFIG_FOUND,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_NO_PBX_CONFIG_FOUND;
    }
    // parse the attribute
    ds_hstring ds_pbx_config = dsl_pbx_attributes.m_get(0).m_get_value_at(0);
    m_log_info(SDH_HOBPHONE_STATUS_OK,ds_pbx_config,"PBX Configuration: ");
    // build an object structure from xml
	dsd_xml_tag *ads_pbx_root = dsc_xml.m_from_xml(ds_pbx_config.m_const_str());
    if (!ads_pbx_root) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_NO_PBX_CONFIG_FOUND,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_NO_PBX_CONFIG_FOUND;
    }
    // it the structure is not valid return exception
    if (memcmp(ads_pbx_root->ach_data, "pbx-entries", ads_pbx_root->in_len_data) != 0) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG;
    }
    // loop over all pbx entry nodes
    dsd_xml_tag *ads_pbx_entry_node = dsc_xml.m_get_firstchild(ads_pbx_root);
    // if no nodes found return exception
    if (ads_pbx_entry_node == NULL) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_EMPTY_PBX_CONFIG,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_EMPTY_PBX_CONFIG;
    }
    dsd_xml_tag *ads_pbx_return = NULL;
    const char *ach_pbx_value;
    int im_pbx_value;
    while (ads_pbx_entry_node) {
        // create a new instance of the entry; mem is released when it is overwritten
        void *avo_entry_mem = ads_wsp_helper->m_cb_get_memory(sizeof(ds_pbx_entry), FALSE);
        ds_pbx_entry *ads_entry = reinterpret_cast<ds_pbx_entry *>(new (avo_entry_mem) ds_pbx_entry(ads_wsp_helper));
        // name
        ads_pbx_return = dsc_xml.m_get_value(ads_pbx_entry_node, "name", &ach_pbx_value, &im_pbx_value);
        if (ach_pbx_value == NULL || im_pbx_value == 0) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_NAME,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_NAME;
        }
        ads_entry->m_set_name(ach_pbx_value, im_pbx_value);
        // comment
        ads_pbx_return = dsc_xml.m_get_value(ads_pbx_entry_node, "comment", &ach_pbx_value, &im_pbx_value);
        ads_entry->m_set_comment(ach_pbx_value, im_pbx_value);
        // protocolid
        ads_pbx_return = dsc_xml.m_get_value(ads_pbx_entry_node, "protocolid", &ach_pbx_value, &im_pbx_value);
        ads_entry->m_set_protocolid(ach_pbx_value, im_pbx_value);
        // protocolname
        ads_pbx_return = dsc_xml.m_get_value(ads_pbx_entry_node, "protocolname", &ach_pbx_value, &im_pbx_value);
        ads_entry->m_set_protocolname(ach_pbx_value, im_pbx_value);
        // pbx-ineta
        ads_pbx_return = dsc_xml.m_get_value(ads_pbx_entry_node, "pbx-ineta", &ach_pbx_value, &im_pbx_value);
        if (!ads_pbx_return) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_INETA,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_INETA;
        }
        ads_entry->m_set_pbx_ineta(ach_pbx_value, im_pbx_value);
        // pbx-port
        ads_pbx_return = dsc_xml.m_get_value(ads_pbx_entry_node, "pbx-port", &ach_pbx_value, &im_pbx_value);
        if (!ads_pbx_return) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_PORT,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_PORT;
        }
        ads_entry->m_set_pbx_port(ach_pbx_value, im_pbx_value);
        // TODO max session
        // UDP-gw-name
        ads_pbx_return = dsc_xml.m_get_value(ads_pbx_entry_node, "UDP-gw-name", &ach_pbx_value, &im_pbx_value);
        // if no gw name is defined try to use default
        if (ads_pbx_return) {
            // if default is set use it
            if (ads_config->ach_udp_gw_name != NULL && ads_config->im_udp_gw_name_len > 0) {
                ach_pbx_value = ads_config->ach_udp_gw_name;
                im_pbx_value = ads_config->im_udp_gw_name_len;
            }
            // if no default return exception
            else {
                m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_UDP_GW,__LINE__, NULL);
                return SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_UDP_GW;
            }
        }
        ads_entry->m_set_udp_gw_name(ach_pbx_value, im_pbx_value);

        //outbound proxy - optional
        ads_pbx_return = dsc_xml.m_get_value(ads_pbx_entry_node, "outbound-proxy", &ach_pbx_value, &im_pbx_value);
        if (ads_pbx_return != NULL) {
            ads_entry->m_set_proxy_ineta(ach_pbx_value,im_pbx_value);            
        }
        ads_pbx_return = dsc_xml.m_get_value(ads_pbx_entry_node, "outbound-proxy-port", &ach_pbx_value, &im_pbx_value);
        if (ads_pbx_return != NULL) {
            ads_entry->m_set_proxy_port(ach_pbx_value,im_pbx_value);
        }


        // add the pbx entry to the map of entries
        m_add_pbx_entry(ads_entry->m_get_name(), ads_entry->m_get_name_len(), ads_entry);
        ads_pbx_entry_node = dsc_xml.m_get_nextsibling(ads_pbx_entry_node);
    }
    // read the user specific attribute from ldap
    // the attribute as hstring
    ds_hstring hstr_attr_list(ads_wsp_helper, "hobphoneconfig");
    // a return vector
    ds_hvector<ds_attribute_string> dsl_v_attributes(ads_wsp_helper);
    // read the config
    inl_ret = ds_ldap_instance.m_read_attributes (&hstr_attr_list, NULL, &hstr_our_dn, ied_sear_baseobject,
        &dsl_v_attributes);
    if (inl_ret != SUCCESS) {
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_GETTING_PHONE_CONFIG,__LINE__, hstr.m_get_ptr());
        return SDH_HOBPHONE_STATUS_ERROR_GETTING_PHONE_CONFIG;
    }
    // only one config is valid
    int im_size = dsl_v_attributes.m_size();
    if (im_size == 0 || im_size > 1) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_NO_PHONE_CONFIG,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_NO_PHONE_CONFIG;
    }
    ds_hstring ds_config = dsl_v_attributes.m_get(0).m_get_value_at(0);
    m_log_info(SDH_HOBPHONE_STATUS_OK,ds_config,"HOBPhone Configuration: "); 
    dsc_xml.m_clear();
    // build xml structure from attribute
	dsd_xml_tag *ads_root = dsc_xml.m_from_xml(ds_config.m_const_str());
    if (!ads_root || !memcmp(ads_root->ach_data, "SIP-profile", ads_root->in_len_data) == 0) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG;
    }
    int im_channel_index = 0;
    // get the profile
    dsd_xml_tag *ads_profile = dsc_xml.m_get_firstchild(ads_root);
    // a handle to a char chain
    const char *ach_value = NULL;
    // the length of the char chain
    int im_value_len = 0;
    // a general return node - used for detection of invalid xml
    dsd_xml_tag *ads_return_tag = NULL;
    // the sip ident
    char * ach_sip_ident;
    // the length of the sip ident
    int im_sip_ident_length;
    //return value for registration of the sip_request
    BOOL bo_ret;
    // flag to indicate the first sip request - needed for the sip ineta and port
    BOOL bo_first = TRUE;
    // loop over all profiles
    while (ads_profile) {
        char ch_channel_id = m_convert_to_channel_id(im_channel_index);
        // write the channel id
        hstr_config1.m_writef("channel-id:%c\r\n", ch_channel_id);
        // get the profile name
        ads_return_tag = dsc_xml.m_get_value(ads_profile, "pbx-profile", &ach_value, &im_value_len);
        if (!ads_return_tag) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_NO_PBX_PROFILE_DEFINED,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_NO_PBX_PROFILE_DEFINED;
        }
        // get the pbx profile from the map
        ds_pbx_entry *ads_pbx_entry_needed;
        BOOL bo_pbx_found = dsc_pbx_table.m_get(ach_value, im_value_len, &ads_pbx_entry_needed);
        if (!bo_pbx_found) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_PBX_PROFILE_NOT_FOUND,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_PBX_PROFILE_NOT_FOUND;
        }
        // get the protocolid
        if (ads_pbx_entry_needed->m_get_protocolid_len() != 0) {
            hstr_config1.m_writef("protocolid:%.*s\r\n", ads_pbx_entry_needed->m_get_protocolid_len(), ads_pbx_entry_needed->m_get_protocolid());
        }
        // get the protocolname
        if (ads_pbx_entry_needed->m_get_protocolname_len() != 0) {
            hstr_config1.m_writef("protocolname:%.*s\r\n", ads_pbx_entry_needed->m_get_protocolname_len(), ads_pbx_entry_needed->m_get_protocolname());
        }
        // get the name
        ads_return_tag = dsc_xml.m_get_value(ads_profile, "SIP-fullname", &ach_value, &im_value_len);
        hstr_config1.m_writef("SIP-fullname:%.*s\r\n", im_value_len, ach_value);
        // get the sip ident
        ads_return_tag = dsc_xml.m_get_value(ads_profile, "SIP-ident", &ach_value, &im_value_len);
        if (!ads_return_tag) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_NO_IDENT,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_NO_IDENT;
        }
        hstr_config1.m_writef("SIP-ident:%.*s\r\n", im_value_len, ach_value);

        m_setcontact(ch_channel_id,ach_value, im_value_len);

        // this value is needed later so we have to copy it to be safe
        ach_sip_ident = reinterpret_cast<char *>(ads_wsp_helper->m_cb_get_memory(im_value_len, FALSE));
        memcpy(ach_sip_ident, ach_value, im_value_len);
        im_sip_ident_length = im_value_len;
        // get the shared secret
        ads_return_tag = dsc_xml.m_get_value(ads_profile, "SIP-shared-secret", &ach_value, &im_value_len);
        hstr_config1.m_writef("SIP-shared-secret:%.*s\r\n", im_value_len, ach_value);
        // get the display-number
        ads_return_tag = dsc_xml.m_get_value(ads_profile, "SIP-display-number", &ach_value, &im_value_len);
        hstr_config1.m_writef("SIP-display-number:%.*s\r\n", im_value_len, ach_value);
        // write the profile specific data
        hstr_config1.m_writef("ineta-SIP-gateway:%.*s\r\n", ads_pbx_entry_needed->m_get_pbx_ineta_len(), ads_pbx_entry_needed->m_get_pbx_ineta());
        hstr_config1.m_writef("port-SIP-gateway:%.*s\r\n", ads_pbx_entry_needed->m_get_pbx_port_len(), ads_pbx_entry_needed->m_get_pbx_port());
        if (ads_pbx_entry_needed->m_get_proxy_ineta() != NULL)
            hstr_config1.m_writef("ineta-SIP-proxy:%.*s\r\n", ads_pbx_entry_needed->m_get_proxy_ineta_len(), ads_pbx_entry_needed->m_get_proxy_ineta());
        if (ads_pbx_entry_needed->m_get_proxy_port() != NULL)
            hstr_config1.m_writef("port-SIP-proxy:%.*s\r\n", ads_pbx_entry_needed->m_get_proxy_port_len(), ads_pbx_entry_needed->m_get_proxy_port());
        hstr_config1.m_writef("pbx-profile:%.*s\r\n", ads_pbx_entry_needed->m_get_name_len(), ads_pbx_entry_needed->m_get_name());
        // use srtp
        ads_return_tag = dsc_xml.m_get_value(ads_profile, "use-SRTP", &ach_value, &im_value_len);
        if (ach_value == NULL) {
            hstr_config1.m_write("use-SRTP:YES\r\n");
        }
        else {
            hstr_config1.m_writef("use-SRTP:%.*s\r\n", im_value_len, ach_value);
        }
        // autoregister
        ads_return_tag = dsc_xml.m_get_value(ads_profile, "auto-register", &ach_value, &im_value_len);
        if (ach_value == NULL) {
            hstr_config1.m_write("auto-register:YES\r\n\r\n");
        }
        else {
            hstr_config1.m_writef("auto-register:%.*s\r\n\r\n", im_value_len, ach_value);
        }
        //TODO: here we can add the local address (multihoming) if ever needed

        // when this point is reached the config is valid 
        // create sip channel for each config (if set)
        dsd_sdh_sip_requ_1 *ads_sip_request1 = 
            reinterpret_cast<dsd_sdh_sip_requ_1 *>(ads_wsp_helper->m_cb_get_memory(sizeof(dsd_sdh_sip_requ_1), FALSE));
        // convert the ineta to byte sequence big endian
        dsd_ineta_container ds_ineta;
        BOOL bo_ineta_valid;
        if (ads_pbx_entry_needed->m_get_proxy_ineta())
        {
            bo_ineta_valid = m_parse_ineta(ads_pbx_entry_needed->m_get_proxy_ineta(),
                ads_pbx_entry_needed->m_get_proxy_ineta_len(), ds_ineta);
            if (!bo_ineta_valid) {
                m_update_exception_message_l(SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_INVALID_INETA,__LINE__,
                    ads_pbx_entry_needed->m_get_proxy_ineta(), ads_pbx_entry_needed->m_get_proxy_ineta_len());
                return SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_INVALID_INETA;
            }
        }
        else
        {
            bo_ineta_valid = m_parse_ineta(ads_pbx_entry_needed->m_get_pbx_ineta(),
                ads_pbx_entry_needed->m_get_pbx_ineta_len(), ds_ineta);
            if (!bo_ineta_valid) {
                m_update_exception_message_l(SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_INVALID_INETA,__LINE__,
                    ads_pbx_entry_needed->m_get_pbx_ineta(), ads_pbx_entry_needed->m_get_pbx_ineta_len());
                return SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_INVALID_INETA;
            }
        }
        
        char *ach_ineta_sip_gw;
        ach_ineta_sip_gw = reinterpret_cast<char *>(ads_wsp_helper->m_cb_get_memory(ds_ineta.usc_length, FALSE));
        memcpy(ach_ineta_sip_gw, &ds_ineta.chrc_ineta, ds_ineta.usc_length);
        // FIXME define the target port of the sip gateway ?
        ads_sip_request1->achc_ineta_sip_gw = ach_ineta_sip_gw;
        ads_sip_request1->imc_len_ineta_sip_gw = ds_ineta.usc_length;
        ads_sip_request1->ac_sip_ident = ach_sip_ident;
        ads_sip_request1->imc_len_sip_ident = im_sip_ident_length;
        ads_sip_request1->iec_chs_sip_ident = ied_chs_utf_8;
        ads_sip_request1->imc_signal = HL_AUX_SIGNAL_IO_1;
        ads_sip_request1->iec_sdh_sipr1 = ied_sdh_sipr1_register;    
        // register sip request
        bo_ret = ads_wsp_helper->m_cb_sip_request(ads_sip_request1);
        if (!bo_ret) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_REGISTERING_SIP_REQUEST,__LINE__, &ch_channel_id, &(ads_sip_request1->iec_ret_sipr1));
            return  SDH_HOBPHONE_STATUS_ERROR_REGISTERING_SIP_REQUEST;
        }
        // if this is the first call the ineta and the port have to be added
        if (bo_first) {
            bo_first = FALSE;
            hstr_config0.m_write("ineta-WSP:");
            dsd_ineta_container ds_ineta;
            ied_sdh_hobphone_status ie_status = m_get_ineta_container(ds_ineta, (sockaddr_storage*)ads_sip_request1->achc_local_sip_sockaddr);
            if (ie_status != SDH_HOBPHONE_STATUS_OK) {
                return ie_status;
            }
            m_write_ineta(hstr_config0, ds_ineta);
            hstr_config0.m_write("\r\nport-WSP:");
            hstr_config0.m_writef("%u", ds_ineta.us_port);
            hstr_config0.m_write("\r\n");
            hstr_config0.m_writef("allow-local-pass:%s\r\n",ads_config->bo_allowlocalpass ? "YES" : "NO");
            hstr_config0.m_writef("client-keepalive:%s\r\n",ads_config->bo_client_timeout_priority ? "YES" : "NO");            
            hstr_config0.m_writef("WSP-cookie:");
            hstr_config0 += dsl_ucma.m_get_sticket();
            hstr_config0.m_write("\r\n");   
            m_setcontactineta(ds_ineta);

            // addressbook information
            if (ads_config->ads_addressbook_config != NULL) {
                ds_hstring adsl_domain = dsl_ucma.m_get_userdomain();
                m_write_addressbook_config(ads_config->ads_addressbook_config, hstr_config0,adsl_domain);
            }
        }
        // keep the request in our list
        m_set_sip_request(im_channel_index++, ads_sip_request1);
        // add the config to the whole
        hstr_config0 += hstr_config1;
        // reset the single
        hstr_config1.m_reset();
        // get the next profile
        ads_profile = dsc_xml.m_get_nextsibling(ads_profile);
    }
    hstrc_config.m_write_nhasn(hstr_config0.m_get_len());
    hstrc_config.m_write(hstr_config0.m_get_ptr(), hstr_config0.m_get_len());
    //    }
    //break;
    //case DEF_CLIB1_CONF_USERLI:
    //    {
    //        // use wsp.xml
    //        // write the channel id - only one channel supported
    //        hstr_config1.m_writef("channel-id:A\r\n");
    //        // get the name
    //        hstr_config1.m_writef("SIP-fullname:%.*s\r\n", ds_ident.dsc_sip_fullname.imc_len_str, ds_ident.dsc_sip_fullname.ac_str);
    //        // get the sip ident
    //        // this value is needed later so we have to copy it to be safe
    //        char *ach_sip_ident = reinterpret_cast<char *>(ads_wsp_helper->m_cb_get_memory(ds_ident.dsc_sip_ident.imc_len_str, FALSE));
    //        memcpy(ach_sip_ident, ds_ident.dsc_sip_ident.ac_str, ds_ident.dsc_sip_ident.imc_len_str);
    //        hstr_config1.m_writef("SIP-ident:%.*s\r\n", ds_ident.dsc_sip_ident.imc_len_str, ds_ident.dsc_sip_ident.ac_str);
    //        // get the shared secret
    //        hstr_config1.m_writef("SIP-shared-secret:%.*s\r\n", ds_ident.dsc_sip_shase.imc_len_str, ds_ident.dsc_sip_shase.ac_str);
    //        // get the display-number
    //        hstr_config1.m_writef("SIP-display-number:%.*s\r\n", ds_ident.dsc_sip_display_number.imc_len_str, ds_ident.dsc_sip_display_number.ac_str);
    //        // TODO for now assuming big endian - this has to be checked on other platforms
    //        // the sip gateway           
    //        // convert the data into a ds_ineta_container structure
    //        hstr_config1.m_write("ineta-SIP-gateway:");
    //        dsd_ineta_container ds_ineta;
    //        switch (ds_ident.imc_len_ineta_sip_gw)
    //        {
    //            // ipv4
    //        case 4:
    //            ds_ineta.usc_family = AF_INET;
    //            memcpy(&ds_ineta.chrc_ineta, ds_ident.achc_ineta_sip_gw, 4);
    //            ds_ineta.usc_length = 4;
    //            break;
    //            // ipv6
    //        case 16:
    //            ds_ineta.usc_family = AF_INET6;
    //            memcpy(&ds_ineta.chrc_ineta, ds_ident.achc_ineta_sip_gw, 16);
    //            ds_ineta.usc_length = 16;
    //            break;
    //        default:
    //            m_update_exception_message(SDH_HOBPHONE_STATUS_UNSUPPROTED_IP_VERSION, &ds_ident.imc_len_ineta_sip_gw);
    //            return SDH_HOBPHONE_STATUS_UNSUPPROTED_IP_VERSION;
    //        }
    //        m_write_ineta(hstr_config1, ds_ineta);
    //        hstr_config1.m_write("\r\n");
    //        // TODO port is assumed to be 5060 check if needed
    //        hstr_config1.m_write("port-SIP-gateway:5060\r\n");
    //        // use srtp is not needed in wsp mode
    //        hstr_config1.m_write("use-SRTP:YES\r\n");
    //        // autoregister defaults to yes
    //        hstr_config1.m_write("auto-register:YES\r\n");
    //        // when we reach this point the config is valid 
    //        // create sip channel for each config (if set)
    //        dsd_sdh_sip_requ_1 *ads_sip_request1 = 
    //            reinterpret_cast<dsd_sdh_sip_requ_1 *>(ads_wsp_helper->m_cb_get_memory(sizeof(dsd_sdh_sip_requ_1), TRUE));
    //        //ds_hstring hstr_ineta(ads_wsp_helper);
    //        char *ach_ineta_sip_gw;
    //        ach_ineta_sip_gw = reinterpret_cast<char *>(ads_wsp_helper->m_cb_get_memory(ds_ineta.usc_length, FALSE));
    //        memcpy(ach_ineta_sip_gw, &ds_ineta.chrc_ineta, ds_ineta.usc_length);
    //        // FIXME define the target port of the sip gateway ?
    //        // TODO remove: test values for jbtsipc1
    //        // char temp[4] = { 172, 22, 0, 140 };
    //        // ads_sip_request1->achc_ineta_sip_gw = temp;
    //        // ads_sip_request1->imc_len_ineta_sip_gw = 4;
    //        // /remove
    //        // TODO restore
    //        ads_sip_request1->achc_ineta_sip_gw = ach_ineta_sip_gw;
    //        ads_sip_request1->imc_len_ineta_sip_gw = ds_ineta.usc_length;
    //        // /restore
    //        ads_sip_request1->ac_sip_ident = ach_sip_ident;
    //        ads_sip_request1->imc_len_sip_ident = ds_ident.dsc_sip_ident.imc_len_str;
    //        ads_sip_request1->iec_chs_sip_ident = ied_chs_utf_8;
    //        ads_sip_request1->imc_signal = HL_AUX_SIGNAL_IO_1;
    //        ads_sip_request1->iec_sdh_sipr1 = ied_sdh_sipr1_register;
    //        // register sip request
    //        BOOL bo_ret = ads_wsp_helper->m_cb_sip_request(ads_sip_request1);
    //        if (!bo_ret) {
    //            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_REGISTERING_SIP_REQUEST, "A");
    //            return  SDH_HOBPHONE_STATUS_ERROR_REGISTERING_SIP_REQUEST;
    //        }
    //        // if this is the first call dd the ineta and the port
    //        hstr_config0.m_write("ineta-WSP:");
    //        ied_sdh_hobphone_status ie_status = m_get_ineta_container(ds_ineta, ads_sip_request1->achc_local_sip_sockaddr);
    //        if (ie_status != SDH_HOBPHONE_STATUS_OK) {
    //            return ie_status;
    //        }
    //        m_write_ineta(hstr_config0, ds_ineta);
    //        hstr_config0.m_write("\r\nport-WSP:");
    //        hstr_config0.m_writef("%u", ds_ineta.us_port);
    //        hstr_config0.m_write("\r\n");
    //        // addressbook information
    //        if (ads_config->ads_addressbook_config != NULL) {
    //            m_write_addressbook_config(ads_config->ads_addressbook_config, hstr_config0);
    //        }
    //        // keep the request in our list
    //        m_set_sip_request(0, ads_sip_request1);
    //        // add the config to the whole
    //        hstr_config0 += hstr_config1;
    //        hstr_config2.m_write_nhasn(hstr_config0.m_get_len());
    //        hstr_config2.m_write(hstr_config0.m_get_ptr(), hstr_config0.m_get_len());
    //    }
    //    break;
    //default:
    //    // BIG problem!
    //    m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_SOURCE, NULL);
    //    return SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_SOURCE;
    //}
    // send configurations
    dsc_xml.m_clear();
    bol_ret = ads_wsp_helper->m_send_data(hstrc_config.m_get_ptr(), hstrc_config.m_get_len());
    if (!bol_ret)
    {
        m_update_exception_message(SDH_HOBPHONE_STATUS_SEND_FAILED, __LINE__, 0);
        return SDH_HOBPHONE_STATUS_SEND_FAILED;
    }
    return SDH_HOBPHONE_STATUS_OK;
}

ied_sdh_hobphone_status ds_hobphone2::m_system_initialize_wsp_udp(BOOL bop_reload) {
    // we want to create...
    ds_udp_gate.iec_cmd_ug = ied_cmd_udp_gate_create;
    // until not succeeded repeat this step
    BOOL bo_success = FALSE;
    do {
        // get the nonce and pack it into the gate structure
        //if reload do not generate a new nonce - this allows the client to keep the existing structures (alternative: client must take new nonce)
        if (!ads_wsp_helper->m_cb_get_random(ds_udp_gate.chrc_nonce, DEF_LEN_UDP_GATE_NONCE)) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_GETTING_RANDOM,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_ERROR_GETTING_RANDOM;
        }
        if (bop_reload)
        {
            int imli = 0;                       
            while (imli < DEF_LEN_UDP_GATE_NONCE && ds_udp_gate.chrc_nonce[imli] == 0)
            {
                imli++;
            }
            if (imli == DEF_LEN_UDP_GATE_NONCE)
            {
                m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_UNKNOWN_UDPGATE_STATE,__LINE__, NULL);
                return SDH_HOBPHONE_STATUS_ERROR_UNKNOWN_UDPGATE_STATE;
            }
        }
        // make the callback
        // on fatal failure return with exception
        if (!ads_wsp_helper->m_cb_udp_gate(&ds_udp_gate)) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CREATING_UPD_GATE,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_ERROR_CREATING_UPD_GATE;
        }
        // checkt the return value
        switch (ds_udp_gate.iec_ret_ug) {
            case ied_ret_udp_gate_ok:
                {
                    // it worked - in principal
                    bo_success = TRUE;
                    // send the reply
                    ds_hstring hstr_reply(ads_wsp_helper);
                    hstr_reply.m_write("00CHECK UDP ROUTE\r\n");
                    // write the ineta
                    dsd_ineta_container ds_container;
                    if (ds_udp_gate.adsc_udp_gate_ineta->boc_ipv4) {
                        // ipv4
                        ds_container.usc_family = AF_INET;
                        ds_container.usc_length = sizeof(sockaddr_in);
                        memcpy(ds_container.chrc_ineta, &ds_udp_gate.adsc_udp_gate_ineta->dsc_soai4.sin_addr, sizeof(sockaddr_in));
                        ds_container.us_port = static_cast<short>(ds_udp_gate.imc_udp_gate_ipv4_port);
                    }
                    else if (ds_udp_gate.adsc_udp_gate_ineta->boc_ipv6) {
                        // ipv6
                        ds_container.usc_family = AF_INET6;
                        ds_container.usc_length = sizeof(sockaddr_in6);
                        memcpy(ds_container.chrc_ineta, &ds_udp_gate.adsc_udp_gate_ineta->dsc_soai6.sin6_addr, sizeof(sockaddr_in6));
                        ds_container.us_port = static_cast<short>(ds_udp_gate.imc_udp_gate_ipv6_port);
                    }
                    hstr_reply.m_write("ineta-WSP:");
                    m_write_ineta(hstr_reply, ds_container);
                    hstr_reply.m_writef("\r\nport-WSP:%hu\r\nnonce:", ds_container.us_port);
                    hstr_reply.m_write(ds_udp_gate.chrc_nonce, DEF_LEN_UDP_GATE_NONCE);
                    hstr_reply.m_write("\r\n");
                    hstr_reply.m_writef("timeout:%ld\r\n", ads_config->il_udp_gate_timeout);
                    hstr_reply.m_writef("keepalive:%ld\r\n", ads_config->im_udp_gate_keepalive);
                    ds_hstring hstr_buffer(ads_wsp_helper);
                    hstr_buffer.m_write_nhasn(hstr_reply.m_get_len());
                    hstr_buffer += hstr_reply;
                    // TODO return check
                    BOOL bol_send = ads_wsp_helper->m_send_data(hstr_buffer.m_get_ptr(), hstr_buffer.m_get_len());
                    if (!bol_send)
                    {
                        m_update_exception_message(SDH_HOBPHONE_STATUS_SEND_FAILED,__LINE__,0);
                        return SDH_HOBPHONE_STATUS_SEND_FAILED;
                    }
                }
                break;
            case ied_ret_udp_gate_nonce_double:
                continue;
            case ied_ret_udp_gate_not_conf:
                m_update_exception_message(SDH_HOBPHONE_STATUS_UDP_GATE_NOT_CONFIGURED,__LINE__, NULL);
                return SDH_HOBPHONE_STATUS_UDP_GATE_NOT_CONFIGURED;
            default:
                // TODO tidy up
                m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CREATING_UPD_GATE,__LINE__, NULL);
                return SDH_HOBPHONE_STATUS_ERROR_CREATING_UPD_GATE;
        }
    } while(!bo_success);
    bo_use_udp_gate = TRUE;
    return SDH_HOBPHONE_STATUS_OK;
}

ied_sdh_hobphone_status ds_hobphone2::m_system_message_enable_udp_gate(ds_gather_iterator &dsp_it) {
    // the header is used so we have only the conten
    // content should be 'enable:(YES|NO)\r\n'
    if (dsp_it.m_get_remaining_length() < 11) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_ENABLE_UDP_GATE_MESSAGE,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_INVALID_ENABLE_UDP_GATE_MESSAGE;
    }
    if (m_compare(astr_enabled_yes, dsp_it)) {
        if (bo_use_udp_gate == TRUE) { 
            // has to be warning - infos are not logged
            m_update_exception_message(SDH_HOBPHONE_STATUS_UDP_GATE_ENABLED,__LINE__, NULL);
            //m_log_warning(SDH_HOBPHONE_STATUS_UDP_GATE_ENABLED, hstr_exception_message);
            return SDH_HOBPHONE_STATUS_OK;
        }
        else {
            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_INVALID_STATE_ON_ENABLE_UDP_GATE,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_ERROR_INVALID_STATE_ON_ENABLE_UDP_GATE;
        }
    }
    if (m_compare(astr_enabled_no, dsp_it)) {
        // TODO clean up
        // has to be warning - infos are not logged
        m_update_exception_message(SDH_HOBPHONE_STATUS_UDP_GATE_DISABLED,__LINE__, NULL);
        //m_log_warning(SDH_HOBPHONE_STATUS_UDP_GATE_DISABLED, hstr_exception_message);
        return SDH_HOBPHONE_STATUS_OK;
    }
    m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_ENABLE_UDP_GATE_MESSAGE,__LINE__, NULL);
    return SDH_HOBPHONE_STATUS_INVALID_ENABLE_UDP_GATE_MESSAGE;
}

ied_sdh_hobphone_status ds_hobphone2::m_system_message_create_channel(ds_gather_iterator &dsp_it) {

    // get channel type
    if (!m_compare(astr_channel_type, dsp_it)) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_TYPE,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_TYPE;
    }
    // get channel type number
    ds_hstring hstr_line;
    dsp_it.m_get_line(hstr_line);
    if (hstr_line.m_get_len() == 0) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_TYPE,__LINE__, NULL);
        return SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_TYPE;
    }
    int im_channel_type = 0;
    hstr_line.m_to_int(&im_channel_type);
    switch (im_channel_type)
    {
    default:
        m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_UNSUPPROTED_TYPE,__LINE__, &im_channel_type);
        return SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_UNSUPPROTED_TYPE;
    case SDH_HOBPHONE_CHANNEL_TYPE_UDP:
    case SDH_HOBPHONE_CHANNEL_TYPE_UDP_DIRECT:
        // get free channel_id
        int im_channel_index = m_get_free_channel_index();
        char ch_channel_id = m_convert_to_channel_id(im_channel_index);
        // if none is free -> exception
        if (im_channel_index < 0) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CREATING_CHANNEL_NO_FREE_CHANNEL,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_ERROR_CREATING_CHANNEL_NO_FREE_CHANNEL;
        }
        // get call id
        if (!m_compare(astr_call_id, dsp_it)) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_CALL_ID,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_CALL_ID;
        }
        ds_hstring hstr_call_id(ads_wsp_helper);
        dsp_it.m_get_line(hstr_call_id);
        if (hstr_call_id.m_get_len() == 0) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_CALL_ID,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_CALL_ID;
        }
        // get the udp gw name
        ds_hstring hstr_udp_gw_name(ads_wsp_helper);
        dsp_it.m_get_line(hstr_udp_gw_name);
        // prepare a udp request
        dsd_sdh_udp_requ_1 *ads_udp_request1 = reinterpret_cast<dsd_sdh_udp_requ_1 *>(ads_wsp_helper->m_cb_get_memory(sizeof(dsd_sdh_udp_requ_1), TRUE));
        // set the command to be executed
        ads_udp_request1->iec_sdh_udpr1 = ied_sdh_udpr1_register;
        // set the signal we want to receive
        ads_udp_request1->imc_signal = HL_AUX_SIGNAL_IO_2;
        // get the pbx profile to use
        // pbx-profile: first relevant char is 12
        dsd_const_string hstr_ug_name(hstr_udp_gw_name.m_substring(12));
        // get the pbx entry 
        ds_pbx_entry *ads_pbx_entry;
        // if pbx found use the name in the entry
        BOOL bo_udp_set = dsc_pbx_table.m_get(hstr_ug_name.m_get_ptr(), hstr_ug_name.m_get_len(), &ads_pbx_entry);
        if (bo_udp_set) {                    
            ads_udp_request1->ac_bind = reinterpret_cast<void *>(const_cast<char *>(ads_pbx_entry->m_get_udp_gw_name()));
            ads_udp_request1->imc_len_bind = ads_pbx_entry->m_get_udp_gw_name_len();
            ads_udp_request1->iec_chs_bind = ied_chs_utf_8;
        }

        // if no gw set but default use that one
        BOOL bo_default_set = ads_config->ach_udp_gw_name != NULL && ads_config->im_udp_gw_name_len > 0;
        if (!bo_udp_set && bo_default_set) {
            ads_udp_request1->ac_bind = ads_config->ach_udp_gw_name;
            ads_udp_request1->imc_len_bind = ads_config->im_udp_gw_name_len;
            ads_udp_request1->iec_chs_bind = ied_chs_utf_8;
        }
        // if none set return exception
        if (!bo_udp_set && !bo_default_set) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_UDP_GW_CONFIGURATION,__LINE__, NULL);
            return SDH_HOBPHONE_STATUS_INVALID_UDP_GW_CONFIGURATION;
        }
        // prepare 2 socket address structures to send/receive
        // using ipv6 so save in size
        sockaddr_in6 *ads_send = reinterpret_cast<sockaddr_in6 *>(ads_wsp_helper->m_cb_get_memory(sizeof(sockaddr_in6), TRUE));
        sockaddr_in6 *ads_bind = reinterpret_cast<sockaddr_in6 *>(ads_wsp_helper->m_cb_get_memory(sizeof(sockaddr_in6), TRUE));
        // set the socket addresses
        ads_udp_request1->achc_sockaddr  = (char *)ads_send;
        ads_udp_request1->imc_len_sockaddr = sizeof(sockaddr_in);
        ads_udp_request1->achc_soa_bind = (char *)ads_bind;
        ads_udp_request1->imc_len_soa_bind = sizeof(sockaddr_in);
        BOOL bo_result = ads_wsp_helper->m_cb_udp_request(ads_udp_request1);
        // if failed, udp gw set and default set try default
        if (!bo_result && bo_udp_set && bo_default_set) {
            ads_udp_request1->ac_bind = ads_config->ach_udp_gw_name;
            ads_udp_request1->imc_len_bind = ads_config->im_udp_gw_name_len;
            ads_udp_request1->iec_chs_bind = ied_chs_utf_8;
            bo_result = ads_wsp_helper->m_cb_udp_request(ads_udp_request1);
            // if still no success clean up and error
            if (!bo_result) {
                ads_wsp_helper->m_cb_free_memory(ads_send, sizeof(sockaddr_in));
                ads_wsp_helper->m_cb_free_memory(ads_bind, sizeof(sockaddr_in));
                ads_wsp_helper->m_cb_free_memory(ads_udp_request1, sizeof(dsd_sdh_udp_requ_1));
                m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_REGISTERING_UDP_REQUEST,__LINE__, &ch_channel_id);
                return SDH_HOBPHONE_STATUS_ERROR_REGISTERING_UDP_REQUEST;
            }
        }
        // we succeeded
        m_set_udp_request(im_channel_index, ads_udp_request1);
        // get the ineta to bind to
        dsd_ineta_container ds_ineta;
        ied_sdh_hobphone_status ie_status = m_get_ineta_container(ds_ineta, (sockaddr_storage*)ads_bind);
        if (ie_status != SDH_HOBPHONE_STATUS_OK) {
            return ie_status;
        }
        // create the result string
        ds_hstring str_text(ads_wsp_helper);
        str_text.m_write("00CHANNEL CREATED\r\nchannel-type:");
        switch (im_channel_type)
        {
        case SDH_HOBPHONE_CHANNEL_TYPE_UDP:
            str_text.m_write(&SDH_HOBPHONE_CHAR_CHANNEL_TYPE_UDP, 1);
            break;
        case SDH_HOBPHONE_CHANNEL_TYPE_UDP_DIRECT:
            str_text.m_write(&SDH_HOBPHONE_CHAR_CHANNEL_TYPE_UDP_DIRECT, 1);
            break;
        }
        str_text.m_write("\r\nchannel-id:");
        str_text.m_write(&ch_channel_id, 1);
        str_text.m_write("\r\n");
        str_text.m_write("call-id:");
        str_text += hstr_call_id;
        str_text.m_write("\r\n");
        str_text.m_write("ineta-local:");
        m_write_ineta(str_text, ds_ineta);
        str_text.m_write("\r\n");
        str_text.m_write("port-local:");
        str_text.m_writef("%u", ds_ineta.us_port);
        str_text.m_write("\r\n");
        // we have to add the length - nhasn encoded
        ds_hstring str_buffer(ads_wsp_helper);
        str_buffer.m_write_nhasn(str_text.m_get_len());
        str_buffer += str_text;
        // send it
#ifdef DEBUG_CHANNELS
		m_log_warning(str_buffer.m_const_str());
#endif
        ads_wsp_helper->m_send_data(str_buffer.m_get_ptr(), str_buffer.m_get_len());
        break;
    }
    return SDH_HOBPHONE_STATUS_OK;
}

ied_sdh_hobphone_status ds_hobphone2::m_system_message_set_channel(ds_gather_iterator &dsp_it) {
    // get the channel_type
    ds_hstring hstr_type(ads_wsp_helper);
    dsp_it.m_get_line(hstr_type);
    int im_channel_type;
    BOOL bo_result = hstr_type.m_to_int(&im_channel_type, 13);
    // if we can not parse the channel type throw exception
    if (!bo_result) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_INVALID_CHANNEL_TYPE,__LINE__, hstr_type.m_get_ptr());
        return SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_INVALID_CHANNEL_TYPE;
    }
    switch (im_channel_type) {
        default:
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE,__LINE__, &im_channel_type);
            return SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE;
        case SDH_HOBPHONE_CHANNEL_TYPE_UDP:
        case SDH_HOBPHONE_CHANNEL_TYPE_UDP_DIRECT:
            // get the channel id
            ds_hstring hstr_id(ads_wsp_helper);
            dsp_it.m_get_line(hstr_id);
            char ch_channel_id = *(hstr_id.m_get_ptr() + 11);
            // get the index
            int im_channel_index = m_get_index(ch_channel_id);
            if (im_channel_index == -1) {
                m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_INVALID_CHANNEL,__LINE__, &ch_channel_id);
                return SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_INVALID_CHANNEL;
            }
            // get the ineta
            ds_hstring hstr_ineta(ads_wsp_helper);
            dsp_it.m_get_line(hstr_ineta);
            // get the port
            ds_hstring hstr_port(ads_wsp_helper);
            dsp_it.m_get_line(hstr_port);
            int im_port = 0;
            hstr_port.m_to_int(&im_port, 12);
            // convert the port to network byte order
            u_short us_port_nbo = htons(im_port);
            BOOL bo_need_crypto = FALSE;
            // additional crypto fields are only valid when srtp:NO
            char chr_keys[DEF_LEN_UDP_GATE_KEYS];
            // get the srtp state
            if (m_compare(astr_srtp_no, dsp_it)) {
                // keep the state
                bo_need_crypto = TRUE;
                // the keys
                ds_hstring hstr_master(ads_wsp_helper);
                dsp_it.m_get_line(hstr_master);
                int im_master_len = hstr_master.m_get_len() - 7;
                memcpy(chr_keys, hstr_master.m_get_ptr() + 7, im_master_len);
            }
            // get the container
            dsd_sdh_udp_requ_1 *ads_request = m_get_udp_request(m_get_index(ch_channel_id));
            // if no valid request found throw exception
            if (ads_request == NULL) {
                m_mark_used(dsp_it.m_get_current_gather(), dsp_it.m_get_remaining_length());
                // we have to free the memory
                m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_SETTING_CHANNEL_NO_CHANNEL,__LINE__, &ch_channel_id);
                return SDH_HOBPHONE_STATUS_ERROR_SETTING_CHANNEL_NO_CHANNEL;
            }
            dsd_ineta_container ds_ineta;
            dsd_const_string dsl_ineta(hstr_ineta.m_substring(13));
            m_parse_ineta(dsl_ineta.m_get_ptr(), dsl_ineta.m_get_len(), ds_ineta);
            // if it is already set free the old data
            if ((sockaddr_in *)ads_request->achc_sockaddr) {
                ads_wsp_helper->m_cb_free_memory(ads_request->achc_sockaddr, ads_request->imc_len_sockaddr);
            }
            // get a new sockaddr depending on ip version
            switch (ds_ineta.usc_family) {
        case AF_INET:
            {
                // create ipv4
                sockaddr_in *ads_sock = reinterpret_cast<sockaddr_in *>(ads_wsp_helper->m_cb_get_memory(sizeof(sockaddr_in), FALSE));
                // populate
                ads_sock->sin_port = us_port_nbo;
                ads_sock->sin_family = AF_INET;
#if defined WIN32 || defined WIN64
                memcpy(&ads_sock->sin_addr.S_un.S_un_b.s_b1, &ds_ineta.chrc_ineta, ds_ineta.usc_length);
#else
                memcpy(&ads_sock->sin_addr.s_addr, &ds_ineta.chrc_ineta, ds_ineta.usc_length);
#endif
                // set
                ads_request->achc_sockaddr = reinterpret_cast<char *>(ads_sock);
                ads_request->imc_len_sockaddr = sizeof(sockaddr_in);
            }
            break;
        case AF_INET6:
            {
                // create ipv6
                sockaddr_in6 *ads_sock = reinterpret_cast<sockaddr_in6 *>(ads_wsp_helper->m_cb_get_memory(sizeof(sockaddr_in6), FALSE));
                // populate
                ads_sock->sin6_port = us_port_nbo;
                ads_sock->sin6_family = AF_INET6;
#if defined WIN32 || defined WIN64
                memcpy(&ads_sock->sin6_addr.u.Byte, &ds_ineta.chrc_ineta, ds_ineta.usc_length);
#else
                memcpy(&ads_sock->sin6_addr.s6_addr, &ds_ineta.chrc_ineta, ds_ineta.usc_length);
#endif
                // set
                ads_request->achc_sockaddr = reinterpret_cast<char *>(ads_sock);
                ads_request->imc_len_sockaddr = sizeof(sockaddr_in6);
            }
            break;
        default:
            // we have to free the memory
            m_update_exception_message(SDH_HOBPHONE_STATUS_UNSUPPROTED_IP_VERSION,__LINE__, &ds_ineta.usc_family);
            return SDH_HOBPHONE_STATUS_UNSUPPROTED_IP_VERSION;
            }
            //// if a subchannel already exists remove it
            //if (adsr_udp_subchannels[im_channel_index] != NULL) {
            //    ds_udp_gate.ucc_subchannel_id = ch_channel_id;
            //    ds_udp_gate.vpc_udpr_handle = ads_request->vpc_udpr_handle;
            //    ds_udp_gate.vpc_ug_subch_handle = adsr_udp_subchannels[im_channel_index];
            //    // if we fail, the udp gate has to be disabled
            //    if (!ads_wsp_helper->m_cb_udp_gate(&ds_udp_gate)) {
            //        // we have to free the memory
            //        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_GATE_SUBCHANNEL, &hstr_exception_message);
            //        return SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_GATE_SUBCHANNEL;
            //    }
            //}

            // if a subchannel already exists skip the creation
            // if we created a udp_gate subchannel request we have to remember it
            if (im_channel_type == SDH_HOBPHONE_CHANNEL_TYPE_UDP_DIRECT /*&& adsr_udp_subchannels[im_channel_index] == NULL*/) {
                if (adsr_udp_subchannels[im_channel_index] != NULL)
                {
                    //remove existing entry
                    ds_udp_gate.iec_cmd_ug = ied_cmd_uga_subch_close;
                    ds_udp_gate.vpc_udpr_handle = ads_request->vpc_udpr_handle;
                    ds_udp_gate.vpc_ug_subch_handle = adsr_udp_subchannels[im_channel_index];
                    if (!ads_wsp_helper->m_cb_udp_gate(&ds_udp_gate)) {
                        // we have to free the memory
                        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_GATE_SUBCHANNEL,__LINE__, &hstr_exception_message);
                        return SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_GATE_SUBCHANNEL;
                    }

                }
                // we first have to make a call to create a subchannel
                ds_udp_gate.ucc_subchannel_id = ch_channel_id;
                ds_udp_gate.vpc_udpr_handle = ads_request->vpc_udpr_handle;
                ds_udp_gate.iec_cmd_ug = ied_cmd_uga_subch_register;
                ds_udp_gate.boc_subch_srtp = !bo_need_crypto;
                ds_udp_gate.achc_subch_keys = bo_need_crypto ? chr_keys : NULL;
                ds_udp_gate.achc_subch_sockaddr = ads_request->achc_sockaddr;
                ds_udp_gate.imc_len_subch_sockaddr = ads_request->imc_len_sockaddr;
                // if we fail, the udp gate has to be disabled
                if (!ads_wsp_helper->m_cb_udp_gate(&ds_udp_gate)) {
                    // we have to free the memory
                    m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CREATING_UDP_GATE_SUBCHANNEL,__LINE__, &hstr_exception_message);
                    return SDH_HOBPHONE_STATUS_ERROR_CREATING_UDP_GATE_SUBCHANNEL;
                }
                // remember
                adsr_udp_subchannels[im_channel_index] = ds_udp_gate.vpc_ug_subch_handle;
            }
            // create the reply message                    
            ds_hstring hstr_reply(ads_wsp_helper);
            hstr_reply.m_writef("00CHANNEL SET\r\nchannel-type:%d\r\nchannel-id:", im_channel_type);
            hstr_reply.m_write(&ch_channel_id, 1);
            hstr_reply.m_write("\r\nineta-target:");
            // using the original to reply with a known expression
            hstr_reply.m_write(hstr_ineta.m_substring(13));
            hstr_reply.m_write("\r\nport-target:");
            hstr_reply.m_writef("%u\r\n", im_port);
            ds_hstring hstr_buffer(ads_wsp_helper);
            hstr_buffer.m_write_nhasn(hstr_reply.m_get_len());
            hstr_buffer += hstr_reply;
#ifdef DEBUG_CHANNELS
			m_log_warning(hstr_buffer.m_const_str());
#endif
            ads_wsp_helper->m_send_data(hstr_buffer.m_get_ptr(), hstr_buffer.m_get_len());
            return SDH_HOBPHONE_STATUS_OK;
    }
}

ied_sdh_hobphone_status ds_hobphone2::m_system_message_remove_channel(ds_gather_iterator &dsp_it) {
    // get the channel_type
    ds_hstring hstr_type(ads_wsp_helper);
    dsp_it.m_get_line(hstr_type);
    const char *ach_channel_type = hstr_type.m_get_ptr() + 13;
    char ch_channel_type = *ach_channel_type;
    int im_channel_type;
    BOOL bo_result = hstr_type.m_to_int(&im_channel_type, 13);
    // if we can not parse the channel type throw exception
    if (!bo_result) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_INVALID_CHANNEL_TYPE,__LINE__, &ch_channel_type);
        return SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_INVALID_CHANNEL_TYPE;
    }
    switch (im_channel_type) {
        default:
            m_update_exception_message(SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE,__LINE__, &ch_channel_type);
            return SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE;
        case SDH_HOBPHONE_CHANNEL_TYPE_UDP:
        case SDH_HOBPHONE_CHANNEL_TYPE_UDP_DIRECT:
            // get the channel id
            ds_hstring hstr_id(ads_wsp_helper);
            dsp_it.m_get_line(hstr_id);
            char ch_channel_id = *(hstr_id.m_get_ptr() + 11);
            int im_channel_index = m_get_index(ch_channel_id);
            // if no valid request found throw exception
            if (m_get_udp_request(im_channel_index) == NULL) {
                m_mark_used(dsp_it.m_get_current_gather(), dsp_it.m_get_remaining_length());
                m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_REMOVING_CHANNEL_NO_CHANNEL,__LINE__, &ch_channel_id);
                return SDH_HOBPHONE_STATUS_ERROR_REMOVING_CHANNEL_NO_CHANNEL;
            }
            m_set_udp_request(im_channel_index, NULL);
            // reply
            ds_hstring hstr_reply(ads_wsp_helper);
            hstr_reply.m_writef("00CHANNEL REMOVED\r\nchannel-type:%c\r\nchannel-id:%c\r\n", ch_channel_type, ch_channel_id);
            ds_hstring hstr_buffer(ads_wsp_helper);
            hstr_buffer.m_write_nhasn(hstr_reply.m_get_len());
            hstr_buffer += hstr_reply;
#ifdef DEBUG_CHANNELS
			m_log_warning(hstr_buffer.m_const_str());
#endif
            ads_wsp_helper->m_send_data(hstr_buffer.m_get_ptr(), hstr_buffer.m_get_len());
            return SDH_HOBPHONE_STATUS_OK;
    }
}

ied_sdh_hobphone_status ds_hobphone2::m_redirect_sip_to_pbx(ds_gather_iterator &dsp_it) {
    // get the channel id
    char ch_id = m_get_channel_id(dsp_it);
    // get the corresponding request
    dsd_sdh_sip_requ_1 *ads_request = m_get_sip_request(m_get_index(ch_id));
    if (!ads_request) {
        // mark the message as used 
        m_mark_used(dsp_it.m_get_current_gather(), dsp_it.m_get_remaining_length());
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_SIP_TO_PBX_NO_REQUEST,__LINE__, &ch_id);
        return SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_SIP_TO_PBX_NO_REQUEST;
    }
    // duplicate the gather chain for the valid message
    dsd_gather_i_1 *ads_duplicate = dsp_it.m_duplicate(ads_wsp_helper);
    // send the duplicate
    ads_request->adsc_gai1_send = ads_duplicate;
    ads_request->iec_sdh_sipr1 = ied_sdh_sipr1_send_gather;
    ads_wsp_helper->m_cb_sip_request(ads_request);
    // delete the gather chain
    m_free_gatherchain(ads_duplicate);
    // mark the message as used 
    m_mark_used(dsp_it.m_get_current_gather(), dsp_it.m_get_remaining_length());
    return SDH_HOBPHONE_STATUS_OK;
}

ied_sdh_hobphone_status ds_hobphone2::m_redirect_udp_to_pbx(ds_gather_iterator &dsp_it) {
    // get the channel id
    char ch_id = m_get_channel_id(dsp_it);
    // get the corresponding request
    dsd_sdh_udp_requ_1 *ads_request = m_get_udp_request(m_get_index(ch_id));
    if (!ads_request) {
        // mark the message as used 
        m_mark_used(dsp_it.m_get_current_gather(), dsp_it.m_get_remaining_length());
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_UDP_TO_PBX_NO_REQUEST,__LINE__, &ch_id);
        return SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_UDP_TO_PBX_NO_REQUEST;
    }
    // duplicate the gather chain for the valid message
    dsd_gather_i_1 *ads_duplicate = dsp_it.m_duplicate(ads_wsp_helper);
    // send the duplicate
    ads_request->adsc_gai1_send = ads_duplicate;
    ads_request->iec_sdh_udpr1 = ied_sdh_udpr1_send_gather;
    ads_wsp_helper->m_cb_udp_request(ads_request);
    // delete the gather chain
    m_free_gatherchain(ads_duplicate);
    // mark the message as used 
    m_mark_used(dsp_it.m_get_current_gather(), dsp_it.m_get_remaining_length());
    return SDH_HOBPHONE_STATUS_OK;
}

//static bool p1,p2,p3;


ied_sdh_hobphone_status ds_hobphone2::m_redirect_sip_to_client() {
    // loop over all sip_requests
    dsd_sdh_sip_requ_1 *ads_request;
    char ch_channel_id;
    for (char ch_i = 0; ch_i < im_max_account_count; ++ch_i) {
        if (adsr_sip_requests[ch_i] == NULL) {
            continue;
        }
        // get the request
        ads_request = adsr_sip_requests[ch_i];
        // calculate the id
        ch_channel_id = m_convert_to_channel_id(ch_i);
        ads_request->iec_sdh_sipr1 = ied_sdh_sipr1_update_recv;
        // update the request
        ads_wsp_helper->m_cb_sip_request(ads_request);
        // loop over until last buffer
        while (ads_request->adsc_recb_1 != NULL) {
            ds_hstring hstr_text1(ads_wsp_helper);
            ds_hstring hstr_buffer(ads_wsp_helper);
            dsd_sdh_udp_recbuf_1 *ads_buffer = ads_request->adsc_recb_1;
            int im_length = 0;
            //SIP handling goes here!
            // loop over all buffers
            BOOL bol_handled = FALSE;
            while (ads_buffer) {
                
                
                //if (p1)
                //{
               /* dsd_hl_clib_1* adsl_hlclib = (dsd_hl_clib_1*)(ads_wsp_helper->m_get_structure());
                char* achl_work_1 = adsl_hlclib->achc_work_area;  
                dsd_gather_i_1* adsl_current_out = (dsd_gather_i_1*)achl_work_1;
                achl_work_1 += sizeof(struct dsd_gather_i_1); //gather must come before that since that is what wsp helper expects
                achl_work_1++; //leave space for channel
                //free space in work area: length minus 1 byte for byte 0, 1 byte for channel and size of gather
                int iml_len = adsl_hlclib->inc_len_work_area - 2 - sizeof(struct dsd_gather_i_1);  
                                                                  */
                                            
                if (ads_config->bo_sipautoreply)
                {
                    

                    char* adsl_sipreply = adsc_sipreply[ch_i];                    
                    adsl_sipreply+= sizeof(struct dsd_gather_i_1);
                    int iml_len = 2048 - 1 - sizeof(struct dsd_gather_i_1);
                    //if(m_handlesip(ads_buffer, achl_work_1, iml_len, &imc_sipreplylen))
                    if(m_handlesip(ads_buffer, &(adsl_sipreply[1]), iml_len, &imc_sipreplylen))                    
                    {
                        //SIP message was handled by SDH, do not forward to client
                        //ads_wsp_helper->m_send_data(adsc_sipreply,imc_sipreplylen,ied_sdh_dd_toserver);
                        //if (p2)
                        //{
                        /*achl_work_1--;
                        *achl_work_1 = ch_channel_id;*/

                        dsd_gather_i_1* adsl_current_out = (dsd_gather_i_1*)(adsc_sipreply[ch_i]);
                        *adsl_sipreply = ch_channel_id;

                        adsl_current_out->achc_ginp_cur = adsl_sipreply;
                        adsl_current_out->achc_ginp_end = adsl_sipreply+imc_sipreplylen+1;
                        adsl_current_out->adsc_next = NULL;
                        
                        /*adsl_current_out->achc_ginp_cur = achl_work_1;
                        adsl_current_out->achc_ginp_end = achl_work_1+imc_sipreplylen+1;
                        adsl_current_out->adsc_next = NULL;*/
                        
                        ds_gather_iterator ds_iter(adsl_current_out,imc_sipreplylen+1);
                        //if (p3)
                        m_redirect_sip_to_pbx(ds_iter);
                        imc_sipreplylen = 0;
                        bol_handled = TRUE;
                        //} //p2
                        
                    }
                }
                //} //p1
                if (bol_handled)
                {       
                    bol_handled = FALSE;
                }
                else
                {
                    if (ads_buffer->imc_len_data >0) {
                        hstr_text1.m_write(&SDH_HOBPHONE_CHAR_CHANNEL_TYPE_UDP_SIP, 1);
                        hstr_text1.m_write(&ch_channel_id, 1);
                        hstr_text1.m_write(ads_buffer->achc_data, ads_buffer->imc_len_data);
                        im_length = hstr_text1.m_get_len();
                        hstr_buffer.m_write_nhasn(im_length);
                        hstr_buffer += hstr_text1;
                        // TODO remove and send only gather
                        ads_wsp_helper->m_send_data(hstr_buffer.m_get_ptr(), hstr_buffer.m_get_len());
                        hstr_text1.m_reset();
                        hstr_buffer.m_reset();
                    } else {
                        printf("received sip packet with length 0!\n" );
                    }
                }
                ads_buffer = ads_buffer->adsc_next;
            } //while(ads_buffer)
            if (true || !bol_handled)
            {
                ads_request->iec_sdh_sipr1 = ied_sdh_sipr1_free_buffer;
                ads_wsp_helper->m_cb_sip_request(ads_request);
            
                ads_request->iec_sdh_sipr1 = ied_sdh_sipr1_update_recv;
                ads_wsp_helper->m_cb_sip_request(ads_request);
            }
        }
    }
    return SDH_HOBPHONE_STATUS_OK;
}

ied_sdh_hobphone_status ds_hobphone2::m_redirect_udp_to_client() {
    // loop over all udp requests
    dsd_sdh_udp_requ_1 *ads_request;
    char ch_channel_id;
    for (int im_channel_index = 0; im_channel_index < im_max_channel_count; ++im_channel_index) {
        // if this is a udp gate request it has to be skipped
        if (adsr_udp_subchannels[im_channel_index] != NULL) {
            continue;
        }
       
        // get the request
        ads_request = m_get_udp_request(im_channel_index);
        if (ads_request) {
            // calculate the id - MS 22.04.15 only calculate the id if we need to! (mostly avoids 63 useless calls to convert channel!)
            ch_channel_id = m_convert_to_channel_id(im_channel_index);

            ads_request->iec_sdh_udpr1 = ied_sdh_udpr1_update_recv;
            // update the request
            ads_wsp_helper->m_cb_udp_request(ads_request);
            ds_hstring hstr_text1(ads_wsp_helper);
            ds_hstring hstr_buffer(ads_wsp_helper);
            dsd_sdh_udp_recbuf_1 *ads_buffer = ads_request->adsc_recb_1;
            int im_length = 0;
            // loop until last buffer
            while (ads_buffer) {
                
                //if we are in a disconnected state we need to discard UDP data
                if (ie_state != SDH_HOBPHONE_STATE_DISCONNECTED)
                {
                    // loop over all buffers  
                    while (ads_buffer) {                   
                        if (ads_buffer->imc_len_data != 0) {
                            // TODO when multiple channel types are implemented this has to be checked, not now
                            hstr_text1.m_write("2");
                            hstr_text1.m_write(&ch_channel_id, 1);
                            hstr_text1.m_write(
                                ads_buffer->achc_data, ads_buffer->imc_len_data);
                            im_length = hstr_text1.m_get_len();
                            if (im_length > 2) {
                                // debug
    #ifdef DUMP
                                unsigned int im_seqnum = (*(ads_buffer->achc_data + 2) & 0xff) << 8;
                                im_seqnum |= *(ads_buffer->achc_data + 3) &0xff;
                                SYSTEMTIME time;
                                GetSystemTime(&time);
                                WORD millis = (time.wSecond * 1000) + time.wMilliseconds;
                                printf("### packet %u received at %ld\r\n", im_seqnum, millis);
                                // /debug
    #endif
                                hstr_buffer.m_write_nhasn(im_length);
                                hstr_buffer += hstr_text1;
                                // TODO remove and send only gather
                                
                                ads_wsp_helper->m_send_data(hstr_buffer.m_get_ptr(), hstr_buffer.m_get_len());
    #ifdef DUMP      
                                // debug
                                fstream file;
                                std::stringstream name;
                                name << "dump_";
                                name << im_seqnum;
                                file.open(name.str().c_str(), ios::out);
                                char *data = hstr_buffer.m_get_ptr();
                                for (int i = 0; i < hstr_buffer.m_get_len(); i++) {
                                    file << *(data + i);
                                }
                                file.close();
                                // /debug
    #endif
                            }
                            hstr_text1.m_reset();
                            hstr_buffer.m_reset();
                        }
                        ads_buffer = ads_buffer->adsc_next;
                    }
                
                    ads_request->iec_sdh_udpr1 = ied_sdh_udpr1_free_buffer;
                    ads_wsp_helper->m_cb_udp_request(ads_request);
                    ads_request->iec_sdh_udpr1 = ied_sdh_udpr1_update_recv;
                    ads_wsp_helper->m_cb_udp_request(ads_request);
                }
                else
                {
                    ads_request->iec_sdh_udpr1 = ied_sdh_udpr1_free_buffer;
                    ads_wsp_helper->m_cb_udp_request(ads_request);
                    ads_buffer = NULL;//ads_buffer->adsc_next;
                }
            }
        }
    }
    return SDH_HOBPHONE_STATUS_OK;
}

int ds_hobphone2::m_get_free_channel_index() {
    // loop over all channels
    for (int im_i = 0; im_i < im_max_channel_count; im_i++) {
        // if no request is found return the channel
        if (adsr_udp_requests[im_i] == NULL) {
            return im_i;
        }
    }
    // if no channel left return -1
    return -1;
}

void ds_hobphone2::m_write_ineta(ds_hstring &hstrp_text, const dsd_ineta_container &dsp_ineta) {
    switch (dsp_ineta.usc_family) {
        case AF_INET:
            {
                unsigned char const * ach_digit = dsp_ineta.chrc_ineta;
                hstrp_text.m_writef("%u.%u.%u.%u", *ach_digit, *(ach_digit + 1), *(ach_digit + 2), *(ach_digit + 3));
            }
            break;
        case AF_INET6:
            {
                unsigned char const * ach_digit = dsp_ineta.chrc_ineta;
                hstrp_text.m_writef("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    *ach_digit, *(ach_digit + 1), *(ach_digit + 2),*(ach_digit + 3),
                    *(ach_digit + 4), *(ach_digit + 5), *(ach_digit + 6),*(ach_digit + 7),
                    *(ach_digit + 8), *(ach_digit + 9), *(ach_digit + 10),*(ach_digit + 11),
                    *(ach_digit + 12), *(ach_digit + 13), *(ach_digit + 14),*(ach_digit + 15));
            }
            break;
        default:
            ads_wsp_helper->m_log(ied_sdh_log_error, "ds_hobphone2.cpp could not parse socket address, illegal type");
    }
}

ied_sdh_hobphone_status ds_hobphone2::m_set_sip_request(int imp_channel_index, dsd_sdh_sip_requ_1 *adsp_sip_request) {
    // get the request
    dsd_sdh_sip_requ_1 *ads_sip_request = m_get_sip_request(imp_channel_index);
    // if it exists remove the old
    if (ads_sip_request) {
        ied_sdh_hobphone_status ie_retval = m_close_sip_request(imp_channel_index);
        if (ie_retval != SDH_HOBPHONE_STATUS_OK) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_SETTING_SIP_REQUEST,__LINE__,&imp_channel_index);
            return SDH_HOBPHONE_STATUS_ERROR_SETTING_SIP_REQUEST;
        }
        ie_retval = m_free_sip_request(imp_channel_index);
        if (ie_retval != SDH_HOBPHONE_STATUS_OK) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_SETTING_SIP_REQUEST,__LINE__,&imp_channel_index);
            return SDH_HOBPHONE_STATUS_ERROR_SETTING_SIP_REQUEST;
        }
    }
    // set the request
    adsr_sip_requests[imp_channel_index] = adsp_sip_request;
    return SDH_HOBPHONE_STATUS_OK;
}

ied_sdh_hobphone_status ds_hobphone2::m_set_udp_request(int imp_channel_index, dsd_sdh_udp_requ_1 *adsp_udp_request) {
    // get the request
    dsd_sdh_udp_requ_1 *ads_udp_request = m_get_udp_request(imp_channel_index);
    // if it exists remove the old
    if (ads_udp_request) {
        ied_sdh_hobphone_status ie_retval = m_close_udp_request(imp_channel_index);
        if (ie_retval != SDH_HOBPHONE_STATUS_OK) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_SETTING_UDP_REQUEST,__LINE__,0);
            return SDH_HOBPHONE_STATUS_ERROR_SETTING_UDP_REQUEST;
        }
        ie_retval = m_free_udp_request(imp_channel_index);
        if (ie_retval != SDH_HOBPHONE_STATUS_OK) {
            m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_SETTING_UDP_REQUEST,__LINE__,0);
            return SDH_HOBPHONE_STATUS_ERROR_SETTING_UDP_REQUEST;
        }
    }
    // set the request
    adsr_udp_requests[imp_channel_index] = adsp_udp_request;
    return SDH_HOBPHONE_STATUS_OK;
}

dsd_sdh_sip_requ_1 * ds_hobphone2::m_get_sip_request(int imp_channel_index) {
    // range check
    if (0 > imp_channel_index || imp_channel_index >= im_max_account_count) {
        return NULL;
    }
    return adsr_sip_requests[imp_channel_index];
}

dsd_sdh_udp_requ_1 * ds_hobphone2::m_get_udp_request(int imp_channel_index) {
    // range check
    if (0 > imp_channel_index || imp_channel_index >= im_max_channel_count) {
        return NULL;
    }
    return adsr_udp_requests[imp_channel_index];
}

ied_sdh_hobphone_status ds_hobphone2::m_close_sip_request(int imp_channel_index) {
    dsd_sdh_sip_requ_1 *ads_sip_request = m_get_sip_request(imp_channel_index);
    char ch_channel_id = m_convert_to_channel_id(imp_channel_index);
    if (!ads_sip_request) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_NO_REQUEST,__LINE__, &ch_channel_id);
        return SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_NO_REQUEST;
    }
    ads_sip_request->iec_sdh_sipr1 = ied_sdh_sipr1_close;
    if (!ads_wsp_helper->m_cb_sip_request(ads_sip_request)) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_CLOSE_FAILED,__LINE__, &ch_channel_id);
        return SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_CLOSE_FAILED;
    }
    return SDH_HOBPHONE_STATUS_OK;
}

ied_sdh_hobphone_status ds_hobphone2::m_close_udp_request(int imp_channel_index) {
    dsd_sdh_udp_requ_1 *ads_udp_request = m_get_udp_request(imp_channel_index);
    char ch_channel_id = m_convert_to_channel_id(imp_channel_index);
    if (!ads_udp_request) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_NO_REQUEST,__LINE__, &ch_channel_id);
        return SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_NO_REQUEST;
    }
    // close the subchannel if existing
    if (adsr_udp_subchannels[imp_channel_index] != NULL) {
        // return and status are ignored - anyway we shut down
        ds_udp_gate.iec_cmd_ug = ied_cmd_uga_subch_close;
        ds_udp_gate.vpc_udpr_handle = ads_udp_request;
        ds_udp_gate.vpc_ug_subch_handle = adsr_udp_subchannels[imp_channel_index];
        ads_wsp_helper->m_cb_udp_gate(&ds_udp_gate);
    }
    // close the request itself
    ads_udp_request->iec_sdh_udpr1 = ied_sdh_udpr1_close;
    if (!ads_wsp_helper->m_cb_udp_request(ads_udp_request)) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_CLOSE_FAILED,__LINE__, &ch_channel_id);
        return SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_CLOSE_FAILED;
    }
    return SDH_HOBPHONE_STATUS_OK;
}


BOOL ds_hobphone2::m_parse_ineta( const char* ach_ineta, int in_length,
                                 dsd_ineta_container &dsp_ineta )
{
    ///*
    //this function decides whether a given ineta (as string)
    //is an IPv4 or IPv6 ineta.

    //Valid addresses should look like:
    //IPv4: 123.111.222.101
    //IPv6: 2001:0db8:85a3::1319:8a2e:0370:7344
    //MS 23.07.2013 - we also have to support DNS names since these can be used in the PBX configurations
    //*/

    //// initialize some variables:
    BOOL                bol_valid    = TRUE;        // valid ineta?
    int                 inl_ret;                    // return value
    //int                 inl_pos;                    // current pos in input
    //int                 inl_dots     = 0;           // count dots
    //int                 inl_two_dots = 0;           // count double dots "::"
    //int                 inl_nums     = 0;           // count numbers between dots
    //int                 inl_value;                  // value for checking
    //unsigned short int  uisl_type    = 0;           // type of ineta

    ////-------------------------------------------
    //// do IPv4 or IPv6 validation:
    ////-------------------------------------------
    //for ( inl_pos = 0; inl_pos < in_length; inl_pos++ ) {
    //    if ( ach_ineta[inl_pos] == '.' ) {
    //        uisl_type = AF_INET;
    //        break;
    //    } else if (  ach_ineta[inl_pos] == ':' ) {
    //        uisl_type = AF_INET6;
    //        break;
    //    }
    //}

    //if ( uisl_type == AF_INET ) {
    //    //---------------------------------------
    //    // do IPv4 validation:
    //    //---------------------------------------
    //    for ( inl_pos = 0; inl_pos < in_length; inl_pos++ ) {
    //        switch ( ach_ineta[inl_pos] ) {
    //            case '.': 
    //                inl_dots++;
    //                if (    inl_dots < 4     /* IPv4 has exact 3 dots      */
    //                    && inl_nums < 4     /* max 3 numbers between dots */
    //                    && inl_nums > 0     /* min 1 number between dots  */ )
    //                {
    //                    inl_value = atoi(&ach_ineta[inl_pos - inl_nums]);  
    //                    if ( inl_value < 0 || inl_value > 255 ) {
    //                        break;
    //                    }
    //                    inl_nums = 0;
    //                    continue;
    //                }
    //                break; // otherwise error
    //            case '0':
    //            case '1':
    //            case '2':
    //            case '3':
    //            case '4':
    //            case '5':
    //            case '6':
    //            case '7':
    //            case '8':
    //            case '9':
    //                inl_nums++;
    //                if ( inl_nums < 4 /* max 3 numbers between dots */ ) {
    //                    continue;
    //                }
    //                break; // otherwise error
    //            default:
    //                // other char as number, '.' or ':' -> invalid address
    //                break; 
    //        }
    //        bol_valid = FALSE; // an error occurred
    //        break;
    //    } // end of for loop

    //    if ( bol_valid == TRUE ) {
    //        if (    inl_dots == 3    /* exactly 3 dots             */
    //            && inl_nums < 4     /* max 3 numbers between dots */
    //            && inl_nums > 0     /* min 1 number between dots  */ )
    //        {
    //            inl_value = atoi(&ach_ineta[inl_pos - inl_nums]);    
    //            if ( inl_value < 0 || inl_value > 255 ) {
    //                bol_valid = FALSE;
    //            }
    //        }
    //    }

    //} // end of IPv4 validation

    //else if ( uisl_type == AF_INET6 ) {
    //    //---------------------------------------
    //    // do IPv6 validation:
    //    //---------------------------------------        
    //    for ( inl_pos = 0; inl_pos < in_length; inl_pos++ ) {
    //        switch ( ach_ineta[inl_pos] ) {
    //            case ':':
    //                inl_dots++;
    //                if (    inl_two_dots < 2 /* "::" is allowed only once  */
    //                    && inl_dots < 8     /* max 7 dots                 */
    //                    && inl_nums < 5     /* max 4 numbers between dots */ )
    //                {
    //                    if ( inl_nums == 0 ) {
    //                        inl_two_dots++;
    //                    }
    //                    inl_nums = 0;
    //                    continue;
    //                }
    //                break; // otherwise error
    //            case '0':
    //            case '1':
    //            case '2':
    //            case '3':
    //            case '4':
    //            case '5':
    //            case '6':
    //            case '7':
    //            case '8':
    //            case '9':
    //            case 'a':
    //            case 'b':
    //            case 'c':
    //            case 'd':
    //            case 'e':
    //            case 'f':
    //            case 'A':
    //            case 'B':
    //            case 'C':
    //            case 'D':
    //            case 'E':
    //            case 'F':
    //                inl_nums++;
    //                if ( inl_nums < 5     /* max 4 numbers between dots */ ) {
    //                    continue;
    //                }
    //                break; // otherwise error
    //            default:
    //                // other char as number or ':' -> invalid address
    //                break; 
    //        }
    //        bol_valid = FALSE; // an error occurred
    //        break;
    //    } // end of for loop

    //    if ( bol_valid == TRUE ) {
    //        if (    inl_two_dots < 2 /* "::" is allowed only once  */
    //            && inl_dots < 8     /* max 7 dots                 */
    //            && inl_nums < 5     /* max 4 numbers between dots */ )
    //        {
    //        } else {
    //            bol_valid = FALSE;
    //        }
    //    }
    //} // end of IPv6 validation
    //else {
    //    return FALSE;
    //}

    //-------------------------------------------
    // fill output structure:
    //-------------------------------------------
    if ( bol_valid == TRUE ) {
        struct addrinfo  dsl_addr_hints;
        struct addrinfo* adsl_addrinfo = NULL;
        ds_hstring dsl_ineta( ads_wsp_helper, ach_ineta, in_length );

        memset( &dsl_addr_hints, 0, sizeof(dsl_addr_hints) );
       // dsl_addr_hints.ai_family = uisl_type;

        inl_ret = getaddrinfo( dsl_ineta.m_get_ptr(), NULL, &dsl_addr_hints, &adsl_addrinfo );
        if (    inl_ret       != 0
            || adsl_addrinfo == NULL ) {
                return FALSE;
        }

        switch ( adsl_addrinfo->ai_family ) {
            case AF_INET:
                dsp_ineta.usc_family = AF_INET;
                dsp_ineta.usc_length = 4;
                memcpy( dsp_ineta.chrc_ineta,
                    &(((struct sockaddr_in*)adsl_addrinfo->ai_addr)->sin_addr.s_addr),
                    dsp_ineta.usc_length );
                break;

            case AF_INET6:
                dsp_ineta.usc_family = AF_INET6;
                dsp_ineta.usc_length = 16;
                memcpy( dsp_ineta.chrc_ineta,
                    &(((struct sockaddr_in6*)adsl_addrinfo->ai_addr)->sin6_addr),
                    dsp_ineta.usc_length );
                break;

            default:
                bol_valid = FALSE;
                break;
        }

        freeaddrinfo( adsl_addrinfo );
    }

    return bol_valid;
} // end of ds_settcma::m_parse_ineta

void ds_hobphone2::m_free_gatherchain(dsd_gather_i_1 *adsp_gather) {
    if (adsp_gather == NULL) {
        return;
    }
    dsd_gather_i_1 *ads_gather = adsp_gather;
    dsd_gather_i_1 *ads_next;
    do {
        ads_next = ads_gather->adsc_next;
        ads_wsp_helper->m_cb_free_memory(ads_gather, sizeof(dsd_gather_i_1));
        ads_gather = ads_next;
    } while (ads_gather);
}

ied_sdh_hobphone_status ds_hobphone2::m_free_sip_request(int imp_channel_index) {
    dsd_sdh_sip_requ_1 *ads_request = m_get_sip_request(imp_channel_index);
    char ch_channel_id = m_convert_to_channel_id(imp_channel_index);
    if (ads_request == NULL) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_FREEING_SIP_REQUEST_NO_REQUEST,__LINE__, &ch_channel_id);
        return SDH_HOBPHONE_STATUS_ERROR_FREEING_SIP_REQUEST_NO_REQUEST;
    }
    ads_wsp_helper->m_cb_free_memory(ads_request->ac_sip_ident, ads_request->imc_len_sip_ident);
    ads_wsp_helper->m_cb_free_memory(ads_request, sizeof(dsd_sdh_sip_requ_1));
    return SDH_HOBPHONE_STATUS_OK;
}

ied_sdh_hobphone_status ds_hobphone2::m_free_udp_request(int imp_channel_index) {
    dsd_sdh_udp_requ_1 *ads_request = m_get_udp_request(imp_channel_index);
    char ch_channel_id = m_convert_to_channel_id(imp_channel_index);
    if (ads_request == NULL) {
        m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_FREEING_UDP_REQUEST_NO_REQUEST,__LINE__, &ch_channel_id);
        return SDH_HOBPHONE_STATUS_ERROR_FREEING_UDP_REQUEST_NO_REQUEST;
    }
    ads_wsp_helper->m_cb_free_memory(ads_request->achc_soa_bind, sizeof(sockaddr_in6));
    ads_wsp_helper->m_cb_free_memory(ads_request->achc_sockaddr, sizeof(sockaddr_in6));
    ads_wsp_helper->m_cb_free_memory(ads_request, sizeof(dsd_sdh_udp_requ_1));
    adsr_udp_requests[imp_channel_index] = NULL;
    adsr_udp_subchannels[imp_channel_index] = NULL;
    return SDH_HOBPHONE_STATUS_OK;
}

const char * const ds_hobphone2::m_get_exception_message(ied_ret_sip_requ_1_def iep_val) {
    switch (iep_val)
    {
        
        case ied_ret_sipr1_net_err:                   /* SIP request network error */
            return "Network error";
        case ied_ret_sipr1_ident_invalid:             /* SIP ident invalid parameter */
            return "Invalid ident parameter";
        case ied_ret_sipr1_entry_double:              /* SIP entry defined double */
            return "Running HOBPhone session found";
        case ied_ret_sipr1_send_error:        /* SIP send failed         */
            return "SIP send failed";
        default: return "";
    }
}
const char * const ds_hobphone2::m_get_exception_message(ied_sdh_hobphone_status iep_status) {
    
    switch (iep_status) 
    {
        // general
    case SDH_HOBPHONE_STATUS_UNKNOWN_CHANNEL_TYPE:
        return "Unknown channel type: %c, discarded %d\r\n";
    case SDH_HOBPHONE_ILLEGAL_STATE:
        return "Illegal state: %u\r\n";
    case SDH_HOBPHONE_STATUS_SEND_FAILED:
        return "Send Failed!\r\n";
        // system messages
    case SDH_HOBPHONE_STATUS_INVALID_SYSTEM_MESSAGE:
        return "Invalid system message: %s\r\n";
    case SDH_HOBPHONE_STATUS_UNSUPPROTED_IP_VERSION:
        return "Unsupported IP length: %d .";
        // get configuration
    case SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_INVALID_INETA:
        return "Exception getting config: invalid ineta: %s ";
    case SDH_HOBPHONE_STATUS_ERROR_REGISTERING_SIP_REQUEST:
        return "Exception registering SIP request: channel %c , %s ";
        // pbx configuration
    case SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_SOURCE:
        return "Exception getting configuration source. ";
    case SDH_HOBPHONE_STATUS_INVALID_LDAP_SRV:
        return "Invalid LDAP server. ";
    case SDH_HOBPHONE_STATUS_ERROR_ACCESSING_LDAP:
        return "Exception accessing LDAP: %s ";
    case SDH_HOBPHONE_STATUS_ERROR_GETTING_PBX_CONFIG:
        return "Exception reading PBX configuration from LDAP: %s ";
    case SDH_HOBPHONE_STATUS_NO_PBX_CONFIG_FOUND:
        return "No PBX configuration found. ";
    case SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG:
        return "Invalid PBX configuration. ";
    case SDH_HOBPHONE_STATUS_EMPTY_PBX_CONFIG:
        return "Empty PBX configuration. ";
    case SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_NAME:
        return "Invalid PBX configuration: no name. ";
    case SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_INETA:
        return "Invalid PBX configuration: no INETA. ";
    case SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_PORT:
        return "Invalid PBX configuration: no port. ";
    case SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_UDP_GW:
        return "Invalid PBX configuration: no UDP gateway. ";
        // user configuration
    case SDH_HOBPHONE_STATUS_NO_USER_CONFIG:
        return "No user configuration found. ";
    case SDH_HOBPHONE_STATUS_ERROR_GETTING_PHONE_CONFIG:
        return "Exception reading phone configuration: %s ";
    case SDH_HOBPHONE_STATUS_NO_PHONE_CONFIG:
        return "No phone configuration found. ";
    case SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG:
        return "Invalid phone configuration. ";
    case SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_NO_IDENT:
        return "Invalid phone configuration: no ident. ";
    case SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_NO_PBX_PROFILE_DEFINED:
        return "Invalid phone configuration: no pbx profile. ";
    case SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_PBX_PROFILE_NOT_FOUND:
        return "Invalid phone configuration: pbx profile not found. ";
        // create channel
    case SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_TYPE:
        return "Invalid create channel message: no type. ";
    case SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_UNSUPPROTED_TYPE:
        return "Invalid create channel message: unsupported type %d . ";
    case SDH_HOBPHONE_STATUS_ERROR_CREATING_CHANNEL_NO_FREE_CHANNEL:
        return "Exception creating channel: no free channel. ";
    case SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_CALL_ID:
        return "Invalid create channel message: no call id. ";
    case SDH_HOBPHONE_STATUS_INVALID_UDP_GW_CONFIGURATION:
        return "Invalid UDP gateway configuration: no configuration. ";
    case SDH_HOBPHONE_STATUS_ERROR_REGISTERING_UDP_REQUEST:
        return "Exception registering UDP request: %c . ";
        // set channel
    case SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_INVALID_CHANNEL_TYPE:
        return "Invalid set channel message: invalid channel type %s ";
    case SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE:
        return "Invalid set channel message: unsupported channel type %d . ";
    case SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_INVALID_CHANNEL:
        return "Invalid set channel message: invalid channel %c . ";
    case SDH_HOBPHONE_STATUS_ERROR_SETTING_CHANNEL_NO_CHANNEL:
        return "Exception setting channel: no channel %c . ";
        // remove channel
    case SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_INVALID_CHANNEL_TYPE:
        return "Invalid remove channel message: invalid channel type %s ";
    case SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE:
        return "Invalid remove channel message: unsupported channel type %d . ";
    case SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_INVALID_CHANNEL:
        return "Invalid remove channel message: invalid channel %c . ";
    case SDH_HOBPHONE_STATUS_ERROR_REMOVING_CHANNEL_NO_CHANNEL:
        return "Exception removing channel: no channel %c . ";
    case SDH_HOBPHONE_STATUS_ERROR_FREEING_SIP_REQUEST_NO_REQUEST:
        return "Exception freeing SIP request: no request %c . ";
    case SDH_HOBPHONE_STATUS_ERROR_FREEING_UDP_REQUEST_NO_REQUEST:
        return "Exception freeing UDP request: no request %c . ";
        // redirect
    case SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_SIP_TO_PBX_NO_REQUEST:
        return "Exception redirecting SIP to PBX: no request %c . ";
    case SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_UDP_TO_PBX_NO_REQUEST:
        return "Exception redirecting UDP to PBX: no request %c . ";
        // close request
    case SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_NO_REQUEST:
        return "Exception closing SIP request: no request %c . ";
    case SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_NO_REQUEST:
        return "Exception closing UDP request: no request %c . ";
    case SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_CLOSE_FAILED:
        return "Exception closing SIP request: close failed channel %c . ";
    case SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_CLOSE_FAILED:
        return "Exception closing UDP request: close failed channel %c . ";
        // NHASN
    case SDH_HOBPHONE_STATUS_EMPTY_NHASN:
        return "Empty NHASN: %d . ";
    case SDH_HOBPHONE_STATUS_INCOMPLETE_NHASN:
        return "Incomplete NHASN: length %d . ";
    case SDH_HOBPHONE_STATUS_NHASN_OUT_OF_RANGE:
        return "NHASN out of range: %d . ";
        // set request - secondary exceptions
    case SDH_HOBPHONE_STATUS_ERROR_SETTING_SIP_REQUEST:
        return "Error setting SIP request: cause %u . ";
    case SDH_HOBPHONE_STATUS_ERROR_SETTING_UDP_REQUEST:
        return "Error setting UDP request: cause %u . ";
    case SDH_HOBPHONE_STATUS_ERROR_GETTING_RANDOM:
        return "Error getting random for UDP gate. ";
    case SDH_HOBPHONE_STATUS_ERROR_CREATING_UPD_GATE:
        return "Error creating UDP gate. ";
    case SDH_HOBPHONE_STATUS_ERROR_UNKNOWN_UDPGATE_STATE:
        return "Error in UDP Gate state. ";
    case SDH_HOBPHONE_STATUS_UDP_GATE_NOT_CONFIGURED:
        return "UDP gate not configured. ";
    case SDH_HOBPHONE_STATUS_INVALID_ENABLE_UDP_GATE_MESSAGE:
        return "Invalid 'ENABLE UDP GATE' message. ";
    case SDH_HOBPHONE_STATUS_UDP_GATE_ENABLED:
        return "UDP gate enabled. ";
    case SDH_HOBPHONE_STATUS_UDP_GATE_DISABLED:
        return "UDP gate disabled. ";
    case SDH_HOBPHONE_STATUS_ERROR_INVALID_STATE_ON_ENABLE_UDP_GATE:
        return "Invalid call to enable UDP gate. ";
    case SDH_HOBPHONE_STATUS_ERROR_CREATING_UDP_GATE_SUBCHANNEL:
        return "Error creating subchannel for UDP gate. ";
    case SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_GATE_SUBCHANNEL:
        return "Error closing subchannel for UDP gate. ";
    case SDH_HOBPHONE_STATUS_ERROR_ACTIVE_INSTANCE_ON_CLUSTER:
        return "An active instance was found on the cluster. ";
    case SDH_HOBPHONE_STATUS_ERROR_CREATING_CMA:
        return "Error creating CMA. ";
    case SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR:
        return "Reverse Phone Lookup failure. ";
    case SDH_HOBPHONE_STATUS_KEEPALIVE_ERROR:
        return "Keepalive Error! ";
    case SDH_HOBPHONE_STATUS_VERSION_ERROR:
        return "Client Version Error ";
    default:
        return "Unknown exception. ";
    }
}
//TODO sockaddr_storage can probably be used to completely replace dsd_ineta_container
ied_sdh_hobphone_status ds_hobphone2::m_get_ineta_container(dsd_ineta_container &dsp_ineta, sockaddr_storage* adsp_sockaddr) {
    switch (adsp_sockaddr->ss_family) {
        case AF_INET:
            {
                dsp_ineta.usc_family = AF_INET;
                dsp_ineta.usc_length = 4;
                sockaddr_in *ads_sock = reinterpret_cast<sockaddr_in *>(adsp_sockaddr);
                memcpy(dsp_ineta.chrc_ineta, &ads_sock->sin_addr, 4);
                dsp_ineta.us_port = ntohs(ads_sock->sin_port);
            }
            break;
        case AF_INET6:
            {
                dsp_ineta.usc_family = AF_INET6;
                dsp_ineta.usc_length = 16;
                sockaddr_in6 *ads_sock = reinterpret_cast<sockaddr_in6 *>(adsp_sockaddr);
                memcpy(dsp_ineta.chrc_ineta, &ads_sock->sin6_addr, 16);
                dsp_ineta.us_port = ntohs(ads_sock->sin6_port);
            }
            break;
        default:
            m_update_exception_message(SDH_HOBPHONE_STATUS_UNSUPPROTED_IP_VERSION,__LINE__, &(adsp_sockaddr->ss_family));
            return SDH_HOBPHONE_STATUS_UNSUPPROTED_IP_VERSION;
    }
    return SDH_HOBPHONE_STATUS_OK;
}

void ds_hobphone2::m_log_error(ied_sdh_hobphone_status iep_status, ds_hstring& hstrp_ex_message) {
    ds_hstring hstr_text(ads_wsp_helper);
    hstr_text.m_writef(SDH_ERROR(iep_status), hstrp_ex_message.m_get_ptr());
    ads_wsp_helper->m_log(ied_sdh_log_error, hstr_text.m_const_str());
}

void ds_hobphone2::m_log_warning(ied_sdh_hobphone_status iep_status, ds_hstring& hstrp_ex_message) {
    ds_hstring hstr_text(ads_wsp_helper);
    hstr_text.m_writef(SDH_WARN(iep_status), hstrp_ex_message.m_get_ptr());
    ads_wsp_helper->m_log(ied_sdh_log_warning, hstr_text.m_const_str());
}

void ds_hobphone2::m_log_warning(const dsd_const_string& chrp_message)
{
    ads_wsp_helper->m_log(ied_sdh_log_warning, chrp_message);
}

void ds_hobphone2::m_log_info(ied_sdh_hobphone_status iep_status, ds_hstring& hstrp_ex_message, const char* achp_extra /*=NULL*/) {
    ds_hstring hstr_text(ads_wsp_helper);
    if (achp_extra)
        hstr_text.m_write_zeroterm(achp_extra);
    hstr_text.m_writef(SDH_INFO(iep_status), hstrp_ex_message.m_get_ptr());
    ads_wsp_helper->m_log(ied_sdh_log_info, hstr_text.m_const_str());
}

void ds_hobphone2::m_log_info(ied_sdh_hobphone_status iep_status, const dsd_const_string& achp_message) {
    ads_wsp_helper->m_log(ied_sdh_log_info, achp_message);
}

//static void m_writetolog(int imp_level, char* achp_message, byte chrp_other[],int imp_start, int imp_len)
#define m_writetolog(level,msg,other,start,len) m_log_info(SDH_HOBPHONE_STATUS_SIP_PARSER, msg)



void ds_hobphone2::m_update_exception_message(ied_sdh_hobphone_status iep_status, int imp_line, const void * const avop_param, const void * const avop_param2 /*=NULL*/) {
    hstr_exception_message.m_reset();
    switch (iep_status) 
    {
        // general
         
    case SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_UNSUPPROTED_TYPE:
    case SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_INVALID_CHANNEL:    
    case SDH_HOBPHONE_STATUS_ERROR_SETTING_CHANNEL_NO_CHANNEL:
    case SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_INVALID_CHANNEL:
    case SDH_HOBPHONE_STATUS_ERROR_REMOVING_CHANNEL_NO_CHANNEL:
    case SDH_HOBPHONE_STATUS_ERROR_FREEING_SIP_REQUEST_NO_REQUEST:    
    case SDH_HOBPHONE_STATUS_ERROR_FREEING_UDP_REQUEST_NO_REQUEST:
    case SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_SIP_TO_PBX_NO_REQUEST:
    case SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_UDP_TO_PBX_NO_REQUEST:
    case SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_NO_REQUEST:
    case SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_NO_REQUEST:
    case SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_CLOSE_FAILED:
    case SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_CLOSE_FAILED:
        hstr_exception_message.m_writef(m_get_exception_message(iep_status),avop_param ? *((char*)avop_param) : ' ');
        break;
    case SDH_HOBPHONE_STATUS_ERROR_REGISTERING_SIP_REQUEST:
        if (avop_param2 == NULL)
            hstr_exception_message.m_writef(m_get_exception_message(iep_status),avop_param ? *((char*)avop_param) : ' ');
        else
            hstr_exception_message.m_writef(m_get_exception_message(iep_status),avop_param ? *((char*)avop_param) : ' ', m_get_exception_message(*(ied_ret_sip_requ_1_def*)avop_param2));
        break;
    case SDH_HOBPHONE_ILLEGAL_STATE:    
    case SDH_HOBPHONE_STATUS_ERROR_REGISTERING_UDP_REQUEST:
    case SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE:
    case SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE:
    case SDH_HOBPHONE_STATUS_EMPTY_NHASN:
    case SDH_HOBPHONE_STATUS_INCOMPLETE_NHASN:
    case SDH_HOBPHONE_STATUS_NHASN_OUT_OF_RANGE:
    case SDH_HOBPHONE_STATUS_ERROR_SETTING_SIP_REQUEST:        
    case SDH_HOBPHONE_STATUS_ERROR_SETTING_UDP_REQUEST:       
    case SDH_HOBPHONE_STATUS_SEND_FAILED:
    case SDH_HOBPHONE_STATUS_UNKNOWN_CHANNEL_TYPE:  
        hstr_exception_message.m_writef(m_get_exception_message(iep_status),avop_param ? *((char*)avop_param) : ' ',avop_param2 ? *((int*)avop_param2) : 0);
        break;
    case SDH_HOBPHONE_STATUS_UNSUPPROTED_IP_VERSION:
        hstr_exception_message.m_writef(m_get_exception_message(iep_status),avop_param ? *((short*)avop_param) : 0);
        break; 
    default:
        hstr_exception_message.m_writef(m_get_exception_message(iep_status), avop_param);
        break;


    }  

    hstr_exception_message.m_writef(" %u",imp_line);
    m_log_error(iep_status, hstr_exception_message);

    
}
 
void ds_hobphone2::m_update_exception_message_l(ied_sdh_hobphone_status iep_status,int imp_line, const char * achp_param,
                                              int imp_length) 
{
    hstr_exception_message.m_reset();
    hstr_exception_message.m_write_zeroterm(m_get_exception_message(iep_status));
    hstr_exception_message.m_write(achp_param, imp_length);
    hstr_exception_message.m_writef(" %u",imp_line);
    m_log_error(iep_status, hstr_exception_message);
}

void ds_hobphone2::m_update_exception_message_l(ied_sdh_hobphone_status iep_status,int imp_line, const dsd_const_string achp_param) 
{
    hstr_exception_message.m_reset();
    hstr_exception_message.m_write_zeroterm(m_get_exception_message(iep_status));
    hstr_exception_message.m_write(achp_param);
    hstr_exception_message.m_writef(" %u",imp_line);
    m_log_error(iep_status, hstr_exception_message);
}

void ds_hobphone2::m_update_exception_message(ied_sdh_hobphone_status iep_status, int imp_line,ds_gather_iterator& dsp_it) {
    ds_hstring hstr_temp(ads_wsp_helper);
    ds_gather_iterator ds_it(dsp_it.m_get_current_gather(), dsp_it.m_get_remaining_length());
    while (ds_it.m_has_more()) {
        const char * ach_char = ds_it.m_next();
        if (*ach_char == 0) {
            break;
        }
        hstr_temp.m_write(ach_char, 1);
    }
    hstr_exception_message.m_reset();
    hstr_exception_message.m_writef(" %u ",imp_line);
    hstr_exception_message += hstr_temp;

    m_log_error(iep_status, hstr_exception_message);
}

char ds_hobphone2::m_convert_to_channel_id(int imp_index) {

#ifdef DEBUG_CHANNELS
//DEBUG CHANNELS  
   /* hstr_channels.m_reset();
    hstr_channels.m_writef("Converting index %d to channel",imp_index);
    m_log_warning(hstr_channels.m_get_ptr());*/
#endif
    // 0 - 25 (0x1A) -> 0x41
    if (0 <= imp_index && imp_index < 0x1A) {
        return imp_index + 0x41;
    }
    // 26 - 51 (0x1A - 0x33) -> 0x61 - 0x1A = 0x47
    if (0x1A <= imp_index && imp_index < 0x34) {
        return imp_index + 0x47;
    }
    // 52 - 61 (0x34 - 0x3d) -> 0
    if (0x34 <= imp_index && imp_index < 0x3e) {
        return imp_index -4;
    }
    // 62
    if (0x3e == imp_index) {
        return 0x2B;
    }
    // 63
    if (0x3f == imp_index) {
        return 0x2F;
    }
    return -1;
}

int ds_hobphone2::m_get_index(char chp_channel_id) {

#ifdef DEBUG_CHANNELS
//DEBUG CHANNELS  
  /*  hstr_channels.m_reset();
    hstr_channels.m_writef("getting index for channel %c",chp_channel_id);
    m_log_warning(hstr_channels.m_get_ptr());*/
#endif
    // 0x41 - 0x5a
    if (0x41 <= chp_channel_id && chp_channel_id <0x5b) {
        return chp_channel_id - 0x41;
    }
    if (0x61 <= chp_channel_id && chp_channel_id < 0x7b) {
        return chp_channel_id - 0x47;
    }
    if (0x30 <= chp_channel_id && chp_channel_id < 0x3a) {
        return chp_channel_id + 4;
    }
    if (0x2b == chp_channel_id) {
        return 0x3e;
    }
    if (0x2f == chp_channel_id) {
        return 0x3f;
    }
    return -1;


}


ied_sdh_hobphone_status ds_hobphone2::m_system_message_search_number(ds_gather_iterator &dsp_it)
{
    //parse query
    ds_hstring hstr_type(ads_wsp_helper);
    dsp_it.m_get_line(hstr_type);
    const char* achl_number;
    int iml_numlen;
    if (hstr_type.m_starts_with("number:"))
    {
        achl_number = hstr_type.m_get_from(7);
        iml_numlen = hstr_type.m_get_len() - 7;
    }
    else
    {
        m_update_exception_message_l(SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR,__LINE__,"Incorrectly formatted request");
        return SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR; //incorrectly formatted request - ignore
    }
    ds_hstring hstr_number(ads_wsp_helper);
    for (int i=0; i<iml_numlen;i++)
    {
        hstr_number.m_write("*");
        hstr_number += achl_number[i];
    }
        
    //do search

    // get user data
    dsd_sdh_ident_set_1 ds_ident;
    ads_wsp_helper->m_cb_get_ident(&ds_ident);
    ds_usercma dsl_ucma;
    if (!ds_usercma::m_get_usercma( ads_wsp_helper, &dsl_ucma )) {
        //m_update_exception_message(SDH_HOBPHONE_STATUS_NUMSEARCH_LDAP_ERROR, NULL);
        m_send_search_number_reply(achl_number, iml_numlen, NULL,0);
        m_update_exception_message_l(SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR,__LINE__,"Error getting User CMA");
        return SDH_HOBPHONE_STATUS_NUMSEARCH_LDAP_ERROR;
    }
    struct dsd_getuser dsl_user;
    dsl_ucma.m_get_user( &dsl_user );
//    int inl_domain_auth = dsl_user.inc_auth_method;
    // build configuration container
    // all configurations + channel info
    ds_hstring hstr_config0(ads_wsp_helper);
    // single configuration
    ds_hstring hstr_config1(ads_wsp_helper);
    // complete with nhasn
    ds_hstring hstr_config2(ads_wsp_helper);
    
    // temporary variable used for return values
    BOOL bol_ret = FALSE;
    // switch by authentication type
#ifndef B110318
    bol_ret = dsl_ucma.m_select_config_ldap();
    if ( bol_ret == FALSE ) {
       //  m_update_exception_message(SDH_HOBPHONE_STATUS_NUMSEARCH_LDAP_ERROR, NULL);
        m_send_search_number_reply(achl_number, iml_numlen, NULL,0);
        m_update_exception_message_l(SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR,__LINE__,"Could not select LDAP config");
        return SDH_HOBPHONE_STATUS_NUMSEARCH_LDAP_ERROR;
    }
#endif

    // read settings from the one and only ldap
    // bind with user rights
    //int inl_ret = ds_ldap_instance.m_bind(&(dsl_user.dsc_username), NULL, ied_auth_admin );
    int inl_ret = ds_ldap_instance.m_simple_bind();
    if (inl_ret != SUCCESS) {
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();
      //  m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_ACCESSING_LDAP, hstr.m_get_ptr());
        m_send_search_number_reply(achl_number, iml_numlen, NULL,0);
        m_update_exception_message_l(SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR,__LINE__,"Could not bind to ldap instance");
        return SDH_HOBPHONE_STATUS_NUMSEARCH_LDAP_ERROR;
    }
    // get the dn
    ds_hstring hstr_our_dn = dsl_user.dsc_userdn;
    // read the global pbx configuration from ldap
    // the attribute as hstring
    ds_hstring hstr_attrlist(ads_wsp_helper, "displayName,telephoneNumber,otherTelephone,homePhone,otherHomePhone,mobile,otherMobile,ipPhone,otherIpPhone");
    // a return vector
    ds_hvector<ds_attribute_string> dsl_ret_attributes(ads_wsp_helper);

    //"(|(telephoneNumber=$number)(otherTelephone=$number)(homePhone=$number)(otherHomePhone=$number)(mobile=$number)(otherMobile=$number)(ipPhone=$number)(otherIpPhone=$number))"
    ds_hstring hstr_filter(ads_wsp_helper);
    hstr_filter.m_writef("(|(telephoneNumber=%s)(otherTelephone=%s)(homePhone=%s)(otherHomePhone=%s)(mobile=%s)(otherMobile=%s)(ipPhone=%s)(otherIpPhone=%s))",
        hstr_number.m_get_ptr(),hstr_number.m_get_ptr(),hstr_number.m_get_ptr(),hstr_number.m_get_ptr(),hstr_number.m_get_ptr(),hstr_number.m_get_ptr(),hstr_number.m_get_ptr(),hstr_number.m_get_ptr());
    
    
    int im_ldapret = ds_ldap_instance.m_read_attributes(&hstr_attrlist, &hstr_filter, &hstr_our_dn, ied_sear_root,
        &dsl_ret_attributes);
    // if pbx config could not be fetched
    if (im_ldapret != SUCCESS) {
        ds_hstring hstr = ds_ldap_instance.m_get_last_error();
      //  m_update_exception_message(SDH_HOBPHONE_STATUS_ERROR_GETTING_PBX_CONFIG, hstr.m_get_ptr());
        m_send_search_number_reply(achl_number, iml_numlen, NULL,0);
        m_update_exception_message_l(SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR,__LINE__,"Unable to read LDAP attributes");
        return SDH_HOBPHONE_STATUS_NUMSEARCH_LDAP_ERROR;
    }
 
    //NOTE: LDAP attributes are not ordered!
    int iml_attributes = dsl_ret_attributes.m_size();

    int iml_foundattribpos = 0;
    ds_attribute_string ds_foundphone;
    for (int imli = 0; imli < iml_attributes && iml_foundattribpos == 0; imli++)                       
    {
        ds_foundphone = dsl_ret_attributes.m_get(imli);

        //this is one of the multi-value attributes
        int iml_values = ds_foundphone.m_count_values();//if iml_values > 1 we have a multi attribute value
        for (int imlj = 0; imlj < iml_values; imlj++)
        {
            //check all values within the single/multi-value attribute for a match
            ds_hstring ds_phonenum = ds_foundphone.m_get_value_at(imlj);            
            if (m_match_number(ds_phonenum.m_get_from(0),ds_phonenum.m_get_len(),achl_number,iml_numlen))
            {     
                iml_foundattribpos = imli;
            }
        }
    
    }
    //now that we found the phone we have to find the corresponding name
    //options: 
    //1. resend a new query to LDAP with the exact phone number to get the display name
    //2. Find the display name from the current results
    //2.
    int im_foundstate = IM_NAMESTATE_INIT;  
    int imli = iml_foundattribpos+1;
    ds_hstring dsl_dn = ds_foundphone.m_get_dn();
    ds_attribute_string ds_displayname;
    int iml_items = dsl_ret_attributes.m_size();
    while (im_foundstate == IM_NAMESTATE_INIT)
    {
        if (imli >= iml_items)
        {
            im_foundstate = IM_NAMESTATE_ENDLIST;
        }
        else
        {
            ds_displayname = dsl_ret_attributes.m_get(imli++);       
        
            if (ds_displayname.m_get_name().m_equals("displayName"))
            {
                im_foundstate = IM_NAMESTATE_FOUND_POTENTIAL;
            }
        }
    }

    if (ds_displayname.m_get_values().m_size() > 0)
    {
        if (im_foundstate == IM_NAMESTATE_FOUND_POTENTIAL && ds_displayname.m_get_dn().m_equals(dsl_dn))
        {
            //display name found
            im_foundstate = IM_NAMESTATE_FOUND_CONFIRM;
        }
    }

    if (im_foundstate != IM_NAMESTATE_FOUND_CONFIRM)
    {
        imli = iml_foundattribpos-1;
        //we reached end of list without finding a displayName attribute, or the display name we found was from a different dn - so we have to search backwards        
        while (im_foundstate != IM_NAMESTATE_FOUND_CONFIRM && imli >= 0)
        {   
            ds_displayname = dsl_ret_attributes.m_get(imli--);
            if (ds_displayname.m_get_name().m_equals("displayName"))
            {
                //now we have to compare the dn again
                if (ds_displayname.m_get_dn().m_equals(dsl_dn))
                {
                    //display name found
                    im_foundstate = IM_NAMESTATE_FOUND_CONFIRM;
                }
            }
        }
    }
    if (im_foundstate == IM_NAMESTATE_FOUND_CONFIRM)
    {
        ds_hstring ds_attribute = ds_displayname.m_get_value_at(0);

        //return the first item - TODO if more than 1 item found try to match the best
        //ds_hstring ds_attribute = dsl_ret_attributes.m_get(iml_foundattribpos).m_get_value_at(iml_foundname); 
        const char* achl_value = ds_attribute.m_get_from(0);
        int iml_value_len = ds_attribute.m_get_len();

      

        if (m_send_search_number_reply(achl_number, iml_numlen, achl_value, iml_value_len))
        {

            return SDH_HOBPHONE_STATUS_OK;
        }
    }
    m_update_exception_message(SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR,__LINE__,0);   
    return SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR;

    

}

BOOL ds_hobphone2::m_match_number(const char* achp_string, int imp_len, const char* achp_matchto, int imp_len2)
{             
    if (achp_string == NULL || achp_matchto == NULL)
        return FALSE;
    //remove the + if present
    if(*achp_string == '+')
    {
        achp_string++;
        imp_len--;
    } 
    char achl_new[32];
    
    if (imp_len > 31)
        return FALSE;

    char* achl_curr = achl_new;
    int iml_newlen = 0;       

    //remove spaces
    while(imp_len > 0)
    {         
        if (*achp_string != ' ')
        {
            *achl_curr++ = *achp_string;
            iml_newlen++;
        }
        imp_len--;
        achp_string++;
    }
    achl_curr = achl_new;

    if (imp_len2 == iml_newlen)
    {
        
        while(imp_len2 > 0)
        {
            if (*achl_curr++ != *achp_matchto++)
                break;
            imp_len2--;
        }
    }   

    if (imp_len2 > 0)
        return FALSE;//no match
    else    
        return TRUE; //match
}


BOOL ds_hobphone2::m_send_search_number_reply( const char* achp_number, int imp_numlen, const char* achp_value, int imp_value_len)
{
    //char *ach_value = " ";
    //int im_value_len = 1;
    
    ds_hstring hstr_reply(ads_wsp_helper);
    hstr_reply.m_writef("00NUMBER SEARCH\r\n");
    ds_hstring hstr_buffer(ads_wsp_helper);
    hstr_reply.m_writef("Number:%.*s\r\n", imp_numlen, achp_number);
    //ach_value = ds_attribute.m_get_from(0);
    //im_value_len = ds_attribute.m_get_len();
    if (achp_value != NULL || imp_value_len > 0)
    {
        hstr_reply.m_writef("Display-name:%.*s\r\n", imp_value_len, achp_value);
    }else{    
        hstr_reply.m_writef("Display-name:*\r\n");
    }

    hstr_buffer.m_write_nhasn(hstr_reply.m_get_len());
    hstr_buffer += hstr_reply;
    return ads_wsp_helper->m_send_data(hstr_buffer.m_get_ptr(), hstr_buffer.m_get_len());
}


ied_sdh_hobphone_status ds_hobphone2::m_system_message_keepalive(ds_gather_iterator &dsp_it)
{      
#ifdef NOTIMEOUT
    return SDH_HOBPHONE_STATUS_OK; 
#endif
    int iml_interval =  ads_config->im_tcp_keepalive;

    //we need to get the line before we check the server setting since we still have to discard the client message till the end of the PING
    ds_hstring hstr_type(ads_wsp_helper);     
    dsp_it.m_get_line(hstr_type);

    if (iml_interval <= 0)
    {
        return SDH_HOBPHONE_STATUS_OK; //if config parameter not set do not do anything
    }
    
    //delay our timer - done automatically on m_check_timeout 
    //amc_aux(vpc_userfld,DEF_AUX_TIMER1_SET,NULL,iml_interval+2000);

    
    int iml_current = 0; //the client delay between keepalives
    if (!hstr_type.m_to_int(&iml_current))
    {
        m_update_exception_message(SDH_HOBPHONE_STATUS_KEEPALIVE_ERROR,__LINE__,0);
        return SDH_HOBPHONE_STATUS_KEEPALIVE_ERROR;
    }

    //if client and server intervals match
    if (iml_current == iml_interval)
        iml_interval = 0;  
   
    
    if (ads_config->bo_client_timeout_priority)
    {
        //if client has priority, (and intervals do not match)
        if (iml_interval > 0)
        {
            //we need to change the interval
            ads_config->im_tcp_keepalive = iml_current;
        }
    }
    else
    {
        //if client does not have priority (and intervals do not match)
        if (iml_interval > 0)
        {
            //we need to tell the client to change its interval
            if (m_send_keepalive(iml_interval))
            {
                return SDH_HOBPHONE_STATUS_OK;
            }
            m_update_exception_message(SDH_HOBPHONE_STATUS_KEEPALIVE_ERROR,__LINE__,0);
            return SDH_HOBPHONE_STATUS_KEEPALIVE_ERROR;
        }
    }
    //if the intervals match do nothing

    return SDH_HOBPHONE_STATUS_OK;
}



BOOL ds_hobphone2::m_send_keepalive(int imp_interval)
{
#ifdef NOTIMEOUT
    return TRUE;
#endif
    ds_hstring hstr_reply(ads_wsp_helper);
    hstr_reply.m_writef("00PONG\r\n");           
    ds_hstring hstr_buffer(ads_wsp_helper); 
    //if we have a change in interval send the new interval to the client
    if (imp_interval > 0 )
        hstr_reply.m_writef("%d\r\n", imp_interval);
      
    hstr_buffer.m_write_nhasn(hstr_reply.m_get_len());
    hstr_buffer += hstr_reply;
    return ads_wsp_helper->m_send_data(hstr_buffer.m_get_ptr(), hstr_buffer.m_get_len());

}


void ds_hobphone2::m_check_timeout(struct dsd_hl_clib_1* adsp_trans, BOOL bop_reset)
{   
#ifdef NOTIMEOUT
    return;
#endif                                                                   
    if (ie_state != SDH_HOBPHONE_STATE_NORMAL || ads_config->im_tcp_keepalive <= 0)
        return; //do not set kepalive if not in normal state (eg before greeting) , or if the keepalive is not configured !

    struct dsd_timer1_ret dsl_tr;
    BOOL bol_ret = adsp_trans->amc_aux(adsp_trans->vpc_userfld, DEF_AUX_TIMER1_QUERY, &dsl_tr, sizeof(dsl_tr));

#ifdef DEBUGTRACE
    struct dsd_sdh_call_1 dsl_sdh_call_1;    /* SDH call structure      */
	dsl_sdh_call_1.amc_aux = adsp_trans->amc_aux;  /* auxiliary subroutine */
    dsl_sdh_call_1.vpc_userfld = adsp_trans->vpc_userfld;  /* User Field Subroutine */
    m_sdh_printf(&dsl_sdh_call_1,"TIMER QUERY: epoch: %lld set:%d timer: %lld",dsl_tr.ilc_epoch,dsl_tr.boc_timer_set,dsl_tr.ilc_timer);
#endif
    if (!dsl_tr.boc_timer_set)
    {        
        bop_reset = TRUE; //force reset when the time was unset(expired)

        //before sending anything the greeting has to have been negotiated. 
        m_send_keepalive(ads_config->im_tcp_keepalive);
#ifdef DEBUGTRACE
        bol_ret = adsp_trans->amc_aux(adsp_trans->vpc_userfld, DEF_AUX_TIMER1_QUERY, &dsl_tr, sizeof(dsl_tr));
        m_sdh_printf(&dsl_sdh_call_1,"TIMER QUERY (unset): epoch: %lld set:%d timer: %lld",dsl_tr.ilc_epoch,dsl_tr.boc_timer_set,dsl_tr.ilc_timer);
#endif
    }   
    if (bop_reset)
    {
        //only reset the timer if reset is true (non-null data) or is the timer was unset (expired)
        int iml_interval = ads_config->im_tcp_keepalive;
        amc_aux(vpc_userfld,DEF_AUX_TIMER1_SET,NULL,iml_interval+2000);
    }
#ifdef DEBUGTRACE
    bol_ret = adsp_trans->amc_aux(adsp_trans->vpc_userfld, DEF_AUX_TIMER1_QUERY, &dsl_tr, sizeof(dsl_tr));
    m_sdh_printf(&dsl_sdh_call_1,"TIMER QUERY AFTER SET: interval:%d epoch: %lld set:%d timer: %lld",iml_interval+2000,dsl_tr.ilc_epoch,dsl_tr.boc_timer_set,dsl_tr.ilc_timer);
#endif

}


//RECONNECTION
//called when the client gets disconnected
void ds_hobphone2::m_client_disco()
{
#if DEBUG_RECONNECT
    ads_wsp_helper->m_cb_printf_out("HOBPHONE SDH RELOAD: client disconnected, this: %x",this);    
#endif
    ie_state = SDH_HOBPHONE_STATE_DISCONNECTED;
}


void ds_hobphone2::m_reloaded()
{
#if DEBUG_RECONNECT
    ads_wsp_helper->m_cb_printf_out("HOBPHONE SDH RELOAD: reloaded, this: %x",this);    
#endif
    if (bo_use_udp_gate) {
        // return and status are ignored - anyway we shut down
        ds_udp_gate.iec_cmd_ug = ied_cmd_udp_gate_delete;
        ads_wsp_helper->m_cb_udp_gate(&ds_udp_gate);
    }
    ie_state = SDH_HOBPHONE_STATE_DISCONNECTED;
}

///SIP///

void ds_hobphone2::m_setcontactineta(dsd_ineta_container dsp_ineta )
{
    //hstr_sipcontact.m_writef("<sip:%s@%s:%s;transport=UDP>",)

}

void ds_hobphone2::m_setcontact(char chp_channelid,const char* achp_value,int imp_valuelen)
{
}

#define m_tolower tolower //in C we can use the standard tolower
#define boolean bool
#define final const
#define byte char

enum ied_valid_requests{
IM_RESPONSE,
IM_REQ_ACK,
IM_REQ_BYE,
IM_REQ_CANCEL,
IM_REQ_INFO,
IM_REQ_INVITE,
IM_REQ_MESSAGE,
IM_REQ_NOTIFY,
IM_REQ_OPTIONS,
IM_REQ_PRACK,
IM_REQ_PUBLISH,
IM_REQ_REFER,
IM_REQ_REGISTER,
IM_REQ_SUBSCRIBE,
IM_REQ_UPDATE
};


///////////////
//SIP PARSING//
///////////////
#define null NULL
#define uri_items_NUM 20

enum ied_string_constants{
IM_CONST_SIPVER,
IM_CONST_TAG,
IM_CONST_GMT,
IM_CONST_SDP,
IM_CONST_SIPFRAG
};

static const int dsrr_sip_const_strings[][2] = {               
    { (unsigned int) 0X09A9020B, IM_CONST_SIPVER },
    { (unsigned int) 0X0285013C, IM_CONST_TAG },
    { (unsigned int) 0X01C300E8, IM_CONST_GMT },
    { (unsigned int) 0X30E5060A, IM_CONST_SDP },
    { (unsigned int) 0X303C0600, IM_CONST_SIPFRAG },
};



static const int dsrr_sip_request[][2] = { 


    { (unsigned int) 0X019400CF, IM_REQ_ACK },
    { (unsigned int) 0X01BD00E0, IM_REQ_BYE },
    { (unsigned int) 0X02E9012C, IM_REQ_INFO },
    { (unsigned int) 0X046C0171, IM_REQ_PRACK },
    { (unsigned int) 0X045C0174, IM_REQ_REFER },
    { (unsigned int) 0X05AE01A6, IM_REQ_CANCEL },
    { (unsigned int) 0X065C01CF, IM_REQ_INVITE },
    { (unsigned int) 0X066F01D9, IM_REQ_NOTIFY },
    { (unsigned int) 0X064E01C3, IM_REQ_UPDATE },
    { (unsigned int) 0X083A0205, IM_REQ_MESSAGE },
    { (unsigned int) 0X08AD022C, IM_REQ_OPTIONS },
    { (unsigned int) 0X08710217, IM_REQ_PUBLISH },
    { (unsigned int) 0X0AAE0265, IM_REQ_REGISTER },
    { (unsigned int) 0X0D8E02A2, IM_REQ_SUBSCRIBE },
};





static const int dsrr_sip_headers[][2] = { 


    { (unsigned int) 0X043901B4, IM_From },
    { (unsigned int) 0X00660066, IM_From },
    { (unsigned int) 0X015700E3, IM_To },
    { (unsigned int) 0X00740074, IM_To },
    { (unsigned int) 0X0BA202EC, IM_Contact },
    { (unsigned int) 0X006D006D, IM_Contact },
    { (unsigned int) 0X0ED1033C, IM_Reply_To },
    { (unsigned int) 0X08440270, IM_Accept },
    { (unsigned int) 0X2E7E05E4, IM_Accept_Encoding },
    { (unsigned int) 0X2E9105E1, IM_Accept_Language },
    { (unsigned int) 0X159E03F1, IM_Alert_Info },
    { (unsigned int) 0X062E021F, IM_Allow },
    { (unsigned int) 0X4E6E07B9, IM_Authentication_Info },
    { (unsigned int) 0X26E30591, IM_Authorization },
    { (unsigned int) 0X0A840296, IM_Call_ID },
    { (unsigned int) 0X11090375, IM_Call_Info },
    { (unsigned int) 0X4DB407DD, IM_Content_Disposition },
    { (unsigned int) 0X36E1066F, IM_Content_Encoding },
    { (unsigned int) 0X36F4066C, IM_Content_Language },
    { (unsigned int) 0X2A9A05AA, IM_Content_Length },
    { (unsigned int) 0X006C006C, IM_Content_Length },
    { (unsigned int) 0X200C04EA, IM_Content_Type },
    { (unsigned int) 0X042001AC, IM_CSeq },
    { (unsigned int) 0X0400019E, IM_Date },
    { (unsigned int) 0X16430403, IM_Error_Info },
    { (unsigned int) 0X06500222, IM_Event },
    { (unsigned int) 0X0BFA0300, IM_Expires },
    { (unsigned int) 0X19350440, IM_In_Reply_To },
    { (unsigned int) 0X1ED904DB, IM_Max_Forwards },
    { (unsigned int) 0X1A090471, IM_Min_Expires },
    { (unsigned int) 0X1EFB04DB, IM_MIME_Version },
    { (unsigned int) 0X20F00515, IM_Organization },
    { (unsigned int) 0X0FA30382, IM_Priority },
    { (unsigned int) 0X262F056C, IM_Proxy_Require },
    { (unsigned int) 0X1F7004DB, IM_Record_Route },
    { (unsigned int) 0X0C0902FD, IM_Require },
    { (unsigned int) 0X1AEE0475, IM_Retry_After },
    { (unsigned int) 0X06A2022F, IM_Route },
    { (unsigned int) 0X09110297, IM_Server },
    { (unsigned int) 0X0BDE02F0, IM_Subject },
    { (unsigned int) 0X13E003E6, IM_Supported },
    { (unsigned int) 0X133103D4, IM_Timestamp },
    { (unsigned int) 0X1D3304C9, IM_Unsupported },
    { (unsigned int) 0X15F103FB, IM_User_Agent },
    { (unsigned int) 0X02950140, IM_Via },
    { (unsigned int) 0X00760076, IM_Via },
    { (unsigned int) 0X0BF702F6, IM_Warning },
    { (unsigned int) 0X47E80773, IM_subscription_state },
    { (unsigned int) 0X0E560324, IM_refer_to },
    { (unsigned int) 0X4FA30800, IM_Proxy_Authorization },
    { (unsigned int) 0X46FF076E, IM_Proxy_Authenticate },
    { (unsigned int) 0X37E20691, IM_WWW_Authenticate },
};

enum ied_contenttype{
IM_CONTENTTYPE_SDP,
IM_CONTENTTYPE_SIPFRAG,
IM_CONTENTTYPE_UNKNOWN
};



static const char STR_SIPVERSION[] = {'s','i','p','/','2','.','0'}; 
static const char STR_TAG[] = {'t','a','g'};
static const char STR_DIGEST[] = {'d','i','g','e','s','t'};
static const char STR_EXPIRES[] = {'e','x','p','i','r','e','s'};
static const char STR_GMT[] ={'G','M','T'};
static const char STR_AUTHINT[] = {'a','u','t','h','-','i','n','t'};
static const char STR_AUTH[] = {'a','u','t','h'};




/**
 * Parse the SIP message - does equivalent necessary parts of c_parsedmessage2.m_parse.
 * NOTE: local variable names with p prefix would be parameters in full m_parse - names not changed as this would complicate future updates
 * @return TRUE if the message was handled, FALSE if message should be forwarded
 * 
 */
BOOL ds_hobphone2::m_handlesip( dsd_sdh_udp_recbuf_1 *ads_buffer, char* adsp_reply, int imp_maxlen, int* imp_replylen)
{  
    /* char* chl_next = dsp_it.m_next(); //first char is not SIP relevant
    if (!chl_next)
    {
    dsp_it.m_reset();
    return FALSE;
    }
    chl_next = dsp_it.m_next(); //first char is not SIP relevant
    if (!chl_next)
    {
    dsp_it.m_reset();
    return FALSE;
    }
    int iml_len = dsp_it.m_get_remaining_length();       */

    BOOL bop_issipfrag = FALSE; //forced assumption that this is not a SIP fragment

    int imrl_isreq[] = {-1,0}; 
    int imrl_dest[6] = {0};
    int imp_offset = 0;
    int imp_len = ads_buffer->imc_len_data;
    char* byrp_packet = ads_buffer->achc_data;
    while (imp_offset < imp_len && (byrp_packet[imp_offset] == '\r' || byrp_packet[imp_offset] == '\n'))
    {
        imp_offset++;
    }


    c_parsedmessage2 adsl_parsed = {0}; 
    //equivalent of c_parsedmessage2 constructor:
    adsl_parsed.byrc_message = byrp_packet;
    adsl_parsed.imc_content_type = IM_CONTENTTYPE_UNKNOWN;
    adsl_parsed.imc_messagelen = imp_len-imp_offset;

    //TODO depending on what is needed - these will have to be stored in the work area
    //adsl_parsed.dsc_contact = new HEADERLIST(uri_items_NUM,false);
    //adsl_parsed.dsc_via = null; //new HEADERLIST(1);
    //adsl_parsed.dsc_route = null; //= new HEADERLIST(1);
    //adsl_parsed.dsc_record_route = null; //= new HEADERLIST(1);
    //adsl_parsed.dsc_proxy_authenticate = new HEADERLIST(IM_AUTHPARTS_NUM,false);
    //adsl_parsed.dsc_proxy_authorization = new HEADERLIST(IM_AUTHPARTS_NUM,false);
    //adsl_parsed.dsc_www_authenticate = new HEADERLIST(IM_AUTHPARTS_NUM,false);

    //struct is already set to all 0
    //memset(&(adsl_parsed.imrc_message[0]),0,sizeof(int)*IM_NUM_HEADERS*2);

    //TODO - if needed
    //adsl_parsed.adsc_extra = new c_request(128);
    //adsl_parsed.adsc_extra->imc_offset = 8;

    int* imrl_message = adsl_parsed.imrc_message;

    int iml_currpos = m_parserequest(byrp_packet,imp_offset,imp_len , imrl_dest, imrl_isreq);

    BOOL iml_optionsreply = ads_config->bo_qualifyreply;
    BOOL iml_notifyreply = ads_config->bo_notifyreply;

    //if ((imp_optionsreply && (imrl_isreq[0] == IM_REQ_OPTIONS)) || (imp_notifyreply && (imrl_isreq[0] == IM_REQ_NOTIFY))) 
    if ((!iml_optionsreply || (imrl_isreq[0] != IM_REQ_OPTIONS)) && (!iml_notifyreply || (imrl_isreq[0] != IM_REQ_NOTIFY))) 
    {
        return FALSE;
    }



    adsl_parsed.imc_is_request = imrl_isreq[0];
    if (imrl_isreq[0] > IM_RESPONSE)
    {
        adsl_parsed.imc_error = imrl_isreq[1];
        adsl_parsed.imc_sipstatus = -1;
    }
    else
    {
        adsl_parsed.imc_sipstatus = imrl_isreq[1];
        if (imrl_isreq[0] == IM_RESPONSE)
        {
            adsl_parsed.imc_error = 0;
        }
        else
        {
            adsl_parsed.imc_error = imrl_isreq[1];
        }

    }

    if (iml_currpos < 0)
    {
        m_writetolog(LEVEL_WARNING,"Invalid SIP Message, error in Request/Response Line",byrp_packet,0,imp_len-imp_offset);
        //delete adsl_parsed;
        return FALSE;

    }

    boolean bol_eom = false; //end of sip message found
    if (bop_issipfrag && iml_currpos == imp_len-2 && byrp_packet[iml_currpos] == '\r'  && byrp_packet[iml_currpos+1] == '\n')
    {
        //we are parsing a SIP message from contents that has no body (eg: sipfrag with NOTIFY)
        bol_eom = true;
    }

    //SDH VIA HANDLING
    BOOL bol_invia = FALSE;

    while (iml_currpos < imp_len && !bol_eom)
    {
        int iml_endheader = iml_currpos;
        //find the next colon
        while (iml_endheader < imp_len && byrp_packet[iml_endheader] != ':')
        {
            iml_endheader++;
        }
        if (iml_endheader < imp_len)
        {
            //find the end of the line, start from the character after the colon
            int iml_endline = ++iml_endheader;
            boolean bol_eolfound = false;
            while (!bol_eolfound)
            {
                while (iml_endline < imp_len && byrp_packet[iml_endline] != '\r'  )
                {
                    iml_endline++;
                }
                if (iml_endline == imp_len)
                {
                    m_writetolog(LEVEL_WARNING,"Invalid SIP Message - incomplete line terminator",byrp_packet,0,imp_len);
                    //SDH delete adsl_parsed;
                    return FALSE; //no end of line found
                }
                if (byrp_packet[iml_endline+1] == '\n')
                {
                    if (iml_endline+2 < imp_len-1)
                    {
                        // CRLF found, check next char:
                        if (byrp_packet[iml_endline+2] == ' ' || byrp_packet[iml_endline+2] == '\t')
                        {
                            //this means we have folding so continue looking for the end of the header.
                            iml_endline++;
                        }
                        else if (byrp_packet[iml_endline+2] == '\r' && byrp_packet[iml_endline+3] == '\n')
                        {
                            //double CRLF means we are the end of the SIP message
                            bol_eolfound = true;
                            bol_eom = true;
                        }
                        else 
                        {
                            //end of header found
                            bol_eolfound = true;
                        }
                    }
                    else
                    {
                        m_writetolog(LEVEL_WARNING,"Invalid SIP Message - does not end with double CRLF - attempting to continue!",byrp_packet,0,imp_len);
                        bol_eolfound = true;
                        bol_eom = true;
                    }
                }
            }

            int iml_header = m_findheader(byrp_packet,iml_currpos,iml_endheader);
            //ignore any whitespace between the : and the next non-whitespace character
            iml_endheader = m_trimleading(byrp_packet,iml_endheader,iml_endline);
            int iml_len = iml_endline -iml_endheader; //compute length from char after : to next \r
            iml_currpos = iml_endline+2; //skip the \r\n at the end of the header
            //iml_endheader++; //skip the :
            int* imrc_message = adsl_parsed.imrc_message;

            //SDH VIA HANDLING
            if (bol_invia && iml_header != IM_Via)
            {
                bol_invia = FALSE;
            }
            if (iml_header == IM_Via && !bol_invia && adsl_parsed.imc_viapos != 0)
            {                                                        
                //We found another VIA, not right after the last via
                return FALSE;
            }

            switch (iml_header)
            {
            case IM_From: 
                if (m_parse_uri_content(byrp_packet,iml_endheader, iml_len, imrc_message, IM_From_content_POS) == -1)
                {
                    m_writetolog(LEVEL_WARNING,"Invalid SIP MESSAGE - INVALID FROM",byrp_packet,iml_header,iml_len);
                    //                    delete adsl_parsed;
                    return FALSE;
                }
                break;
            case IM_To: 
                if (m_parse_uri_content(byrp_packet,iml_endheader, iml_len, imrc_message, IM_To_content_POS) == -1)
                {
                    m_writetolog(LEVEL_WARNING,"Invalid SIP MESSAGE - INVALID TO",byrp_packet,iml_header,iml_len);
                    // delete adsl_parsed;
                    return FALSE;
                }
                break;      
            case IM_Contact: 
                {
                    //Incoming contact can be ignored for options since we always send to where we got the request from anyway -
                    //TODO! this might(?) cause issues in some configurations (if the sender does not accept the reply and the reply is expected at the contact)
                    //               //split contacts by comma
                    //               //contact list is either a list of valid contacts or considered invalid if any one of the contacts is invalid
                    //               //hence no m_remove, instead set to null
                    //               int iml_comma = iml_endheader-1;
                    //               int iml_startcontact = iml_endheader;
                    //HEADERLIST* adsl_next = adsl_parsed.dsc_contact->m_append();
                    //adsl_next->imrc_sub[IM_URI_content_POS] = iml_endheader;
                    //               
                    //               while (iml_comma < iml_endline)
                    //               {
                    //                   while (byrp_packet[iml_comma] != ',' && iml_comma < iml_endline)
                    //                   {
                    //                       iml_comma++;
                    //                   }
                    //                   adsl_next->imrc_sub[IM_URI_content_LEN] = iml_comma-iml_startcontact;

                    //                   if (iml_comma < iml_endline)
                    //                   {
                    //                       //comma found                                                                         
                    //                       iml_comma++;
                    //                       adsl_next = adsl_next->m_append();
                    //                       adsl_next->imrc_sub[IM_URI_content_POS] = iml_comma;
                    //                       iml_startcontact = iml_comma;
                    //                       //adsl_next = adsl_next->m_append();
                    //                       //adsl_next->imrc_sub[IM_URI_content_POS] = iml_comma;

                    //                   }

                    //               }
                    //               //parse the contacts
                    //               adsl_next = adsl_parsed.dsc_contact;
                    //               //adsl_next = adsl_parsed.dsc_contact;
                    //               while (adsl_next != null)
                    //               {
                    //                   if (m_parse_uri_content(byrp_packet,adsl_next->imrc_sub[IM_URI_content_POS], adsl_next->imrc_sub[IM_URI_content_LEN], adsl_next->imrc_sub, 0) == -1)
                    //                   {
                    //                       //invalid contact, if this is an invite we have to reject the SIP message, otherwise just ignore the contact 
                    //                       if (imrl_isreq[0] == IM_REQ_INVITE)
                    //                       {
                    //                           m_writetolog(LEVEL_WARNING,"Invalid SIP Message - Invalid Contact in INVITE",byrp_packet,iml_endheader,iml_len);
                    //                           adsl_next = null;                                                          
                    //                           HEADERLIST::m_freeall(adsl_parsed.dsc_contact);
                    //                           
                    //                           adsl_parsed.dsc_contact = null;
                    //                           adsl_parsed.imc_error = 400;
                    //                           //adsl_next = adsl_parsed.dsc_contact = null;                                    
                    //                           //adsl_parsed.imc_error = 400;
                    //                           break;
                    //                           //return null;
                    //                       }
                    //                       else
                    //                       {
                    //                           m_writetolog(LEVEL_INFO,"Contact invalid, Header ignored",byrp_packet, iml_endheader,iml_len);
                    //                           /*
                    //                           //ignore just the invalid contact
                    //                           adsl_next = HEADERLIST::m_remove(adsl_next);
                    //                             */
                    //                           //ignore the whole contact header
                    //                           HEADERLIST::m_freeall(adsl_parsed.dsc_contact);
                    //                           adsl_parsed.dsc_contact = null;
                    //			
                    //                           //adsl_next = adsl_parsed.dsc_contact = null;
                    //                           //adsl_next = adsl_parsed.dsc_contact = null;
                    //                           break;
                    //                       }
                    //                   }
                    //                   else
                    //                   {
                    //                       adsl_next = adsl_next->adsc_next;
                    //                       //adsl_next = adsl_next->adsc_next;
                    //                   }
                    //               }
                }
                break;
            case IM_Reply_To: 
                if (m_parse_uri_content(byrp_packet,iml_endheader, iml_len, imrc_message,IM_Reply_to_content_POS) == -1)
                {
                    m_writetolog(LEVEL_INFO,"Reply-To invalid, Header ignored",byrp_packet, iml_endheader,iml_len);
                }
                break;
            case IM_Accept: 
                imrc_message[IM_Accept_POS] = iml_endheader;
                imrc_message[IM_Accept_LEN] = iml_len;
                break;
            case IM_Accept_Encoding: 
                imrc_message[IM_Accept_Encoding_POS] = iml_endheader;
                imrc_message[IM_Accept_Encoding_LEN] = iml_len;
                break;
            case IM_Accept_Language: 
                imrc_message[IM_Accept_Language_POS] = iml_endheader;
                imrc_message[IM_Accept_Language_LEN] = iml_len;
                break;
            case IM_Alert_Info: 
                imrc_message[IM_Alert_Info_POS] = iml_endheader;
                imrc_message[IM_Alert_Info_LEN] = iml_len;
                break;
            case IM_Allow: 
                imrc_message[IM_Allow_POS] = iml_endheader;
                imrc_message[IM_Allow_LEN] = iml_len;
                break;
            case IM_Authentication_Info:
                imrc_message[IM_Authentication_Info_POS] = iml_endheader;
                imrc_message[IM_Authentication_Info_LEN] = iml_len;
                break;
            case IM_Authorization: 
                imrc_message[IM_Authorization_POS] = iml_endheader;
                imrc_message[IM_Authorization_LEN] = iml_len;
                break;
            case IM_Call_ID: 
                imrc_message[IM_Call_ID_POS] = iml_endheader;
                imrc_message[IM_Call_ID_LEN] = iml_len;
                break;
            case IM_Call_Info: 
                imrc_message[IM_Call_Info_POS] = iml_endheader;
                imrc_message[IM_Call_Info_LEN] = iml_len;
                break;                      
            case IM_Content_Disposition: 
                imrc_message[IM_Content_Disposition_POS] = iml_endheader;
                imrc_message[IM_Content_Disposition_LEN] = iml_len;
                break;
            case IM_Content_Encoding: 
                imrc_message[IM_Content_Encoding_POS] = iml_endheader;
                imrc_message[IM_Content_Encoding_LEN] = iml_len;
                break;
            case IM_Content_Language: 
                imrc_message[IM_Content_Language_POS] = iml_endheader;
                imrc_message[IM_Content_Language_LEN] = iml_len;
                break;
            case IM_Content_Length: 
                {
                    long ilrl_content[] = {0};
                    if (m_checkint(byrp_packet,iml_endheader,iml_len,0,65535,ilrl_content))
                    {
                        imrc_message[IM_Content_Length_POS] = iml_endheader;
                        imrc_message[IM_Content_Length_LEN] = iml_len;
                        adsl_parsed.imc_content_len = (int)ilrl_content[0];

                    }
                    else
                    {
                        //invalid content length
                        m_writetolog(LEVEL_INFO,"Content Length invalid, Header ignored",byrp_packet, iml_endheader,iml_len);
                        imrc_message[IM_Content_Length_POS] = -1;
                        imrc_message[IM_Content_Length_LEN] = 0;
                    }
                    //SDHIf there is content pass the message to the client for full parsing
                    //notify has content!
                    //if ( adsl_parsed.imc_content_len > 0)
                    //    return FALSE;
                }
                break;
            case IM_Content_Type: 
                imrc_message[IM_Content_Type_POS] = iml_endheader;
                imrc_message[IM_Content_Type_LEN] = iml_len;
                break;
            case IM_CSeq: 
                {
                    long ilrl_cseqval[]={-1};
                    int iml_cseqreqtype = m_parse_cseq(byrp_packet,iml_endheader,iml_len,imrc_message,IM_CSeq_POS,ilrl_cseqval);
                    if (imrl_isreq[0] == IM_RESPONSE)
                    {
                        if(iml_cseqreqtype < 0)
                        {
                            //invalid SIP response - discard the message
                            m_writetolog(LEVEL_WARNING,"Invalid SIP RESPONSE - INVALID CSEQ",byrp_packet,iml_header,iml_len);
                            //delete adsl_parsed;
                            return FALSE;
                        }
                        //else valid response, continue normally
                        adsl_parsed.imc_cseq = (int) ilrl_cseqval[0];
                    }
                    else
                    {
                        if (-2 == iml_cseqreqtype)
                        {
                            //cseq error (non integer), whole SIP message is invalid and can be dropped
                            m_writetolog(LEVEL_WARNING,"Invalid SIP REQUEST - INVALID CSEQ",byrp_packet,iml_header,iml_len);
                            adsl_parsed.imc_error = 400;
                            //adsl_parsed.imc_error = 400;
                            //SDH - on error we can stop
                            return FALSE;
                        }
                        //compare the method in the CSEQ to the method in the request line
                        //note that all unknown methods are considered equal
                        else if (iml_cseqreqtype != imrl_isreq[0])
                        {
                            m_writetolog(LEVEL_WARNING,"Invalid SIP REQUEST - CSEQ Method does not match with Request line",byrp_packet,iml_header,iml_len);
                            adsl_parsed.imc_error = 400;
                            //SDH - on error we can stop
                            return FALSE;
                        }
                        else if (-1 == iml_cseqreqtype)
                        {
                            m_writetolog(LEVEL_WARNING,"Invalid SIP REQUEST - Unknown request type",byrp_packet,iml_header,iml_len);
                            break;
                            //unknown request type, we could continue matching with the request line but since this is unknown
                            //the message is already invalid so ignore this and continue parsing.
                            //For future implementation, if needed, it is possible to do this check if we want to do strict parsing, 
                            //so that we can drop the packet completely if the methods don't match
                        }
                        else
                        {
                            //else valid request, continue normally
                            adsl_parsed.imc_cseq = (int) ilrl_cseqval[0];
                        }

                    }
                }
                break;
            case IM_Date: 
                if (!m_parse_rfc1123_date(byrp_packet,iml_endheader,iml_len,imrc_message,IM_Date_POS))
                {
                    //incorrect date, an error should be printed but continue parsing
                    m_writetolog(LEVEL_INFO, "Non-conforming date, ignored:",byrp_packet,iml_endheader,iml_len);
                }
                break;
            case IM_Error_Info: 
                imrc_message[IM_Error_Info_POS] = iml_endheader;
                imrc_message[IM_Error_Info_LEN] = iml_len;
                break;
            case IM_Expires: 
                if (m_checkint(byrp_packet,iml_endheader,iml_len,0,-1,null))
                {
                    imrc_message[IM_Expires_POS] = iml_endheader;
                    imrc_message[IM_Expires_LEN] = iml_len;
                }
                else
                {
                    //invalid expires, ignore header
                    m_writetolog(LEVEL_INFO,"Expires invalid, Header ignored",byrp_packet, iml_endheader,iml_len);
                    imrc_message[IM_Expires_POS] = -1;
                    imrc_message[IM_Expires_LEN] = 0;
                }
                break;   
            case IM_Event: 
                imrc_message[IM_Event_POS] = iml_endheader;
                imrc_message[IM_Event_LEN] = iml_len;
                break;
            case IM_In_Reply_To: 
                imrc_message[IM_In_Reply_To_POS] = iml_endheader;
                imrc_message[IM_In_Reply_To_LEN] = iml_len;
                break;
            case IM_Max_Forwards: 
                {
                    long ilrl_maxforwards[] = {0};
                    if (m_checkint(byrp_packet,iml_endheader,iml_len,0,-1,ilrl_maxforwards))
                    {
                        if (ilrl_maxforwards[0] > 255)
                        {
                            //if > 255 set to 0
                            for (int iml_i = 0; iml_i< iml_len; iml_i++)
                            {
                                byrp_packet[iml_endheader+iml_i] = '0';
                            }
                        }
                        imrc_message[IM_Max_Forwards_POS] = iml_endheader;
                        imrc_message[IM_Max_Forwards_LEN] = iml_len;
                    }
                    else
                    {
                        //invalid max-forwards, invalid SIP message
                        m_writetolog(LEVEL_WARNING,"Invalid SIP Message - Invalid Max-Forwards",byrp_packet,iml_endheader,iml_len);
                        //delete adsl_parsed;
                        //SDH - on error we can stop
                        return FALSE;

                    }
                }
                break;
            case IM_MIME_Version: 
                imrc_message[IM_MIME_Version_POS] = iml_endheader;
                imrc_message[IM_MIME_Version_LEN] = iml_len;
                break;
            case IM_Min_Expires: 
                if (m_checkint(byrp_packet,iml_endheader,iml_len,0,-1,null))
                {
                    imrc_message[IM_Min_Expires_POS] = iml_endheader;
                    imrc_message[IM_Min_Expires_LEN] = iml_len;
                }
                else
                {
                    //invalid min-expires, ignore header
                    m_writetolog(LEVEL_INFO,"Min-Expires invalid, Header ignored",byrp_packet, iml_endheader,iml_len);
                    imrc_message[IM_Min_Expires_POS] = -1;
                    imrc_message[IM_Min_Expires_LEN] = 0;
                    //SDH - on error we can stop
                    return FALSE;
                }
                break;
            case IM_Organization: 
                imrc_message[IM_Organization_POS] = iml_endheader;
                imrc_message[IM_Organization_LEN] = iml_len;
                break;
            case IM_Priority:
                imrc_message[IM_Priority_POS] = iml_endheader;
                imrc_message[IM_Priority_LEN] = iml_len;
                break;    
            case IM_Proxy_Require: 
                imrc_message[IM_Proxy_Require_POS] = iml_endheader;
                imrc_message[IM_Proxy_Require_LEN] = iml_len;
                break;
            case IM_Record_Route: 
                {
                    //SDH TODO: initial implementation does not support record-route handling and passes it to client
                    return FALSE;
                    //					HEADERLIST* adsl_next = adsl_parsed.dsc_record_route;
                    //                    if (adsl_next == null)
                    //                    {
                    //                        adsl_next = new HEADERLIST(2);
                    //adsl_parsed.dsc_record_route = adsl_next;
                    //                        //adsl_parsed.dsc_via = adsl_next;
                    //                    }
                    //                    else
                    //					{
                    //adsl_next = adsl_next->m_append();
                    //                        //adsl_next = adsl_next->m_append();                        
                    //					}
                    //                    int* imrl_dest = adsl_next->imrc_sub;
                    //
                    //                    imrl_dest[0] = iml_endheader;
                    //                    imrl_dest[1] = iml_len;
                }
                break;

            case IM_Require: 
                imrc_message[IM_Require_POS] = iml_endheader;
                imrc_message[IM_Require_LEN] = iml_len;
                break;
            case IM_Retry_After: 
                if (m_checkint(byrp_packet,iml_endheader,iml_len,0,-1,null))
                {
                    imrc_message[IM_Retry_After_POS] = iml_endheader;
                    imrc_message[IM_Retry_After_LEN] = iml_len;
                }
                else
                {
                    //invalid retry-after, ignore header
                    m_writetolog(LEVEL_INFO,"Retry-After invalid, Header ignored",byrp_packet, iml_endheader,iml_len);
                    imrc_message[IM_Retry_After_POS] = -1;
                    imrc_message[IM_Retry_After_LEN] = 0;
                }
                break;
            case IM_Route: 
                {
                    //SDH TODO: initial implementation does not support record-route handling and passes it to client
                    return FALSE;
                    //					HEADERLIST* adsl_next = adsl_parsed.dsc_route;
                    //					if (adsl_next == null)
                    //                    {
                    //                        adsl_next = new HEADERLIST(2);
                    //adsl_parsed.dsc_route = adsl_next;
                    //                        //adsl_parsed.dsc_route = adsl_next;
                    //                    }
                    //                    else
                    //					{
                    //adsl_next = adsl_next->m_append();
                    //                        //adsl_next = adsl_next->m_append();                        
                    //					}
                    //                    int* imrl_dest = adsl_next->imrc_sub;
                    //                    imrl_dest[0] = iml_endheader;
                    //                    imrl_dest[1] = iml_len;
                }
                break;
            case IM_Server: 
                imrc_message[IM_Server_POS] = iml_endheader;
                imrc_message[IM_Server_LEN] = iml_len;
                break;
            case IM_Subject: 
                imrc_message[IM_Subject_POS] = iml_endheader;
                imrc_message[IM_Subject_LEN] = iml_len;
                break;
            case IM_Supported: 
                imrc_message[IM_Supported_POS] = iml_endheader;
                imrc_message[IM_Supported_LEN] = iml_len;
                break;
            case IM_Timestamp: 
                imrc_message[IM_Timestamp_POS] = iml_endheader;
                imrc_message[IM_Timestamp_LEN] = iml_len;
                break;                       
            case IM_Unsupported: 
                imrc_message[IM_Unsupported_POS] = iml_endheader;
                imrc_message[IM_Unsupported_LEN] = iml_len;
                break;
            case IM_User_Agent: 
                imrc_message[IM_User_Agent_POS] = iml_endheader;
                imrc_message[IM_User_Agent_LEN] = iml_len;
                break;
            case IM_Via: 
                {
                    //SDH VIA HANDLING
                    adsl_parsed.imc_viapos = iml_endheader;
                    adsl_parsed.imc_vialen = iml_len;
                    bol_invia = TRUE;
                    //
                    //					HEADERLIST* adsl_next = adsl_parsed.dsc_via;
                    //                     if (adsl_next == null)
                    //                    {
                    //                        adsl_next = new HEADERLIST(2);
                    //adsl_parsed.dsc_via = adsl_next;
                    //                        //adsl_parsed.dsc_via = adsl_next;
                    //                    }
                    //                    else
                    //					{
                    //adsl_next = adsl_next->m_append();
                    //                        //adsl_next = adsl_next->m_append();                        
                    //					}
                    //
                    //                    int* imrl_dest = adsl_next->imrc_sub;
                    //                    imrl_dest[0] = iml_endheader;
                    //                    imrl_dest[1] = iml_len;
                    //                    //TODO via is not being checked for validity
                }
                break;
            case IM_Warning:
                //SDH warning not allowed in OPT
                return FALSE;
                /*if (m_parse_warning(byrp_packet,iml_endheader,iml_len,imrc_message,IM_Warning_POS) < 0)
                {                     
                m_writetolog(LEVEL_INFO,"Warning invalid, Header ignored",byrp_packet, iml_endheader,iml_len);
                }
                break;    */
            case IM_subscription_state: 
                imrc_message[IM_subscription_state_POS] = iml_endheader;
                imrc_message[IM_subscription_state_LEN] = iml_len;
                break;
            case IM_refer_to: 
                imrc_message[IM_refer_to_POS] = iml_endheader;
                imrc_message[IM_refer_to_LEN] = iml_len;
                break;
            case IM_Proxy_Authenticate: 
                {
                    //SDH not allowed in OPT
                    return FALSE;
                    //					HEADERLIST* adsl_next = adsl_parsed.dsc_proxy_authenticate;
                    //adsl_next = adsl_next->m_append();
                    //
                    //
                    //                    int* imrl_dest = adsl_next->imrc_sub;
                    //                    
                    //                    if (!m_parse_auth(byrp_packet,iml_endheader, iml_len, imrl_dest))
                    //                    {
                    //                        m_writetolog(LEVEL_INFO,"Proxy AUthenticate Invalid",byrp_packet,iml_endheader,iml_len);
                    //                        adsl_next->m_clean();
                    //
                    //                    }
                }
                break;
            case IM_Proxy_Authorization: 
                {
                    //SDH TODO - can this be present? - This is optional in OPT Request unless there'a Proxy AFTER the WSP won't be there

                    return FALSE;
                    //					HEADERLIST* adsl_next = adsl_parsed.dsc_proxy_authorization;
                    //adsl_next = adsl_next->m_append();
                    //
                    //
                    //                    int* imrl_dest = adsl_next->imrc_sub;
                    //                    
                    //                    if (!m_parse_auth(byrp_packet,iml_endheader, iml_len, imrl_dest))
                    //                    {
                    //                        m_writetolog(LEVEL_INFO,"Proxy Authorization Invalid",byrp_packet,iml_endheader,iml_len);
                    //                        adsl_next->m_clean();
                    //                    }
                }
                break;
            case IM_WWW_Authenticate: 
                {                                                      
                    //SDH not allowed in OPT
                    return FALSE;
                    //					HEADERLIST* adsl_next = adsl_parsed.dsc_www_authenticate;
                    //adsl_next = adsl_next->m_append();
                    //
                    //
                    //                    int* imrl_dest = adsl_next->imrc_sub;
                    //                    
                    //                    if (!m_parse_auth(byrp_packet,iml_endheader, iml_len, imrl_dest))
                    //                    {
                    //                        m_writetolog(LEVEL_INFO,"WWW AUthenticate Invalid",byrp_packet,iml_endheader,iml_len);
                    //                        adsl_next->m_clean();
                    //                    }
                }
                break;
            default:
                {
                    m_writetolog(LEVEL_INFO,"Unknown Header ignored",byrp_packet, iml_endheader,iml_len);
                    break;
                }
            }
        }
        else if (byrp_packet[iml_currpos] == '\r' && byrp_packet[iml_currpos+1] == '\n')
        {
            //end of SIP
            break;
        }
    }
    if (!bol_eom)
    {
        //no end of message found
        m_writetolog(LEVEL_WARNING,"Invalid SIP Message - No end of message marker found",byrp_packet,0,imp_len);
        //        delete adsl_parsed;
        return FALSE;
    }
    //parse contents
    //strlen("application/sdp") == 15
    //strlen("message/sipfrag") == 15
    //   int* imrl_message = adsl_parsed.imrc_message;
    if (imrl_message[IM_Content_Type_LEN] == 15)
    {
        m_log_info(SDH_HOBPHONE_STATUS_SIP_PARSER,"SDP content found, passing SIP message to client");
        return FALSE; //SDH SDP in OPTIONS??!
        //        if (m_eqlowercase2(dsrr_sip_const_strings,sizeof(dsrr_sip_const_strings) / (sizeof(int)*2),IM_CONST_SDP,byrp_packet,imrl_message[IM_Content_Type_POS],imrl_message[IM_Content_Type_LEN]))
        //        {
        //                                //TODO parse SDP
        //			//M$DEF$SETMEM(adsl_parsed,imc_content_pos,'iml_currpos');
        //adsl_parsed.imc_content_type = IM_CONTENTTYPE_SDP;
        //            if (bop_parsecontents)
        //            {
        //                if (adsl_parsed.imc_content_len != 0 && adsl_parsed.imc_content_len != (imp_len-iml_currpos-2))
        //            	{
        //            			m_writetolog(LEVEL_WARNING, "Content length in SIP contents does not match with received data - ignoring SIP content length");
        //            	}
        //adsl_parsed.imc_content_len = imp_len-iml_currpos;
        //                if (adsl_parsed.imc_content_len)
        //                    adsl_parsed.adsc_content = c_sdpsession::m_parsesdp(byrp_packet,iml_currpos,imp_len,null);
        //            }
        //        }
        //        else if (m_eqlowercase2(dsrr_sip_const_strings,sizeof(dsrr_sip_const_strings) / (sizeof(int)*2),IM_CONST_SIPFRAG,byrp_packet,imrl_message[IM_Content_Type_POS],imrl_message[IM_Content_Type_LEN]))
        //        {
        //adsl_parsed.imc_content_type = IM_CONTENTTYPE_SIPFRAG;
        //            if (bop_parsecontents)
        //adsl_parsed.adsc_sipfragmessage = m_parse(byrp_packet,iml_currpos,imp_len,false,true);
        //}              
    }


    /* PHEADERLIST adsl_recordroute;
    adsl_recordroute = adsl_parsed.dsc_record_route;
    if (adsl_recordroute != null)
    {
    if (adsl_parsed.dsc_route == null)
    adsl_parsed.dsc_route = adsl_recordroute;
    else
    {
    //we have both route and record route - is this possbile?
    c_debug.m_writetolog(LEVEL_WARNING,"Route and Record-Route headers found in sip message",byrp_packet,0,imp_len);
    }
    }     */
//SDH TODO    adsl_parsed.m_setup_rport();
    //return adsl_parsed;
    //    }

//TODO TODO TODO - rport    
    return m_received_siprequest(&adsl_parsed, adsp_reply, imp_maxlen, imp_replylen);

 

}

int ds_hobphone2::m_parserequest(char byrp_packet[],int imp_offset, int imp_len, int imrp_dest[], int imrp_isreq[])
{      
    int iml_endline = imp_offset;
    int iml_currpos = imp_offset;
    if (imrp_dest == null || imrp_isreq == null)
    {
        return -2;
    }
    if (imp_len < 13) //sipversion + spaces + min 1 char for method etc
        return -3;

    while (byrp_packet[iml_endline] != '\r' && iml_endline < imp_len-1)
    {
        iml_endline++;
    }
    if (iml_endline == imp_len-1 || byrp_packet[iml_endline+1] != '\n')
    {
        m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "incomplete String terminator");
        //            m_writetolog(LEVEL_INFO,"incomplete String terminator");
        return -1;
    }

    // int iml_request1 = 0; //position of first space
    //int iml_request2 = 0; //position of second space

    //ignore leading whitespace, see RFC 4475 3.1.2.10. 
    while ((byrp_packet[iml_currpos] == ' ' || byrp_packet[iml_currpos] == '\t') && (iml_currpos < iml_endline))
    {
        iml_currpos++;
    }
    int iml_startpos = iml_currpos;
    while (byrp_packet[iml_currpos] != ' ' && iml_currpos < iml_endline)
    {            
        iml_currpos++;            
    }
    //first space
    int iml_request1 = iml_currpos;
    iml_currpos++;

    while (byrp_packet[iml_currpos] != ' ' && iml_currpos < iml_endline)
    {

        iml_currpos++;                        
    }
    //second space
    int iml_request2 = iml_currpos;
    iml_currpos++;

    //check for response:
    /* byte byrl_sipversion[] = {0,0,0,0,0,0,0,0};
    int iml_i = 0;
    //convert first 7 chars to lowercase   
    while (iml_i < 7 && iml_startpos < iml_endline)
    {
    byrl_sipversion[iml_i] = m_tolower(byrp_packet[iml_startpos]);
    iml_startpos++;
    iml_i++;
    };        */

    //check if SIP message starts with sip/2.0
    //TODO sip/2.0 can also be compared using a hash

    //if (!strcmp(byrl_sipversion,"sip/2.0"))
    if (m_eqlowercase2(dsrr_sip_const_strings,sizeof(dsrr_sip_const_strings) / (sizeof(int)*2),IM_CONST_SIPVER,byrp_packet,iml_startpos,iml_request1-iml_startpos))
    {
        //we have a response

        // adsp_parsed->boc_is_request = false;
        imrp_isreq[0] = IM_RESPONSE;
        imrp_dest[IM_RESPONSE_STATUS_POS] = iml_request1+1;
        imrp_dest[IM_RESPONSE_STATUS_LEN] = iml_request2 - iml_request1 - 1; //-1 to remove space at the end
        long ilrl_responsecode[] = {0};
        if (!m_checkint(byrp_packet,imrp_dest[IM_RESPONSE_STATUS_POS],imrp_dest[IM_RESPONSE_STATUS_LEN],100,699,ilrl_responsecode))
        {
            m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "SIP response-code out of range");
            //                m_writetolog(LEVEL_INFO,"SIP response-code out of range, expected 100-699, found: ",byrp_packet,imrp_dest[IM_RESPONSE_STATUS_POS],imrp_dest[IM_RESPONSE_STATUS_LEN]);
            return -1;
        }  
        imrp_isreq[1] = (int) ilrl_responsecode[0];
    }
    else
    {
        //check for request
        iml_startpos = iml_request2+1;
        /*iml_i = 0;
        while ((iml_i < 7) && (iml_startpos < iml_endline))
        {
        byrl_sipversion[iml_i] = m_tolower(byrp_packet[iml_startpos]);
        iml_startpos++;
        iml_i++;
        };    */
        while (byrp_packet[iml_endline-1] == ' ' || byrp_packet[iml_endline-1] == '\t')
        {
            //ignore spaces at the end (after the SIP Version)
            //this is optional - see RFC4475 3.1.2.10.  SP Characters at End of Request-Line
            iml_endline--;
        }
        if (m_eqlowercase2(dsrr_sip_const_strings,sizeof(dsrr_sip_const_strings) / (sizeof(int)*2),IM_CONST_SIPVER,byrp_packet,iml_startpos,iml_endline-iml_startpos))
        {
            //we have a request
            // adsp_parsed->boc_is_request = true;
            imrp_isreq[0] = m_is_validrequest(byrp_packet,imp_offset,iml_request1-imp_offset);
            if (imrp_isreq[0] == -1)
            {
                m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Invalid URI in request line - unknown request type");
                //                    m_writetolog(LEVEL_INFO,"Invalid URI in request line - unknown request type",byrp_packet,0,iml_request1);
                imrp_isreq[1] = 501;//unknown request type
            }
            imrp_dest[IM_REQUEST_METHOD_POS] = imp_offset;
            imrp_dest[IM_REQUEST_METHOD_LEN] = iml_request1-imp_offset;
            imrp_dest[IM_REQUEST_URI_POS] = iml_request1+1;
            imrp_dest[IM_REQUEST_URI_LEN] = iml_request2 - iml_request1 -1 ; //-1 to remove space at the end
            int imrl_uri_parts[uri_items_NUM] = {0};//for now only needed to be filled in by m_parse_sip_uri, values currently not used
            //we need to check that the URI in the request is valid!
            if (byrp_packet[++iml_request1] == '<' && byrp_packet[--iml_request2] == '>')
            {
                //handle a very specific but necessary case where the SIP uri is in <>
                //here we could simple return a 400 Bad Request but breaking an installation
                //for such a small issue is not a good idea,
                //it is also acceptable to ignore the <> - see rfc 4476 ltgtruri example
                iml_request1++;
                iml_request2--;
            }
            int iml_sipuri = m_parse_sip_uri(byrp_packet,iml_request1,iml_request2,imrl_uri_parts,0);
            if (iml_sipuri < 0)
            {
                m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Invalid URI in request line");
                //                    m_writetolog(LEVEL_INFO,"Invalid URI in request line",byrp_packet,iml_request1,iml_request2-iml_request1);
                if (iml_sipuri == -1)
                {
                    imrp_isreq[1] = 400;
                }
                else
                {
                    imrp_isreq[1] = iml_sipuri*-1;
                }
            }
        }
        else
        {             
            m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Could not determine message type - incorrectly formatted request");
            //                m_writetolog(LEVEL_INFO,"Could not determine message type - incorrectly formatted request",byrp_packet,iml_startpos,iml_endline);
            return -1;
        }

    }

    return iml_endline+2; //skip the CRLF

}

int ds_hobphone2::m_is_validrequest(char byrp_packet[], int imp_start, int imp_len)
{
    /*"ACK", // RFC3261     
    "BYE",// RFC3261         
    "CANCEL", // RFC3261    
    "INFO",// RFC6068       
    "INVITE", // RFC3261    
    "MESSAGE",// RFC3428    
    "NOTIFY",// RFC3265    
    "OPTIONS", // RFC3261   
    "PRACK", // RFC3262     
    "PUBLISH",// RFC3909   
    "REFER",// RFC3515    
    "REGISTER",// RFC3261  
    "SUBSCRIBE",// RFC3265  
    "UPDATE"// RFC3311  */
    //TODO - we can do this using a hash     
    int iml_adler = m_calc_adler(byrp_packet,imp_start,imp_start+imp_len);
    int iml1 = 0;
    int iml_numitems = sizeof(dsrr_sip_request) / (sizeof(int)*2);
    do {
        if (dsrr_sip_request[ iml1 ][0]== iml_adler) {  /* compare hash of name */
            return dsrr_sip_request[iml1][1];                       /* option found in table   */
        }
        iml1++;                                /* increment index         */
    } while (iml1 < iml_numitems) ;
    /*
    switch (imp_len)
    {
    case 3:
    if (!memcmp(&byrp_packet[imp_start],"ACK",3))
    return IM_REQ_ACK; 
    else if (!memcmp(&byrp_packet[imp_start],"BYE",3))
    return IM_REQ_BYE;
    case 4:
    if (!memcmp(&byrp_packet[imp_start],"INFO",4))
    return IM_REQ_INFO;
    case 5:
    if (!memcmp(&byrp_packet[imp_start],"PRACK",5))
    return IM_REQ_PRACK;
    else if (!memcmp(&byrp_packet[imp_start],"REFER",5))
    return IM_REQ_REFER;
    case 6:
    if (!memcmp(&byrp_packet[imp_start],"CANCEL",6))
    return IM_REQ_CANCEL;
    else if (!memcmp(&byrp_packet[imp_start],"INVITE",6))
    return IM_REQ_INVITE;
    else if (!memcmp(&byrp_packet[imp_start],"NOTIFY",6))
    return IM_REQ_NOTIFY;
    else if (!memcmp(&byrp_packet[imp_start],"UPDATE",6))
    return IM_REQ_UPDATE;
    case 7:
    if (!memcmp(&byrp_packet[imp_start],"MESSAGE",7))
    return IM_REQ_MESSAGE;
    else if (!memcmp(&byrp_packet[imp_start],"OPTIONS",7))
    return IM_REQ_OPTIONS;
    else if (!memcmp(&byrp_packet[imp_start],"PUBLISH",7))
    return IM_REQ_PUBLISH;
    case 8:
    if (!memcmp(&byrp_packet[imp_start],"REGISTER",8))
    return IM_REQ_REGISTER;
    case 9:
    if (!memcmp(&byrp_packet[imp_start],"SUBSCRIBE",9))
    return IM_REQ_SUBSCRIBE;
    */

    m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Unknown request type");
    //        m_writetolog(LEVEL_INFO,"Unknown request type",byrp_packet,imp_start,imp_len);
    return -1;
}


int ds_hobphone2::m_parse_sip_uri(char byrp_packet[], int imp_start, int imp_end,int imrp_dest[], int imp_index)
{
    //trim the uri - this implies spaces between the < or > and the uri
    //not strictly conforming but allowed and should not fail - see RFC 4475 badaspec
    imp_start = m_trimleading(byrp_packet,imp_start,imp_end);
    imp_end = m_trimtrailing(byrp_packet,imp_start,imp_end);        
    int iml_prot = m_findnext(byrp_packet,imp_start,imp_end,':');        
    if (iml_prot >= 0)
    { 
        //make sure this is a sip uri
        //            if ((iml_prot-imp_start != 3) || memcmp("sip",&byrp_packet[imp_start],3))
        if ((iml_prot-imp_start != 3) || byrp_packet[imp_start] != 's' || byrp_packet[imp_start+1] != 'i' || byrp_packet[imp_start+2] != 'p')
        {
            m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Invalid URI, unknown protocol (only sip supported)");
            //                m_writetolog(LEVEL_INFO,"Invalid URI, unknown protocol (only sip supported) ",byrp_packet,imp_start,iml_prot - imp_start);
            //unsupported URI scheme (possibly due to invalid characters such as < - see lgtgruri in rfc 4475
            return -416;
        }
        imrp_dest[imp_index+IM_URI_protocol_POS] = imp_start;
        imrp_dest[imp_index+IM_URI_protocol_LEN] = iml_prot-imp_start;
        int iml_user = m_findnext(byrp_packet, iml_prot, imp_end, '@');
        if (iml_user == -1)
        {
            //no user part in URL (valid)
            iml_user = iml_prot;
            imrp_dest[imp_index+IM_URI_name_POS] = -1;
            imrp_dest[imp_index+IM_URI_name_LEN] = 0;
        }
        else
        {  
            //validate user part - no spaces allowed!
            if (m_findnext(byrp_packet, iml_prot+1, iml_user-1, ' ') > 0)
            {
                m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Invalid number, no spaces allowed, attempting to continue!");
                //            		 m_writetolog(LEVEL_WARNING,"Invalid number, no spaces allowed, attempting to continue!",byrp_packet,imp_start,imp_end - imp_start);
                //return -1;
            }
            imrp_dest[imp_index+IM_URI_name_POS] = iml_prot+1;
            imrp_dest[imp_index+IM_URI_name_LEN] = iml_user-1-iml_prot;
        }

        if (iml_user >= iml_prot)
        {
            if (m_parse_host(byrp_packet,iml_user+1,imp_end,imrp_dest,imp_index) < 0)
            {
                //invalid host
                return -400;
            }
        }
        else
        {
            // @ before : => invalid URI
            m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Invalid URI, '@' before ':' ");
            //                m_writetolog(LEVEL_INFO,"Invalid URI, '@' before ':' ",byrp_packet,imp_start,imp_end - imp_start);
            return -1;
        } 
    }
    else
    {
        //missing : => invalid URI
        m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Invalid URI, missing ':' ");
        //            m_writetolog(LEVEL_INFO,"Invalid URI, missing ':' ",byrp_packet,imp_start,imp_end - imp_start);
        return -1;
    }
    imrp_dest[imp_index+IM_URI_uri_POS] = imp_start;
    imrp_dest[imp_index+IM_URI_uri_LEN] = imp_end-imp_start;
    return 0;
}


int ds_hobphone2::m_parse_host(char byrp_packet[], int imp_start, int imp_end,int imrp_dest[], int imp_index)
{
    int iml_port = m_findnext(byrp_packet,imp_start,imp_end,':');
    int iml_tags = m_findnext(byrp_packet,imp_start,imp_end,';');
    //bounds checking
    if (iml_port == 0 || iml_tags == 0 || (-1 != iml_tags && iml_port > iml_tags))
    {
        //invalid URI
        m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Invalid host part in URI");
        //            m_writetolog(LEVEL_INFO,"Invalid host part in URI",byrp_packet,imp_start,imp_end-imp_start);
        return -1;
    }
    imrp_dest[imp_index+IM_URI_hostname_POS] = imp_start;
    if (iml_port == -1 && iml_tags == -1)
    {
        //no tags and no port
        imrp_dest[imp_index+IM_URI_hostname_LEN] = imp_end-imp_start;
    }
    else
    {
        if (iml_port != -1)
        {
            //port specified

            //Set the name from beginning to start of port  
            imrp_dest[imp_index+IM_URI_hostname_LEN] = iml_port-imp_start;

            imrp_dest[imp_index+IM_URI_hostport_POS] = iml_port+1;
            if (iml_tags != -1)
            {      
                //tags also specified
                imrp_dest[imp_index+IM_URI_hostport_LEN] = iml_tags-iml_port-1;
            }
            else
            {                                                                              
                imrp_dest[imp_index+IM_URI_hostport_LEN] = imp_end-iml_port-1;
            }


            //validate port
            if (!m_checkint(byrp_packet,imrp_dest[imp_index+IM_URI_hostport_POS],imrp_dest[imp_index+IM_URI_hostport_LEN],0,65536,null))
            {
                //invalid port
                imrp_dest[imp_index+IM_URI_hostport_POS] = -1;
                imrp_dest[imp_index+IM_URI_hostname_POS] = -1;
                m_log_info(SDH_HOBPHONE_STATUS_SIP_ERROR, "Invalid port");
                //                    m_writetolog(LEVEL_INFO,"Invalid Port",byrp_packet,imp_start,imp_end - imp_start);
                return -1;
            }
        }
        if (iml_tags != -1)
        {
            //tags specified
            imrp_dest[imp_index+IM_URI_hosttags_POS] = iml_tags+1;
            imrp_dest[imp_index+IM_URI_hosttags_LEN] = imp_end-iml_tags-1;

            //no port - set name from beginning to start of tags
            if (iml_port == -1)
            {
                imrp_dest[imp_index+IM_URI_hostname_LEN] = iml_tags-imp_start;
            }
        }
    }
    return 0;
}


int ds_hobphone2::m_parse_uri_content(char byrp_packet[], int imp_start, int imp_len, int imrp_dest[], int imp_index)
{
    //find the last '<'
    imrp_dest[imp_index+IM_URI_content_POS] = -1;
    imrp_dest[imp_index+IM_URI_content_LEN] = 0;
    int iml_lquot = m_findlast(byrp_packet,imp_start, imp_start+imp_len, '<');
    if (iml_lquot >= 0){
        int iml_rquot = m_findlast(byrp_packet,imp_start, imp_start+imp_len, '>');
        if (iml_rquot > 0 || iml_rquot < iml_lquot) {
            //<> or only < found (< can be in username quoted string)
            //display name lies between imp_start and iml_lquot
            int iml_quotepos = m_startswith(byrp_packet,imp_start, iml_lquot, '"');
            if (iml_quotepos >= 0)
            {
                //display name is a quoted string (starts with ")
                int iml_endquote = iml_quotepos; 
                do{
                    iml_endquote= m_findnext(byrp_packet,iml_endquote+1,iml_lquot,'"');
                }while(iml_endquote > 0 && byrp_packet[iml_endquote-1] == '\\' ); //watch out for escaped " within "

                if (iml_endquote == -1)
                {
                    //no closing quote, but we can accept this name by inferring a terminating quote,
                    //even if not exactly conformant to the standard
                    //see RFC 4475 3.1.2.6.  Unterminated Quoted String in Display Name
                    imrp_dest[imp_index+IM_URI_fullname_POS] = iml_quotepos+1;
                    imrp_dest[imp_index+IM_URI_fullname_LEN] = iml_lquot-1-iml_quotepos-1;//second -1 to exclude the opening "
                }
                else if (m_iswhitespace(byrp_packet, iml_endquote+1,iml_lquot))
                {
                    //closing quote just before < (exlucing whitespaces)
                    imrp_dest[imp_index+IM_URI_fullname_POS] = iml_quotepos+1;
                    imrp_dest[imp_index+IM_URI_fullname_LEN] = iml_endquote-1-iml_quotepos;
                }
                else
                {
                    //we have text between the closing quote and the opening < - invalid
                    //memset(&imrp_dest[imp_index],0,uri_items_NUM);
                    for (int imli = 0; imli < uri_items_NUM; imli++)
                    {
                        imrp_dest[imp_index+imli] = 0;
                    }

                    m_writetolog(LEVEL_INFO,"Invalid URI content text found between name and uri",byrp_packet,imp_start,imp_len);
                    return -1;
                }
            } //endif (iml_quotepos >= 0)
            else //does not start with "
            {                           
                iml_quotepos = m_findnext(byrp_packet,imp_start, iml_lquot, '"');
                if (iml_quotepos == -1)
                {

                    //TODO *(token LWS)/ quoted-string is accepted. 
                    //to be fully compliant here we should check for the
                    //presence of token = 1*(alphanum / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`" / "'" / "~" )
                    if (iml_lquot == imp_start)
                    {
                        //no name included
                        imrp_dest[imp_index+IM_URI_fullname_POS] = -1;
                        imrp_dest[imp_index+IM_URI_fullname_LEN] = 0;
                    }
                    else
                    {
                        imrp_dest[imp_index+IM_URI_fullname_POS] = imp_start;
                        imrp_dest[imp_index+IM_URI_fullname_LEN] = iml_lquot-1-imp_start;
                    }
                }
                else
                {
                    //if the message does not start with a " but it contains a " it is invalid
                    //memset(&imrp_dest[imp_index],0,uri_items_NUM);
                    for (int imli = 0; imli < uri_items_NUM; imli++)
                    {
                        imrp_dest[imp_index+imli] = 0;
                    }
                    m_writetolog(LEVEL_INFO,"Invalid URI content '\"' out of place ",byrp_packet,imp_start,imp_len);
                    return -1;
                }
            }

            //parse the SIP URI between the <>
            if (m_parse_sip_uri(byrp_packet, iml_lquot+1, iml_rquot, imrp_dest, imp_index) < 0)
            {
                m_writetolog(LEVEL_INFO,"Invalid SIP URI - ignored ",byrp_packet,imp_start,imp_len);
                return -1;
            }
            //parse the tags
            if (m_parse_tags(byrp_packet, iml_rquot+1, imp_len+imp_start, imrp_dest, imp_index) == -1)
            {
                m_writetolog(LEVEL_INFO,"Invalid SIP URI - ignored",byrp_packet,imp_start,imp_len);
                return -1;
            }  
        }
        else 
        {
            //missing >
            m_writetolog(LEVEL_INFO,"Invalid URIm missing closing '>' ",byrp_packet,imp_start,imp_len);
            return -1;
        }
    }
    else
    {
        //no < found
        int iml_semi = m_findnext(byrp_packet,imp_start,imp_start+imp_len,';');
        if (iml_semi == -1)
        {
            //no tags, use whole string
            iml_semi = imp_start+imp_len;
        }
        if (m_parse_sip_uri(byrp_packet, imp_start, iml_semi, imrp_dest, imp_index) < 0)
        {
            m_writetolog(LEVEL_INFO,"Invalid SIP URI - ignored ",byrp_packet,imp_start,imp_len);
            return -1;
        }
        if (m_parse_tags(byrp_packet, iml_semi, imp_len+imp_start, imrp_dest, imp_index) == -1)
        {
            m_writetolog(LEVEL_INFO,"Invalid SIP URI - ignored",byrp_packet,imp_start,imp_len);
            return -1;
        }           

    }

    imrp_dest[imp_index+IM_URI_content_POS] = imp_start;
    imrp_dest[imp_index+IM_URI_content_LEN] = imp_len;

    return 1;
}

int ds_hobphone2::m_parse_tags(char byrp_packet[], int imp_start, int imp_end,int imrp_dest[], int imp_index)
{
    if (imp_start >= imp_end)
    {
        imrp_dest[imp_index+IM_URI_tag_POS] = imp_start;
        imrp_dest[imp_index+IM_URI_tag_LEN] = 0;
        imrp_dest[imp_index+IM_URI_fields_POS] = imp_start;
        imrp_dest[imp_index+IM_URI_fields_LEN] = 0;
        return 1; //no tags (not invalid)
    }

    imrp_dest[imp_index+IM_URI_tag_POS] = -1;
    imrp_dest[imp_index+IM_URI_tag_LEN] = 0;    
    imrp_dest[imp_index+IM_URI_fields_POS] = -1;
    imrp_dest[imp_index+IM_URI_fields_LEN] = 0; 


    int iml_tag = -1;
    int iml_nexttag = imp_start;
    boolean bol_moretags = true;
    int iml_fields = 0;
    while(bol_moretags)
    {
        if (iml_tag < 0)
        {
            //the provided string must start with a ; (possibly with leading whitespace)
            iml_tag = m_startswith(byrp_packet,iml_nexttag,imp_end,';');
            iml_fields = iml_tag+1;
        }
        if (iml_tag == -1)
        {
            //tag must be present if got here.
            m_writetolog(LEVEL_INFO,"Invalid tag: missing tag",byrp_packet,imp_start,imp_end - imp_start);
            return -1;
        }

        iml_tag++;

        iml_nexttag = m_findnext(byrp_packet,iml_tag,imp_end,';');
        if (iml_nexttag == -1)
        {
            //there is no other tag
            iml_nexttag = imp_end;
            bol_moretags = false;
        }
        if (iml_tag==iml_nexttag)
        {
            //we have extra ; without content, this is invalid - see rfc 4475 3.1.2.1 badinv01
            m_writetolog(LEVEL_INFO,"Invalid tag, extra ';' ",byrp_packet,imp_start,imp_end - imp_start);
            return -1;
        }
        //look for an = between the ;, this separates the tag name from its value
        int iml_equals = m_findnext(byrp_packet,iml_tag,iml_nexttag,'=');
        if (iml_equals == -1)
        {
            //this is a valid tag without a value : generic-param = token [EQUAL gen-value]
        }
        else 
        {
            if (-1 != m_findnext(byrp_packet,iml_equals+1,iml_nexttag,'='))
            {
                //look for another =, in this case we have an error, incomplete tag
                m_writetolog(LEVEL_INFO,"Invalid tag - incomplete ",byrp_packet,imp_start,imp_end - imp_start);
                return -1;
            }
            else
            {
                //check if the current tag is "tag"

                if ((iml_equals - iml_tag) == 3) 
                {
                    //if the value of the tag is 3 characters check if it is equal to "tag"
                    //convert first 3 chars to lowercase 
                    /*byte byrl_tagname[] = {0,0,0,0};
                    int iml_i = 0;
                    while ((iml_i < 3) && (iml_tag < iml_equals))
                    {
                        byrl_tagname[iml_i] = m_tolower(byrp_packet[iml_tag]);
                        iml_tag++;
                        iml_i++;
                    };        
                    if (!strcmp("tag",byrl_tagname))  */
                    if (m_eqlowercase2(dsrr_sip_const_strings,sizeof(dsrr_sip_const_strings) / (sizeof(int)*2),IM_CONST_TAG,byrp_packet,iml_tag,iml_equals-iml_tag))
                    {
                        imrp_dest[imp_index+IM_URI_tag_POS] = iml_equals+1;
                        imrp_dest[imp_index+IM_URI_tag_LEN] = iml_nexttag-iml_equals-1;
                    }
                }
            }
        }
        iml_tag = iml_nexttag;



    }
    //set the position and length of parameters for this uri. 
    //Parsing of specific parameters is not done here since it is not always required.
    imrp_dest[imp_index+IM_URI_fields_POS] = iml_fields;
    imrp_dest[imp_index+IM_URI_fields_LEN] = imp_end-iml_fields;
    return 0;

}


int ds_hobphone2::m_parse_cseq(char byrp_packet[], int imp_start, int imp_len,int imrp_dest[], int imp_index, long ilrl_cseqval[])
{
    imrp_dest[imp_index] = -1;
    imrp_dest[imp_index+1] = 0;
    int iml_end = imp_start+imp_len;
    int iml_space = m_findnext(byrp_packet,imp_start,iml_end,' ');
    if (iml_space < 0)
        iml_space = iml_end;
    //long ilrl_val[] = {-1};
    if (!m_checkint(byrp_packet,imp_start,iml_space-imp_start,0,IM_CSEQ_MAX_VAL,ilrl_cseqval))
    { 
        m_writetolog(LEVEL_INFO,"Invalid CSeq - non numeric or out of range",byrp_packet,imp_start,imp_len);
        return -2;
    }
    iml_space = m_trimleading(byrp_packet,iml_space,iml_end-1);  //ignore leading whitespace
    int iml_requesttype = m_is_validrequest(byrp_packet,iml_space,iml_end-iml_space);
    if (iml_requesttype > 0)
    {
        imrp_dest[imp_index] = imp_start;
        imrp_dest[imp_index+1] = imp_len;
    }
    return iml_requesttype;
}

BOOL ds_hobphone2::m_parse_rfc1123_date(char byrp_packet[], int imp_start, int imp_len,int imrp_dest[], int imp_index)
{
    //assume error
    imrp_dest[imp_index] = -1; //POS
    imrp_dest[imp_index+1] = 0; //LEN

    int iml_end = imp_start+imp_len;
    //we need 2 variables to hold the positions of space characters so that we 
    //can check the parts between them. Date format is as follows:


    int iml_space1; //used to hold positions of odd numbered spaces (1,3 and 5)
    int iml_space2; //used to hold positions of even numbered spaces (2 and 4)

    iml_space1 = m_findnext(byrp_packet,imp_start,iml_end,' '); //first space
    if (iml_space1 == -1)
    {
        return false; //date too short           
    }

    int iml_comma = m_endswith(byrp_packet,imp_start,iml_space1,',');
    if (iml_comma == -1 || !m_is_weekday(byrp_packet,imp_start,iml_comma-imp_start)) 
    {
        return false; //invalid weekday
    }

    iml_space2 = m_findnext(byrp_packet,iml_space1+1,iml_end,' ');  //second space                                                 

    //check day - we are also allowing single digit days which are not strictly compliant
    if (iml_space2 == -1 || !m_checkint(byrp_packet,iml_space1+1,iml_space2-1-iml_space1,1,31,null))
    {
        return false; //invalid day   or //date too short
    }

    iml_space1 = m_findnext(byrp_packet,iml_space2+1,iml_end,' ');  //third space
    if (iml_space1 == -1 || !m_is_month(byrp_packet,iml_space2+1,iml_space1-1-iml_space2))
    {
        return false; //invalid month (or date too short)
    }

    iml_space2 = m_findnext(byrp_packet,iml_space1+1,iml_end,' ');  //fourth space
    //check Year - we start from 1000 - 9999 to ensure 4 digits
    if (iml_space2 == -1 || !m_checkint(byrp_packet,iml_space1+1,iml_space2-1-iml_space1,1000,9999,null))
    {
        return false; //invalid year   or //date too short
    }

    iml_space1 = m_findnext(byrp_packet,iml_space2+1,iml_end,' ');  //fifth (last) space

    int iml_colon = m_findnext(byrp_packet,iml_space2+1,iml_space1,':');
    if (iml_colon == -1 || !m_checkint(byrp_packet,iml_space2+1,iml_colon-1-iml_space2,0,23,null))
    {
        return false;  //incorrect hour
    }      

    int iml_colon2 = m_findnext(byrp_packet,iml_colon+1,iml_space1,':');
    if (iml_colon2 == -1 || !m_checkint(byrp_packet,iml_colon+1,iml_colon2-1-iml_colon,0,59,null))
    {
        return false; //incorrect minutes 
    } 

    if (!m_checkint(byrp_packet,iml_colon2+1,iml_space1-1-iml_colon2,0,59,null))
    {
        return false;  //incorrect seconds
    }   

    if ((iml_end-1-iml_space1) != 3)
    {
        return false;
    }

    int imli = 0;
    while (imli < 3)
    {        
        if (byrp_packet[++iml_space1] != STR_GMT[imli++])
        {
            return false; //invalid timezone
        }
    }

    imrp_dest[imp_index] = imp_start; //POS
    imrp_dest[imp_index+1] = imp_len; //LEN
    return true;
}


BOOL ds_hobphone2::m_is_weekday(char byrp_packet[], int imp_start, int imp_len)
{
    //TODO - we can do this using a hash
    if (imp_len != 3)
        return false;

    switch (byrp_packet[imp_start])
    {
        case 'F':
            if (byrp_packet[imp_start+1] == 'r' && byrp_packet[imp_start+2] == 'i')
                return true;
            break;
        case 'M':
            if (byrp_packet[imp_start+1] == 'o' && byrp_packet[imp_start+2] == 'n')
                return true;
            break;
        case 'S':
             if ((byrp_packet[imp_start+1] == 'a' && byrp_packet[imp_start+2] == 't') || (byrp_packet[imp_start+1] == 'u' && byrp_packet[imp_start+2] == 'n'))
                return true;
            break;
        case 'T':
            if ((byrp_packet[imp_start+1] == 'u' && byrp_packet[imp_start+2] == 'e') || (byrp_packet[imp_start+1] == 'h' && byrp_packet[imp_start+2] == 'u'))
                return true;
            break;
        case 'W':
            if (byrp_packet[imp_start+1] == 'e' && byrp_packet[imp_start+2] == 'd')
                return true;
            break;
        default:
            break;
    }

    /*if (!memcmp(&byrp_packet[imp_start],"Mon",3) ||
        !memcmp(&byrp_packet[imp_start],"Tue",3) ||
        !memcmp(&byrp_packet[imp_start],"Wed",3) ||
        !memcmp(&byrp_packet[imp_start],"Thu",3) ||
        !memcmp(&byrp_packet[imp_start],"Fri",3) ||
        !memcmp(&byrp_packet[imp_start],"Sat",3) ||
        !memcmp(&byrp_packet[imp_start],"Sun",3))
        return true;*/
    return false;

}

BOOL ds_hobphone2::m_is_month(char byrp_packet[], int imp_start, int imp_len)
{
    //TODO - we can do this using a hash
    if (imp_len != 3)
        return false;

      switch (byrp_packet[imp_start])
      {
        case 'A':
            if ((byrp_packet[imp_start+1] == 'p' && byrp_packet[imp_start+2] == 'r') || (byrp_packet[imp_start+1] == 'u' && byrp_packet[imp_start+2] == 'g'))
                return true;
            break;
        case 'D':
            if (byrp_packet[imp_start+1] == 'e' && byrp_packet[imp_start+2] == 'c')
                return true;
            break;
        case 'F':
            if (byrp_packet[imp_start+1] == 'e' && byrp_packet[imp_start+2] == 'b')
                return true;
            break;
        case 'J':
            switch (byrp_packet[imp_start+1])
            {
            case 'a':
                 if (byrp_packet[imp_start+2] == 'n')
                     return true;
                 break;
            case 'u':
                 if ((byrp_packet[imp_start+2] == 'n') || (byrp_packet[imp_start+2] == 'l'))
                     return true;
            }
            break;
        case 'M':
            if ((byrp_packet[imp_start+1] == 'a' && byrp_packet[imp_start+2] == 'r') || (byrp_packet[imp_start+1] == 'a' && byrp_packet[imp_start+2] == 'y'))
                return true;
            break;
        case 'N':
            if (byrp_packet[imp_start+1] == 'o' && byrp_packet[imp_start+2] == 'v')
                return true;
            break;
        case 'O':
            if (byrp_packet[imp_start+1] == 'c' && byrp_packet[imp_start+2] == 't')
                return true;
            break;
        case 'S':
             if (byrp_packet[imp_start+1] == 'e' && byrp_packet[imp_start+2] == 'p')
                return true;
            break;
        default:
            break;
        }
   /* if (!memcmp(&byrp_packet[imp_start],"Jan",3) ||
        !memcmp(&byrp_packet[imp_start],"Feb",3) ||
        !memcmp(&byrp_packet[imp_start],"Mar",3) ||
        !memcmp(&byrp_packet[imp_start],"Apr",3) ||
        !memcmp(&byrp_packet[imp_start],"May",3) ||
        !memcmp(&byrp_packet[imp_start],"Jun",3) ||
        !memcmp(&byrp_packet[imp_start],"Jul",3) ||
        !memcmp(&byrp_packet[imp_start],"Aug",3) ||
        !memcmp(&byrp_packet[imp_start],"Sep",3) ||
        !memcmp(&byrp_packet[imp_start],"Oct",3) ||
        !memcmp(&byrp_packet[imp_start],"Nov",3) ||
        !memcmp(&byrp_packet[imp_start],"Dec",3))
        return true;           */
    return false;

}

int ds_hobphone2::m_findheader(char byrp_packet[], int imp_start, int imp_end)
{

    //ignore leading and trailing whitespace
    while (byrp_packet[imp_start] == ' ' || byrp_packet[imp_start] == '\t')
    {
        imp_start++;
    }
    //ignore the colon
    imp_end--;
    imp_end--; //character before the colon
    //check for whitespace between the header name and the colon
    while (byrp_packet[imp_end] == ' ' || byrp_packet[imp_end] == '\t')
    {
        imp_end--;
    }
    imp_end++;//go back to the char after the last valid char
    int iml_hdrlen = imp_end-imp_start;
    //SDH char* byrl_header = new char[iml_hdrlen]; 
    char byrl_header[128];
    if (iml_hdrlen > 127)
        return -1;

    // byrl_header[imp_end - imp_start] = '\0';
    int iml_pos = 0;

    //convert to lowercase
    while (imp_start < imp_end)
    {
        byrl_header[iml_pos] = m_tolower(byrp_packet[imp_start]);
        imp_start++;
        iml_pos++;
    };

    int iml_adler = m_calc_adler(byrl_header,0,iml_hdrlen);
    int iml1 = 0;
    int iml_numitems = sizeof(dsrr_sip_headers) / (sizeof(int)*2);
    do {
        if (dsrr_sip_headers[ iml1 ][0]== iml_adler) {  /* compare hash of name */
            //delete[] byrl_header;
            return dsrr_sip_headers[iml1][1];                       /* option found in table   */
        }
        iml1++;                                /* increment index         */
    } while (iml1 < iml_numitems) ;


    //delete[] byrl_header;
    return -1;
}


////SIP response    (c_line / c_sipengine)
#define imf_BAD_REQUEST 400
#define imf_OK 200
#define imf_NOT_ACCEPTABLE_HERE 488


BOOL ds_hobphone2::m_received_siprequest(c_parsedmessage2* ds_msg_in, char* byrp_reply, int imp_maxlen, int* imp_replylen)
{
    const char* achl_contact = "";
    

    if (!(ds_msg_in->imc_error == 0))
	{
		return m_prepare_response(achl_contact,imf_BAD_REQUEST, *ds_msg_in,imp_maxlen,imp_replylen,byrp_reply);
	}
	else
	{
	switch(ds_msg_in->imc_is_request)		{
        case IM_REQ_INVITE: 
            return FALSE; //error - not handled - we should never get here			
		case IM_REQ_OPTIONS:// c_sipconstants.byf_OPTIONS:
			/* OPTIONS */
			return m_prepare_response(achl_contact,imf_OK, *ds_msg_in,imp_maxlen,imp_replylen,byrp_reply);
			break;
		case IM_REQ_REGISTER:
		case IM_REQ_MESSAGE:
		case IM_REQ_INFO:
		case IM_REQ_SUBSCRIBE:
		case IM_REQ_REFER:
		case IM_REQ_PRACK:
		case IM_REQ_PUBLISH:
		case IM_REQ_UPDATE:
            return FALSE; //we should never get here
			
		case IM_REQ_NOTIFY: /* NOTIFY */
			// TODO: Process NOTIFY
			return m_prepare_response(achl_contact,imf_NOT_ACCEPTABLE_HERE, *ds_msg_in,imp_maxlen,imp_replylen,byrp_reply); //TODO or do we send not allowed ? 
			break;
		default:
			 return FALSE; //error - not handled - we should never get here
	}
	}
}


//////// c_siprequest
static byte byrr_sipmethods[][10] = {
     "INVITE", "ACK","CANCEL","BYE","OPTIONS","REGISTER","REGISTER",
     "MESSAGE","INFO","SUBSCRIBE","NOTIFY","REFER","PRACK","PUBLISH","UPDATE",
    }; //register repeated for UNREGISTER event

static final byte RFC3515_TRYING[] =  "SIP/2.0 100 Trying";
static final byte RFC3515_OK[] = "SIP/2.0 200 OK";  
static final byte RFC3515_UNAVAILABLE[] = "SIP/2.0 503 Service Unavailable";
static final byte RFC3515_DECLINED[] = "SIP/2.0 603 Declined";
static final byte STR_SIPV[] = "SIP/2.0 ";
static final byte STR_SIP[] = "sip:";
static final byte STR_SIPVEOL[] = " SIP/2.0\r\n";
static final byte STR_RPORT[] = ";rport";
static final byte STR_BRANCH[] = ";branch=";
static final byte STR_SIPH_ROUTE[] = "Route: ";
static final byte STR_SIPH_TO[] = "To: ";
static final byte STR_PARAM_TAG[] = ";tag=";
static final byte STR_SIPH_REFERTO[] = "Refer-To: ";
static final byte STR_SIPH_CONTACT[] = "Contact: ";
static final byte STR_SIPH_MAXF[] = "Max-forwards: 70\r\n";
static final byte STR_SIPH_CONTENTLEN[] = "Content-Length: ";
static final byte STR_SIPH_DATE[] = "Date: ";
static final byte STR_SIPH_EXPIRES900[] = "Expires: 900\r\n";
static final byte STR_SIPH_EXPIRES0[] = "Expires: 0\r\n";
static final byte STR_SIPH_ALLOW[] = "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n";
static final byte STR_SIPH_SUBSCRIPTION[] = "Subscription-state: ";
static final byte STR_SUBSCRIPTION_ACTIVE[] = "active\r\n";
static final byte STR_SUBSCRIPTION_TERMINATED[] = "terminated\r\n";
static final byte STR_SIPH_SIPFRAG[] = "Content-Type: message/sipfrag\r\n";
static final byte STR_SIPH_SDP[] = "Content-Type: application/sdp\r\n";
static final byte STR_SIPH_CALLID[] = "Call-ID: ";
static final byte STR_SIPH_CSEQ[] = "CSeq: ";
static final byte STR_SIPH_UA[] = "User-Agent: ";
static final byte STR_SIPH_VIA[] = "Via: ";
static final byte STR_SIPH_RECORDROUTE[] = "Record-Route: ";
static final byte STR_SIPH_FROM[] = "From: ";
static final byte STR_SIPH_ACCEPTLANG[] = "Accept: application/sdp\r\n";
static final byte STR_SIPH_ACCEPT[] = "Accept-Language: en\r\n";

static final byte STR_UA[] = "HOBPhone v2.3";

static final byte byr_TRYING[] = "Trying";
static final byte byr_RINGING[] = "Ringing";
static final byte byr_CALL_IS_BEING_FORWARDED[] = "Call is Being Forwarded";
static final byte byr_QUEUED[] = "Queued";
static final byte byr_SESSION_PROGRESS[] = "Session Progress";
static final byte byr_OK[] = "OK";
static final byte byr_ACCEPTED[] = "Accepted";
static final byte byr_MULTIPLE_CHOICES[] = "Multiple Choices";
static final byte byr_MOVED_PERMANENTLY[] = "Moved Permanently";
static final byte byr_MOVED_TEMPORARILY[] = "Moved Temporarily";
static final byte byr_USE_PROXY[] = "Use Proxy";
static final byte byr_ALTERNATIVE_SERVICE[] = "Alternative Service";
static final byte byr_BAD_REQUEST[] = "Bad Request";
static final byte byr_UNAUTHORIZED[] = "Unauthorized";
static final byte byr_PAYMENT_REQUIRED[] = "Payment Required";
static final byte byr_FORBIDDEN[] = "Forbidden";
static final byte byr_NOT_FOUND[] = "Not Found";
static final byte byr_METHOD_NOT_ALLOWED[] = "Method Not Allowed";
static final byte byr_NOT_ACCEPTABLE[] = "Not Acceptable";
static final byte byr_PROXY_AUTHENTICATION_REQUIRED[] = "Proxy Authentication Required";
static final byte byr_REQUEST_TIMEOUT[] = "Request Timeout";
static final byte byr_GONE[] = "Gone";
static final byte byr_REQUEST_ENTITY_TOO_LARGE[] = "Request Entity Too Large";
static final byte byr_REQUEST_URI_TOO_LONG[] = "Request-URI Too Long";
static final byte byr_UNSUPPORTED_MEDIA_TYPE[] = "Unsupported Media Type";
static final byte byr_UNSUPPORTED_URI_SCHEME[] = "Unsupported URI Scheme";
static final byte byr_BAD_EXTENSION[] = "Bad Extension";
static final byte byr_EXTENSION_REQUIRED[] = "Extension Required";
static final byte byr_INTERNAL_TOO_BRIEF[] = "Internal Too Brief";
static final byte byr_TEMPORARILY_UNAVAILABLE[] = "Temporarily Unavailable";
static final byte byr_CALL_TRANSACTION_DOES_NOT_EXIST[] = "Call/Transaction Does Not Exist";
static final byte byr_LOOP_DETECTED[] = "Loop Detected";
static final byte byr_TOO_MANY_HOPS[] = "Too Many Hops";
static final byte byr_ADDRESS_INCOMPLETE[] = "Address Incomplete";
static final byte byr_AMBIGOUS[] = "Ambigous";
static final byte byr_BUSY_HERE[] = "Busy Here";
static final byte byr_REQUEST_TERMINATED[] = "Request Terminated";
static final byte byr_NOT_ACCEPTABLE_HERE[] = "Not Acceptable Here";
static final byte byr_REQUEST_PENDING[] = "Request Pending";
static final byte byr_UNDECIPHERABLE[] = "Undecipherable";
static final byte byr_SERVER_INTERNAL_ERROR[] = "Server Internal Error";
static final byte byr_NOT_IMPLEMENTED[] = "Not Implemented";
static final byte byr_BAD_GATEWAY[] = "Bad Gateway";
static final byte byr_SERVICE_UNAVAILABLE[] = "Service Unavailable";
static final byte byr_SERVER_TIMEOUT[] = "Server Timeout";
static final byte byr_VERSION_NOT_SUPPORTED[] = "Version Not Supported";
static final byte byr_MESSAGE_TOO_LARGE[] = "Message Too Large";
static final byte byr_BUSY_EVERYWHERE[] = "Busy Everywhere";
static final byte byr_DECLINE[] = "Decline";
static final byte byr_DOES_NOT_EXIST_ANYWHERE[] = "Does Not Exist Anywhere";
static final byte byr_NOT_ACCEPTABLE_GLOBAL[] = "Not Acceptable";


enum ied_sip_strings{
IM_TRYING = 100,
IM_RINGING = 180,
IM_CALL_IS_BEING_FORWARDED = 181,
IM_QUEUED = 182,
IM_SESSION_PROGRESS = 183,
IM_OK = 200,
IM_ACCEPTED = 202,
IM_MULTIPLE_CHOICES = 300,
IM_MOVED_PERMANENTLY = 301,
IM_MOVED_TEMPORARILY = 302,
IM_USE_PROXY = 305,
IM_ALTERNATIVE_SERVICE = 380,
IM_BAD_REQUEST = 400,
IM_UNAUTHORIZED = 401,
IM_PAYMENT_REQUIRED = 402,
IM_FORBIDDEN = 403,
IM_NOT_FOUND = 404,
IM_METHOD_NOT_ALLOWED = 405,
IM_NOT_ACCEPTABLE = 406,
IM_PROXY_AUTHENTICATION_REQUIRED = 407,
IM_REQUEST_TIMEOUT = 408,
IM_GONE = 410,
IM_REQUEST_ENTITY_TOO_LARGE = 413,
IM_REQUEST_URI_TOO_LONG = 414,
IM_UNSUPPORTED_MEDIA_TYPE = 415,
IM_UNSUPPORTED_URI_SCHEME = 416,
IM_BAD_EXTENSION = 420,
IM_EXTENSION_REQUIRED = 421,
IM_INTERNAL_TOO_BRIEF = 423,
IM_TEMPORARILY_UNAVAILABLE = 480,
IM_CALL_TRANSACTION_DOES_NOT_EXIST = 481,
IM_LOOP_DETECTED = 482,
IM_TOO_MANY_HOPS = 483,
IM_ADDRESS_INCOMPLETE = 484,
IM_AMBIGOUS = 485,
IM_BUSY_HERE = 486,
IM_REQUEST_TERMINATED = 487,
IM_NOT_ACCEPTABLE_HERE = 488,
IM_REQUEST_PENDING = 491,
IM_UNDECIPHERABLE = 493,
IM_SERVER_INTERNAL_ERROR = 500,
IM_NOT_IMPLEMENTED = 501,
IM_BAD_GATEWAY = 502,
IM_SERVICE_UNAVAILABLE = 503,
IM_SERVER_TIMEOUT = 504,
IM_VERSION_NOT_SUPPORTED = 505,
IM_MESSAGE_TOO_LARGE = 513,
IM_BUSY_EVERYWHERE = 600,
IM_DECLINE = 603,
IM_DOES_NOT_EXIST_ANYWHERE = 604,
IM_NOT_ACCEPTABLE_GLOBAL = 606
};

//"INVITE", "ACK","CANCEL","BYE","OPTIONS","REGISTER","REGISTER","MESSAGE","INFO","SUBSCRIBE","NOTIFY","REFER","PRACK","PUBLISH","UPDATE",
enum ied_sip_methods{
IM_INVITE,
IM_ACK,
IM_CANCEL,
IM_BYE,
IM_OPTIONS,
IM_REGISTER,
IM_UNREGISTER,
IM_MESSAGE,
IM_INFO,
IM_SUBSCRIBE,
IM_NOTIFY,
IM_REFER,
IM_PRACK,
IM_PUBLISH,
IM_UPDATE,
IM_SIP_METHOD_INVALID
};


const char* ds_hobphone2::get_keyname(int key) {
	switch (key) {
		case IM_TRYING:
			return byr_TRYING;
		case IM_RINGING:
			return byr_RINGING;
		case IM_CALL_IS_BEING_FORWARDED:
			return byr_CALL_IS_BEING_FORWARDED;
		case IM_QUEUED:
			return byr_QUEUED;
		case IM_SESSION_PROGRESS:
			return byr_SESSION_PROGRESS;
		case IM_OK:
			return byr_OK;
		case IM_ACCEPTED:
			return byr_ACCEPTED;
		case IM_MULTIPLE_CHOICES:
			return byr_MULTIPLE_CHOICES;
		case IM_MOVED_PERMANENTLY:
			return byr_MOVED_PERMANENTLY;
		case IM_MOVED_TEMPORARILY:
			return byr_MOVED_TEMPORARILY;
		case IM_USE_PROXY:
			return byr_USE_PROXY;
		case IM_ALTERNATIVE_SERVICE:
			return byr_ALTERNATIVE_SERVICE;
		case IM_BAD_REQUEST:
			return byr_BAD_REQUEST;
		case IM_UNAUTHORIZED:
			return byr_UNAUTHORIZED;
		case IM_PAYMENT_REQUIRED:
			return byr_PAYMENT_REQUIRED;
		case IM_FORBIDDEN:
			return byr_FORBIDDEN;
		case IM_NOT_FOUND:
			return byr_NOT_FOUND;
		case IM_METHOD_NOT_ALLOWED:
			return byr_METHOD_NOT_ALLOWED;
		case IM_NOT_ACCEPTABLE:
			return byr_NOT_ACCEPTABLE;
		case IM_PROXY_AUTHENTICATION_REQUIRED:
			return byr_PROXY_AUTHENTICATION_REQUIRED;
		case IM_REQUEST_TIMEOUT:
			return byr_REQUEST_TIMEOUT;
		case IM_GONE:
			return byr_GONE;
		case IM_REQUEST_ENTITY_TOO_LARGE:
			return byr_REQUEST_ENTITY_TOO_LARGE;
		case IM_REQUEST_URI_TOO_LONG:
			return byr_REQUEST_URI_TOO_LONG;
		case IM_UNSUPPORTED_MEDIA_TYPE:
			return byr_UNSUPPORTED_MEDIA_TYPE;
		case IM_UNSUPPORTED_URI_SCHEME:
			return byr_UNSUPPORTED_URI_SCHEME;
		case IM_BAD_EXTENSION:
			return byr_BAD_EXTENSION;
		case IM_EXTENSION_REQUIRED:
			return byr_EXTENSION_REQUIRED;
		case IM_INTERNAL_TOO_BRIEF:
			return byr_INTERNAL_TOO_BRIEF;
		case IM_TEMPORARILY_UNAVAILABLE:
			return byr_TEMPORARILY_UNAVAILABLE;
		case IM_CALL_TRANSACTION_DOES_NOT_EXIST:
			return byr_CALL_TRANSACTION_DOES_NOT_EXIST;
		case IM_LOOP_DETECTED:
			return byr_LOOP_DETECTED;
		case IM_TOO_MANY_HOPS:
			return byr_TOO_MANY_HOPS;
		case IM_ADDRESS_INCOMPLETE:
			return byr_ADDRESS_INCOMPLETE;
		case IM_AMBIGOUS:
			return byr_AMBIGOUS;
		case IM_BUSY_HERE:
			return byr_BUSY_HERE;
		case IM_REQUEST_TERMINATED:
			return byr_REQUEST_TERMINATED;
		case IM_NOT_ACCEPTABLE_HERE:
			return byr_NOT_ACCEPTABLE_HERE;
		case IM_REQUEST_PENDING:
			return byr_REQUEST_PENDING;
		case IM_UNDECIPHERABLE:
			return byr_UNDECIPHERABLE;
		case IM_SERVER_INTERNAL_ERROR:
			return byr_SERVER_INTERNAL_ERROR;
		case IM_NOT_IMPLEMENTED:
			return byr_NOT_IMPLEMENTED;
		case IM_BAD_GATEWAY:
			return byr_BAD_GATEWAY;
		case IM_SERVICE_UNAVAILABLE:
			return byr_SERVICE_UNAVAILABLE;
		case IM_SERVER_TIMEOUT:
			return byr_SERVER_TIMEOUT;
		case IM_VERSION_NOT_SUPPORTED:
			return byr_VERSION_NOT_SUPPORTED;
		case IM_MESSAGE_TOO_LARGE:
			return byr_MESSAGE_TOO_LARGE;
		case IM_BUSY_EVERYWHERE:
			return byr_BUSY_EVERYWHERE;
		case IM_DECLINE:
			return byr_DECLINE;
		case IM_DOES_NOT_EXIST_ANYWHERE:
			return byr_DOES_NOT_EXIST_ANYWHERE;
		case IM_NOT_ACCEPTABLE_GLOBAL:
			return byr_NOT_ACCEPTABLE_GLOBAL;
		default:
			return "";
	}
}


const byte* ds_hobphone2::m_get_sip_method(int imp_method)
{             
    if (imp_method >= 0 && imp_method < IM_SIP_METHOD_INVALID)
        return byrr_sipmethods[imp_method];
    else 
    	return get_keyname(imp_method);
    return null;
}



BOOL ds_hobphone2::m_prepare_response(const char* chr_contact, int imp_msgkey, /* c_sipdialog* dsp_dialog, byte byrp_content[],*/ c_parsedmessage2& dsp_msg_in, int imp_maxlen, int imrp_length[], char* byrp_request)
{
    
    //char byrl_request[2048];
    c_request adsl_request(byrp_request, imp_maxlen);
    const byte* byrl_method;
    byte* byrl_srcbuffer;
    int* imrl_message;
    
    byrl_method = m_get_sip_method(imp_msgkey);
    byrl_srcbuffer = dsp_msg_in.byrc_message;
    imrl_message = dsp_msg_in.imrc_message;
    //SIP/2.0 nnn METHOD\r\n


    //NOTE on return values from c_request methods: 
    // Adding data to the request can fail by returning -1 if there is insufficient space in the buffer.
    // This also sets the imc_error which is then checked at the end of this function.
    // A check after every call is thus not necessary since it would only speed up processing
    // in the case of insufficient space (which is not expected to occur normally) but slow down
    // processing on every successful request (1 additional check per added SIP part)
    adsl_request.m_addstring(STR_SIPV);
    adsl_request.m_addint(imp_msgkey);
    adsl_request.m_addspace();
    adsl_request.m_addstring(byrl_method);
    adsl_request.m_endline();

    //VIA
    /*PHEADERLIST adsl_via =  dsp_msg_in.dsc_via;
    if (adsl_via != null)
    {
        do
        {
            adsl_request.m_addstring(STR_SIPH_VIA);
            adsl_request.m_addbytes(byrl_srcbuffer,adsl_via->imrc_sub[IM_POS],adsl_via->imrc_sub[IM_LEN]);
            adsl_request.m_endline();
adsl_via = adsl_via->adsc_next;
        }while (adsl_via != null);
    }         */ 
    //SDH VIA changed to single item
    adsl_request.m_addstring(STR_SIPH_VIA);
    adsl_request.m_addbytes(byrl_srcbuffer,dsp_msg_in.imc_viapos,dsp_msg_in.imc_vialen);
    adsl_request.m_endline();
    //process record-route entries if they exist
   
    //SDH record route not processed
    /*
    PHEADERLIST adsl_recordroute = dsp_msg_in.dsc_record_route;
    if (adsl_recordroute != null)
    {
        do
        {
            adsl_request.m_addstring(STR_SIPH_RECORDROUTE);
            adsl_request.m_addbytes(byrl_srcbuffer,adsl_recordroute->imrc_sub[IM_POS],adsl_recordroute->imrc_sub[IM_LEN]);
            adsl_request.m_endline();
adsl_recordroute = adsl_recordroute->adsc_next;
        }while (adsl_recordroute != null);
    }
    */

    //FROM
    adsl_request.m_addstring(STR_SIPH_FROM);
    adsl_request.m_addbytes(byrl_srcbuffer,imrl_message[IM_From_content_POS],imrl_message[IM_From_content_LEN]);
    adsl_request.m_endline();
    //TO
    adsl_request.m_addstring(STR_SIPH_TO);
    adsl_request.m_addbytes(byrl_srcbuffer,imrl_message[IM_To_content_POS],imrl_message[IM_To_content_LEN]);
  /*SDH TODO - add to tag
    if (imp_msgkey != IM_TRYING)
    {
        //add the local tag, if it has not already been generated a new tag is generated by m_get_localtag()
        //SDH no dialog - if (dsp_dialog != null)
        {   
            //if no tag add it
            adsl_request.m_addstring(STR_PARAM_TAG);
            byte* byrl_localtag = m_get_localtag();
            adsl_request.m_addstring(byrl_localtag);
        }
    }   */

    adsl_request.m_endline();
    //CALLID
    adsl_request.m_addstring(STR_SIPH_CALLID);
    adsl_request.m_addbytes(byrl_srcbuffer,imrl_message[IM_Call_ID_POS],imrl_message[IM_Call_ID_LEN]);
    adsl_request.m_endline();
    //cseq
    adsl_request.m_addstring(STR_SIPH_CSEQ);
    adsl_request.m_addbytes(byrl_srcbuffer,imrl_message[IM_CSeq_POS],imrl_message[IM_CSeq_LEN]);
    adsl_request.m_endline();
    //contact
 //SDH TODO TODO TODO
    /*adsl_request.m_addstring(STR_SIPH_CONTACT);
    adsl_request.m_addstring(chr_contact);
    adsl_request.m_endline();*/
    //User agent
    adsl_request.m_addstring(STR_SIPH_UA);
    adsl_request.m_addstring(STR_UA);
    adsl_request.m_endline();
    //ALLOW:
    if (dsp_msg_in.imc_is_request == IM_REQ_OPTIONS)
    {
    	adsl_request.m_addstring(STR_SIPH_ALLOW);
        adsl_request.m_addstring(STR_SIPH_ACCEPT);
        adsl_request.m_addstring(STR_SIPH_ACCEPTLANG);
    }
    //CONTENT
   /* int iml_contentlen = 0;
    if (byrp_content != null)
    {        
        iml_contentlen = strlen(byrp_content);
    }
    if (iml_contentlen > 0)
    {
        adsl_request.m_addstring(STR_SIPH_SDP);
        adsl_request.m_addstring(STR_SIPH_CONTENTLEN);
        adsl_request.m_addint(iml_contentlen);
        adsl_request.m_endline();
        adsl_request.m_endline();
        adsl_request.m_addbytes(byrp_content,0,iml_contentlen);
        //adsl_request.m_endline();
        //adsl_request.m_endline();
    }
    else
    { */                                                
    adsl_request.m_addstring(STR_SIPH_CONTENTLEN);
    adsl_request.m_addint(0);
    adsl_request.m_endline();
    adsl_request.m_endline();
    /*}             */
    //adsl_request.m_addchar('\0');
    if (adsl_request.imc_error == 0)
    {
    	imrp_length[0] = adsl_request.imc_offset;
    	return TRUE;//adsl_request.byrc_request;
    }
    imrp_length[0] = 0;
    return FALSE;

}

//pu
#define ADLER_BASE             65521        /* largest prime smaller than 65536 */
int ds_hobphone2::m_calc_adler( char achp_buffer[], int imp_start, int imp_end)
{
    int        iml_adler;
    int        iml_sum2;
    //char       *achl_cur;
    //char       *achl_end;

    iml_adler = iml_sum2 = 0;
    //achl_cur = achp_buffer;
    //achl_end = achp_buffer + imp_len_buffer;

    do {
        iml_adler += achp_buffer[imp_start];
        imp_start++;
        iml_sum2 += iml_adler;
        if (iml_adler >= ADLER_BASE) iml_adler -= ADLER_BASE;
    } while (imp_start < imp_end);
    iml_sum2 %= ADLER_BASE;
    return iml_adler | (iml_sum2 << 16);
} 


BOOL ds_hobphone2::m_eqlowercase2(const int dsrrp_strings[][2],int imp_size, int imp_compareto, char byrp_packet[], int imp_start, int imp_len)
{
    if (imp_len <= 0 ||imp_len > 127) //SDH added max len
        return false;
    //first get the hash of the expected item
    int imli = 0;
    int iml_adlertarget = 0;


    int iml_numitems = imp_size;//sizeof(dsrrp_strings) / (sizeof(int)*2);


    do{
        if (dsrrp_strings[imli][1] == imp_compareto){
            iml_adlertarget = dsrrp_strings[imli][0]; //match
            break;
        }
        imli++;
    }while(imli < iml_numitems);

    int iml_end = imp_start+imp_len;
    //convert to lowercase 
    char byrl_newstring[128];//SDH = new char[imp_len];
    imli = 0;
    //convert  to lowercase   
    while (imli < imp_len && imp_start < iml_end)
    {
        byrl_newstring[imli] = m_tolower(byrp_packet[imp_start]);
        imp_start++;
        imli++;
    };      
    if (imp_start != iml_end)
    {
        //SDH delete[] byrl_newstring;
        return false;
    }

    //calculate hash of string in packet
    int iml_adler = m_calc_adler(byrl_newstring,0,imp_len);
    //SDH delete[] byrl_newstring;
    if (iml_adler == iml_adlertarget)
        return true;
    return false;
}


BOOL ds_hobphone2::m_checkint(char byrp_packet[], int imp_start, int imp_len, int imp_min, long ilp_max, long ilr_outval[])
{        
    if (imp_len <= 0)
        return false;
    long ull_num = 0;

    //ignore whitespace (including CRLF at the beginning and end
    while (byrp_packet[imp_start] == ' ' || byrp_packet[imp_start] == '\t' || byrp_packet[imp_start] == '\r' || byrp_packet[imp_start] == '\n')
    {
        imp_start++;
        imp_len--;
    }
    int iml_end = imp_start+imp_len-1;

    while (byrp_packet[iml_end] == ' ' || byrp_packet[iml_end] == '\t' || byrp_packet[iml_end] == '\r' || byrp_packet[iml_end] == '\n')
    {
        iml_end--;
        imp_len--;
    }
    iml_end++;

    //immediately exclude numbers longer than 10 digits
    if (imp_len > 10)
        return false;

    //since we can't use atoi without copying (requires null termination) use a custom atoi
    while ( imp_start<iml_end && byrp_packet[imp_start] >= '0' && byrp_packet[imp_start] <= '9' )
    {      
        ull_num = (ull_num * 10) + (byrp_packet[imp_start]) - '0';
        imp_start++;
    }
    //at this point we have a number which is maximum 9999999999

    //if greater than 2**31 return false
    //if (ull_num > IM_MAX_INT_32)
    //   return false;

    if (imp_start == iml_end)
    {
        if((imp_min < 0 || ull_num >= imp_min) && (ilp_max < 0 || ull_num <= ilp_max))
        {
            if (ilr_outval != null)
            {
                //ignore truncation warning since we already checked above if ull_num is in range
                ilr_outval[0]=(int)ull_num;  
            }
            return true;
        }//else number out of range
    }//else non numeric characters found

    return false;

}

/**
* Trim leading whitespace from a character sequence.
* @return The index of the first character that is not whitespace
*/

int ds_hobphone2::m_trimleading(char byrp_packet[], int imp_start, int imp_end)
{
    //ignore leading whitespace (including CRLF)
    while(imp_start < imp_end && (byrp_packet[imp_start] == ' ' || byrp_packet[imp_start] == '\t' || byrp_packet[imp_start] == '\r' || byrp_packet[imp_start] == '\n'))
    {
        imp_start++;
    }
    return imp_start;
}

/**
* Trim trailing whitespace from a character sequence.
* @return The index of the first character from the end of the sequence that is not whitespace
*/
int ds_hobphone2::m_trimtrailing(char byrp_packet[], int imp_start, int imp_end)
{
    //ignore leading whitespace (including CRLF)
    while(imp_start < imp_end && (byrp_packet[imp_end-1] == ' ' || byrp_packet[imp_end-1] == '\t' || byrp_packet[imp_end-1] == '\r' || byrp_packet[imp_end-1] == '\n') )
    {
        imp_end--;
    }
    return imp_end;
}

int ds_hobphone2::m_findnext(char byrp_packet[], int imp_start, int imp_end, char byp_char)
{
    if (imp_start < 0)
        return -1;
    while ((imp_start < imp_end) && (byrp_packet[imp_start] != byp_char))
    {
        imp_start++;
    }
    if (imp_start < imp_end)
        return imp_start;
    return -1;
}

int ds_hobphone2::m_findlast(char byrp_packet[], int imp_start, int imp_end, char byp_char)
{
    imp_end--; //do not include the last character
    while (imp_end >= imp_start && byrp_packet[imp_end] != byp_char)
    {
        imp_end--;
    }
    if (imp_end < imp_start)
        return -1;
    else
        return imp_end;
}

int ds_hobphone2::m_startswith(char byrp_packet[], int imp_start, int imp_end, char byp_char)
{
    //check for whitespace until the character before last. The last char will be compared
    //at the last step
    imp_end--; 

    //ignore leading whitespace
    while(imp_start < imp_end && (byrp_packet[imp_start] == ' ' || byrp_packet[imp_start] == '\t' || byrp_packet[imp_start] == '\r' || byrp_packet[imp_start] == '\n'  ))
    {
        imp_start++;
    }
    if (byrp_packet[imp_start] == byp_char)
    {
        return imp_start;
    }
    else
        return -1;
}

BOOL ds_hobphone2::m_iswhitespace(char byrp_packet[], int imp_start, int imp_end)
{  
    while(imp_start < imp_end && (byrp_packet[imp_start] == ' ' || byrp_packet[imp_start] == '\t' || byrp_packet[imp_start] == '\r' || byrp_packet[imp_start] == '\n') )
    {
        imp_start++;
    }
    return (imp_start == imp_end);
}

int ds_hobphone2::m_endswith(char byrp_packet[], int imp_start, int imp_end, char byp_char)
{
    //ignore trailing whitespace
    while(imp_end >= imp_start && (byrp_packet[imp_end] == ' ' || byrp_packet[imp_end] == '\t' || byrp_packet[imp_end] == '\r' || byrp_packet[imp_end] == '\n'))
    {
        imp_end--;
    }
    if (byrp_packet[imp_end] == byp_char)
    {
        return imp_end;
    }
    else
        return -1;
}

////c_request - changed to use memory allocated from caller - does not allocate or change size of memory used
#define IM_RESPONSE_INITSIZE 2048

c_request::c_request(char* byrp_request, int imp_maxsize)
{                  
    byrc_request = byrp_request;
    imc_size = imp_maxsize;
    imc_offset = 0;
    imc_error = 0;
}
    
int c_request::m_addstring(const char byrp_src[])
{
    if (byrp_src == null)
		return imc_offset;
    int imli = 0;        

    //find the end of the string
    //NOTE that if byrp_src is not null termianted we will get an exception --- C++ byrp_src MUST be null terminated
    while (byrp_src[imli] != '\0')
    {
    	imli++;
    }        
    //add the bytes to the buffer
    return m_addbytes(byrp_src,0,imli);
}

int c_request::m_addbytes(const char byrp_src[],int imp_srcpos, int imp_srclen)
{
    if (byrp_src == null)
		return imc_offset;
    int imli = 0;
    
    int iml_maxlen = imc_size-imc_offset;
    
    //if necessary resize the buffer
    //if (imp_srclen+IM_RESIZE_THRESHOLD > iml_maxlen)
    if (imp_srclen >= iml_maxlen) 
    {
        //resize disabled
        imc_error = imc_offset;
        return -1;
        //m_resizebuffer();
        //iml_maxlen = imc_size-imc_offset ;
    }

    //copy from source to destination
    while (imli < imp_srclen && imli < iml_maxlen)
    {
        byrc_request[imc_offset] = byrp_src[imp_srcpos];
        imc_offset++;
        imp_srcpos++;
        imli++;
    }
    if (imli == imp_srclen)
    {
        return imc_offset;
    }
    imc_error = imc_offset;
    return -1;
}

int c_request::m_addchar(char byp_src)
{
    if (imc_size <= imc_offset/*+IM_RESIZE_THRESHOLD*/)
    {
        imc_error = imc_offset;
        return -1;
        //m_resizebuffer();
    }

    byrc_request[imc_offset++] = (byte)byp_src;
    return imc_offset;
}

int c_request::m_addspace()
{
    if (imc_size <= imc_offset/*+IM_RESIZE_THRESHOLD*/)
    {
        imc_error = imc_offset;
        return -1;
        //m_resizebuffer();
    }

    byrc_request[imc_offset++] = ' ';
    return imc_offset;
}

int c_request::m_addint(long iml_val)
{
    if (imc_size <= imc_offset/*+IM_RESIZE_THRESHOLD*/)
    {
        imc_error = imc_offset;
        return -1;
        //m_resizebuffer();
    }
    //count number of digits
    long iml_temp = iml_val;
    int iml_digits = 0;
    if (iml_val == 0)
    {
        //handle special case where value is '0'
        iml_digits = 1;
    }
    else
    {
        while (iml_val > 0)
        {
            iml_digits++;
            iml_val = iml_val / 10;
        }
    }

    if (imc_size <= imc_offset+iml_digits)
    {
        imc_error = imc_offset;
        return -1;
        //m_resizebuffer();
    }

    int iml_newoffset = imc_offset+iml_digits;
            
    while (iml_digits > 0)
    {     
        iml_digits--;
        byrc_request[imc_offset+iml_digits] = (byte)('0'+(iml_temp%10));
        iml_temp = iml_temp / 10;            
    }

    imc_offset = iml_newoffset;
    return imc_offset;
}
int c_request::m_endline()
{
    if (imc_size <= imc_offset/*+IM_RESIZE_THRESHOLD*/)
    {
        imc_error = imc_offset;
        return -1;
        //m_resizebuffer();
    }

    byrc_request[imc_offset++] = '\r';
    byrc_request[imc_offset++] = '\n';
    return imc_offset;
}


////
