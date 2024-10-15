//+-------------------------------------------------------------------+
//|                                                                   |
//| PROGRAM NAME: xshsstp01.cpp                                       |
//| -------------                                                     |
//|  HOB SSTP Protocol module for use with HUSIP and WSP              |
//|    modules                                                        |
//|                                                                   |
//| COPYRIGHT:                                                        |
//| ----------                                                        |
//|  Copyright (C) HOB Germany 2015                                   |
//|                                                                   |
//+-------------------------------------------------------------------+

#ifndef D_INCL_TUN_CTRL
#define D_INCL_TUN_CTRL
#endif

#ifndef HL_UNIX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include "hob-unix01.h"
#endif
#ifndef HL_UNIX
#include <hob-avl03.h>
#else
#include "hob-avl03.h"
#endif
#ifndef HL_UNIX
typedef int socklen_t;
#endif
#ifdef HL_UNIX
#ifndef HOB_CONTR_TIMER
#define HOB_CONTR_TIMER
#endif
#ifdef HL_FREEBSD
//#include <net/if_tun.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if_tun.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <netinet/if_ether.h>
//#include <sys/types.h>
#include <sys/sysctl.h>
#endif
#include <net/if.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>

//#include "types_defines.h"
#ifndef byte
#define byte unsigned char
#endif

#else
#include <setupapi.h>
#endif
#include <hob-xslhcla1.hpp>
#include <hob-netw-01.h>
#include <string>
#include <map>
#include <list>
#include <queue>
#include <stddef.h>
#include <iostream>
#include <time.h>
#include "hob-xslcontr.h"
#include "hob-tun01.h"
#include "hob-htcp-int-01.h"
//#include "hob-htcp-int-types.h"
//#include "hob-htcp.h"
//#include "hob-htcp-bit-reference.h"
//#include "hob-htcp-tcpip-hdr.h"
//#include "hob-htcp-misc.h"
//#include "hob-htcp-connection.h"
#include "hob-session01.h"
//#include "hob-htcp-session.h"
#include "hob-gw-ppp-1.h"
#include "hob-hppp01.h"
#include "hob-hsstp01.h"
#include "hob-tuntapif01.h"
#include <stdio.h>
#include <vector>
#include "hob-xslcontr.h"
#include "hob-sessutil01.h"
#define DOMNode void
#define DEF_HL_INCL_DOM
#include "hob-wsppriv.h"
#include "hob-xsclib01.h"
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
#include "hob-http-header-1.h"
#include "hob-encry-1.h"


#ifdef HL_UNIX
#include <semaphore.h>
#endif

#ifndef MLSSTPHMAC
extern PTYPE BOOL m_check_tun_sstp_channel_binding( struct dsd_tun_contr_conn *, char *, int );
extern PTYPE BOOL m_get_tun_sstp_flag_channel_binding( struct dsd_tun_contr_conn * );
#endif

#define HTTP_PROTOVER "HTTP/1.1 "
#define HTTP_STATCODE "200 \r\n"
#define HTTP_CONTLEN  "Content-Length: 18446744073709551615\r\n"
#define HTTP_SERVER   "Server: HOB-WSP/2.3\r\n"
#define HTTP_DATE_LEN 39

#define BASE_ERR_NUMBER 200

// Buffer for Protocol Version string.
static const byte byrg_http_proto_ver[] = HTTP_PROTOVER;
static const unsigned int umg_len_http_proto_ver =
sizeof(byrg_http_proto_ver) - 1;
// Buffer for Status Code string.
static const byte         byrg_http_stat_code[] = HTTP_STATCODE;
static const unsigned int umg_len_http_stat_code =
sizeof(byrg_http_stat_code) - 1;
// Buffer for Content Length string.
static const byte         byrg_http_cont_len[] = HTTP_CONTLEN;
static const unsigned int umg_len_http_cont_len =
sizeof(byrg_http_cont_len) - 1;
// Buffer for Server string.
static const byte         byrg_http_server[] = HTTP_SERVER;
static const unsigned int umg_len_http_server = sizeof(byrg_http_server) - 1;

#define D_POS_IPV4_H_PROT 14
#define D_ARRAY_PACKET 8

#ifdef ML
// Buffer for OK message string
static byte byrg_http_OK[umg_len_http_proto_ver
+ umg_len_http_stat_code
+ umg_len_http_cont_len
+ umg_len_http_server
+ HTTP_DATE_LEN];
#endif

// Days of Week string array.
static const char chrrl_days_of_week[][7] = { "Sun",
"Mon",
"Tue",
"Wed",
"Thu",
"Fri",
"Sat" };

// Months of Year string array.
static const char chrrl_months_of_year[][12] = { "Jan",
"Feb",
"Mar",
"Apr",
"May",
"Jun",
"Jul",
"Aug",
"Sep",
"Oct",
"Nov",
"Dec" };

static const struct dsd_proc_http_header_server_1 dss_phhs1 = {
#ifndef D_MAP_STORAGE_CONTAINER
    NULL,                                    /* amc_store_alloc - storage container allocate memory */
    NULL,                                    /* amc_store_free - storage container free memory */
#else
    (amd_store_alloc) &m_aux_stor_alloc,     /* amc_store_alloc - storage container allocate memory */
    (amd_store_free) &m_aux_stor_free,       /* amc_store_free - storage container free memory */
#endif
    TRUE,                                    /* boc_consume_input - consume input */
    FALSE,                                    /* boc_store_cookies - store cookies */
    FALSE                                     /* boc_out_os - output fields for other side */
};


#ifdef ML
#ifndef HL_UNIX
// Signaled when a session is done with the C++ timer structure.
static HANDLE dsc_eve_timer = CreateEvent(NULL, TRUE, TRUE, NULL);
#else
static sem_t dsc_eve_timer;
int um_sem_ret = sem_init (&dsc_eve_timer, 0, 1);
#endif
#endif

// TODO - random nonce and chal
#ifdef ML
static byte byrl_nonce[] =
{ 0xE6, 0xEC, 0x2A, 0x72, 0xB3, 0x31, 0x73, 0xFD,
0x4C, 0x10, 0x2C, 0x1F, 0xB0, 0x68, 0x02, 0x6F,
0xDE, 0x76, 0x59, 0x02, 0x01, 0xFA, 0x39, 0x31,
0xB0, 0x66, 0xDA, 0xA9, 0x34, 0x42, 0x73, 0x38 };
#endif

// TODO - really needed??
#ifdef ML
static byte byrl_chap_chal[] =
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
#endif


// Callback for new PPP implementation to send SSTP message back to client.
static void m_ppp_send_callback_se(dsd_ppp_server_1* adsp_ppp_server,
                                   dsd_buf_vector_ele* adsp_buf_vec);

// Callback for new PPP implementation to do authentication.
extern PTYPE void m_ppp_auth_1(struct dsd_ppp_server_1*);

// Create target filter
#ifdef TJ_B160707
extern PTYPE struct dsd_ppp_targfi_act_1 * m_create_ppp_targfi( struct dsd_targfi_1 * );
#else
extern PTYPE struct dsd_ppp_targfi_act_1 * m_create_ppp_targfi( struct dsd_targfi_1 * , int, int );
#endif
// Check target filter
extern PTYPE enum ied_ret_cf m_proc_ppp_targfi_ipv4( struct dsd_hco_wothr *, struct dsd_ppp_targfi_act_1 *, struct dsd_gather_i_1 *, int );

// New function to get address of INETA configured for htun.
static char * m_ppp_se_get_ineta_client(struct dsd_ppp_server_1 *adsp_ppp_se_1);

static void m_log_sstp_warning(dsd_ppp_server_1*, char*);

static void m_ppp_se_hs_compl(dsd_ppp_server_1*);

static void m_sstp_make_http_response( char * );

static void m_cb_timer_close(dsd_timer_ele* adsp_timer_close);

//struct dsd_sstp_session* adsc_session_aux;
// HTTP request
static const char SSTP_HTTP_REQUEST[] = "SSTP_DUPLEX_POST";


dsd_sstp_session::dsd_sstp_session(dsd_tun_start_ppp * adsp_tun_start_ppp,
                                   dsd_tun_contr_conn* adsp_tun_contr_conn,
                                   dsd_tun_contr_ineta* adsp_tun_contr_ineta)
                                   : dsd_session(adsp_tun_contr_conn, adsp_tun_contr_ineta),
                                   iec_sstp_state(ied_sstp_state_waithttp),
                                   umc_packets_list(0),
                                   adsc_queue_first(NULL),
                                   adsc_queue_last(NULL),
                                   boc_lcp_sent(FALSE),
                                   adsc_targ_filter(NULL),
                                   adsc_ppp_targfi_act(NULL),
								   umc_discard_count(0),
                                   boc_crypto_ok(FALSE)
{
    dsc_sstp_wrap.adsc_sstp_session = this;
    dsc_htun_handle.vpc_contr = this;

    memset(&dsc_sstp_wrap.dsc_ppp_se_1, 0, sizeof(dsd_ppp_server_1));
    m_htun_ppp_set_auth( adsp_tun_contr_conn, (char *) &(dsc_sstp_wrap.dsc_ppp_se_1.chrc_ppp_auth) );

    umc_client_ineta = adsp_tun_start_ppp->umc_s_nw_ineta_ipv4;

    dsc_cs.m_create();

};

dsd_sstp_session::~dsd_sstp_session()
{
    // Inform WSP re session close.
    //m_htun_session_end(adsc_tun_contr_conn, -1);

    if (adsc_tun_contr_ineta){
        m_htun_ppp_free_resources(adsc_tun_contr_ineta);
        adsc_tun_contr_ineta = NULL;
    }

    // Release target filter resources.
    if (adsc_ppp_targfi_act)
        free(adsc_ppp_targfi_act);

    dsc_cs.m_close();

};

int dsd_sstp_session::mc_init()
{
    // Init dsd_ppp_server_1 instance in order to use new PPP implementation.
    dsc_sstp_wrap.dsc_ppp_se_1.isc_recv_ident_lcp_conf = -1;
    dsc_sstp_wrap.dsc_ppp_se_1.amc_ppp_se_send = m_ppp_send_callback_se;
    dsc_sstp_wrap.dsc_ppp_se_1.amc_ppp_se_auth = m_ppp_auth_1;
    dsc_sstp_wrap.dsc_ppp_se_1.amc_ppp_se_get_ineta_client = m_ppp_se_get_ineta_client;
    dsc_sstp_wrap.dsc_ppp_se_1.amc_ppp_se_abend = m_log_sstp_warning;
    dsc_sstp_wrap.dsc_ppp_se_1.amc_ppp_se_hs_compl = m_ppp_se_hs_compl;



    int iml1, iml2;
    do {                                     /* compute magic number    */
        iml1 = iml2 = sizeof(dsc_sstp_wrap.dsc_ppp_se_1.chrc_magic_number_se);
        do {
            iml1--;                              /* decrement index         */
            dsc_sstp_wrap.dsc_ppp_se_1.chrc_magic_number_se[ iml1 ]
            = (unsigned char) m_get_random_number( 0X0100 );
            if (dsc_sstp_wrap.dsc_ppp_se_1.chrc_magic_number_se[ iml1 ] == 0) {
                iml2--;                            /* count character zero    */
            }
        } while (iml1 > 0);
    } while (iml2 == 0);                     /* magic number zero not allowed */


    do {                                     /* compute nonce               */
        iml1 = iml2 = sizeof(byrc_nonce);
        do {
            iml1--;                              /* decrement index         */
            byrc_nonce[ iml1 ] = (unsigned char) m_get_random_number( 0X0100 );
            if (byrc_nonce[ iml1 ] == 0) {
                iml2--;                            /* count character zero    */
            }
        } while (iml1 > 0);
    } while (iml2 == 0);                     /* magic number zero not allowed */


    dsc_sstp_wrap.dsc_ppp_se_1.vpc_handle = adsc_tun_contr_conn;

    dsc_sstp_wrap.dsc_ppp_se_1.adsc_ppp_auth_header = NULL;
    dsc_sstp_wrap.dsc_ppp_se_1.adsc_ppp_cl_1 = NULL;
    dsc_sstp_wrap.dsc_ppp_se_1.imc_auth_no = 0;
    dsc_sstp_wrap.dsc_ppp_se_1.imc_options = 0;
    memset( &dsc_sstp_wrap.dsc_ppp_se_1.chrc_ineta_stat, 0, 5*sizeof(char) );
    dsc_sstp_wrap.dsc_ppp_se_1.ucc_send_ident_lcp_conf = 0;
    memset( &dsc_sstp_wrap.dsc_ppp_se_1.chrc_magic_number_cl, 0, 4*sizeof(char) );


    // Rreturn OK.
    return 0;
}

void dsd_sstp_session::mc_close()
{

    // Enter CS in order to complete the end handshake with the WSP
    dsc_cs.m_enter();
    // Inform WSP re session close.
    m_htun_session_end(adsc_tun_contr_conn, -1);
    adsc_tun_contr_conn = 0;

    dsc_cs.m_leave();

    // Create and set timer to release resources (Route, PARP, INETA etc...).
    memset(&dsc_sstp_wrap.dsc_timer_close, 0, sizeof(dsc_sstp_wrap.dsc_timer_close));
    dsc_sstp_wrap.dsc_timer_close.amc_compl = m_cb_timer_close;
    dsc_sstp_wrap.dsc_timer_close.ilcwaitmsec = 1000 * 60; // 60s timeout.
    m_time_set(&dsc_sstp_wrap.dsc_timer_close, false);

}

int dsd_sstp_session::mc_interpret_msg(dsd_gather_i_1* adsp_gather,
                                       dsd_hco_wothr*  adsp_hco_wothr)
{

    while((adsp_gather->achc_ginp_cur != adsp_gather->achc_ginp_end)
        || (adsp_gather->adsc_next != NULL))
    {
        // If current link is completely consumed, move to next link.
        while(adsp_gather->achc_ginp_cur == adsp_gather->achc_ginp_end)
        {
            adsp_gather = adsp_gather->adsc_next;
            if(adsp_gather == NULL)
                return 0;
        }

        // Check state of SSTP fsm.
        switch(iec_sstp_state)
        {
        case ied_sstp_state_waithttp: // Server waiting for SSTP_DUPLEX_POST.
            {

                // Look for HTTP message.

                // Length of data seen/traversed.
                unsigned int uml_http_len = 0;
                // Traverse chain of buffers, starting from first link.
                dsd_gather_i_1* adsl_link_cur = adsp_gather;

                // Search for 0x0D0A0D0A value in current buffer.
                byte* abyl_data_end
                    = m_search_nlnl((byte*)(adsl_link_cur->achc_ginp_cur),
                    (byte*)(adsl_link_cur->achc_ginp_end));
                // Increment length of data seen.
                uml_http_len +=
                    adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;

                while(adsl_link_cur != NULL && abyl_data_end == NULL)
                {
                    // Move to next link in chain.
                    adsl_link_cur = adsl_link_cur->adsc_next;
                    if(adsl_link_cur != NULL)
                    {
                        // Search for 0x0D0A0D0A value in current buffer.
                        abyl_data_end =
                            m_search_nlnl((byte*)(adsl_link_cur->achc_ginp_cur),
                            (byte*)(adsl_link_cur->achc_ginp_end));
                        // Increment length of data seen.
                        uml_http_len
                            += adsl_link_cur->achc_ginp_end -
                            adsl_link_cur->achc_ginp_cur;
                    }
                }

                if(abyl_data_end != NULL)
                {  // 0x0D0A0D0A found.
                    // Reset current link ptr to start of chain.
                    adsl_link_cur = adsp_gather;

                    struct dsd_call_http_header_server_1 dsl_chhs1;  /* call HTTP processing at server */
                    struct dsd_http_header_server_1 dsl_hhs1;  /* HTTP processing at server */
                    bool bol_rc = false;


                    memset( &dsl_chhs1, 0, sizeof(struct dsd_call_http_header_server_1) );  /* call HTTP processing at server */


                    dsl_chhs1.adsc_gai1_in = adsl_link_cur;  /* gather input data */

                    bol_rc = m_proc_http_header_server( &dss_phhs1,  /* HTTP processing at server */
                        &dsl_chhs1,  /* call HTTP processing at server */
                        &dsl_hhs1 );  /* HTTP processing at server */	

                    if ( bol_rc &&
                        dsl_hhs1.iec_hme == ied_hme_sstp &&
                        dsl_hhs1.iec_hpr == ied_hpr_http_1_1 //&&
                        //dsl_hhs1.imc_length_url_path == sizeof() &&
                        //!memcmp( dsl_hhs1.achc_url_path, , dsl_hhs1.imc_length_url_path)
                        // dsl_hhs1.imc_content_length == ULONG_MAX
                        )
                    {  // SSTP_DUPLEX_POST verb found.
                        // Get new buffer.
                        void* al_handle;
                        char* achl_data;
                        int iml_data_len;
                        iml_data_len = m_htun_getrecvbuf(&al_handle, &achl_data);

                        // TODO - Really needed??? + SetEvent
#ifdef ML
#ifndef HL_UNIX
                        WaitForSingleObject(dsc_eve_timer, INFINITE);
#else
                        sem_wait (&dsc_eve_timer);
#endif
#endif

                        // Create HTTP OK message.
                        m_sstp_make_http_response( achl_data );
#ifdef ML
                        // Write HTTP OK message.
                        memcpy(achl_data, byrg_http_OK, sizeof(byrg_http_OK));
#endif

#ifdef ML
#ifndef HL_UNIX
                        SetEvent(dsc_eve_timer);
#endif
#endif
                        // Init new vec ele.
                        dsd_buf_vector_ele dsl_http_ok;
                        dsl_http_ok.ac_handle = al_handle;
                        dsl_http_ok.achc_data = achl_data;
                        dsl_http_ok.imc_len_data = umg_len_http_proto_ver
                                                 + umg_len_http_stat_code
                                                 + umg_len_http_cont_len
                                                 + umg_len_http_server
                                                 + HTTP_DATE_LEN;

                        // Check whether it is OK to send message towards client...
                        if(boc_cansend)
                        {
                            // Send pkt to client.
                            if(!(m_se_htun_recvbuf(adsc_tun_contr_conn, &dsl_http_ok, 1)))
                            {
                                // Indicate that it is not OK to send more messages
                                // towards client.
                                boc_cansend = false;
                            }
                        }
                        else
                        {
                            // Increment number of messages discarded.
                            umc_discard_count++;
                        }

                        // Set SSTP fsm state to waiting for CALL_CONNECT_REQ.
                        iec_sstp_state = ied_sstp_state_waitcallconnreq;
                    }
                    else
                    {
                        // Indicate incorrect HTTP message.
                        m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 0, "SSTP warning: Invalid HTTP message received.");
                        // TODO: Send HTTP message with error code.
                        return 1;
                    }
                    // Consume gathers and return
                    while(adsp_gather){
                        adsp_gather->achc_ginp_cur = adsp_gather->achc_ginp_end;
                        adsp_gather = adsp_gather->adsc_next;
                    }
                    return 0;

                }
                else
                {
                    // Ccomplete message not available in chain.
                    return 0;
                }
            }; break;
            // Server waiting for CALL_CONNECT_REQUEST SSTP ctrl message.
        case ied_sstp_state_waitcallconnreq:
            {
                // Try to read Control field of SSTP message.
                dsd_gather_i_1* adsl_link_cur = adsp_gather;

                int32_t iml1 = 0; // Use as offset.


                char chl_sstp_control = -1;

                while(adsl_link_cur){
                    if(adsl_link_cur->achc_ginp_cur >= adsl_link_cur->achc_ginp_end)
                        adsl_link_cur = adsl_link_cur->adsc_next;
                    else
                        break;
                }
                if (!adsl_link_cur)
                    return 0;

                // Check first byte
                if (*adsl_link_cur->achc_ginp_cur != SSTP_VERSION_BYTE){
                    m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 1, "SSTP warning: Invalid length SSTP message received during SSTP wait call conn req. Session closed.");

                    // TODO - consume gahters???

                    // Send SSTP Call Abort message.
                    mc_abort_sstp_conn();
                    // Close SSTP connection.
                    boc_sess_closed = true;

                    return 1;
                }
                iml1++;

#ifdef B150821
                if ((adsl_link_cur->achc_ginp_cur + iml1) == adsl_link_cur->achc_ginp_end){
                    adsl_link_cur = adsl_link_cur->adsc_next;
                    iml1 = 0;
                }
                if (!adsl_link_cur)
                    return 0;
#endif
#ifndef B150821
                while ((adsl_link_cur->achc_ginp_cur + iml1) >= adsl_link_cur->achc_ginp_end) {
                    adsl_link_cur = adsl_link_cur->adsc_next;
                    if (adsl_link_cur == NULL) return 0;  /* end of input data */
                    iml1 = 0;
                }

                /* problem SSTP 21.08.15 KB                            */
                /* workaround - first check if we have enough data for the SSTP header */
                {
                  int imh1;
                  char *achh_w1;
                  struct dsd_gather_i_1 *adsh_link_cur_w1;

                  imh1 = 4;
                  adsh_link_cur_w1 = adsl_link_cur;
                  achh_w1 = adsl_link_cur->achc_ginp_cur + iml1;
                  while (TRUE) {
                    imh1 -= adsh_link_cur_w1->achc_ginp_end - achh_w1;
                    if (imh1 <= 0) break;   /* at least complete header */
                    adsh_link_cur_w1 = adsh_link_cur_w1->adsc_next;  /* get next in chain */
                    if (adsh_link_cur_w1 == NULL) return 0;  /* end of input data */
                    achh_w1 = adsh_link_cur_w1->achc_ginp_cur;
                  }
                }
#endif

                chl_sstp_control = *(adsl_link_cur->achc_ginp_cur + iml1);
                iml1++;

                // Check if this appears to be a valid SSTP message.
                if(chl_sstp_control == SSTP_CONTROL_BYTE)
                {
                    // At this point, message seems to be valid SSTP.
                    // Now find LengthPacket field, and read rest of packet from
                    // chain.
                    unsigned short iml_lengthpacket;

                    iml_lengthpacket = m_get_sstp_lengthpacket(adsp_gather);

                    if(iml_lengthpacket < 0)
                    {  // Entire length value not available.
                        return 0;
                    }


                    // At this point we have lenght of SSTP message.
                    // Now make sure entire message is available in chain.
                    if(!m_check_sstp_complete(adsp_gather, iml_lengthpacket))
                    {
                        // Entire SSTP message is not available.
                        return 0;
                    }
                    iml1 += 2;


                    // At this point we know that the entire SSTP pkt is available.
                    // Now we can process the remaining contents of the message.

                    // Make sure that SSTP message has correct size.
                    if(iml_lengthpacket < 8)
                    {
                        // Indicate invalid SSTP message.
                        m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 2, "SSTP warning: Invalid length SSTP message received during SSTP connection establishment. Session closed.");
                        //adsl_link_cur->achc_ginp_cur = adsl_link_cur->achc_ginp_end;
                        m_consume_hpppt1_msg( &adsp_gather, iml_lengthpacket );
                        // Send SSTP Call Abort message.
                        mc_abort_sstp_conn();
                        // Close SSTP connection.
                        boc_sess_closed = true;

                        return 1;
                    }

                    // Make sure MessageType value is SSTP_MSG_CALL_CONNECT_REQ.
                    while((adsl_link_cur->achc_ginp_cur + iml1) >= adsl_link_cur->achc_ginp_end){
                        iml1 -= adsl_link_cur->achc_ginp_end - (adsl_link_cur->achc_ginp_cur + iml1);
                        adsl_link_cur = adsl_link_cur->adsc_next;
                    }

                    switch ((*((unsigned short*)(adsl_link_cur->achc_ginp_cur + iml1))))
                    {
                    case SSTP_MSG_CALL_ABORT:
                        {
                            sprintf(chrc_last_error, "SSTP warning: SSTP connection establishment aborted by peer. Session closed.\n");
                            // Close SSTP connection.
                            boc_sess_closed = true;

                        }; break;
                    case SSTP_MSG_CALL_DISCONNECT:
                        {
                            // Create and send SSTP_MSG_CALL_DISCONNECT_ACK SSTP msg.
                            // Get new buffer.
                            void* al_handle;
                            char* achl_data;
                            int iml_data_len;
                            iml_data_len = m_htun_getrecvbuf(&al_handle, &achl_data);
                            // Init new vec ele.
                            dsd_buf_vector_ele dsl_sstp_call_disconn_ack;
                            dsl_sstp_call_disconn_ack.ac_handle = al_handle;
                            dsl_sstp_call_disconn_ack.achc_data =
                                achl_data + iml_data_len;
                            dsl_sstp_call_disconn_ack.imc_len_data = 0;
                            // Write SSTP SSTP_MSG_CALL_DISCONNECT_ACK message.
                            mc_make_sstp_disconnect_ack(&dsl_sstp_call_disconn_ack);

                            // Check whether it is OK to send message towards client...
                            if(boc_cansend)
                            {
                                // Send pkt to client.
                                if(!(m_se_htun_recvbuf(adsc_tun_contr_conn,
                                    &dsl_sstp_call_disconn_ack, 1)))
                                {
                                    // Indicate that it is not OK to send more messages
                                    // towards client.
                                    boc_cansend = false;
                                }
                            }
                            else
                            {
                                // Increment number of messages discarded.
                                umc_discard_count++;
                            }

                            // Close SSTP connection.
                            boc_sess_closed = true;

                        }; break;
                    case SSTP_MSG_CALL_CONNECT_REQ:
                        {
                            // Make sure NumAttributes value is 0x0001 (only 1
                            // attribute).
                            iml1 += 2;

                            if(*((unsigned short*)(adsl_link_cur->achc_ginp_cur + iml1)) != 0x0100)
                            {
                                // Indicate invalid SSTP message.
                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 3, "SSTP warning: Unexpected SSTP NumAttributes received during SSTP connection establishment. Session closed.");

                                // Send SSTP Call Abort message.
                                mc_abort_sstp_conn();
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 1;
                            }
                            // Make sure AttributeID value is
                            // SSTP_ATTR_ENCAPSULATED_PROTO.
                            iml1 += 3;
                            if(*((byte*)(adsl_link_cur->achc_ginp_cur + iml1)) !=
                                SSTP_ATTR_ENCAPSULATED_PROTO)
                            {
                                // Indicate invalid SSTP message.
                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 4, "SSTP warning: Unexpected SSTP AttributeID received during SSTP connection establishment. Session closed.");

                                // Send SSTP Call Abort message.
                                mc_abort_sstp_conn();
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 1;
                            }
                            // Make sure ProtocolID value is
                            // SSTP_ATTR_ENCAPSULATED_PROTO_PPP.
                            iml1 += 3;
                            if((*(adsl_link_cur->achc_ginp_cur + iml1 + 0) != 0)    // SSTP_ATTR_ENCAPSULATED_PROTO_PPP
                                || (*(adsl_link_cur->achc_ginp_cur + iml1 + 1))  != 1)
                            {
                                // Indicate invalid SSTP message.
                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 5, "SSTP warning: Unexpected SSTP ProtocolID received during SSTP connection establishment. Session closed");

                                // Send SSTP Call Abort message.
                                mc_abort_sstp_conn();
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 1;
                            }

                            // Now we know we've received a valid SSTP CALL_CONNECT_REQ
                            // message.
                            // Next, we reply with a CALL_CONNECT_ACK SSTP message.

                            // Get new buffer.
                            void* al_handle;
                            char* achl_data;
                            int32_t iml_data_len;
                            iml_data_len = m_htun_getrecvbuf(&al_handle, &achl_data);
                            // Write SSTP CALL_CONNECT_ACK message.
                            // Version and control fields.
                            *(achl_data + 0) = 0x10;  //SSTP_CONTROL_MSG;
                            *(achl_data + 1) = 0x01;
                            // LengthPacket field.
                            *(achl_data + 2) = 0x00;
                            *(achl_data + 3) = 0x30;
                            // MessageType field.
                            *(achl_data + 4) = 0x00; //SSTP_MSG_CALL_CONNECT_ACK;
                            *(achl_data + 5) = 0x02;
                            // NumAttributes field.
                            *(achl_data + 6) = 0x00;
                            *(achl_data + 7) = 0x01;
                            // Reserved1 field.
                            *((byte*)(achl_data + 8)) = 0x00;
                            // AttributeID field.
                            *((byte*)(achl_data + 9)) = 0x04;//SSTP_ATTR_CRYPTO_REQ;
                            // LengthAttribute field.
                            *(achl_data + 10) = 0x00;
                            *(achl_data + 11) = 0x28;
                            // Reserved2 field.
                            memset(achl_data + 12, 0, 3);
                            // HashProtocol field.
                            *((byte*)(achl_data + 15)) = HASH_PROTO_SHA1 | HASH_PROTO_SHA256;
                            // todo - should SHA1 be supported??
                                //HASH_PROTO_SHA1 | HASH_PROTO_SHA256;
                            // Nonce field.
                            memcpy(achl_data + 16, byrc_nonce, sizeof(byrc_nonce));

                            // Init new vec ele.
                            dsd_buf_vector_ele dsl_sstp_call_conn_ack;
                            dsl_sstp_call_conn_ack.ac_handle = al_handle;
                            dsl_sstp_call_conn_ack.achc_data = achl_data;
                            dsl_sstp_call_conn_ack.imc_len_data = 0x0030;

                            // Check whether it is OK to send message towards client...
                            if(boc_cansend)
                            {
                                // Send pkt to client.
                                if(!(m_se_htun_recvbuf(adsc_tun_contr_conn,
                                    &dsl_sstp_call_conn_ack, 1)))
                                {
                                    // Indicate that it is not OK to send more messages
                                    // towards client.
                                    boc_cansend = false;
                                }
                            }
                            else
                            {
                                // Increment number of messages discarded.
                                umc_discard_count++;
                            }

                            // Set SSTP fsm state to waiting for CALL_CONNECTED.
                            iec_sstp_state = ied_sstp_state_waitcallconnected;

                        }; break;
                    default:
                        {
                            // Indicate invalid SSTP message.
                            m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 6, "SSTP warning: Unexpected SSTP MessageType received during SSTP connection establishment. Session closed.");

                            // Send SSTP Call Abort message.
                            mc_abort_sstp_conn();
                            // Close SSTP connection.
                            boc_sess_closed = true;

                            return 1;
                        }; break;
                    }

                    // Consume pkt from chain of gathers
                    m_consume_hpppt1_msg( &adsp_gather, iml_lengthpacket );
                }
                else // Not an SSTP message.
                {
                    // Indicate invalid SSTP message.
                    m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 6, "SSTP warning: Invalid SSTP message received during SSTP connection establishment. Session closed.");
                    // Send SSTP Call Abort message.
                    mc_abort_sstp_conn();
                    // Close SSTP connection.
                    boc_sess_closed = true;

                    return 1;
                }
            }; break;
            // Server waiting for CALL_CONNECTED SSTP ctrl message.
        case ied_sstp_state_waitcallconnected:
            {
                // Try to read Control field of SSTP message.
                dsd_gather_i_1* adsl_link_cur = adsp_gather;

                int32_t iml1 = 0; // Use as offset.

                char chl_sstp_control = -1;

#ifdef B150821
                while(adsl_link_cur){
                    if(adsl_link_cur->achc_ginp_cur >= adsl_link_cur->achc_ginp_end)
                        adsl_link_cur = adsl_link_cur->adsc_next;
                    else
                        break;
                }
                if (!adsl_link_cur)
                    return 0;
#endif
#ifndef B150821
                while (adsl_link_cur->achc_ginp_cur >= adsl_link_cur->achc_ginp_end) {
                    adsl_link_cur = adsl_link_cur->adsc_next;
                    if (adsl_link_cur == NULL) return 0;  /* end of input data */
                }

                /* problem SSTP 21.08.15 KB                            */
                /* workaround - first check if we have enough data for the SSTP header */
                {
                  int imh1;
                  char *achh_w1;
                  struct dsd_gather_i_1 *adsh_link_cur_w1;

                  imh1 = 4;
                  adsh_link_cur_w1 = adsl_link_cur;
//                achh_w1 = adsl_link_cur->achc_ginp_cur + iml1;
                  achh_w1 = adsl_link_cur->achc_ginp_cur;
                  while (TRUE) {
                    imh1 -= adsh_link_cur_w1->achc_ginp_end - achh_w1;
                    if (imh1 <= 0) break;   /* at least complete header */
                    adsh_link_cur_w1 = adsh_link_cur_w1->adsc_next;  /* get next in chain */
                    if (adsh_link_cur_w1 == NULL) return 0;  /* end of input data */
                    achh_w1 = adsh_link_cur_w1->achc_ginp_cur;
                  }
                }
#endif

                // Check first byte
                if (*adsl_link_cur->achc_ginp_cur != SSTP_VERSION_BYTE){
                     // Indicate invalid SSTP message.
                    m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 7, "SSTP warning: Invalid SSTP message received during SSTP wait call connected. Session closed.");
                    // Send SSTP Call Abort message.
                    mc_abort_sstp_conn();
                    // Close SSTP connection.
                    boc_sess_closed = true;
                    return 1;
                }
                iml1++;

                while (adsl_link_cur){
                    if ((adsl_link_cur->achc_ginp_cur + iml1) < adsl_link_cur->achc_ginp_end){
                        chl_sstp_control = *(adsl_link_cur->achc_ginp_cur + iml1);
                        break;
                    }
                    iml1 -= adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
                    adsl_link_cur = adsl_link_cur->adsc_next;
                }
                // Message incomplete
                if (!adsl_link_cur)
                    return 0;

                iml1++;


                // Check if this appears to be a valid SSTP message.
                if((chl_sstp_control == SSTP_DATA_BYTE) || // Data msg
                    (chl_sstp_control == SSTP_CONTROL_BYTE))   // Control msg
                {
                    // At this point, message seems to be valid SSTP.
                    // Now find LengthPacket field and read rest of pkt from chain.

                    int32_t iml_lengthpacket = m_get_sstp_lengthpacket(adsp_gather);
                    if(iml_lengthpacket < 0)
                    { // Entire length value not available.
                        return 0;
                    }


                    // At this point we have lenght of SSTP message.
                    // Now make sure entire message is available in chain.
                    if(!m_check_sstp_complete(adsp_gather, iml_lengthpacket))
                    {
                        // Entire SSTP message is not available.
                        return 0;
                    }

                    // At this point we know that the entire SSTP pkt is available.
#ifndef B150704
                    BOOL bol_consume_input = TRUE;  /* default: consume input at end */
#endif

                    // Check what type of SSTP message this is.
                    if(chl_sstp_control == SSTP_CONTROL_BYTE) // SSTP Control message.
                    {
                        // Now we can process the remaining contents of the message.

                        // Make sure that SSTP message has correct size.
                        if(iml_lengthpacket < 8)
                        {
                            // Indicate invalid SSTP message
                            m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 8, "SSTP warning: Invalid length SSTP message received during SSTP connection establishment. Session closed.");

                            // Send SSTP Call Abort message.
                            mc_abort_sstp_conn();
                            // Close SSTP connection.
                            boc_sess_closed = true;

                            return 1;
                        }


                        // Copy pkt to contiguous memory
                        iml1 = iml_lengthpacket;
                        int32_t iml2 = 0;      // buffer offset
                        adsl_link_cur = adsp_gather;
                        while(iml1){
                            if ((adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur) < iml1){
                                iml1 -= adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
                                memcpy( chrc_work1 + iml2, adsl_link_cur->achc_ginp_cur, adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur );
                                iml2 += adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
                                adsl_link_cur = adsl_link_cur->adsc_next;
                            }
                            else{
                                memcpy( chrc_work1 + iml2, adsl_link_cur->achc_ginp_cur, iml1 );
                                iml1 = 0;
                            }
                        }
                        // Make sure MessageType value is SSTP_MSG_CALL_CONNECTED. 0x0004
                        iml1 += 4;
                        if( (chrc_work1[ iml1 + 0 ] != 0x00)
                         || (chrc_work1[ iml1 + 1] != 0x04) )
                        {
                            // Check if MessageType is SSTP_MSG_CALL_ABORT. 0x0005
                            if( (chrc_work1[ iml1 + 0 ] == 0x00)
                             || (chrc_work1[ iml1 + 1 ] == 0x05) )
                            {
                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 9, "SSTP warning: SSTP connection establishment aborted by peer. Session closed");
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 1;
                            }
                            // Check if MessageType is SSTP_MSG_CALL_DISCONNECT. 0x0006
                            else if( (chrc_work1[ iml1 + 0 ] == 0x00)
                                  || (chrc_work1[ iml1 + 1 ] == 0x06) )
                            {
                                // Create and send SSTP_MSG_CALL_DISCONNECT_ACK SSTP
                                // message.
                                // Get new buffer.
                                void* al_handle;
                                char* achl_data;
                                int32_t iml_data_len;
                                iml_data_len = m_htun_getrecvbuf(&al_handle, &achl_data);
                                // Init new vec ele.
                                dsd_buf_vector_ele dsl_sstp_call_disconn_ack;
                                dsl_sstp_call_disconn_ack.ac_handle = al_handle;
                                dsl_sstp_call_disconn_ack.achc_data =
                                    achl_data + iml_data_len;
                                dsl_sstp_call_disconn_ack.imc_len_data = 0;
                                // Write SSTP SSTP_MSG_CALL_DISCONNECT_ACK message.
                                mc_make_sstp_disconnect_ack(&dsl_sstp_call_disconn_ack);

                                // Check whether it is OK to send message towards client...
                                if(boc_cansend)
                                {
                                    // Send pkt to client.
                                    if(!(m_se_htun_recvbuf(adsc_tun_contr_conn,
                                        &dsl_sstp_call_disconn_ack,
                                        1)))
                                    {
                                        // Indicate that it is not OK to send more messages
                                        // towards client.
                                        boc_cansend = false;
                                    }
                                }
                                else
                                {
                                    // Increment number of messages discarded.
                                    umc_discard_count++;
                                }

                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 0;
                            }
                            else
                            {
                                // Indicate invalid SSTP message.
                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 10, "SSTP warning: Unexpected SSTP MessageType received during SSTP connection establishment. Session closed.");
                                // Send SSTP Call Abort message.
                                mc_abort_sstp_conn();
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 1;
                            }
                        }
                        // Message is SSTP_MSG_CALL_CONNECTED
                        // Make sure NumAttributes value is 0x0001 (only 1 attribute).
                        iml1 += 2;
                        if( (chrc_work1[ iml1 + 0 ] != 0x00)
                         || (chrc_work1[ iml1 + 1 ] != 0x01) )
                        {
                            // Indicate invalid SSTP message.
                            m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 11, "SSTP warning: Unexpected SSTP NumAttributes received during SSTP connection establishment. Session closed.");

                            // Send SSTP Call Abort message.
                            mc_abort_sstp_conn();
                            // Close SSTP connection.
                            boc_sess_closed = true;

                            return 1;
                        }
                        // Make sure AttributeID value is SSTP_ATTR_CRYPTO.
                        iml1 += 3;
                        if(chrc_work1[ iml1 ] != SSTP_ATTR_CRYPTO)
                        {
                            // Indicate invalid SSTP message.
                            m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 12, "SSTP warning: Unexpected SSTP AttributeID received during SSTP connection establishment. Session closed.");

                            // Send SSTP Call Abort message.
                            mc_abort_sstp_conn();
                            // Close SSTP connection.
                            boc_sess_closed = true;

                            return 1;
                        }
                        // Make sure HashProtocol value is either SHA1 or SHA256.
                        iml1 += 6;

                        // todo - should we support SHA1???
                        if( (chrc_work1[ iml1 ] != HASH_PROTO_SHA1) &&
                            (chrc_work1[ iml1 ] != HASH_PROTO_SHA256))
                        //if (chrc_work1[ iml1 ] != HASH_PROTO_SHA256)
                        {
                            // Indicate invalid SSTP message.
                            m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 13, "SSTP warning: Unexpected HashProtocol received during SSTP connection establishment. Session closed.");

                            // Send SSTP Call Abort message.
                            mc_abort_sstp_conn();
                            // Close SSTP connection.
                            boc_sess_closed = true;

                            return 1;
                        }
                        // Make sure nonce matches the one sent.
                        iml1 += 1;
                        if(memcmp(chrc_work1 + iml1,
                            byrc_nonce,
                            sizeof(byrc_nonce)) != 0)
                        {
                            // Indicate invalid SSTP message.
                            m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 14, "SSTP warning: Unexpected SSTP Nonce received during SSTP connection establishment. Session closed.");

                            // Send SSTP Call Abort message.
                            mc_abort_sstp_conn();
                            // Close SSTP connection.
                            boc_sess_closed = true;

                            return 1;
                        }



                        if ( !m_get_tun_sstp_flag_channel_binding( adsc_tun_contr_conn )){
                            if (!m_check_tun_sstp_channel_binding(adsc_tun_contr_conn, chrc_work1, iml_lengthpacket )){

                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 15, "SSTP warning: SSTP Crypto Binding incorrect. Session closed.");

                                // Send SSTP Call Abort message.
                                mc_abort_sstp_conn();
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 0;
                            }
                        }

                        boc_crypto_ok = TRUE;

                        if ( (dsc_sstp_wrap.dsc_ppp_se_1.imc_options & D_PPP_OPT_HS_COMPL) == 0 ){
                            // todo - correct error number
                            //m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 19, "SSTP warning: SSTP attempted crypto binding with but AUTH not OK.");

                            // Send SSTP Call Abort message.
                            //mc_abort_sstp_conn();
                            // Close SSTP connection.
                            //boc_sess_closed = true;

                            m_consume_hpppt1_msg(&adsp_gather, iml_lengthpacket);
                            return 0;
                        }


                        // All done.

                        // Now we know we've recvd a valid SSTP CALL_CONNECTED msg.
                        // SSTP connection has been successfully established.

                        // Set SSTP fsm state to connected.
                        iec_sstp_state = ied_sstp_state_connected;

                        // Create target filter, if necessary.
#ifdef callback_hs_compl
                        adsc_targ_filter = m_htun_ppp_get_targfi(adsc_tun_contr_conn);
                        if(adsc_targ_filter != NULL)
                        {
                            if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
                            {
                                // TODO - trace - correct?
                                m_do_wsp_trace("SNEPPPTC", 0, adsc_tun_contr_conn->imc_sno,
                                    adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
                                    "Creating PPP target filter - SSTP.");
                            }
                            adsc_ppp_targfi_act = m_create_ppp_targfi(adsc_targ_filter);
                        }
#endif

                    }

                    else if(chl_sstp_control == SSTP_DATA_BYTE) // SSTP Data message.
                    {

                        dsc_sstp_wrap.adsp_hco_wothr = adsp_hco_wothr;
                        //adsc_session_aux = this;


                        // At this point we need the rest of SSTP message in a single,
                        // contiguous buffer.
                        // Now we can process the remaining contents of the message.

                        // We move the pointer to the beggining of data
                        int iml2 = 4;
                        iml1 = 0;
                        adsl_link_cur = adsp_gather;
                        do{
                            if (iml2 < (adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur)){
                                iml1 = iml2;
                                break;
                            }
                            if (adsl_link_cur->achc_ginp_end > adsl_link_cur->achc_ginp_cur){
                                iml2 -= adsl_link_cur->achc_ginp_end > adsl_link_cur->achc_ginp_cur;
                            }
                            adsl_link_cur = adsl_link_cur->adsc_next;
                        }while (iml2);

#ifdef B150704
                        // Copy all data into a single buffer
                        iml2 = iml_lengthpacket - 4;
                        if ((adsl_link_cur->achc_ginp_end - (adsl_link_cur->achc_ginp_cur + iml1)) < iml2){
                            memcpy( chrc_work1, adsl_link_cur->achc_ginp_cur + iml1, adsl_link_cur->achc_ginp_end - (adsl_link_cur->achc_ginp_cur + iml1) );
                            iml2 -= adsl_link_cur->achc_ginp_end - (adsl_link_cur->achc_ginp_cur + iml1);
                            iml1 = adsl_link_cur->achc_ginp_end - (adsl_link_cur->achc_ginp_cur + iml1);   // Now iml1 offset for the ppp data buffer
                            adsl_link_cur = adsl_link_cur->adsc_next;
                        }
                        else{
                            memcpy( chrc_work1, adsl_link_cur->achc_ginp_cur + iml1, iml2 );
                            iml2 = 0;
                        }
                        while(iml2){
                            memcpy( chrc_work1 + iml1, adsl_link_cur->achc_ginp_cur, adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur );
                            iml2 -= adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
                            iml1 += adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
                        }


                        // Send Data field to PPP implementation for processing.
                        m_recv_ppp_server_cs(&dsc_sstp_wrap.dsc_ppp_se_1,
                            chrc_work1,
                            iml_lengthpacket - 4);



                        // Sends the PPP server's first Configure Request LCP msg,
                        // Kick off the server's PPP negoitation process. Ideally
                        if(!boc_lcp_sent)
                        {
                            m_start_ppp_server_cs(&dsc_sstp_wrap.dsc_ppp_se_1);

                            //dsc_sstp_wrap.dsc_ppp_se_1.vpc_radius = NULL;
                            boc_lcp_sent = TRUE;

                        }

#endif
#ifndef B150704
                        /* Copy all data into a single buffer or pass in one chunk */
                        iml2 = iml_lengthpacket - 4;
                        if (iml2 <= 0) {    /* length is invalid       */
                                // Indicate invalid SSTP message.
                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 21, "SSTP warning: Unexpected SSTP MessageLength received during SSTP connection establishment. Session closed.");
                                // Send SSTP Call Abort message.
                                mc_abort_sstp_conn();
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 1;
                        }

                        bol_consume_input = FALSE;  /* input already consumed */

                        char *achl_w1, *achl_w2;

                        adsl_link_cur->achc_ginp_cur += iml1;
#ifndef B150821
                        /* problem SSTP 21.08.15 KB                    */
                        /* workaround - consume all bytes in previous gather structures */
                        {
                          struct dsd_gather_i_1 *adsh_link_cur_w1;

                          adsh_link_cur_w1 = adsp_gather;
                          while (adsh_link_cur_w1 != adsl_link_cur) {
                            adsh_link_cur_w1->achc_ginp_cur = adsh_link_cur_w1->achc_ginp_end;
                            adsh_link_cur_w1 = adsh_link_cur_w1->adsc_next;  /* get next in chain */
                          }
                        }
#endif
                        if ((adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur) >= iml2) {
                            achl_w1 = adsl_link_cur->achc_ginp_cur;  /* here is beginning of data */
                            adsl_link_cur->achc_ginp_cur += iml2;  /* data consumed */
                            if (adsl_link_cur->achc_ginp_cur >= adsl_link_cur->achc_ginp_end) {  /* end of this gather */
                              adsl_link_cur = adsl_link_cur->adsc_next;
                            }
                        }
                        else{               /* need to copy data to contiguous memory area */
                          if (iml2 > sizeof(chrc_work1)) {
                                // Indicate invalid SSTP message.
                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 22, "SSTP warning: Unexpected SSTP MessageLength received during SSTP connection establishment. Session closed.");
                                // Send SSTP Call Abort message.
                                mc_abort_sstp_conn();
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 1;
                          }
                          achl_w1 = achl_w2 = chrc_work1;
                          do {              /* loop to copy data       */
                            if (adsl_link_cur == NULL) {  /* no more gather - no more data */
                                // Indicate invalid SSTP message.
                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 23, "SSTP warning: SSTP processing illogic. Session closed.");
                                // Send SSTP Call Abort message.
                                mc_abort_sstp_conn();
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 1;
                            }
                            iml1 = adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
                            if (iml1 > iml2) iml1 = iml2;
                            if (iml1 > 0) {
                              memcpy( achl_w2, adsl_link_cur->achc_ginp_cur, iml1 );
                              achl_w2 += iml1;
                              adsl_link_cur->achc_ginp_cur += iml1;
                              iml2 -= iml1;  /* part copied            */
                            }
                            if (adsl_link_cur->achc_ginp_cur >= adsl_link_cur->achc_ginp_end) {  /* end of this gather */
                              adsl_link_cur = adsl_link_cur->adsc_next;
                            }
                          } while (iml2 > 0);
                        }

// to-do 04.07.15 KB - illogic, first send data and afterwards start PPP

                        // Send Data field to PPP implementation for processing.
                        m_recv_ppp_server_cs(&dsc_sstp_wrap.dsc_ppp_se_1,
                            achl_w1,
                            iml_lengthpacket - 4);



                        // Sends the PPP server's first Configure Request LCP msg,
                        // Kick off the server's PPP negoitation process. Ideally
                        if(!boc_lcp_sent)
                        {
                            m_start_ppp_server_cs(&dsc_sstp_wrap.dsc_ppp_se_1);

                            //dsc_sstp_wrap.dsc_ppp_se_1.vpc_radius = NULL;
                            boc_lcp_sent = TRUE;

                        }

                        if (adsl_link_cur == NULL) return 0;
#endif

                    }

#ifdef B150704
                    // Consume pkt here from the chain of gahters
                    m_consume_hpppt1_msg(&adsp_gather, iml_lengthpacket);
                    if (!adsp_gather)
                        return 0;
#endif
#ifndef B150704
                    if (bol_consume_input) {  /* default: consume input at end */
                      // Consume pkt here from the chain of gahters
                      m_consume_hpppt1_msg(&adsp_gather, iml_lengthpacket);
                      if (!adsp_gather)
                          return 0;
                    }
#endif
                }
                else // Not an SSTP message.
                {
                    // Indicate invalid SSTP message.
                    m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 16, "SSTP warning: Invalid SSTP message received during SSTP connection establishment. Session closed.");
                    // Send SSTP Call Abort message.
                    mc_abort_sstp_conn();
                    // Close SSTP connection.
                    boc_sess_closed = true;

                    return 1;
                }

            }; break;
        case ied_sstp_state_connected: // SSTP connection established.
            {
                // Try to read Control field of SSTP message.
                dsd_gather_i_1* adsl_link_cur = adsp_gather;
                int iml1 = 0;  // offset

                char chl_sstp_control;

                // Not complete pkt
                if (!adsl_link_cur)
                    return 0;

                // Check Version field
                if ((*adsl_link_cur->achc_ginp_cur) != SSTP_VERSION_BYTE){
                    // Indicate invalid SSTP message.
                    m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 17, "SSTP warning: Invalid SSTP message received during SSTP connected. Session closed.");
                    // Send SSTP Call Abort message.
                    mc_abort_sstp_conn();
                    // Close SSTP connection.
                    boc_sess_closed = true;
                    return 1;
                }
                iml1++;

                if ((adsl_link_cur->achc_ginp_cur + iml1) < adsl_link_cur->achc_ginp_end)
                    chl_sstp_control = *(adsl_link_cur->achc_ginp_cur + iml1);
                else{
                    iml1 = 0;
                    adsl_link_cur = adsl_link_cur->adsc_next;
                    if (!adsl_link_cur)
                        return 0;        // pkt not yet complete
                    chl_sstp_control = *adsl_link_cur->achc_ginp_cur;
                }
                iml1++;

                // Check if this appears to be a valid SSTP message.
                if((chl_sstp_control == SSTP_CONTROL_BYTE) ||
                    (chl_sstp_control == SSTP_DATA_BYTE))
                {

                    // At this point, message seems to be valid SSTP.
                    // Now find LengthPacket field, and read rest of pkt from chain.

                    int32_t iml_lengthpacket = 0;
                    iml_lengthpacket = m_get_sstp_lengthpacket(adsp_gather);
                    if(iml_lengthpacket < 0)
                    {  // Entire length value not available.
                        return 0;
                    }

                    // At this point we have lenght of SSTP message.
                    // Now make sure entire message is available in chain.
                    if(!m_check_sstp_complete(adsp_gather, iml_lengthpacket))
                    {
                        // Entire SSTP message is not available.
                        return 0;
                    }
                    iml1 += 2;

                    // At this point we know that the entire SSTP pKt is available.

#ifndef B150704
                    BOOL bol_consume_input = TRUE;  /* default: consume input at end */
#endif
                    // Check what type of SSTP message this is.

                    if(chl_sstp_control == SSTP_DATA_BYTE) // SSTP Data message.
                    {
                        // At this point we have the entire SSTP message in a single,
                        // contiguous buffer.
                        // Now we can process the remaining contents of the message.

                        // Check if PPP protocol field shows IP (0x21).
                        dsc_sstp_wrap.adsp_hco_wothr = adsp_hco_wothr;
                        //adsc_session_aux = this;


                        while ((adsl_link_cur->achc_ginp_cur + iml1) > adsl_link_cur->achc_ginp_end){
                            iml1--;
                            adsl_link_cur = adsl_link_cur->adsc_next;
                        }

                        if ((adsl_link_cur->achc_ginp_cur + iml1) == adsl_link_cur->achc_ginp_end){
                            adsl_link_cur = adsl_link_cur->adsc_next;
                            iml1 = 0;
                        }

                        if(*(adsl_link_cur->achc_ginp_cur + iml1) == 0x21)
                        {
                            // Send IP packet over internal network.
                            iml1++;
                            dsd_gather_i_1 dsl_gather_data;
                            memcpy( &dsl_gather_data, adsl_link_cur, sizeof(dsl_gather_data) );
                            dsl_gather_data.achc_ginp_cur += iml1;
                            // Target Filter
                            ied_ret_cf iel_ret_cf = ied_rcf_ok;
                            if(adsc_ppp_targfi_act != NULL)
                            {
                                iel_ret_cf = m_proc_ppp_targfi_ipv4(adsp_hco_wothr,
                                    adsc_ppp_targfi_act,
                                    &dsl_gather_data,
                                    iml_lengthpacket - 5);
                            }
                            // If packet can be passed...
                            if(iel_ret_cf == ied_rcf_ok)
                            {
                                m_se_husip_send_gather( &dsl_gather_data, iml_lengthpacket - 5);
                            }
                            // TODO - discard count
                        }
                        else
                        {

#ifdef B150704
                            // Copy all data into a single buffer for PPP implementation
                            int iml2 = iml_lengthpacket - 4;
                            if ((adsl_link_cur->achc_ginp_end - (adsl_link_cur->achc_ginp_cur + iml1)) < iml2){
                                memcpy( chrc_work1, adsl_link_cur->achc_ginp_cur + iml1, adsl_link_cur->achc_ginp_end - (adsl_link_cur->achc_ginp_cur + iml1) );
                                iml2 -= adsl_link_cur->achc_ginp_end - (adsl_link_cur->achc_ginp_cur + iml1);
                                iml1 = adsl_link_cur->achc_ginp_end - (adsl_link_cur->achc_ginp_cur + iml1);   // Now iml1 offset for the ppp data buffer
                                adsl_link_cur = adsl_link_cur->adsc_next;
                            }
                            else{
                                memcpy( chrc_work1, adsl_link_cur->achc_ginp_cur + iml1, iml2 );
                                iml2 = 0;
                            }
                            while(iml2){
                                memcpy( chrc_work1 + iml1, adsl_link_cur->achc_ginp_cur, adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur );
                                iml2 -= adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
                                iml1 += adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
                            }

                            // Send Data field to PPP implementation for processing.
                            m_recv_ppp_server_cs(&dsc_sstp_wrap.dsc_ppp_se_1,
                                chrc_work1,
                                iml_lengthpacket - 4);
#endif
#ifndef B150704
                            /* Copy all data into a single buffer or pass in one chunk */
                            int iml2;
                            iml2 = iml_lengthpacket - 4;
                            if (iml2 <= 0) {    /* length is invalid       */
                                    // Indicate invalid SSTP message.
                                    m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 24, "SSTP warning: Unexpected SSTP MessageLength received during SSTP connection establishment. Session closed.");
                                    // Send SSTP Call Abort message.
                                    mc_abort_sstp_conn();
                                    // Close SSTP connection.
                                    boc_sess_closed = true;

                                    return 1;
                            }

                            bol_consume_input = FALSE;  /* input already consumed */

                            char *achl_w1, *achl_w2;

                            adsl_link_cur->achc_ginp_cur += iml1;
#ifndef B150821
                        /* problem SSTP 21.08.15 KB                    */
                        /* workaround - consume all bytes in previous gather structures */
                        {
                          struct dsd_gather_i_1 *adsh_link_cur_w1;

                          adsh_link_cur_w1 = adsp_gather;
                          while (adsh_link_cur_w1 != adsl_link_cur) {
                            adsh_link_cur_w1->achc_ginp_cur = adsh_link_cur_w1->achc_ginp_end;
                            adsh_link_cur_w1 = adsh_link_cur_w1->adsc_next;  /* get next in chain */
                          }
                        }
#endif
                            if ((adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur) >= iml2) {
                                achl_w1 = adsl_link_cur->achc_ginp_cur;  /* here is beginning of data */
                                adsl_link_cur->achc_ginp_cur += iml2;  /* data consumed */
                                if (adsl_link_cur->achc_ginp_cur >= adsl_link_cur->achc_ginp_end) {  /* end of this gather */
                                  adsl_link_cur = adsl_link_cur->adsc_next;
                                }
                            }
                            else{               /* need to copy data to contiguous memory area */
                              if (iml2 > sizeof(chrc_work1)) {
                                    // Indicate invalid SSTP message.
                                    m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 25, "SSTP warning: Unexpected SSTP MessageLength received during SSTP connection establishment. Session closed.");
                                    // Send SSTP Call Abort message.
                                    mc_abort_sstp_conn();
                                    // Close SSTP connection.
                                    boc_sess_closed = true;

                                    return 1;
                              }
                              achl_w1 = achl_w2 = chrc_work1;
                              do {          /* loop to copy data       */
                                if (adsl_link_cur == NULL) {  /* no more gather - no more data */
                                    // Indicate invalid SSTP message.
                                    m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 26, "SSTP warning: SSTP processing illogic. Session closed.");
                                    // Send SSTP Call Abort message.
                                    mc_abort_sstp_conn();
                                    // Close SSTP connection.
                                    boc_sess_closed = true;

                                    return 1;
                                }
                                iml1 = adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
                                if (iml1 > iml2) iml1 = iml2;
                                if (iml1 > 0) {
                                  memcpy( achl_w2, adsl_link_cur->achc_ginp_cur, iml1 );
                                  achl_w2 += iml1;
                                  adsl_link_cur->achc_ginp_cur += iml1;
                                  iml2 -= iml1;  /* part copied        */
                                }
                                if (adsl_link_cur->achc_ginp_cur >= adsl_link_cur->achc_ginp_end) {  /* end of this gather */
                                  adsl_link_cur = adsl_link_cur->adsc_next;
                                }
                              } while (iml2 > 0);
                            }

                            // Send Data field to PPP implementation for processing.
                            m_recv_ppp_server_cs(&dsc_sstp_wrap.dsc_ppp_se_1,
                                achl_w1,
                                iml_lengthpacket - 4);


                            if (adsl_link_cur == NULL) return 0;
#endif

                        }

                    }
                    else if(chl_sstp_control == SSTP_CONTROL_BYTE)
                    {  // SSTP Control message.
                        // At this point we have the entire SSTP message in a single,
                        // contiguous buffer.
                        // Now we can process the remaining contents of the message.

                        // Make sure SSTP message has valid length.
                        if(iml_lengthpacket < 8)
                        {
                            // Indicate invalid SSTP message.
                            m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 15, "SSTP warning: Invalid length SSTP message received. Session closed.");

                            // Send SSTP Call Abort message.
                            mc_abort_sstp_conn();
                            // Close SSTP connection.
                            boc_sess_closed = true;

                            return 1;
                        }

                        while ((adsl_link_cur->achc_ginp_cur + iml1) > adsl_link_cur->achc_ginp_end){
                            iml1--;
                            adsl_link_cur = adsl_link_cur->adsc_next;
                        }

                        if ((adsl_link_cur->achc_ginp_cur + iml1) == adsl_link_cur->achc_ginp_end){
                            adsl_link_cur = adsl_link_cur->adsc_next;
                            iml1 = 0;
                        }


                        // Read the MessageType field of the SSTP Control message.
                        switch(( *(adsl_link_cur->achc_ginp_cur + iml1 + 1) << 8) & 0xFF00 |
                              (( *(adsl_link_cur->achc_ginp_cur + iml1 + 0) << 0) & 0x00FF) )
                        {
                        case SSTP_MSG_ECHO_REQ:
                            {
                                // Create and send SSTP_MSG_ECHO_ACK SSTP message.
                                // Get new buffer.
                                void* al_handle;
                                char* achl_data;
                                int32_t iml_data_len;
                                iml_data_len = m_htun_getrecvbuf(&al_handle, &achl_data);
                                // Write SSTP SSTP_MSG_ECHO_ACK message.
                                // Version and control fields.
                                *(achl_data + 0)              = SSTP_VERSION_BYTE;
                                *(achl_data + 1)              = SSTP_CONTROL_BYTE;
                                // LengthPacket field.
                                *(achl_data + 2) = 0x00;
                                *(achl_data + 3) = 0x08;
                                // MessageType field. SSTP_MSG_ECHO_ACK 0x0009
                                *(achl_data + 4) = 0x00;
                                *(achl_data + 5) = 0x09;
                                // NumAttributes field.
                                *(achl_data + 6) = 0x00;
                                *(achl_data + 7) = 0x00;

                                // Init new vec ele.
                                dsd_buf_vector_ele dsl_sstp_echo_ack;
                                dsl_sstp_echo_ack.ac_handle = al_handle;
                                dsl_sstp_echo_ack.achc_data = achl_data;
                                dsl_sstp_echo_ack.imc_len_data = 0x0008;

                                // Check whether it is OK to send message towards
                                // client...
                                if(boc_cansend)
                                {
                                    // Send pkt to client.
                                    if(!(m_se_htun_recvbuf(adsc_tun_contr_conn,
                                        &dsl_sstp_echo_ack, 1)))
                                    {
                                        // Indicate that it is not OK to send more
                                        // messages towards client.
                                        boc_cansend = false;
                                    }
                                }
                                else
                                {
                                    // Increment number of messages discarded.
                                    umc_discard_count++;
                                }
                            }; break;
                        case SSTP_MSG_CALL_DISCONNECT:
                            {
                                // Create & send SSTP_MSG_CALL_DISCONNECT_ACK SSTP msg.
                                // Get new buffer.
                                void* al_handle;
                                char* achl_data;
                                int32_t iml_data_len;
                                iml_data_len = m_htun_getrecvbuf(&al_handle, &achl_data);
                                // Init new vec ele.
                                dsd_buf_vector_ele dsl_sstp_call_disconn_ack;
                                dsl_sstp_call_disconn_ack.ac_handle = al_handle;
                                dsl_sstp_call_disconn_ack.achc_data =
                                    achl_data + iml_data_len;
                                dsl_sstp_call_disconn_ack.imc_len_data = 0;
                                // Write SSTP SSTP_MSG_CALL_DISCONNECT_ACK message.
                                mc_make_sstp_disconnect_ack(&dsl_sstp_call_disconn_ack);
                                // Send SSTP SSTP_MSG_CALL_DISCONNECT_ACK message to
                                // client.

                                // Check whether it is OK to send message towards
                                // client...
                                if(boc_cansend)
                                {
                                    // Send pkt to client.
                                    if(!(m_se_htun_recvbuf(adsc_tun_contr_conn,
                                        &dsl_sstp_call_disconn_ack,
                                        1)))
                                    {
                                        // Indicate that it is not OK to send more
                                        // messages towards client.
                                        boc_cansend = false;
                                    }
                                }
                                else
                                {
                                    // Increment number of messages discarded.
                                    umc_discard_count++;
                                }

                                // Close SSTP connection.
                                boc_sess_closed = true;

                            }; break;
                        case SSTP_MSG_CALL_ABORT:
                            {
                                // Close SSTP connection.
                                boc_sess_closed = true;

                            }; break;
                        default:
                            {
                                // Indicate invalid SSTP message.
                                m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 16, "SSTP warning: Unexpected SSTP MessageType received. Session closed.");

                                // Send SSTP Call Abort message.
                                mc_abort_sstp_conn();
                                // Close SSTP connection.
                                boc_sess_closed = true;

                                return 1;
                            }; break;
                        }
                    }

#ifdef B150704
                    // Consume pkt here from the chain of gahters
                    m_consume_hpppt1_msg(&adsp_gather, iml_lengthpacket);
                    if (!adsp_gather)
                        return 0;
#endif
#ifndef B150704
                    if (bol_consume_input) {  /* default: consume input at end */
                      // Consume pkt here from the chain of gathers
                      m_consume_hpppt1_msg(&adsp_gather, iml_lengthpacket);
                      if (!adsp_gather)
                          return 0;
                    }
#endif
                }
                else // Not an SSTP message.
                {
                    // Indicate invalid SSTP message.
                    m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 17, "SSTP warning: Invalid SSTP message received. Session closed.");
                    // Send SSTP Call Abort message.
                    mc_abort_sstp_conn();

                    // Close SSTP connection.
                    boc_sess_closed = true;

                    return 1;
                }
            }; break;
        }
    }

    return 0;
}


// Called from the callback for new PPP implementation to send SSTP message back to client.
int32_t dsd_sstp_session::mc_tunnel_to_cl(void* ap_handle,
                                          byte* abyp_data,
                                          uint32_t ump_length)
{
    // Create buf vec ele.
    ump_length += 4;
    *(--abyp_data) = ump_length & 0xFF;
    *(--abyp_data) = (ump_length & 0xFF00) >> 8;
    *(--abyp_data) = SSTP_DATA_BYTE;
    *(--abyp_data) = SSTP_VERSION_BYTE;

    mc_sstp_tunnel_data(ap_handle, abyp_data, ump_length);

    return 0;
}


int32_t dsd_sstp_session::mc_encapsulate_msg(void* ap_handle,
                                             byte* abyp_data,
                                             uint32_t ump_length)
{
    // Check if it is connected and therefore able to send to data to client
    if ( iec_sstp_state != ied_sstp_state_connected ){
		m_htun_relrecvbuf(ap_handle);
		m_htun_warning(adsc_tun_contr_conn,adsc_tun_contr_ineta, BASE_ERR_NUMBER + 20, "SSTP warning: msg to client before tunnel established.");
		return 0;
	}


    // Create buf vec ele.
    ump_length += 5;
    *(--abyp_data) = 0x21;
    *(--abyp_data) = ump_length & 0xFF;
    *(--abyp_data) = (ump_length & 0xFF00) >> 8;
    *(--abyp_data) = SSTP_DATA_BYTE;
    *(--abyp_data) = SSTP_VERSION_BYTE;

    mc_sstp_tunnel_data(ap_handle, abyp_data, ump_length);


    return 0;
}


void dsd_sstp_session::mc_sstp_tunnel_data(void*  ap_handle,
                                           byte*  abyp_data,
                                           unsigned int ump_length)
{
    bool bol_rc;
    // todo - CS needed??
    // Enter general CS.
    dsc_cs.m_enter();


    if(adsc_tun_contr_conn == NULL){
        boc_cansend = FALSE;
        dsc_cs.m_leave();
        m_htun_relrecvbuf(ap_handle);
        return;
    }



#define UMC_ON_THE_FLY_CURRENT (adsc_tun_contr_conn->imc_on_the_fly_packets_client + umc_packets_list)

    if (boc_cansend == FALSE) {
p_cannot_send_00:
        if( (UMC_ON_THE_FLY_CURRENT < MAX_PPP_ON_THE_FLY_PACKETS_CLIENT)
            || ((adsc_tun_contr_conn->boc_not_drop_tcp_packet != FALSE)
            && (*(abyp_data + D_POS_IPV4_H_PROT) == IPPROTO_TCP)))
        {
            umc_packets_list++;
            if (adsc_queue_last != NULL){
                adsc_queue_last->adsc_next = (struct dsd_packet *) ap_handle;
                adsc_queue_last = adsc_queue_last->adsc_next;
            }
            adsc_queue_last = (struct dsd_packet *) ap_handle;
            adsc_queue_last->dsl_buf_vec.ac_handle = ap_handle;
            adsc_queue_last->dsl_buf_vec.achc_data = (char*) abyp_data;
            adsc_queue_last->dsl_buf_vec.imc_len_data = ump_length;
            adsc_queue_last->adsc_next = NULL;
            if (adsc_queue_first == NULL)
                adsc_queue_first = adsc_queue_last;
            goto p_return_00;
        }

        goto p_backlog_00;
    }
    // Create buf vec ele.
    struct dsd_buf_vector_ele dsl_buf_vec[ D_ARRAY_PACKET ];
    int iml_array_len;

p_from_queue_00:
    // check if queued entries, if yes, fill array
    // when array full, jump to p_send_00:                                /* send packets to the WSP */
    iml_array_len = 0;

    // If number of queued messages is still below limit OR no drop flag is
    // set ...
    if (   (UMC_ON_THE_FLY_CURRENT >= MAX_PPP_ON_THE_FLY_PACKETS_CLIENT)
        && (   (adsc_tun_contr_conn->boc_not_drop_tcp_packet == FALSE)
        || (*(abyp_data + D_POS_IPV4_H_PROT) != IPPROTO_TCP))
        && (ap_handle!=0)) {
            // free memory of received packet
            m_htun_relrecvbuf(ap_handle);
            // Increment number of messages discarded.
            umc_discard_count++;
    } else {
        // Fill the vector
        for (int iml1 = 0; iml1 < D_ARRAY_PACKET; iml1++){
            if (adsc_queue_first == NULL) break;
            dsl_buf_vec[ iml_array_len ].ac_handle = adsc_queue_first->dsl_buf_vec.ac_handle;
            dsl_buf_vec[ iml_array_len ].achc_data = (char*)adsc_queue_first->dsl_buf_vec.achc_data;
            dsl_buf_vec[ iml_array_len ].imc_len_data = adsc_queue_first->dsl_buf_vec.imc_len_data;
            adsc_queue_first = adsc_queue_first->adsc_next;
            umc_packets_list--;
            iml_array_len++;                        /* entry filled            */
        }
        if(adsc_queue_first == NULL)
            adsc_queue_last = NULL;
        if (ap_handle == NULL){
            if (iml_array_len > 0){
                goto p_send_00;
            }
            goto p_return_00;
        }
        // Add new packet either to the vector or the list
        if (iml_array_len < D_ARRAY_PACKET){
            dsl_buf_vec[ iml_array_len ].ac_handle = ap_handle;
            dsl_buf_vec[ iml_array_len ].achc_data = (char*) abyp_data;
            dsl_buf_vec[ iml_array_len ].imc_len_data = ump_length;
            ap_handle = NULL;
            iml_array_len++;
        }
        else if (   (adsc_tun_contr_conn->boc_not_drop_tcp_packet != FALSE)
            && (*(abyp_data + D_POS_IPV4_H_PROT) == IPPROTO_TCP)) {
                umc_packets_list++;
                if (adsc_queue_last != NULL){
                    adsc_queue_last->adsc_next = (struct dsd_packet *) ap_handle;
                    adsc_queue_last = adsc_queue_last->adsc_next;
                }
                adsc_queue_last = (struct dsd_packet *) ap_handle;
                adsc_queue_last->dsl_buf_vec.ac_handle = ap_handle;
                adsc_queue_last->dsl_buf_vec.achc_data = (char*) abyp_data;
                adsc_queue_last->dsl_buf_vec.imc_len_data = ump_length;
                adsc_queue_last->adsc_next = NULL;
                if (adsc_queue_first == NULL)
                    adsc_queue_first = adsc_queue_last;
                ap_handle = NULL;
        }
        else {
            // free memory of received packet
            m_htun_relrecvbuf(ap_handle);
            // Increment number of messages discarded.
            umc_discard_count++;
            ap_handle = NULL;
        }
    }

    if(iml_array_len == 0){
        goto p_return_00;
    }

p_send_00:                                /* send packets to the WSP */
    /* pass all iml_array_len records in one set of vectors */
    if ((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
    {
        /* all packets go into the WSP-trace */
        // Prepare gather structure for tracing.
        for(int iml1 = 0; iml1 < iml_array_len; iml1++){
            dsd_gather_i_1 dsl_gath;
            dsl_gath.achc_ginp_cur = dsl_buf_vec[iml1].achc_data;
            dsl_gath.achc_ginp_end = dsl_gath.achc_ginp_cur + dsl_buf_vec[iml1].imc_len_data;
            dsl_gath.adsc_next = NULL;

            // TODO - wsp trace
            /*m_do_wsp_trace("SNETUNSE", 0, adsc_tun_contr_conn->imc_sno,
            adsc_tun_contr_conn->imc_trace_level, &dsl_gath,
            dsl_buf_vec[iml1].imc_len_data, 20,
            "HOB-PPP-T1 send %d bytes to client.",
            dsl_buf_vec[iml1].imc_len_data);*/
        }
    }

    adsc_tun_contr_conn->imc_on_the_fly_packets_client += iml_array_len;
    // Send message to client.
    bol_rc = m_se_htun_recvbuf(adsc_tun_contr_conn, dsl_buf_vec, iml_array_len);
    if(!bol_rc)
    {
        // Indicate that it is not OK to send more messages towards client.
        boc_cansend = false;
    }

    if (boc_cansend == false) {
        goto p_cannot_send_00;
    }
    goto p_from_queue_00;

p_backlog_00:
    /* check again if we can discard the packet */
    if (   (UMC_ON_THE_FLY_CURRENT >= MAX_PPP_ON_THE_FLY_PACKETS_CLIENT)
        && (   (adsc_tun_contr_conn->boc_not_drop_tcp_packet == FALSE)
        || (*(abyp_data + D_POS_IPV4_H_PROT) != IPPROTO_TCP))
        && (ap_handle != NULL)) {
            // free memory of received packet
            m_htun_relrecvbuf(ap_handle);
            // Increment number of messages discarded.
            umc_discard_count++;
            goto p_return_00;
    }

    /* if not, append to chain - backlog */

p_return_00:
    // TODO - CS??
    // Leave general CS.
    //dsd_cs.m_leave();

    dsc_cs.m_leave();

    return;
#undef UMC_ON_THE_FLIGHT
}


void dsd_sstp_session::mc_make_sstp_disconnect_ack
(dsd_buf_vector_ele *adsp_buf_vec)
{
    adsp_buf_vec->imc_len_data += 8;
    // NumAttributes field.
    *(--adsp_buf_vec->achc_data) = 0x00;
    *(--adsp_buf_vec->achc_data) = 0x00;
    // MessageType field. SSTP_MSG_CALL_DISCONNECT_ACK
    *(--adsp_buf_vec->achc_data) = 0x07;
    *(--adsp_buf_vec->achc_data) = 0x00;
    // LengthPacket field.
    *(--adsp_buf_vec->achc_data) = 0x08;
    *(--adsp_buf_vec->achc_data) = 0x00;
    // Version and control fields.
    *(--adsp_buf_vec->achc_data) = SSTP_CONTROL_BYTE;
    *(--adsp_buf_vec->achc_data) = SSTP_VERSION_BYTE;
}
void dsd_sstp_session::mc_make_sstp_call_abort(dsd_buf_vector_ele* adsp_buf_vec)
{
    // Update length value for vec ele.
    adsp_buf_vec->imc_len_data += 8;
    // Write NumAttributes field.
    *(--adsp_buf_vec->achc_data) = 0x00;
    *(--adsp_buf_vec->achc_data) = 0x00;
    // Write MessageType field. SSTP_MSG_CALL_ABORT
    *(--adsp_buf_vec->achc_data) = 0x05;
    *(--adsp_buf_vec->achc_data) = 0x00;
    // Write LengthPacket field.
    *(--adsp_buf_vec->achc_data) = 0x08;
    *(--adsp_buf_vec->achc_data) = 0x00;
    // Write Version & Control fields.
    *(--adsp_buf_vec->achc_data) = SSTP_CONTROL_BYTE;
    *(--adsp_buf_vec->achc_data) = SSTP_VERSION_BYTE;
}

void dsd_sstp_session::mc_abort_sstp_conn()
{
    // Get new recv buffer.
    void* al_handle;
    char* achl_data;
    int32_t iml_data_len;
    iml_data_len = m_htun_getrecvbuf(&al_handle, &achl_data);
    // Create & init new vec ele struct.
    dsd_buf_vector_ele dsl_sstp_call_abort;
    dsl_sstp_call_abort.ac_handle = al_handle;
    dsl_sstp_call_abort.achc_data = achl_data + iml_data_len;
    dsl_sstp_call_abort.imc_len_data = 0;
    // Write SSTP CallAbort message.
    mc_make_sstp_call_abort(&dsl_sstp_call_abort);

    // todo - error atrib.

    // Check whether it is OK to send message towards client...
    if(boc_cansend)
    {
        // Send pkt to client.
        if(!(m_se_htun_recvbuf(adsc_tun_contr_conn, &dsl_sstp_call_abort, 1)))
        {
            // Indicate that it is not OK to send more messages towards client.
            boc_cansend = false;
        }
    }
    else
    {
        // Increment number of messages discarded.
        umc_discard_count++;
    }
}


// Create target filter for the SSTP session
// if crypto binding completed then state connected
void dsd_sstp_session::mc_auth_compl(){
    if(boc_crypto_ok)
        iec_sstp_state = ied_sstp_state_connected;
	if(adsc_targ_filter)
		return;
	adsc_targ_filter = m_htun_ppp_get_targfi(adsc_tun_contr_conn);
	if(adsc_targ_filter != NULL)
	{
		if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
		{
			// TODO - trace - correct?
			m_do_wsp_trace("SNEPPPTC", 0, adsc_tun_contr_conn->imc_sno,
				adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
				"Creating PPP target filter - SSTP.");
		}
#ifdef TJ_B160707
		adsc_ppp_targfi_act = m_create_ppp_targfi(adsc_targ_filter);
#else
		adsc_ppp_targfi_act = m_create_ppp_targfi(adsc_targ_filter,adsc_tun_contr_conn->imc_trace_level,adsc_tun_contr_conn->imc_sno);
#endif
	}
}



// Callback for new PPP implementation to send SSTP message back to client.
static void m_ppp_send_callback_se(dsd_ppp_server_1* adsp_ppp_server,
                                   dsd_buf_vector_ele* adsp_buf_vec)
{
    /* TODO Usage of the offsetof macro on non-pod structures
    could be dangaerous*/
    // dsd_sstp_session* adsl_sess =
    //    (dsd_sstp_session*)((char*)adsp_ppp_server -
    //    offsetof(dsd_sstp_session, dsc_ppp_se_1));
    dsd_sstp_session* adsl_sess = m_sstp_session_from_s1(adsp_ppp_server);
    adsl_sess->mc_tunnel_to_cl( adsp_buf_vec->ac_handle,
        (byte*)adsp_buf_vec->achc_data,
        adsp_buf_vec->imc_len_data);
    return;

}

// New routine implemented in order to get address of INETA configured for htun.
static char* m_ppp_se_get_ineta_client(struct dsd_ppp_server_1 *adsp_ppp_se_1)
{

	dsd_sstp_session* adsl_sess = m_sstp_session_from_s1(adsp_ppp_se_1);
    dsd_tun_contr_ineta* adsc_ineta_aux = NULL;
    if (adsl_sess->adsc_tun_contr_ineta == NULL){
        adsc_ineta_aux = m_htun_ppp_acquire_local_ineta_ipv4( adsl_sess->dsc_sstp_wrap.adsp_hco_wothr,
            adsl_sess->adsc_tun_contr_conn,
            adsl_sess->adsc_tun_contr_ineta );
        if ( adsc_ineta_aux == 0 ){
            memset(&adsl_sess->dsc_sstp_wrap.dsc_timer_close, 0, sizeof(adsl_sess->dsc_sstp_wrap.dsc_timer_close));
            adsl_sess->dsc_sstp_wrap.dsc_timer_close.amc_compl = m_cb_timer_close;
            adsl_sess->dsc_sstp_wrap.dsc_timer_close.ilcwaitmsec = 1000 * 10; // 10s timeout.
            m_time_set(&adsl_sess->dsc_sstp_wrap.dsc_timer_close, false);
            return NULL;
        }
    }
    else{
        return (char*)&(adsl_sess->adsc_tun_contr_ineta->dsc_soa_local_ipv4.sin_addr);
    }

    adsl_sess->adsc_tun_contr_ineta = adsc_ineta_aux;
    adsl_sess->adsc_tun_contr_ineta->adsc_tun_contr_conn = adsl_sess->adsc_tun_contr_conn;
    adsl_sess->umc_client_ineta = inet_addr(inet_ntoa(adsl_sess->adsc_tun_contr_ineta->dsc_soa_local_ipv4.sin_addr));


    return (char*)&(adsl_sess->adsc_tun_contr_ineta->dsc_soa_local_ipv4.sin_addr);

} // End m_ppp_se_get_ineta_client().

// New function implemented to set proper values in initial HTTP response.
static void m_sstp_make_http_response( char *achl_buffer )
{
    char chrl_temp_buf[5] = { 0 };

    memcpy(achl_buffer, byrg_http_proto_ver, umg_len_http_proto_ver);
    memcpy(achl_buffer + umg_len_http_proto_ver,
        byrg_http_stat_code,
        umg_len_http_stat_code);
    memcpy(achl_buffer + umg_len_http_proto_ver + umg_len_http_stat_code,
        byrg_http_cont_len,
        umg_len_http_cont_len);
    memcpy(achl_buffer + umg_len_http_proto_ver + umg_len_http_stat_code +
        umg_len_http_cont_len,
        byrg_http_server,
        umg_len_http_server);

    time_t dsl_rawtime = time(NULL);
    tm* adsl_gmtime = gmtime(&dsl_rawtime);

    const uint32_t uml_offset_date =
        umg_len_http_proto_ver + umg_len_http_stat_code + umg_len_http_cont_len +
        umg_len_http_server;
    uint32_t uml_tmp_offset = uml_offset_date;
    memcpy(achl_buffer + uml_tmp_offset, "Date: ", 6);
    uml_tmp_offset += 6;
    memcpy(achl_buffer + uml_tmp_offset,
        chrrl_days_of_week[adsl_gmtime->tm_wday],
        3);
    uml_tmp_offset += 3;
    memcpy(achl_buffer + uml_tmp_offset, ", ", 2);
    uml_tmp_offset += 2;
    if(adsl_gmtime->tm_mday < 10)
    {
        memcpy(achl_buffer + uml_tmp_offset, "0", 1);
        uml_tmp_offset += 1;
        sprintf(chrl_temp_buf, "%d", adsl_gmtime->tm_mday);
        memcpy(achl_buffer + uml_tmp_offset, chrl_temp_buf,
            1);
        uml_tmp_offset += 1;
    }
    else
    {
        sprintf(chrl_temp_buf, "%d", adsl_gmtime->tm_mday);
        memcpy(achl_buffer + uml_tmp_offset, chrl_temp_buf,
            2);
        uml_tmp_offset += 2;
    }
    memcpy(achl_buffer + uml_tmp_offset, " ", 1);
    uml_tmp_offset += 1;
    memcpy(achl_buffer + uml_tmp_offset,
        chrrl_months_of_year[adsl_gmtime->tm_mon],
        3);
    uml_tmp_offset += 3;
    memcpy(achl_buffer + uml_tmp_offset, " ", 1);
    uml_tmp_offset += 1;
    sprintf(chrl_temp_buf, "%d", adsl_gmtime->tm_year + 1900);
    memcpy(achl_buffer + uml_tmp_offset, chrl_temp_buf, 4);
    uml_tmp_offset += 4;
    memcpy(achl_buffer + uml_tmp_offset, " ", 1);
    uml_tmp_offset += 1;
    if(adsl_gmtime->tm_hour < 10)
    {
        memcpy(achl_buffer + uml_tmp_offset, "0", 1);
        uml_tmp_offset += 1;
        sprintf(chrl_temp_buf, "%d", adsl_gmtime->tm_hour);
        memcpy(achl_buffer + uml_tmp_offset, chrl_temp_buf,
            1);
        uml_tmp_offset += 1;
    }
    else
    {
        sprintf(chrl_temp_buf, "%d", adsl_gmtime->tm_hour);
        memcpy(achl_buffer + uml_tmp_offset, chrl_temp_buf,
            2);
        uml_tmp_offset += 2;
    }
    memcpy(achl_buffer + uml_tmp_offset, ":", 1);
    uml_tmp_offset += 1;
    if(adsl_gmtime->tm_min < 10)
    {
        memcpy(achl_buffer + uml_tmp_offset, "0", 1);
        uml_tmp_offset += 1;
        sprintf(chrl_temp_buf, "%d", adsl_gmtime->tm_min);
        memcpy(achl_buffer + uml_tmp_offset, chrl_temp_buf,
            1);
        uml_tmp_offset += 1;
    }
    else
    {
        sprintf(chrl_temp_buf, "%d", adsl_gmtime->tm_min);
        memcpy(achl_buffer + uml_tmp_offset, chrl_temp_buf,
            2);
        uml_tmp_offset += 2;
    }
    memcpy(achl_buffer + uml_tmp_offset, ":", 1);
    uml_tmp_offset += 1;
    if(adsl_gmtime->tm_sec < 10)
    {
        memcpy(achl_buffer + uml_tmp_offset, "0", 1);
        uml_tmp_offset += 1;
        sprintf(chrl_temp_buf, "%d", adsl_gmtime->tm_sec);
        memcpy(achl_buffer + uml_tmp_offset, chrl_temp_buf,
            1);
        uml_tmp_offset += 1;
    }
    else
    {
        sprintf(chrl_temp_buf, "%d", adsl_gmtime->tm_sec);
        memcpy(achl_buffer + uml_tmp_offset, chrl_temp_buf,
            2);
        uml_tmp_offset += 2;
    }
    memcpy(achl_buffer + uml_tmp_offset, " GMT\r\n\r\n", 8);
    uml_tmp_offset += 8;
}

static void m_cb_timer_close(dsd_timer_ele* adsp_timer_close)
{
    /*TODO Usage of offsetof on non-pod structures could be dangerous */
    // Obtain ptr to sstp session.
    // int iml_offset = offsetof(dsd_sstp_session, dsc_timer_close);
    // dsd_sstp_session* adsl_sstp_sess =
    //     (dsd_sstp_session*)((char*)adsp_timer_close - iml_offset);
    dsd_sstp_session* adsl_sstp_sess = m_sstp_session_from_te(adsp_timer_close);

    // Call class dtor.
    delete adsl_sstp_sess;

    // Free session resources are freed in the destructor.

    return;
}


static void m_log_sstp_warning(dsd_ppp_server_1* adsp_ppp_svr, char* achp_message)
{
	dsd_sstp_session* adsl_sess = m_sstp_session_from_s1(adsp_ppp_svr);
    if(adsl_sess->adsc_tun_contr_conn == NULL)
        return;
    m_htun_warning(adsl_sess->adsc_tun_contr_conn, adsl_sess->adsc_tun_contr_ineta,
        BASE_ERR_NUMBER + 18, achp_message);
    return;
}

static void m_ppp_se_hs_compl(dsd_ppp_server_1* adsp_ppp_svr)
{
#ifndef callback_hs_compl
	dsd_sstp_session* adsl_sess = m_sstp_session_from_s1(adsp_ppp_svr);
	adsl_sess->mc_auth_compl();
#endif
    return;
}

