//#define HTCP_TRY_100830
//#define HTCP_TRY_100819
/******************************************************************************
 * File name: htcp_session.h
 *
 * HTCP interface with HUSIP.
 *
 * Requires C++.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/

#ifndef HTCP_SESSION_H
#define HTCP_SESSION_H

#ifdef DOES_INCL_HEADERS
#if defined WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#elif defined HL_UNIX
#include "hob-hunix01.h"
#else // !defined WIN32 && !defined HL_UNIX
#error htcp_session.h needs either WIN32 or HL_UNIX
#endif // !defined WIN32 && !defined HL_UNIX

#include <list>
#include "int_types.h"
#include "htcp.h"
#include "hob-netw-01.h"
#include "hob-tun01.h"
#include "hob-session01.h"
#include "connection.h"
#endif

#ifdef B100706
// The default local port for HTCP connections.
static const uint16 us_htcp_default_port = 10000;
#endif

void m_htcp_connect_wsp(dsd_htcp_conn* ads_conn);
void m_htcp_conn_cleanup_wsp(dsd_htcp_conn* ads_conn);

#ifdef B100721
// Each connection will handle sending data to WSP.
struct dsd_htcp_recv_data {
    dsd_mutex_lock ds_lock;
    bool bo_servicing;
    std::list<dsd_buf_vector_ele> ds_data;

    dsd_htcp_recv_data()
        : bo_servicing(false)
    {
    }

    /* KS 18-03-09 - no longer required
    dsd_htcp_recv_data(const dsd_htcp_recv_data& ds_other)
    {
      bo_servicing = ds_other.bo_servicing;
      ds_data = ds_other.ds_data;
    }
    */
};
#endif

// Used while establishing connection.
struct dsd_htcp_target_inet {
    dsd_ineta_single_1* ads_first_address;
    dsd_ineta_single_1* ads_current_address;
    int in_current;
    int in_remain;
    int in_total;
    bool bo_round_robin;
    uint64 um_unused;
};

enum ied_hs_state {
    ied_hs_connecting,
    ied_hs_connected,
    ied_hs_fin_received,
    ied_hs_fin_sent,
    ied_hs_closed_time_wait,
    ied_hs_closed
};

typedef char dsd_htcp_conn_internal_buf[sizeof(dsd_htcp_conn_internal)];

// A dsd_htcp_session represents an HTCP session.
class dsd_htcp_session : public dsd_session {
public:

    dsd_htcp_session(dsd_tun_start1* ads_tun_start,
                     dsd_tun_contr1* ads_sess_info);
    ~dsd_htcp_session();

    int mc_init();

    void mc_close();

    // Try connecting with the next target address in line.
    void m_try_next_address();

    // Process data from WSP.
    int mc_interpret_msg(dsd_gather_i_1* ads_message,
                         dsd_hco_wothr* adsp_hco_wothr);

    // Handle buffers received from the TUN interface via HUSIP.
    int mc_encapsulate_msg(void* vp_handle, byte* aby_buffer, uint32 un_len);

    void mc_can_send();
    void mc_do_send();

    dsd_htcp_conn ds_connection;
    dsd_htcp_conn_internal_buf ds_conn_internal;

#ifdef B100721
    dsd_htcp_recv_data ds_rdata;
#endif
    bool boc_sending;
    bool boc_sending_try_again;
    bool boc_cansend_again;

    dsd_htcp_target_inet ds_target;

    ied_hs_state iec_state;
    dsd_timer_ele dsc_timer;
    bool boc_wsp_closed;
    bool boc_htcp_closed;

#ifdef B100706
    dsd_htcp_session* ads_previous;
    dsd_htcp_session* ads_next;
    uint16 us_next_port;
    dsd_session_info ds_handle_info;
    dsd_avl_session* ads_avl_sess;
#endif

#ifdef HTCP_TRY_100819
    dsd_gather_i_1* ads_output_gather;
    uint32 um_output_gather_count;
#endif // HTCP_TRY_100819

};

// Timer callback
void m_hs_cb_timer(dsd_timer_ele* adsp_te);

// HTCP connection callbacks
void m_htcp_cb_connected(dsd_htcp_conn* ads_conn, int in_code);
void m_htcp_cb_connection_failed(dsd_htcp_conn* ads_conn, int in_code);
void m_htcp_cb_recv_data(dsd_htcp_conn* ads_conn, int in_code);
void m_htcp_cb_data_acked(dsd_htcp_conn* ads_conn, int in_code);
void m_htcp_cb_recv_eof(dsd_htcp_conn* ads_conn, int in_code);
void m_htcp_cb_conn_reset(dsd_htcp_conn* ads_conn, int in_code);
void m_htcp_cb_conn_closed(dsd_htcp_conn* ads_conn, int in_code);

// send packet(s) to TUN via HUSIP
void m_send_packet(dsd_htcp_conn* ads_conn, dsd_send_packet_info& ds_packet);
void m_send_packets(dsd_htcp_conn* ads_conn,
                    std::list<dsd_send_packet_info>& ds_packets);

// send received data to WSP
void m_data_received(dsd_htcp_conn* ads_conn);

#endif // HTCP_SESSION_H
