//#define TRACE_120717
//#define TRACE_120717_EXTRA

/******************************************************************************
 * File name: htcp_session.cpp
 *
 * Implements htcp_session.h
 *
 * Requires C++.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/

#include <assert.h>
#include <string.h>

// required for hob-tun01.h
#ifdef HL_UNIX
#include "hob-hunix01.h"
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#ifdef B090317
#include "int_types.h"
#include "htcp.h"
#include "misc.h"
#include "hob-avl03.h"
#include "htcp_session.h"
#include "tcpip_hdr.h"
#include "hob-tun01.h"
#include "hob-session01.h"
#endif
#include "hob-avl03.h"
/* new 19.03.09 start */
#include <hob-xslhcla1.hpp>
#include <hob-netw-01.h>
#include <string>
#include <map>
#include <list>
#include <queue>
#include <stddef.h>
#include <iostream>
#include "hob-xslcontr.h"
#include "hob-tun01.h"
#include "hob-htcp-int-types.h"
#include "hob-htcp.h"
#include "hob-htcp-bit-reference.h"
#include "hob-htcp-tcpip-hdr.h"
#include "hob-htcp-misc.h"
#include "hob-htcp-connection.h"
#include "hob-session01.h"
#include "hob-htcp-session.h"
#include "hob-gw-ppp-1.h"
#include "hob-hppp01.h"
#include "hob-hsstp01.h"
#include "hob-tun02.h"
/* new 19.03.09 end */

extern "C" int m_hl1_printf(char * aptext, ... );
extern "C" int m_get_random_number(int impmax);
extern "C" void m_htun_htcp_send_complete( struct dsd_tun_contr1 *adsp_tun_contr1 );
extern "C" void m_htun_session_end( struct dsd_tun_contr1 *adsp_tun_contr1,
                                         int imp_reason );
extern "C" void m_htun_free_resources( struct dsd_tun_contr1 *adsp_tun_contr1 );
extern "C" void m_htun_critsect_enter( struct dsd_tun_contr1 *adsp_tun_contr1 );
extern "C" void m_htun_critsect_leave( struct dsd_tun_contr1 *adsp_tun_contr1 );

void m_htcp_connect_wsp(dsd_htcp_conn* ads_conn)
{
    // dsd_htcp_conn_internal constructor initializes connection variables
    dsd_htcp_conn_internal* ads_ci =
        new(ads_conn->vp_internal) dsd_htcp_conn_internal(ads_conn);
    ads_ci->m_active_open();
}

void m_htcp_conn_cleanup_wsp(dsd_htcp_conn* ads_conn)
{
    dsd_htcp_conn_internal* ads_ci = m_get_internal(ads_conn);
    ads_ci->m_reset();
    ads_ci->~dsd_htcp_conn_internal();
    ads_conn->vp_internal = 0;
}

// Make sure order is correct, see htcp.h
dsd_htcp_conn_callbacks ds_htcp_callbacks = {
    m_htcp_cb_connected,
    m_htcp_cb_connection_failed,
    m_htcp_cb_recv_data,
    m_htcp_cb_data_acked,
    m_htcp_cb_recv_eof,
    m_htcp_cb_conn_reset,
    m_htcp_cb_conn_closed
};

dsd_htcp_session::dsd_htcp_session(dsd_tun_start1* ads_tun_start,
                                   dsd_tun_contr1* ads_sess_info)
    : dsd_session(ads_sess_info)
{
#ifdef HTCP_TRY_100819
    ads_output_gather = 0;
    um_output_gather_count = 0;
#endif // HTCP_TRY_100819

#ifdef B100706
    unsigned un_local_port;
    if (vp_info == 0) {
        // this is the first session with this local IP
        us_next_port = us_htcp_default_port;
        un_local_port = us_next_port++;
        ads_previous = 0;
        ads_next = 0;
    } else {
        // this is at least another session with this local IP
        // TODO: is synchronization necessary?
        dsd_htcp_session* ads_first = (dsd_htcp_session*)vp_info;
        us_next_port = 0; // indicates this is not first in list
        un_local_port = ads_first->us_next_port++;
        // TODO: if port wraps, ensure we skip ports still in use
        if (ads_first->us_next_port == 0)
            ads_first->us_next_port = un_local_port;
        ads_previous = ads_first;
        ads_next = ads_first->ads_next;
        ads_previous->ads_next = this;
        if (ads_next != 0) {
            ads_next->ads_previous = this;
        }
    }
    ds_handle_info.ie_type = ied_tunc_htcp;
    ds_handle_info.ads_sess = this;
    ads_avl_sess = 0;
#endif // B100706
    ds_connection.vp_user_data = this;
    ds_connection.vp_internal = &ds_conn_internal;

    assert(ads_tun_start->dsc_soa_local.ss_family == 2); // IPv4
    sockaddr_in* ads_isa = (sockaddr_in*)&ads_tun_start->dsc_soa_local;
    ds_connection.um_local_addr = ntohl(ads_isa->sin_addr.s_addr);
    ds_connection.us_local_port = ntohs(ads_isa->sin_port);
    ds_connection.us_remote_port = ads_tun_start->imc_server_port;

    ds_connection.um_send_pend = 0;
    ds_connection.um_recv_avail = 0;
    ds_connection.ads_callbacks = &ds_htcp_callbacks;

    // process target addresses
    ds_target.ads_current_address = ds_target.ads_first_address =
        (dsd_ineta_single_1*)(ads_tun_start->adsc_server_ineta + 1);
    ds_target.in_current = 0;
    ds_target.in_remain = ds_target.in_total =
        ads_tun_start->adsc_server_ineta->imc_no_ineta;
    ds_target.bo_round_robin = ads_tun_start->boc_connect_round_robin;
    assert(ds_target.in_total <= 64);
    ds_target.um_unused = (1 << ds_target.in_total) - 1;

    boc_sending = false;

    iec_state = ied_hs_connecting;
    boc_wsp_closed = false;
    boc_htcp_closed = false;

    std::memset(&dsc_timer, 0, sizeof(dsc_timer));
}

dsd_htcp_session::~dsd_htcp_session()
{
#ifdef HTCP_TRY_100819
    while (ads_output_gather) {
        dsd_gather_i_1* ads_n = ads_output_gather->adsc_next;
        delete ads_output_gather;
        ads_output_gather = ads_n;
    }
#endif // HTCP_TRY_100819
}

int dsd_htcp_session::mc_init()
{
    m_try_next_address();
    return 0;
}

void dsd_htcp_session::mc_close()
{
#ifdef TRACE_120717
    m_htun_warning(adsc_sess_info, 123, "TRACE_120717 closing at line %d in state %d", __LINE__, iec_state);
#endif // TRACE_120717

#ifdef B120709
    assert(!boc_wsp_closed); // should only be called once per session
    if (boc_htcp_closed) {
        dsd_htcp_conn_internal* adsl_hci = (dsd_htcp_conn_internal*)
            &ds_conn_internal;
        dsd_timer_ele* adsl_te = &adsl_hci->ds_timer.ds_te;
        m_time_rel(adsl_te);
        adsl_te = &adsl_hci->ds_da_timer.ds_te;
        m_time_rel(adsl_te);
        adsl_te = &dsc_timer;
        m_time_rel(adsl_te);
        m_htun_free_resources(adsc_sess_info);
        return;
    }
    boc_wsp_closed = true;
#endif // B120709

    switch (iec_state) {
    case ied_hs_connecting:
#ifndef B120703
        m_htun_warning(adsc_sess_info, 123,
                       "Closing HTCP session while connecting.");
        m_htun_htcp_connect_end(adsc_sess_info, -1);
        m_htun_htcp_free_target_ineta(adsc_sess_info,
            (dsd_target_ineta_1*)ds_target.ads_first_address - 1);
        // mc_session_end(0); // TODO: remove
        m_get_internal(&ds_connection)->m_reset();
        // m_reset() will cause m_htcp_cb_conn_closed() to be called for cleanup
#else // B120703
        m_htun_warning(adsc_sess_info, 123,
                       "Closing HTCP session while connecting.");
        m_htcp_conn_cleanup_wsp(&ds_connection);
        m_htun_htcp_free_target_ineta(adsc_sess_info,
            (dsd_target_ineta_1*)ds_target.ads_first_address - 1);
#ifdef B120213
        m_htun_session_end(adsc_sess_info, 0);
#else
        mc_session_end(0);
#endif
        {
            dsd_htcp_conn_internal* adsl_hci = (dsd_htcp_conn_internal*)
                &ds_conn_internal;
            dsd_timer_ele* adsl_te = &adsl_hci->ds_timer.ds_te;
            m_time_rel(adsl_te);
            adsl_te = &adsl_hci->ds_da_timer.ds_te;
            m_time_rel(adsl_te);
            adsl_te = &dsc_timer;
            m_time_rel(adsl_te);
        }
        m_htun_free_resources(adsc_sess_info);
#endif // B120703
        break;

    case ied_hs_connected:
        iec_state = ied_hs_fin_sent;
        // if remote end does not close within 30s, reset connection
        std::memset(&dsc_timer, 0, sizeof(dsc_timer));
#ifndef B120709
        dsc_timer.ilcwaitmsec = 1000;
#else // B120709
        dsc_timer.ilcwaitmsec = 30000;
#endif // B120709
        dsc_timer.amc_compl = &m_hs_cb_timer;
        m_time_set(&dsc_timer, FALSE);
        m_htcp_conn_close(&ds_connection); // send fin
        break;

    case ied_hs_fin_received:
#ifndef B120709
        // Race - m_htun_sess_close() and m_htun_htcp_session_end() called together.
        // So ignore m_htun_sess_close() here.
#else // B120709
        m_htun_warning(adsc_sess_info, 123,
                       "Warning: attempting to close HTCP session which was already being closed remotely.");
#endif // B120709
        break;

    case ied_hs_fin_sent:
        m_htun_warning(adsc_sess_info, 123,
                       "Error: closing HTCP session for the second time.");
        break;

    case ied_hs_closed_time_wait:
        m_htun_warning(adsc_sess_info, 123,
                       "Error: closing HTCP session for the second time.");
        break;

    case ied_hs_closed:
        m_htun_warning(adsc_sess_info, 123,
                       "Error: closing HTCP session which was already closed.");
        break;
    };
}

void dsd_htcp_session::m_try_next_address()
{
#ifdef TRACE_120717
    m_htun_warning(adsc_sess_info, 123, "TRACE_120717 trying an address at line %d", __LINE__);
#endif // TRACE_120717

    while (ds_target.in_remain) {
        if (ds_target.bo_round_robin) {
            // random order
            int in_next = m_get_random_number(ds_target.in_remain);
            uint32 um_mask = 1;
            int in_index = 0;
            for (; ; ) {
                // skip used
                while (!(ds_target.um_unused & um_mask)) {
                    um_mask <<= 1;
                    ++in_index;
                    assert(in_index <= ds_target.in_total);
                }

                if (!in_next)
                    break;
                --in_next;

                // skip this unused
                um_mask <<= 1;
                ++in_index;
                assert(in_index <= ds_target.in_total);
            }
            ds_target.um_unused ^= um_mask; // unset

            if (in_index < ds_target.in_current) {
                ds_target.in_current = 0;
                ds_target.ads_current_address = ds_target.ads_first_address;
            }

            while (ds_target.in_current < in_index) {
                ds_target.ads_current_address = (dsd_ineta_single_1*)
                    ((char*)(ds_target.ads_current_address + 1) +
                     ds_target.ads_current_address->usc_length);
                ++ds_target.in_current;
            }
        } else { // !ds_target.bo_round_robin
            if (ds_target.in_remain != ds_target.in_total) {
                ds_target.ads_current_address = (dsd_ineta_single_1*)
                    ((char*)(ds_target.ads_current_address + 1) +
                     ds_target.ads_current_address->usc_length);
                ++ds_target.in_current;
            }
        } // !ds_target.bo_round_robin

        --ds_target.in_remain;

        if (ds_target.ads_current_address->usc_family != AF_INET ||
            ds_target.ads_current_address->usc_length != 4) {
            // non-IPv4 connections not yet supported
            m_htun_warning(adsc_sess_info, 123,
                           "Error: HTCP only supports IPv4 connections.");
            m_htun_htcp_connect_failed(adsc_sess_info, 0, 0,
                                       ds_target.in_current,
                                       ds_target.in_total,
                                       -1);
            continue;
        }

        char* ach_addrp = (char*)(ds_target.ads_current_address + 1);
        uint32 um_addr = ach_addrp[0] & 0xff;
        um_addr <<= 8;
        um_addr |= ach_addrp[1] & 0xff;
        um_addr <<= 8;
        um_addr |= ach_addrp[2] & 0xff;
        um_addr <<= 8;
        um_addr |= ach_addrp[3] & 0xff;
        ds_connection.um_remote_addr = um_addr;

        m_htcp_connect_wsp(&ds_connection);
        return;
    }

    // all the connections failed
    m_htun_warning(adsc_sess_info, 123, "HTCP could not connect.");
#ifndef B120703
    m_htun_htcp_connect_end(adsc_sess_info, -1);
    m_htun_htcp_free_target_ineta(adsc_sess_info,
        (dsd_target_ineta_1*)ds_target.ads_first_address - 1);
    dsd_htcp_conn_internal* adsl_hci = (dsd_htcp_conn_internal*)
        &ds_conn_internal;
    dsd_timer_ele* adsl_te = &adsl_hci->ds_timer.ds_te;
    m_time_rel(adsl_te);
    adsl_te = &adsl_hci->ds_da_timer.ds_te;
    m_time_rel(adsl_te);
    adsl_te = &dsc_timer;
    m_time_rel(adsl_te);
#ifdef TRACE_120717
    m_htun_warning(adsc_sess_info, 123, "TRACE_120717 no good address found - line %d", __LINE__);
#endif // TRACE_120717
    m_htun_free_resources(adsc_sess_info);
#else // B120703
    m_htun_htcp_free_target_ineta(adsc_sess_info,
        (dsd_target_ineta_1*)ds_target.ads_first_address - 1);
    m_htun_htcp_connect_end(adsc_sess_info, -1);
#ifdef B120213
    m_htun_session_end(adsc_sess_info, -1);
#else // B120213
    mc_session_end(-1);
#endif // B120213
    dsd_htcp_conn_internal* adsl_hci = (dsd_htcp_conn_internal*)
        &ds_conn_internal;
    dsd_timer_ele* adsl_te = &adsl_hci->ds_timer.ds_te;
    m_time_rel(adsl_te);
    adsl_te = &adsl_hci->ds_da_timer.ds_te;
    m_time_rel(adsl_te);
    adsl_te = &dsc_timer;
    m_time_rel(adsl_te);
    m_htun_free_resources(adsc_sess_info);
#endif // B120703
}

int dsd_htcp_session::mc_interpret_msg(dsd_gather_i_1* ads_message,
                                       dsd_hco_wothr* adsp_hco_wothr)
{
#ifdef TRACE_120717_EXTRA
    m_htun_warning(adsc_sess_info, 123, "TRACE_120717 got data at line %d in state %d", __LINE__, iec_state);
#endif // TRACE_120717_EXTRA

    if (iec_state != ied_hs_connected) {
        m_htun_warning(adsc_sess_info, 123,
                      "m_htun_sess_send() called for session in invalid state");
        return 0;
    }

#ifdef HTCP_TRY_100819
    while (ads_output_gather &&
           ads_output_gather->achc_ginp_cur ==
           ads_output_gather->achc_ginp_end) {
        dsd_gather_i_1* ads_del = ads_output_gather;
        ads_output_gather = ads_output_gather->adsc_next;
        delete ads_del;
    }

    dsd_gather_i_1** aads_tail;
    unsigned un_len = 0;
    for (aads_tail = &ads_output_gather;
         *aads_tail;
         aads_tail = &(*aads_tail)->adsc_next) {
        un_len += (*aads_tail)->achc_ginp_end - (*aads_tail)->achc_ginp_cur;
    }
    assert(un_len <= um_output_gather_count);
    un_len = um_output_gather_count - un_len;
    um_output_gather_count -= un_len;

    while (un_len) {
        assert(ads_message);
        if (un_len < ads_message->achc_ginp_end - ads_message->achc_ginp_cur)
            break;
        un_len -= ads_message->achc_ginp_end - ads_message->achc_ginp_cur;
        dsd_gather_i_1* ads_del = ads_message;
        ads_message = ads_message->adsc_next;
        ads_del->achc_ginp_cur = ads_del->achc_ginp_end;
    }
    ads_message->achc_ginp_cur += un_len;

    un_len = um_output_gather_count;
    while (un_len) {
        assert(ads_message);
        if (un_len < ads_message->achc_ginp_end - ads_message->achc_ginp_cur)
            break;
        un_len -= ads_message->achc_ginp_end - ads_message->achc_ginp_cur;
        ads_message = ads_message->adsc_next;
    }
    while (ads_message) {
        *aads_tail = new dsd_gather_i_1;
        (*aads_tail)->achc_ginp_cur = ads_message->achc_ginp_cur + un_len;
        (*aads_tail)->achc_ginp_end = ads_message->achc_ginp_end;
        (*aads_tail)->adsc_next = 0;
        un_len = 0;
        um_output_gather_count +=
            (*aads_tail)->achc_ginp_end - (*aads_tail)->achc_ginp_cur;
        aads_tail = &(*aads_tail)->adsc_next;
        ads_message = ads_message->adsc_next;
    }

    ads_message = ads_output_gather;
#endif // HTCP_TRY_100819

    uint32 um_sent = m_htcp_conn_send(&ds_connection, ads_message);
    return 0;
}

int dsd_htcp_session::mc_encapsulate_msg(void* vp_handle,
                                         byte* aby_buffer, uint32 un_len)
{
    char* ach_buffer = reinterpret_cast<char*>(aby_buffer);
    tcp_segment ds_packet(reinterpret_cast<uint8*>(ach_buffer));

#ifdef TRACE_120717_EXTRA
    m_htun_warning(adsc_sess_info, 123, "TRACE_120717 got packet at line %d in state %d", __LINE__, iec_state);
#endif // TRACE_120717_EXTRA

    // basic ip sanity check
    if (!ds_packet.packet_ok(un_len)) {
        strcpy(chrc_last_error, "Invalid IP packet.");
        m_htun_relrecvbuf(vp_handle);
        return -1;
    }

    if (ds_packet.is_fragment()) {
        // TODO: reassembly
        m_htun_warning(adsc_sess_info, 123,
                       "HTCP does not yet support IP reassembly - fragment dropped.");
        m_htun_relrecvbuf(vp_handle);
        return -1;
    }

    if (ds_packet.protocol() == 1) {
        // TODO: HTCP does not yet support ICMP handling - packet dropped.
        m_htun_relrecvbuf(vp_handle);
        return -1;
    }

    // basic tcp sanity check (includes test if packet is actual tcp segment)
    if (!ds_packet.tcp_segment_ok()) {
        m_htun_warning(adsc_sess_info, 123, "Invalid TCP segment dropped.");
        m_htun_relrecvbuf(vp_handle);
        return -1;
    }

#ifdef B190309
    // check if this TCP segment should be received here
    if (ds_packet.source_address() != ds_connection.um_remote_addr ||
        ds_packet.source_port() != ds_connection.us_remote_port ||
        ds_packet.destination_address() != ds_connection.um_local_addr ||
        ds_packet.destination_port() != ds_connection.us_local_port) {
        strcpy(chrc_last_error, "Incorrectly routed TCP segment.");
        m_tun_relrecvbuf(vp_handle);
        return -1;
    }

    COUT2("********** htcp received: ", ds_packet);
    dsd_buf_vector_ele ds_vec =
        m_make_buf_vector_ele(vp_handle, ach_buffer, un_len);
    m_get_internal(&ds_connection)->m_process_segment(&ds_vec, 1);
    return 0;
#endif // B190309

    // check packet identification
    if (ds_packet.source_address() != ds_connection.um_remote_addr ||
        ds_packet.source_port() != ds_connection.us_remote_port ||
        ds_packet.destination_address() != ds_connection.um_local_addr ||
        ds_packet.destination_port() != ds_connection.us_local_port) {
        m_htun_warning(adsc_sess_info, 123, "Incorrectly routed TCP segment.");
        if (!ds_packet.rst()) {
            // send RST
            uint8* aut_rst_buffer = m_allocate_header();
            tcp_segment ds_rst_segment(aut_rst_buffer);
            ds_rst_segment.version() = 4;
            ds_rst_segment.header_length() = 5;
            ds_rst_segment.type_of_service() = 0;
            ds_rst_segment.total_length() = 40;
            ds_rst_segment.identification() = 0;
            ds_rst_segment.flags() = 0;
            ds_rst_segment.fragment_offset() = 0;
            ds_rst_segment.time_to_live() = 128;
            ds_rst_segment.protocol() = 6;
            ds_rst_segment.source_address() = ds_packet.destination_address();
            ds_rst_segment.destination_address() = ds_packet.source_address();
            ds_rst_segment.update_checksum();
            ds_rst_segment.source_port() = ds_packet.destination_port();
            ds_rst_segment.destination_port() = ds_packet.source_port();
            if (ds_packet.ack()) {
                ds_rst_segment.sequence_number() = ds_packet.acknowledgement_number();
            } else {
                ds_rst_segment.sequence_number() = 0;
            }
            ds_rst_segment.acknowledgement_number() = ds_packet.sequence_number();
            ds_rst_segment.tcp_header_length() = 5;
            ds_rst_segment.tcp_reserved() = 0;
            ds_rst_segment.tcp_flags() = 0;
            ds_rst_segment.ack() = 1;
            ds_rst_segment.rst() = 1;
            ds_rst_segment.window_size() = 0;
            ds_rst_segment.urgent_pointer() = 0;
            ds_rst_segment.update_tcp_checksum();
            m_send_packet(&ds_connection, dsd_send_packet_info(aut_rst_buffer, 40, 0, 0, 40));
        }
        m_htun_relrecvbuf(vp_handle);
        return -1;
    }

    dsd_buf_vector_ele ds_vec =
        m_make_buf_vector_ele(vp_handle, ach_buffer, un_len);
    m_get_internal(&ds_connection)->m_process_segment(&ds_vec, 1);
    return 0;
}

void dsd_htcp_session::mc_can_send()
{
    bool bol_warn1 = false;
    bool bol_warn2 = false;
    bool bol_do_send = false;

#ifdef TRACE_120717_EXTRA
    m_htun_warning(adsc_sess_info, 123, "TRACE_120717 can send at line %d in state %d", __LINE__, iec_state);
#endif // TRACE_120717_EXTRA

    m_htun_critsect_enter(adsc_sess_info);

    if (boc_sending) {
        bol_warn1 = !boc_cansend;

        boc_cansend = true;
        boc_cansend_again = true;
    } else { // !boc_sending
        bol_warn2 = boc_cansend;

        boc_cansend = true;
        boc_sending = true;
        boc_sending_try_again = false;
        boc_cansend_again = false;
        bol_do_send = true;
    }

    m_htun_critsect_leave(adsc_sess_info);

    if (bol_warn1) {
        m_htun_warning(adsc_sess_info, 123,
                       "m_htun_sess_cansend found boc_sending but !boc_cansend");
        return;
    }

    if (bol_warn2) {
        m_htun_warning(adsc_sess_info, 123,
                       "received extra m_htun_sess_cansend");
        return;
    }

    if (bol_do_send)
        mc_do_send();
}

void dsd_htcp_session::mc_do_send()
{
    dsd_htcp_conn* ads_conn = &this->ds_connection;

    const unsigned un_vec_count = 16;
    dsd_buf_vector_ele ds_buffers[un_vec_count];

    for (; ; ) {
        unsigned un_count = un_vec_count;
        m_htcp_conn_recv(ads_conn, ds_buffers, &un_count);
        while (un_count == 0) {
            bool bol_try;

            m_htun_critsect_enter(adsc_sess_info);
            bol_try = boc_sending_try_again;
            boc_sending_try_again = false;
            if (!bol_try) {
                boc_sending = false;
            }
            m_htun_critsect_leave(adsc_sess_info);

            if (bol_try) {
                un_count = un_vec_count;
                m_htcp_conn_recv(ads_conn, ds_buffers, &un_count);
            } else {
                return;
            }
        }

        if (!m_se_htun_recvbuf(adsc_sess_info, ds_buffers, un_count)) {
            bool bol_again;

            m_htun_critsect_enter(adsc_sess_info);
            bol_again = boc_cansend_again;
            boc_cansend_again = false;
            if (!bol_again) {
                boc_cansend = false;
                boc_sending = false;
            }
            m_htun_critsect_leave(adsc_sess_info);
            if (!bol_again)
                return;
        }

//        if (un_count < un_vec_count) {
//            // not all element spaces were used, so we have all data
//            break;
//        }
//
//        m_htcp_conn_recv(ads_conn, ds_buffers, &un_count);
    }
}

void m_hs_cb_timer(dsd_timer_ele* adsp_te)
{
    dsd_htcp_session* adsl_hs = (dsd_htcp_session*)
        ((char*)adsp_te - offsetof(dsd_htcp_session, dsc_timer));

#ifndef B120709
    m_htun_warning(adsl_hs->adsc_sess_info, 123,
                   "HTCP sent FIN, no FIN received - resetting session.");
    m_htcp_conn_reset(&adsl_hs->ds_connection);
    m_htcp_conn_cleanup_wsp(&adsl_hs->ds_connection);
    dsd_htcp_conn_internal* adsl_hci = (dsd_htcp_conn_internal*)
        &adsl_hs->ds_conn_internal;
    dsd_timer_ele* adsl_te = &adsl_hci->ds_timer.ds_te;
    m_time_rel(adsl_te);
    adsl_te = &adsl_hci->ds_da_timer.ds_te;
    m_time_rel(adsl_te);
    m_htun_free_resources(adsl_hs->adsc_sess_info);
#else // B120709
    adsl_hs->iec_state = ied_hs_closed;
    m_htun_warning(adsl_hs->adsc_sess_info, 123,
                   "HTCP sent FIN, no FIN received - resetting session.");
#ifdef B120213
    m_htun_session_end(adsl_hs->adsc_sess_info, -1);
#else
    adsl_hs->mc_session_end(-1);
#endif
    m_htcp_conn_reset(&adsl_hs->ds_connection);
#endif // B120709
}

void m_htcp_cb_connected(dsd_htcp_conn* ads_conn, int in_code)
{
    dsd_htcp_session* ads_hs = (dsd_htcp_session*)ads_conn->vp_user_data;
#ifdef TRACE_120717
    m_htun_warning(ads_hs->adsc_sess_info, 123, "TRACE_120717 connected at line %d", __LINE__);
#endif // TRACE_120717
    ads_hs->iec_state = ied_hs_connected;
    m_htun_htcp_free_target_ineta(ads_hs->adsc_sess_info,
        (dsd_target_ineta_1*)ads_hs->ds_target.ads_first_address - 1);
    m_htun_htcp_connect_end(ads_hs->adsc_sess_info, 0);
}

void m_htcp_cb_connection_failed(dsd_htcp_conn* ads_conn, int in_code)
{
    dsd_htcp_session* ads_hs = (dsd_htcp_session*)ads_conn->vp_user_data;
#ifdef TRACE_120717
    m_htun_warning(ads_hs->adsc_sess_info, 123, "TRACE_120717 connection failed at line %d", __LINE__);
#endif // TRACE_120717
    sockaddr_in ds_sa;
    memset(&ds_sa, 0, sizeof(ds_sa));
    ds_sa.sin_family = AF_INET;
    ds_sa.sin_addr.s_addr =htonl(ads_hs->ds_connection.um_remote_addr);
    ds_sa.sin_port = htons(ads_hs->ds_connection.us_remote_port);
    m_htun_htcp_connect_failed(ads_hs->adsc_sess_info,
                               (sockaddr*)&ds_sa, sizeof(ds_sa),
                               ads_hs->ds_target.in_current,
                               ads_hs->ds_target.in_total,
                               -1);
    ads_hs->m_try_next_address();
}

void m_htcp_cb_recv_data(dsd_htcp_conn* ads_conn, int in_code)
{
    dsd_htcp_session* adsl_hs = (dsd_htcp_session*)ads_conn->vp_user_data;

#ifdef TRACE_120717_EXTRA
    m_htun_warning(adsl_hs->adsc_sess_info, 123, "TRACE_120717 received data at line %d in state %d", __LINE__, adsl_hs->iec_state);
#endif // TRACE_120717_EXTRA

    switch (adsl_hs->iec_state) {
    case ied_hs_connecting:
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: HTCP received data on session which is not yet connected.");
        break;

    case ied_hs_connected:
        m_data_received(ads_conn);
        break;

    case ied_hs_fin_received:
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: HTCP received data after FIN.");
        break;

    case ied_hs_fin_sent:
        if (m_time_rel(&adsl_hs->dsc_timer)) {
#ifdef B120717
            adsl_hs->iec_state = ied_hs_closed;
#endif // B120717
            m_htun_warning(adsl_hs->adsc_sess_info, 123,
                           "HTCP received data after sending FIN - half-close not supported, so sending RST.");
#ifdef B120717
#ifdef B120213
            m_htun_session_end(adsl_hs->adsc_sess_info, -1);
#else // B120213
            adsl_hs->mc_session_end(-1);
#endif // B120213
#endif // B120717
            m_htcp_conn_reset(&adsl_hs->ds_connection);
            // m_reset() will cause m_htcp_cb_conn_closed(),
            // m_htcp_cb_conn_closed() will attempt to free timer
            // and on failing will exit quietly,
            // so cleanup done here

            m_htcp_conn_cleanup_wsp(&adsl_hs->ds_connection);
            dsd_htcp_conn_internal* adsl_hci = (dsd_htcp_conn_internal*)
                &adsl_hs->ds_conn_internal;
            dsd_timer_ele* adsl_te = &adsl_hci->ds_timer.ds_te;
            m_time_rel(adsl_te);
            adsl_te = &adsl_hci->ds_da_timer.ds_te;
            m_time_rel(adsl_te);
            m_htun_free_resources(adsl_hs->adsc_sess_info);
        }
        break;

    case ied_hs_closed_time_wait:
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: HTCP received data on closed session in TIME_WAIT state.");
        break;

    case ied_hs_closed:
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: HTCP received data on closed session.");
        break;
    };
}

void m_htcp_cb_data_acked(dsd_htcp_conn* ads_conn, int in_code)
{
    dsd_htcp_session* adsl_hs = (dsd_htcp_session*)ads_conn->vp_user_data;
#ifdef TRACE_120717_EXTRA
    m_htun_warning(adsl_hs->adsc_sess_info, 123, "TRACE_120717 data acknowledged at line %d in state %d", __LINE__, adsl_hs->iec_state);
#endif // TRACE_120717_EXTRA
    m_htun_htcp_send_complete(adsl_hs->adsc_sess_info);
    // TODO: is there a way to tell WSP which data is ACKED?
}

void m_htcp_cb_recv_eof(dsd_htcp_conn* ads_conn, int in_code)
{
    dsd_htcp_session* adsl_hs = (dsd_htcp_session*)ads_conn->vp_user_data;

#ifdef TRACE_120717
    m_htun_warning(adsl_hs->adsc_sess_info, 123, "TRACE_120717 received EOF at line %d in state %d", __LINE__, adsl_hs->iec_state);
#endif // TRACE_120717

    switch (adsl_hs->iec_state) {
    case ied_hs_connecting: {
        adsl_hs->iec_state = ied_hs_closed;
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: FIN callback in HTCP session while connecting.");

        m_htcp_cb_connection_failed(ads_conn, in_code);
        break;
    }

    case ied_hs_connected:
        adsl_hs->iec_state = ied_hs_fin_received;
        m_htcp_conn_close(&adsl_hs->ds_connection); // send FIN back
        // m_htun_session_end() will be called when last ACK is received
        break;

    case ied_hs_fin_received:
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: HTCP called FIN callback twice.");
        break;

    case ied_hs_fin_sent:
        // m_htcp_conn_close() already called
        // now wait for m_htcp_cb_conn_closed() after TIME_WAIT
        adsl_hs->iec_state = ied_hs_closed_time_wait;
#ifndef B120709
        // timer release attempt should be in m_htcp_cb_conn_closed()
#else // B120709
        if (m_time_rel(&adsl_hs->dsc_timer)) {
#ifdef B120213
            m_htun_session_end(adsl_hs->adsc_sess_info, 0);
#else
            adsl_hs->mc_session_end(0);
#endif
        }
#endif // B120709
        break;

    case ied_hs_closed_time_wait:
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: HTCP called FIN callback while in TIME_WAIT state.");
        break;

    case ied_hs_closed:
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: HTCP called FIN callback after session closed.");
        break;
    };
}

void m_htcp_cb_conn_reset(dsd_htcp_conn* ads_conn, int in_code)
{
    dsd_htcp_session* adsl_hs = (dsd_htcp_session*)ads_conn->vp_user_data;

#ifdef TRACE_120717
    m_htun_warning(adsl_hs->adsc_sess_info, 123, "TRACE_120717 received reset at line %d in state %d", __LINE__, adsl_hs->iec_state);
#endif // TRACE_120717

    switch (adsl_hs->iec_state) {
    case ied_hs_connecting:
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: HTCP sent RST callback instead of \"connection refused\".");
        m_htcp_cb_connection_failed(ads_conn, in_code);
        break;

    case ied_hs_connected:
        adsl_hs->iec_state = ied_hs_closed;
#ifdef B120709
#ifdef B120213
        m_htun_session_end(adsl_hs->adsc_sess_info, -1);
#else
        adsl_hs->mc_session_end(-1);
#endif
#endif // B120709
        break;

    case ied_hs_fin_received:
        adsl_hs->iec_state = ied_hs_closed;
        // change state from ied_hs_fin_received so m_htun_session_end() is called with error
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "HTCP received RST after receiving FIN.");
#ifdef B120709
#ifdef B120213
        m_htun_session_end(adsl_hs->adsc_sess_info, -1);
#else
        adsl_hs->mc_session_end(-1);
#endif
#endif // B120709
        break;

    case ied_hs_fin_sent:
#ifndef B120709
        // timer release attempt should be in m_htcp_cb_conn_closed()
        // WARNING: do not change state from ied_hs_fin_sent - otherwise timer will not be released.
#else // B120709
        if (m_time_rel(&adsl_hs->dsc_timer)) {
            adsl_hs->iec_state = ied_hs_closed;
            m_htun_warning(adsl_hs->adsc_sess_info, 123,
                           "HTCP received RST after sending FIN.");
#ifdef B120213
            m_htun_session_end(adsl_hs->adsc_sess_info, -1);
#else
            adsl_hs->mc_session_end(-1);
#endif
        }
#endif // B120709
        break;

    case ied_hs_closed_time_wait:
#ifdef B120717
        adsl_hs->iec_state = ied_hs_closed;
#endif
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Warning: HTCP received RST during TIME_WAIT.");
        break;

    case ied_hs_closed:
        m_htun_warning(adsl_hs->adsc_sess_info, 123,
                       "Error: HTCP called RST callback for closed session.");
        break;
    };

    // m_htcp_cb_conn_closed() will still be called
}

void m_htcp_cb_conn_closed(dsd_htcp_conn* ads_conn, int in_code)
{
    dsd_htcp_session* adsl_hs = (dsd_htcp_session*)ads_conn->vp_user_data;

#ifdef TRACE_120717
    m_htun_warning(adsl_hs->adsc_sess_info, 123, "TRACE_120717 HTCP closed at line %d in state %d", __LINE__, adsl_hs->iec_state);
#endif // TRACE_120717

#ifndef B120709

    if (adsl_hs->iec_state == ied_hs_fin_sent ||
        adsl_hs->iec_state == ied_hs_closed_time_wait) {

        if (!m_time_rel(&adsl_hs->dsc_timer)) {
            // cleanup already being done by timeout
#ifdef TRACE_120717
            m_htun_warning(adsl_hs->adsc_sess_info, 123, "TRACE_120717 detected timeout trigger at line %d", __LINE__);
#endif // TRACE_120717
            return;
        }
        // adsl_hs->mc_session_end(0); // TODO: remove
    } else if (adsl_hs->iec_state == ied_hs_fin_received) {
        adsl_hs->mc_session_end(0);
    }else {
        adsl_hs->mc_session_end(-1);
    }

    m_htcp_conn_cleanup_wsp(ads_conn);
    dsd_htcp_conn_internal* adsl_hci = (dsd_htcp_conn_internal*)
        &adsl_hs->ds_conn_internal;
    dsd_timer_ele* adsl_te = &adsl_hci->ds_timer.ds_te;
    m_time_rel(adsl_te);
    adsl_te = &adsl_hci->ds_da_timer.ds_te;
    m_time_rel(adsl_te);
    m_htun_free_resources(adsl_hs->adsc_sess_info);

#else // B120709

    assert(!adsl_hs->boc_htcp_closed); // should only be called once per session

    // after receiving FIN and sending FIN, session ends on receiving last ACK
    if (adsl_hs->iec_state == ied_hs_fin_received) {
#ifdef B120213
        m_htun_session_end(adsl_hs->adsc_sess_info, 0);
#else
        adsl_hs->mc_session_end(0);
#endif
    }

    // if clean closing, still need to clean up
    m_htcp_conn_cleanup_wsp(ads_conn);

    adsl_hs->boc_sess_closed = TRUE;
    adsl_hs->~dsd_htcp_session();

    if (adsl_hs->boc_wsp_closed) {
        dsd_htcp_conn_internal* adsl_hci = (dsd_htcp_conn_internal*)
            &adsl_hs->ds_conn_internal;
        dsd_timer_ele* adsl_te = &adsl_hci->ds_timer.ds_te;
        m_time_rel(adsl_te);
        adsl_te = &adsl_hci->ds_da_timer.ds_te;
        m_time_rel(adsl_te);
        adsl_te = &adsl_hs->dsc_timer;
        m_time_rel(adsl_te);
        m_htun_free_resources(adsl_hs->adsc_sess_info);
        return;
    }
    adsl_hs->boc_htcp_closed = true;

#endif // B120709
}

void m_send_packet(dsd_htcp_conn* ads_conn, dsd_send_packet_info& ds_packet)
{
    unsigned un_len = ds_packet.un_total_len;
    unsigned un_l = ds_packet.un_head_len;
    assert(un_len < 65536);
    assert(un_l <= un_len);

    if (un_len == un_l) {
        m_se_husip_send(ds_packet.aby_header, un_l);
    } else {
        unsigned char byr_buffer[65535];
        unsigned char* aby_bufferp = byr_buffer;
        memcpy(aby_bufferp, ds_packet.aby_header, un_l);
        aby_bufferp += un_l;
        un_len -= un_l;

        dsd_gather_i_1* ads_g = ds_packet.ads_payload;
        char* ach_gcur = ds_packet.ach_plstart;
        while(un_len) {
            assert(ads_g);

            un_l = ads_g->achc_ginp_end - ach_gcur;
            if (un_l > un_len)
                un_l = un_len;
            memcpy(aby_bufferp, ach_gcur, un_l);
            aby_bufferp += un_l;
            un_len -= un_l;
            ads_g = ads_g->adsc_next;
            if (ads_g)
                ach_gcur = ads_g->achc_ginp_cur;
        }
        m_se_husip_send(byr_buffer, ds_packet.un_total_len);
    }

    m_deallocate_header(ds_packet.aby_header);
}

void m_send_packets(dsd_htcp_conn* ads_conn,
                    std::list<dsd_send_packet_info>& ds_packets)
{
    std::list<dsd_send_packet_info>::iterator dsl_iter;
    for (dsl_iter = ds_packets.begin();
         dsl_iter != ds_packets.end();
         ++dsl_iter) {
        m_send_packet(ads_conn, *dsl_iter);
    }
}

void m_data_received(dsd_htcp_conn* ads_conn)
{
    dsd_htcp_session* ads_hs = (dsd_htcp_session*) (ads_conn->vp_user_data);

#ifdef TRACE_120717_EXTRA
    m_htun_warning(ads_hs->adsc_sess_info, 123, "TRACE_120717 sending data at line %d in state %d", __LINE__, ads_hs->iec_state);
#endif // TRACE_120717_EXTRA

    bool bol_do_send = false;

    m_htun_critsect_enter(ads_hs->adsc_sess_info);
    if (ads_hs->boc_cansend) {
        if (ads_hs->boc_sending) {
            ads_hs->boc_sending_try_again = true;
        } else {
            ads_hs->boc_sending = true;
            ads_hs->boc_sending_try_again = false;
            ads_hs->boc_cansend_again = false;
            bol_do_send = true;
        }
    }
    m_htun_critsect_leave(ads_hs->adsc_sess_info);

    if (bol_do_send) {
        ads_hs->mc_do_send();
    }
}

#ifdef B100721 // HTCP used to send data to TUN and WSP on workthreads

// Sending packets to the tun interface

dsd_mutex_lock ds_output_queue_lock;
bool bo_output_queue_servicing = false;
std::list<dsd_send_packet_info> ds_output_queue;

void m_wt_send_task(struct dsd_hco_wothr* ads_wt,
                    void* vp_p0, void* vp_p1, void* vp_p2)
{
    std::list<dsd_send_packet_info> ds_packets;

    m_hco_wothr_blocking(ads_wt);

    dsd_mutex_locker ds_locker(&ds_output_queue_lock);

    ds_packets.swap(ds_output_queue);
    while (!ds_packets.empty()) {
        ds_locker.m_reset();
        while (!ds_packets.empty()) {
            dsd_send_packet_info& ds_info = ds_packets.front();

            unsigned un_len = ds_info.un_total_len;
            unsigned un_l = ds_info.un_head_len;
            assert(un_len < 65536);
            assert(un_l <= un_len);

            if (un_l) { // HTCP
            unsigned char byr_buffer[65535];
            unsigned char* aby_bufferp = byr_buffer;
            memcpy(aby_bufferp, ds_info.aby_header, un_l);
            aby_bufferp += un_l;
            un_len -= un_l;

            dsd_gather_i_1* ads_g = ds_info.ads_payload;
            char* ach_gcur = ds_info.ach_plstart;
            while(un_len) {
                assert(ads_g);

                un_l = ads_g->achc_ginp_end - ach_gcur;
                if (un_l > un_len)
                    un_l = un_len;
                memcpy(aby_bufferp, ach_gcur, un_l);
                aby_bufferp += un_l;
                un_len -= un_l;
                ads_g = ads_g->adsc_next;
                if (ads_g)
                    ach_gcur = ads_g->achc_ginp_cur;
            }
            m_se_husip_send(byr_buffer, ds_info.un_total_len);

            m_deallocate_header(ds_info.aby_header);
            } else { // PPP
                assert(ds_info.aby_header == 0);
                assert(ds_info.ads_payload == 0);
                byte* aby_buf = (byte*)ds_info.ach_plstart;
                m_se_husip_send(aby_buf, ds_info.un_total_len);
                delete[] aby_buf;
            }

            ds_packets.pop_front();
        }
        ds_locker.m_reset(&ds_output_queue_lock);
        ds_packets.swap(ds_output_queue);
    }

    bo_output_queue_servicing = false;

    // no need to call because exiting from work thread
    // m_hco_wothr_active(ads_wt);
}

void m_send_packet(dsd_htcp_conn* ads_conn, dsd_send_packet_info& ds_packet)
{
    dsd_mutex_locker ds_locker(&ds_output_queue_lock);
    ds_output_queue.push_back(ds_packet);
    if (bo_output_queue_servicing)
        return;
    bo_output_queue_servicing = true;
    ds_locker.m_reset();

    dsd_call_para_1 ds_para;

    ds_para.amc_function = &m_wt_send_task;
    ds_para.ac_param_1 = 0;
    ds_para.ac_param_2 = 0;
    ds_para.ac_param_3 = 0;

    // TODO: confirm ds_para can be temporary
    m_hco_run_thread(&ds_para);
}

void m_send_packets(dsd_htcp_conn* ads_conn,
                    std::list<dsd_send_packet_info>& ds_packets)
{
    dsd_mutex_locker ds_locker(&ds_output_queue_lock);
    ds_output_queue.splice(ds_output_queue.end(), ds_packets);
    if (bo_output_queue_servicing)
        return;
    bo_output_queue_servicing = true;
    ds_locker.m_reset();

    dsd_call_para_1 ds_para;
    ds_para.amc_function = &m_wt_send_task;
    ds_para.ac_param_1 = 0;
    ds_para.ac_param_2 = 0;
    ds_para.ac_param_3 = 0;
    // TODO: confirm ds_para can be temporary
    m_hco_run_thread(&ds_para);
}

void m_send_packet(char* ach_buffer, int in_len)
{
    dsd_mutex_locker ds_locker(&ds_output_queue_lock);
    dsd_send_packet_info ds_info((uint8*)ach_buffer, in_len, 0, 0, in_len);
    ds_output_queue.push_back(ds_info);
    if (bo_output_queue_servicing)
        return;
    bo_output_queue_servicing = true;
    ds_locker.m_reset();

    dsd_call_para_1 ds_para;

    ds_para.amc_function = &m_wt_send_task;
    ds_para.ac_param_1 = 0;
    ds_para.ac_param_2 = 0;
    ds_para.ac_param_3 = 0;

    // TODO: confirm ds_para can be temporary
    m_hco_run_thread(&ds_para);
}

// Sending the received data to WSP

void m_wt_recv_task(struct dsd_hco_wothr* ads_wt,
                    void* vp_p0, void* vp_p1, void* vp_p2)
{
    dsd_htcp_session* ads_hs = (dsd_htcp_session*) vp_p0;
    dsd_htcp_recv_data* ads_rdata = &ads_hs->ds_rdata;
    dsd_tun_contr1* ads_tc = ads_hs->adsc_sess_info;

    std::list<dsd_buf_vector_ele> ds_data;

    dsd_mutex_locker ds_locker(&ads_rdata->ds_lock);
    ds_data.swap(ads_rdata->ds_data);
    while (!ds_data.empty()) {
        ds_locker.m_reset();
        while (!ds_data.empty()) {
            m_hco_wothr_blocking(ads_wt);
#if defined WIN32 || defined WIN64
            WaitForSingleObject(ads_hs->dsc_eve_cansend, INFINITE);
#endif
            m_hco_wothr_active(ads_wt);
            bool bo_more = m_se_htun_recvbuf(ads_tc, &ds_data.front(), 1);
            ds_data.pop_front();
            while (bo_more && !ds_data.empty()) {
                bo_more = m_se_htun_recvbuf(ads_tc, &ds_data.front(), 1);
                ds_data.pop_front();
            }
#if defined WIN32 || defined WIN64
            if (!bo_more)
                ResetEvent(ads_hs->dsc_eve_cansend);
#endif
        }
        ds_locker.m_reset(&ads_rdata->ds_lock);
        ds_data.swap(ads_rdata->ds_data);
    }
    ads_rdata->bo_servicing = false;
}

void m_data_received(dsd_htcp_conn* ads_conn)
{
    dsd_htcp_session* ads_hs = (dsd_htcp_session*) (ads_conn->vp_user_data);
    dsd_htcp_recv_data* ads_rdata = &ads_hs->ds_rdata;
    dsd_mutex_locker ds_locker(&ads_rdata->ds_lock);

    const unsigned un_vec_count = 10;

    dsd_buf_vector_ele ds_buffers[un_vec_count];
    unsigned un_count = un_vec_count;
    m_htcp_conn_recv(ads_conn, ds_buffers, &un_count);
    while (un_count) {
        for (unsigned un_i = 0; un_i < un_count; ++un_i)
            ads_rdata->ds_data.push_back(ds_buffers[un_i]);
        un_count = un_vec_count;
        m_htcp_conn_recv(ads_conn, ds_buffers, &un_count);
    }

    if (ads_rdata->bo_servicing)
        return;

    ads_rdata->bo_servicing = true;
    ds_locker.m_reset();

    dsd_call_para_1 ds_para;
    ds_para.amc_function = &m_wt_recv_task;
    ds_para.ac_param_1 = ads_hs;
    ds_para.ac_param_2 = 0;
    ds_para.ac_param_3 = 0;
    // TODO: confirm ds_para can be temporary
    m_hco_run_thread(&ds_para);
}
#endif // B100721
