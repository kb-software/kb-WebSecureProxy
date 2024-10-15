/******************************************************************************
 * File name: connection.cpp
 *
 * Implementation for htcp.h and connection.h
 *
 * Requires C++.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/

#define DEF_TIME_WAIT_SHORT /* MJ 03.02.2012    workaround for close problems */

#ifdef COUT_LOG
#include <iostream>
#endif

// required for hob-tun01.h
#ifdef HL_UNIX
#include "hob-hunix01.h"
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include <cstring>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <cassert>

#include "hob-xslcontr.h"

#ifdef B090317
#include "int_types.h"
#include "misc.h"
#include "tcpip_hdr.h"
#include "htcp.h"
#include "hob-avl03.h"
#include "connection.h"
#include "htcp_session.h"
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

#ifdef EXTRA_VERBOSE
#include <sstream>
extern "C" int m_hlnew_printf( int imp_type, char *aptext, ... );
#define COUT1(par1) \
{ \
    std::ostringstream _oss; \
    _oss << (par1); \
    m_hlnew_printf(0, "%s", _oss.str().c_str()); \
}
#define COUT2(par1, par2) \
{ \
    std::ostringstream _oss; \
    _oss << (par1) << (par2); \
    m_hlnew_printf(0, "%s", _oss.str().c_str()); \
}
#endif

void m_htcp_connect(dsd_htcp_conn* ads_conn)
{
    // dsd_htcp_conn_internal constructor initializes connection variables
    dsd_htcp_conn_internal* ads_ci =
        new dsd_htcp_conn_internal(ads_conn);

    ads_conn->vp_internal = ads_ci;
    ads_ci->m_active_open();
}

void m_htcp_conn_accept(dsd_htcp_conn* ads_conn)
{
    m_get_internal(ads_conn)->m_accept();
}

void m_htcp_conn_refuse(dsd_htcp_conn* ads_conn)
{
    m_get_internal(ads_conn)->m_reset();
}

uint32 m_htcp_conn_send(dsd_htcp_conn* ads_conn, dsd_gather_i_1* ads_data)
{
    return m_get_internal(ads_conn)->m_send(ads_data);
}

uint32 m_htcp_conn_recv(dsd_htcp_conn* ads_conn,
                        dsd_buf_vector_ele* ads_vec,
                        unsigned* aun_count)
{
    return m_get_internal(ads_conn)->m_recv(ads_vec, aun_count);
}

void m_htcp_conn_close(dsd_htcp_conn* ads_conn)
{
    m_get_internal(ads_conn)->m_close();
}

void m_htcp_conn_reset(dsd_htcp_conn* ads_conn)
{
    m_get_internal(ads_conn)->m_reset();
}

void m_htcp_conn_cleanup(dsd_htcp_conn* ads_conn)
{
    dsd_htcp_conn_internal* ads_ci = m_get_internal(ads_conn);
    ads_ci->m_reset();
    delete ads_ci;
    ads_conn->vp_internal = 0;
}

dsd_htcp_conn_internal::dsd_htcp_conn_internal(dsd_htcp_conn* ads_c)
    : ads_connection(ads_c)
{
    m_construct(false);
}

dsd_htcp_conn_internal::dsd_htcp_conn_internal(dsd_htcp_conn* ads_c,
                                               tcp_segment& ds_synseg)
    : ads_connection(ads_c)
{
    m_construct(true, &ds_synseg);
}

void m_check_syn_options(tcp_segment& ds_segment,
                         uint32& um_snd_smss,
                         bool& bo_sack,
                         bool& bo_winscale, uint32& um_snd_winscale,
                         bool& bo_timestamp, uint32& um_ts)
{
    // defaults
    // um_snd_smss is already set to default
    bo_sack = false;
    bo_winscale = false;
    um_snd_winscale = 0;
    bo_timestamp = false;
    um_ts = 0;

    tcp_options ds_options(ds_segment);
    while (!ds_options.end_of_options()) {
        switch (ds_options.option_type()) {
        case 2: // mss
            if (ds_options.option_length() == 4)
                um_snd_smss = (ds_options.option()[2] << 8) +
                    ds_options.option()[3];
            break;
        case 3: // window size shift bits
            if (ds_options.option_length() == 3) {
                um_snd_winscale = ds_options.option()[2];
                bo_winscale = true;
                if (um_snd_winscale > 14)
                    um_snd_winscale = 14;
            }
            break;
        case 4: // allow SACK
            if (ds_options.option_length() == 2) {
                bo_sack = true;
            }
            break;
        case 8: // use timestamps
            if (ds_options.option_length() == 10) {
                bo_timestamp = true;
                um_ts = bit_reference<const uint8*, 0, 32>
                    (ds_options.option() + 2);
            }
        }
        ds_options.goto_next_option();
    }
}

void dsd_htcp_conn_internal::m_construct(bool bo_received,
                                         tcp_segment* ads_synseg)
{
    ie_state = bo_received ? ied_htcp_listen : ied_htcp_syn_sent;
    bo_closed_by_app = false;

    ads_output_gather = 0;
#ifdef B100819
    um_output_gather_remove = 0;
#endif // B100819

    um_input_buffer_size = 0;

    bo_oo_fin_received = false;

    um_snd_iss = m_random32();
    um_snd_una = um_snd_iss;
    um_snd_nxt = um_snd_iss;
    um_snd_wnd = 0;
    um_snd_smss = um_out_mss;

    uint32 um_irs = bo_received ? uint32(ads_synseg->sequence_number()) : 0;
    um_rcv_nxt = bo_received ? um_irs + 1 : 0;
    um_last_ack_sent = um_rcv_nxt;
    um_rcv_wnd = um_in_bufsize;
    um_rcv_irs = bo_received ? um_irs : 0;
    um_rcv_rmss = um_in_mss;
    um_rcv_reduction = 0;

    uint32 um_maxwin = 65535;
    for (um_rcv_winscale = 0; um_rcv_winscale < 14; ++um_rcv_winscale) {
        if ((um_maxwin << um_rcv_winscale) >= um_in_bufsize)
            break;
        um_maxwin <<= 1;
    }

    if (bo_received) {
        m_check_syn_options(*ads_synseg, um_snd_smss, bo_use_sack,
                            bo_use_winscale, um_snd_winscale,
                            bo_use_timestamp, um_ts_recent);
        if (!bo_use_winscale)
            um_rcv_winscale = 0;
        if (bo_use_timestamp)
            um_snd_smss -= 12;
    } else {
        bo_use_sack = true;
        bo_use_winscale = true;
        um_snd_winscale = 0;
        // timestamp option will be sent in syn
        // then if timestamp option is in synack bo_use_timestamp set to true
        // bo_use_timestamp should be false here to start timing
        bo_use_timestamp = false;
        um_ts_recent = 0;
        im_recent_age_s = m_monotonic_time().m_in_s() + 0x80000000; // invalid
    }

    m_rto_init();

    am_cc_fun = m_cc_reno;
    m_cc_init();
    if (bo_received) {
        // TODO : place in cc_init
        um_cwnd = (std::min)(4 * um_snd_smss,
                             (std::max)(2 * um_snd_smss, 4380U));
    }
    um_dack = 0;
    bo_recovering = false;
    um_sack_data_size = 0;
    um_recover = um_snd_iss;
    um_exp_backoff = 1;

    ads_connection->um_send_pend = 0;
    ads_connection->um_recv_avail = 0;

    ds_timer.ads_ci = this;
    std::memset(&ds_timer.ds_te, 0, sizeof(ds_timer.ds_te));
    //    bo_timer_on = false;
    ds_da_timer.ads_ci = this;
    std::memset(&ds_da_timer.ds_te, 0, sizeof(ds_da_timer.ds_te));
    ds_da_timer.ds_te.ilcwaitmsec = um_delay_ack_ms;
    ds_da_timer.ds_te.amc_compl = &m_hc_da_timer_callback;
    //    bo_da_timer_on = false;
}

uint32 dsd_htcp_conn_internal::m_calc_win(uint32 um_w)
{
    um_w >>= um_rcv_winscale;
    if (um_w > 65535)
        um_w = 65535;
    return um_w;
}

uint32 dsd_htcp_conn_internal::m_decode_win(uint32 um_w)
{
    um_w <<= um_snd_winscale;
    return um_w;
}

dsd_htcp_conn_internal::~dsd_htcp_conn_internal()
{
    // lock to allow any running function which has lock to return cleanly
    dsd_mutex_locker ds_locker(&ds_lock);

    m_stop_timer();
    m_stop_da_timer();

    // discard output buffer
    /*
    // instead of code below, caller application should clear its gather buffers
    while (ads_output_gather != 0) {
        ads_output_gather->achc_ginp_cur = ads_output_gather->achc_ginp_end;
        ads_output_gather = ads_output_gather->adsc_next;
    }
    */
    ads_connection->um_send_pend = 0;

    // discard input buffer
    dsd_input_buffer_iterator ds_iter = ds_input_buffer.begin();
    while (ds_iter != ds_input_buffer.end()) {
        m_htun_relrecvbuf(ds_iter->ac_handle);
        ++ds_iter;
    }

    // discard oo buffer
    dsd_oobuffer_iterator ds_ooiter = ds_oobuffer.begin();
    while (ds_ooiter != ds_oobuffer.end()) {
        m_htun_relrecvbuf(ds_ooiter->ds_ve.ac_handle);
        ++ds_ooiter;
    }
}

uint32 dsd_htcp_conn_internal::m_send(dsd_gather_i_1* ads_data)
{
    // lock on connection
    dsd_mutex_locker ds_locker(&ds_lock);

#ifdef B100819
    // remove acknowledged data
    if (um_output_gather_remove > 0) {
        assert(ads_data);
        unsigned un_len = ads_data->achc_ginp_end - ads_data->achc_ginp_cur;
        while (um_output_gather_remove > un_len) {
            ads_data->achc_ginp_cur = ads_data->achc_ginp_end;
            um_output_gather_remove -= un_len;
            ads_data = ads_data->adsc_next;
            if (ads_data) {
                un_len = ads_data->achc_ginp_end - ads_data->achc_ginp_cur;
            } else {
                assert(um_output_gather_remove == 0);
            }
        }
        if (um_output_gather_remove > 0) {
            ads_data->achc_ginp_cur += um_output_gather_remove;
            um_output_gather_remove = 0;
        }
    }

    // skip over data we already have
    uint32 um_skip = ads_connection->um_send_pend;
    if (um_skip > 0) {
        assert(ads_data);
        unsigned un_len = ads_data->achc_ginp_end - ads_data->achc_ginp_cur;
        while (um_skip > un_len) {
            um_skip -= un_len;
            ads_data = ads_data->adsc_next;
            if (ads_data) {
                un_len = ads_data->achc_ginp_end - ads_data->achc_ginp_cur;
            } else {
                assert(um_skip == 0);
                return 0;
            }
        }
    }
#endif

    switch (ie_state) {

    case ied_htcp_syn_sent:
    case ied_htcp_syn_rcvd:
    case ied_htcp_established:
    case ied_htcp_close_wait:
        {
#ifdef B100829
            uint32 um_len = 0;
            // copy gather information which references data
            dsd_gather_i_1** aads_glink = 0;
            if (!ds_output_gather.empty())
                aads_glink = &ds_output_gather.back().adsc_next;
            ds_output_gather.push_back(*ads_data);
            ads_data = &ds_output_gather.back();
            ads_data->achc_ginp_cur += um_skip;
            um_len += ads_data->achc_ginp_end - ads_data->achc_ginp_cur;
            if (aads_glink)
                *aads_glink = ads_data;
            aads_glink = &ads_data->adsc_next;
            ads_data = ads_data->adsc_next;
            while (ads_data) {
                ds_output_gather.push_back(*ads_data);
                ads_data = &ds_output_gather.back();
                um_len += ads_data->achc_ginp_end - ads_data->achc_ginp_cur;
                *aads_glink = ads_data;
                aads_glink = &ads_data->adsc_next;
                ads_data = ads_data->adsc_next;
            }
#endif // B100829

            uint32 um_len = 0;
            if (ads_connection->um_send_pend == 0) {
                if (!ads_data) {
                    assert(ads_output_gather == 0);
                    return 0;
                }
                ads_output_gather = ads_data;
                ads_output_gather_tail = ads_data;
                um_len = ads_output_gather_tail->achc_ginp_end -
                    ads_output_gather_tail->achc_ginp_cur;
            } else {
                // TODO: maybe assert gather structures consistent
                assert(ads_data);
                assert(ads_output_gather != 0 && 
                       ads_output_gather_tail != 0 &&
                       ads_output_gather_tail_end != 0);
                if (ads_output_gather_tail_end !=
                    ads_output_gather_tail->achc_ginp_end) {
                    um_len = ads_output_gather_tail->achc_ginp_end -
                        ads_output_gather_tail_end;
                }
            }
            while (ads_output_gather_tail->adsc_next) {
                ads_output_gather_tail = ads_output_gather_tail->adsc_next;
                um_len += ads_output_gather_tail->achc_ginp_end -
                    ads_output_gather_tail->achc_ginp_cur;
            }
            ads_output_gather_tail_end = ads_output_gather_tail->achc_ginp_end;

            ads_connection->um_send_pend += um_len;

            if (ie_state == ied_htcp_syn_sent || ie_state == ied_htcp_syn_rcvd)
                return um_len;
            m_send_available();
            return um_len;
        }

    case ied_htcp_fin_wait_1:
    case ied_htcp_fin_wait_2:
    case ied_htcp_closing:
    case ied_htcp_time_wait:
    case ied_htcp_last_ack:
        return 0;

    case ied_htcp_closed:
#ifdef COUT_LOG
        std::cout << "attempting to send data on closed connection"
                  << std::endl;
#endif
        return 0;

    case ied_htcp_listen:
#ifdef COUT_LOG
        std::cout << "attempting to send data before accepting" << std::endl;
#endif
        return 0;

    default:
        // should not arrive here
        assert(false);
        return 0;
    }
}

uint32 dsd_htcp_conn_internal::m_recv(dsd_buf_vector_ele* ads_vec,
                                      unsigned* aun_count)
{
    // lock on connection
    dsd_mutex_locker ds_locker(&ds_lock);

    switch (ie_state) {

    case ied_htcp_syn_sent:
    case ied_htcp_syn_rcvd:
        // no data yet available
        *aun_count = 0;
        return 0;

    case ied_htcp_established:
    case ied_htcp_fin_wait_1:
    case ied_htcp_fin_wait_2:
    case ied_htcp_closing:
    case ied_htcp_time_wait:
    case ied_htcp_close_wait:
    case ied_htcp_last_ack:
        {
            uint32 um_len = 0;
            unsigned un_i;
            for (un_i = 0; un_i < *aun_count; ++un_i) {
                if (ds_input_buffer.begin() == ds_input_buffer.end())
                    break;
                ads_vec[un_i] = ds_input_buffer.front();
                ds_input_buffer.pop_front();
                um_len += ads_vec[un_i].imc_len_data;
            }
            *aun_count = un_i;
            um_input_buffer_size -= um_len;
            um_rcv_reduction += um_len;
            ads_connection->um_recv_avail -= um_len;
            if (um_rcv_reduction >=
                (um_rcv_reduction + um_input_buffer_size + um_rcv_wnd) / 2) {

                m_send_acknowledgement(); // send window update
            }
            // um_rcv_wnd += um_len;
            // if (0 && um_len) /////////////// TODO
            //     m_send_acknowledgement(); // send window update
            return um_len;
        }

    case ied_htcp_closed:
        // no more data now
        *aun_count = 0;
        return 0;

    default:
        // should not arrive here
        assert(false);
        *aun_count = 0;
        return 0;
    }
}

void dsd_htcp_conn_internal::m_close()
{
    bool bo_do_cb_reset = false;
    bool bo_do_cb_closed = false;

    int in_par_cb_reset;
    int in_par_cb_closed;

    dsd_mutex_locker ds_locker(&ds_lock);

    switch (ie_state) {

    case ied_htcp_syn_sent:
        ie_state = ied_htcp_closed;
        bo_do_cb_closed = true;
        in_par_cb_closed = 0; // TODO
        break;

    case ied_htcp_syn_rcvd:
        // should not arrive here - application should not receive
        // connection before it is fully established
        ie_state = ied_htcp_closed;
        bo_do_cb_reset = true;
        in_par_cb_reset = 0; // TODO
        bo_do_cb_closed = true;
        in_par_cb_closed = 0; // TODO
        break;

    case ied_htcp_established:
        ie_state = ied_htcp_fin_wait_1;
        m_send_available();
        break;

    case ied_htcp_close_wait:
        ie_state = ied_htcp_last_ack;
        m_send_available();
        break;

    case ied_htcp_fin_wait_1:
    case ied_htcp_fin_wait_2:
    case ied_htcp_closing:
    case ied_htcp_time_wait:
    case ied_htcp_last_ack:
        // called twice, ignore
        break;

    case ied_htcp_closed:
        // ignore
        break;

    default:
        // should not arrive here
        assert(false);
        break;;
    }

    ds_locker.m_reset();

    dsd_htcp_conn_callbacks* ads_cbs = ads_connection->ads_callbacks;

    if (ads_cbs != 0) {
        if (bo_do_cb_reset && ads_cbs->am_conn_reset != 0)
            ads_cbs->am_conn_reset(ads_connection, in_par_cb_reset);
        if (bo_do_cb_closed && ads_cbs->am_conn_closed != 0)
            ads_cbs->am_conn_closed(ads_connection, in_par_cb_closed);
    }
}

void dsd_htcp_conn_internal::m_reset()
{
    dsd_mutex_locker ds_locker(&ds_lock);

    if (ie_state == ied_htcp_closed)
        return;

    m_send_reset(um_snd_nxt, um_rcv_nxt);
    ie_state = ied_htcp_closed;

    ds_locker.m_reset();

    dsd_htcp_conn_callbacks* ads_cbs = ads_connection->ads_callbacks;

    if (ie_state == ied_htcp_syn_sent)
        return;

    if (ads_cbs != 0) {
//        if (ads_cbs->am_conn_reset != 0)
//            ads_cbs->am_conn_reset(ads_connection, 0); // TODO (0)
        if (ads_cbs->am_conn_closed != 0)
            ads_cbs->am_conn_closed(ads_connection, 0); // TODO (0)
    }
}

void dsd_htcp_conn_internal::m_active_open()
{
    // lock on connection
    dsd_mutex_locker ds_locker(&ds_lock);

    ds_syn_time = m_monotonic_time();

    m_send_syn();
}

void dsd_htcp_conn_internal::m_send_syn()
{
    tcp_segment ds_segment = m_create_segment(0, 19);
    tcp_segment::pointer a_th = ds_segment.tcp_header();
    ds_segment.sequence_number(a_th) = um_snd_iss;
    ds_segment.acknowledgement_number(a_th) = 0;
    ds_segment.syn(a_th) = 1;
    // no window scaling in SYN segment
    ds_segment.window_size(a_th) = um_rcv_wnd > 65535 ? 65535 : um_rcv_wnd;

    // mss
    ds_segment.tcp_options(a_th)[0] = 2;
    ds_segment.tcp_options(a_th)[1] = 4;
    ds_segment.tcp_options(a_th)[2] = um_rcv_rmss / 256;
    ds_segment.tcp_options(a_th)[3] = um_rcv_rmss % 256;
    // window size shift
    ds_segment.tcp_options(a_th)[4] = 3;
    ds_segment.tcp_options(a_th)[5] = 3;
    ds_segment.tcp_options(a_th)[6] = um_rcv_winscale;
    // accept SACK
    ds_segment.tcp_options(a_th)[7] = 4;
    ds_segment.tcp_options(a_th)[8] = 2;
    // timestamp
    ds_segment.tcp_options(a_th)[9] = 8;
    ds_segment.tcp_options(a_th)[10] = 10;
    bit_reference<uint8*, 0, 32>(ds_segment.tcp_options(a_th) + 11)
        = m_create_timestamp();
    bit_reference<uint8*, 0, 32>(ds_segment.tcp_options(a_th) + 15)
        = 0;

    ds_segment.update_tcp_checksum(a_th);

    m_rto_sending(um_snd_iss, 1);
    m_restart_rexmt_timer();
    m_send_segment(ds_segment.get(), 60, 0, 0, 60);

    um_snd_nxt = um_snd_iss + 1;
}

void dsd_htcp_conn_internal::m_accept()
{
    // lock on connection
    dsd_mutex_locker ds_locker(&ds_lock);

    ie_state = ied_htcp_syn_rcvd;
    m_send_synack();
}

void dsd_htcp_conn_internal::m_send_synack()
{
    uint32 um_tcp_options = 4;
    if (bo_use_winscale)
        um_tcp_options += 3;
    if (bo_use_sack)
        um_tcp_options += 2;
    if (bo_use_timestamp)
        um_tcp_options += 10;
    uint32 um_op_cur = 0;

    tcp_segment ds_segment = m_create_segment(0, um_tcp_options);
    tcp_segment::pointer a_th = ds_segment.tcp_header();
    ds_segment.sequence_number(a_th) = um_snd_iss;
    ds_segment.acknowledgement_number(a_th) = um_rcv_nxt;
    ds_segment.syn(a_th) = 1;
    ds_segment.ack(a_th) = 1;
    // no window scaling in SYN segment
    ds_segment.window_size(a_th) = um_rcv_wnd > 65535 ? 65535 : um_rcv_wnd;

    // mss
    ds_segment.tcp_options(a_th)[um_op_cur++] = 2;
    ds_segment.tcp_options(a_th)[um_op_cur++] = 4;
    ds_segment.tcp_options(a_th)[um_op_cur++] = um_rcv_rmss / 256;
    ds_segment.tcp_options(a_th)[um_op_cur++] = um_rcv_rmss % 256;
    if (bo_use_winscale) {
        // window size shift
        ds_segment.tcp_options(a_th)[um_op_cur++] = 3;
        ds_segment.tcp_options(a_th)[um_op_cur++] = 3;
        ds_segment.tcp_options(a_th)[um_op_cur++] = um_rcv_winscale;
    }
    if (bo_use_sack) {
        // accept SACK
        ds_segment.tcp_options(a_th)[um_op_cur++] = 4;
        ds_segment.tcp_options(a_th)[um_op_cur++] = 2;
    }
    if (bo_use_timestamp) {
        // timestamp
        ds_segment.tcp_options(a_th)[um_op_cur++] = 8;
        ds_segment.tcp_options(a_th)[um_op_cur++] = 10;
        bit_reference<uint8*, 0, 32>(ds_segment.tcp_options(a_th) + um_op_cur)
            = m_create_timestamp();
        um_op_cur += 4;
        bit_reference<uint8*, 0, 32>(ds_segment.tcp_options(a_th) + um_op_cur)
            = um_ts_recent;
        um_op_cur += 4;
    }

    um_tcp_options = (um_tcp_options + 3) & 0xfc;

    ds_segment.update_tcp_checksum(a_th);

    um_snd_nxt = um_snd_iss + 1;

    m_rto_sending(um_snd_iss, 1);
    m_send_segment(ds_segment.get(),
                   40 + um_tcp_options, 0, 0, 40 + um_tcp_options);
}

void dsd_htcp_conn_internal::
m_process_segment(dsd_buf_vector_ele* ads_buffers, unsigned un_count)
{
    assert(un_count > 0);
    // packet already sanity checked

    tcp_segment ds_segment(reinterpret_cast<uint8*>(ads_buffers->achc_data));

    bool bo_do_cb_connected = false;
    bool bo_do_cb_connection_failed = false;
    bool bo_do_cb_recv_data = false;
    bool bo_do_cb_data_acked = false;
    bool bo_do_cb_recv_eof = false;
    bool bo_do_cb_reset = false;
    bool bo_do_cb_closed = false;

    int in_par_cb_connected;
    int in_par_cb_connection_failed;
    int in_par_cb_recv_data;
    int in_par_cb_data_acked;
    int in_par_cb_recv_eof;
    int in_par_cb_reset;
    int in_par_cb_closed;

    // lock on connection
    dsd_mutex_locker ds_locker(&ds_lock);

    switch (ie_state) {

    case ied_htcp_closed:
        {
            if (ds_segment.rst())
                break;

            if (ds_segment.ack())
                m_send_reset(ds_segment.acknowledgement_number());
            else
                m_send_reset(0,
                             ds_segment.sequence_number() +
                             ds_segment.tcp_data_length());

            break;
        }

    case ied_htcp_listen:
        {
            // TODO: This state should no longer be allowed.
            // syn packet received, but application has not yet accepted
            // TODO: process RST?
            break;
        }

    case ied_htcp_syn_sent:
        {
            if (ds_segment.ack()) {
                // ack on
                if (!m_within(um_snd_iss + 1, um_snd_nxt + 1,
                              ds_segment.acknowledgement_number()) ||
                    !m_within(um_snd_una, um_snd_nxt + 1,
                              ds_segment.acknowledgement_number())) {
                    // ack out of range => invalid segment received

                    if (!ds_segment.rst()) {
                        // if invalid segment received has RST set, ignore it
                        // otherwise, reply with a RST segment
                        m_send_reset(ds_segment.acknowledgement_number());
                    }

                    break;
                }

                if (ds_segment.rst()) {
                    ie_state = ied_htcp_closed;
                    bo_do_cb_connection_failed = true;
                    in_par_cb_connection_failed = 0; // TODO
                    break;
                }

                if (!ds_segment.syn()) {
                    break;
                }

                m_check_syn_options(ds_segment, um_snd_smss, bo_use_sack,
                                    bo_use_winscale, um_snd_winscale,
                                    bo_use_timestamp, um_ts_recent);
                if (!bo_use_winscale)
                    um_rcv_winscale = 0;
                if (bo_use_timestamp)
                    um_snd_smss -= 12;
                // TODO : place in cc_init
                um_cwnd = (std::min)(4 * um_snd_smss,
                                     (std::max)(2 * um_snd_smss, 4380U));

                um_rcv_irs = ds_segment.sequence_number();
                um_rcv_nxt = um_rcv_irs + 1;
                um_last_ack_sent = um_rcv_nxt;
                um_snd_una = ds_segment.acknowledgement_number();
                um_snd_wnd = m_decode_win(ds_segment.window_size());

                // since we did not send any data yet, there is no need
                // to remove acked segments from output buffer

                m_rto_received();

                // send any data available; if none, send ack
                if (!m_send_available())
                    m_send_acknowledgement();

                ie_state = ied_htcp_established;
                bo_do_cb_connected = true;
                in_par_cb_connected = 0; // TODO
                break;
            } else {
                // ack off
                if (ds_segment.rst() || !ds_segment.syn())
                    break;
                um_rcv_irs = ds_segment.sequence_number();
                um_rcv_nxt = um_rcv_irs + 1;
                um_last_ack_sent = um_rcv_nxt;

                m_send_synack();

                ie_state = ied_htcp_syn_rcvd;
                break;
            }
        }

    case ied_htcp_syn_rcvd:
    case ied_htcp_established:
    case ied_htcp_fin_wait_1:
    case ied_htcp_fin_wait_2:
    case ied_htcp_close_wait:
    case ied_htcp_closing:
    case ied_htcp_last_ack:
    case ied_htcp_time_wait:
        {
            uint32 um_seg_seq = ds_segment.sequence_number();
            uint32 um_seg_len = ds_segment.tcp_data_length();
            bool bo_seg_fin = ds_segment.fin() == 1;

            bool bo_just_ack = ds_segment.ack() == 1 &&
                ds_segment.fin() == 0 &&
                ds_segment.tcp_data_length() == 0;

            const uint8* aut_ts_option = 0;
            const uint8* aut_sack_option = 0;
            uint32 um_sack_option_count = 0;

            if (bo_use_timestamp || bo_use_sack) {
                // traverse options to find relevant options
                tcp_options ds_options(ds_segment);
                while (!ds_options.end_of_options()) {
                    if (bo_use_timestamp &&
                        aut_ts_option == 0 &&
                        ds_options.option_type() == 8 &&
                        ds_options.option_length() == 10) {
                        aut_ts_option = ds_options.option() + 2;
                        if (!bo_use_sack || aut_sack_option != 0)
                            break;
                    }

                    if (bo_use_sack &&
                        aut_sack_option == 0 &&
                        ds_options.option_type() == 5 &&
                        ds_options.option_length() >= 10 &&
                        ds_options.option_length() % 8 == 2) {
                        aut_sack_option = ds_options.option() + 2;
                        um_sack_option_count = ds_options.option_length() / 8;
                        if (!bo_use_timestamp || aut_ts_option != 0)
                            break;
                    }

                    ds_options.goto_next_option();
                }
            }

            // PAWS, check the sequence number
            bool bo_invalid = false;
            uint32 um_seg_tsval;
            uint32 um_seg_tsecr;
            if (!bo_invalid) {
                if (bo_use_timestamp) {
                    if (aut_ts_option) {
                        um_seg_tsval = bit_reference<const uint8*, 0, 32>
                            (aut_ts_option + 0);
                        um_seg_tsecr = bit_reference<const uint8*, 0, 32>
                            (aut_ts_option + 4);
                        bo_invalid = m_wlt(um_seg_tsval, um_ts_recent) &&
                            m_monotonic_time().m_in_s() - im_recent_age_s
                            >= 0 &&
                            ds_segment.rst() == 0;
                    } else {
                        bo_invalid = ds_segment.rst() == 0;
                    }
                }
            }
            if (!bo_invalid) {
                if (um_rcv_wnd == 0) {
                    bo_invalid = um_seg_len != 0 || um_seg_seq != um_rcv_nxt;
                } else {
                    if (m_within(um_rcv_nxt, um_rcv_nxt + um_rcv_wnd,
                                 um_seg_seq)) {
                        bo_invalid = false;
                    } else {
                        bo_invalid = um_seg_len == 0 ||
                            !m_within(um_rcv_nxt, um_rcv_nxt + um_rcv_wnd,
                                      um_seg_seq + um_seg_len - 1);
                    }
                }
            }
            if (!bo_invalid && ds_segment.ack() == 1) {
                bo_invalid = !m_within(um_snd_una, um_snd_nxt + 1,
                                       ds_segment.acknowledgement_number());
            }
            if (bo_invalid) {
                if (ds_segment.rst() == 0)
                    m_send_acknowledgement();
                break;
            }

            // chop off packets that go beyond receive window
            if (m_within(um_seg_seq, um_seg_seq + um_seg_len,
                         um_rcv_nxt + um_rcv_wnd)) {
                bo_seg_fin = false;
                um_seg_len = um_rcv_nxt - um_seg_seq + um_rcv_wnd;
            }

            // chop off packets that go beyond a previously received FIN
            if (bo_oo_fin_received) {
                assert(um_oo_fin_seq != um_rcv_nxt);

                if (m_within(um_seg_seq, um_seg_seq + um_seg_len, um_rcv_nxt)) {
                    // sequence number <= rcv_nxt
                    if (m_within(um_seg_seq, um_seg_seq + um_seg_len,
                                 um_oo_fin_seq)) {
                        um_seg_len = um_oo_fin_seq - um_seg_seq;
                        bo_seg_fin = false;
                        assert(m_within(um_seg_seq, um_seg_seq + um_seg_len,
                                        um_rcv_nxt));
                    }
                } else {
                    // sequence number > rcv_nxt
                    if (m_within(um_rcv_nxt + 1, um_seg_seq + 1,
                                 um_oo_fin_seq)) {
                        um_seg_len = 0;
                        bo_seg_fin = false;
                    } else if (m_within(um_seg_seq, um_seg_seq + um_seg_len,
                                        um_oo_fin_seq)) {
                        assert(um_oo_fin_seq != um_seg_seq);
                        um_seg_len = um_oo_fin_seq - um_seg_seq;
                        bo_seg_fin = false;
                    }
                }
            }

            // check the RST bit
            if (ds_segment.rst() == 1) {
                ie_state = ied_htcp_closed;
                bo_do_cb_reset = true;
                in_par_cb_reset = 0; // TODO
                bo_do_cb_closed = true;
                in_par_cb_closed = 0; // TODO
                // application still has to call close/abort to delete TCB
                break;
            }

            // check the SYN bit
            if (ds_segment.syn() == 1) {
                m_send_reset(um_snd_nxt);

                ie_state = ied_htcp_closed;
                bo_do_cb_reset = true;
                in_par_cb_reset = 0; // TODO
#ifndef B120703
                bo_do_cb_closed = true;
                in_par_cb_closed = 0; // TODO
#endif // B120703
                // application still has to call close/abort to delete TCB
                break;
            }

            // check the ACK field
            if (ds_segment.ack() == 0)
                break;

            if (ie_state == ied_htcp_syn_rcvd) {
                // RFC 793 indicates um_snd_una, um_snd_nxt + 1,
                // but this allows an ack which does not acknowledge syn
                // to change our state to ied_htcp_established
                if (m_within(um_snd_una + 1, um_snd_nxt + 1,
                             ds_segment.acknowledgement_number())) {
                    um_snd_una = ds_segment.acknowledgement_number();
                    ie_state = ied_htcp_established;
                    m_rto_received();
                } else if (ds_segment.acknowledgement_number() != um_snd_una) {
                    m_send_reset(ds_segment.acknowledgement_number());
                    break;
                } else {
                    // instead of following RFC, drop the segment in this case
                    break;
                }
            }

            if (bo_use_timestamp) {
                if (m_wle(um_seg_seq, um_last_ack_sent)) {
                    um_ts_recent = um_seg_tsval;
                    im_recent_age_s = m_monotonic_time().m_in_s();
                }

                m_rto_timestamp_update(um_seg_tsecr);
            }

            bool bo_sack_new_info = false;
            if (bo_use_sack) {
                m_update_snd_sack(um_seg_seq, um_seg_len);
                bo_sack_new_info =
                    m_update_rcv_sack(ds_segment.acknowledgement_number(),
                                      aut_sack_option, um_sack_option_count);
            }

            // 0: not necessary to send
            // 1: send ack, may delay
            // 2: send ack, no delay
            uint32 um_force_send = bo_just_ack ? 0 : 1;
            // if recovery packets sent, never force sending
            bool bo_sent_something = false;

            if (m_within(um_snd_una + 1, um_snd_nxt + 1,
                         ds_segment.acknowledgement_number())) {
                // new ack
#ifdef COUT_LOG
                if (!(ie_state == ied_htcp_established ||
                      ie_state == ied_htcp_fin_wait_1 ||
                      ie_state == ied_htcp_closing ||
                      ie_state == ied_htcp_close_wait ||
                      ie_state == ied_htcp_last_ack))
                    std::cout << "ie_state == " << ie_state << std::endl;
#endif

                assert(ie_state == ied_htcp_established ||
                       ie_state == ied_htcp_fin_wait_1 ||
                       ie_state == ied_htcp_closing ||
                       ie_state == ied_htcp_close_wait ||
                       ie_state == ied_htcp_last_ack);

                // empty relevent section from tx queue
                uint32 um_remove =
                    ds_segment.acknowledgement_number() - um_snd_una;

                // check if sent FIN bit acknowledged
                if (ds_segment.acknowledgement_number() ==
                    um_snd_una + ads_connection->um_send_pend + 1) {
                    switch (ie_state) {
                    case ied_htcp_fin_wait_1:
                        ie_state = ied_htcp_fin_wait_2;
                        --um_remove;
                        break;
                    case ied_htcp_closing:
                        ie_state = ied_htcp_time_wait;
                        m_restart_time_wait_timer();
                        --um_remove;
                        break;
                    case ied_htcp_last_ack:
                        ie_state = ied_htcp_closed;
                        bo_do_cb_closed = true;
                        in_par_cb_closed = 0; // TODO

                        --um_remove;
                        break;
                    default:
                        // should not arrive here
                        assert(false);
                        break;
                    }
                }

#ifdef B100819
                // remove ACKed data from output queue
                assert(ads_connection->um_send_pend >= um_remove);
                ads_connection->um_send_pend -= um_remove;
                // mark for removal when m_send() is called
                um_output_gather_remove += um_remove;
                // now remove from own gather list
                unsigned un_clen = 0;
                if (um_remove > 0) {
                    bo_do_cb_data_acked = true;
                    in_par_cb_data_acked = um_remove;
                    assert(!ds_output_gather.empty());
                    un_clen = ds_output_gather.front().achc_ginp_end -
                        ds_output_gather.front().achc_ginp_cur;
                }
                while (um_remove > 0 && um_remove >= un_clen) {
                    um_remove -= un_clen;
                    ds_output_gather.pop_front();
                    assert(um_remove == 0 || !ds_output_gather.empty());
                    if (!ds_output_gather.empty())
                        un_clen = ds_output_gather.front().achc_ginp_end -
                            ds_output_gather.front().achc_ginp_cur;
                }
                if (um_remove > 0)
                    ds_output_gather.front().achc_ginp_cur += um_remove;
#endif // B100819
                // remove ACKed data from output queue
                assert(ads_connection->um_send_pend >= um_remove);
                ads_connection->um_send_pend -= um_remove;
                unsigned un_clen;
                if (um_remove > 0) {
                    bo_do_cb_data_acked = true;
                    in_par_cb_data_acked = um_remove;
                    assert(ads_output_gather);
                    un_clen = ads_output_gather->achc_ginp_end -
                        ads_output_gather->achc_ginp_cur;
                }
                while (um_remove > 0 && um_remove >= un_clen) {
                    um_remove -= un_clen;
                    dsd_gather_i_1* ads_del = ads_output_gather;
                    ads_output_gather = ads_output_gather->adsc_next;
                    ads_del->achc_ginp_cur = ads_del->achc_ginp_end;
                    if (ads_output_gather) {
                        un_clen = ads_output_gather->achc_ginp_end -
                            ads_output_gather->achc_ginp_cur;
                    } else {
                        assert(um_remove == 0);
                    }
                }
                if (um_remove > 0)
                    ads_output_gather->achc_ginp_cur += um_remove;

                uint32 um_acked_len = ds_segment.acknowledgement_number()
                    - um_snd_una;
                um_snd_una = ds_segment.acknowledgement_number();
                // TODO: fix window update
                um_snd_wnd = m_decode_win(ds_segment.window_size());
                um_exp_backoff = 1;
                // TODO: release/reset rexmt timer

                // update congestion window, recovery mechanisms
                if (bo_recovering) {
                    if (m_wgt(um_snd_una, um_recover)) {
                        // full ack - same with and without sack
                        m_cc_recover_ack();
                        bo_recovering = false;
                    } else {
                        // partial ack
                        if (bo_use_sack) {
                            m_update_sack_pipe();
                        } else {
                            um_cwnd -= um_acked_len;
                            if (um_acked_len >= um_snd_smss)
                                um_cwnd += um_snd_smss;
                            uint32 um_len = ads_connection->um_send_pend;
                            if (um_len > 0) {
                                if (um_len > um_snd_smss)
                                    um_len = um_snd_smss;
                                m_rto_sending(um_snd_una, um_len);
                                m_send_range(um_snd_una, um_len, bo_pack_time);
                                bo_sent_something = true;
                                bo_pack_time = false;
                            }
                        }
                    }
                } else {
                    um_bytes_acked += um_acked_len;
                    m_cc_newack();
                    um_recover = um_snd_una;
                }
                um_dack = 0;

                m_rto_received();
            } else if (ds_segment.acknowledgement_number() == um_snd_nxt) {
                // dup ack, but no unacked data
                // update window size
                // TODO: fix window update
                if (um_snd_wnd < m_decode_win(ds_segment.window_size()))
                    um_snd_wnd = m_decode_win(ds_segment.window_size());
            } else if (ds_segment.acknowledgement_number() == um_snd_una &&
                       bo_just_ack) {
                // duplicate ack
                ++um_dack;
                if (um_dack == um_dup_thresh && !bo_recovering &&
                    m_wgt(um_snd_una, um_recover)) {
                    // do fast retransmission, start fast recovery
                    bo_recovering = true;
                    bo_pack_time = true;
                    um_recover = um_snd_una;
                    m_cc_three_dup();
                    uint32 um_len = ads_connection->um_send_pend;
                    if (um_len > um_snd_nxt - um_snd_una)
                        um_len = um_snd_nxt - um_snd_una;
                    if (um_len > 0) {
                        if (um_len > um_snd_smss)
                            um_len = um_snd_smss;
                        m_rto_sending(um_snd_una, um_len);
                        m_send_range(um_snd_una, um_len);
                        bo_sent_something = true;
                        um_high_rxt = um_snd_una + um_len;
                        m_update_sack_pipe();
                    }
                } else if (bo_recovering) {
                    if (!bo_use_sack) {
                        // fast recovery
                        assert(um_dack > um_dup_thresh);
                        m_cc_more_dup();
                        uint32 um_win = (std::min)(um_snd_wnd, um_cwnd);
                        uint32 um_send = (std::min)
                            (ads_connection->um_send_pend, um_win);
                        uint32 um_flight = um_snd_nxt - um_snd_una;
                        if (um_send > um_flight) {
                            um_send -= um_flight;
                            if (um_send > um_snd_smss)
                                um_send = um_snd_smss;
                            if (um_send > 0) {
                                m_rto_sending(um_snd_nxt, um_send);
                                m_send_range(um_snd_nxt, um_send);
                                bo_sent_something = true;
                                um_snd_nxt += um_send;
                            }
                        }
                    }
                } else if (um_dack < um_dup_thresh) {
                    // limited transmit
                    if (!bo_use_sack || bo_sack_new_info) {
                        uint32 um_send = (std::min)
                            (ads_connection->um_send_pend, um_snd_wnd);
                        uint32 um_flight = um_snd_nxt - um_snd_una;
                        if (um_send > um_flight) {
                            um_send -= um_flight;
                            if (um_send > um_snd_smss)
                                um_send = um_snd_smss;
                            if (um_send > 0) {
                                m_rto_sending(um_snd_nxt, um_send);
                                m_send_range(um_snd_nxt, um_send);
                                bo_sent_something = true;
                                um_snd_nxt += um_send;
                            }
                        }
                    }
                }
            }

            // process segment text
            if (um_seg_len > 0 &&
                m_within(um_seg_seq, um_seg_seq + um_seg_len, um_rcv_nxt)) {
                // append data to input buffer

                um_force_send = 1; // ack data received

                uint32 um_added_length = 0;

                uint32 um_ofs = um_rcv_nxt - um_seg_seq;
                uint32 um_len = um_seg_len - um_ofs;
                assert(um_len > 0);

                uint32 um_skip = um_ofs;
                um_skip += ds_segment.real_header_length();
                um_skip += ds_segment.real_tcp_header_length();

                // from now on, do not use header buffer (may be deallocated)

                while (um_skip >= ads_buffers->imc_len_data) {
                    um_skip -= ads_buffers->imc_len_data;
                    m_htun_relrecvbuf(ads_buffers->ac_handle);
                    ++ads_buffers;
                    --un_count;
                    assert(un_count > 0);
                }
                ads_buffers->achc_data += um_skip;
                ads_buffers->imc_len_data -= um_skip;

                um_added_length += um_len;
                while (um_len > 0) {
                    dsd_buf_vector_ele ds_node = *ads_buffers;
                    if (ds_node.imc_len_data > um_len)
                        ds_node.imc_len_data = um_len;
                    um_len -= ds_node.imc_len_data;
                    ds_input_buffer.push_back(ds_node);
                    um_input_buffer_size += ds_node.imc_len_data;
                    ++ads_buffers;
                    assert(un_count > 0);
                    --un_count;
                }

                um_rcv_nxt = um_seg_seq + um_seg_len;

                if (bo_seg_fin) {
                    // we will not need out-of-order segments, clean up
                    dsd_oobuffer_iterator ds_iter = ds_oobuffer.begin();
                    while(ds_iter != ds_oobuffer.end()) {
                        m_htun_relrecvbuf(ds_iter->ds_ve.ac_handle);
                        ds_oobuffer.erase(ds_iter);
                        ds_iter = ds_oobuffer.begin();
                    }
                    bo_oo_fin_received = false;
                }

                // check out of order segments available
                dsd_oobuffer_iterator ds_iter = ds_oobuffer.begin();
                while (ds_iter != ds_oobuffer.end()) {
                    dsd_buf_vector_ele ds_node = ds_iter->ds_ve;
                    uint32 um_oo_seq = ds_iter->um_seq;
                    uint32 um_oo_len = ds_node.imc_len_data;

                    if (m_within(um_seg_seq + um_ofs, um_rcv_nxt,
                                 um_oo_seq + um_oo_len - 1)) {
                        // out of order segment redundant
                        m_htun_relrecvbuf(ds_node.ac_handle);
                    } else if (m_within(um_oo_seq, um_oo_seq + um_oo_len,
                                        um_rcv_nxt)) {
                        // use out of order segment

                        // append data to input buffer
                        ds_node.achc_data += um_rcv_nxt - um_oo_seq;
                        ds_node.imc_len_data -= um_rcv_nxt - um_oo_seq;

                        ds_input_buffer.push_back(ds_node);
                        um_input_buffer_size += ds_node.imc_len_data;
                        um_added_length += ds_node.imc_len_data;
                        um_rcv_nxt = um_oo_seq + um_oo_len;
                    } else {
                        // out of order segments still not usable
                        break;
                    }

                    // remove oo segment entry from ds_oobuffer map
                    dsd_oobuffer_iterator ds_del = ds_iter;
                    ++ds_iter;
                    ds_oobuffer.erase(ds_del);
                }
                // check out of order FIN
                if (bo_oo_fin_received && um_oo_fin_seq == um_rcv_nxt) {
                    bo_seg_fin = true;
                    bo_oo_fin_received = false;
                }

                // notify application
                um_rcv_wnd -= um_added_length;
                ads_connection->um_recv_avail += um_added_length;
                bo_do_cb_recv_data = true;
                in_par_cb_recv_data = 0; // TODO
            } else if (um_seg_len > 0) {
                // add to out of order buffer

                um_force_send = 2; // must ack out-of-order segment

                ads_buffers->imc_len_data -= ds_segment.real_header_length() +
                    ds_segment.real_tcp_header_length();
                ads_buffers->achc_data += ds_segment.real_header_length() +
                    ds_segment.real_tcp_header_length();

                if (ads_buffers->imc_len_data == 0) {
                    m_htun_relrecvbuf(ads_buffers->ac_handle);
                    ++ads_buffers;
                    --un_count;
                    assert(un_count > 0);
                }

                // assert that out of order segment is not beyond a FIN
                if(bo_oo_fin_received &&
                   !m_wle(um_seg_seq + um_seg_len, um_oo_fin_seq)) {
                }
                assert(!bo_oo_fin_received ||
                       m_wle(um_seg_seq + um_seg_len, um_oo_fin_seq));

                // first, set iter to point to oo segment just before
                // the sequence number of this segment
                dsd_oobuffer_iterator ds_iter = ds_oobuffer.begin();
                while (ds_iter != ds_oobuffer.end() &&
                       m_wge(um_seg_seq,
                             ds_iter->um_seq + ds_iter->ds_ve.imc_len_data)) {
                    ++ds_iter;
                }
//                 dsd_oobuffer_iterator ds_iter =
//                     ds_oobuffer.upper_bound(um_seg_seq);
//                 if (ds_iter != ds_oobuffer.begin())
//                     --ds_iter;

                // We are now sure that there is no overlap before ds_iter.
                // The above statement will always hold.

                while (um_seg_len > 0 && ds_iter != ds_oobuffer.end()) {
                    if (ads_buffers->imc_len_data > um_seg_len)
                        ads_buffers->imc_len_data = um_seg_len;

                    // buffer we are inserting:
                    uint32 um_buf_b = um_seg_seq;
                    uint32 um_buf_e = um_buf_b + ads_buffers->imc_len_data;
                    // current block in ds_oobuffer:
                    uint32 um_block_b = ds_iter->um_seq;
                    uint32 um_block_e = um_block_b +
                        ds_iter->ds_ve.imc_len_data;

                    // first handle the common cases of no conflict

                    // block does not interfere, so skip
                    if (m_wle(um_block_e, um_buf_b)) {
                        ++ds_iter;
                        continue;
                    }

                    // buf is before block, so just insert
                    if (m_wle(um_buf_e, um_block_b)) {
//                         dsd_buf_vector_ele ds_node = *ads_buffers;
//                         ds_iter = ds_oobuffer.insert(ds_iter, std::make_pair
//                                                      (um_seg_seq, ds_node));
                        dsd_oo_node ds_node(*ads_buffers, um_seg_seq);
                        ds_iter = ds_oobuffer.insert(ds_iter, ds_node);
                        ++ds_iter;

                        um_seg_seq += ads_buffers->imc_len_data;
                        um_seg_len -= ads_buffers->imc_len_data;

                        ++ads_buffers;
                        assert(un_count > 0);
                        --un_count;
                        continue;
                    }

                    // now the not-so-common cases of conflicts

                    // buf is contained in block, so erase buf
                    if (m_wge(um_buf_b, um_block_b) &&
                        m_wle(um_buf_e, um_block_e)) {
                        um_seg_seq += ads_buffers->imc_len_data;
                        um_seg_len -= ads_buffers->imc_len_data;
                        m_htun_relrecvbuf(ads_buffers->ac_handle);
                        ++ads_buffers;
                        assert(un_count > 0);
                        --un_count;
                        continue;
                    }

                    // block is contained in buf, so erase block
                    if (m_wge(um_block_b, um_buf_b) &&
                        m_wle(um_block_e, um_buf_e)) {
                        m_htun_relrecvbuf(ds_iter->ds_ve.ac_handle);
                        dsd_oobuffer_iterator ds_del = ds_iter;
                        ++ds_iter;
                        ds_oobuffer.erase(ds_del);
                        continue;
                    }

                    // crop last part of buf and insert
                    if (m_wlt(um_buf_b, um_block_b)) {
                        assert(m_wgt(um_buf_e, um_block_b));
                        assert(m_wlt(um_buf_e, um_block_e));
//                         dsd_buf_vector_ele ds_node = *ads_buffers;
//                         ds_node.imc_len_data -= um_buf_e - um_block_b;
//                         ds_iter = ds_oobuffer.insert(ds_iter, std::make_pair
//                                                      (um_seg_seq, ds_node));
                        dsd_oo_node ds_node(*ads_buffers, um_seg_seq);
                        ds_node.ds_ve.imc_len_data -= um_buf_e - um_block_b;
                        ds_iter = ds_oobuffer.insert(ds_iter, ds_node);
                        ++ds_iter;

                        um_seg_seq += ads_buffers->imc_len_data;
                        um_seg_len -= ads_buffers->imc_len_data;

                        ++ads_buffers;
                        assert(un_count > 0);
                        --un_count;
                        continue;
                    }

                    // crop first part of buf, update ds_iter, loop
                    assert(m_wgt(um_buf_b, um_block_b));
                    assert(m_wlt(um_buf_b, um_block_e));
                    assert(m_wgt(um_buf_e, um_block_e));
                    uint32 um_skip = um_block_e - um_buf_b;
                    ads_buffers->achc_data += um_skip;
                    ads_buffers->imc_len_data -= um_skip;
                    um_seg_seq += um_skip;
                    um_seg_len -= um_skip;
                    ++ds_iter;
                }

                // now append final parts
                while (um_seg_len > 0) {
                    if (ads_buffers->imc_len_data > um_seg_len)
                        ads_buffers->imc_len_data = um_seg_len;

//                     dsd_buf_vector_ele ds_node = *ads_buffers;
//                     ds_oobuffer.insert(ds_oobuffer.end(),
//                                        std::make_pair(um_seg_seq, ds_node));
                    dsd_oo_node ds_node(*ads_buffers, um_seg_seq);
                    ds_iter = ds_oobuffer.insert(ds_iter, ds_node);

                    um_seg_seq += ads_buffers->imc_len_data;
                    um_seg_len -= ads_buffers->imc_len_data;

                    ++ads_buffers;
                    assert(un_count > 0);
                    --un_count;
                }

                assert(ds_oobuffer.begin() != ds_oobuffer.end());

                // now store out-of-order FIN
                if (bo_seg_fin) {
                    bo_seg_fin = false;
                    ds_iter = ds_oobuffer.end();
                    --ds_iter;
                    if (!bo_oo_fin_received &&
                        m_wge(um_seg_seq,
                              ds_iter->um_seq + ds_iter->ds_ve.imc_len_data)) {
                        bo_oo_fin_received = true;
                        um_oo_fin_seq = um_seg_seq;
#ifdef COUT_LOG
                        std::cout << "received oo fin: "
                                  << um_oo_fin_seq << std::endl;
#endif
                    }
                }
            }

            // check the FIN bit
            if (bo_seg_fin) {
                um_force_send = 2; // must ack FIN bit

                bool bo_fin_retransmit = ie_state == ied_htcp_time_wait;

                if (ie_state == ied_htcp_established) {
                    ie_state = ied_htcp_close_wait;
                } else if (ie_state == ied_htcp_fin_wait_1) {
                    ie_state = ied_htcp_closing;
                } else if (ie_state == ied_htcp_fin_wait_2) {
                    ie_state = ied_htcp_time_wait;
                    m_restart_time_wait_timer();
                }

                ++um_rcv_nxt;

                if (!bo_fin_retransmit) {
                    bo_do_cb_recv_eof = true;
                    in_par_cb_recv_eof = 0; // TODO
                }
            }

            if (bo_use_sack && bo_recovering) {
                uint32 um_seq;
                uint32 um_len;
                while (um_cwnd >= um_sack_pipe + um_snd_smss &&
                       m_sack_nextseg(um_seq, um_len)) {
                    // TODO: optimize for fragmented segments because
                    // of output sack options

                    // no need to update um_snd_nxt or um_high_rxt
                    // since m_sack_nextseg() does so automatically
                    m_send_range(um_seq, um_len);
                    um_sack_pipe += um_len;
                }
            }

            // send available data; if there is no data, may send ACK anyway
            m_send_available(bo_sent_something ? 0 : um_force_send);

            break;
        }

    default:
        // should not arrive here
        assert(false);
        break;
    }

    ds_locker.m_reset();

    for (unsigned un_i = 0; un_i < un_count; ++un_i)
        m_htun_relrecvbuf(ads_buffers[un_i].ac_handle);

    dsd_htcp_conn_callbacks* ads_cbs = ads_connection->ads_callbacks;

    if (ads_cbs != 0) {
        if (bo_do_cb_connected && ads_cbs->am_connected != 0)
            ads_cbs->am_connected(ads_connection, in_par_cb_connected);
        if (bo_do_cb_connection_failed && ads_cbs->am_connection_failed != 0)
            ads_cbs->am_connection_failed(ads_connection,
                                          in_par_cb_connection_failed);
        if (bo_do_cb_recv_data && ads_cbs->am_recv_data != 0)
            ads_cbs->am_recv_data(ads_connection, in_par_cb_recv_data);
        if (bo_do_cb_data_acked && ads_cbs->am_data_acked != 0)
            ads_cbs->am_data_acked(ads_connection, in_par_cb_data_acked);
        if (bo_do_cb_recv_eof && ads_cbs->am_recv_eof != 0)
            ads_cbs->am_recv_eof(ads_connection, in_par_cb_recv_eof);
        if (bo_do_cb_reset && ads_cbs->am_conn_reset != 0)
            ads_cbs->am_conn_reset(ads_connection, in_par_cb_reset);
        if (bo_do_cb_closed && ads_cbs->am_conn_closed != 0)
            ads_cbs->am_conn_closed(ads_connection, in_par_cb_closed);
    }
    return;
}

void dsd_htcp_conn_internal::m_timeout()
{
    bool bo_do_cb_connection_failed = false;
    bool bo_do_cb_reset = false;
    bool bo_do_cb_closed = false;

    int in_par_cb_connection_failed;
    int in_par_cb_reset;
    int in_par_cb_closed;

    if (ie_state == ied_htcp_closed)
        return;

    // lock on connection
    dsd_mutex_locker ds_locker(&ds_lock);

    if (um_exp_backoff == 128) {
        // give up
        if (ie_state == ied_htcp_syn_sent) {
            bo_do_cb_connection_failed = true;
            in_par_cb_connection_failed = 0; // TODO
        } else {
            bo_do_cb_reset = true;
            in_par_cb_reset = 0; // TODO
#ifndef B120703
            bo_do_cb_closed = true;
            in_par_cb_closed = 0; // TODO
#endif // B120703
        }
#ifdef B120703
        bo_do_cb_closed = true;
        in_par_cb_closed = 0; // TODO
#endif // B120703
        ie_state = ied_htcp_closed;
    }

    switch (ie_state) {
    case ied_htcp_closed:
        break;

    case ied_htcp_syn_sent:
        {
            um_exp_backoff *= 2;
            m_send_syn();
            break;
        }

    case ied_htcp_syn_rcvd:
        {
            um_exp_backoff *= 2;
            m_send_synack();
            break;
        }

    case ied_htcp_established:
    case ied_htcp_close_wait:
        {
            um_exp_backoff *= 2;
            m_cc_timeout();

            if (bo_use_sack && bo_recovering) {
                bo_recovering = false;
                ds_rcv_sack.clear();
                um_sack_data_size = 0;
                um_recover = um_snd_nxt;
            }

            uint32 um_win = (std::min)(um_snd_wnd, um_cwnd);
            uint32 um_len = (std::min)(ads_connection->um_send_pend, um_win);
            if (um_len == 0)
                break;
            if (um_len > um_snd_smss)
                um_len = um_snd_smss;
            m_rto_sending(um_snd_una, um_len);
            m_send_range(um_snd_una, um_len);
            if (m_within(um_snd_una, um_snd_una + um_len, um_snd_nxt))
                um_snd_nxt = um_snd_una + um_len;
            break;
        }

    case ied_htcp_time_wait:
        {
            ie_state = ied_htcp_closed;
            bo_do_cb_closed = true;
            in_par_cb_closed = 0; // TODO
            break;
        }

        // TODO: more states?
    case ied_htcp_fin_wait_1:
    case ied_htcp_fin_wait_2:
    case ied_htcp_closing:
    case ied_htcp_last_ack:
        break;

    default:
        // should not arrive here
        assert(false);
        break;
    }

    ds_locker.m_reset();

    dsd_htcp_conn_callbacks* ads_cbs = ads_connection->ads_callbacks;

    if (ads_cbs != 0) {
        if (bo_do_cb_connection_failed && ads_cbs->am_connection_failed != 0)
            ads_cbs->am_connection_failed(ads_connection,
                                          in_par_cb_connection_failed);
        if (bo_do_cb_reset && ads_cbs->am_conn_reset != 0)
            ads_cbs->am_conn_reset(ads_connection, in_par_cb_reset);
        if (bo_do_cb_closed && ads_cbs->am_conn_closed != 0)
            ads_cbs->am_conn_closed(ads_connection, in_par_cb_closed);
    }
}

void dsd_htcp_conn_internal::m_da_timeout()
{
    // lock on connection
    dsd_mutex_locker ds_locker(&ds_lock);

    m_send_acknowledgement();
}

tcp_segment dsd_htcp_conn_internal::m_create_segment(uint16 us_data_len,
                                                     uint8 ut_opts_len)
{
    // TODO: better storage/management of next id
    // Note that id should be unique for each IP packet,
    // even on different connections.
    static uint32 um_next_ip_id = 0;

    uint8 ut_opts_max = ut_opts_len + 3 & 0xfc;

    uint16 um_len = 40 + ut_opts_max + us_data_len;
    uint8* aby_header = m_allocate_header();
    tcp_segment ds_segment(aby_header);

    // ip header
    ds_segment.version() = 4;
    ds_segment.header_length() = 5;
    ds_segment.type_of_service() = 0;
    ds_segment.total_length() = um_len;
    ds_segment.identification() = um_next_ip_id++; // TODO: see above
    ds_segment.flags() = 0;
    ds_segment.fragment_offset() = 0;
    ds_segment.time_to_live() = 128;
    ds_segment.protocol() = 6;
    ds_segment.source_address() = ads_connection->um_local_addr;
    ds_segment.destination_address() = ads_connection->um_remote_addr;
    ds_segment.update_checksum();

    // tcp header
    tcp_segment::pointer a_th = ds_segment.tcp_header();
    ds_segment.source_port(a_th) = ads_connection->us_local_port;
    ds_segment.destination_port(a_th) = ads_connection->us_remote_port;
    ds_segment.tcp_header_length(a_th) = 5 + ut_opts_max / 4;
    ds_segment.tcp_reserved(a_th) = 0;
    ds_segment.tcp_flags(a_th) = 0;
    ds_segment.urgent_pointer(a_th) = 0;

    for (unsigned un_i = 40 + ut_opts_len; un_i < 40 + ut_opts_max; ++un_i)
        aby_header[un_i] = 0;

    // seq, ack, win, tcp checksum are not filled in, tcp flags set to 0

    return ds_segment;
}

void dsd_htcp_conn_internal::m_stop_timer()
{
    //if (bo_timer_on) {
    if (ds_timer.ds_te.vpc_chain_2) {
        m_time_rel(&ds_timer.ds_te);
        //bo_timer_on = false;
    }
}

void m_hc_timer_callback(dsd_timer_ele* ads_hc_te)
{
    dsd_ext_timer_ele* ads_ete =
        reinterpret_cast<dsd_ext_timer_ele*>(ads_hc_te);
    ads_ete->ads_ci->m_timeout();
}


void dsd_htcp_conn_internal::m_restart_rexmt_timer()
{
    m_stop_timer();
    std::memset(&ds_timer.ds_te, 0, sizeof(ds_timer.ds_te));
    if (um_exp_backoff > 64) {
        // one last time with 2MSL
        ds_timer.ds_te.ilcwaitmsec = 2 * um_msl_s * 1000;
    } else {
        ds_timer.ds_te.ilcwaitmsec = um_rto_ms * um_exp_backoff;
    }
    ds_timer.ds_te.amc_compl = &m_hc_timer_callback;
    m_time_set(&ds_timer.ds_te, 0);
    //bo_timer_on = true;
}

void dsd_htcp_conn_internal::m_restart_time_wait_timer()
{
    m_stop_timer();
    std::memset(&ds_timer.ds_te, 0, sizeof(ds_timer.ds_te));
#ifdef DEF_TIME_WAIT_SHORT
    ds_timer.ds_te.ilcwaitmsec = 100;
#else
    ds_timer.ds_te.ilcwaitmsec = 2 * um_msl_s * 1000;
#endif
    ds_timer.ds_te.amc_compl = &m_hc_timer_callback;
    m_time_set(&ds_timer.ds_te, 0);
    //bo_timer_on = true;
}

void dsd_htcp_conn_internal::m_stop_da_timer()
{
    m_time_rel(&ds_da_timer.ds_te);
}

bool dsd_htcp_conn_internal::m_da_timer_active()
{
    return ds_da_timer.ds_te.vpc_chain_2;
}

void m_hc_da_timer_callback(dsd_timer_ele* ads_hc_te)
{
    dsd_ext_timer_ele* ads_ete =
        reinterpret_cast<dsd_ext_timer_ele*>(ads_hc_te);
    ads_ete->ads_ci->m_da_timeout();
}

void dsd_htcp_conn_internal::m_start_da_timer()
{
    m_time_set(&ds_da_timer.ds_te, 0);
    //bo_da_timer_on = true;
}

void dsd_htcp_conn_internal::m_send_segment(uint8* aby_header,
                                            unsigned un_headlen,
                                            dsd_gather_i_1* ads_payload,
                                            char* ach_plstart,
                                            unsigned un_tlen)
{
    dsd_send_packet_info ds_spi(aby_header, un_headlen,
                                 ads_payload, ach_plstart, un_tlen);
    m_send_packet(ads_connection, ds_spi);
}

void dsd_htcp_conn_internal::
m_send_segments(std::list<dsd_send_packet_info>& ds_segments)
{
    m_send_packets(ads_connection, ds_segments);
}

void dsd_htcp_conn_internal::m_send_range(uint32 um_seq, uint32 um_len,
                                          bool bo_retime)
{
    if (um_len == 0)
        return;

    uint32 um_mss = um_snd_smss;
    uint32 um_olen = bo_use_timestamp ? 10 : 0;
    uint32 um_s_max = 40 - um_olen;
    // um_snd_smss already allows for timestamp option
    if (bo_use_sack) {
        uint32 um_slen = m_sack_option_avail(um_s_max);
        um_olen += um_slen;
        um_mss -= um_slen;
    }
    uint32 um_hlen = 40 + (um_olen + 3) & 0xfc;

    if (um_rcv_reduction >= um_rcv_rmss) {
        um_rcv_wnd += um_rcv_reduction;
        um_rcv_reduction = 0;
    }

    bool bo_fin =
        um_seq - um_snd_una + um_len == ads_connection->um_send_pend + 1;
    if (bo_fin) {
        assert(ie_state == ied_htcp_fin_wait_1 ||
               ie_state == ied_htcp_fin_wait_2 ||
               ie_state == ied_htcp_closing ||
               ie_state == ied_htcp_time_wait ||
               ie_state == ied_htcp_last_ack);
        --um_len;
        if (um_len == 0) {
            tcp_segment ds_segment = m_create_segment(0, um_olen);
            ds_segment.sequence_number() = um_seq;
            ds_segment.acknowledgement_number() = um_rcv_nxt;
            ds_segment.window_size() = m_calc_win(um_rcv_wnd);
            ds_segment.ack() = 1;
            ds_segment.fin() = 1;
            uint8* aut_oppos = ds_segment.tcp_options();
            if (bo_use_timestamp) {
                m_create_timestamp_option(aut_oppos);
                aut_oppos += 10;
            }
            if (bo_use_sack) {
                aut_oppos += m_create_sack_option(aut_oppos, um_s_max);
            }
            assert(aut_oppos == ds_segment.tcp_options() + um_olen);
            ds_segment.update_tcp_checksum();

            m_restart_rexmt_timer();
            m_send_segment(ds_segment.get(), um_hlen, 0, 0, um_hlen);
            m_stop_da_timer();
            return;
        }
    }

    std::list<dsd_send_packet_info> ds_segments;

#ifdef B100819
    dsd_gather_i_1* ads_node = &ds_output_gather.front();
#endif // B100819
    dsd_gather_i_1* ads_node = ads_output_gather;
    char* ach_cur = ads_node->achc_ginp_cur;
    uint32 um_nlen = ads_node->achc_ginp_end - ads_node->achc_ginp_cur;
    uint32 um_skip = um_seq - um_snd_una;
    while (um_len > 0) {
        while (um_skip > 0 && um_skip >= um_nlen) {
            um_skip -= um_nlen;
            ads_node = ads_node->adsc_next;
            assert (ads_node != 0);
            if (ads_node == 0)
                return;
            ach_cur = ads_node->achc_ginp_cur;
            um_nlen = ads_node->achc_ginp_end - ads_node->achc_ginp_cur;
        }
        ach_cur += um_skip;
        um_nlen -= um_skip;

        uint32 um_slen = um_len;
        if (um_slen > um_mss)
            um_slen = um_mss;
        tcp_segment ds_segment = m_create_segment(um_slen, um_olen);
        ds_segment.sequence_number() = um_seq;
        ds_segment.acknowledgement_number() = um_rcv_nxt;
        ds_segment.window_size() = m_calc_win(um_rcv_wnd);
        ds_segment.ack() = 1;
        if (um_len == um_slen) {
            ds_segment.psh() = 1;
            if (bo_fin)
                ds_segment.fin() = 1;
        }
        uint8* aut_oppos = ds_segment.tcp_options();
        if (bo_use_timestamp) {
            m_create_timestamp_option(aut_oppos);
            aut_oppos += 10;
        }
        if (bo_use_sack) {
            aut_oppos += m_create_sack_option(aut_oppos, um_s_max);
        }
        assert(aut_oppos == ds_segment.tcp_options() + um_olen);
        ds_segment.update_tcp_checksum(ads_node, ach_cur);

        ds_segments.push_back(dsd_send_packet_info(ds_segment.get(), um_hlen,
                                                   ads_node, ach_cur,
                                                   um_hlen + um_slen));

        um_seq += um_slen;
        um_len -= um_slen;
        um_skip = um_slen;
    }

    assert(!ds_segments.empty());

    if (bo_retime)
        m_restart_rexmt_timer();
    um_last_ack_sent = um_rcv_nxt;
    m_send_segments(ds_segments);
    m_stop_da_timer();
}

uint32 dsd_htcp_conn_internal::m_send_available(uint32 um_force_send)
{
    uint32 um_win = (std::min)(um_snd_wnd, um_cwnd);
    uint32 um_send = (std::min)(ads_connection->um_send_pend, um_win);
    bool bo_fin = (um_send == ads_connection->um_send_pend &&
                   (ie_state == ied_htcp_fin_wait_1 ||
                    ie_state == ied_htcp_closing ||
                    ie_state == ied_htcp_last_ack));
    if (bo_fin)
        // include FIN
        ++um_send;

    uint32 um_flight = um_snd_nxt - um_snd_una;
    if (um_send <= um_flight)
        um_send = 0;
    else
        um_send -= um_flight;

    if (bo_fin) {
        if (um_send > 1)
            m_rto_sending(um_snd_nxt, um_send - 1);
    } else {
        if (um_send > 0)
            m_rto_sending(um_snd_nxt, um_send);
    }

    if (um_send > 0) {
        m_send_range(um_snd_nxt, um_send);
        um_snd_nxt += um_send;
    } else if (um_force_send == 2 ||
               (um_force_send == 1 && m_da_timer_active())) {
        m_send_acknowledgement();
    } else if (um_force_send == 1) {
        m_start_da_timer();
    }

    return um_send;
}

void dsd_htcp_conn_internal::m_send_acknowledgement()
{
    uint32 um_olen = bo_use_timestamp ? 10 : 0;
    uint32 um_s_max = 40 - um_olen;
    // um_snd_smss already allows for timestamp option
    if (bo_use_sack)
        um_olen += m_sack_option_avail(um_s_max);
    uint32 um_hlen = 40 + (um_olen + 3) & 0xfc;

    if (um_rcv_reduction >= um_rcv_rmss) {
        um_rcv_wnd += um_rcv_reduction;
        um_rcv_reduction = 0;
    }

    tcp_segment ds_ack_seg = m_create_segment(0, um_olen);
    ds_ack_seg.sequence_number() = um_snd_nxt;
    ds_ack_seg.acknowledgement_number() = um_rcv_nxt;
    ds_ack_seg.window_size() = m_calc_win(um_rcv_wnd);
    ds_ack_seg.ack() = 1;
    uint8* aut_oppos = ds_ack_seg.tcp_options();
    if (bo_use_timestamp) {
        m_create_timestamp_option(aut_oppos);
        aut_oppos += 10;
    }
    if (bo_use_sack) {
        aut_oppos += m_create_sack_option(aut_oppos, um_s_max);
    }
    assert(aut_oppos == ds_ack_seg.tcp_options() + um_olen);
    ds_ack_seg.update_tcp_checksum();
//     if (um_olen > 10) {
//         for (uint32 um_i = 0; um_i < um_hlen; ++um_i) {
//             std::cout << m_hex(ds_ack_seg.get()[um_i], 2);
//             if (um_i % 16 == 15 || um_i == um_hlen - 1)
//                 std::cout << std::endl;
//             else if (um_i % 16 == 7)
//                 std::cout << "  ";
//             else
//                 std::cout << " ";
//         }
//     }

    um_last_ack_sent = um_rcv_nxt;
    dsd_send_packet_info ds_info(ds_ack_seg.get(), um_hlen, 0, 0, um_hlen);
    m_send_packet(ads_connection, ds_info);
    m_stop_da_timer();
}

void dsd_htcp_conn_internal::m_send_reset(uint32 um_seq)
{
    tcp_segment ds_rst_seg = m_create_segment();
    ds_rst_seg.sequence_number() = um_seq;
    ds_rst_seg.acknowledgement_number() = 0;
    ds_rst_seg.window_size() = 0;
    ds_rst_seg.rst() = 1;
    ds_rst_seg.update_tcp_checksum();

    dsd_send_packet_info ds_info(ds_rst_seg.get(), 40, 0, 0, 40);
    m_send_packet(ads_connection, ds_info);
}

void dsd_htcp_conn_internal::m_send_reset(uint32 um_seq, uint32 um_ack)
{
    tcp_segment ds_rst_seg = m_create_segment();
    ds_rst_seg.sequence_number() = um_seq;
    ds_rst_seg.acknowledgement_number() = um_ack;
    ds_rst_seg.window_size() = 0;
    ds_rst_seg.ack() = 1;
    ds_rst_seg.rst() = 1;
    ds_rst_seg.update_tcp_checksum();

    dsd_send_packet_info ds_info(ds_rst_seg.get(), 40, 0, 0, 40);
    m_send_packet(ads_connection, ds_info);
}

void dsd_htcp_conn_internal::m_send_reset(uint32 um_seq,
                                          uint32 um_ack, uint32 um_tsecr)
{
    tcp_segment ds_rst_seg = m_create_segment(0, 10);
    ds_rst_seg.sequence_number() = um_seq;
    ds_rst_seg.acknowledgement_number() = um_ack;
    ds_rst_seg.window_size() = 0;
    ds_rst_seg.ack() = 1;
    ds_rst_seg.rst() = 1;
    uint8* aut_o = ds_rst_seg.tcp_options();
    aut_o[0] = 8;
    aut_o[1] = 10;
    bit_reference<uint8*, 0, 32>(aut_o + 2) = 0;
    bit_reference<uint8*, 0, 32>(aut_o + 6) = um_tsecr;
    ds_rst_seg.update_tcp_checksum();

    dsd_send_packet_info ds_info(ds_rst_seg.get(), 52, 0, 0, 52);
    m_send_packet(ads_connection, ds_info);
}

bool dsd_htcp_conn_internal::m_check_segment_seq(tcp_segment ds_segment)
{
    uint32 um_seg_seq = ds_segment.sequence_number();
    uint32 um_seg_len = ds_segment.tcp_data_length();

    if (um_rcv_wnd == 0) {
        if (um_seg_len == 0) {
            if (um_seg_seq == um_rcv_nxt)
                return true;
        }
    } else {
        if (um_seg_len == 0) {
            if (m_within(um_rcv_nxt, um_rcv_nxt + um_rcv_wnd, um_seg_seq))
                return true;
        } else {
            if (m_within(um_rcv_nxt, um_rcv_nxt + um_rcv_wnd, um_seg_seq) ||
                m_within(um_rcv_nxt, um_rcv_nxt + um_rcv_wnd,
                         um_seg_seq + ds_segment.tcp_data_length() - 1))
                return true;
        }
    }

#ifdef COUT_LOG
    std::cout << "segment not acceptable: ";
    uint32 um_ip = ads_connection->um_remote_addr;
    std::cout << int((um_ip & 0xff000000) >> 24) << '.'
              << int((um_ip & 0x00ff0000) >> 16) << '.'
              << int((um_ip & 0x0000ff00) >> 8) << '.'
              << int(um_ip & 0x000000ff) << ':'
              << ads_connection->us_remote_port;
    std::cout << "->";
    um_ip = ads_connection->um_local_addr;
    std::cout << int((um_ip & 0xff000000) >> 24) << '.'
              << int((um_ip & 0x00ff0000) >> 16) << '.'
              << int((um_ip & 0x0000ff00) >> 8) << '.'
              << int(um_ip & 0x000000ff) << ':'
              << ads_connection->us_local_port;
    std::cout << " seg.seq(" << um_seg_seq
              << ") seg.len(" << um_seg_len
              << ") rcv.nxt(" << um_rcv_nxt
              << ") rcv.wnd(" << um_rcv_wnd << ')' << std::endl;
#endif

    if (ds_segment.rst() == 0)
        m_send_acknowledgement();

    return false;
}

void dsd_htcp_conn_internal::m_update_snd_sack(uint32 um_seg_seq, uint32 um_len)
{
    if (m_wle(um_seg_seq, um_rcv_nxt) || um_len == 0) {
        // just check which elements in list we discard
        uint32 um_nxt = um_seg_seq + um_len;
        if (m_wgt(um_rcv_nxt, um_nxt))
            um_nxt = um_rcv_nxt;

        dsd_sack_iterator ds_iter = ds_snd_sack.begin();
        while (ds_iter != ds_snd_sack.end()) {
            if (m_wle(ds_iter->first, um_rcv_nxt)) {
                dsd_sack_iterator ds_del = ds_iter;
                ++ds_iter;
                ds_snd_sack.erase(ds_del);
                continue;
            }
            ++ds_iter;
        }
        return;
    }

//     std::cout << "inserting " << (um_seg_seq - um_rcv_irs)
//               << "/" << (um_seg_seq + um_len - um_rcv_irs) << std::endl;

    ds_snd_sack.push_front(dsd_sack_pair(um_seg_seq, um_seg_seq + um_len));
    dsd_sack_iterator ds_new = ds_snd_sack.begin();
    dsd_sack_iterator ds_iter = ds_new;
    ++ds_iter;
    assert(ds_new->first == um_seg_seq);
    assert(ds_new->second == um_seg_seq + um_len);
    // check which elements to discard and which to assimilate into new
    while (ds_iter != ds_snd_sack.end()) {
        if (m_wle(ds_iter->first, um_rcv_nxt)) {
            // discard
            dsd_sack_iterator ds_del = ds_iter;
            ++ds_iter;
            ds_snd_sack.erase(ds_del);
            continue;
        }
        if (m_wlt(ds_iter->second, ds_new->first) ||
            m_wgt(ds_iter->first, ds_new->second)) {
            // no overlap
            ++ds_iter;
            continue;
        }
        if (m_wge(ds_iter->first, ds_new->first) &&
            m_wle(ds_iter->second, ds_new->second)) {
            // old fully inside new
            dsd_sack_iterator ds_del = ds_iter;
            ++ds_iter;
            ds_snd_sack.erase(ds_del);
            continue;
        }
        if (m_wle(ds_iter->first, ds_new->first) &&
            m_wge(ds_iter->second, ds_new->second)) {
            // new fully inside old
            *ds_new = *ds_iter;
            dsd_sack_iterator ds_del = ds_iter;
            ++ds_iter;
            ds_snd_sack.erase(ds_del);
            continue;
        }
        if (m_wlt(ds_iter->first, ds_new->first)) {
            assert(m_wlt(ds_iter->second, ds_new->second));
            ds_new->first = ds_iter->first;
            dsd_sack_iterator ds_del = ds_iter;
            ++ds_iter;
            ds_snd_sack.erase(ds_del);
            continue;
        }
        assert(m_wgt(ds_iter->first, ds_new->first));
        assert(m_wgt(ds_iter->second, ds_new->second));
        ds_new->second = ds_iter->second;
        dsd_sack_iterator ds_del = ds_iter;
        ++ds_iter;
        ds_snd_sack.erase(ds_del);
    }

//     ds_iter = ds_snd_sack.begin();
//     while (ds_iter != ds_snd_sack.end()) {
//         std::cout << "    " << (ds_iter->first - um_rcv_irs)
//                   << "/" << (ds_iter->second - um_rcv_irs) << std::endl;
//         ++ds_iter;
//     }
}

// returns true if we had new sack information
bool dsd_htcp_conn_internal::m_update_rcv_sack(uint32 um_seg_ack,
                                               const uint8* aut_option_data,
                                               uint32 um_count)
{
    assert(m_wge(um_seg_ack, um_snd_una));
    uint32 umr_left[4];
    uint32 umr_right[4];
    assert(um_count <= 4);
    // we can sort incoming SACK information - we do not use order
    for (uint32 um_i = 0; um_i < um_count; ++um_i) {
        uint32 um_left =
            bit_reference<const uint8*, 0, 32>(aut_option_data + 0);
        uint32 um_right =
            bit_reference<const uint8*, 0, 32>(aut_option_data + 4);
        aut_option_data += 8;
        if (m_wge(um_left, um_right) ||
            m_wle(um_left, um_seg_ack) ||
            m_wgt(um_right, um_snd_nxt)) {
            --um_count;
            --um_i;
            continue;
        }
        uint32 um_j;
        bool bo_drop = false;
        for (um_j = 0; um_j < um_i; ++um_j) {
            if (m_wlt(um_right, umr_left[um_j])) {
                // current block precedes block j
                for (uint32 um_k = um_i; um_k > um_j; --um_k) {
                    umr_left[um_k] = umr_left[um_k - 1];
                    umr_right[um_k] = umr_right[um_k - 1];
                }
                break;
            }
            if (!m_wgt(um_left, umr_right[um_j])) {
                // current block collides with block j - drop it
                bo_drop = true;
                break;
            }
        }
        if (bo_drop) {
            --um_count;
            --um_i;
            continue;
        }
        umr_left[um_j] = um_left;
        umr_right[um_j] = um_right;
    }

    // now check any table sack info colliding with ack - and discard
    dsd_sack_iterator ds_iter = ds_rcv_sack.begin();
    while (ds_iter != ds_rcv_sack.end() && m_wle(ds_iter->first, um_seg_ack)) {
        um_sack_data_size -= ds_iter->second - ds_iter->first;
        ds_iter = ds_rcv_sack.erase(ds_iter);
    }

    if (um_count == 0)
        return false;

    // now merge received sack information in sack table
    bool bo_done_some_update = false;
    ds_iter = ds_rcv_sack.begin();
    uint32 um_i = 0;
    while (ds_iter != ds_rcv_sack.end() && um_i < um_count) {
        if (m_wlt(umr_right[um_i], ds_iter->first)) {
            // current received block before current table block
            um_sack_data_size += umr_right[um_i] - umr_left[um_i];
            ds_iter = ds_rcv_sack.insert(ds_iter,
                                         dsd_sack_pair(umr_left[um_i],
                                                       umr_right[um_i]));
            ++ds_iter;
            ++um_i;
            bo_done_some_update = true;
            continue;
        }

        if (m_wgt(umr_left[um_i], ds_iter->second)) {
            // current received block after current table block
            ++ds_iter;
            continue;
        }

        // now resolve collisions

        if (m_wge(umr_left[um_i], ds_iter->first) &&
            m_wle(umr_right[um_i], ds_iter->second)) {
            // current received block totally inside current table block
            ++um_i;
            continue;
        }

        if (m_wle(umr_left[um_i], ds_iter->first) &&
            m_wge(umr_right[um_i], ds_iter->second)) {
            // current received block totally encloses current table block
            um_sack_data_size -= ds_iter->second - ds_iter->first;
            ds_iter = ds_rcv_sack.erase(ds_iter);
            bo_done_some_update = true;
            continue;
        }

        if (m_wlt(umr_left[um_i], ds_iter->first)) {
            // update left edge of current table block
            um_sack_data_size += ds_iter->first - umr_left[um_i];
            ds_iter->first = umr_left[um_i];
            ++um_i;
            bo_done_some_update = true;
            continue;
        }

        if (m_wgt(umr_right[um_i], ds_iter->second)) {
            // update right edge of current received block
            um_sack_data_size += umr_right[um_i] - ds_iter->second;
            umr_left[um_i] = ds_iter->first;
            ++um_i;
            bo_done_some_update = true;
            continue;
        }

        // should not arrive here - all cases should be handled above
        assert(false);
        break;
    }

    // put remaining received blocks at end of table
    for (; um_i < um_count; ++um_i) {
        um_sack_data_size += umr_right[um_i] - umr_left[um_i];
        ds_rcv_sack.push_back(dsd_sack_pair(umr_left[um_i], umr_right[um_i]));
        bo_done_some_update = true;
    }

    return bo_done_some_update;
}

void dsd_htcp_conn_internal::m_update_sack_pipe()
{
    // TODO: optimization - maybe continuously keep pipe variable uptodate

    uint32 um_higher_sack_count = ds_rcv_sack.size();
    uint32 um_higher_sack_data = um_sack_data_size;

    um_sack_pipe = 0;

    uint32 um_last_edge = um_snd_una;
    dsd_sack_iterator ds_iter = ds_rcv_sack.begin();
    while (ds_iter != ds_rcv_sack.end()) {
        uint32 um_cur_hole = ds_iter->first - um_last_edge;

        if (um_higher_sack_count >= um_dup_thresh ||
            um_higher_sack_data >= um_dup_thresh * um_snd_smss) {
            // current hole is not considered lost
            um_sack_pipe += um_cur_hole;
        }

        if (m_wlt(ds_iter->first, um_high_rxt)) {
            // current hole is retransmitted
            um_sack_pipe += um_cur_hole;
        } else if (m_wlt(um_last_edge, um_high_rxt)) {
            // part of current hole is retransmitted
            um_sack_pipe += um_high_rxt - um_last_edge;
        }

        --um_higher_sack_count;
        um_higher_sack_data -= ds_iter->second - ds_iter->first;
        um_last_edge = ds_iter->second;
        ++ds_iter;
    }

    // now add data beyond highest sack block
    um_sack_pipe += um_snd_nxt - um_last_edge;
    // TODO: is the following really necessary?
    if (m_wlt(um_snd_nxt, um_high_rxt)) {
        um_sack_pipe += um_snd_nxt - um_last_edge;
    } else if (m_wlt(um_last_edge, um_high_rxt)) {
        um_sack_pipe += um_high_rxt - um_last_edge;
    }
}

// Note: ONLY call when REALLY sending segment - may update high_rxt or snd_nxt
bool dsd_htcp_conn_internal::m_sack_nextseg(uint32& um_seq, uint32& um_len)
{
    uint32 um_higher_sack_count = ds_rcv_sack.size();
    uint32 um_higher_sack_data = um_sack_data_size;

    bool bo_last_resort = false;

    uint32 um_last_edge = um_snd_una;
    dsd_sack_iterator ds_iter = ds_rcv_sack.begin();
    while (ds_iter != ds_rcv_sack.end()) {
        uint32 um_cur_hole = ds_iter->first - um_last_edge;

        if (m_wgt(ds_iter->first, um_high_rxt)) {
            if (um_higher_sack_count >= um_dup_thresh ||
                um_higher_sack_data >= um_dup_thresh * um_snd_smss) {
                um_seq = (std::max)(um_last_edge, um_high_rxt);
                um_len = (std::max)(ds_iter->first - um_seq, um_snd_smss);
                um_high_rxt = um_seq + um_len;
                return true;
            } else if (!bo_last_resort) {
                um_seq = (std::max)(um_last_edge, um_high_rxt);
                um_len = (std::max)(ds_iter->first - um_seq, um_snd_smss);
                bo_last_resort = true;
            }
        }

        --um_higher_sack_count;
        um_higher_sack_data -= ds_iter->second - ds_iter->first;
        um_last_edge = ds_iter->second;
        ++ds_iter;
    }

    uint32 um_unsent = ads_connection->um_send_pend - um_snd_nxt;
    uint32 um_win = um_snd_una + um_snd_wnd - um_snd_nxt;
    if (m_wlt(um_snd_una + um_snd_wnd, um_snd_nxt))
        um_win = 0;
    uint32 um_l = (std::min)(um_unsent, um_win);
    if (um_l > 0) {
        um_l = (std::min)(um_l, um_snd_smss);
        um_seq = um_snd_nxt;
        um_len = um_l;
        um_snd_nxt += um_l;
        return true;
    }

    if (bo_last_resort) {
        um_high_rxt = um_seq + um_len;
        return true;
    }

    return false;
}

void dsd_htcp_conn_internal::m_rto_init()
{
    um_srtt_ms = 0;
    um_rttvar_ms = 0;
    um_rto_ms = 3000;
    um_last_update_ts = m_monotonic_time().m_in_m() - 3000;

    bo_rtt_calc_valid = false;
}

void dsd_htcp_conn_internal::m_rto_sending(uint32 um_seq, uint32 um_len)
{
    if (bo_use_timestamp)
        return;

    // if already timing and this send is no duplicate (Karn), return
    if (bo_rtt_calc_valid &&
        !m_within(um_seq, um_seq + um_len, um_rtt_calc_seq_sent)) {
        return;
    }

    bo_rtt_calc_valid = false;

    if (um_snd_nxt == um_snd_una &&
        m_within(um_seq, um_seq + um_len, um_snd_nxt)) {
        // a usable unsent byte exists
        ds_rtt_calc_time_sent = m_monotonic_time();
        um_rtt_calc_seq_sent = um_snd_nxt;
        bo_rtt_calc_valid = true;
    }
}

void dsd_htcp_conn_internal::m_rto_received()
{
    if (bo_use_timestamp)
        return;

    if (!bo_rtt_calc_valid) {
        return;
    }

    if (!m_within(um_rtt_calc_seq_sent + 1, um_snd_nxt + 1, um_snd_una)) {
        return;
    }

    // relevant byte acknowledged

    m_rto_update();
    bo_rtt_calc_valid = false;
}

void dsd_htcp_conn_internal::m_rto_update()
{
    if (bo_use_timestamp)
        return;

    int32 im_this_rtt = (m_monotonic_time() - ds_rtt_calc_time_sent).m_in_m();

    if (um_srtt_ms == 0) {
        // first measurement
        um_srtt_ms = im_this_rtt;
        um_rttvar_ms = im_this_rtt / 2;
    } else {
        int32 im_diff = im_this_rtt - um_srtt_ms;
        um_srtt_ms += im_diff / 8;
        um_rttvar_ms += (std::abs(im_diff) - int32(um_rttvar_ms)) / 4;
    }

    um_rto_ms = um_srtt_ms + 4 * um_rttvar_ms;
    if (um_rto_ms < 1000) // SHOULD hava a minimum
        um_rto_ms = 1000;
    else if (um_rto_ms > 60000) // MAY have a maximum of at least 60s
        um_rto_ms = 60000;

    bo_rtt_calc_valid = false;
}

void dsd_htcp_conn_internal::m_rto_timestamp_update(uint32 um_seg_tsecr)
{
    uint32 um_now_ms = m_monotonic_time().m_in_m();
    uint32 um_this_rtt = um_now_ms - um_seg_tsecr;

    if (um_srtt_ms == 0) {
        // first measurement
        um_srtt_ms = um_this_rtt;
        um_rttvar_ms = um_this_rtt / 2;
        um_last_tsecr = um_seg_tsecr;
    } else if (um_seg_tsecr != um_last_tsecr) {
        int32 im_diff = um_this_rtt - um_srtt_ms;
        // TODO: check overflow when multiplying?
        int32 im_w_num = um_now_ms - um_last_update_ts;
        int32 im_w_den = um_rto_ms;
        if (im_w_num > im_w_den) {
            um_srtt_ms += im_diff / 8;
            um_rttvar_ms += (std::abs(im_diff) - int32(um_rttvar_ms)) / 4;
        } else {
            um_srtt_ms += (im_diff / 8 * im_w_num + im_w_den - 1) / im_w_den;
            um_rttvar_ms += ((std::abs(im_diff) - int32(um_rttvar_ms)) / 4
                             * im_w_num + im_w_den - 1) / im_w_den;
        }
    }
    um_last_update_ts = um_now_ms;
    um_last_tsecr = um_seg_tsecr;

    um_rto_ms = um_srtt_ms + 4 * um_rttvar_ms;
    // SHOULD hava a minimum
    // MAY have a maximum of at least 60s
    if (um_rto_ms < 1000) {
        um_rto_ms = 1000;
    } else if (um_rto_ms > 60000) {
        um_rto_ms = 60000;
    }
}

uint32 dsd_htcp_conn_internal::m_create_timestamp()
{
    return uint32(m_monotonic_time().m_in_m());
}

void dsd_htcp_conn_internal::m_create_timestamp_option(uint8* aut_o)
{
    aut_o[0] = 8;
    aut_o[1] = 10;
    bit_reference<uint8*, 0, 32>(aut_o + 2) = m_create_timestamp();
    bit_reference<uint8*, 0, 32>(aut_o + 6) = um_ts_recent;
}

uint32 dsd_htcp_conn_internal::m_sack_option_avail(uint32 um_max)
{
    if (um_max < 10 || ds_snd_sack.empty())
        return 0;
    return 2 + 8 * (std::min)((um_max - 2) / 8, uint32(ds_snd_sack.size()));
}

uint32 dsd_htcp_conn_internal::m_create_sack_option(uint8* aut_o,
                                                    uint32 um_avail)
{
    if (um_avail < 10 || ds_snd_sack.empty())
        return 0;

    uint32 um_count = 0;

    aut_o[um_count++] = 5;
    ++um_count; // add length later
    dsd_sack_iterator ds_iter = ds_snd_sack.begin();
    while (um_count + 8 <= um_avail && ds_iter != ds_snd_sack.end()) {
        bit_reference<uint8*, 0, 32>(aut_o + um_count) = ds_iter->first;
        um_count += 4;
        bit_reference<uint8*, 0, 32>(aut_o + um_count) = ds_iter->second;
        um_count += 4;
//         if (ds_iter == ds_snd_sack.begin()) {
//             std::cout << "writing: ";
//         } else {
//             std::cout << "         ";
//         }
//         std::cout << (ds_iter->first - um_rcv_irs)
//                   << "/" << (ds_iter->second - um_rcv_irs) << std::endl;
        ++ds_iter;
    }
    aut_o[1] = um_count;
    return um_count;
}


// um_flight = um_snd_nxt - um_snd_una
void m_cc_reno(ied_cce_event ie_cce_e, uint32 um_snd_smss, uint32 um_flight,
               uint32* aum_cwnd, uint32* aum_ssthresh, uint32* aum_bytes_acked)
{
    switch (ie_cce_e) {
    case ied_cce_init:
        *aum_cwnd = um_snd_smss; // may be up to 2 * um_snd_smss
        *aum_ssthresh = 65535; // arbitrary
        *aum_bytes_acked = 0;
        break;

    case ied_cce_newack:
        if (*aum_cwnd <= *aum_ssthresh) {
            // slow start
            //*aum_cwnd += um_snd_smss;
            // appropriate byte counting
            if (*aum_bytes_acked >= um_snd_smss) {
                *aum_bytes_acked -= um_snd_smss;
                *aum_cwnd += um_snd_smss;
                if (*aum_bytes_acked > um_snd_smss)
                    *aum_bytes_acked = um_snd_smss;
            }
        } else {
            // congestion avoidance
            // *aum_cwnd += (std::max)(uint32(1),
            //                       um_snd_smss * um_snd_smss / *aum_cwnd);
            // appropriate byte counting
            if (*aum_bytes_acked >= *aum_cwnd) {
                *aum_bytes_acked -= *aum_cwnd;
                *aum_cwnd += um_snd_smss;
            }
        }
        break;

    case ied_cce_timeout:
        *aum_ssthresh = (std::max)(um_flight / 2, 2 * um_snd_smss);
        *aum_cwnd = (std::min)(*aum_cwnd, um_snd_smss);
        break;

    case ied_cce_three_dup:
        *aum_ssthresh = (std::max)(um_flight / 2, 2 * um_snd_smss);
        *aum_cwnd = *aum_ssthresh + 3 * um_snd_smss;
        break;

    case ied_cce_more_dup:
        *aum_cwnd += um_snd_smss;
        break;

    case ied_cce_recover_ack:
        // *aum_cwnd = *aum_ssthresh;
        // New Reno improvement:
        *aum_cwnd = (std::min)(*aum_ssthresh, um_flight + um_snd_smss);
        break;

    default:
        // should not arrive here
        assert(false);
    }
}

void dsd_htcp_conn_internal::m_cc_init()
{
    am_cc_fun(ied_cce_init, um_snd_smss, um_snd_nxt - um_snd_una,
              &um_cwnd, &um_ssthresh, &um_bytes_acked);
}

void dsd_htcp_conn_internal::m_cc_newack()
{
    am_cc_fun(ied_cce_newack, um_snd_smss, um_snd_nxt - um_snd_una,
              &um_cwnd, &um_ssthresh, &um_bytes_acked);
}

void dsd_htcp_conn_internal::m_cc_timeout()
{
    am_cc_fun(ied_cce_timeout, um_snd_smss, um_snd_nxt - um_snd_una,
              &um_cwnd, &um_ssthresh, &um_bytes_acked);
}

void dsd_htcp_conn_internal::m_cc_three_dup()
{
    am_cc_fun(ied_cce_three_dup, um_snd_smss, um_snd_nxt - um_snd_una,
              &um_cwnd, &um_ssthresh, &um_bytes_acked);
    if (bo_use_sack) {
        // TODO: fix plugabbility of congestion control
        um_ssthresh = um_cwnd = (um_snd_nxt - um_snd_una) / 2;
    }
}

void dsd_htcp_conn_internal::m_cc_more_dup()
{
    am_cc_fun(ied_cce_more_dup, um_snd_smss, um_snd_nxt - um_snd_una,
              &um_cwnd, &um_ssthresh, &um_bytes_acked);
}

void dsd_htcp_conn_internal::m_cc_recover_ack()
{
    am_cc_fun(ied_cce_recover_ack, um_snd_smss, um_snd_nxt - um_snd_una,
              &um_cwnd, &um_ssthresh, &um_bytes_acked);
}

// void dsd_htcp_conn_internal::m_cc_init()
// {
//     um_cwnd = um_snd_smss; // may be up to 2 * um_snd_smss
//     um_ssthresh = 65535; // arbitrary
// }

// void dsd_htcp_conn_internal::m_cc_newack()
// {
//     if (um_cwnd <= um_ssthresh) {
//         // slow start
//         um_cwnd += um_snd_smss;
//     } else {
//         // congestion avoidance
//         um_cwnd += (std::max)(uint32(1), um_snd_smss * um_snd_smss / um_cwnd);
//     }
// }

// void dsd_htcp_conn_internal::m_cc_timeout()
// {
//     um_ssthresh = (std::max)((um_snd_nxt - um_snd_una) / 2, 2 * um_snd_smss);
//     um_cwnd = (std::min)(um_cwnd, um_snd_smss);
// }

// void dsd_htcp_conn_internal::m_cc_three_dup()
// {
//     um_ssthresh = (std::max)((um_snd_nxt - um_snd_una) / 2, 2 * um_snd_smss);
//     um_cwnd = um_ssthresh + 3 * um_snd_smss;
// }

// void dsd_htcp_conn_internal::m_cc_more_dup()
// {
//     um_cwnd += um_snd_smss;
// }

// void dsd_htcp_conn_internal::m_cc_recover_ack()
// {
//     um_cwnd = um_ssthresh;
// }
