/******************************************************************************
 * File name: connection.h
 *
 * HTCP connection internal representation. Depends on struct dsd_htcp_conn
 * defined in htcp.h
 *
 * Requires C++.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/

#ifndef HTCP_CONNECTION_H
#define HTCP_CONNECTION_H

#ifdef DOES_INCL_HEADERS
#include <map>
#include <list>
#include <cstddef>

#include "int_types.h"
#include "misc.h"
#include "htcp.h"
#include "tcpip_hdr.h"
#include "connection.h"
#include "hob-xslcontr.h"
#endif

// TODO: make configurable
static const uint32 um_in_bufsize = 131070; // initial receive window
static const uint32 um_in_mss = 1460;  // incoming maximum segment size
static const uint32 um_out_mss = 536; // default outgoing mss
static const uint32 um_msl_s = 30; // MSL used in calculation of timeouts
static const uint32 um_delay_ack_ms = 100; // delayed ACK timeout

enum ied_tcp_state_t {
    ied_htcp_closed,
    ied_htcp_listen,
//     ied_htcp_listen_sr,
    ied_htcp_syn_sent,
    ied_htcp_syn_rcvd,
    ied_htcp_established,
    ied_htcp_fin_wait_1,
    ied_htcp_fin_wait_2,
    ied_htcp_closing,
    ied_htcp_time_wait,
    ied_htcp_close_wait,
    ied_htcp_last_ack
};

struct dsd_buffer_node {
    void* vp_handle;
    char* ach_buffer;
    unsigned un_len;

    dsd_buffer_node(void* vp_h, char* ach_b, unsigned un_l)
        : vp_handle(vp_h),
          ach_buffer(ach_b),
          un_len(un_l)
    {}
};

inline dsd_buf_vector_ele m_make_buf_vector_ele(void* vp_h,
                                                char* ach_b, int in_l)
{
    dsd_buf_vector_ele ds_bve;
    ds_bve.ac_handle = vp_h;
    ds_bve.achc_data = ach_b;
    ds_bve.imc_len_data = in_l;
    return ds_bve;
}

inline bool m_wlt(uint32 um_a, uint32 um_b)
{
    return (um_a - um_b) >= 0x80000000U;
}

inline bool m_wle(uint32 um_a, uint32 um_b)
{
    return !m_wlt(um_b, um_a);
}

inline bool m_wgt(uint32 um_a, uint32 um_b)
{
    return m_wlt(um_b, um_a);
}

inline bool m_wge(uint32 um_a, uint32 um_b)
{
    return !m_wlt(um_a, um_b);
}

// check if lower <= x < upper ignoring wraparound
inline bool m_within(uint32 um_lower_inc, uint32 um_upper_exc, uint32 um_x)
{
    return um_x - um_lower_inc < um_upper_exc - um_lower_inc;
}

struct dsd_seq_compare {
    bool operator() (uint32 um_a, uint32 um_b) const
    {
        return m_wlt(um_a, um_b);
    }
};

struct dsd_send_packet_info {
    uint8* aby_header;
    unsigned un_head_len;
    dsd_gather_i_1* ads_payload;
    char* ach_plstart;
    unsigned un_total_len;
    dsd_send_packet_info(uint8* aby_h,
                         unsigned un_hl,
                         dsd_gather_i_1* ads_p,
                         char* ach_ps,
                         unsigned un_tl)
        : aby_header(aby_h),
          un_head_len(un_hl),
          ads_payload(ads_p),
          ach_plstart(ach_ps),
          un_total_len(un_tl)
    {
    }
};

class dsd_htcp_conn_internal;

struct dsd_ext_timer_ele {
    dsd_timer_ele ds_te;
    dsd_htcp_conn_internal* ads_ci;
};

struct dsd_oo_node {
    dsd_buf_vector_ele ds_ve;
    uint32 um_seq;
    dsd_oo_node(dsd_buf_vector_ele& ds_b, uint32 um_s)
        : ds_ve(ds_b),
          um_seq(um_s)
        {
        }
};

void m_hc_timer_callback(dsd_timer_ele* ads_hc_te);
void m_hc_da_timer_callback(dsd_timer_ele* ads_hc_te);

// congestion control interface

enum ied_htcp_cc_algorithm {
    ied_htcp_cc_newreno,
    ied_htcp_cc_cubic,
    ied_htcp_cc_compound,
    ied_htcp_cc_illinois
};

enum ied_cce_event {
    ied_cce_init,
    ied_cce_newack,
    ied_cce_timeout,
    ied_cce_three_dup,
    ied_cce_more_dup,
    ied_cce_recover_ack
};

typedef void (*am_cc_func)(ied_cce_event ie_cce_e,
                           uint32 um_snd_smss, uint32 um_flight,
                           uint32* aum_cwnd, uint32* aum_ssthresh,
                           uint32* aum_bytes_acked);

void m_cc_reno(ied_cce_event ie_cce_e, uint32 um_snd_smss, uint32 um_flight,
               uint32* aum_cwnd, uint32* aum_ssthresh, uint32* aum_bytes_acked);

class dsd_htcp_conn_internal {

public:

    dsd_htcp_conn_internal(dsd_htcp_conn* ads_c);
    dsd_htcp_conn_internal(dsd_htcp_conn* ads_c, tcp_segment& ds_synseg);
    ~dsd_htcp_conn_internal();

    uint32 m_send(dsd_gather_i_1* ads_data);
    uint32 m_recv(dsd_buf_vector_ele* ads_vec, unsigned* aun_count);
    void m_shutdown();
    void m_do_shutdown(); // TODO: make private
    void m_close();
    void m_reset();

    void m_active_open();

    void m_accept();
    void m_process_segment(dsd_buf_vector_ele* ads_buffers, unsigned un_count);

    void m_timeout();
    void m_da_timeout();

    // seq, ack, win, tcp checksum are not filled in, tcp flags set to 0
    // ut_opts_len should be multiple of 4, options area not initialized
    tcp_segment m_create_segment(uint16 us_data_len = 0, uint8 ut_opts_len = 0);

    void m_restart_rexmt_timer();
    void m_stop_timer();
    void m_restart_time_wait_timer();
    void m_start_da_timer();
    void m_stop_da_timer();
    bool m_da_timer_active();
    void m_send_segment(uint8* ach_header, unsigned un_headlen,
                        dsd_gather_i_1* ads_payload, char* ach_plstart,
                        unsigned un_tlen);
    void m_send_segments(std::list<dsd_send_packet_info>& ds_segments);
    void m_send_range(uint32 um_seq, uint32 um_len, bool bo_retime = true);
    uint32 m_send_available(uint32 um_force_send = 0);
    void m_send_acknowledgement();
    void m_send_reset(uint32 um_seq);
    void m_send_reset(uint32 um_seq, uint32 um_ack);
    void m_send_reset(uint32 um_seq, uint32 um_ack, uint32 um_tsecr);
    void m_send_syn();
    void m_send_synack();

    bool m_check_segment_seq(tcp_segment ds_segment);

//private:

    void m_construct(bool bo_received, tcp_segment* ads_synseg = 0);

    uint32 m_calc_win(uint32 um_w);
    uint32 m_decode_win(uint32 um_w);

    struct dsd_htcp_conn* ads_connection;

    ied_tcp_state_t ie_state;
    ied_tcp_state_t ie_prev_state;
    bool bo_closed_by_app;

    // output buffer first byte is um_snd_una
    // if ads_output_gather is 0,tail and tail_end may be undefined
    dsd_gather_i_1* ads_output_gather;
    dsd_gather_i_1* ads_output_gather_tail;
    char* ads_output_gather_tail_end;
#ifdef B100819
    std::list<dsd_gather_i_1> ds_output_gather;
    uint32 um_output_gather_remove;
#endif // B100819

    // input buffer last byte is just before um_rcv_nxt
    std::list<dsd_buf_vector_ele> ds_input_buffer;
    typedef std::list<dsd_buf_vector_ele>::iterator dsd_input_buffer_iterator;
    uint32 um_input_buffer_size;

    // out-of-order buffer
    // key: sequence number of first byte
    // value: data buffer
    // TODO: maybe map is overkill and list is better
//     std::map<uint32, dsd_buf_vector_ele, dsd_seq_compare> ds_oobuffer;
//     typedef std::map<uint32, dsd_buf_vector_ele, dsd_seq_compare>::iterator
    std::list<dsd_oo_node> ds_oobuffer;
    typedef std::list<dsd_oo_node>::iterator
    dsd_oobuffer_iterator;
    bool bo_oo_fin_received;
    uint32 um_oo_fin_seq;

    uint32 um_snd_una;
    uint32 um_snd_nxt;
    uint32 um_snd_wnd;
    uint32 um_snd_iss;
    uint32 um_snd_smss;
    uint32 um_last_ack_sent;

    uint32 um_rcv_nxt;
    uint32 um_rcv_wnd;
    uint32 um_rcv_irs;
    uint32 um_rcv_rmss;
    uint32 um_rcv_reduction;

    bool bo_use_sack;
    bool bo_use_winscale;
    bool bo_use_timestamp;
    uint32 um_snd_winscale;
    uint32 um_rcv_winscale;

    uint32 um_srtt_ms;
    uint32 um_rttvar_ms;
    uint32 um_rto_ms;
    uint32 um_ts_recent;
    int32 im_recent_age_s;
    uint32 um_last_update_ts;
    uint32 um_last_tsecr;

    dsd_duration ds_rtt_calc_time_sent;
    uint32 um_rtt_calc_seq_sent;
    bool bo_rtt_calc_valid;

    dsd_duration ds_syn_time; // for connecting timeout

    am_cc_func am_cc_fun;
    uint32 um_cwnd;
    uint32 um_ssthresh;
    uint32 um_bytes_acked;
    bool bo_recovering;
    bool bo_pack_time;
    uint32 um_recover;
    uint32 um_dack;
    uint32 um_exp_backoff;

    typedef std::pair<uint32, uint32> dsd_sack_pair;
    typedef std::list<dsd_sack_pair> dsd_sack_list;
    typedef dsd_sack_list::iterator dsd_sack_iterator;
    dsd_sack_list ds_snd_sack; // sent sack
    void m_update_snd_sack(uint32 um_seg_seq, uint32 um_len);
    dsd_sack_list ds_rcv_sack; // received sack
    uint32 um_sack_data_size;
    bool m_update_rcv_sack(uint32 um_seg_ack,
                           const uint8* aut_option_data, uint32 um_count);
    void m_update_sack_pipe();
    bool m_sack_nextseg(uint32& um_seq, uint32& um_len);
    uint32 um_recovery_point;
    uint32 um_sack_pipe;
    uint32 um_high_rxt; // beyond last highest retransmitted
    static const uint32 um_dup_thresh = 3;

    dsd_ext_timer_ele ds_timer;
    dsd_ext_timer_ele ds_da_timer;

    dsd_mutex_lock ds_lock;

    void m_rto_init();
    void m_rto_sending(uint32 um_seq, uint32 um_len);
    void m_rto_received();
    void m_rto_update();
    void m_rto_timestamp_update(uint32 um_seg_tsecr);
    uint32 m_create_timestamp();
    void m_create_timestamp_option(uint8* aut_o);
    uint32 m_sack_option_avail();
    uint32 m_sack_option_avail(uint32 um_max);
    uint32 m_create_sack_option(uint8* aut_o, uint32 um_avail);

    void m_cc_init();
    void m_cc_newack();
    void m_cc_timeout();
    void m_cc_three_dup();
    void m_cc_more_dup();
    void m_cc_recover_ack();

    // for WSP
    friend class dsd_htcp_session;

};

inline dsd_htcp_conn_internal* m_get_internal(dsd_htcp_conn* ads_conn)
{
    return static_cast<dsd_htcp_conn_internal*>(ads_conn->vp_internal);
}

inline void m_do_callback(dsd_htcp_conn* ads_conn, int in_code,
                          amd_htcp_conn_callback dsd_htcp_conn_callbacks::* cb)
{
    dsd_htcp_conn_callbacks* ads_cbs = ads_conn->ads_callbacks;
    if (ads_cbs == 0)
        return;
    if (ads_cbs->*cb == 0)
        return;
    (ads_cbs->*cb)(ads_conn, in_code);
}

#endif // HTCP_CONNECTION_H
