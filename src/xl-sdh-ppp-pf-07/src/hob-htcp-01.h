/******************************************************************************
 * File name: hob-htcp-01.h
 *
 * Interface for HTCP.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2011
 ******************************************************************************/

#ifndef HOB_HTCP_01_H
#define HOB_HTCP_01_H

#ifdef DEF_INCLUDE_HEADERS
#include "hob-htcp-int-01.h"
#include "hob-htcp-hdr-01.h"
#endif /* DEF_INCLUDE_HEADERS */

#ifdef __cplusplus
extern "C" {
#endif
#if 0
} /* so as not to confuse auto-indentation */
#endif

/*
 * output: direction from application to network
 * input: direction from network to application
 */

enum ied_htcp_close {
    ied_htcpc_open,
    ied_htcpc_normal,
    ied_htcpc_conn_refused,
    ied_htcpc_conn_timeout,
    ied_htcpc_conn_error,
    ied_htcpc_remote_reset,
    ied_htcpc_local_reset,
    ied_htcpc_error,
    ied_htcpc_interface_error,
    ied_htcpc_application_error
};

struct dsd_htcp_in_info {
    uint32_t umc_seq;
    uint32_t umc_len;
    uint32_t umc_offset;
    bool boc_push;
    struct dsd_htcp_in_info* adsc_next;
};

enum ied_htcp_cc_algorithm {
    ied_htcp_cca_newreno,
    ied_htcp_cca_cubic,
    ied_htcp_cca_compound,
    ied_htcp_cca_illinois
};

enum ied_htcp_cc_event {
    ied_htcp_cce_init,
    ied_htcp_cce_newack,
    ied_htcp_cce_timeout,
    ied_htcp_cce_three_dup,
    ied_htcp_cce_three_dup_sack,
    ied_htcp_cce_more_dup,
    ied_htcp_cce_recover_ack
};

struct dsd_htcp_cc_newreno {
    uint32_t umc_ssthresh;
};

struct dsd_htcp_cc_cubic {
    uint32_t umc_ssthresh;
    uint32_t umc_w_lastmax;
    int64_t ilc_epoch_start;
    uint32_t umc_origin_point;
    uint32_t umc_dmin;
    uint32_t umc_wtcp;
    uint32_t umc_k;
    uint32_t umc_ack_cnt;
};

union dsd_htcp_ucc {
    struct dsd_htcp_cc_newreno dsc_cc_newreno;
    struct dsd_htcp_cc_cubic dsc_cc_cubic;
};

struct dsd_htcp_cc {
    uint32_t umc_cwnd;
    uint32_t umc_bytes_acked;
    union dsd_htcp_ucc dsc_ucc;
};

typedef void (*amd_cc_func)(enum ied_htcp_cc_event iep_cce_e,
                            int64_t ilp_time, uint32_t ump_rtt_ms,
                            uint32_t ump_snd_smss, uint32_t ump_flight,
                            struct dsd_htcp_cc* adsp_cc);

struct dsd_htcp_config {
    uint32_t umc_in_bufsize; /* initial receive window */
    uint32_t umc_in_mss; /* incoming maximum segment size */
    uint32_t umc_out_mss_cap; /* outgoing maximum segment size cap */
    uint32_t umc_msl_s; /* MSL used in calculation of timeouts */
    uint32_t umc_delay_ack_ms; /* delayed ACK timeout */
    bool boc_sack; /* use selective acknowledgement option */
    bool boc_window_scaling; /* use window scaling option */
    bool boc_timestamp; /* use timestamp option */
    bool boc_out_chksum; /* generate output TCP checksum */
    bool boc_in_chksum; /* check input TCP checksum */
    enum ied_htcp_cc_algorithm iec_cc_algorithm; /* congestion control */
};

struct dsd_htcp_status {
    /* TODO: add more fields */
    uint32_t umc_out_queue_len;
    uint32_t umc_out_in_flight;
};

void m_htcp_init(struct dsd_htcp_conn* adsp_hc,
                 const struct dsd_htcp_config* adsp_hconf,
                 const struct dsd_htcp_callbacks* adsp_hcb,
                 uint16_t usp_pseudo_header_chksum,
                 uint16_t usp_local_port, uint16_t usp_remote_port);

void m_htcp_out_send(struct dsd_htcp_conn* adsp_hc,
                     uint32_t ump_len, bool bop_push, bool bop_eof);

void m_htcp_out_get_packet(struct dsd_htcp_conn* adsp_hc,
                           char* achp_header, uint32_t* aump_hlen,
                           uint32_t* aump_offset, uint32_t* aump_dlen,
                           bool* abop_more);

void m_htcp_in_packet(struct dsd_htcp_conn* adsp_hc,
                      struct dsd_htcp_in_info* adsp_hii,
                      uint32_t ump_tcp_len);

void m_htcp_in_get_data(struct dsd_htcp_conn* adsp_hc,
                        struct dsd_htcp_in_info** aadsp_hii,
                        uint32_t* aump_offset, uint32_t* aump_len,
                        bool* abop_push,
                        bool* abop_eof, bool* abop_more,
                        bool bop_throttle);

void m_htcp_timeout(struct dsd_htcp_conn* adsp_hc);

void m_htcp_abort(struct dsd_htcp_conn* adsp_hc, bool bop_reset);

void m_htcp_status(struct dsd_htcp_conn* adsp_hc,
                   struct dsd_htcp_status* adsp_hs);

void m_htcp_describe_close(struct dsd_htcp_conn* adsp_hc,
                           char* achp_description, uint32_t* aump_dlen,
                           char* achp_debug_info, uint32_t* aump_dilen);

struct dsd_htcp_callbacks {

    bool (*amc_out_get)(struct dsd_htcp_conn* adsp_hc,
                        uint32_t ump_offset,
                        const char** aachp_buf, uint32_t* aump_len);
    bool (*amc_out_packets)(struct dsd_htcp_conn* adsp_hc);
    bool (*amc_out_ack)(struct dsd_htcp_conn* adsp_hc, uint32_t ump_len);

    bool (*amc_in_get)(struct dsd_htcp_conn* adsp_hc,
                       struct dsd_htcp_in_info* adsp_hii,
                       uint32_t ump_offset,
                       const char** aachp_buf, uint32_t* aump_len);
    bool (*amc_in_more_data)(struct dsd_htcp_conn* adsp_hc);
    bool (*amc_in_rel)(struct dsd_htcp_conn* adsp_hc,
                       struct dsd_htcp_in_info* adsp_hii);

    bool (*amc_get_time)(struct dsd_htcp_conn* adsp_hc, int64_t* ailp_time);
    bool (*amc_set_timer)(struct dsd_htcp_conn* adsp_hc,
                          uint32_t ump_delay_ms);
    bool (*amc_rel_timer)(struct dsd_htcp_conn* adsp_hc);

    bool (*amc_lock)(struct dsd_htcp_conn* adsp_hc);
    bool (*amc_unlock)(struct dsd_htcp_conn* adsp_hc);

    bool (*amc_established)(struct dsd_htcp_conn* adsp_hc);
    void (*amc_closed)(struct dsd_htcp_conn* adsp_hc,
                       enum ied_htcp_close iep_htcpc);
};



extern const struct dsd_htcp_config dsg_htcp_default_config;


enum ied_tcp_state_t {
    ied_htcp_closed,
    ied_htcp_listen,
    ied_htcp_syn_sent,
    ied_htcp_syn_rcvd,
    ied_htcp_syn_sent_eof,
    ied_htcp_syn_rcvd_eof,
    ied_htcp_established,
    ied_htcp_fin_wait_1,
    ied_htcp_fin_wait_2,
    ied_htcp_closing,
    ied_htcp_time_wait,
    ied_htcp_close_wait,
    ied_htcp_last_ack
};

static const int ins_htcp_out_sack_count = 6;
static const int ins_dup_thresh = 3;

struct dsd_htcp_conn {

    enum ied_tcp_state_t iec_state;

    struct dsd_htcp_in_info* adsc_in_list;
    struct dsd_htcp_in_info* adsc_oo_list;
    struct dsd_htcp_in_info* adsc_sack_first;

    bool boc_oo_fin_received;
    uint32_t umc_oo_fin_seq;

    /* umc_snd_nxt:     highest octet sent
     * umc_snd_nxt_cur: after timeout, assume in flight octets are lost,
     *                  and sending is done here
     */
    uint32_t umc_snd_una;
    uint32_t umc_snd_nxt;
    uint32_t umc_snd_nxt_cur;
    uint32_t umc_snd_wnd;
    uint32_t umc_snd_iss;
    uint32_t umc_snd_smss;

    uint32_t umc_send_pending;
    uint32_t umc_out_send_recover_seq;
    bool boc_out_send_recover;

    uint32_t umc_rcv_nxt;
    uint32_t umc_rcv_wnd;
    uint32_t umc_rcv_irs;
    uint32_t umc_rcv_rmss;
    uint32_t umc_last_ack_sent;
    uint32_t umc_rcv_wnd_throttled;

    uint32_t umc_msl_s;
    uint32_t umc_delay_ack_ms;

    bool boc_use_sack;
    bool boc_use_winscale;
    bool boc_use_timestamp;
    uint32_t umc_snd_winscale;
    uint32_t umc_rcv_winscale;

    uint32_t umc_srtt_ms;
    uint32_t umc_rttvar_ms;
    uint32_t umc_rto_ms;
    uint32_t umc_ts_recent;
    int32_t imc_recent_age_s;
    uint32_t umc_last_update_ts;
    uint32_t umc_last_tsecr;

    int64_t ilc_rtt_calc_time_sent_ms;
    uint32_t umc_rtt_calc_seq_sent;
    bool boc_rtt_calc_valid;

    uint64_t ulc_syn_time_ms;

    amd_cc_func amc_cc_func;
    struct dsd_htcp_cc dsc_cc;
    bool boc_recovering;
    bool boc_pack_time;
    uint32_t umc_recover;
    uint32_t umc_dack;
    uint32_t umc_exp_backoff;

    uint32_t umrc_out_sack_left[ins_htcp_out_sack_count];
    uint32_t umrc_out_sack_right[ins_htcp_out_sack_count];
    uint32_t umc_out_sack_count;

    uint32_t umc_sack_data_size;
    uint32_t umc_recovery_point;
    uint32_t umc_sack_pipe;
    uint32_t umc_high_rxt; /* beyond last highest retransmitted */

    int64_t ilc_timer;
    int64_t ilc_da_timer;

    enum ied_htcp_close iec_htcpc;
    const char* achc_close_reason;
    int inc_close_line;

    uint16_t usc_local_port;
    uint16_t usc_remote_port;
    uint16_t usc_pseudo_header_chksum;
    bool boc_out_chksum;
    bool boc_in_chksum;
    const struct dsd_htcp_callbacks* adsc_cb;

    /*
     * umc_packet_seq used for SYN/RST/recover packets:
     * during syn or after rst, recover should not be invoked
     *
     * umc_packet_ack used only for RST
     */
    bool boc_out_packet_promised;
    bool boc_zwnd_probe;
    bool boc_recover_packet;
    uint8_t utc_packet_flags;
    uint32_t umc_packet_seq;
    uint32_t umc_packet_ack;
    uint32_t umc_limited_transmit;
    uint32_t umc_tosend_dack;
    uint32_t umc_pending_dacks;
};

#if 0
{ /* so as not to confuse auto-indentation */
#endif
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !HOB_HTCP_01_H */
