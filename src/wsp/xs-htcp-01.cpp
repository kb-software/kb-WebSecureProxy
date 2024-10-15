/******************************************************************************
 * File name: xs-htcp-01.cpp
 *
 * Implementation for HTCP
 *
 * Author: Kevin Spiteri
 *         Miguel Loureiro
 * Copyright: Copyright (c) HOB Software 2011
 * Copyright: Copyright (c) HOB Software 2015
 ******************************************************************************/

// unacked zero window probe should not lead to retransmission in next packet
// (would not be sent out, because send window is still zero)
// but to another zero window probe.
// also rto timebase reset to 1s on every zero window probe.
#define TRY_131219

#include <stdio.h>

#ifdef _MSC_VER
#pragma warning(disable: 4996)
#include <stdarg.h>

static int snprintf(char* achp_str, size_t upp_size,
                    const char* achp_format, ...)
{
    va_list ap;
    int inl_ret;

    if (achp_str != NULL && upp_size > 0) {
        va_start(ap, achp_format);
        inl_ret = _vsnprintf(achp_str, upp_size, achp_format, ap);
        va_end(ap);

        if (inl_ret != -1 && inl_ret != (int)upp_size)
            return inl_ret;

        achp_str[upp_size - 1] = '\0';
    }

    va_start(ap, achp_format);
    inl_ret = _vscprintf(achp_format, ap);
    va_end(ap);

    return inl_ret;
}
#endif /* _MSC_VER */

#ifndef DEF_INCLUDE_HEADERS
#define DEF_INCLUDE_HEADERS
#endif /* !DEF_INCLUDE_HEADERS */

#include "hob-htcp-int-01.h"
#include "hob-htcp-hdr-01.h"
#include "hob-htcp-01.h"


// Internal functions return bool. If an error occured and the connection was
// terminated, the function returns false. Otherwise the function returns true.
//
// Some functions are called from inside a critical section. In such cases, the
// function name starts with "m_locked_". If an error occurs, the function
// leaves the critical section before returning false. The "m_locked_" functions
// do not leave the critical section unless an error that causes connection
// termination occurs.
//
// The function m_unlock_do_sendavail_or_remove() is called from inside a
// critical section. The function may leave the critical section to do some
// callbacks and reacquire the critical section. The function finally leaves
// the critical section before returning.


#ifdef HTCP_NCHECK_LOCK

#define HTCP_LOCK      (adsp_hc->adsc_cb->amc_lock(adsp_hc))
#define HTCP_LOCK_F    HTCP_LOCK
#define HTCP_UNLOCK    (adsp_hc->adsc_cb->amc_unlock(adsp_hc))
#define HTCP_UNLOCK_F  HTCP_UNLOCK

#else // !HTCP_NCHECK_LOCK

#define HTCP_LOCK                                               \
    do {                                                        \
        if (!adsp_hc->adsc_cb->amc_lock(adsp_hc)) {             \
            m_do_abort(adsp_hc, ied_htcpc_application_error,    \
                       __LINE__, "amc_lock() failed");          \
            return;                                             \
        }                                                       \
    } while (0)

#define HTCP_LOCK_F                                             \
    do {                                                        \
        if (!adsp_hc->adsc_cb->amc_lock(adsp_hc)) {             \
            m_do_abort(adsp_hc, ied_htcpc_application_error,    \
                       __LINE__, "amc_lock() failed");          \
            return false;                                       \
        }                                                       \
    } while (0)

#define HTCP_UNLOCK                                             \
    do {                                                        \
        if (!adsp_hc->adsc_cb->amc_unlock(adsp_hc)) {           \
            m_do_abort(adsp_hc, ied_htcpc_application_error,    \
                       __LINE__, "amc_unlock() failed");        \
            return;                                             \
        }                                                       \
    } while (0)

#define HTCP_UNLOCK_F                                           \
    do {                                                        \
        if (!adsp_hc->adsc_cb->amc_unlock(adsp_hc)) {           \
            m_do_abort(adsp_hc, ied_htcpc_application_error,    \
                       __LINE__, "amc_unlock() failed");        \
            return false;                                       \
        }                                                       \
    } while (0)

#endif // !HTCP_NCHECK_LOCK


#define HTCP_ERROR(t)                                           \
    do {                                                        \
        m_do_abort(adsp_hc, ied_htcpc_error, __LINE__, (t));    \
        return;                                                 \
    } while (0)

#define HTCP_ERROR_F(t)                                         \
    do {                                                        \
        m_do_abort(adsp_hc, ied_htcpc_error, __LINE__, (t));    \
        return false;                                           \
    } while (0)

#define HTCP_LOCKED_ERROR(t)                                    \
    do {                                                        \
        adsp_hc->adsc_cb->amc_unlock(adsp_hc);                  \
        m_do_abort(adsp_hc, ied_htcpc_error, __LINE__, (t));    \
        return;                                                 \
    } while (0)

#define HTCP_LOCKED_ERROR_F(t)                                  \
    do {                                                        \
        adsp_hc->adsc_cb->amc_unlock(adsp_hc);                  \
        m_do_abort(adsp_hc, ied_htcpc_error, __LINE__, (t));    \
        return false;                                           \
    } while (0)


#ifdef NDEBUG

#define HTCP_ASSERT(a)                 do {} while (0)
#define HTCP_ASSERT_F(a)               do {} while (0)
#define HTCP_LOCKED_ASSERT(a)          do {} while (0)
#define HTCP_LOCKED_ASSERT_F(a)        do {} while (0)

#else // !NDEBUG

#define HTCP_ASSERT(a)                                          \
    do {                                                        \
        if (!(a)) {                                             \
            m_do_abort(adsp_hc, ied_htcpc_error, __LINE__,      \
                       "assertion (" #a ") failed");            \
            return;                                             \
        }                                                       \
    } while (0)

#define HTCP_ASSERT_F(a)                                        \
    do {                                                        \
        if (!(a)) {                                             \
            m_do_abort(adsp_hc, ied_htcpc_error, __LINE__,      \
                       "assertion (" #a ") failed");            \
            return false;                                       \
        }                                                       \
    } while (0)

#define HTCP_LOCKED_ASSERT(a)                                   \
    do {                                                        \
        if (!(a)) {                                             \
            adsp_hc->adsc_cb->amc_unlock(adsp_hc);              \
            m_do_abort(adsp_hc, ied_htcpc_error, __LINE__,      \
                       "assertion (" #a ") failed");            \
            return;                                             \
        }                                                       \
    } while (0)

#define HTCP_LOCKED_ASSERT_F(a)                                 \
    do {                                                        \
        if (!(a)) {                                             \
            adsp_hc->adsc_cb->amc_unlock(adsp_hc);              \
            m_do_abort(adsp_hc, ied_htcpc_error, __LINE__,      \
                       "assertion (" #a ") failed");            \
            return false;                                       \
        }                                                       \
    } while (0)

#endif // !NDEBUG


#define HTCP_TEST(a, t)                                         \
    do {                                                        \
        if (!(a)) {                                             \
            m_do_abort(adsp_hc, ied_htcpc_conn_error, __LINE__, \
                       t);                                      \
            return;                                             \
        }                                                       \
    } while (0)

#define HTCP_TEST_F(a, t)                                       \
    do {                                                        \
        if (!(a)) {                                             \
            m_do_abort(adsp_hc, ied_htcpc_conn_error, __LINE__, \
                       t);                                      \
            return false;                                       \
        }                                                       \
    } while (0)

#define HTCP_LOCKED_TEST(a, t)                                  \
    do {                                                        \
        if (!(a)) {                                             \
            adsp_hc->adsc_cb->amc_unlock(adsp_hc);              \
            m_do_abort(adsp_hc, ied_htcpc_conn_error, __LINE__, \
                       t);                                      \
            return;                                             \
        }                                                       \
    } while (0)

#define HTCP_LOCKED_TEST_F(a, t)                                \
    do {                                                        \
        if (!(a)) {                                             \
            adsp_hc->adsc_cb->amc_unlock(adsp_hc);              \
            m_do_abort(adsp_hc, ied_htcpc_conn_error, __LINE__, \
                       t);                                      \
            return false;                                       \
        }                                                       \
    } while (0)


#define HTCP_CHECK_CB_RET(t)                                    \
    do {                                                        \
        if (!bol_ret) {                                         \
            m_do_abort(adsp_hc, ied_htcpc_application_error,    \
                       __LINE__, #t "() failed");               \
            return;                                             \
        }                                                       \
    } while (0)

#define HTCP_CHECK_CB_RET_F(t)                                  \
    do {                                                        \
        if (!bol_ret) {                                         \
            m_do_abort(adsp_hc, ied_htcpc_application_error,    \
                       __LINE__, #t "() failed");               \
            return false;                                       \
        }                                                       \
    } while (0)

#define HTCP_LOCKED_CHECK_CB_RET(t)                             \
    do {                                                        \
        if (!bol_ret) {                                         \
            adsp_hc->adsc_cb->amc_unlock(adsp_hc);              \
            m_do_abort(adsp_hc, ied_htcpc_application_error,    \
                       __LINE__, #t "() failed");               \
            return;                                             \
        }                                                       \
    } while (0)

#define HTCP_LOCKED_CHECK_CB_RET_F(t)                           \
    do {                                                        \
        if (!bol_ret) {                                         \
            adsp_hc->adsc_cb->amc_unlock(adsp_hc);              \
            m_do_abort(adsp_hc, ied_htcpc_application_error,    \
                       __LINE__, #t "() failed");               \
            return false;                                       \
        }                                                       \
    } while (0)


static void m_cc_newreno(enum ied_htcp_cc_event iep_cce_e,
                         int64_t ilp_time, uint32_t ump_rtt_ms,
                         uint32_t ump_snd_smss, uint32_t ump_flight,
                         struct dsd_htcp_cc* adsp_cc);

static void m_cc_cubic(enum ied_htcp_cc_event iep_cce_e,
                       int64_t ilp_time, uint32_t ump_rtt_ms,
                       uint32_t ump_snd_smss, uint32_t ump_flight,
                       struct dsd_htcp_cc* adsp_cc);

/*
 * m_do_close() should be called exactly once
 * m_do_abort() may be called once, more than once, or not at all
 * IMPORTANT:
 * achp_why MUST remain valid until any m_htcp_describe_close() call is done.
 * achp_why MAY be NULL.
 * achp_why MAY point to a string literal.
 * achp_why SHOULD NOT be on the stack.
 */
static void m_do_close(struct dsd_htcp_conn* adsp_hc,
                       enum ied_htcp_close iep_htcpc,
                       int inp_line, const char* achp_why);
static void m_do_abort(struct dsd_htcp_conn* adsp_hc,
                       enum ied_htcp_close iep_htcpc,
                       int inp_line, const char* achp_why);

static void m_rto_init(struct dsd_htcp_conn* adsp_hc);
static bool m_locked_rto_sending(struct dsd_htcp_conn* adsp_hc,
                                 int64_t ilp_now_ms,
                                 uint32_t ump_seq, uint32_t ump_len);
static bool m_locked_rto_received(struct dsd_htcp_conn* adsp_hc,
                                  int64_t ilp_now_ms);
static bool m_locked_rto_timestamp_update(struct dsd_htcp_conn* adsp_hc,
                                          int64_t ilp_now_ms,
                                          uint32_t ump_seg_tsecr);

static bool m_locked_process_syn_options(struct dsd_htcp_conn* adsp_hc,
                                         const char* achp_tcp_header,
                                         uint32_t ump_hlen);

static bool m_locked_create_timestamp_option(struct dsd_htcp_conn* adsp_hc,
                                             char* achp_o,
                                             int64_t ilp_now_ms);

static bool m_update_timer(struct dsd_htcp_conn* adsp_hc,
                           int64_t ilp_now_ms, int64_t ilp_timer);

static bool m_locked_stop_timer(struct dsd_htcp_conn* adsp_hc,
                                bool* abop_update, int64_t* ailp_update_timer,
                                int64_t* ailp_timer, int64_t ilp_other);

static bool m_locked_start_timer(struct dsd_htcp_conn* adsp_hc,
                                 bool* abop_update, int64_t* ailp_update_timer,
                                 int64_t* ailp_timer, int64_t ilp_new_time,
                                 int64_t ilp_other);

static bool m_locked_restart_rexmt_timer(struct dsd_htcp_conn* adsp_hc,
                                         bool* abop_update,
                                         int64_t* ailp_update_timer,
                                         int64_t ilp_now_ms);
static bool m_locked_restart_time_wait_timer(struct dsd_htcp_conn* adsp_hc,
                                             bool* abop_update,
                                             int64_t* ailp_update_timer,
                                             int64_t ilp_now_ms);


static bool m_locked_start_da_timer(struct dsd_htcp_conn* adsp_hc,
                                    bool* abop_update,
                                    int64_t* ailp_update_timer,
                                    int64_t ilp_now_ms);

static bool m_locked_stop_da_timer(struct dsd_htcp_conn* adsp_hc,
                                   bool* abop_update,
                                   int64_t* ailp_update_timer);

static bool m_locked_update_rcv_sack(struct dsd_htcp_conn* adsp_hc,
                                     uint32_t ump_ack,
                                     const char* achp_option_data,
                                     int32_t imp_option_count);


static bool m_locked_update_sack_pipe(struct dsd_htcp_conn* adsp_hc);

static bool m_locked_sack_nextseg(struct dsd_htcp_conn* adsp_hc,
                                  bool* abop_segment, uint32_t* aump_seq);

static bool m_locked_create_sack_option(struct dsd_htcp_conn* adsp_hc,
                                        char* achp_o, uint32_t* aump_len);

static bool m_locked_start_header(struct dsd_htcp_conn* adsp_hc,
                                  char* achp_header, uint32_t* aump_hlen,
                                  uint8_t utp_flags, uint16_t usp_urg,
                                  int64_t ilp_now_ms);

static bool m_locked_prepare_syn(struct dsd_htcp_conn* adsp_hc,
                                 char* achp_header, uint32_t* aump_hlen,
                                 bool bop_ack, int64_t ilp_now_ms);

static bool m_locked_packets_available(struct dsd_htcp_conn* adsp_hc,
                                       bool* abop_available);

static bool m_send_rst(struct dsd_htcp_conn* adsp_hc,
                       uint32_t ump_seq_or_ack, bool bop_ack);

static inline bool m_wlt(uint32_t ump_x, uint32_t ump_y)
{
    return (ump_x - ump_y) >= 0x80000000U;
}

static inline bool m_wle(uint32_t ump_x, uint32_t ump_y)
{
    return !m_wlt(ump_y, ump_x);
}

static inline bool m_wgt(uint32_t ump_x, uint32_t ump_y)
{
    return m_wlt(ump_y, ump_x);
}

static inline bool m_wge(uint32_t ump_x, uint32_t ump_y)
{
    return !m_wlt(ump_x, ump_y);
}

// check if low <= x < hi ignoring wraparound
static inline
bool m_within(uint32_t ump_low_inc, uint32_t ump_hi_exc, uint32_t ump_x)
{
    return ump_x - ump_low_inc < ump_hi_exc - ump_low_inc;
}

static inline uint16_t m_get_16_bit(const char* achp_p)
{
    return ((uint8_t)achp_p[0] << 8) |
      (uint8_t)achp_p[1];
}

static inline uint32_t m_get_32_bit(const char* achp_p)
{
    return ((uint8_t)achp_p[0] << 24) | ((uint8_t)achp_p[1] << 16) |
      ((uint8_t)achp_p[2] << 8) | (uint8_t)achp_p[3];
}

static inline void m_put_16_bit(char* achp_p, uint16_t usp_x)
{
    achp_p[0] = usp_x >> 8;
    achp_p[1] = usp_x;
}

static inline void m_put_32_bit(char* achp_p, uint32_t ump_x)
{
    achp_p[0] = ump_x >> 24;
    achp_p[1] = ump_x >> 16;
    achp_p[2] = ump_x >> 8;
    achp_p[3] = ump_x;
}

const struct dsd_htcp_config dsg_htcp_default_config = {
    131070, // umc_in_bufsize
    1360, // umc_in_mss
    1360, // umc_out_mss_cap
	60, // umc_msl_s
    100, // umc_delay_ack_ms
    true, // boc_sack
    true, // boc_window_scaling
    true, // boc_timestamp
    ied_htcp_cca_cubic // iec_cc_algorithm
};



void m_htcp_init(struct dsd_htcp_conn* adsp_hc,
                 const struct dsd_htcp_config* adsp_hconf,
                 const struct dsd_htcp_callbacks* adsp_hcb,
                 uint16_t usp_pseudo_header_chksum,
                 uint16_t usp_local_port, uint16_t usp_remote_port)
{
    int64_t ilc_time;
    uint8_t utl_hash;
    bool bol_ret;
    uint32_t uml_maxwin;

    adsp_hc->adsc_cb = adsp_hcb;

    bol_ret = adsp_hc->adsc_cb->amc_get_time(adsp_hc, &ilc_time);
    HTCP_CHECK_CB_RET(amc_get_time);

    if (adsp_hconf == NULL)
        adsp_hconf = &dsg_htcp_default_config;

    adsp_hc->usc_local_port = usp_local_port;
    adsp_hc->usc_remote_port = usp_remote_port;
    adsp_hc->usc_pseudo_header_chksum = usp_pseudo_header_chksum;

    adsp_hc->iec_state = ied_htcp_listen;

    adsp_hc->adsc_in_list = NULL;
    adsp_hc->adsc_oo_list = NULL;
    adsp_hc->adsc_sack_first = NULL;
    adsp_hc->boc_oo_fin_received = false;

    // hash does not really help - stale connections that might be detected
    // by different iss would have same hash
    utl_hash = usp_pseudo_header_chksum;
    utl_hash ^= usp_pseudo_header_chksum >> 8;
    utl_hash ^= usp_local_port;
    utl_hash ^= usp_local_port >> 8;
    utl_hash ^= usp_remote_port;
    utl_hash ^= usp_remote_port >> 8;
    adsp_hc->umc_snd_iss = (ilc_time << 8) | utl_hash;

    adsp_hc->umc_snd_una = adsp_hc->umc_snd_iss;
    adsp_hc->umc_snd_nxt = adsp_hc->umc_snd_iss + 1;
    adsp_hc->umc_snd_nxt_cur = adsp_hc->umc_snd_nxt;
    adsp_hc->umc_snd_wnd = 0;
    adsp_hc->umc_snd_smss = adsp_hconf->umc_out_mss_cap;
    if (adsp_hc->umc_snd_smss < 536)
        adsp_hc->umc_snd_smss = 536;
    if (adsp_hc->umc_snd_smss > 65495)
        adsp_hc->umc_snd_smss = 65495;

    adsp_hc->umc_rcv_rmss = adsp_hconf->umc_in_mss;
    if (adsp_hc->umc_rcv_rmss < 536)
        adsp_hc->umc_rcv_rmss = 536;
    if (adsp_hc->umc_rcv_rmss > 65495)
        adsp_hc->umc_rcv_rmss = 65495;

    adsp_hc->umc_rcv_wnd = adsp_hconf->umc_in_bufsize;
    adsp_hc->umc_rcv_wnd_throttled = 0;

    adsp_hc->umc_delay_ack_ms = adsp_hconf->umc_delay_ack_ms;

#ifndef ML150430
    adsp_hc->umc_msl_s = adsp_hconf->umc_msl_s;
#endif

    adsp_hc->boc_use_sack = adsp_hconf->boc_sack;
    adsp_hc->boc_use_winscale = adsp_hconf->boc_window_scaling;
    adsp_hc->boc_use_timestamp = false; // SYN packet starts timing
    adsp_hc->boc_use_timestamp = adsp_hconf->boc_timestamp;

    adsp_hc->umc_ts_recent = 0;

    if (adsp_hc->boc_use_winscale) {
        uml_maxwin = 0xffff;
        for (adsp_hc->umc_rcv_winscale = 0;
             adsp_hc->umc_rcv_winscale < 14;
             ++adsp_hc->umc_rcv_winscale) {

            if (uml_maxwin >= adsp_hconf->umc_in_bufsize)
                break;
            uml_maxwin <<= 1;
        }
    }
    adsp_hc->umc_snd_winscale = 0;

    m_rto_init(adsp_hc);

    switch (adsp_hconf->iec_cc_algorithm) {
    case ied_htcp_cca_newreno:
        adsp_hc->amc_cc_func = m_cc_newreno;
        break;

    case ied_htcp_cca_cubic:
        adsp_hc->amc_cc_func = m_cc_cubic;
        break;

        // TODO: add more congestion control functions

    default:
        adsp_hc->amc_cc_func = m_cc_newreno;
    }
    // amc_cc_func(ied_htcp_cce_init, ...) is called after
    // receiving SYN because of MSS

    adsp_hc->umc_out_sack_count = 0;

    adsp_hc->umc_dack = 0;
    adsp_hc->boc_recovering = false;
    adsp_hc->umc_sack_data_size = 0;
    adsp_hc->umc_recover = adsp_hc->umc_snd_iss;
    adsp_hc->umc_high_rxt = adsp_hc->umc_snd_iss; // TODO: check
    adsp_hc->umc_exp_backoff = 1;

    adsp_hc->ilc_timer = 0;
    adsp_hc->ilc_da_timer = 0;

    adsp_hc->iec_htcpc = ied_htcpc_open;
    adsp_hc->achc_close_reason = NULL;
    adsp_hc->inc_close_line = 0;

    adsp_hc->umc_send_pending = 0;
    adsp_hc->boc_out_send_recover = false;

    adsp_hc->boc_out_packet_promised = false;
    adsp_hc->boc_zwnd_probe = false;
    adsp_hc->boc_recover_packet = false;
    adsp_hc->utc_packet_flags = 0;
    adsp_hc->umc_limited_transmit = 0;
    adsp_hc->umc_tosend_dack = 0;
    adsp_hc->umc_pending_dacks = 0;
}

void m_htcp_out_send(struct dsd_htcp_conn* adsp_hc,
                     uint32_t ump_len, bool bop_push, bool bop_eof)
{
    bool bol_send_notify = false;
    bool bol_incorrect_state = false;
    int64_t ill_now_ms;
    bool bol_ret;

    // TODO: use bop_push
    // currently it is always treated as true
    // if we can treat it as false, we must timeout to send data anyway

    bol_ret = adsp_hc->adsc_cb->amc_get_time(adsp_hc, &ill_now_ms);
    HTCP_CHECK_CB_RET(amc_get_time);

    HTCP_LOCK;

    switch (adsp_hc->iec_state) {
    case ied_htcp_closed:
        break;

    case ied_htcp_listen:
        HTCP_LOCKED_ASSERT(m_get_tcp_flags_rst(adsp_hc->utc_packet_flags) == 0);
        adsp_hc->utc_packet_flags = utd_tcp_syn;
        adsp_hc->umc_send_pending += ump_len;
        if (bop_eof)
            adsp_hc->iec_state = ied_htcp_syn_sent_eof;
        else
            adsp_hc->iec_state = ied_htcp_syn_sent;
        break;

    case ied_htcp_syn_sent:
        adsp_hc->umc_send_pending += ump_len;
        if (bop_eof)
            adsp_hc->iec_state = ied_htcp_syn_sent_eof;
        break;

    case ied_htcp_syn_rcvd:
        adsp_hc->umc_send_pending += ump_len;
        if (bop_eof)
            adsp_hc->iec_state = ied_htcp_syn_rcvd_eof;
        break;

    case ied_htcp_established:
        adsp_hc->umc_send_pending += ump_len;
        if (bop_eof)
            adsp_hc->iec_state = ied_htcp_fin_wait_1;
        break;

    case ied_htcp_close_wait:
        adsp_hc->umc_send_pending += ump_len;
        if (bop_eof)
            adsp_hc->iec_state = ied_htcp_last_ack;
        break;

    default:
        // eof already received or connection closed, should not receive data
        if (ump_len > 0) {
            adsp_hc->iec_state = ied_htcp_closed;
            bol_incorrect_state = true;
        }
    }

    bol_send_notify = false;
    if (!adsp_hc->boc_out_packet_promised) {
        bol_ret = m_locked_packets_available(adsp_hc, &bol_send_notify);
        if (!bol_ret)
            return;
        adsp_hc->boc_out_packet_promised = bol_send_notify;
    }

    HTCP_UNLOCK;

    if (bol_send_notify) {
        bol_ret = adsp_hc->adsc_cb->amc_out_packets(adsp_hc);
        HTCP_CHECK_CB_RET(amc_out_packets);
    }

    if (bol_incorrect_state) {
        m_do_close(adsp_hc, ied_htcpc_interface_error, __LINE__,
                   "m_htcp_out_send() call not expected");
        return;
    }
}

static bool m_check_packet(struct dsd_htcp_conn* adsp_hc,
                           struct dsd_htcp_in_info* adsp_hii,
                           uint32_t ump_tcp_len,
                           bool* abop_packet_ok,
                           uint32_t* aump_hlen,
                           char* achp_header,
                           const char** aachp_header)
{
    bool bol_ret;
    const char* achl_part_buf;
    uint32_t uml_part_len;
    uint32_t uml_hofs;
    uint16_t usl_chksum;
    uint32_t uml_len;

    // check if segment too short
    if (ump_tcp_len < 20) {
        bol_ret = adsp_hc->adsc_cb->amc_in_rel(adsp_hc, adsp_hii);
        HTCP_CHECK_CB_RET_F(amc_in_rel);
        *abop_packet_ok = false;
        return true;
    }

    // get header (or first part of it)
    bol_ret = adsp_hc->adsc_cb->
        amc_in_get(adsp_hc, adsp_hii, 0, &achl_part_buf, &uml_part_len);
    HTCP_CHECK_CB_RET_F(amc_in_get);

    // calculate header length if header available
    if (uml_part_len < 20) {
        *aump_hlen = 20;
    } else {
        *aump_hlen = m_get_calc_tcp_hlen(achl_part_buf);
        // check if segment shorter than header or invalid header length
        if (ump_tcp_len < *aump_hlen || *aump_hlen < 20) {
            bol_ret = adsp_hc->adsc_cb->amc_in_rel(adsp_hc, adsp_hii);
            HTCP_CHECK_CB_RET_F(amc_in_rel);
            *abop_packet_ok = false;
            return true;
        }
    }

    if (uml_part_len < *aump_hlen) {
        // copy fragmented header

        memcpy(achp_header, achl_part_buf, uml_part_len);
        uml_hofs = uml_part_len;
        do {
            // get next part of header
            bol_ret = adsp_hc->adsc_cb->
                amc_in_get(adsp_hc, adsp_hii, uml_hofs,
                           &achl_part_buf, &uml_part_len);
            HTCP_CHECK_CB_RET_F(amc_in_get);

            // can we calculate header length?
            if (uml_hofs < 20 && uml_hofs + uml_part_len >= 20) {
                // update *aump_hlen
                memcpy(achp_header + uml_hofs, achl_part_buf, 20 - uml_hofs);
                achl_part_buf += 20 - uml_hofs;
                uml_part_len -= 20 - uml_hofs;
                uml_hofs = 20;
                *aump_hlen = m_get_calc_tcp_hlen(achl_part_buf);
                // check if segment shorter than header or invalid header length
                if (ump_tcp_len < *aump_hlen || *aump_hlen < 20) {
                    bol_ret = adsp_hc->adsc_cb->amc_in_rel(adsp_hc, adsp_hii);
                    HTCP_CHECK_CB_RET_F(amc_in_rel);
                    *abop_packet_ok = false;
                    return true;
                }
            }

            if (uml_hofs + uml_part_len > *aump_hlen)
                uml_len = *aump_hlen - uml_hofs;
            else
                uml_len = uml_part_len;
            memcpy(achp_header + uml_hofs, achl_part_buf, uml_len);
            uml_hofs += uml_len;
        } while (uml_hofs < *aump_hlen);

        *aachp_header = achp_header;
        achl_part_buf += uml_len;
        uml_part_len -= uml_len;
    } else {
        *aachp_header = achl_part_buf;
        achl_part_buf += *aump_hlen;
        uml_part_len -= *aump_hlen;
    }

    // check ports
    if (m_get_tcp_src_port(*aachp_header) != adsp_hc->usc_remote_port ||
        m_get_tcp_dst_port(*aachp_header) != adsp_hc->usc_local_port) {

        bol_ret = adsp_hc->adsc_cb->amc_in_rel(adsp_hc, adsp_hii);
        HTCP_CHECK_CB_RET_F(amc_in_rel);
        *abop_packet_ok = false;
        return true;
    }

    // check checksum
    usl_chksum = adsp_hc->usc_pseudo_header_chksum;
    uml_len = *aump_hlen;
    while (uml_len < ump_tcp_len) {
        if (uml_len != *aump_hlen || uml_part_len == 0) {
            bol_ret = adsp_hc->adsc_cb->
                amc_in_get(adsp_hc, adsp_hii, uml_len,
                           &achl_part_buf, &uml_part_len);
            HTCP_CHECK_CB_RET_F(amc_in_get);
        }

        if (uml_len + uml_part_len > ump_tcp_len)
            uml_part_len = ump_tcp_len - uml_len;

        if (uml_len % 2 == 0) {
            usl_chksum = m_calc_tcp_data_chksum(achl_part_buf,
                                                uml_part_len,
                                                usl_chksum);
        } else {
            usl_chksum = m_calc_tcp_odd_data_chksum(achl_part_buf,
                                                    uml_part_len,
                                                    usl_chksum);
        }

        uml_len += uml_part_len;
    }

    if (m_calc_tcp_chksum(*aachp_header, ump_tcp_len - *aump_hlen, usl_chksum)
        != m_get_tcp_chksum(*aachp_header)) {

        bol_ret = adsp_hc->adsc_cb->amc_in_rel(adsp_hc, adsp_hii);
        HTCP_CHECK_CB_RET_F(amc_in_rel);
        *abop_packet_ok = false;
        return true;
    }

    *abop_packet_ok = true;
    return true;
}

static void m_do_htcp_in_packet(struct dsd_htcp_conn* adsp_hc,
                                struct dsd_htcp_in_info* adsp_hii,
                                uint32_t ump_tcp_len,
                                struct dsd_htcp_in_info** aadsp_to_del);

void m_htcp_in_packet(struct dsd_htcp_conn* adsp_hc,
                      struct dsd_htcp_in_info* adsp_hii,
                      uint32_t ump_tcp_len)
{
    struct dsd_htcp_in_info* adsl_to_del = NULL;
    struct dsd_htcp_in_info* adsl_hii;

    m_do_htcp_in_packet(adsp_hc, adsp_hii, ump_tcp_len, &adsl_to_del);

    while (adsl_to_del != NULL) {
        adsl_hii = adsl_to_del;
        adsl_to_del = adsl_to_del->adsc_next;
        /*
         * Do not check for errors when realeasing:
         * if freeing here, the connection was terminated anyway.
         */
        adsp_hc->adsc_cb->amc_in_rel(adsp_hc, adsl_hii);
    }
}

static void m_do_htcp_in_packet(struct dsd_htcp_conn* adsp_hc,
                                struct dsd_htcp_in_info* adsp_hii,
                                uint32_t ump_tcp_len,
                                struct dsd_htcp_in_info** aadsp_to_del)
{
    bool bol_packet_ok;

    uint32_t uml_seq;
    uint32_t uml_ack;
    uint32_t uml_win;
    uint32_t uml_dlen;
    uint8_t utl_flags;
    char chrl_header[60];
    uint32_t uml_hlen;
    const char* achl_header;
    uint32_t uml_len;
    int64_t ill_now_ms;

    bool bol_invalid;
    bool bol_fin;
    bool bol_just_ack;
    bool bol_ret;
    const char* achl_option;
    const char* achl_ts_option;
    const char* achl_sack_option;
    uint32_t uml_sack_option_count;
    uint32_t uml_seg_tsval;
    uint32_t uml_seg_tsecr;
    uint32_t uml_acked_len;
    struct dsd_htcp_in_info* adsl_hii;
    struct dsd_htcp_in_info** aadsl_hii;
    uint32_t uml_buf_b;
    uint32_t uml_buf_e;
    uint32_t uml_block_b;
    uint32_t uml_block_e;
    uint32_t uml_remove = 0;

    bool bol_invalid_init = false;
    bool bol_send_notify = false;
    bool bol_update_timer = false;
    int64_t ill_update_timer;
    bool bol_reply_reset = false;
    bool bol_conn_established = false;
    bool bol_reset_by_peer = false;
    bool bol_conn_refused = false;
    bool bol_conn_closed = false;
    bool bol_new_data = false;

    /* if check fails, packet is freed inside m_check_packet() */
    bol_ret = m_check_packet(adsp_hc, adsp_hii, ump_tcp_len, &bol_packet_ok,
                             &uml_hlen, chrl_header, &achl_header);
    if (!bol_ret)
        return;
    if (!bol_packet_ok) {
        HTCP_LOCK;
        if (adsp_hc->iec_state == ied_htcp_listen) {
            bol_invalid_init = true;
            adsp_hc->iec_state = ied_htcp_closed;
        }
        HTCP_UNLOCK;

        if (bol_invalid_init)
            m_do_abort(adsp_hc, ied_htcpc_conn_error, __LINE__,
                       "received invalid initial packet");

        return;
    }

    bol_ret = adsp_hc->adsc_cb->amc_get_time(adsp_hc, &ill_now_ms);
    HTCP_CHECK_CB_RET(amc_get_time);

    // start packet processing

    bol_update_timer = false;

    // copy fields - may be overwritten when writing to adsp_hii or chrl_header
    uml_seq = m_get_tcp_seqn(achl_header);
    uml_ack = m_get_tcp_ackn(achl_header);
    uml_win = m_get_tcp_window(achl_header); // soon scaled
    uml_dlen = ump_tcp_len - uml_hlen;
    utl_flags = m_get_tcp_flags(achl_header);

    adsp_hii->umc_offset = uml_hlen;

    adsp_hii->adsc_next = *aadsp_to_del;
    *aadsp_to_del = adsp_hii;

    HTCP_LOCK;

    if (!m_get_tcp_flags_syn(utl_flags))
        uml_win <<= adsp_hc->umc_snd_winscale;

    switch (adsp_hc->iec_state) {

    case ied_htcp_closed:
        if (m_get_tcp_flags_rst(utl_flags))
            break;
        bol_reply_reset = true;
        break;

    case ied_htcp_listen:
        if (m_get_tcp_flags_rst(utl_flags)) {
            bol_invalid_init = true;
            break;
        }

        if (m_get_tcp_flags_ack(utl_flags)) {
            bol_reply_reset = true;
            bol_invalid_init = true;
            break;
        }

        if (!m_get_tcp_flags_syn(utl_flags)) {
            bol_invalid_init = true;
            break;
        }

        bol_ret = m_locked_process_syn_options(adsp_hc, achl_header, uml_hlen);
        if (!bol_ret)
            return;

        adsp_hc->umc_rcv_irs = uml_seq;
        adsp_hc->umc_rcv_nxt = uml_seq + 1;
        adsp_hc->umc_last_ack_sent = uml_seq + 1;

        adsp_hc->amc_cc_func(ied_htcp_cce_init,
                             ill_now_ms, adsp_hc->umc_srtt_ms,
                             adsp_hc->umc_snd_smss, 0,
                             &adsp_hc->dsc_cc);

        if (uml_dlen > adsp_hc->umc_snd_wnd) {
            uml_dlen = adsp_hc->umc_snd_wnd;
        }

        if (uml_dlen > 0) {
            uml_dlen = 0;// TODO: accept data?
        }

        HTCP_LOCKED_ASSERT(m_get_tcp_flags_rst(adsp_hc->utc_packet_flags) == 0);
        adsp_hc->utc_packet_flags = utd_tcp_syn_ack;

        adsp_hc->iec_state = ied_htcp_syn_rcvd;
        break;

    case ied_htcp_syn_sent:
    case ied_htcp_syn_sent_eof:
        if (m_get_tcp_flags_ack(utl_flags)) {
            if (!m_within(adsp_hc->umc_snd_iss + 1, adsp_hc->umc_snd_nxt + 1,
                          uml_ack) ||
                !m_within(adsp_hc->umc_snd_una, adsp_hc->umc_snd_nxt + 1,
                          uml_ack)) {

                if (m_get_tcp_flags_rst(utl_flags))
                    break;
                bol_reply_reset = true;
                break;
            }
        };

        if (m_get_tcp_flags_rst(utl_flags)) {
            if (!m_get_tcp_flags_ack(utl_flags))
                break;
            bol_conn_refused = true;
            adsp_hc->iec_state = ied_htcp_closed;
            break;
        }

        if (!m_get_tcp_flags_syn(utl_flags))
            break;

        // received syn from here on

        bol_ret = m_locked_process_syn_options(adsp_hc, achl_header, uml_hlen);
        if (!bol_ret)
            return;

        adsp_hc->umc_rcv_irs = uml_seq;
        adsp_hc->umc_rcv_nxt = uml_seq + 1;
        adsp_hc->umc_last_ack_sent = uml_seq + 1;

        adsp_hc->amc_cc_func(ied_htcp_cce_init,
                             ill_now_ms, adsp_hc->umc_srtt_ms,
                             adsp_hc->umc_snd_smss, 0,
                             &adsp_hc->dsc_cc);

        if (uml_dlen > adsp_hc->umc_snd_wnd) {
            // initial umc_snd_wnd == 0, so this currently ensures uml_dlen == 0
            uml_dlen = adsp_hc->umc_snd_wnd;
        }

        if (uml_dlen > 0) {
            uml_dlen = 0; // TODO: accept data on SYN and SYNACK? RFC says yes
        }

        if (m_get_tcp_flags_ack(utl_flags)) {
            
            // received syn ack in a state of syn sent.
            // this leads to connection establishment and scheduling of an ack to send
            
            adsp_hc->umc_snd_una = uml_ack;
            adsp_hc->umc_snd_wnd = uml_win;

            HTCP_LOCKED_ASSERT(m_get_tcp_flags_rst(adsp_hc->utc_packet_flags)
                               == 0);
            adsp_hc->utc_packet_flags = utd_tcp_ack;
            bol_conn_established = true;
            if (adsp_hc->iec_state == ied_htcp_syn_sent_eof)
                adsp_hc->iec_state = ied_htcp_fin_wait_1;
			else
			{
				adsp_hc->iec_state = ied_htcp_established;
				adsp_hc->umc_rto_ms = 1000; // Once connection established, timer shorter than 3 sec.
			}

        } else {

            // received a syn but no ack after syn sent.
            // this is the case of both sides sending syn "at the same time"
            // reply with syn ack and go into state 'syn received'

            HTCP_LOCKED_ASSERT(m_get_tcp_flags_rst(adsp_hc->utc_packet_flags)
                               == 0);
            adsp_hc->utc_packet_flags = utd_tcp_syn_ack;

            adsp_hc->iec_state = ied_htcp_syn_rcvd;
        }
        break;

    case ied_htcp_syn_rcvd:
    case ied_htcp_syn_rcvd_eof:
    case ied_htcp_established:
    case ied_htcp_fin_wait_1:
    case ied_htcp_fin_wait_2:
    case ied_htcp_close_wait:
    case ied_htcp_closing:
    case ied_htcp_last_ack:
    case ied_htcp_time_wait:

        bol_fin = m_get_tcp_flags_fin(utl_flags) != 0;
        bol_just_ack = m_get_tcp_flags_ack(utl_flags) &&
            !bol_fin &&
            uml_dlen == 0;

        achl_ts_option = NULL;
        achl_sack_option = NULL;
        uml_sack_option_count = 0;

        // after the following block 'achl_ts_option' and
        // 'achl_sack_option' point to the relevant option fields
        // in the header, if applicable
        // also 'uml_sack_option_count' is set appropriately

        if (adsp_hc->boc_use_timestamp || adsp_hc->boc_use_sack) {
            // traverse options to find relevant options
            achl_option = m_first_tcp_option(achl_header,
                                             achl_header + uml_hlen);
            while (achl_option < achl_header + uml_hlen) {
                if (adsp_hc->boc_use_timestamp &&
                    achl_ts_option == NULL &&
                    achl_option[0] == 8 &&
                    achl_option[1] == 10) {
                    achl_ts_option = achl_option + 2;
                    if (!adsp_hc->boc_use_sack || achl_sack_option != NULL)
                        break;
                }

                if (adsp_hc->boc_use_sack &&
                    achl_sack_option == NULL &&
                    achl_option[0] == 5 &&
                    achl_option[1] >= 10 &&
                    achl_option[1] % 8 == 2) {
                    achl_sack_option = achl_option + 2;
                    uml_sack_option_count = achl_option[1] / 8;
                    if (!adsp_hc->boc_use_timestamp || achl_ts_option != NULL)
                        break;
                }

                achl_option = m_next_tcp_option(achl_option,
                                                achl_header + uml_hlen);
            }
        }

        // PAWS, check the sequence number by using timestamp variables
        // the internal timestamp bookkeeping variables (umc_ts_recent, imc_recent_age_s)
        // are updated further below in the code.

        bol_invalid = false;
        if (!bol_invalid) {
            if (adsp_hc->boc_use_timestamp) {
                if (achl_ts_option != NULL) {
                    uml_seg_tsval = m_get_32_bit(achl_ts_option);      // tsval = timestamp value
                    uml_seg_tsecr = m_get_32_bit(achl_ts_option + 4);  // tsecr = timestamp echo reply
                    bol_invalid =
                        m_wlt(uml_seg_tsval, adsp_hc->umc_ts_recent) &&
                        ill_now_ms / 1000 - adsp_hc->imc_recent_age_s >= 0 &&
                        !m_get_tcp_flags_rst(utl_flags);
                } else {
                    bol_invalid = !m_get_tcp_flags_rst(utl_flags);
                }
            }
        }

        // check overlap of data with receive window
        if (!bol_invalid) {
            if (adsp_hc->umc_rcv_wnd == 0) {
                bol_invalid = uml_dlen != 0 || uml_seq != adsp_hc->umc_rcv_nxt;
            } else {
                // packet is valid when start or end falls into receive window
                bol_invalid =
                    !m_within(adsp_hc->umc_rcv_nxt,
                              adsp_hc->umc_rcv_nxt + adsp_hc->umc_rcv_wnd,
                              uml_seq) &&                               
                    (uml_dlen == 0 ||
                     !m_within(adsp_hc->umc_rcv_nxt,
                               adsp_hc->umc_rcv_nxt + adsp_hc->umc_rcv_wnd,
                               uml_seq + uml_dlen - 1));
            }
        }

        // ack must fall into area of unacknowledged but sent data
        if (!bol_invalid && m_get_tcp_flags_ack(utl_flags)) {
            bol_invalid = !m_within(adsp_hc->umc_snd_una,
                                    adsp_hc->umc_snd_nxt + 1,
                                    uml_ack);
        }
        if (bol_invalid) {
            if (!m_get_tcp_flags_rst(utl_flags)) {
                adsp_hc->utc_packet_flags |= utd_tcp_ack;

                if (adsp_hc->iec_state == ied_htcp_syn_rcvd ||
                    adsp_hc->iec_state == ied_htcp_syn_rcvd_eof) {

                    adsp_hc->utc_packet_flags |= utd_tcp_syn;
                }
            }
            break;
        }

        // check if packet goes beyond a previously received FIN
        if (adsp_hc->boc_oo_fin_received) {
            HTCP_LOCKED_TEST(m_wle(uml_seq + uml_dlen, adsp_hc->umc_oo_fin_seq),
                             "received data beyond previously received FIN");
        }

        // chop off packets that go beyond receive window
        if (m_within(uml_seq, uml_seq + uml_dlen,
                     adsp_hc->umc_rcv_nxt + adsp_hc->umc_rcv_wnd)) {

            bol_fin = false;
            uml_dlen = adsp_hc->umc_rcv_nxt + adsp_hc->umc_rcv_wnd - uml_seq;
        }

        // chop off duplicate/already received data at beginning
        if (uml_dlen > 0 &&
            m_within(uml_seq + 1, uml_seq + uml_dlen, adsp_hc->umc_rcv_nxt)) {

            uml_dlen -= adsp_hc->umc_rcv_nxt - uml_seq;
            adsp_hii->umc_offset += adsp_hc->umc_rcv_nxt - uml_seq;
            uml_seq = adsp_hc->umc_rcv_nxt;
        }

        // check the RST bit
        // receiving RST closes the connection
        if (m_get_tcp_flags_rst(utl_flags)) {
            bol_reset_by_peer = true;
            adsp_hc->iec_state = ied_htcp_closed;
            break;
        }

        // check the SYN bit
        // in the current state, an introductory SYN for the connection has already
        // been received. Another SYN leads to connection reset and close.

        if (m_get_tcp_flags_syn(utl_flags)) {
            bol_reply_reset = true;
            bol_reset_by_peer = true;
            adsp_hc->iec_state = ied_htcp_closed;
            break;
        }

        // check the ACK field
        if (!m_get_tcp_flags_ack(utl_flags))
            break;

        // from now on we know, that ACK is set in incoming packet.

        if (adsp_hc->iec_state == ied_htcp_syn_rcvd ||
            adsp_hc->iec_state == ied_htcp_syn_rcvd_eof) {

            // RFC 793 indicates
            // adsp_hc->umc_snd_una, adsp_hc->umc_snd_nxt + 1,
            // but this allows an ack which does not acknowledge syn
            // to change our state to ied_htcp_established
            if (!m_within(adsp_hc->umc_snd_una + 1, adsp_hc->umc_snd_nxt + 1,
                          uml_ack)) {

                if (uml_ack != adsp_hc->umc_snd_una)
                    bol_reply_reset = true;
                // instead of following RFC, drop the segment
                break;
            }

            adsp_hc->umc_snd_una = uml_ack;
            adsp_hc->umc_snd_wnd = uml_win;
            // TODO: check window update
            bol_conn_established = true;
            if (adsp_hc->iec_state == ied_htcp_syn_rcvd_eof)
                adsp_hc->iec_state = ied_htcp_fin_wait_1;
            else
                adsp_hc->iec_state = ied_htcp_established;
            bol_ret = m_locked_rto_received(adsp_hc, ill_now_ms);
            if (!bol_ret)
                return;
        }

        // update the PAWS timestamp bookkeeping variables
        if (adsp_hc->boc_use_timestamp) {
            if (m_wle(uml_seq, adsp_hc->umc_last_ack_sent)) {
                adsp_hc->umc_ts_recent = uml_seg_tsval;
                adsp_hc->imc_recent_age_s = ill_now_ms / 1000;
            }
        }

        if (adsp_hc->boc_use_sack) {
            bol_ret = m_locked_update_rcv_sack(adsp_hc, uml_ack,
                                               achl_sack_option,
                                               uml_sack_option_count);
            if (!bol_ret)
                return;
        }

        if (m_within(adsp_hc->umc_snd_una + 1, adsp_hc->umc_snd_nxt + 1,
                     uml_ack)) {
            // new ack

            if (m_wlt(adsp_hc->umc_snd_nxt_cur, uml_ack))
                adsp_hc->umc_snd_nxt_cur = uml_ack;

            bol_ret = m_locked_restart_rexmt_timer(adsp_hc, &bol_update_timer,
                                                   &ill_update_timer,
                                                   ill_now_ms);
            if (!bol_ret)
                return;

            if (adsp_hc->boc_use_timestamp) {
                HTCP_LOCKED_ASSERT(achl_ts_option != NULL);
                bol_ret =
                    m_locked_rto_timestamp_update(adsp_hc, ill_now_ms,
                                                  m_get_32_bit(achl_ts_option +
                                                               4));  // last is tsecr (time stamp echo reply)
                if (!bol_ret)
                    return;
            }

            HTCP_LOCKED_ASSERT(adsp_hc->iec_state == ied_htcp_established ||
                               adsp_hc->iec_state == ied_htcp_fin_wait_1 ||
                               adsp_hc->iec_state == ied_htcp_closing ||
                               adsp_hc->iec_state == ied_htcp_close_wait ||
                               adsp_hc->iec_state == ied_htcp_last_ack);

            uml_acked_len = uml_ack - adsp_hc->umc_snd_una;

            // check if sent FIN bit acknowledged
            if (uml_acked_len == adsp_hc->umc_send_pending + 1) {

                HTCP_LOCKED_ASSERT(adsp_hc->iec_state == ied_htcp_fin_wait_1 ||
                                   adsp_hc->iec_state == ied_htcp_closing ||
                                   adsp_hc->iec_state == ied_htcp_last_ack);

                --uml_acked_len;

                switch (adsp_hc->iec_state) {
                case ied_htcp_fin_wait_1:
                    adsp_hc->iec_state = ied_htcp_fin_wait_2;
                    break;

                case ied_htcp_closing:
                    bol_ret =
                        m_locked_restart_time_wait_timer(adsp_hc,
                                                         &bol_update_timer,
                                                         &ill_update_timer,
                                                         ill_now_ms);
                    if (!bol_ret)
                        return;
                    adsp_hc->iec_state = ied_htcp_time_wait;
                    break;

                case ied_htcp_last_ack:
                    bol_conn_closed = true;
                    adsp_hc->iec_state = ied_htcp_closed;
                    break;

                default:
                    // should not arrive here
                    HTCP_LOCKED_ERROR("processing invalid ACK number");
                }
            }

            adsp_hc->umc_snd_una = uml_ack;
            // TODO: fix window update
            adsp_hc->umc_snd_wnd = uml_win;
            // leave exponential backoff for zero window probe
            if (uml_win != 0)
                adsp_hc->umc_exp_backoff = 1;
            // TODO: release/reset rexmt timer

            // to empty relevent section from out queue
            uml_remove += uml_acked_len;

            // update congestion window, recovery mechanisms
            if (adsp_hc->boc_recovering) {
                if (m_wge(adsp_hc->umc_snd_una, adsp_hc->umc_recover)) {
                    // full ack - same with and without sack

                    // note: since recovering (not timeout recovery),
                    //       umc_snd_nxt == umc_snd_nxt_cur
                    HTCP_LOCKED_ASSERT(adsp_hc->umc_snd_nxt_cur ==
                                       adsp_hc->umc_snd_nxt); // recovering

                    adsp_hc->amc_cc_func(ied_htcp_cce_recover_ack,
                                         ill_now_ms,
                                         adsp_hc->umc_srtt_ms,
                                         adsp_hc->umc_snd_smss,
                                         adsp_hc->umc_snd_nxt -
                                         adsp_hc->umc_snd_una,
                                         &adsp_hc->dsc_cc);
                    adsp_hc->boc_recovering = false;
                } else {
                    // partial ack
                    if (!adsp_hc->boc_use_sack) {
                        adsp_hc->dsc_cc.umc_cwnd -= uml_acked_len;
                        if (uml_acked_len >= adsp_hc->umc_snd_smss)
                            adsp_hc->dsc_cc.umc_cwnd += adsp_hc->umc_snd_smss;
                        if (!adsp_hc->boc_out_send_recover) {
                            // if there is an recovery packet pending,
                            // we cannot handle sending additional packet

                            if (adsp_hc->umc_send_pending > 0) {
                                adsp_hc->boc_out_send_recover = true;
                                adsp_hc->umc_out_send_recover_seq =
                                    adsp_hc->umc_snd_una;
                                if (adsp_hc->boc_pack_time) {
                                    bol_ret = m_locked_restart_rexmt_timer
                                        (adsp_hc,
                                         &bol_update_timer, &ill_update_timer,
                                         ill_now_ms);
                                    if (!bol_ret)
                                        return;
                                    adsp_hc->boc_pack_time = false;
                                }
                            }
                        }
                    }
                }
            } else { // !adsp_hc->boc_recovering
                adsp_hc->dsc_cc.umc_bytes_acked += uml_acked_len;
                adsp_hc->amc_cc_func(ied_htcp_cce_newack,
                                     ill_now_ms,
                                     adsp_hc->umc_srtt_ms,
                                     adsp_hc->umc_snd_smss,
                                     adsp_hc->umc_snd_nxt_cur -
                                     adsp_hc->umc_snd_una,
                                     &adsp_hc->dsc_cc);
                if (m_wlt(adsp_hc->umc_recover, adsp_hc->umc_snd_una))
                    adsp_hc->umc_recover = adsp_hc->umc_snd_una;
            }
            adsp_hc->umc_dack = 0;

            bol_ret = m_locked_rto_received(adsp_hc, ill_now_ms);
            if (!bol_ret)
                return;
        } else if (uml_ack == adsp_hc->umc_snd_nxt) {
            // dup ack, but no unacked data

            // update window size
            // TODO: fix window update
            if (adsp_hc->umc_snd_wnd < uml_win)
                adsp_hc->umc_snd_wnd = uml_win;
        } else if (uml_ack == adsp_hc->umc_snd_una && bol_just_ack) {
            // duplicate ack

            ++adsp_hc->umc_dack;
            if ((int)adsp_hc->umc_dack == ins_dup_thresh &&
                !adsp_hc->boc_recovering &&
                m_wge(adsp_hc->umc_snd_una, adsp_hc->umc_recover)) {

                // do fast retransmission, start fast recovery

                // note: since recovering (not timeout recovery),
                //       umc_snd_nxt == umc_snd_nxt_cur.
                //       Otherwise, umc_snd_una >= umc_recover not satisfied.
                HTCP_LOCKED_ASSERT(adsp_hc->umc_snd_nxt_cur ==
                                   adsp_hc->umc_snd_nxt); // recovering

                adsp_hc->boc_recovering = true;
                adsp_hc->boc_pack_time = true;
                adsp_hc->umc_recover = adsp_hc->umc_snd_nxt;
                if (adsp_hc->boc_use_sack) {
                    adsp_hc->amc_cc_func(ied_htcp_cce_three_dup_sack,
                                         ill_now_ms,
                                         adsp_hc->umc_srtt_ms,
                                         adsp_hc->umc_snd_smss,
                                         adsp_hc->umc_snd_nxt -
                                         adsp_hc->umc_snd_una,
                                         &adsp_hc->dsc_cc);

                    bol_ret = m_locked_update_sack_pipe(adsp_hc);
                    if (!bol_ret)
                        return;
                } else {
                    adsp_hc->amc_cc_func(ied_htcp_cce_three_dup,
                                         ill_now_ms,
                                         adsp_hc->umc_srtt_ms,
                                         adsp_hc->umc_snd_smss,
                                         adsp_hc->umc_snd_nxt -
                                         adsp_hc->umc_snd_una,
                                         &adsp_hc->dsc_cc);
                }

                if (adsp_hc->umc_snd_nxt != adsp_hc->umc_snd_una &&
                    !adsp_hc->boc_out_send_recover) {

                    adsp_hc->boc_out_send_recover = true;
                    adsp_hc->umc_out_send_recover_seq = adsp_hc->umc_snd_una;
                }
            } else if (adsp_hc->boc_recovering) {
                // fast recovery
                if (adsp_hc->boc_use_sack) {
                    bol_ret = m_locked_update_sack_pipe(adsp_hc);
                    if (!bol_ret)
                        return;
                } else {
                    HTCP_LOCKED_ASSERT(adsp_hc->umc_snd_nxt_cur ==
                                       adsp_hc->umc_snd_nxt); // recovering

                    adsp_hc->amc_cc_func(ied_htcp_cce_more_dup,
                                         ill_now_ms,
                                         adsp_hc->umc_srtt_ms,
                                         adsp_hc->umc_snd_smss,
                                         adsp_hc->umc_snd_nxt -
                                         adsp_hc->umc_snd_una,
                                         &adsp_hc->dsc_cc);
                    ++adsp_hc->umc_pending_dacks;
                }
            } else if (adsp_hc->umc_dack < (uint32_t)ins_dup_thresh &&
                       !adsp_hc->boc_out_send_recover &&
                       adsp_hc->umc_snd_nxt_cur == adsp_hc->umc_snd_nxt) {

                // limited transmit
                uml_len = adsp_hc->umc_send_pending;
                if (uml_len > adsp_hc->umc_snd_wnd)
                    uml_len = adsp_hc->umc_snd_wnd;
                if (uml_len > adsp_hc->umc_snd_nxt - adsp_hc->umc_snd_una) {

                    adsp_hc->boc_out_send_recover = true;
                    adsp_hc->umc_out_send_recover_seq = adsp_hc->umc_snd_nxt;
                }
            }
        }

        if (uml_dlen > 0) {
            HTCP_LOCKED_TEST(*aadsp_to_del == adsp_hii,
                             "incorrect internal state");
            *aadsp_to_del = (*aadsp_to_del)->adsc_next;
            HTCP_LOCKED_ASSERT(*aadsp_to_del == NULL);
        }

        // process segment text
        if (uml_dlen > 0 &&
            m_within(uml_seq, uml_seq + uml_dlen, adsp_hc->umc_rcv_nxt)) {
            // append data to input buffer

            bol_new_data = true;
            aadsl_hii = &adsp_hc->adsc_in_list;
            while (*aadsl_hii != NULL)
                aadsl_hii = &(*aadsl_hii)->adsc_next;
            *aadsl_hii = adsp_hii;
            adsp_hii->adsc_next = NULL;
            aadsl_hii = &adsp_hii->adsc_next;

            adsp_hii->umc_seq = adsp_hc->umc_rcv_nxt;
            adsp_hii->umc_len = uml_dlen;
            adsp_hii->boc_push = m_get_tcp_flags_psh(utl_flags) == 1;

            adsp_hc->umc_rcv_nxt = uml_seq + uml_dlen;

            if (bol_fin) {
                HTCP_LOCKED_TEST(!adsp_hc->boc_oo_fin_received ||
                                 adsp_hc->umc_oo_fin_seq == uml_seq + uml_dlen,
                                 "conflicting FINs received");
                adsp_hc->boc_oo_fin_received = false;

                // we will not need out-of-order segments, mark for release
                adsp_hc->adsc_sack_first = NULL;
                while (adsp_hc->adsc_oo_list != NULL) {
                    adsl_hii = adsp_hc->adsc_oo_list;
                    adsp_hc->adsc_oo_list = adsp_hc->adsc_oo_list->adsc_next;
                    adsl_hii->adsc_next = *aadsp_to_del;
                    *aadsp_to_del = adsl_hii;
                }

                // TODO: test out of order segments not beyond FIN
            } else {
                // Check out of order segments available.
                while ((adsl_hii = adsp_hc->adsc_oo_list) != NULL) {
                    if (m_wge(uml_seq + uml_dlen,
                              adsl_hii->umc_seq + adsl_hii->umc_len)) {

                        // out of order segment redundant
                        // [...]: new segment
                        // |xxx|: segment from list
                        // |xxxxxxxx[....|.......]
                        // segment |xxxxx| is redundant
                        adsp_hc->adsc_oo_list = adsl_hii->adsc_next;
                        adsl_hii->adsc_next = *aadsp_to_del;
                        *aadsp_to_del = adsl_hii;
                    } else if (m_wge(uml_seq + uml_dlen, adsl_hii->umc_seq)) {
                        // use out of order segment
                        // [.....|xxxxxxx]+++++|
                        // append ]+++++| to input buffer as adsl_hii
                        // append data to input buffer

                        adsp_hc->adsc_oo_list = adsl_hii->adsc_next;
                        *aadsl_hii = adsl_hii;
                        adsl_hii->adsc_next = NULL;
                        aadsl_hii = &adsl_hii->adsc_next;

                        if (adsl_hii->umc_seq != uml_seq + uml_dlen) {
                            adsl_hii->umc_offset += uml_seq + uml_dlen -
                                adsl_hii->umc_seq;
                            adsl_hii->umc_len -= uml_seq + uml_dlen -
                                adsl_hii->umc_seq;
                            adsl_hii->umc_seq = uml_seq + uml_dlen;
                        }

                        uml_dlen += adsl_hii->umc_len;
                    } else {
                        // out of order segments still not usable
                        break;
                    }

                    // here if oo segment removed from queue
                    if (adsp_hc->adsc_sack_first == adsl_hii)
                        adsp_hc->adsc_sack_first = adsp_hc->adsc_oo_list;
                }

                adsp_hc->umc_rcv_nxt = uml_seq + uml_dlen;

                // check out of order FIN
                if (adsp_hc->boc_oo_fin_received &&
                    adsp_hc->umc_oo_fin_seq == adsp_hc->umc_rcv_nxt) {
                    bol_fin = true;
                    adsp_hc->boc_oo_fin_received = false;
                }
            } // !bol_fin

            adsp_hc->umc_rcv_wnd -= uml_dlen;

            // notify application
            if (adsp_hc->ilc_da_timer == 0) {
                bol_ret = m_locked_start_da_timer(adsp_hc, &bol_update_timer,
                                                  &ill_update_timer,
                                                  ill_now_ms);
                if (!bol_ret)
                    return;
            } else {
                bol_ret = m_locked_stop_da_timer(adsp_hc, &bol_update_timer,
                                                 &ill_update_timer);
                if (!bol_ret)
                    return;
                if (adsp_hc->utc_packet_flags == 0)
                    adsp_hc->utc_packet_flags = utd_tcp_ack;
            }

        } else if (uml_dlen > 0) {
            // add to out of order buffer

            // do not prepare ACK segment here - do it later (end of this scope)
            // since it might contain SACK fields which require
            // adsp_hc->adsc_oo_list to be up to date

            HTCP_LOCKED_TEST(!adsp_hc->boc_oo_fin_received ||
                             m_wle(uml_seq + uml_dlen, adsp_hc->umc_oo_fin_seq),
                             "received data beyond received FIN");

            // first, find oo segment just before this segment
            aadsl_hii = &adsp_hc->adsc_oo_list;
            while (*aadsl_hii != NULL &&
                   // actual segment ends before uml_seq segment begins
                   m_wge(uml_seq,
                         (*aadsl_hii)->umc_seq + (*aadsl_hii)->umc_len)) {

                aadsl_hii = &(*aadsl_hii)->adsc_next;
            }

            // We are now sure that there is no overlap before iterator.
            // The above statement will always hold.

            while (uml_dlen > 0 && *aadsl_hii != NULL) {
                // buffer we are inserting:
                uml_buf_b = uml_seq;
                uml_buf_e = uml_buf_b + uml_dlen;
                // current block in adsc_oo_list:
                uml_block_b = (*aadsl_hii)->umc_seq;
                uml_block_e = uml_block_b + (*aadsl_hii)->umc_len;

                // first handle the common cases of no conflict

                // block does not interfere, so skip
                if (m_wle(uml_block_e, uml_buf_b)) {
                    aadsl_hii = &(*aadsl_hii)->adsc_next;
                    continue;
                }

                // buf is before block, so just insert
                if (m_wle(uml_buf_e, uml_block_b)) {
                    adsp_hii->umc_seq = uml_seq;
                    adsp_hii->umc_len = uml_dlen;
                    adsp_hii->boc_push = m_get_tcp_flags_psh(utl_flags) == 1;

                    adsp_hii->adsc_next = *aadsl_hii;
                    *aadsl_hii = adsp_hii;

                    uml_seq += uml_dlen;
                    uml_dlen = 0;
                    break;
                }

                // now the not-so-common cases of conflicts

                // buf is contained in block, so erase buf
                if (m_wge(uml_buf_b, uml_block_b) &&
                    m_wle(uml_buf_e, uml_block_e)) {
                    adsp_hii->adsc_next = *aadsp_to_del;
                    *aadsp_to_del = adsp_hii;
                    uml_seq += uml_dlen;
                    uml_dlen = 0;
                    break;
                }

                // block is contained in buf, so erase block
                if (m_wge(uml_block_b, uml_buf_b) &&
                    m_wle(uml_block_e, uml_buf_e)) {
                        // JB: try fix
                        dsd_htcp_in_info* adsl_old_next = (*aadsl_hii)->adsc_next;
                        (*aadsl_hii)->adsc_next = *aadsp_to_del;
                        *aadsp_to_del = *aadsl_hii;
                        // TODO: FIXME: something wrong with (*aadsl_hii)->adsc_next
                        //*aadsl_hii = (*aadsl_hii)->adsc_next;
                        *aadsl_hii = adsl_old_next;
                    continue;
                }

                // crop last part of buf and insert
                if (m_wlt(uml_buf_b, uml_block_b)) {
                    HTCP_LOCKED_ASSERT(m_wgt(uml_buf_e, uml_block_b));
                    HTCP_LOCKED_ASSERT(m_wlt(uml_buf_e, uml_block_e));

                    adsp_hii->umc_seq = uml_seq;
                    adsp_hii->umc_len = uml_block_b - uml_buf_b;;
                    adsp_hii->boc_push = m_get_tcp_flags_psh(utl_flags) == 1;

                    adsp_hii->adsc_next = *aadsl_hii;
                    *aadsl_hii = adsp_hii;

                    uml_seq += uml_dlen;
                    uml_dlen = 0;
                    break;
                }

                // crop first part of buf, update aadsl_hii, loop
                HTCP_LOCKED_ASSERT(m_wgt(uml_buf_b, uml_block_b));
                HTCP_LOCKED_ASSERT(m_wlt(uml_buf_b, uml_block_e));
                HTCP_LOCKED_ASSERT(m_wgt(uml_buf_e, uml_block_e));

                adsp_hii->umc_offset += uml_block_e - uml_buf_b;
                uml_dlen -= uml_block_e - uml_buf_b;
                uml_seq = uml_block_e;
                aadsl_hii = &(*aadsl_hii)->adsc_next;
            }

            // now append final parts
            if (uml_dlen > 0) {
                HTCP_LOCKED_ASSERT(*aadsl_hii == NULL);

                adsp_hii->umc_seq = uml_seq;
                adsp_hii->umc_len = uml_dlen;
                adsp_hii->boc_push = m_get_tcp_flags_psh(utl_flags) == 1;

                adsp_hii->adsc_next = NULL;
                *aadsl_hii = adsp_hii;
            }

            // now store out-of-order FIN
            if (bol_fin) {
                HTCP_LOCKED_TEST(adsp_hii->adsc_next == NULL,
                                 "received data beyond received FIN");

                adsp_hc->boc_oo_fin_received = true;
                adsp_hc->umc_oo_fin_seq = uml_seq + uml_dlen;
                bol_fin = false;
            }

            // now update adsp_hc->adsc_sack_first
            if (adsp_hc->boc_use_sack) {
                adsl_hii = adsp_hc->adsc_oo_list;
                adsp_hc->adsc_sack_first = adsl_hii;
                while (!m_within(adsl_hii->umc_seq,
                                 adsl_hii->umc_seq + adsl_hii->umc_len + 1,
                                 uml_seq)) {

                    if (adsl_hii->adsc_next == NULL)
                    HTCP_LOCKED_ASSERT(adsl_hii->adsc_next != NULL);

                    HTCP_LOCKED_ASSERT(m_wge(adsl_hii->adsc_next->umc_seq,
                                             adsl_hii->umc_seq +
                                             adsl_hii->umc_len));
                    if (adsl_hii->adsc_next->umc_seq !=
                        adsl_hii->umc_seq + adsl_hii->umc_len) {

                        adsp_hc->adsc_sack_first = adsl_hii->adsc_next;
                    }

                    adsl_hii = adsl_hii->adsc_next;
                }
            }

            // ACK out-of-order segment
            ++adsp_hc->umc_tosend_dack;
        } else if (bol_fin && uml_seq != adsp_hc->umc_rcv_nxt) {
            adsp_hc->boc_oo_fin_received = true;
            adsp_hc->umc_oo_fin_seq = uml_seq;
            bol_fin = false;
        }
        // done processing segment text

        // check the FIN bit
        if (bol_fin) {
            if (adsp_hc->utc_packet_flags == 0)
                adsp_hc->utc_packet_flags = utd_tcp_ack;

            ++adsp_hc->umc_rcv_nxt;

            switch (adsp_hc->iec_state) {
            case ied_htcp_established:
                adsp_hc->iec_state = ied_htcp_close_wait;
                bol_new_data = true;
                break;
            case ied_htcp_fin_wait_1:
                adsp_hc->iec_state = ied_htcp_closing;
                bol_new_data = true;
                break;
            case ied_htcp_fin_wait_2:
                adsp_hc->iec_state = ied_htcp_time_wait;
                bol_new_data = true;
                bol_ret = m_locked_restart_time_wait_timer(adsp_hc,
                                                           &bol_update_timer,
                                                           &ill_update_timer,
                                                           ill_now_ms);
                if (!bol_ret)
                    return;
                break;
            default:
                // repeated FIN - send ACK
                adsp_hc->utc_packet_flags |= utd_tcp_ack;
            }
        }

        break;

    default:
        // should not arrive here
        HTCP_LOCKED_ERROR("invalid state inside m_htcp_in_packet()");
    }

    adsp_hc->umc_send_pending -= uml_remove;

    bol_send_notify = false;
    if (!adsp_hc->boc_out_packet_promised) {
        bol_ret = m_locked_packets_available(adsp_hc, &bol_send_notify);
        adsp_hc->boc_out_packet_promised = bol_send_notify;
    }

    HTCP_UNLOCK;

    if (uml_remove > 0) {
        bol_ret = adsp_hc->adsc_cb->amc_out_ack(adsp_hc, uml_remove);
        HTCP_CHECK_CB_RET(amc_out_ack);
    }

    if (bol_send_notify) {
        bol_ret = adsp_hc->adsc_cb->amc_out_packets(adsp_hc);
        HTCP_CHECK_CB_RET(amc_out_packets);
    }

    while (*aadsp_to_del != NULL) {
        adsl_hii = *aadsp_to_del;
        *aadsp_to_del = adsl_hii->adsc_next;
        bol_ret = adsp_hc->adsc_cb->amc_in_rel(adsp_hc, adsl_hii);
        HTCP_CHECK_CB_RET(amc_in_rel);
    }

    if (bol_update_timer) {
        bol_ret = m_update_timer(adsp_hc, ill_now_ms, ill_update_timer);
        if (!bol_ret)
            return;
    }

    if (bol_reply_reset) {
        if (m_get_tcp_flags_ack(utl_flags)) {
            bol_ret = m_send_rst(adsp_hc, uml_ack, false);
            if (!bol_ret)
                return;
        } else {
            bol_ret = m_send_rst(adsp_hc, uml_seq, true);
            if (!bol_ret)
                return;
        }
    }

    if (bol_invalid_init) {
        m_do_abort(adsp_hc, ied_htcpc_conn_error, __LINE__,
                   "received invalid initial packet");
    }

    if (bol_conn_established) {
        bol_ret = adsp_hc->adsc_cb->amc_established(adsp_hc);
        HTCP_CHECK_CB_RET(amc_established);
    }

    if (bol_new_data) {
        bol_ret = adsp_hc->adsc_cb->amc_in_more_data(adsp_hc);
        HTCP_CHECK_CB_RET(amc_in_more_data);
    }

    if (bol_reset_by_peer) {
        m_do_close(adsp_hc, ied_htcpc_remote_reset, __LINE__,
                   "connection reset by peer");
        return;
    }

    if (bol_conn_refused) {
        m_do_close(adsp_hc, ied_htcpc_conn_refused, __LINE__,
                   "connection refused");
        return;
    }

    if (bol_conn_closed) {
        m_do_close(adsp_hc, ied_htcpc_normal, __LINE__,
                   "connection closed normally");
        return;
    }
}

void m_htcp_in_get_data(struct dsd_htcp_conn* adsp_hc,
                        struct dsd_htcp_in_info** aadsp_hii,
                        uint32_t* aump_offset, uint32_t* aump_len,
                        bool* abop_push,
                        bool* abop_eof, bool* abop_more,
                        bool bop_throttle)
{
    bool bol_win_update = false;
    bool bol_ret;

    // if throttle, do not reopen receive window for any data retrieved

    HTCP_LOCK;
    if (aadsp_hii != NULL) {
        if (adsp_hc->adsc_in_list != NULL) {
            *aadsp_hii = adsp_hc->adsc_in_list;
            *aump_offset = adsp_hc->adsc_in_list->umc_offset;
            *aump_len = adsp_hc->adsc_in_list->umc_len;
            *abop_push = adsp_hc->adsc_in_list->boc_push;

            adsp_hc->adsc_in_list = adsp_hc->adsc_in_list->adsc_next;
            adsp_hc->umc_rcv_wnd_throttled += *aump_len;
        } else {
            *aadsp_hii = NULL;
            *aump_offset = 0;
            *aump_len = 0;
            *abop_push = false;
        }
    }

    if (adsp_hc->adsc_in_list == NULL) {
        *abop_more = false;
        switch (adsp_hc->iec_state) {
        case ied_htcp_close_wait:
        case ied_htcp_last_ack:
        case ied_htcp_closing:
        case ied_htcp_time_wait:
        case ied_htcp_closed:
            *abop_eof = true;
            break;

        default:
            *abop_eof = false;
        }
    } else {
        *abop_more = true;
        *abop_eof = false;
    }

    if (!bop_throttle) {
        bol_win_update = adsp_hc->umc_rcv_wnd < adsp_hc->umc_rcv_rmss;
        adsp_hc->umc_rcv_wnd += adsp_hc->umc_rcv_wnd_throttled;
        adsp_hc->umc_rcv_wnd_throttled = 0;
        bol_win_update = bol_win_update &&
            adsp_hc->umc_rcv_wnd >= adsp_hc->umc_rcv_rmss;
    }

    HTCP_UNLOCK;

    if (bol_win_update) {
        HTCP_LOCK;
        adsp_hc->utc_packet_flags |= utd_tcp_ack;
        HTCP_UNLOCK;
        bol_ret = adsp_hc->adsc_cb->amc_out_packets(adsp_hc);
        HTCP_CHECK_CB_RET(amc_out_packets);
     }
}

void m_htcp_timeout(struct dsd_htcp_conn* adsp_hc)
{
    bool bol_ret;
    int64_t ill_now_ms;

    bool bol_update_timer = false;
    int64_t ill_update_timer = 0;

    bool bol_transmitting = false;
    bool bol_restart_rxt = false;

    bol_ret = adsp_hc->adsc_cb->amc_get_time(adsp_hc, &ill_now_ms);
    HTCP_CHECK_CB_RET(amc_get_time);

    HTCP_LOCK;

    bol_transmitting = adsp_hc->boc_out_packet_promised;

    if (adsp_hc->ilc_timer != 0 && adsp_hc->ilc_timer <= ill_now_ms) {
        adsp_hc->ilc_timer = 0;

        // service retransmit/time_wait timer/zero window probe

#ifdef TRY_131219
		if ((adsp_hc->umc_exp_backoff == 1<<30 )  // allow 30 tries
			||((adsp_hc->iec_state == ied_htcp_syn_sent) && (adsp_hc->umc_exp_backoff == 4))){ //connecting retries
#else
        if (adsp_hc->umc_exp_backoff == 128  ) {
#endif
            // give up
            adsp_hc->iec_state = ied_htcp_closed;

            HTCP_UNLOCK;
            m_do_close(adsp_hc, ied_htcpc_conn_timeout, __LINE__,
                       "connection timed out");
            return;
        }

        adsp_hc->umc_recover = adsp_hc->umc_snd_nxt;

        switch (adsp_hc->iec_state) {
        case ied_htcp_closed:
            break;

        case ied_htcp_syn_sent:
            HTCP_LOCKED_ASSERT(m_get_tcp_flags_rst(adsp_hc->utc_packet_flags)
                               == 0);
            bol_restart_rxt = true;
            bol_transmitting = true;
            adsp_hc->umc_exp_backoff *= 2;
            adsp_hc->utc_packet_flags = utd_tcp_syn;
            break;

        case ied_htcp_syn_rcvd:
            HTCP_LOCKED_ASSERT(m_get_tcp_flags_rst(adsp_hc->utc_packet_flags)
                               == 0);
            bol_restart_rxt = true;
            bol_transmitting = true;
            adsp_hc->umc_exp_backoff *= 2;
            adsp_hc->utc_packet_flags = utd_tcp_syn_ack;
            break;

        case ied_htcp_established:
        case ied_htcp_close_wait:
        case ied_htcp_last_ack:
        case ied_htcp_fin_wait_1:
        case ied_htcp_closing:

#ifdef testzerowindowprintf
            printf("test zero window 1.\n");
#endif
#ifdef TRY_131219
            if ( m_wle(adsp_hc->umc_snd_nxt, adsp_hc->umc_snd_una + 1)) {
#else
            if ( adsp_hc->umc_snd_nxt == adsp_hc->umc_snd_una) {
#endif
                // nothing to retransmit
#ifdef testzerowindowprintf
                printf("test zero window 1 passed.\ntest zero window 2.\n");
#endif

                // check if we need to send zero window probe
                if (adsp_hc->utc_packet_flags == 0 &&
                    !adsp_hc->boc_out_packet_promised &&
                    m_wlt(adsp_hc->umc_snd_nxt_cur,
                    adsp_hc->umc_snd_una + adsp_hc->umc_send_pending)) {

#ifdef testzerowindowprintf
                    printf("test zero window 2 passed.\n");
#endif

#ifdef TRY_131219
                    if (adsp_hc->umc_snd_nxt == adsp_hc->umc_snd_una + 1) {
                       adsp_hc->umc_snd_nxt_cur = adsp_hc->umc_snd_una;
                    }
#endif

                    bol_transmitting = true;
                    bol_restart_rxt = true;
                    
#ifdef TRY_131219
                    adsp_hc->umc_rto_ms = 1000;
#endif
                    adsp_hc->boc_zwnd_probe = true;
                    adsp_hc->umc_exp_backoff *= 2;
                }
                // TODO: reset round-trip-time estimate?
                break;
            }

#ifdef testzerowindowprintf
            printf("umc_snd_nxt = %u, umc_snd_una = %u.\n", adsp_hc->umc_snd_nxt, adsp_hc->umc_snd_una );
#endif

            adsp_hc->umc_exp_backoff *= 2;
            adsp_hc->amc_cc_func(ied_htcp_cce_timeout,
                                 ill_now_ms,
                                 adsp_hc->umc_srtt_ms,
                                 adsp_hc->umc_snd_smss,
                                 adsp_hc->umc_snd_nxt_cur -
                                 adsp_hc->umc_snd_una,
                                 &adsp_hc->dsc_cc);

            if (adsp_hc->boc_recovering) {
                adsp_hc->boc_out_send_recover = false;
                adsp_hc->boc_recovering = false;
                adsp_hc->umc_out_sack_count = 0;
                adsp_hc->umc_sack_data_size = 0;
            }
            //adsp_hc->umc_recover = adsp_hc->umc_snd_nxt;

            // start retransmitting from last acked place
            adsp_hc->umc_snd_nxt_cur = adsp_hc->umc_snd_una;

            bol_transmitting = true;
            bol_restart_rxt = true;

            break;

        case ied_htcp_fin_wait_2:
            // should not really arrive here:
            // nothing to retransmit, timer should have been released
            break;

        case ied_htcp_time_wait:
            adsp_hc->iec_state = ied_htcp_closed;
            HTCP_UNLOCK;
            m_do_close(adsp_hc, ied_htcpc_normal, __LINE__,
                       "connection ended normally");
            return;

        default:
            // should not arrive here
            HTCP_LOCKED_ERROR("invalid state inside m_htcp_timeout()");
        }

        // if too much timeouts, reset rtt estimate (RFC 2988 5)
        if (adsp_hc->umc_exp_backoff >= 8)
            adsp_hc->umc_srtt_ms = 0;
    }

    // if transmitting something, ACK will be sent, so clear delayed ACK timer
    if (bol_transmitting)
        adsp_hc->ilc_da_timer = 0;

    if (adsp_hc->ilc_da_timer != 0) {
        if (adsp_hc->ilc_da_timer <= ill_now_ms) {
            adsp_hc->ilc_da_timer = 0;

            // service delayed ACK timer

            HTCP_LOCKED_ASSERT(adsp_hc->utc_packet_flags == 0);
            adsp_hc->utc_packet_flags = utd_tcp_ack;
        }
    }

    if (bol_restart_rxt) {
        bol_ret = m_locked_restart_rexmt_timer(adsp_hc,
                                               &bol_update_timer,
                                               &ill_update_timer,
                                               ill_now_ms);
        if (!bol_ret)
            return;
    }

    if (adsp_hc->ilc_timer != 0) {
        bol_update_timer = true;
        if (adsp_hc->ilc_da_timer != 0 &&
            adsp_hc->ilc_da_timer < adsp_hc->ilc_timer) {

            ill_update_timer = adsp_hc->ilc_da_timer;
        } else {
            ill_update_timer = adsp_hc->ilc_timer;
        }
    } else if (adsp_hc->ilc_da_timer != 0) {
        bol_update_timer = true;
        ill_update_timer = adsp_hc->ilc_da_timer;
    } else {
        bol_update_timer = false;
    }

    bol_transmitting = false;
    if (!adsp_hc->boc_out_packet_promised) {
        bol_ret = m_locked_packets_available(adsp_hc, &bol_transmitting);
        if (!bol_ret)
            return;
        adsp_hc->boc_out_packet_promised = bol_transmitting;
    }

    HTCP_UNLOCK;

    if (bol_transmitting) {
        bol_ret = adsp_hc->adsc_cb->amc_out_packets(adsp_hc);
        HTCP_CHECK_CB_RET(amc_out_packets);
    }

    if (bol_update_timer) {
        bol_ret = adsp_hc->adsc_cb->amc_set_timer(adsp_hc,
                                                  ill_update_timer -
                                                  ill_now_ms);
        HTCP_CHECK_CB_RET(amc_set_timer);
    }
}

void m_htcp_out_get_packet(struct dsd_htcp_conn* adsp_hc,
                           char* achp_header, uint32_t* aump_hlen,
                           uint32_t* aump_offset, uint32_t* aump_dlen,
                           bool* abop_more)
{
    int64_t ill_now_ms;
    int64_t ill_update_timer = 0;
    bool bol_update_timer = false;
    uint32_t uml_pending;
    uint32_t uml_cwnd;
    uint8_t utl_flags;
    uint16_t usl_chksum;
    uint32_t uml_seq;
    uint32_t uml_offset;
    uint32_t uml_to_send;
    uint32_t uml_smss;
    uint32_t uml_nxt_offset;
    const char* achl_part_buf;
    uint32_t uml_part_data_len;
    uint32_t uml_cur_data_len;
    bool bol_send_fin;
    bool bol_have_packet;
    bool bol_packet;
    bool bol_ret;

    bol_ret = adsp_hc->adsc_cb->amc_get_time(adsp_hc, &ill_now_ms);
    HTCP_CHECK_CB_RET(amc_get_time);

    HTCP_LOCK;

    bol_have_packet = adsp_hc->boc_out_packet_promised;
    adsp_hc->boc_out_packet_promised = false;
    if (!bol_have_packet) {
        bol_ret = m_locked_packets_available(adsp_hc, &bol_have_packet);
        if (!bol_ret) {
            // TODO: maybe better error reporting
            *aump_hlen = 0;
            *aump_offset = 0;
            *aump_dlen = 0;
            *abop_more = false;
            return;
        }
    }

    if (!bol_have_packet) {
        HTCP_UNLOCK;
        *aump_hlen = 0;
        *aump_offset = 0;
        *aump_dlen = 0;
        *abop_more = false;
        return;
    }

    // there is no need to keep delayed ACK timer
    if (adsp_hc->ilc_da_timer != 0) {
        bol_ret = m_locked_stop_da_timer(adsp_hc, &bol_update_timer,
                                         &ill_update_timer);
        if (!bol_ret) {
            // TODO: maybe better error reporting
            *aump_hlen = 0;
            *aump_offset = 0;
            *aump_dlen = 0;
            *abop_more = false;
            return;
        }
    }

    usl_chksum = adsp_hc->usc_pseudo_header_chksum;

    utl_flags = adsp_hc->utc_packet_flags;
    adsp_hc->utc_packet_flags = 0;

    if (m_get_tcp_flags_rst(utl_flags)) {
        // RST
        m_set_tcp_seqn(achp_header, adsp_hc->umc_packet_seq);
        m_set_tcp_ackn(achp_header, adsp_hc->umc_packet_ack);
        HTCP_UNLOCK;
        m_set_tcp_src_port(achp_header, adsp_hc->usc_local_port);
        m_set_tcp_dst_port(achp_header, adsp_hc->usc_remote_port);
        m_set_calc_tcp_hlen(achp_header, 20);
        m_set_tcp_resv(achp_header, 0);
        m_set_tcp_flags(achp_header, utl_flags);
        m_set_tcp_window(achp_header, 0);
        m_set_tcp_urgent(achp_header, 0);

        usl_chksum = m_calc_tcp_chksum(achp_header, 0, usl_chksum);
        m_set_tcp_chksum(achp_header, usl_chksum);

        *aump_hlen = 20;
        *aump_offset = 0;
        *aump_dlen = 0;
        *abop_more = false;
        return; // RST
    }

    if (m_get_tcp_flags_syn(utl_flags)) {
        // SYN
        uml_seq = adsp_hc->umc_snd_iss;

        bol_ret = m_locked_prepare_syn(adsp_hc, achp_header, aump_hlen,
                                       m_get_tcp_flags_ack(utl_flags),
                                       ill_now_ms);

        if (bol_ret) {
            bol_ret = m_locked_restart_rexmt_timer(adsp_hc,
                                                   &bol_update_timer,
                                                   &ill_update_timer,
                                                   ill_now_ms);
        }

        if (bol_ret) {
            bol_ret = m_locked_rto_sending(adsp_hc, ill_now_ms,
                                           uml_seq, 1);
        }

        if (!bol_ret) {
            // TODO: maybe better error reporting
            *aump_hlen = 0;
            *aump_offset = 0;
            *aump_dlen = 0;
            *abop_more = false;
            return;
        }

        HTCP_UNLOCK;

        usl_chksum = m_calc_tcp_chksum(achp_header, 0, usl_chksum);
        m_set_tcp_chksum(achp_header, usl_chksum);

        *aump_offset = 0;
        *aump_dlen = 0;
        *abop_more = false;

        if (bol_update_timer) {
            bol_ret = m_update_timer(adsp_hc, ill_now_ms, ill_update_timer);
            if (!bol_ret)
                return;
        }

        return; // SYN
    }

    // If we do not have to send SYN flag, we cannot be in all states.
    HTCP_LOCKED_ASSERT(adsp_hc->iec_state != ied_htcp_syn_sent &&
                       adsp_hc->iec_state != ied_htcp_syn_rcvd &&
                       adsp_hc->iec_state != ied_htcp_syn_sent_eof &&
                       adsp_hc->iec_state != ied_htcp_syn_rcvd_eof);


    // When sending RST or SYN, no more packets would be available. From now
    // on, we must check if more packets are available before returning.

    bol_send_fin = (adsp_hc->iec_state == ied_htcp_syn_rcvd_eof ||
                    adsp_hc->iec_state == ied_htcp_fin_wait_1 ||
                    adsp_hc->iec_state == ied_htcp_closing ||
                    adsp_hc->iec_state == ied_htcp_last_ack);

    utl_flags = utd_tcp_ack;
    HTCP_LOCKED_ASSERT(m_wge(adsp_hc->umc_snd_nxt_cur, adsp_hc->umc_snd_una));
    uml_nxt_offset = adsp_hc->umc_snd_nxt_cur - adsp_hc->umc_snd_una;
    uml_pending = adsp_hc->umc_send_pending;
    HTCP_LOCKED_ASSERT(uml_pending + (bol_send_fin ? 1 : 0)
                       >= uml_nxt_offset);
    uml_cwnd = adsp_hc->dsc_cc.umc_cwnd;

    bol_ret = m_locked_start_header(adsp_hc, achp_header, aump_hlen,
                                    utl_flags, 0, ill_now_ms);
    if (!bol_ret) {
        // TODO: maybe better error reporting
        *aump_hlen = 0;
        *aump_offset = 0;
        *aump_dlen = 0;
        *abop_more = false;
        return;
    }

    if (adsp_hc->boc_zwnd_probe) {
        adsp_hc->boc_zwnd_probe = false;

        if (uml_pending > uml_nxt_offset) { // useless without pending data
            bol_ret = m_locked_packets_available(adsp_hc, abop_more);
            if (!bol_ret) {
                // TODO: maybe better error reporting
                *aump_hlen = 0;
                *aump_offset = 0;
                *aump_dlen = 0;
                *abop_more = false;
                return;
            }
            adsp_hc->boc_out_packet_promised = *abop_more;

            adsp_hc->umc_last_ack_sent = adsp_hc->umc_rcv_nxt;

            if (m_wle(adsp_hc->umc_snd_nxt, adsp_hc->umc_snd_nxt_cur)) {
                adsp_hc->umc_snd_nxt = adsp_hc->umc_snd_nxt_cur + 1;
            }

            HTCP_UNLOCK;

            bol_ret = adsp_hc->adsc_cb->
                amc_out_get(adsp_hc, uml_nxt_offset,
                            &achl_part_buf, &uml_part_data_len);
            HTCP_CHECK_CB_RET(amc_out_get);
            HTCP_ASSERT(uml_part_data_len > 0);
            usl_chksum = m_calc_tcp_data_chksum(achl_part_buf, 1, usl_chksum);
            usl_chksum = m_calc_tcp_chksum(achp_header, 1, usl_chksum);
            m_set_tcp_chksum(achp_header, usl_chksum);

            *aump_offset = uml_nxt_offset;
            *aump_dlen = 1;

            return; // zero window probe
        }
    }

    // The special cases RST, SYN and zero window probe are handled by now.
    // From now on, some work is shared at a later stage.

    if (uml_pending > adsp_hc->umc_snd_wnd) {
        uml_pending = adsp_hc->umc_snd_wnd;
        bol_send_fin = false;
    }

    bol_packet = false;

    if (adsp_hc->boc_recovering) {

        if (adsp_hc->boc_recover_packet) {
            uml_seq = adsp_hc->umc_packet_seq;
            HTCP_LOCKED_ASSERT(m_wge(uml_seq, adsp_hc->umc_snd_una));
            bol_packet = true;
        } else if (adsp_hc->boc_use_sack) {
            bol_ret = m_locked_sack_nextseg(adsp_hc, &bol_packet, &uml_seq);
            if (!bol_ret) {
                // TODO: maybe better error reporting
                *aump_hlen = 0;
                *aump_offset = 0;
                *aump_dlen = 0;
                *abop_more = false;
                return;
            }
        }
    }

    // limited transmit
    if (!bol_packet && adsp_hc->umc_limited_transmit > 0) {
        --adsp_hc->umc_limited_transmit;
        if (uml_pending > uml_nxt_offset &&
            uml_cwnd + 2 * adsp_hc->umc_snd_smss > uml_nxt_offset) {

            bol_packet = true;
            uml_seq = adsp_hc->umc_snd_nxt_cur;
        } else {
            adsp_hc->umc_limited_transmit = 0;
        }
    }

    if (!bol_packet &&
        adsp_hc->boc_recovering && adsp_hc->umc_pending_dacks > 0) {

        --adsp_hc->umc_pending_dacks;
        if (uml_pending > uml_nxt_offset &&
            uml_cwnd > uml_nxt_offset) {

            bol_packet = true;
            uml_seq = adsp_hc->umc_snd_nxt_cur;
        } else {
            adsp_hc->umc_pending_dacks = 0;
        }
    }

    if (!bol_packet &&
        ((uml_pending > uml_nxt_offset && uml_cwnd > uml_nxt_offset) ||
         (uml_pending == uml_nxt_offset && bol_send_fin))) {

        bol_packet = true;
        uml_seq = adsp_hc->umc_snd_nxt_cur;
    }

    // now the work to construct the packet

    if (bol_packet) {
        HTCP_LOCKED_ASSERT(m_within(adsp_hc->umc_snd_una,
            adsp_hc->umc_snd_una + adsp_hc->umc_send_pending + 1,
            uml_seq));
        uml_offset = uml_seq - adsp_hc->umc_snd_una;
        if (uml_pending > uml_offset) {
            uml_to_send = uml_pending - uml_offset;
        } else {
            // latest assertion above implies uml_pending == uml_offset
            uml_to_send = 0;
        }

        uml_smss = adsp_hc->umc_snd_smss;
        if (adsp_hc->boc_use_timestamp) {
            HTCP_LOCKED_ASSERT(*aump_hlen >= 32);
            HTCP_LOCKED_ASSERT(uml_smss > (*aump_hlen - 32));
            uml_smss -= (*aump_hlen - 32);
        } else {
            HTCP_LOCKED_ASSERT(*aump_hlen >= 20);
            HTCP_LOCKED_ASSERT(uml_smss > (*aump_hlen - 20));
            uml_smss -= (*aump_hlen - 20);
        }

        if (uml_to_send > uml_smss) {
            uml_to_send = uml_smss;
            bol_send_fin = false;
        }

        if (adsp_hc->boc_recovering) {
            HTCP_LOCKED_ASSERT(adsp_hc->umc_snd_nxt ==
                               adsp_hc->umc_snd_nxt_cur);
            if (m_wlt(uml_seq, adsp_hc->umc_snd_nxt)) {
                adsp_hc->umc_high_rxt = uml_seq + uml_to_send;
                if (m_wgt(adsp_hc->umc_high_rxt, adsp_hc->umc_snd_nxt))
                    adsp_hc->umc_high_rxt = adsp_hc->umc_snd_nxt;
            }
            if (adsp_hc->boc_use_sack)
                adsp_hc->umc_sack_pipe += uml_to_send;
        }

        if (bol_send_fin) {
            adsp_hc->umc_snd_nxt_cur = uml_seq + uml_to_send + 1;
            adsp_hc->umc_snd_nxt = adsp_hc->umc_snd_nxt_cur;
        } else {
            if (m_wlt(adsp_hc->umc_snd_nxt_cur, uml_seq + uml_to_send)) {
                adsp_hc->umc_snd_nxt_cur = uml_seq + uml_to_send;
            }
            if (m_wlt(adsp_hc->umc_snd_nxt, uml_seq + uml_to_send)) {
                adsp_hc->umc_snd_nxt = uml_seq + uml_to_send;
            }
        }
    } else {
        uml_seq = adsp_hc->umc_snd_nxt_cur;
        bol_send_fin = false;
        uml_offset = 0;
        uml_to_send = 0;
    }

    *aump_offset = uml_offset;
    *aump_dlen = uml_to_send;

    if (uml_to_send == 0 && adsp_hc->umc_tosend_dack > 0)
        --adsp_hc->umc_tosend_dack;

    if (!adsp_hc->boc_use_timestamp) {
        bol_ret = m_locked_rto_sending(adsp_hc, ill_now_ms,
                                       uml_seq, uml_to_send);
        if (!bol_ret) {
            // TODO: maybe better error reporting
            *aump_hlen = 0;
            *aump_offset = 0;
            *aump_dlen = 0;
            *abop_more = false;
            return;
        }
    }

    if ((uml_to_send > 0 || bol_send_fin) && adsp_hc->ilc_timer == 0) {
        bol_ret = m_locked_restart_rexmt_timer(adsp_hc, &bol_update_timer,
                                               &ill_update_timer, ill_now_ms);
        if (!bol_ret) {
            // TODO: maybe better error reporting
            *aump_hlen = 0;
            *aump_offset = 0;
            *aump_dlen = 0;
            *abop_more = false;
            return;
        }
    }

    bol_ret = m_locked_packets_available(adsp_hc, abop_more);
    if (!bol_ret) {
        // TODO: maybe better error reporting
        *aump_hlen = 0;
        *aump_offset = 0;
        *aump_dlen = 0;
        *abop_more = false;
        return;
    }
    adsp_hc->boc_out_packet_promised = *abop_more;

    adsp_hc->umc_last_ack_sent = adsp_hc->umc_rcv_nxt;

    HTCP_UNLOCK;

    // complete header

    m_set_tcp_seqn(achp_header, uml_seq);
    if (bol_send_fin)
        m_set_tcp_fin(achp_header, 1);
    else if (bol_packet && !*abop_more)
        m_set_tcp_psh(achp_header, 1);

    // calculate checksum

    uml_cur_data_len = 0;
    while (uml_cur_data_len < uml_to_send) {
        bol_ret = adsp_hc->adsc_cb->
            amc_out_get(adsp_hc, uml_offset + uml_cur_data_len,
                        &achl_part_buf, &uml_part_data_len);
        HTCP_CHECK_CB_RET(amc_out_get);

        HTCP_ASSERT(uml_part_data_len > 0);

        if (uml_cur_data_len + uml_part_data_len > uml_to_send) {
            HTCP_ASSERT(uml_to_send > uml_cur_data_len);
            uml_part_data_len = uml_to_send - uml_cur_data_len;
        }

        if (uml_cur_data_len % 2 == 0) {
            usl_chksum = m_calc_tcp_data_chksum(achl_part_buf,
                                                uml_part_data_len,
                                                usl_chksum);
        } else {
            usl_chksum = m_calc_tcp_odd_data_chksum(achl_part_buf,
                                                    uml_part_data_len,
                                                    usl_chksum);
        }

        uml_cur_data_len += uml_part_data_len;
    }

    HTCP_ASSERT(m_get_calc_tcp_hlen(achp_header) == *aump_hlen);
    usl_chksum = m_calc_tcp_chksum(achp_header, uml_to_send, usl_chksum);
    m_set_tcp_chksum(achp_header, usl_chksum);

    // checksum calculation done

    if (bol_update_timer) {
        bol_ret = m_update_timer(adsp_hc, ill_now_ms, ill_update_timer);
        if (!bol_ret)
            return;
    }
}

void m_htcp_abort(struct dsd_htcp_conn* adsp_hc, bool bop_reset)
{
    bool bol_close;
    bool bol_ack;
    uint32_t uml_seq_or_ack;

    HTCP_LOCK;

    switch (adsp_hc->iec_state) {

    case ied_htcp_closed:
    case ied_htcp_listen:
        bol_close = false;
        break;

    case ied_htcp_syn_rcvd:
    case ied_htcp_syn_rcvd_eof:
        bol_close = true;
        bol_ack = true;
        uml_seq_or_ack = adsp_hc->umc_last_ack_sent;
        break;

    default:
        bol_close = true;
        bol_ack = false;
        uml_seq_or_ack = adsp_hc->umc_snd_nxt;
    }

    adsp_hc->iec_state = ied_htcp_closed;

    HTCP_UNLOCK;

    if (bol_close) {
        if (bop_reset)
            m_send_rst(adsp_hc, uml_seq_or_ack, bol_ack);

        m_do_close(adsp_hc, ied_htcpc_local_reset, __LINE__,
                   "connection reset by application");
    }
}

void m_htcp_status(struct dsd_htcp_conn* adsp_hc,
                   struct dsd_htcp_status* adsp_hs)
{
    HTCP_LOCK;
    adsp_hs->umc_out_queue_len = adsp_hc->umc_send_pending;
    adsp_hs->umc_out_in_flight = adsp_hc->umc_snd_nxt - adsp_hc->umc_snd_una;

    if (adsp_hc->iec_state == ied_htcp_syn_sent ||
        adsp_hc->iec_state == ied_htcp_syn_rcvd ||
        adsp_hc->iec_state == ied_htcp_syn_sent_eof ||
        adsp_hc->iec_state == ied_htcp_syn_rcvd_eof) {

        --adsp_hs->umc_out_in_flight;
    }

    if (adsp_hc->iec_state == ied_htcp_syn_rcvd_eof ||
        adsp_hc->iec_state == ied_htcp_fin_wait_1 ||
        adsp_hc->iec_state == ied_htcp_closing ||
        adsp_hc->iec_state == ied_htcp_last_ack) {

        --adsp_hs->umc_out_in_flight;
    }

    HTCP_UNLOCK;
}

void m_htcp_describe_close(struct dsd_htcp_conn* adsp_hc,
                           char* achp_description, uint32_t* aump_dlen,
                           char* achp_debug_info, uint32_t* aump_dilen)
{
    int inl_ret;

    if (adsp_hc->iec_htcpc == ied_htcpc_open) {
        *aump_dlen = 0;
        *aump_dilen = 0;
        return;
    }

    if (achp_description != NULL && aump_dlen != NULL && *aump_dlen > 0) {
        switch (adsp_hc->iec_htcpc) {
        case ied_htcpc_normal:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection closed normally");
            break;

        case ied_htcpc_conn_refused:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection refused");
            break;

        case ied_htcpc_conn_timeout:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection timed out");
            break;

        case ied_htcpc_conn_error:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection error");
            break;

        case ied_htcpc_remote_reset:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection reset by peer");
            break;

        case ied_htcpc_local_reset:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection reset by application");
            break;

        case ied_htcpc_error:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection internal error");
            break;

        case ied_htcpc_interface_error:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection interface error");
            break;

        case ied_htcpc_application_error:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection application error");
            break;

        default:
            inl_ret = snprintf(achp_description, *aump_dlen, "%s",
                               "connection closed");
        }
        if (inl_ret < 0)
            *aump_dlen = 0;
        else
            *aump_dlen = inl_ret;
    }

    if (achp_debug_info != NULL && aump_dilen != NULL && *aump_dilen > 0) {
        inl_ret = snprintf(achp_debug_info, *aump_dilen, "%s%04d%s%s",
                           "xs-htcp-01.cpp:", adsp_hc->inc_close_line,
                           " - ", adsp_hc->achc_close_reason);
        if (inl_ret < 0)
            *aump_dilen = 0;
        else
            *aump_dilen = inl_ret;
    }
}


static void m_do_close(struct dsd_htcp_conn* adsp_hc,
                       enum ied_htcp_close iep_htcpc,
                       int inp_line, const char* achp_why)
{
    struct dsd_htcp_in_info* adsl_hii;

    while (adsp_hc->adsc_in_list != NULL) {
        adsl_hii = adsp_hc->adsc_in_list;
        adsp_hc->adsc_in_list = adsl_hii->adsc_next;
        adsp_hc->adsc_cb->amc_in_rel(adsp_hc, adsl_hii);
    }

    while (adsp_hc->adsc_oo_list != NULL) {
        adsl_hii = adsp_hc->adsc_oo_list;
        adsp_hc->adsc_oo_list = adsl_hii->adsc_next;
        adsp_hc->adsc_cb->amc_in_rel(adsp_hc, adsl_hii);
    }

    adsp_hc->adsc_cb->amc_rel_timer(adsp_hc);

    //adsp_hc->iec_state = ied_htcp_closed;
    adsp_hc->iec_htcpc = iep_htcpc;
    adsp_hc->achc_close_reason = achp_why;
    adsp_hc->inc_close_line = inp_line;
    adsp_hc->adsc_cb->amc_closed(adsp_hc, iep_htcpc);
}

static void m_do_abort(struct dsd_htcp_conn* adsp_hc,
                       enum ied_htcp_close iep_htcpc,
                       int inp_line, const char* achp_why)
{
    bool bol_close;

    adsp_hc->adsc_cb->amc_lock(adsp_hc);
    bol_close = adsp_hc->iec_state != ied_htcp_closed;
    adsp_hc->iec_state = ied_htcp_closed;
    adsp_hc->adsc_cb->amc_unlock(adsp_hc);

    if (bol_close) {
        m_do_close(adsp_hc, iep_htcpc, inp_line, achp_why);
    }
}

static bool m_locked_process_syn_options(struct dsd_htcp_conn* adsp_hc,
                                         const char* achp_tcp_header,
                                         uint32_t ump_hlen)
{
    const char* achl_option;
    bool bol_search_mss = true;
    bool bol_search_winscale = adsp_hc->boc_use_winscale;
    bool bol_search_sack = adsp_hc->boc_use_sack;
    bool bol_search_timestamp = adsp_hc->boc_use_timestamp;
    uint16_t usl_mss;

    // adsp_hc->umc_snd_smss is already set to default

    achl_option = m_first_tcp_option(achp_tcp_header,
                                     achp_tcp_header + ump_hlen);
    while (achl_option < achp_tcp_header + ump_hlen) {
        switch (achl_option[0]) {
        case 2: // mss
            if (!bol_search_mss || achl_option[1] != 4)
                break;
            usl_mss = m_get_16_bit(achl_option + 2);
            if (usl_mss < adsp_hc->umc_snd_smss) {
                if (usl_mss < 536)
                    adsp_hc->umc_snd_smss = 536;
                else
                    adsp_hc->umc_snd_smss = usl_mss;
            }
            bol_search_mss = false;
            break;

        case 3: // window scaling
            if (!bol_search_winscale || achl_option[1] != 3)
                break;
            adsp_hc->umc_snd_winscale = *(const uint8_t*)(achl_option + 2);
            if (adsp_hc->umc_snd_winscale > 14)
                adsp_hc->umc_snd_winscale = 14;
            bol_search_winscale = false;
            break;

        case 4: // allow SACK
            if (!bol_search_sack || achl_option[1] != 2)
                break;
            bol_search_sack = false;
            break;

        case 8: // timestamps
            if (!bol_search_timestamp || achl_option[1] != 10)
                break;
            adsp_hc->umc_ts_recent = m_get_32_bit(achl_option + 2);
            bol_search_timestamp = false;
            break;
        }

        achl_option = m_next_tcp_option(achl_option,
                                        achp_tcp_header + ump_hlen);
    }

    if (bol_search_mss) {
        adsp_hc->umc_snd_smss = 536;
    }

    if (bol_search_winscale) {
        adsp_hc->boc_use_winscale = false;
        adsp_hc->umc_rcv_winscale = 0;
    }

    if (bol_search_sack) {
        adsp_hc->boc_use_sack = false;
    }

    if (bol_search_timestamp) {
        adsp_hc->boc_use_timestamp = false;
    } else if (adsp_hc->boc_use_timestamp) {
        adsp_hc->umc_snd_smss -= 12;
    }

    // TODO: if this is SYNACK with timestamp, update rtt estimate

    return true;
}

// um_flight = um_snd_nxt - um_snd_una
static void m_cc_newreno(enum ied_htcp_cc_event iep_cce_e,
                         int64_t ilp_time, uint32_t ump_rtt_ms,
                         uint32_t ump_snd_smss, uint32_t ump_flight,
                         struct dsd_htcp_cc* adsp_cc)
{
    struct dsd_htcp_cc_newreno* adsl_newreno = &adsp_cc->dsc_ucc.dsc_cc_newreno;

    switch (iep_cce_e) {
    case ied_htcp_cce_init:
        // adsp_cc->umc_cwnd = ump_snd_smss; // may be up to 2 * ump_snd_smss
        /*
        adsp_cc->umc_cwnd = 4380;
        if (adsp_cc->umc_cwnd < 2 * ump_snd_smss)
            adsp_cc->umc_cwnd = 2 * ump_snd_smss;
        if (adsp_cc->umc_cwnd > 4 * ump_snd_smss)
            adsp_cc->umc_cwnd = 4 * ump_snd_smss;
        */
        // draft-ietf-tcpm-initcwnd-03
        adsp_cc->umc_cwnd = 14600;
        if (adsp_cc->umc_cwnd < 2 * ump_snd_smss)
            adsp_cc->umc_cwnd = 2 * ump_snd_smss;
        if (adsp_cc->umc_cwnd > 10 * ump_snd_smss)
            adsp_cc->umc_cwnd = 10 * ump_snd_smss;
        // draft-ietf-tcpm-initcwnd-03
        adsl_newreno->umc_ssthresh = 65535; // arbitrary
        adsp_cc->umc_bytes_acked = 0;
        break;

    case ied_htcp_cce_newack:
        if (adsp_cc->umc_cwnd <= adsl_newreno->umc_ssthresh) {
            // slow start
            //adsp_cc->umc_cwnd += ump_snd_smss;
            // appropriate byte counting
            if (adsp_cc->umc_bytes_acked >= ump_snd_smss) {
                adsp_cc->umc_bytes_acked -= ump_snd_smss;
                adsp_cc->umc_cwnd += ump_snd_smss;
                if (adsp_cc->umc_bytes_acked > ump_snd_smss)
                    adsp_cc->umc_bytes_acked = ump_snd_smss;
            }
        } else {
            // congestion avoidance
            // adsp_cc->umc_cwnd += (std::max)(uint32(1),
            //               ump_snd_smss * ump_snd_smss / adsp_cc->umc_cwnd);
            // appropriate byte counting
            if (adsp_cc->umc_bytes_acked >= adsp_cc->umc_cwnd) {
                adsp_cc->umc_bytes_acked -= adsp_cc->umc_cwnd;
                adsp_cc->umc_cwnd += ump_snd_smss;
            }
        }
        break;

    case ied_htcp_cce_timeout:
        if (true || adsl_newreno->umc_ssthresh > ump_flight / 2)
            adsl_newreno->umc_ssthresh = ump_flight / 2;
        if (adsl_newreno->umc_ssthresh < 2 * ump_snd_smss)
            adsl_newreno->umc_ssthresh = 2 * ump_snd_smss;
        adsp_cc->umc_cwnd = ump_snd_smss;
        adsp_cc->umc_bytes_acked = 0;
        break;

    case ied_htcp_cce_three_dup:
        if (true || adsl_newreno->umc_ssthresh > ump_flight / 2)
            adsl_newreno->umc_ssthresh = ump_flight / 2;
        if (adsl_newreno->umc_ssthresh < 2 + ump_snd_smss)
            adsl_newreno->umc_ssthresh = 2 + ump_snd_smss;
        adsp_cc->umc_cwnd = adsl_newreno->umc_ssthresh + 3 * ump_snd_smss;
        break;

    case ied_htcp_cce_three_dup_sack:
        if (true || adsl_newreno->umc_ssthresh > ump_flight / 2)
            adsl_newreno->umc_ssthresh = ump_flight / 2;
        if (adsl_newreno->umc_ssthresh < 2 + ump_snd_smss)
            adsl_newreno->umc_ssthresh = 2 + ump_snd_smss;
        adsp_cc->umc_cwnd = adsl_newreno->umc_ssthresh;
        break;

    case ied_htcp_cce_more_dup:
        adsp_cc->umc_cwnd += ump_snd_smss;
        break;

    case ied_htcp_cce_recover_ack:
        adsp_cc->umc_cwnd = adsl_newreno->umc_ssthresh;
        // New Reno improvement:
        if (adsp_cc->umc_cwnd > ump_flight + ump_snd_smss)
            adsp_cc->umc_cwnd = ump_flight + ump_snd_smss;
        break;
    }
}

static uint32_t m_cbrt(uint32_t ump_x)
{
    int inl_i;
    uint32_t uml_y, uml_b, uml_y2;

    uml_y2 = 0;
    uml_y = 0;
    for (inl_i = 30; inl_i >= 0; inl_i -= 3) {
        uml_y2 <<= 2;
        uml_y <<= 1;
        uml_b = (3 * (uml_y2 + uml_y) + 1) << inl_i;
        if (ump_x >= uml_b) {
            ump_x -= uml_b;
            uml_y2 += uml_y + uml_y + 1;
            ++uml_y;
        }
    }
    return uml_y;
}

// um_flight = um_snd_nxt - um_snd_una
static void m_cc_cubic(enum ied_htcp_cc_event iep_cce_e,
                       int64_t ilp_time, uint32_t ump_rtt_ms,
                       uint32_t ump_snd_smss, uint32_t ump_flight,
                       struct dsd_htcp_cc* adsp_cc)
{
    int64_t ill_t;
    uint32_t uml_target;

    if (ilp_time == 0)
        ilp_time = 1;

    struct dsd_htcp_cc_cubic* adsl_cubic = &adsp_cc->dsc_ucc.dsc_cc_cubic;

    switch (iep_cce_e) {
    case ied_htcp_cce_init:
        adsp_cc->umc_cwnd = 14600;
        if (adsp_cc->umc_cwnd < 2 * ump_snd_smss)
            adsp_cc->umc_cwnd = 2 * ump_snd_smss;
        if (adsp_cc->umc_cwnd > 10 * ump_snd_smss)
            adsp_cc->umc_cwnd = 10 * ump_snd_smss;
        adsl_cubic->umc_ssthresh = 65535; // arbitrary
        adsp_cc->umc_bytes_acked = 0;

        adsl_cubic->umc_w_lastmax = 0;
        adsl_cubic->ilc_epoch_start = 0;
        adsl_cubic->umc_origin_point = 0;
        adsl_cubic->umc_dmin = 0;
        adsl_cubic->umc_wtcp = 0;
        adsl_cubic->umc_k = 0;
        adsl_cubic->umc_ack_cnt = 0;
        break;

    case ied_htcp_cce_newack:
    case ied_htcp_cce_recover_ack:
        if (adsl_cubic->umc_dmin == 0 || adsl_cubic->umc_dmin > ump_rtt_ms)
            adsl_cubic->umc_dmin = ump_rtt_ms;
        if (adsp_cc->umc_cwnd <= adsl_cubic->umc_ssthresh) {
            // slow start
            if (adsp_cc->umc_bytes_acked >= ump_snd_smss) {
                adsp_cc->umc_bytes_acked -= ump_snd_smss;
                adsp_cc->umc_cwnd += ump_snd_smss;
                if (adsp_cc->umc_bytes_acked > ump_snd_smss)
                    adsp_cc->umc_bytes_acked = ump_snd_smss;
            }
        } else {
            // congestion avoidance

            if (adsl_cubic->ilc_epoch_start == 0) {
                adsl_cubic->ilc_epoch_start = ilp_time;
                if (adsp_cc->umc_cwnd < adsl_cubic->umc_w_lastmax) {
                    adsl_cubic->umc_k =
                        m_cbrt((adsl_cubic->umc_w_lastmax - adsp_cc->umc_cwnd)
                               * 5 / 2);
                    adsl_cubic->umc_origin_point = adsl_cubic->umc_w_lastmax;
                } else {
                    adsl_cubic->umc_k = 0;
                    adsl_cubic->umc_origin_point = adsp_cc->umc_cwnd;
                }
                adsl_cubic->umc_wtcp = adsp_cc->umc_cwnd;
            }

            ill_t =
                ilp_time + adsl_cubic->umc_dmin - adsl_cubic->ilc_epoch_start;
            uml_target = ill_t - adsl_cubic->umc_k;
            uml_target *= uml_target * uml_target;
            uml_target = uml_target * 2 / 5 + adsl_cubic->umc_origin_point;

            if (adsl_cubic->umc_ack_cnt < adsp_cc->umc_bytes_acked) {
                adsl_cubic->umc_wtcp +=
                    (adsp_cc->umc_bytes_acked - adsl_cubic->umc_ack_cnt) *
                    ump_snd_smss / (adsp_cc->umc_cwnd * 3);
                adsl_cubic->umc_ack_cnt = adsp_cc->umc_bytes_acked;
            }

            if (uml_target < adsl_cubic->umc_wtcp)
                uml_target = adsl_cubic->umc_wtcp;
            if (uml_target > adsp_cc->umc_cwnd) {
                if (adsp_cc->umc_bytes_acked >
                    adsp_cc->umc_cwnd * ump_snd_smss /
                    (uml_target - adsp_cc->umc_cwnd)) {

                    adsp_cc->umc_bytes_acked = 0;
                    adsl_cubic->umc_ack_cnt = 0;
                    adsp_cc->umc_cwnd += ump_snd_smss;
                }
            }
        }
        break;

    case ied_htcp_cce_timeout:
        adsl_cubic->umc_ssthresh = ump_flight / 2;
        if (adsl_cubic->umc_ssthresh < 2 * ump_snd_smss)
            adsl_cubic->umc_ssthresh = 2 * ump_snd_smss;
        adsp_cc->umc_cwnd = ump_snd_smss;

        adsp_cc->umc_bytes_acked = 0;

        adsl_cubic->umc_w_lastmax = 0;
        adsl_cubic->ilc_epoch_start = 0;
        adsl_cubic->umc_origin_point = 0;
        adsl_cubic->umc_dmin = 0;
        adsl_cubic->umc_wtcp = 0;
        adsl_cubic->umc_k = 0;
        adsl_cubic->umc_ack_cnt = 0;
        break;

    case ied_htcp_cce_three_dup:
    case ied_htcp_cce_three_dup_sack:
        adsl_cubic->ilc_epoch_start = 0;
        adsl_cubic->umc_w_lastmax = adsp_cc->umc_cwnd;
        if (adsp_cc->umc_cwnd < adsl_cubic->umc_w_lastmax) {
            adsl_cubic->umc_w_lastmax -= adsp_cc->umc_cwnd / 10;
        }
        adsp_cc->umc_cwnd -= adsp_cc->umc_cwnd / 5;
        adsl_cubic->umc_ssthresh = adsp_cc->umc_cwnd;
        break;

    case ied_htcp_cce_more_dup:
        adsp_cc->umc_cwnd += ump_snd_smss;
        break;
    }
}

static void m_rto_init(struct dsd_htcp_conn* adsp_hc)
{
    adsp_hc->umc_srtt_ms = 0;
    adsp_hc->umc_rttvar_ms = 0;

	adsp_hc->umc_rto_ms = 3000; // 3 sec. for connecting (RFC 793), later 1000 (RFC 6298)

    adsp_hc->boc_rtt_calc_valid = false;
}

static bool m_locked_rto_sending(struct dsd_htcp_conn* adsp_hc,
                                 int64_t ilp_now_ms,
                                 uint32_t ump_seq, uint32_t ump_len)
{
    // if already timing and this send is no duplicate (Karn), return
    if (adsp_hc->boc_rtt_calc_valid &&
        !m_within(ump_seq, ump_seq + ump_len, adsp_hc->umc_rtt_calc_seq_sent)) {

        return true;
    }

    adsp_hc->boc_rtt_calc_valid = false;

    if (adsp_hc->umc_snd_nxt == adsp_hc->umc_snd_una &&
        m_within(ump_seq, ump_seq + ump_len, adsp_hc->umc_snd_nxt)) {
        // a usable unsent byte exists
        adsp_hc->ilc_rtt_calc_time_sent_ms = ilp_now_ms;
        adsp_hc->umc_rtt_calc_seq_sent = adsp_hc->umc_snd_nxt;
        adsp_hc->boc_rtt_calc_valid = true;
    }

    return true;
}

static bool m_locked_rto_received(struct dsd_htcp_conn* adsp_hc,
                                  int64_t ilp_now_ms)
{
    int64_t ill_this_rtt;
    int64_t ill_diff;

    if (adsp_hc->boc_use_timestamp)
        return true;

    if (!adsp_hc->boc_rtt_calc_valid) {
        return true;
    }

    if (!m_within(adsp_hc->umc_rtt_calc_seq_sent + 1, adsp_hc->umc_snd_nxt + 1,
                  adsp_hc->umc_snd_una)) {

        return true;
    }

    // relevant byte acknowledged - do update

    ill_this_rtt = ilp_now_ms - adsp_hc->ilc_rtt_calc_time_sent_ms;

    if (adsp_hc->umc_srtt_ms == 0) {
        // first measurement
        adsp_hc->umc_srtt_ms = ill_this_rtt;
        adsp_hc->umc_rttvar_ms = ill_this_rtt / 2;
    } else {
        ill_diff = ill_this_rtt;
        ill_diff -= adsp_hc->umc_srtt_ms;
        adsp_hc->umc_srtt_ms += ill_diff / 8;
        if (ill_diff < 0)
            ill_diff = -ill_diff;
        adsp_hc->umc_rttvar_ms += (ill_diff - adsp_hc->umc_rttvar_ms) / 4;
    }

    adsp_hc->umc_rto_ms = adsp_hc->umc_srtt_ms + 4 * adsp_hc->umc_rttvar_ms;
    if (adsp_hc->umc_rto_ms < 500) // SHOULD hava a minimum of 1s (using 0.5s)
        adsp_hc->umc_rto_ms = 500;
    else if (adsp_hc->umc_rto_ms > 60000) // MAY have a maximum of at least 60s
        adsp_hc->umc_rto_ms = 60000;

    adsp_hc->boc_rtt_calc_valid = false;

    return true;
}

static bool m_locked_rto_timestamp_update(struct dsd_htcp_conn* adsp_hc,
                                          int64_t ilp_now_ms,
                                          uint32_t ump_seg_tsecr)
{
    uint32_t uml_this_rtt = ilp_now_ms - ump_seg_tsecr;
    int64_t ill_diff;
    int32_t iml_w_num;
    int32_t iml_w_den;

    if (adsp_hc->umc_srtt_ms == 0) {
        // first measurement
        adsp_hc->umc_srtt_ms = uml_this_rtt;
        adsp_hc->umc_rttvar_ms = uml_this_rtt / 2;
        adsp_hc->umc_last_tsecr = ump_seg_tsecr;
    } else if (ump_seg_tsecr != adsp_hc->umc_last_tsecr) {
        ill_diff = uml_this_rtt;
        ill_diff -= adsp_hc->umc_srtt_ms;
        // TODO: check overflow when multiplying?
        iml_w_num = ilp_now_ms - adsp_hc->umc_last_update_ts;
        iml_w_den = adsp_hc->umc_srtt_ms;
        if (iml_w_num >= iml_w_den || true) { // TODO: clean
            adsp_hc->umc_srtt_ms += ill_diff / 8;
            if (ill_diff < 0)
                ill_diff = -ill_diff;
            adsp_hc->umc_rttvar_ms += (ill_diff - adsp_hc->umc_rttvar_ms) / 4;
        } else {
            adsp_hc->umc_srtt_ms +=
                (ill_diff / 8 * iml_w_num + iml_w_den - 1) / iml_w_den;
            if (ill_diff < 0)
                ill_diff = -ill_diff;
            adsp_hc->umc_rttvar_ms += ((ill_diff - adsp_hc->umc_rttvar_ms) / 4
                                       * iml_w_num + iml_w_den - 1) / iml_w_den;
        }
    }
    adsp_hc->umc_last_update_ts = ilp_now_ms;
    adsp_hc->umc_last_tsecr = ump_seg_tsecr;

    adsp_hc->umc_rto_ms = adsp_hc->umc_srtt_ms + 4 * adsp_hc->umc_rttvar_ms;
    // SHOULD hava a minimum of 1s (using 0.5s)
    // MAY have a maximum of at least 60s
    if (adsp_hc->umc_rto_ms < 500) {
        adsp_hc->umc_rto_ms = 500;
    } else if (adsp_hc->umc_rto_ms > 60000) {
        adsp_hc->umc_rto_ms = 60000;
    }

    return true;
}

static bool m_locked_create_timestamp_option(struct dsd_htcp_conn* adsp_hc,
                                             char* achp_o,
                                             int64_t ilp_now_ms)
{
    achp_o[0] = 8;
    achp_o[1] = 10;
    m_put_32_bit(achp_o + 2, ilp_now_ms);
    m_put_32_bit(achp_o + 6, adsp_hc->umc_ts_recent);

    return true;
}

static bool m_update_timer(struct dsd_htcp_conn* adsp_hc,
                           int64_t ilp_now_ms, int64_t ilp_timer)
{
    bool bol_ret;
    int inl_delay;
    int64_t ill_first;
    bool bol_repeat;

    do {
        bol_repeat = false;

        if (ilp_timer == 0) {
            bol_ret = adsp_hc->adsc_cb->amc_rel_timer(adsp_hc);
            HTCP_CHECK_CB_RET_F(amc_rel_timer);
        } else {
            inl_delay = ilp_timer - ilp_now_ms;
            if (inl_delay <= 0)
                inl_delay = 1;
            bol_ret = adsp_hc->adsc_cb->amc_set_timer(adsp_hc, inl_delay);
            HTCP_CHECK_CB_RET_F(amc_set_timer);
        }

        ill_first = 0;
        HTCP_LOCK_F;
        if (ill_first == 0 ||
            (adsp_hc->ilc_timer != 0 && adsp_hc->ilc_timer < ill_first)) {

            ill_first = adsp_hc->ilc_timer;
        }
        if (ill_first == 0 ||
            (adsp_hc->ilc_da_timer != 0 && adsp_hc->ilc_da_timer < ill_first)) {

            ill_first = adsp_hc->ilc_da_timer;
        }
        if (ilp_timer != ill_first) {
            ilp_timer = ill_first;
            bol_repeat = true;
        }
        HTCP_UNLOCK_F;

    } while (bol_repeat);

    return true;
}

static bool m_locked_stop_timer(struct dsd_htcp_conn* adsp_hc,
                                bool* abop_update, int64_t* ailp_update_timer,
                                int64_t* ailp_timer, int64_t ilp_other)
{
    if (*ailp_timer == 0) {
        return true;
    }

    if (ilp_other != 0) {
        if (ilp_other >= *ailp_timer) {
            *abop_update = true;
            *ailp_update_timer = ilp_other;
        }
    } else {
        *abop_update = true;
        *ailp_update_timer = 0;
    }

    *ailp_timer = 0;

    return true;
}

static bool m_locked_start_timer(struct dsd_htcp_conn* adsp_hc,
                                 bool* abop_update, int64_t* ailp_update_timer,
                                 int64_t* ailp_timer, int64_t ilp_new_time,
                                 int64_t ilp_other)
{
    if (ilp_new_time == 0)
        ilp_new_time = 1;

    if (*ailp_timer == ilp_new_time) {
        return true;
    }

    if (ilp_other == 0 || ilp_other >= ilp_new_time) {
        *abop_update = true;
        *ailp_update_timer = ilp_new_time;
    } else if (ilp_other > *ailp_timer) {
        *abop_update = true;
        *ailp_update_timer = ilp_other;
    }

    *ailp_timer = ilp_new_time;

    return true;
}

static bool m_locked_restart_rexmt_timer(struct dsd_htcp_conn* adsp_hc,
                                         bool* abop_update,
                                         int64_t* ailp_update_timer,
                                         int64_t ilp_now_ms)
{
    uint32_t uml_delay_ms;

    if (adsp_hc->umc_exp_backoff > 64)
        uml_delay_ms = 2 * adsp_hc->umc_msl_s * 1000; // one last time with 2MSL
    else
        uml_delay_ms = adsp_hc->umc_rto_ms * adsp_hc->umc_exp_backoff;

    return m_locked_start_timer(adsp_hc, abop_update, ailp_update_timer,
                                &adsp_hc->ilc_timer,
                                ilp_now_ms + uml_delay_ms,
                                adsp_hc->ilc_da_timer);
}

static bool m_locked_restart_time_wait_timer(struct dsd_htcp_conn* adsp_hc,
                                             bool* abop_update,
                                             int64_t* ailp_update_timer,
                                             int64_t ilp_now_ms)
{
    uint32_t uml_delay_ms = 2 * adsp_hc->umc_msl_s * 1000;

    return m_locked_start_timer(adsp_hc, abop_update, ailp_update_timer,
                                &adsp_hc->ilc_timer,
                                ilp_now_ms + uml_delay_ms,
                                adsp_hc->ilc_da_timer);
}


static bool m_locked_start_da_timer(struct dsd_htcp_conn* adsp_hc,
                                    bool* abop_update,
                                    int64_t* ailp_update_timer,
                                    int64_t ilp_now_ms)
{
    return m_locked_start_timer(adsp_hc, abop_update, ailp_update_timer,
                                &adsp_hc->ilc_da_timer,
                                ilp_now_ms + adsp_hc->umc_delay_ack_ms,
                                adsp_hc->ilc_timer);
}

static bool m_locked_stop_da_timer(struct dsd_htcp_conn* adsp_hc,
                                   bool* abop_update,
                                   int64_t* ailp_update_timer)
{
    return m_locked_stop_timer(adsp_hc, abop_update, ailp_update_timer,
                               &adsp_hc->ilc_da_timer, adsp_hc->ilc_timer);
}

static bool m_locked_update_rcv_sack(struct dsd_htcp_conn* adsp_hc,
                                     uint32_t ump_ack,
                                     const char* achp_option_data,
                                     int32_t imp_option_count)
{
    uint32_t umrl_left[4];
    uint32_t umrl_right[4];
    uint32_t uml_left;
    uint32_t uml_right;
    bool bol_drop;
    uint32_t umrl_buf_left[ins_htcp_out_sack_count];
    uint32_t umrl_buf_right[ins_htcp_out_sack_count];
    int32_t iml_buf_count;
    int32_t iml_i;
    int32_t iml_j;
    int32_t iml_k;

    // update the SACK options we receive - concerning output packets

    // Since we arrived here, we know that ump_ack is not before umc_snd_una

    HTCP_LOCKED_ASSERT_F(imp_option_count <= 4);

    // we can sort incoming SACK information - we do not use order yet
    for (iml_i = 0; iml_i < imp_option_count; ++iml_i) {
        uml_left = m_get_32_bit(achp_option_data);
        achp_option_data += 4;
        uml_right = m_get_32_bit(achp_option_data);
        achp_option_data += 4;

        if (m_wge(uml_left, uml_right) ||
            m_wle(uml_left, ump_ack) ||
            m_wgt(uml_right, adsp_hc->umc_snd_nxt)) {
            --imp_option_count;
            --iml_i;
            continue;
        }

        bol_drop = false;
        for (iml_j = 0; iml_j < iml_i; ++iml_j) {
            if (m_wlt(uml_right, umrl_left[iml_j])) {
                // current block precedes block j
                for (iml_k = iml_i; iml_k > iml_j; --iml_k) {
                    umrl_left[iml_k] = umrl_left[iml_k - 1];
                    umrl_right[iml_k] = umrl_right[iml_k - 1];
                }
                break;
            }
            if (m_wle(uml_left, umrl_right[iml_j])) {
                // current block collides with block j - drop it
                bol_drop = true;
                break;
            }
        }
        if (bol_drop) {
            --imp_option_count;
            --iml_i;
            continue;
        }
        umrl_left[iml_j] = uml_left;
        umrl_right[iml_j] = uml_right;
    }

    // update umc_sack_data_size
    for (iml_i = 0; iml_i < imp_option_count; ++iml_i)
        adsp_hc->umc_sack_data_size += umrl_right[iml_i] - umrl_left[iml_i];

    // now check any table SACK info colliding with ack or options - and discard
    // also copy table to temporary buffer to merge later into place

    iml_i = 0; // SACK entries in header
    iml_buf_count = 0;
    for (iml_j = 0; iml_j < (int32_t)adsp_hc->umc_out_sack_count; ++iml_j) {
        if (iml_buf_count == ins_htcp_out_sack_count - imp_option_count ||
            m_wle(adsp_hc->umrc_out_sack_left[iml_j], ump_ack)) {

            adsp_hc->umc_sack_data_size -=
                adsp_hc->umrc_out_sack_right[iml_j] -
                adsp_hc->umrc_out_sack_left[iml_j];
            continue;
        }

        while (iml_i < imp_option_count &&
               m_wlt(umrl_right[iml_i],
                     adsp_hc->umrc_out_sack_left[iml_j])) {

            ++iml_i;
        }
        // iml_i range is not before iml_j range
        if (iml_i < imp_option_count &&
            m_wle(umrl_left[iml_i],
                  adsp_hc->umrc_out_sack_right[iml_j])) {

            adsp_hc->umc_sack_data_size -=
                adsp_hc->umrc_out_sack_right[iml_j] -
                adsp_hc->umrc_out_sack_left[iml_j];
            continue;
        }

        umrl_buf_left[iml_buf_count] = adsp_hc->umrc_out_sack_left[iml_j];
        umrl_buf_right[iml_buf_count] = adsp_hc->umrc_out_sack_right[iml_j];
        ++iml_buf_count;
    }

    // now merge received sack information in sack table
    if (imp_option_count > 0 || iml_buf_count > 0) {
        iml_i = 0;
        iml_j = 0;
        iml_k = 0;
        while (iml_i < imp_option_count && iml_j < iml_buf_count) {
            if (m_wlt(umrl_left[iml_i], umrl_buf_left[iml_j])) {
                adsp_hc->umrc_out_sack_left[iml_k] = umrl_left[iml_i];
                adsp_hc->umrc_out_sack_right[iml_k] = umrl_right[iml_i];
                ++iml_i;
            } else {
                adsp_hc->umrc_out_sack_left[iml_k] = umrl_buf_left[iml_j];
                adsp_hc->umrc_out_sack_right[iml_k] = umrl_buf_right[iml_j];
                ++iml_j;
            }
            ++iml_k;
        }
        if (iml_i < imp_option_count) {
            HTCP_LOCKED_ASSERT_F(iml_j == iml_buf_count);
            while (iml_i < imp_option_count) {
                adsp_hc->umrc_out_sack_left[iml_k] = umrl_left[iml_i];
                adsp_hc->umrc_out_sack_right[iml_k] = umrl_right[iml_i];
                ++iml_i;
                ++iml_k;
            }
        } else {
            HTCP_LOCKED_ASSERT_F(iml_j < iml_buf_count);
            while (iml_j < iml_buf_count) {
                adsp_hc->umrc_out_sack_left[iml_k] = umrl_buf_left[iml_j];
                adsp_hc->umrc_out_sack_right[iml_k] = umrl_buf_right[iml_j];
                ++iml_j;
                ++iml_k;
            }
        }
        adsp_hc->umc_out_sack_count = iml_k;
    } else {
        HTCP_LOCKED_ASSERT_F(adsp_hc->umc_sack_data_size == 0);
        adsp_hc->umc_out_sack_count = 0;
    }

    return true;
}

static bool m_locked_update_sack_pipe(struct dsd_htcp_conn* adsp_hc)
{
    int32_t iml_higher_sack_count;
    int32_t iml_higher_sack_data;
    uint32_t uml_last_edge;
    uint32_t uml_cur_hole;
    uint32_t uml_i;

    iml_higher_sack_count = adsp_hc->umc_out_sack_count;
    iml_higher_sack_data = adsp_hc->umc_sack_data_size;

    adsp_hc->umc_sack_pipe = 0;

    uml_last_edge = adsp_hc->umc_snd_una;

    for (uml_i = 0; uml_i < adsp_hc->umc_out_sack_count; ++uml_i) {
        uml_cur_hole = adsp_hc->umrc_out_sack_left[uml_i] - uml_last_edge;

        if (iml_higher_sack_count < ins_dup_thresh &&
            iml_higher_sack_data <
            ins_dup_thresh * ((int)adsp_hc->umc_snd_smss - 36)) {
            // Reducing 36 from smss ensures we do not miss a detection of a
            // lost segment because we send some SACK data ourselves.
            // On the other hand, if the reduction is not necessary,
            // it is very unlikely to have any effect.

            // current hole is not considered lost, so is in transit (in pipe)
            adsp_hc->umc_sack_pipe += uml_cur_hole;
        }

        if (m_wle(adsp_hc->umrc_out_sack_left[uml_i], adsp_hc->umc_high_rxt)) {
            // current hole is retransmitted, so is in transit (in pipe)
            adsp_hc->umc_sack_pipe += uml_cur_hole;
        } else if (m_wlt(uml_last_edge, adsp_hc->umc_high_rxt)) {
            // part of current hole is retransmitted, so is in transit (in pipe)
            adsp_hc->umc_sack_pipe += adsp_hc->umc_high_rxt - uml_last_edge;
        }

        --iml_higher_sack_count;
        iml_higher_sack_data -= (int32_t)(adsp_hc->umrc_out_sack_right[uml_i] -
                                          adsp_hc->umrc_out_sack_left[uml_i]);
        uml_last_edge = adsp_hc->umrc_out_sack_right[uml_i];
    }

    // now add data beyond highest sack block
    adsp_hc->umc_sack_pipe += adsp_hc->umc_snd_nxt - uml_last_edge;
    if (m_wlt(uml_last_edge, adsp_hc->umc_high_rxt))
        adsp_hc->umc_sack_pipe += adsp_hc->umc_high_rxt - uml_last_edge;

    return true;
}

static bool m_locked_sack_nextseg(struct dsd_htcp_conn* adsp_hc,
                                  bool* abop_segment, uint32_t* aump_seq)
{
    int32_t iml_higher_sack_count;
    int32_t iml_higher_sack_data;
    bool bol_last_resort;
    uint32_t uml_last_edge;
    uint32_t uml_flight;
    uint32_t uml_i;

    if (adsp_hc->dsc_cc.umc_cwnd <
        adsp_hc->umc_sack_pipe + adsp_hc->umc_snd_smss) {

        *abop_segment = false;
        return true;
    }

    iml_higher_sack_count = adsp_hc->umc_out_sack_count;
    iml_higher_sack_data = adsp_hc->umc_sack_data_size;

    bol_last_resort = false;

    uml_last_edge = adsp_hc->umc_snd_una;

    for (uml_i = 0; uml_i < adsp_hc->umc_out_sack_count; ++uml_i) {
        if (m_wgt(adsp_hc->umrc_out_sack_left[uml_i], adsp_hc->umc_high_rxt)) {
            if (m_wlt(uml_last_edge, adsp_hc->umc_high_rxt))
                uml_last_edge = adsp_hc->umc_high_rxt;

            if (iml_higher_sack_count >= ins_dup_thresh ||
                iml_higher_sack_data >=
                ins_dup_thresh * ((int)adsp_hc->umc_snd_smss) - 36) {
                // Reducing 36 from smss ensures we do not miss a detection of a
                // lost segment because we send some SACK data ourselves.
                // On the other hand, if the reduction is not necessary,
                // it is very unlikely to have any effect.

                *aump_seq = uml_last_edge;
                *abop_segment = true;
                return true;
            } else {
                *aump_seq = uml_last_edge;
                bol_last_resort = true;
            }

            break;
        }

        --iml_higher_sack_count;
        iml_higher_sack_data -= (int32_t)(adsp_hc->umrc_out_sack_right[uml_i] -
                                          adsp_hc->umrc_out_sack_left[uml_i]);
        uml_last_edge = adsp_hc->umrc_out_sack_right[uml_i];
    }

    uml_flight = adsp_hc->umc_snd_nxt - adsp_hc->umc_snd_una;
    if (adsp_hc->umc_send_pending >= adsp_hc->umc_snd_wnd) {
        if (adsp_hc->umc_snd_wnd > uml_flight) {
            *aump_seq = adsp_hc->umc_snd_nxt;
            *abop_segment = true;
            return true;
        }
    } else { // adsp_hc->umc_send_pending < adsp_hc->umc_snd_wnd
        if (adsp_hc->umc_send_pending > uml_flight) {
            *aump_seq = adsp_hc->umc_snd_nxt;
            *abop_segment = true;
            return true;
        }
    }

    *abop_segment = bol_last_resort;
    return true;
}

static bool m_locked_create_sack_option(struct dsd_htcp_conn* adsp_hc,
                                        char* achp_o, uint32_t* aump_len)
{
    uint32_t uml_count;
    struct dsd_htcp_in_info* adsl_hii;
    uint32_t uml_seq;
    bool bol_first;
    bool bol_first_found_assertion = false;

    HTCP_LOCKED_ASSERT_F(*aump_len <= 40);

    if (adsp_hc->adsc_sack_first == NULL || *aump_len < 10) {
        *aump_len = 0;
        return true;
    }

    HTCP_LOCKED_ASSERT_F(adsp_hc->adsc_oo_list != NULL);

    adsl_hii = adsp_hc->adsc_sack_first;
    uml_seq = adsl_hii->umc_seq;
    m_put_32_bit(achp_o + 2, uml_seq);
    do {
        uml_seq += adsl_hii->umc_len;
        if (adsl_hii->adsc_next == NULL)
            break;
        adsl_hii = adsl_hii->adsc_next;
    } while (adsl_hii->umc_seq == uml_seq);
    HTCP_LOCKED_ASSERT_F(adsl_hii == NULL ||
                         !m_within(adsl_hii->umc_seq,
                                   adsl_hii->umc_seq + adsl_hii->umc_len,
                                   uml_seq));
    m_put_32_bit(achp_o + 6, uml_seq);


    achp_o[0] = 5;
    uml_count = 10;
    adsl_hii = adsp_hc->adsc_oo_list;
    while (uml_count + 8 <= *aump_len) {
        bol_first = adsl_hii == adsp_hc->adsc_sack_first;

        if (bol_first) {
            HTCP_LOCKED_ASSERT_F(!bol_first_found_assertion);
            bol_first_found_assertion = true;
        }

        uml_seq = adsl_hii->umc_seq;

        if (!bol_first) {
            m_put_32_bit(achp_o + uml_count, uml_seq);
            uml_count += 4;
        }

        do {
            uml_seq += adsl_hii->umc_len;
            adsl_hii = adsl_hii->adsc_next;
        } while (adsl_hii != NULL && adsl_hii->umc_seq == uml_seq);
        HTCP_LOCKED_ASSERT_F(adsl_hii == NULL ||
                             !m_within(adsl_hii->umc_seq,
                                       adsl_hii->umc_seq + adsl_hii->umc_len,
                                       uml_seq));

        if (!bol_first) {
            m_put_32_bit(achp_o + uml_count, uml_seq);
            uml_count += 4;
        }

        if (adsl_hii == NULL)
            break;
    }

    HTCP_LOCKED_ASSERT_F(bol_first_found_assertion ||
                         uml_count + 8 > *aump_len);

    achp_o[1] = uml_count;
    *aump_len = uml_count;
    return true;
}

static bool m_locked_start_header(struct dsd_htcp_conn* adsp_hc,
                                  char* achp_header, uint32_t* aump_hlen,
                                  uint8_t utp_flags, uint16_t usp_urg,
                                  int64_t ilp_now_ms)
{
    uint32_t uml_len;
    uint32_t uml_olen;
    uint32_t uml_win;
    bool bol_ret;

    uml_olen = 0;
    if (adsp_hc->boc_use_timestamp) {
        if (adsp_hc->adsc_sack_first == NULL) {
            achp_header[20 + uml_olen++] = 1; // noop padding
            achp_header[20 + uml_olen++] = 1; // noop padding
        }
        bol_ret = m_locked_create_timestamp_option(adsp_hc,
                                                   achp_header +
                                                   20 + uml_olen,
                                                   ilp_now_ms);
        if (!bol_ret)
            return false;
        uml_olen += 10;
    }

    if (adsp_hc->adsc_sack_first != NULL) {
        if (!adsp_hc->boc_use_timestamp) {
            achp_header[20 + uml_olen++] = 1; // noop padding
            achp_header[20 + uml_olen++] = 1; // noop padding
        }
        uml_len = 40 - uml_olen;
        bol_ret = m_locked_create_sack_option(adsp_hc,
                                              achp_header + 20 + uml_olen,
                                              &uml_len);
        if (!bol_ret)
            return false;
        uml_olen += uml_len;
    }

    HTCP_LOCKED_ASSERT_F(uml_olen <= 40 && uml_olen % 4 == 0);
    *aump_hlen = 20 + uml_olen;

    HTCP_LOCKED_ASSERT_F(m_get_tcp_flags_ack(utp_flags));

    m_set_tcp_src_port(achp_header, adsp_hc->usc_local_port);
    m_set_tcp_dst_port(achp_header, adsp_hc->usc_remote_port);
    m_set_tcp_seqn(achp_header, adsp_hc->umc_snd_nxt_cur);
    m_set_tcp_ackn(achp_header, adsp_hc->umc_rcv_nxt);
    m_set_calc_tcp_hlen(achp_header, *aump_hlen);
    m_set_tcp_resv(achp_header, 0);
    m_set_tcp_flags(achp_header, utp_flags);
    m_set_tcp_urgent(achp_header, usp_urg);

    uml_win = adsp_hc->umc_rcv_wnd >> adsp_hc->umc_rcv_winscale;
    if (uml_win > 65535)
        uml_win = 65535;
    m_set_tcp_window(achp_header, uml_win);

    return true;
}

static bool m_locked_prepare_syn(struct dsd_htcp_conn* adsp_hc,
                                 char* achp_header, uint32_t* aump_hlen,
                                 bool bop_ack, int64_t ilp_now_ms)
{
    uint32_t uml_hlen;
    uint8_t utl_flags;
    bool bol_use_timestamp;
    bool bol_ret;

    // TODO: bol_use_timestamp variable is redundant
    bol_use_timestamp = adsp_hc->boc_use_timestamp;

    uml_hlen = 20;

    // mss
    achp_header[uml_hlen++] = 2;
    achp_header[uml_hlen++] = 4;
    m_put_16_bit(achp_header + uml_hlen, adsp_hc->umc_rcv_rmss);
    uml_hlen += 2;

    // window size shift
    if (adsp_hc->boc_use_winscale) {
        achp_header[uml_hlen++] = 3;
        achp_header[uml_hlen++] = 3;
        achp_header[uml_hlen++] = adsp_hc->umc_rcv_winscale;
        if (adsp_hc->boc_use_sack || bol_use_timestamp)
            achp_header[uml_hlen++] = 1; // noop padding
        else
            achp_header[uml_hlen++] = 0; // end padding
    }

    // accept SACK
    if (adsp_hc->boc_use_sack) {
        achp_header[uml_hlen++] = 4;
        achp_header[uml_hlen++] = 2;
        if (!bol_use_timestamp) {
            achp_header[uml_hlen++] = 0; // end padding
            achp_header[uml_hlen++] = 0; // end padding
        }
    }

    // timestamp
    if (bol_use_timestamp) {
        if (!adsp_hc->boc_use_sack) {
            achp_header[uml_hlen++] = 1; // noop padding
            achp_header[uml_hlen++] = 1; // noop padding
        }
        bol_ret = m_locked_create_timestamp_option(adsp_hc,
                                                   achp_header + uml_hlen,
                                                   ilp_now_ms);
        if (!bol_ret)
            return false;
        uml_hlen += 10;
    }

    HTCP_LOCKED_ASSERT_F(uml_hlen % 4 == 0);

    utl_flags = bop_ack ? utd_tcp_syn_ack : utd_tcp_syn;

    m_set_tcp_src_port(achp_header, adsp_hc->usc_local_port);
    m_set_tcp_dst_port(achp_header, adsp_hc->usc_remote_port);
    m_set_tcp_seqn(achp_header, adsp_hc->umc_snd_iss);
    m_set_tcp_ackn(achp_header, bop_ack ? adsp_hc->umc_rcv_nxt : 0);
    m_set_calc_tcp_hlen(achp_header, uml_hlen);
    m_set_tcp_resv(achp_header, 0);
    m_set_tcp_flags(achp_header, utl_flags);
    m_set_tcp_window(achp_header, adsp_hc->umc_rcv_wnd > 65535 ?
                     65535 : adsp_hc->umc_rcv_wnd);
    m_set_tcp_urgent(achp_header, 0);

    *aump_hlen = uml_hlen;

    return true;
}

static bool m_locked_packets_available(struct dsd_htcp_conn* adsp_hc,
                                       bool* abop_available)
{
    uint32_t uml_pending;
    uint32_t uml_nxt_offset;
    uint32_t uml_cwnd;
    uint32_t uml_dummy;
    bool bol_syn_unacked;
    bool bol_send_fin;

    // check adsp_hc->utc_packet_flags for SYN or RST or ACK,
    // and for zero window probe,
    // and for output dup ACKs
    if (adsp_hc->utc_packet_flags != 0 ||
        adsp_hc->boc_zwnd_probe ||
        adsp_hc->umc_tosend_dack > 0) {
        *abop_available = true;
        return true;
    }

    if (adsp_hc->iec_state == ied_htcp_closed) {
        *abop_available = false;
        return true;
    }

    bol_syn_unacked = (adsp_hc->iec_state == ied_htcp_syn_sent ||
                       adsp_hc->iec_state == ied_htcp_syn_rcvd ||
                       adsp_hc->iec_state == ied_htcp_syn_sent_eof ||
                       adsp_hc->iec_state == ied_htcp_syn_rcvd_eof);

    bol_send_fin = (adsp_hc->iec_state == ied_htcp_syn_rcvd_eof ||
                    adsp_hc->iec_state == ied_htcp_fin_wait_1 ||
                    adsp_hc->iec_state == ied_htcp_closing ||
                    adsp_hc->iec_state == ied_htcp_last_ack);

    HTCP_LOCKED_ASSERT_F(m_wge(adsp_hc->umc_snd_nxt_cur, adsp_hc->umc_snd_una));
    uml_nxt_offset = adsp_hc->umc_snd_nxt_cur - adsp_hc->umc_snd_una;
    uml_pending = adsp_hc->umc_send_pending;
    HTCP_LOCKED_ASSERT_F(uml_pending +
                         (bol_syn_unacked ? 1 : 0) + (bol_send_fin ? 1 : 0)
                         >= uml_nxt_offset);
    uml_cwnd = adsp_hc->dsc_cc.umc_cwnd;

    if (uml_pending > adsp_hc->umc_snd_wnd) {
        uml_pending = adsp_hc->umc_snd_wnd;
        bol_send_fin = false;
    }

    if (adsp_hc->boc_recovering) {

        if (adsp_hc->boc_recover_packet) {
            *abop_available = true;
            return true;
        }

        if (adsp_hc->boc_use_sack) {
            if (!m_locked_sack_nextseg(adsp_hc, abop_available, &uml_dummy))
                return false;
            return true;
        } else { // !adsp_hc->boc_use_sack
            if (adsp_hc->umc_pending_dacks == 0) {
                *abop_available = false;
                return true;
            }

            // If we have limited transmit segments, send those first.
            // Otherwise, go on to check if a packet is available within cwin.
            // Note that this is the only case where we remain in this
            // function if adsp_hc->boc_recovering is true.
        }
    }

    // limited transmit
    if (adsp_hc->umc_limited_transmit > 0) {
        if (uml_pending > uml_nxt_offset &&
            uml_cwnd + 2 * adsp_hc->umc_snd_smss > uml_nxt_offset) {

            *abop_available = true;
            return true;
        }
        adsp_hc->umc_limited_transmit = 0;

        /*
        // optimization to avoid going through next steps:
        adsp_hc->umc_pending_dacks = 0;
        *abop_available = false;
        return true;
        // end of optimization
        */
    }

    if (adsp_hc->boc_recovering) {
        // We only arrive here if handling adsp_hc->umc_pending_dacks
        if (uml_pending > uml_nxt_offset &&
            uml_cwnd > uml_nxt_offset) {

            *abop_available = true;
            return true;
        }
        adsp_hc->umc_pending_dacks = 0;

        /*
        // optimization to avoid going through next step:
        *abop_available = false;
        return true;
        // end of optimization
        */
    }

    if (uml_pending > uml_nxt_offset &&
        uml_cwnd > uml_nxt_offset) {

        *abop_available = true;
        return true;
    }

    if (uml_pending == uml_nxt_offset && bol_send_fin) {
        *abop_available = true;
        return true;
    }

    *abop_available = false;
    return true;
}

static bool m_send_rst(struct dsd_htcp_conn* adsp_hc,
                       uint32_t ump_seq_or_ack, bool bop_ack)
{
    // TODO: syncronize

    bool bol_ret;

    if (bop_ack) {
        adsp_hc->utc_packet_flags = utd_tcp_rst_ack;
        adsp_hc->umc_packet_seq = 0;
        adsp_hc->umc_packet_ack = ump_seq_or_ack;
    } else {
        adsp_hc->utc_packet_flags = utd_tcp_rst;
        adsp_hc->umc_packet_seq = ump_seq_or_ack;
        adsp_hc->umc_packet_ack = 0;
    }

    bol_ret = adsp_hc->adsc_cb->amc_out_packets(adsp_hc);
    HTCP_CHECK_CB_RET_F(amc_out_packets);

    return true;
}
