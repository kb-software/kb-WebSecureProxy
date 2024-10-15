// #define TRY_FORCE_TRACE

/******************************************************************************
 * File name: xs-htcp-htun-01.cpp
 *
 * Authors: Kevin Spiteri
 *          Miguel Loureiro
 * Copyright: Copyright (c) HOB Software 2012
 * Copyright: Copyright (c) HOB Software 2012
 ******************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <list>

#include "hob-htcp-int-01.h"
#include "hob-htcp-hdr-01.h"
#include "hob-htcp-01.h"

#if defined WIN32 || WIN64
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#elif defined HL_UNIX
#include "hob-unix01.h"
#ifdef HL_FREEBSD
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <net/if.h>
#else // !defined WIN32 && !defined HL_UNIX
#error either WIN32 or HL_UNIX needed
#endif // !defined WIN32 && !defined HL_UNIX

#ifndef HOB_CONTR_TIMER
#define HOB_CONTR_TIMER
#endif

typedef unsigned char byte;
#include "hob-netw-01.h"
#include "hob-avl03.h"
#include "hob-xslcontr.h"
#include "hob-tun01.h"
#include "hob-session01.h"
#include "hob-sessutil01.h"

// for WSP tracing:
#ifndef DEF_HL_INCL_DOM
#define DEF_HL_INCL_DOM
#endif
#ifndef DOMNode
#define DOMNode void
#endif
#include "hob-wsppriv.h"
#include "hob-xsclib01.h"
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
extern "C" int img_wsp_trace_core_flags1;

#include "hob-htcp-htun-01.h"

extern "C"
int m_get_random_number(int inp_max);

extern "C"
void m_htun_critsect_enter(struct dsd_tun_contr_conn* adsp_tun_contr_conn);

extern "C"
void m_htun_critsect_leave(struct dsd_tun_contr_conn* adsp_tun_contr_conn);

static const int ins_round_robin_max = 64;


enum ied_htcp_htun_state {
    ied_hhs_connecting,  // still connecting to server
    ied_hhs_conn_abort,  // aborted while connecting to server
    ied_hhs_connected,   // connection active
    ied_hhs_close,       // received m_htun_sess_close() but connection active
    ied_hhs_close_force, // after ied_hhs_close, have not yet received end
    ied_hhs_time_wait,   // after ied_hhs_close, received FIN, TCP TIME_WAIT
    ied_hhs_end,         // received FIN, called m_htun_session_end()
    ied_hhs_closed       // HTCP called amc_closed(), safety timeout phase
};

struct dsd_htcp_htun {
    struct dsd_htun_handle dsc_handle;

    struct dsd_tun_contr_conn* adsc_tcc;
    struct dsd_tun_contr_ineta* adsc_tci;

    /* connection state */
    enum ied_htcp_htun_state iec_hhs;

    /* address information */
    bool boc_ipv6;
    char chrc_local_addr[16];
    char chrc_remote_addr[16];
    uint16_t usc_local_port;
    uint16_t usc_remote_port;

    /*
     * HTCP will only be called on one thread.
     * If a call is received, information may be stored and handled later.
     */
    bool boc_sync_running;
    bool boc_sync_close;
    uint32_t umc_sync_send;
    bool boc_sync_can_recv;
    struct dsd_htcp_packet* adsc_sync_packet;
    bool boc_sync_timeout;

    struct dsd_timer_ele dsc_te;
    struct dsd_timer_ele dsc_te_closing;
    bool boc_te_closing_free;

    /* used while connecting */
    struct dsd_target_ineta_1* adsc_target_ineta;
    void* ac_free_ti1;
    int inc_htcp_error;
    int inc_target_cur;
    int inc_target_random_remain;
    uint64_t ulc_target_unused;

    /* used throughout connection */
    struct dsd_gather_i_1* adsc_sending;
    struct dsd_gather_i_1* adsc_sending_tail;
    char* achc_sending_tail_end;
    bool boc_can_recv;

    /* HTCP connection */
    struct dsd_htcp_conn dsc_hc;
};

struct dsd_htcp_packet_control {
    struct dsd_htcp_packet* adsc_next;
    void* ac_handle;
    char* achc_data;
    uint32_t umc_len;
};

struct dsd_htcp_packet {
    struct dsd_htcp_packet_control dsc_hpc;
    struct dsd_htcp_in_info dsc_hii;
};

static void m_process_sync(struct dsd_htcp_htun* adsp_hh);

static void m_try_next_address(struct dsd_htcp_htun* adsp_hh);

static void m_recv_data(struct dsd_htcp_htun* adsp_hh);

static void m_free_resources(struct dsd_htcp_htun* adsp_hh);


static void m_hct_compl(struct dsd_timer_ele* adsp_te);
static void m_hct_compl_closing(struct dsd_timer_ele* adsp_te);

static bool m_hcb_out_get(struct dsd_htcp_conn* adsp_hc,
                          uint32_t ump_offset,
                          const char** aachp_buf, uint32_t* aump_len);
static bool m_hcb_out_packets(struct dsd_htcp_conn* adsp_hc);
static bool m_hcb_out_ack(struct dsd_htcp_conn* adsp_hc, uint32_t ump_len);

static bool m_hcb_in_get(struct dsd_htcp_conn* adsp_hc,
                         struct dsd_htcp_in_info* adsp_hii,
                         uint32_t ump_offset,
                         const char** aachp_buf, uint32_t* aump_len);
static bool m_hcb_in_more_data(struct dsd_htcp_conn* adsp_hc);
static bool m_hcb_in_rel(struct dsd_htcp_conn* adsp_hc,
                         struct dsd_htcp_in_info* adsp_hii);

static bool m_hcb_get_time(struct dsd_htcp_conn* adsp_hc, int64_t* ailp_time);
static bool m_hcb_set_timer(struct dsd_htcp_conn* adsp_hc,
                            uint32_t ump_delay_ms);
static bool m_hcb_rel_timer(struct dsd_htcp_conn* adsp_hc);

static bool m_hcb_lock(struct dsd_htcp_conn* adsp_hc);
static bool m_hcb_unlock(struct dsd_htcp_conn* adsp_hc);

static bool m_hcb_established(struct dsd_htcp_conn* adsp_hc);
static void m_hcb_closed(struct dsd_htcp_conn* adsp_hc,
                         enum ied_htcp_close iep_htcpc);


static const struct dsd_htcp_callbacks dss_hcb = {
    &m_hcb_out_get,
    &m_hcb_out_packets,
    &m_hcb_out_ack,
    &m_hcb_in_get,
    &m_hcb_in_more_data,
    &m_hcb_in_rel,
    &m_hcb_get_time,
    &m_hcb_set_timer,
    &m_hcb_rel_timer,
    &m_hcb_lock,
    &m_hcb_unlock,
    &m_hcb_established,
    &m_hcb_closed
};

// achp_str should point to a buffer where at least 42 bytes may be written
static void m_print_addr(char* achp_str, const char* achp_addr, bool bop_ipv6)
{
    int inl_i;
    int inrl_a[8];
    int inl_first_zero;
    int inl_zero_count;
    int inl_cur_zero_count;

    if (bop_ipv6) {
        inl_first_zero = 8;
        inl_zero_count = 1;
        inl_cur_zero_count = 0;
        for (inl_i = 0; inl_i < 8; ++inl_i) {
            inrl_a[inl_i] = (unsigned char)*achp_addr++;
            inrl_a[inl_i] <<= 8;
            inrl_a[inl_i] += (unsigned char)*achp_addr++;
            if (inrl_a[inl_i] == 0) {
                ++inl_cur_zero_count;
            } else {
                if (inl_cur_zero_count > inl_zero_count) {
                    inl_first_zero = inl_i - inl_cur_zero_count;
                    inl_zero_count = inl_cur_zero_count;
                }
                inl_cur_zero_count = 0;
            }
        }
        if (inl_cur_zero_count > inl_zero_count) {
            inl_first_zero = inl_i - inl_cur_zero_count;
            inl_zero_count = inl_cur_zero_count;
        }

        *achp_str++ = '[';
        for (inl_i = 0; inl_i < 8; ++inl_i) {
            if (inl_i == inl_first_zero) {
                if (inl_i == 0)
                    *achp_str++ = ':';
                *achp_str++ = ':';
                inl_i += inl_zero_count - 1;
                if (inl_i == 7)
                    ++achp_str;
            } else {
                achp_str += sprintf(achp_str, "%x:", inrl_a[inl_i]);
            }
        }
        *(achp_str - 1) = ']';
        *achp_str++ = '\0';
    } else {
        for (inl_i = 0; inl_i < 4; ++inl_i) {
            inrl_a[inl_i] = (unsigned char)*achp_addr++;
        }
        achp_str += sprintf(achp_str, "%d.%d.%d.%d\0",
                            inrl_a[0], inrl_a[1], inrl_a[2], inrl_a[3]);
    }
}

void m_htun_new_sess_htcp(struct dsd_tun_start_htcp* adsp_tsh,
                          struct dsd_tun_contr_conn* adsp_tcc,
                          struct dsd_tun_contr_ineta* adsp_tci)
{
#ifdef TRY_FORCE_TRACE
    adsp_tcc->imc_trace_level = HL_WT_SESS_NETW | HL_WT_CORE_DATA2;
#endif

    struct dsd_htcp_htun* adsl_hh;

    if ((adsp_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCSN", 0,
                       adsp_tcc->imc_sno,
                       adsp_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP new session.");
    }

    adsl_hh = (struct dsd_htcp_htun*)malloc(sizeof(struct dsd_htcp_htun));
    if (adsl_hh == NULL) {
        m_htun_warning(adsp_tcc, adsp_tci, HTCP_ERR_INTERNAL_ERROR,
                       "Could not allocate memory for HTCP session.");
        m_htun_htcp_connect_end(adsp_tcc, adsp_tsh->adsc_server_ineta,
                                adsp_tsh->ac_free_ti1,
                                NULL, 0, HTCP_ERR_INTERNAL_ERROR);
        m_htun_session_end(adsp_tcc, HTCP_ERR_INTERNAL_ERROR);
        m_htun_htcp_free_resources(adsp_tci);
        return;
    }

    adsl_hh->dsc_handle.iec_tunc = ied_tunc_htcp;
    adsl_hh->dsc_handle.vpc_contr = adsl_hh;

    adsl_hh->adsc_tcc = adsp_tcc;
    adsl_hh->adsc_tci = adsp_tci;

    adsl_hh->iec_hhs = ied_hhs_connecting;

    adsl_hh->usc_remote_port = adsp_tsh->imc_server_port;

    adsl_hh->boc_sync_running = true;
    adsl_hh->boc_sync_close = false;
    adsl_hh->umc_sync_send = 0;
    adsl_hh->boc_sync_can_recv = false;
    adsl_hh->adsc_sync_packet = NULL;
    adsl_hh->boc_sync_timeout = false;

    memset(&adsl_hh->dsc_te, 0, sizeof(adsl_hh->dsc_te));
    adsl_hh->dsc_te.amc_compl = m_hct_compl;
    memset(&adsl_hh->dsc_te_closing, 0, sizeof(adsl_hh->dsc_te_closing));
    adsl_hh->dsc_te_closing.amc_compl = m_hct_compl_closing;
    adsl_hh->boc_te_closing_free = false;

    adsl_hh->adsc_target_ineta = adsp_tsh->adsc_server_ineta;
    adsl_hh->ac_free_ti1 = adsp_tsh->ac_free_ti1;
    adsl_hh->inc_htcp_error = 0;
    if (adsp_tsh->boc_connect_round_robin) {
        adsl_hh->inc_target_random_remain =
            adsp_tsh->adsc_server_ineta->imc_no_ineta;
        if (adsl_hh->inc_target_random_remain > ins_round_robin_max)
            adsl_hh->inc_target_random_remain = ins_round_robin_max;
        // assume two's complement
        adsl_hh->ulc_target_unused = 1;
        adsl_hh->ulc_target_unused <<= adsl_hh->inc_target_random_remain;
        --adsl_hh->ulc_target_unused;
    } else { // !adsp_tsh->boc_connect_round_robin
        adsl_hh->inc_target_random_remain = -1;
        adsl_hh->inc_target_cur = -1;
    }

    adsl_hh->adsc_sending = NULL;
    // If adsc_sending is NULL, adsc_sending_tail and achc_sending_tail_end
    // will not be used.
    adsl_hh->boc_can_recv = true;

    *(adsp_tsh->adsc_htun_h) = &adsl_hh->dsc_handle;

    m_try_next_address(adsl_hh);

    m_process_sync(adsl_hh);
}

void m_htcp_sess_close(struct dsd_htcp_htun* adsp_hh)
{
    bool bol_running;

    if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCSC", 0,
                       adsp_hh->adsc_tcc->imc_sno,
                       adsp_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP being closed by client.");
    }

    m_htun_critsect_enter(adsp_hh->adsc_tcc);
    adsp_hh->boc_sync_close = true;
    bol_running = adsp_hh->boc_sync_running;
    adsp_hh->boc_sync_running = true;
    m_htun_critsect_leave(adsp_hh->adsc_tcc);

    if (!bol_running)
        m_process_sync(adsp_hh);
}

void m_htcp_sess_send(struct dsd_htcp_htun* adsp_hh,
                      struct dsd_gather_i_1* adsp_gai1)
{
    bool bol_running;
    uint32_t uml_send;
    const int inl_trace_size = 16;
    struct dsd_gather_i_1 dsrl_trace_data[inl_trace_size];
    struct dsd_gather_i_1* adsl_trace_data;
    int inl_trace_i;


    m_htun_critsect_enter(adsp_hh->adsc_tcc);

    if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        if (adsp_hh->adsc_sending == NULL) {
            dsrl_trace_data[0].achc_ginp_cur = NULL;
            dsrl_trace_data[0].achc_ginp_end = NULL;
            dsrl_trace_data[0].adsc_next = &dsrl_trace_data[1];
            adsl_trace_data = adsp_gai1;
            inl_trace_i = 1;
        } else {
            dsrl_trace_data[0].achc_ginp_cur =
                adsp_hh->achc_sending_tail_end;
            dsrl_trace_data[0].achc_ginp_end =
                adsp_hh->adsc_sending_tail->achc_ginp_end;
            dsrl_trace_data[0].adsc_next = &dsrl_trace_data[1];
            adsl_trace_data = adsp_hh->adsc_sending_tail->adsc_next;
            inl_trace_i = 1;
        }
        while (inl_trace_i < inl_trace_size && adsl_trace_data != NULL) {
            if (adsl_trace_data->achc_ginp_cur ==
                adsl_trace_data->achc_ginp_end) {

                adsl_trace_data = adsl_trace_data->adsc_next;
                continue;
            }
            dsrl_trace_data[inl_trace_i].achc_ginp_cur =
                adsl_trace_data->achc_ginp_cur;
            dsrl_trace_data[inl_trace_i].achc_ginp_end =
                adsl_trace_data->achc_ginp_end;
            dsrl_trace_data[inl_trace_i].adsc_next =
                &dsrl_trace_data[inl_trace_i + 1];
            ++inl_trace_i;
            adsl_trace_data = adsl_trace_data->adsc_next;
        }
        if (inl_trace_i == 0) {
            dsrl_trace_data[0].achc_ginp_cur = NULL;
            dsrl_trace_data[0].achc_ginp_end = NULL;
            dsrl_trace_data[0].adsc_next = NULL;
        } else {
            dsrl_trace_data[inl_trace_i - 1].adsc_next = NULL;
        }
    }

	// There might be empty gathers. adsc_sending and adsc_sending
	// cannot point to an empty gather, since it may be freed by the WSP
    if (adsp_hh->adsc_sending == NULL) {

        if (adsp_gai1 == NULL) {
            m_htun_critsect_leave(adsp_hh->adsc_tcc);
            return;
        }

        adsp_hh->adsc_sending = adsp_gai1;
        adsp_hh->adsc_sending_tail = adsp_gai1;
        uml_send = adsp_gai1->achc_ginp_end - adsp_gai1->achc_ginp_cur;
    } else { // adsp_hh->adsc_sending != NULL
		// if there was and end
		if(adsp_hh->achc_sending_tail_end)
			uml_send = adsp_hh->adsc_sending_tail->achc_ginp_end - adsp_hh->achc_sending_tail_end;
    }

    adsp_gai1 = adsp_hh->adsc_sending_tail->adsc_next;
    while (adsp_gai1 != NULL) {
        uml_send += adsp_gai1->achc_ginp_end - adsp_gai1->achc_ginp_cur;
		if(adsp_gai1->achc_ginp_end != adsp_gai1->achc_ginp_cur){               // Only if gather not empty. Otherwise it would point to an empty gather
			adsp_hh->adsc_sending_tail = adsp_gai1;                             // which might be freed
		}
        adsp_gai1 = adsp_gai1->adsc_next;
    }

	adsp_hh->achc_sending_tail_end = adsp_hh->adsc_sending_tail->achc_ginp_end;


    if (uml_send > 0) {
        if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
            m_htun_critsect_leave(adsp_hh->adsc_tcc);
            m_do_wsp_trace("SNEHTCSS", 0,
                           adsp_hh->adsc_tcc->imc_sno,
                           adsp_hh->adsc_tcc->imc_trace_level,
                           dsrl_trace_data, uml_send, 16,
                           "HTCP sending %d bytes.",
                           (int)uml_send);
            m_htun_critsect_enter(adsp_hh->adsc_tcc);
        }

        adsp_hh->umc_sync_send += uml_send;
        bol_running = adsp_hh->boc_sync_running;
        adsp_hh->boc_sync_running = true;
    }
    m_htun_critsect_leave(adsp_hh->adsc_tcc);

    if (uml_send > 0 && !bol_running)
        m_process_sync(adsp_hh);

#ifdef ML150122  // Should the first gather be checked here??
	while(adsp_hh->adsc_sending){
		if(adsp_hh->adsc_sending->achc_ginp_cur != adsp_hh->adsc_sending->achc_ginp_end)
			break;
		adsp_hh->adsc_sending = adsp_hh->adsc_sending->adsc_next;
	}
#endif
}

void m_htcp_sess_canrecv(struct dsd_htcp_htun* adsp_hh)
{
    bool bol_running;

    if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCSR", 0,
                       adsp_hh->adsc_tcc->imc_sno,
                       adsp_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP can receive data again.");
    }

    m_htun_critsect_enter(adsp_hh->adsc_tcc);
    adsp_hh->boc_sync_can_recv = true;
    bol_running = adsp_hh->boc_sync_running;
    adsp_hh->boc_sync_running = true;
    m_htun_critsect_leave(adsp_hh->adsc_tcc);

    if (!bol_running)
        m_process_sync(adsp_hh);
}

void m_htcp_packet_from_network(struct dsd_htcp_htun* adsp_hh,
                                void* ap_handle, unsigned unp_offset,
                                char* achp_data, unsigned unp_dlen)
{
    bool bol_running;
    struct dsd_htcp_packet* adsl_hp;
    struct dsd_htcp_packet** aadsl_hp;

    /*
     * Check if we have enough space for control information.
     * The struct dsd_htcp_packet contains two inner structures:
     *   - struct dsd_htcp_packet_control used by xs-htcp-htun-01.cpp and
     *   - struct dsd_htcp_in_info used by xs-htcp-01.cpp.
     * The struct dsd_htcp_packet_control must fit completely inside the space
     * unp_offset before the packet so that it can be filled in immediately.
     * The struct dsd_htcp_in_info may overflow on the IP header and the first
     * 20 bytes of the TCP header, xs-htcp-01.cpp makes sure it does not
     * overwrite any data before the data is used.
     */
    if (offsetof(struct dsd_htcp_packet, dsc_hpc) +
        sizeof(struct dsd_htcp_packet_control) > unp_offset ||
        sizeof(struct dsd_htcp_packet) > unp_offset + 40) {

        // we need more space
        m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                       HTCP_ERR_INTERNAL_ERROR,
                       "Not enough offset before packet.");
        m_htun_relrecvbuf(ap_handle);
        return;
    }

    adsl_hp = (struct dsd_htcp_packet*)(achp_data - unp_offset);
    adsl_hp->dsc_hpc.adsc_next = NULL;
    adsl_hp->dsc_hpc.ac_handle = ap_handle;
    adsl_hp->dsc_hpc.achc_data = achp_data;
    adsl_hp->dsc_hpc.umc_len = unp_dlen;

    m_htun_critsect_enter(adsp_hh->adsc_tcc);

    aadsl_hp = &adsp_hh->adsc_sync_packet;
    while ((*aadsl_hp) != NULL)
        aadsl_hp = &(*aadsl_hp)->dsc_hpc.adsc_next;

    *aadsl_hp = adsl_hp;

    bol_running = adsp_hh->boc_sync_running;
    adsp_hh->boc_sync_running = true;
    m_htun_critsect_leave(adsp_hh->adsc_tcc);

    if (!bol_running)
        m_process_sync(adsp_hh);
}

static void m_process_sync(struct dsd_htcp_htun* adsp_hh)
{
    bool bol_s_close;
    uint32_t uml_s_send;
    bool bol_s_can_recv;
    struct dsd_htcp_packet* adsl_s_packet;
    bool bol_s_timeout;

    struct dsd_htcp_packet* adsl_hp;
    uint32_t uml_len;
    struct dsd_gather_i_1 dsl_trace_data;
    struct dsd_htcp_status dsl_hs;

    // boc_sync_running should be set to true before entering this function.

    if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCPS", 0,
                       adsp_hh->adsc_tcc->imc_sno,
                       adsp_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP starting processing loop.");
    }

    for (; ; ) {
        m_htun_critsect_enter(adsp_hh->adsc_tcc);

        bol_s_close = adsp_hh->boc_sync_close;
        adsp_hh->boc_sync_close = false;

        uml_s_send = adsp_hh->umc_sync_send;
        adsp_hh->umc_sync_send = 0;

        bol_s_can_recv = adsp_hh->boc_sync_can_recv;
        adsp_hh->boc_sync_can_recv = false;

        adsl_s_packet = adsp_hh->adsc_sync_packet;
        adsp_hh->adsc_sync_packet = NULL;

        bol_s_timeout = adsp_hh->boc_sync_timeout;
        adsp_hh->boc_sync_timeout = false;

        if (!bol_s_close &&
            uml_s_send == 0 &&
            !bol_s_can_recv &&
            adsl_s_packet == NULL &&
            !bol_s_timeout) {

            if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
                m_htun_critsect_leave(adsp_hh->adsc_tcc);
                m_do_wsp_trace("SNEHTCPL", 0,
                               adsp_hh->adsc_tcc->imc_sno,
                               adsp_hh->adsc_tcc->imc_trace_level,
                               NULL, 0, 0,
                               "HTCP leaving processing loop.");
                m_htun_critsect_enter(adsp_hh->adsc_tcc);
            }

            adsp_hh->boc_sync_running = false;
            m_htun_critsect_leave(adsp_hh->adsc_tcc);
            return;
        }

        m_htun_critsect_leave(adsp_hh->adsc_tcc);

        if (uml_s_send > 0) {
            if (adsp_hh->iec_hhs == ied_hhs_connected) {
                m_htcp_out_send(&adsp_hh->dsc_hc, uml_s_send, true, false);
            } else {
                m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                               HTCP_ERR_INTERNAL_ERROR,
                               "Ignoring %d outbound bytes in state %d.",
                               (int)uml_s_send, (int)adsp_hh->iec_hhs);
            }
        }

        if (bol_s_can_recv) {
            adsp_hh->boc_can_recv = true;
            m_recv_data(adsp_hh);
        }

        while (adsl_s_packet != NULL) {
            if (adsp_hh->iec_hhs == ied_hhs_conn_abort ||
                adsp_hh->iec_hhs == ied_hhs_close_force ||
                adsp_hh->iec_hhs == ied_hhs_closed) {

                m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci, 1,
                               "Discarding extra packets in state %d.",
                               (int)adsp_hh->iec_hhs);
                do {
                    adsl_hp = adsl_s_packet;
                    adsl_s_packet = adsl_hp->dsc_hpc.adsc_next;
                    m_htun_relrecvbuf(adsl_hp->dsc_hpc.ac_handle);
                } while (adsl_s_packet != NULL);
                break;
            }

            adsl_hp = adsl_s_packet;
            adsl_s_packet = adsl_s_packet->dsc_hpc.adsc_next;

            /*
             * Note: we can assume that any packet that arrives here has an IP
             * header, at least twenty more bytes and a TCP protocol field.
             */

            if (adsp_hh->boc_ipv6) {
                uml_len = 40;
                if (m_get_ip6_version(adsl_hp->dsc_hpc.achc_data) == 6 &&
                    memcmp(m_get_ip6_src_addr(adsl_hp->dsc_hpc.achc_data),
                           adsp_hh->chrc_remote_addr, 16) == 0 &&
                    memcmp(m_get_ip6_dst_addr(adsl_hp->dsc_hpc.achc_data),
                           adsp_hh->chrc_local_addr, 16) == 0) {

                    adsl_hp->dsc_hpc.achc_data += uml_len;
                    uml_len = adsl_hp->dsc_hpc.umc_len - uml_len;
                    adsl_hp->dsc_hpc.umc_len = uml_len;
                }else {
                    uml_len = 0;
                }
            } else { // IPv4
                uml_len = m_get_calc_ip_hlen(adsl_hp->dsc_hpc.achc_data);
                if (m_get_ip_version(adsl_hp->dsc_hpc.achc_data) == 4 &&
                    memcmp(m_get_ip_src_addr_buf(adsl_hp->dsc_hpc.achc_data),
                           adsp_hh->chrc_remote_addr, 4) == 0 &&
                    memcmp(m_get_ip_dst_addr_buf(adsl_hp->dsc_hpc.achc_data),
                           adsp_hh->chrc_local_addr, 4) == 0) {

                    adsl_hp->dsc_hpc.achc_data += uml_len;
                    uml_len = adsl_hp->dsc_hpc.umc_len - uml_len;
                    adsl_hp->dsc_hpc.umc_len = uml_len;
                }else {
                    uml_len = 0;
                }
            }

            if (uml_len > 0) {
                if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW)
                    != 0) {

                    dsl_trace_data.achc_ginp_cur = adsl_hp->dsc_hpc.achc_data;
                    dsl_trace_data.achc_ginp_end =
                        dsl_trace_data.achc_ginp_cur + adsl_hp->dsc_hpc.umc_len;
                    dsl_trace_data.adsc_next = NULL;
                    m_do_wsp_trace("SNEHTCNR", 0,
                                   adsp_hh->adsc_tcc->imc_sno,
                                   adsp_hh->adsc_tcc->imc_trace_level,
                                   &dsl_trace_data, uml_len, 32,
                                   "HTCP received %d-byte segment %p.",
                                   (int)adsl_hp->dsc_hpc.umc_len,
                                   &adsl_hp->dsc_hii);
                }

                m_htcp_in_packet(&adsp_hh->dsc_hc, &adsl_hp->dsc_hii, uml_len);
            } else {
                // discard incorrectly routed packet
                m_htun_relrecvbuf(adsl_hp->dsc_hpc.ac_handle);
            }
        }

        if (bol_s_timeout) {
            m_htcp_timeout(&adsp_hh->dsc_hc);
        }

        if (bol_s_close) {
            switch (adsp_hh->iec_hhs) {
            case ied_hhs_connecting:
                adsp_hh->iec_hhs = ied_hhs_conn_abort;

                m_htun_htcp_connect_end(adsp_hh->adsc_tcc,
                                        adsp_hh->adsc_target_ineta,
                                        adsp_hh->ac_free_ti1,
                                        NULL, 0, HTCP_ERR_CANCELLED);

                // m_htun_session_end() and m_free_resources() will be called
                // inside m_hcb_closed().

                m_htcp_abort(&adsp_hh->dsc_hc, false);
                break;

            case ied_hhs_connected:
                m_htcp_status(&adsp_hh->dsc_hc, &dsl_hs);
                m_htun_session_end(adsp_hh->adsc_tcc, 0);
                if (dsl_hs.umc_out_queue_len != 0) {
                    // Unacknowledged data pending.
                    adsp_hh->iec_hhs = ied_hhs_close_force;
                    m_htun_warning(NULL, adsp_hh->adsc_tci,
                                   HTCP_ERR_SESS_END_RST,
                                   "HTCP session closed while output data "
                                   "is pending, aborting.");
                    m_htcp_abort(&adsp_hh->dsc_hc, true);
                } else {
                    // Wait 30 seconds for graceful close before resetting.
                    adsp_hh->iec_hhs = ied_hhs_close;
                    adsp_hh->dsc_te_closing.ilcwaitmsec = 30000;
                    m_time_set(&adsp_hh->dsc_te_closing, FALSE);
                    m_htcp_out_send(&adsp_hh->dsc_hc, 0, false, true);
                }
                break;

            case ied_hhs_close:
                adsp_hh->iec_hhs = ied_hhs_close_force;
                m_htun_warning(NULL, adsp_hh->adsc_tci,
                               HTCP_ERR_SESS_END_RST,
                               "HTCP session not closed in time, aborting.");
                m_htcp_abort(&adsp_hh->dsc_hc, true);
                break;

            case ied_hhs_end:
                // Race condition, already should have called
                // m_htun_session_end(). Ignore.
                break;

            case ied_hhs_closed:
                // Race condition, received RST while timeout signalled us
                // to stop graceful wait and abort. We already aborted, so
                // do nothing here.
                break;

            default:
                // Should not arrive here. Display error message and ignore.
                m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                               HTCP_ERR_INTERNAL_ERROR,
                               "Internal HTCP error at xs-htcp-htun-01.cpp:%d "
                               "- attempting to close from state %d.",
                               __LINE__, (int)adsp_hh->iec_hhs);
            }
        }
    }
}

static void m_try_next_address(struct dsd_htcp_htun* adsp_hh)
{
    int inl_next;
    int inl_index;
    int inl_i;
    uint64_t ull_cur_bit;
    struct dsd_ineta_single_1* adsl_target;
    char* achl_bound;
    uint16_t usl_chksum;
    struct sockaddr_in dsl_sai;
    struct sockaddr_in6 dsl_sai6;
    char chrl_trace_addr[42];

    while (adsp_hh->inc_target_random_remain >= 0 ||
           adsp_hh->inc_target_cur + 1 <
           adsp_hh->adsc_target_ineta->imc_no_ineta) {

        // First get next address form list.
        if (adsp_hh->inc_target_random_remain == 0) {
            if (ins_round_robin_max >= adsp_hh->adsc_target_ineta->imc_no_ineta)
                break;
            inl_index = ins_round_robin_max;
            adsp_hh->inc_target_cur = inl_index;
        } else if (adsp_hh->inc_target_random_remain > 0) {
            inl_next = m_get_random_number(adsp_hh->inc_target_random_remain);
            --adsp_hh->inc_target_random_remain;

            ++inl_next;
            inl_index = 0;
            ull_cur_bit = 1;
            do {
                while ((adsp_hh->ulc_target_unused & ull_cur_bit) == 0) {
                    ++inl_index;
                    ull_cur_bit <<= 1;
                }

                if (inl_index >= ins_round_robin_max) {
                    // internal error
                    m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                                   HTCP_ERR_INTERNAL_ERROR,
                                   "Internal HTCP error at "
                                   "xs-htcp-htun-01.cpp:%d - "
                                   "confused round robin server order.",
                                   __LINE__);
                    m_htun_htcp_connect_end(adsp_hh->adsc_tcc,
                                            adsp_hh->adsc_target_ineta,
                                            adsp_hh->ac_free_ti1,
                                            NULL, 0, HTCP_ERR_INTERNAL_ERROR);
                    m_htun_session_end(adsp_hh->adsc_tcc,
                                       HTCP_ERR_INTERNAL_ERROR);
                    m_free_resources(adsp_hh);
                    return;
                }

                --inl_next;
                ++inl_index;
                ull_cur_bit <<= 1;
            } while (inl_next > 0);
            --inl_index;
            adsp_hh->ulc_target_unused ^= ull_cur_bit >> 1;
            /*
             * Note that the above code would fail to clear bit 64, but this is
             * not a problem since bit 64 should not be probed more than once.
             */
            adsp_hh->inc_target_cur = inl_index;
        } else { // adsp_hh->inc_target_random_remain < 0
            inl_index = adsp_hh->inc_target_cur + 1;
            adsp_hh->inc_target_cur = inl_index;
        }
        // We now have the index of the next address form list.

        /*
         * Note: we can cache the current location, but it is not really
         * necessary since it only saves a very small amount of time while
         * setting up the connection. On the other hand, it would add memory
         * overhead for each active connection.
         */
        achl_bound = (char*)adsp_hh->adsc_target_ineta +
            adsp_hh->adsc_target_ineta->imc_len_mem;
        adsl_target = (struct dsd_ineta_single_1*)
            (adsp_hh->adsc_target_ineta + 1);
        for (inl_i = 0; inl_i < inl_index; ++inl_i) {
            if ((char*)(adsl_target + 1) > achl_bound)
                break;
            adsl_target = (dsd_ineta_single_1*)
                ((char*)(adsl_target + 1) + adsl_target->usc_length);
        }
        if ((char*)(adsl_target + 1) > achl_bound ||
            ((char*)(adsl_target + 1) + adsl_target->usc_length) > achl_bound) {

            m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                           HTCP_ERR_INTERNAL_ERROR,
                           "Target address %d beyond "
                           "ds_target_ineta.imc_len_mem.",
                           inl_index);
            m_htun_htcp_connect_failed(adsp_hh->adsc_tcc, NULL, 0, inl_index,
                                       adsp_hh->adsc_target_ineta->imc_no_ineta,
                                       HTCP_ERR_INTERNAL_ERROR);

            // try next address
            continue;
        }

        if (adsl_target->usc_family == AF_INET &&
            adsl_target->usc_length == 4 &&
            adsp_hh->adsc_tci->dsc_soa_local_ipv4.sin_family == AF_INET) {

            adsp_hh->boc_ipv6 = false;

            memcpy(adsp_hh->chrc_local_addr,
                   &adsp_hh->adsc_tci->dsc_soa_local_ipv4.sin_addr.s_addr, 4);
            memcpy(adsp_hh->chrc_remote_addr, adsl_target + 1, 4);
            adsp_hh->usc_local_port =
                ntohs(adsp_hh->adsc_tci->dsc_soa_local_ipv4.sin_port);

            usl_chksum = m_calc_tcp_data_chksum(adsp_hh->chrc_local_addr, 4, 6);
            usl_chksum = m_calc_tcp_data_chksum(adsp_hh->chrc_remote_addr, 4,
                                                usl_chksum);

        } else if (adsl_target->usc_family == AF_INET6 &&
                   adsl_target->usc_length == 16 &&
                   adsp_hh->adsc_tci->dsc_soa_local_ipv6.sin6_family ==
                   AF_INET6) {

            adsp_hh->boc_ipv6 = true;

            memcpy(adsp_hh->chrc_local_addr,
                   &adsp_hh->adsc_tci->dsc_soa_local_ipv6.sin6_addr.s6_addr,
                   16);
            memcpy(adsp_hh->chrc_remote_addr, adsl_target + 1, 16);
            adsp_hh->usc_local_port =
                ntohs(adsp_hh->adsc_tci->dsc_soa_local_ipv6.sin6_port);

            usl_chksum = m_calc_tcp_data_chksum(adsp_hh->chrc_local_addr, 16,
                                                6);
            usl_chksum = m_calc_tcp_data_chksum(adsp_hh->chrc_remote_addr, 16,
                                                usl_chksum);
        } else {

            if (adsl_target->usc_family == AF_INET &&
                adsl_target->usc_length == 4) {

                m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                               HTCP_ERR_INTERNAL_ERROR,
                               "Connection has no local IPv4 address.");

                memset(&dsl_sai, 0, sizeof(dsl_sai));
                dsl_sai.sin_family = AF_INET;
                dsl_sai.sin_port = htons(adsp_hh->usc_remote_port);
                memcpy(&dsl_sai.sin_addr.s_addr, adsl_target + 1, 4);

                m_htun_htcp_connect_failed(adsp_hh->adsc_tcc,
                                           (struct sockaddr*)&dsl_sai,
                                           sizeof(dsl_sai),
                                           inl_index, adsp_hh->
                                           adsc_target_ineta->imc_no_ineta,
                                           HTCP_ERR_INTERNAL_ERROR);
            } else if (adsl_target->usc_family == AF_INET6 &&
                       adsl_target->usc_length == 16) {

                m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                               HTCP_ERR_INTERNAL_ERROR,
                               "Connection has no local IPv6 address.");

                memset(&dsl_sai6, 0, sizeof(dsl_sai6));
                dsl_sai6.sin6_family = AF_INET6;
                dsl_sai6.sin6_port = htons(adsp_hh->usc_remote_port);
                memcpy(&dsl_sai6.sin6_addr.s6_addr, adsl_target + 1, 16);

                m_htun_htcp_connect_failed(adsp_hh->adsc_tcc,
                                           (struct sockaddr*)&dsl_sai6,
                                           sizeof(dsl_sai6),
                                           inl_index, adsp_hh->
                                           adsc_target_ineta->imc_no_ineta,
                                           HTCP_ERR_INTERNAL_ERROR);
            } else {
                m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                               HTCP_ERR_INTERNAL_ERROR,
                               "Cannot recognize target address.");

                m_htun_htcp_connect_failed(adsp_hh->adsc_tcc, NULL, 0,
                                           inl_index, adsp_hh->
                                           adsc_target_ineta->imc_no_ineta,
                                           HTCP_ERR_INTERNAL_ERROR);
            }

            // try next address
            continue;
        }

        // we have found a valid address - attempt to connect

        if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
            m_print_addr(chrl_trace_addr,
                         adsp_hh->chrc_remote_addr, adsp_hh->boc_ipv6);
            m_do_wsp_trace("SNEHTCCA", 0,
                           adsp_hh->adsc_tcc->imc_sno,
                           adsp_hh->adsc_tcc->imc_trace_level,
                           NULL, 0, 0,
                           "HTCP attempting to connect to %s:%d.",
                           chrl_trace_addr, (int)adsp_hh->usc_remote_port);
        }

        m_htcp_init(&adsp_hh->dsc_hc, NULL, &dss_hcb, usl_chksum,
                    adsp_hh->usc_local_port, adsp_hh->usc_remote_port);
        m_htcp_out_send(&adsp_hh->dsc_hc, 0, false, false);
        return;
    }

    // no more addresses

    if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCCF", 0,
                       adsp_hh->adsc_tcc->imc_sno,
                       adsp_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP found no server available.");
    }

    if (adsp_hh->inc_htcp_error == 0)
        adsp_hh->inc_htcp_error = HTCP_ERR_CANCELLED;
    m_htun_htcp_connect_end(adsp_hh->adsc_tcc,
                            adsp_hh->adsc_target_ineta,
                            adsp_hh->ac_free_ti1,
                            NULL, 0, adsp_hh->inc_htcp_error);
    m_htun_session_end(adsp_hh->adsc_tcc, adsp_hh->inc_htcp_error);
    m_free_resources(adsp_hh);
}

static void m_recv_data(struct dsd_htcp_htun* adsp_hh)
{
    struct dsd_htcp_in_info* adsl_hii;
    uint32_t uml_offset;
    uint32_t uml_len;
    bool bol_push;
    bool bol_eof;
    bool bol_more;
    const int inl_bve_size = 8;
    struct dsd_buf_vector_ele dsrl_bve[inl_bve_size];
    int inl_bve_index;
    struct dsd_htcp_packet* adsl_hp;
    struct dsd_gather_i_1 dsl_trace_data;

    inl_bve_index = 0;
    do {
        m_htcp_in_get_data(&adsp_hh->dsc_hc, &adsl_hii, &uml_offset, &uml_len,
                           &bol_push, &bol_eof, &bol_more, false);

        if (adsl_hii == NULL)
            break;
        adsl_hp = (struct dsd_htcp_packet*)
            ((char*)adsl_hii - offsetof(struct dsd_htcp_packet, dsc_hii));

        if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
            dsl_trace_data.achc_ginp_cur =
                adsl_hp->dsc_hpc.achc_data + uml_offset;
            dsl_trace_data.achc_ginp_end =
                dsl_trace_data.achc_ginp_cur + uml_len;
            dsl_trace_data.adsc_next = NULL;
            m_do_wsp_trace("SNEHTCHD", 0,
                           adsp_hh->adsc_tcc->imc_sno,
                           adsp_hh->adsc_tcc->imc_trace_level,
                           &dsl_trace_data, uml_len, 16,
                           "HTCP obtained %d bytes from segment %p.",
                           (int)uml_len, adsl_hii);
        }

        dsrl_bve[inl_bve_index].ac_handle = adsl_hp->dsc_hpc.ac_handle;
        dsrl_bve[inl_bve_index].achc_data =
            adsl_hp->dsc_hpc.achc_data + uml_offset;
        dsrl_bve[inl_bve_index].imc_len_data = uml_len;
        ++inl_bve_index;

        if (inl_bve_index == inl_bve_size) {
            if (adsp_hh->iec_hhs != ied_hhs_connected)
                break;
            inl_bve_index = 0;
            if (!m_se_htun_recvbuf(adsp_hh->adsc_tcc, dsrl_bve, inl_bve_size)) {
                if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW)
                    != 0) {

                    m_do_wsp_trace("SNEHTCSB", 0,
                                   adsp_hh->adsc_tcc->imc_sno,
                                   adsp_hh->adsc_tcc->imc_trace_level,
                                   NULL, 0, 0,
                                   "HTCP can no longer receive data.");
                }

                adsp_hh->boc_can_recv = false;
                break;
            }
        }
    } while (bol_more);

    if (inl_bve_index > 0) {
        if (adsp_hh->iec_hhs != ied_hhs_connected) {
            // free all data and abort HTCP
            while (inl_bve_index > 0) {
                --inl_bve_index;
                m_htun_relrecvbuf(dsrl_bve[inl_bve_index].ac_handle);
            }

            // there is no need to get any more data for freeing -
            // HTCP will free the data itself

            m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                           HTCP_ERR_SESS_END_RST,
                           "Received unwanted data.");
            m_htcp_abort(&adsp_hh->dsc_hc, true);
            return;
        }

        if (!m_se_htun_recvbuf(adsp_hh->adsc_tcc, dsrl_bve, inl_bve_index)) {
            adsp_hh->boc_can_recv = false;
        }
    }

    if (bol_eof) {
        if ((adsp_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
            m_do_wsp_trace("SNEHTCHF", 0,
                           adsp_hh->adsc_tcc->imc_sno,
                           adsp_hh->adsc_tcc->imc_trace_level,
                           &dsl_trace_data, uml_len, 16,
                           "HTCP received end of connection indication.");
        }

        switch (adsp_hh->iec_hhs) {
        case ied_hhs_connected:
            adsp_hh->iec_hhs = ied_hhs_end;
            m_htun_session_end(adsp_hh->adsc_tcc, 0);
            m_htcp_out_send(&adsp_hh->dsc_hc, 0, false, true);
            break;

        case ied_hhs_close:
#ifdef ML150127
            if (!m_time_rel(&adsp_hh->dsc_te_closing)) {
                // Did not stop timer in time, so just ignore received FIN and
                // allow timer to take us to ied_hhs_close_force.
                break;
            }
#endif

#ifndef ML150127 // try to make closing here?
			//m_hct_compl_closing(&adsp_hh->dsc_te_closing);
			// TODO - how to handle ied_hhs_time_wait??
			//m_htcp_sess_close(adsp_hh);
			//m_htcp_abort(&adsp_hh->dsc_hc, false);
			/*if(adsp_hh->adsc_tci){
				m_htun_htcp_free_resources(adsp_hh->adsc_tci);
				adsp_hh->adsc_tci = NULL;
			}*/
			break;
			
#else
            adsp_hh->iec_hhs = ied_hhs_time_wait;
            break;
#endif

        case ied_hhs_close_force:
            // Too late now, already aborting.
            break;

        default:
            // should not arrive here
            m_htun_warning(adsp_hh->adsc_tcc, adsp_hh->adsc_tci,
                           HTCP_ERR_INTERNAL_ERROR,
                           "Received FIN in unexpected state - %d.",
                           (int)adsp_hh->iec_hhs);
        }
    }
}

static void m_free_resources(struct dsd_htcp_htun* adsp_hh)
{
    struct dsd_gather_i_1* adsl_gai1;

    // xs-htcp-01.cpp should have freed all packets in out-of-order queue

    // xs-htcp-01.cpp should have freed all packets in output queue
#ifdef B130425
    while (adsp_hh->adsc_sending != NULL) {
        adsl_gai1 = adsp_hh->adsc_sending;
        adsp_hh->adsc_sending = adsl_gai1->adsc_next;
        adsl_gai1->achc_ginp_cur = adsl_gai1->achc_ginp_end;
    }
#endif // B130425

    adsp_hh->iec_hhs = ied_hhs_closed;
    m_htun_htcp_free_resources(adsp_hh->adsc_tci);

    // wait for 30 seconds before freeing memory
    adsp_hh->boc_te_closing_free = true;
    adsp_hh->dsc_te_closing.ilcwaitmsec = 30000;
    m_time_set(&adsp_hh->dsc_te_closing, FALSE);
}

static void m_hct_compl(struct dsd_timer_ele* adsp_te)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_te - offsetof(struct dsd_htcp_htun, dsc_te));
    bool bol_running;

    if ((adsl_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCTO", 0,
                       adsl_hh->adsc_tcc->imc_sno,
                       adsl_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP timeout.");
    }

    m_htun_critsect_enter(adsl_hh->adsc_tcc);
    adsl_hh->boc_sync_timeout = true;
    bol_running = adsl_hh->boc_sync_running;
    adsl_hh->boc_sync_running = true;
    m_htun_critsect_leave(adsl_hh->adsc_tcc);

    if (!bol_running)
        m_process_sync(adsl_hh);
}

static void m_hct_compl_closing(struct dsd_timer_ele* adsp_te)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_te - offsetof(struct dsd_htcp_htun, dsc_te_closing));
    bool bol_running;

    /*
     * This timer only set in two places:
     * 1. After receiving m_htun_sess_close(), to give the session enough time
     *    for graceful closing before sending RST.
     * 2. When a session is ended completely, so that adsl_hh is freed.
     * Case 2. will have adsl_hh->boc_te_closing_free set to true.
     */

    if ((adsl_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCTC", 0,
                       adsl_hh->adsc_tcc->imc_sno,
                       adsl_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       (adsl_hh->boc_te_closing_free ?
                        "HTCP timeout - freeing." :
                        "HTCP timeout - forcing close."));
    }

    if (adsl_hh->boc_te_closing_free) {
        free(adsl_hh);
    } else {
        m_htun_critsect_enter(adsl_hh->adsc_tcc);
        adsl_hh->boc_sync_close = true;
        bol_running = adsl_hh->boc_sync_running;
        adsl_hh->boc_sync_running = true;
        m_htun_critsect_leave(adsl_hh->adsc_tcc);

        if (!bol_running)
            m_process_sync(adsl_hh);
    }
}

static bool m_hcb_out_get(struct dsd_htcp_conn* adsp_hc,
                          uint32_t ump_offset,
                          const char** aachp_buf, uint32_t* aump_len)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));
    struct dsd_gather_i_1* adsl_gai1;

    adsl_gai1 = adsl_hh->adsc_sending;

    while (adsl_gai1 != NULL) {
        if (adsl_gai1->achc_ginp_cur + ump_offset < adsl_gai1->achc_ginp_end) {
            *aachp_buf = adsl_gai1->achc_ginp_cur + ump_offset;
            *aump_len = adsl_gai1->achc_ginp_end - *aachp_buf;
            return true;
        }
        ump_offset -= adsl_gai1->achc_ginp_end - adsl_gai1->achc_ginp_cur;
        adsl_gai1 = adsl_gai1->adsc_next;
    }

    if (ump_offset == 0) {
        *aachp_buf = NULL;
        *aump_len = 0;
        return true;
    }

    m_htun_warning(adsl_hh->adsc_tcc, adsl_hh->adsc_tci,
                   HTCP_ERR_INTERNAL_ERROR,
                   "Internal HTCP error at at xs-htcp-htun-01.cpp:%d - "
                   "output offset too large.",
                   __LINE__);
    return false;
}

static bool m_hcb_out_packets(struct dsd_htcp_conn* adsp_hc)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));
    char chrl_header[100]; // 40 for IP, 60 for TCP
    uint32_t uml_hlen;
    uint32_t uml_offset;
    uint32_t uml_len;
    bool bol_more;
    struct dsd_gather_i_1 dsl_g_header;
    struct dsd_gather_i_1 dsl_g_data;
    struct dsd_gather_i_1* adsl_gai1;
    uint32_t uml_len_test;
    struct dsd_gather_i_1* adsl_gai1_test;
    int inl_trace_offset;
    struct dsd_gather_i_1 dsl_trace_data;

    do {
        uml_hlen = 60;
        m_htcp_out_get_packet(adsp_hc, chrl_header + 40, &uml_hlen,
                              &uml_offset, &uml_len, &bol_more);
        if (uml_hlen == 0)
            break;

        if (adsl_hh->boc_ipv6) {
            m_set_ip6_version(chrl_header, 6);
            m_set_ip6_tcls(chrl_header, 0);
            m_set_ip6_flow(chrl_header, 0);
            m_set_ip6_plen(chrl_header, uml_hlen + uml_len);
            m_set_ip6_nh(chrl_header, 6);
            m_set_ip6_hlim(chrl_header, 128);
            m_set_ip6_src_addr(chrl_header, adsl_hh->chrc_local_addr);
            m_set_ip6_dst_addr(chrl_header, adsl_hh->chrc_remote_addr);

            uml_hlen += 40;
            dsl_g_header.achc_ginp_cur = chrl_header;
            dsl_g_header.achc_ginp_end = chrl_header + uml_hlen;
        } else {
            m_set_ip_version(chrl_header + 20, 4);
            m_set_calc_ip_hlen(chrl_header + 20, 20);
            m_set_ip_tos(chrl_header + 20, 0);
            m_set_ip_tlen(chrl_header + 20, 20 + uml_hlen + uml_len);
            m_set_ip_id(chrl_header + 20, 0);
            m_set_ip_flags(chrl_header + 20, 0);
            m_set_ip_df(chrl_header + 20, 1);
            m_set_calc_ip_fofs(chrl_header + 20, 0);
            m_set_ip_ttl(chrl_header + 20, 128);
            m_set_ip_prot(chrl_header + 20, 6);
            m_set_ip_src_addr_buf(chrl_header + 20, adsl_hh->chrc_local_addr);
            m_set_ip_dst_addr_buf(chrl_header + 20, adsl_hh->chrc_remote_addr);
            m_set_ip_chksum(chrl_header + 20,
                            m_calc_ip_chksum(chrl_header + 20));

            uml_hlen += 20;
            dsl_g_header.achc_ginp_cur = chrl_header + 20;
            dsl_g_header.achc_ginp_end = chrl_header + 20 + uml_hlen;
        }

        if (uml_len == 0) {
            dsl_g_header.adsc_next = NULL;
        } else {
            dsl_g_header.adsc_next = &dsl_g_data;

            adsl_gai1 = adsl_hh->adsc_sending;
            while (adsl_gai1 != NULL) {
                if (adsl_gai1->achc_ginp_cur + uml_offset <
                    adsl_gai1->achc_ginp_end) {

                    break;
                }
                uml_offset -= adsl_gai1->achc_ginp_end -
                    adsl_gai1->achc_ginp_cur;
                adsl_gai1 = adsl_gai1->adsc_next;
            }

            adsl_gai1_test = adsl_gai1;
            uml_len_test = uml_offset + uml_len;
            while (adsl_gai1_test != NULL) {
                if (adsl_gai1_test->achc_ginp_cur + uml_len_test <
                    adsl_gai1_test->achc_ginp_end) {

                    break;
                }
                uml_len_test -= adsl_gai1_test->achc_ginp_end -
                    adsl_gai1_test->achc_ginp_cur;
                adsl_gai1_test = adsl_gai1_test->adsc_next;
            }

            if (adsl_gai1_test == NULL && uml_len_test > 0) {
                m_htun_warning(adsl_hh->adsc_tcc, adsl_hh->adsc_tci,
                               HTCP_ERR_INTERNAL_ERROR,
                               "Internal HTCP error at xs-htcp-htun-01.cpp:%d"
                               " - bad packet length.",
                               __LINE__);
                return false;
            }

            dsl_g_data.achc_ginp_cur = adsl_gai1->achc_ginp_cur + uml_offset;
            dsl_g_data.achc_ginp_end = adsl_gai1->achc_ginp_end;
            dsl_g_data.adsc_next = adsl_gai1->adsc_next;
        }

        if ((adsl_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
            if (adsl_hh->boc_ipv6)
                inl_trace_offset = 40;
            else
                inl_trace_offset = 20;
            dsl_trace_data.achc_ginp_cur =
                dsl_g_header.achc_ginp_cur + inl_trace_offset;
            dsl_trace_data.achc_ginp_end = dsl_g_header.achc_ginp_end;
            dsl_trace_data.adsc_next = dsl_g_header.adsc_next;
            m_do_wsp_trace("SNEHTCNS", 0,
                           adsl_hh->adsc_tcc->imc_sno,
                           adsl_hh->adsc_tcc->imc_trace_level,
                           &dsl_trace_data,
                           uml_hlen + uml_len - inl_trace_offset, 32,
                           "HTCP sending %d-byte segment.",
                           (int)(uml_hlen + uml_len - inl_trace_offset));
        }

        m_se_husip_send_gather(&dsl_g_header, uml_hlen + uml_len);

    } while (bol_more);

    return true;
}

static bool m_hcb_out_ack(struct dsd_htcp_conn* adsp_hc, uint32_t ump_len)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));
    struct dsd_gather_i_1* adsl_gai1;

    if ((adsl_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCHA", 0,
                       adsl_hh->adsc_tcc->imc_sno,
                       adsl_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP releasing %d acknowledged bytes.",
                       (int)(ump_len));
    }

    m_htun_critsect_enter(adsl_hh->adsc_tcc);

    if (adsl_hh->iec_hhs == ied_hhs_close ||
        adsl_hh->iec_hhs == ied_hhs_close_force) {

        // m_htun_session_end() was called, so data is freed
        m_htun_critsect_leave(adsl_hh->adsc_tcc);
        return true;
    }

    adsl_gai1 = adsl_hh->adsc_sending;
    while (ump_len > 0) {
        if (adsl_gai1 == NULL) {
            m_htun_critsect_leave(adsl_hh->adsc_tcc);
            m_htun_warning(adsl_hh->adsc_tcc, adsl_hh->adsc_tci,
                           HTCP_ERR_INTERNAL_ERROR,
                           "Internal HTCP error at xs-htcp-htun-01.cpp:%d - "
                           "acknowledging more data than available.",
                           __LINE__);
            return false;
        }

        // The following line should be < and NOT <= since in case of equality
        // we must forget about the block.
        if (adsl_gai1->achc_ginp_cur + ump_len < adsl_gai1->achc_ginp_end) {
            adsl_gai1->achc_ginp_cur += ump_len;
            break;
        }

        adsl_hh->adsc_sending = adsl_gai1->adsc_next;
        ump_len -= adsl_gai1->achc_ginp_end - adsl_gai1->achc_ginp_cur;
        adsl_gai1->achc_ginp_cur = adsl_gai1->achc_ginp_end;
        adsl_gai1 = adsl_hh->adsc_sending;
    }

	// Check if gather empty at the beginning of sending chain
	while(adsl_hh->adsc_sending){
		if(adsl_hh->adsc_sending->achc_ginp_cur != adsl_hh->adsc_sending->achc_ginp_end)
			break;
		adsl_hh->adsc_sending = adsl_hh->adsc_sending->adsc_next;
	}


    m_htun_critsect_leave(adsl_hh->adsc_tcc);
    m_htun_htcp_send_complete(adsl_hh->adsc_tcc);
    return true;
}

static bool m_hcb_in_get(struct dsd_htcp_conn* adsp_hc,
                         struct dsd_htcp_in_info* adsp_hii,
                         uint32_t ump_offset,
                         const char** aachp_buf, uint32_t* aump_len)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));
    struct dsd_htcp_packet* adsl_hp = (struct dsd_htcp_packet*)
        ((char*)adsp_hii - offsetof(struct dsd_htcp_packet, dsc_hii));

    if (ump_offset > adsl_hp->dsc_hpc.umc_len) {
        m_htun_warning(adsl_hh->adsc_tcc, adsl_hh->adsc_tci,
                       HTCP_ERR_INTERNAL_ERROR,
                       "Internal HTCP error at xs-htcp-htun-01.cpp:%d - "
                       " packet offset too large.",
                       __LINE__);
        return false;
    }

    *aachp_buf = adsl_hp->dsc_hpc.achc_data + ump_offset;
    *aump_len = adsl_hp->dsc_hpc.umc_len - ump_offset;
    return true;
}

static bool m_hcb_in_more_data(struct dsd_htcp_conn* adsp_hc)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));

    if (adsl_hh->boc_can_recv)
        m_recv_data(adsl_hh);

    return true;
}

static bool m_hcb_in_rel(struct dsd_htcp_conn* adsp_hc,
                         struct dsd_htcp_in_info* adsp_hii)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));
    struct dsd_htcp_packet* adsl_hp = (struct dsd_htcp_packet*)
        ((char*)adsp_hii - offsetof(struct dsd_htcp_packet, dsc_hii));

    if ((adsl_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCHL", 0,
                       adsl_hh->adsc_tcc->imc_sno,
                       adsl_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP done using segment %p.",
                       adsp_hii);
    }

    m_htun_relrecvbuf(adsl_hp->dsc_hpc.ac_handle);
    return true;
}

static bool m_hcb_get_time(struct dsd_htcp_conn* adsp_hc, int64_t* ailp_time)
{
    *ailp_time = m_get_epoch_ms();
    return true;
}

static bool m_hcb_set_timer(struct dsd_htcp_conn* adsp_hc,
                            uint32_t ump_delay_ms)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));

    if ((adsl_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCCT", 0,
                       adsl_hh->adsc_tcc->imc_sno,
                       adsl_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP setting timeout - %d ms delay.",
                       (int)(ump_delay_ms));
    }

    m_time_rel(&adsl_hh->dsc_te);
    adsl_hh->dsc_te.ilcwaitmsec = ump_delay_ms;
    m_time_set(&adsl_hh->dsc_te, FALSE);
    return true;
}

static bool m_hcb_rel_timer(struct dsd_htcp_conn* adsp_hc)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));

    if ((adsl_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_do_wsp_trace("SNEHTCHR", 0,
                       adsl_hh->adsc_tcc->imc_sno,
                       adsl_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP releasing timer if active.");
    }

    m_time_rel(&adsl_hh->dsc_te);
    return true;
}

static bool m_hcb_lock(struct dsd_htcp_conn* adsp_hc)
{
    // No need for locking since calls are synchronized.
    return true;
}

static bool m_hcb_unlock(struct dsd_htcp_conn* adsp_hc)
{
    // No need for locking since calls are synchronized.
    return true;
}

static bool m_hcb_established(struct dsd_htcp_conn* adsp_hc)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));
    struct sockaddr_in dsl_sai;
    struct sockaddr_in6 dsl_sai6;
    struct sockaddr* adsl_sa;
    socklen_t ul_sl;
    char chrl_trace_addr[42];

    if ((adsl_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        m_print_addr(chrl_trace_addr,
                     adsl_hh->chrc_remote_addr, adsl_hh->boc_ipv6);
        m_do_wsp_trace("SNEHTCHE", 0,
                       adsl_hh->adsc_tcc->imc_sno,
                       adsl_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP connection established with %s:%d.",
                       chrl_trace_addr, (int)adsl_hh->usc_remote_port);
    }

    adsl_hh->iec_hhs = ied_hhs_connected;

    if (adsl_hh->boc_ipv6) {
        memset(&dsl_sai6, 0, sizeof(dsl_sai6));
        dsl_sai6.sin6_family = AF_INET6;
        dsl_sai6.sin6_port = htons(adsl_hh->usc_remote_port);
        memcpy(&dsl_sai6.sin6_addr.s6_addr, adsl_hh->chrc_remote_addr, 16);
        adsl_sa = (struct sockaddr*)&dsl_sai6;
        ul_sl = sizeof(dsl_sai6);
    } else { // IPv4
        memset(&dsl_sai, 0, sizeof(dsl_sai));
        dsl_sai.sin_family = AF_INET;
        dsl_sai.sin_port = htons(adsl_hh->usc_remote_port);
        memcpy(&dsl_sai.sin_addr.s_addr, adsl_hh->chrc_remote_addr, 4);
        adsl_sa = (struct sockaddr*)&dsl_sai;
        ul_sl = sizeof(dsl_sai);
    }

    m_htun_htcp_connect_end(adsl_hh->adsc_tcc, adsl_hh->adsc_target_ineta,
                            adsl_hh->ac_free_ti1, adsl_sa, ul_sl, 0);

    return true;
}

static void m_hcb_closed(struct dsd_htcp_conn* adsp_hc,
                         enum ied_htcp_close iep_htcpc)
{
    struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)
        ((char*)adsp_hc - offsetof(struct dsd_htcp_htun, dsc_hc));
    char chrl_close_description[128];
    uint32_t uml_dlen;
    char chrl_close_debug_info[128];
    uint32_t uml_dilen;
    struct sockaddr_in dsl_sai;
    struct sockaddr_in6 dsl_sai6;
    struct sockaddr* adsl_sa;
    socklen_t ul_sl;
    int inl_error;

    if ((adsl_hh->adsc_tcc->imc_trace_level & HL_WT_SESS_NETW) != 0) {
        uml_dlen = sizeof(chrl_close_description);
        uml_dilen = sizeof(chrl_close_description);
        m_htcp_describe_close(&adsl_hh->dsc_hc,
                              chrl_close_description, &uml_dlen,
                              chrl_close_debug_info, &uml_dilen);
        m_do_wsp_trace("SNEHTCHC", 0,
                       adsl_hh->adsc_tcc->imc_sno,
                       adsl_hh->adsc_tcc->imc_trace_level,
                       NULL, 0, 0,
                       "HTCP TCP connection closed from state %d - %s (%s).",
                       (int)adsl_hh->iec_hhs,
                       chrl_close_debug_info, chrl_close_debug_info);
    }

    switch (adsl_hh->iec_hhs) {
    case ied_hhs_connecting:
        // Connection failed to establish.
        if (adsl_hh->boc_ipv6) {
            memset(&dsl_sai6, 0, sizeof(dsl_sai6));
            dsl_sai6.sin6_family = AF_INET6;
            dsl_sai6.sin6_port = htons(adsl_hh->usc_remote_port);
            memcpy(&dsl_sai6.sin6_addr.s6_addr, adsl_hh->chrc_remote_addr, 16);
            adsl_sa = (struct sockaddr*)&dsl_sai6;
            ul_sl = sizeof(dsl_sai6);
        } else { // IPv4
            memset(&dsl_sai, 0, sizeof(dsl_sai));
            dsl_sai.sin_family = AF_INET;
            dsl_sai.sin_port = htons(adsl_hh->usc_remote_port);
            memcpy(&dsl_sai.sin_addr.s_addr, adsl_hh->chrc_remote_addr, 4);
            adsl_sa = (struct sockaddr*)&dsl_sai;
            ul_sl = sizeof(dsl_sai);
        }
        uml_dlen = sizeof(chrl_close_description);
        m_htcp_describe_close(&adsl_hh->dsc_hc,
                              chrl_close_description, &uml_dlen,
                              NULL, NULL);

        if (iep_htcpc == ied_htcpc_conn_refused) {
            inl_error = HTCP_ERR_CONN_REFUSED;
            if (adsl_hh->inc_htcp_error == HTCP_ERR_CONN_ALL_TIMEOUT)
                adsl_hh->inc_htcp_error = HTCP_ERR_CONN_ALL_RF_TO;
            else if (adsl_hh->inc_htcp_error != HTCP_ERR_CONN_ALL_RF_TO)
                adsl_hh->inc_htcp_error = HTCP_ERR_CONN_ALL_REFUSED;
        } else if (iep_htcpc == ied_htcpc_conn_timeout) {
            inl_error = HTCP_ERR_CONN_TIMEOUT;
            if (adsl_hh->inc_htcp_error == HTCP_ERR_CONN_ALL_REFUSED)
                adsl_hh->inc_htcp_error = HTCP_ERR_CONN_ALL_RF_TO;
            else if (adsl_hh->inc_htcp_error != HTCP_ERR_CONN_ALL_RF_TO)
                adsl_hh->inc_htcp_error = HTCP_ERR_CONN_ALL_TIMEOUT;
        } else {
            inl_error = HTCP_ERR_CANCELLED;
        }

        m_htun_warning(adsl_hh->adsc_tcc, adsl_hh->adsc_tci, inl_error,
                       "connecting failed - %s", chrl_close_description);
        m_htun_htcp_connect_failed(adsl_hh->adsc_tcc, adsl_sa, ul_sl,
                                   adsl_hh->inc_target_cur,
                                   adsl_hh->adsc_target_ineta->imc_no_ineta,
                                   inl_error);

        m_try_next_address(adsl_hh);
        // return not break - we do not want to close whole session
        return;

    case ied_hhs_conn_abort:
        // Connection aborted while attempting to connect.
        m_htun_session_end(adsl_hh->adsc_tcc, HTCP_ERR_CANCELLED);
        break;

    case ied_hhs_connected:
        // Should be here if we received RST from remote endpoint or timeout.
        if (iep_htcpc == ied_htcpc_conn_timeout)
            inl_error = HTCP_ERR_SESS_END_TIMEOUT;
        else
            inl_error = HTCP_ERR_SESS_END_RST;
        uml_dlen = sizeof(chrl_close_description);
        m_htcp_describe_close(&adsl_hh->dsc_hc,
                              chrl_close_description, &uml_dlen,
                              NULL, NULL);
        m_htun_warning(adsl_hh->adsc_tcc, adsl_hh->adsc_tci, inl_error,
                       "connection closed - %s", chrl_close_description);
        m_htun_session_end(adsl_hh->adsc_tcc, inl_error);
        break;

    case ied_hhs_close:
        // Should be here if we received RST from remote endpoint or timeout
        // after sending FIN.
        adsl_hh->iec_hhs = ied_hhs_closed;
        m_time_rel(&adsl_hh->dsc_te_closing);
        // If we do not manage to stop timer, nothing bad happens. The state
        // ied_hhs_closed would indicate that the connection is ended anyway.
        if (iep_htcpc == ied_htcpc_conn_timeout)
            inl_error = HTCP_ERR_SESS_END_TIMEOUT;
        else
            inl_error = HTCP_ERR_SESS_END_RST;
        uml_dlen = sizeof(chrl_close_description);
        m_htcp_describe_close(&adsl_hh->dsc_hc,
                              chrl_close_description, &uml_dlen,
                              NULL, NULL);
        m_htun_warning(adsl_hh->adsc_tcc, adsl_hh->adsc_tci, inl_error,
                       "connection closed - %s", chrl_close_description);
        m_htun_session_end(adsl_hh->adsc_tcc, inl_error);
        break;

    case ied_hhs_close_force:
        // Should be here after giving up waiting for connection to close
        // gracefully.
        break;

    case ied_hhs_time_wait:
        // connection closed gracefully after TIME_WAIT
        break;

    case ied_hhs_end:
        // Connection closed after receiving FIN and sending FIN.
        // Do not call m_htun_session_end() since it was already called when
        // the state was set to ied_hhs_end.
        break;

    default:
        // should not arrive here
        m_time_rel(&adsl_hh->dsc_te_closing);
        uml_dlen = sizeof(chrl_close_description);
        m_htcp_describe_close(&adsl_hh->dsc_hc,
                              chrl_close_description, &uml_dlen,
                              NULL, NULL);
        m_htun_warning(adsl_hh->adsc_tcc, adsl_hh->adsc_tci,
                       HTCP_ERR_INTERNAL_ERROR,
                       "Internal HTCP error at "
                       "xs-htcp-htun-01.cpp:%d - closed when in state %d - %s.",
                       __LINE__, (int)adsl_hh->iec_hhs, chrl_close_description);
    }

    m_free_resources(adsl_hh);
}
