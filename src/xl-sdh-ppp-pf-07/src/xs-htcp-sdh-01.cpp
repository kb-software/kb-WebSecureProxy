#define SDH_TCP_NO_CUBIC

#define TRACE_EXT_SYN

// If more than one TRY_FORCE_ definition is defined, the ones at the top
// of the list get higher priority.

//#define TRY_FORCE_WSP_TRACE_DATA_2 // extended
//#define TRY_FORCE_WSP_TRACE_DATA_1 // short
//#define TRY_FORCE_WSP_TRACE_NO_DATA
//#define TRY_FORCE_WSP_NO_TRACE

//#define SDH_TCP_TRACE_FILE "SDH-TCP-TRACE-01.dat"

/******************************************************************************
 * File name: xs-htcp-sdh-01.cpp
 *
 * Requires: hob-xsclib01.h, HTCP.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2011-2013
 ******************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>

#ifdef _MSC_VER
#pragma warning(disable: 4244)
#pragma warning(disable: 4800)
#endif

/*
 * Visual Studio does not provide snprintf(), and vsnprintf() is not the same as
 * the standard vsnprintf() when the buffer size is insufficient.
 */

#ifdef _MSC_VER

#pragma warning(disable: 4996)

// va_copy() is not provided by Visual Studio, but va_list can be copied.
#ifndef va_copy
#define va_copy(dst, src) ((dst) = (src))
#endif

static int m_vsnprintf(char* achp_str, size_t upp_size,
                       const char* achp_format, va_list ap)
{
    va_list ap_copy;
    int inl_ret;

    if (achp_str != NULL && upp_size > 0) {
        va_copy(ap_copy, ap);
        inl_ret = _vsnprintf(achp_str, upp_size, achp_format, ap_copy);
        va_end(ap_copy);

        if (inl_ret != -1 && inl_ret != (int)upp_size)
            return inl_ret;

        achp_str[upp_size - 1] = '\0';
    }

    return _vscprintf(achp_format, ap);
}

static int m_snprintf(char* achp_str, size_t upp_size,
                      const char* achp_format, ...)
{
    va_list ap;
    int inl_ret;

    va_start(ap, achp_format);
    inl_ret = m_vsnprintf(achp_str, upp_size, achp_format, ap);
    va_end(ap);

    return inl_ret;
}

#else  /* !defined _MSC_VER */

static int (* const m_vsnprintf)(char* achp_str, size_t upp_size,
                                 const char* achp_format, va_list ap) =
    &vsnprintf;

static int (* const m_snprintf)(char* achp_str, size_t upp_size,
                                const char* achp_format, ...) =
    &snprintf;

#endif /* !defined _MSC_VER */

#ifdef HL_UNIX
#include <arpa/inet.h>
#include "hob-unix01.h"
#else /* !HL_UNIX */
#include <winsock2.h>
#endif /* !HL_UNIX */

#include "hob-xsclib01.h"

#ifndef DEF_INCLUDE_HEADERS
#define DEF_INCLUDE_HEADERS
#endif /* !DEF_INCLUDE_HEADERS */

#include "hob-htcp-int-01.h"
#include "hob-htcp-hdr-01.h"
#include "hob-htcp-01.h"
#include "hob-htcp-sdh-01.h"


#ifdef SDH_TCP_TRACE_FILE

#include <fstream>

std::ofstream dsg_sdh_tcp_trace_file(SDH_TCP_TRACE_FILE);

#ifdef TRACE_STREAM
#undefine TRACE_STREAM
#endif

#define TRACE_STREAM (&dsg_sdh_tcp_trace_file)

#endif // SDH_TCP_TRACE_FILE


#ifdef TRACE_STREAM

#include <fstream>

static const char chrs_char_hex[][2] = {
    {'0', '0'}, {'0', '1'}, {'0', '2'}, {'0', '3'},
    {'0', '4'}, {'0', '5'}, {'0', '6'}, {'0', '7'},
    {'0', '8'}, {'0', '9'}, {'0', 'A'}, {'0', 'B'},
    {'0', 'C'}, {'0', 'D'}, {'0', 'E'}, {'0', 'F'},
    {'1', '0'}, {'1', '1'}, {'1', '2'}, {'1', '3'},
    {'1', '4'}, {'1', '5'}, {'1', '6'}, {'1', '7'},
    {'1', '8'}, {'1', '9'}, {'1', 'A'}, {'1', 'B'},
    {'1', 'C'}, {'1', 'D'}, {'1', 'E'}, {'1', 'F'},
    {'2', '0'}, {'2', '1'}, {'2', '2'}, {'2', '3'},
    {'2', '4'}, {'2', '5'}, {'2', '6'}, {'2', '7'},
    {'2', '8'}, {'2', '9'}, {'2', 'A'}, {'2', 'B'},
    {'2', 'C'}, {'2', 'D'}, {'2', 'E'}, {'2', 'F'},
    {'3', '0'}, {'3', '1'}, {'3', '2'}, {'3', '3'},
    {'3', '4'}, {'3', '5'}, {'3', '6'}, {'3', '7'},
    {'3', '8'}, {'3', '9'}, {'3', 'A'}, {'3', 'B'},
    {'3', 'C'}, {'3', 'D'}, {'3', 'E'}, {'3', 'F'},
    {'4', '0'}, {'4', '1'}, {'4', '2'}, {'4', '3'},
    {'4', '4'}, {'4', '5'}, {'4', '6'}, {'4', '7'},
    {'4', '8'}, {'4', '9'}, {'4', 'A'}, {'4', 'B'},
    {'4', 'C'}, {'4', 'D'}, {'4', 'E'}, {'4', 'F'},
    {'5', '0'}, {'5', '1'}, {'5', '2'}, {'5', '3'},
    {'5', '4'}, {'5', '5'}, {'5', '6'}, {'5', '7'},
    {'5', '8'}, {'5', '9'}, {'5', 'A'}, {'5', 'B'},
    {'5', 'C'}, {'5', 'D'}, {'5', 'E'}, {'5', 'F'},
    {'6', '0'}, {'6', '1'}, {'6', '2'}, {'6', '3'},
    {'6', '4'}, {'6', '5'}, {'6', '6'}, {'6', '7'},
    {'6', '8'}, {'6', '9'}, {'6', 'A'}, {'6', 'B'},
    {'6', 'C'}, {'6', 'D'}, {'6', 'E'}, {'6', 'F'},
    {'7', '0'}, {'7', '1'}, {'7', '2'}, {'7', '3'},
    {'7', '4'}, {'7', '5'}, {'7', '6'}, {'7', '7'},
    {'7', '8'}, {'7', '9'}, {'7', 'A'}, {'7', 'B'},
    {'7', 'C'}, {'7', 'D'}, {'7', 'E'}, {'7', 'F'},
    {'8', '0'}, {'8', '1'}, {'8', '2'}, {'8', '3'},
    {'8', '4'}, {'8', '5'}, {'8', '6'}, {'8', '7'},
    {'8', '8'}, {'8', '9'}, {'8', 'A'}, {'8', 'B'},
    {'8', 'C'}, {'8', 'D'}, {'8', 'E'}, {'8', 'F'},
    {'9', '0'}, {'9', '1'}, {'9', '2'}, {'9', '3'},
    {'9', '4'}, {'9', '5'}, {'9', '6'}, {'9', '7'},
    {'9', '8'}, {'9', '9'}, {'9', 'A'}, {'9', 'B'},
    {'9', 'C'}, {'9', 'D'}, {'9', 'E'}, {'9', 'F'},
    {'A', '0'}, {'A', '1'}, {'A', '2'}, {'A', '3'},
    {'A', '4'}, {'A', '5'}, {'A', '6'}, {'A', '7'},
    {'A', '8'}, {'A', '9'}, {'A', 'A'}, {'A', 'B'},
    {'A', 'C'}, {'A', 'D'}, {'A', 'E'}, {'A', 'F'},
    {'B', '0'}, {'B', '1'}, {'B', '2'}, {'B', '3'},
    {'B', '4'}, {'B', '5'}, {'B', '6'}, {'B', '7'},
    {'B', '8'}, {'B', '9'}, {'B', 'A'}, {'B', 'B'},
    {'B', 'C'}, {'B', 'D'}, {'B', 'E'}, {'B', 'F'},
    {'C', '0'}, {'C', '1'}, {'C', '2'}, {'C', '3'},
    {'C', '4'}, {'C', '5'}, {'C', '6'}, {'C', '7'},
    {'C', '8'}, {'C', '9'}, {'C', 'A'}, {'C', 'B'},
    {'C', 'C'}, {'C', 'D'}, {'C', 'E'}, {'C', 'F'},
    {'D', '0'}, {'D', '1'}, {'D', '2'}, {'D', '3'},
    {'D', '4'}, {'D', '5'}, {'D', '6'}, {'D', '7'},
    {'D', '8'}, {'D', '9'}, {'D', 'A'}, {'D', 'B'},
    {'D', 'C'}, {'D', 'D'}, {'D', 'E'}, {'D', 'F'},
    {'E', '0'}, {'E', '1'}, {'E', '2'}, {'E', '3'},
    {'E', '4'}, {'E', '5'}, {'E', '6'}, {'E', '7'},
    {'E', '8'}, {'E', '9'}, {'E', 'A'}, {'E', 'B'},
    {'E', 'C'}, {'E', 'D'}, {'E', 'E'}, {'E', 'F'},
    {'F', '0'}, {'F', '1'}, {'F', '2'}, {'F', '3'},
    {'F', '4'}, {'F', '5'}, {'F', '6'}, {'F', '7'},
    {'F', '8'}, {'F', '9'}, {'F', 'A'}, {'F', 'B'},
    {'F', 'C'}, {'F', 'D'}, {'F', 'E'}, {'F', 'F'}
};

static const char chrs_char[] = {
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    ' ', '!', '"', '#', '$', '%', '&', '\'',
    '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', ':', ';', '<', '=', '>', '?',
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', '{', '|', '}', '~', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.'
};

#endif // TRACE_STREAM


/* Assume sizeof(void*) is an integral power of 2. */
#define DEF_ALIGN_LEN(len) (((len) + sizeof(void*) - 1) & ~(sizeof(void*) - 1))


struct dsd_workarea_control {
    int32_t imc_count;
    char* achc_buf;
    uint32_t umc_size;
    struct dsd_workarea_control* adsc_next;
};

struct dsd_buf_from_app {
    const char* achc_buffer;
    uint32_t umc_length;
    struct dsd_buf_from_app* adsc_next;
    struct dsd_workarea_control* adsc_wac;
};

struct dsd_buf_from_network {
    const char* achc_buffer;
    uint32_t umc_length;
    struct dsd_buf_from_network* adsc_next;
    struct dsd_workarea_control* adsc_wac;
};

struct dsd_packet_from_network {
    struct dsd_buf_from_network* adsc_bfn;
    bool boc_push;
    struct dsd_packet_from_network* adsc_next;
    struct dsd_packet_from_network* adsc_prev;
    struct dsd_buf_from_network* adsc_cache;
    uint32_t umc_cache_offset;
    struct dsd_htcp_in_info dsc_hii;
    struct dsd_workarea_control* adsc_wac;
};

#define DEF_HII2PFN(hii) ((struct dsd_packet_from_network*) \
    ((char*)(hii) - offsetof(struct dsd_packet_from_network, dsc_hii)))

enum ied_ext_syn_state {
    ied_ess_init,
    ied_ess_rcvd_packet_from_netw,
    ied_ess_rcvd_syn_from_peer,
    ied_ess_done
};

struct dsd_sdh_tcp_ext {
    struct dsd_sdh_tcp_1* adsc_st1;
    struct dsd_buf_from_app* adsc_out_head;
    struct dsd_buf_from_app* adsc_out_tail;
    bool boc_established;
    enum ied_ext_syn_state iec_ess;
    char* achc_syn_packet;
    int inc_syn_length;
    bool boc_eof_sent;
    enum ied_sdh_tcp_state iec_sts;
    struct dsd_buf_from_app* adsc_out_cache;
    uint32_t umc_out_cache_offset;
    bool boc_timer;
    struct dsd_packet_from_network* adsc_in_tmp;
    struct dsd_tcp_data_contr_1** aadsc_to_app;
    struct dsd_tcp_data_contr_1** aadsc_to_network;
    struct dsd_workarea_control* adsc_wac;
    struct dsd_htcp_conn dsc_hc;
    bool boc_shutdown;
    bool boc_free_ext;
    bool boc_packet_pending;
    bool boc_tracing_init_seq_in;
    bool boc_tracing_init_seq_out;
    uint32_t umc_tracing_seq_in;
    uint32_t umc_tracing_seq_out;
};

const int ing_sdhtcp_ext_size = sizeof(struct dsd_sdh_tcp_ext);

#define DEF_HC2STE(hc) ((struct dsd_sdh_tcp_ext*) \
    ((char*)(hc) - offsetof(struct dsd_sdh_tcp_ext, dsc_hc)))

#ifdef TRACE_STREAM
static BOOL m_stream_trace(BOOL (*amp_aux)(void*, int, void*, int),
                           void* vpp_userfld,
                           struct dsd_wsp_trace_header* adsp_wth);
#endif // TRACE_STREAM

static BOOL m_aux_wsp_trace(BOOL (*amp_aux)(void*, int, void*, int),
                            void* vpp_userfld,
                            const char* achp_wtrt_id,
                            int inp_sno, int inp_trace_level,
                            struct dsd_gather_i_1* adsp_data, int inp_data_len,
                            int inp_short_len,
                            const char* achp_message, ...);

static bool m_trace_get_wa(struct dsd_sdh_tcp_1* adsp_st1,
                           char** aachp_begin, char** aachp_end);
static void m_interface_trace(struct dsd_sdh_tcp_1* adsp_st1,
                              bool bop_out,
                              bool* abop_init_seq, uint32_t* aump_seq,
                              bool* abop_init_ack, uint32_t* aump_ack);

static void m_sdhtcp_free(struct dsd_sdh_tcp_ext* adsp_ste);
static void m_sdhtcp_shutdown(struct dsd_sdh_tcp_ext* adsp_ste, int inp_ret);
static void m_sdhtcp_shutdown_rst(struct dsd_sdh_tcp_ext* adsp_ste,
                                  int inp_ret);
static void m_sdhtcp_console_helper(struct dsd_sdh_tcp_1* adsp_st1,
                                    int inp_line,
                                    const char* achp_format, va_list ap);
static void m_sdhtcp_console(struct dsd_sdh_tcp_1* adsp_st1,
                             int inp_line, const char* achp_format, ...);
static void m_shutdown_msg(struct dsd_sdh_tcp_ext* adsp_ste, int inp_ret,
                           int inp_line, const char* achp_format, ...);

bool m_wa_init(struct dsd_sdh_tcp_ext* adsp_ste,
               char* achp_wa, uint32_t ump_wa_len);
void* m_wa_malloc(struct dsd_sdh_tcp_ext* adsp_ste, uint32_t ump_size);
bool m_dec_wac(struct dsd_sdh_tcp_ext* adsp_ste,
               struct dsd_workarea_control* adsp_wac);
bool m_dec_wac_no_shutdown(struct dsd_sdh_tcp_ext* adsp_ste,
                           struct dsd_workarea_control* adsp_wac);

static void m_init(struct dsd_sdh_tcp_ext* adsp_ste, bool bop_free_ext);

static bool m_process_data(struct dsd_sdh_tcp_ext* adsp_ste,
                           const struct dsd_tcp_data_contr_1* adsp_tdc1);
static bool m_process_packets(struct dsd_sdh_tcp_ext* adsp_ste,
                              const struct dsd_tcp_data_contr_1* adsp_tdc1);
static bool m_check_in_data(struct dsd_sdh_tcp_ext* adsp_ste);
static bool m_check_out_packets(struct dsd_sdh_tcp_ext* adsp_ste);

static struct dsd_sdh_tcp_ext* m_start(struct dsd_sdh_tcp_1* adsp_st1);
static bool m_external_syn(struct dsd_sdh_tcp_ext* adsp_ste);


static bool m_stcb_out_get(struct dsd_htcp_conn* adsp_hc,
                           uint32_t ump_offset,
                           const char** aachp_buf, uint32_t* aump_len);

static bool m_stcb_out_packets(struct dsd_htcp_conn* adsp_hc);

static bool m_stcb_out_ack(struct dsd_htcp_conn* adsp_hc, uint32_t ump_len);

static bool m_stcb_in_get(struct dsd_htcp_conn* adsp_hc,
                          struct dsd_htcp_in_info* adsp_hii,
                          uint32_t ump_offset,
                          const char** aachp_buf, uint32_t* aump_len);

static bool m_stcb_in_rel(struct dsd_htcp_conn* adsp_hc,
                          struct dsd_htcp_in_info* adsp_hii);

static bool m_stcb_get_time(struct dsd_htcp_conn* adsp_hc, int64_t* ailp_time);
static bool m_stcb_set_timer(struct dsd_htcp_conn* adsp_hc,
                             uint32_t ump_delay_ms);
static bool m_stcb_rel_timer(struct dsd_htcp_conn* adsp_hc);

static bool m_stcb_noop(struct dsd_htcp_conn* adsp_hc);

static bool m_stcb_established(struct dsd_htcp_conn* adsp_hc);
static void m_stcb_closed(struct dsd_htcp_conn* adsp_hc,
                          enum ied_htcp_close iep_htcpc);

/* order should match that in hob-xs-htcp.h */
const struct dsd_htcp_callbacks dss_hcb = {
    m_stcb_out_get,
    m_stcb_out_packets,
    m_stcb_out_ack,
    m_stcb_in_get,
    m_stcb_noop,
    m_stcb_in_rel,
    m_stcb_get_time,
    m_stcb_set_timer,
    m_stcb_rel_timer,
    m_stcb_noop,
    m_stcb_noop,
    m_stcb_established,
    m_stcb_closed
};

#ifdef TRACE_STREAM

static BOOL m_stream_trace(BOOL (*amp_aux)(void*, int, void*, int),
                           void* vpp_userfld,
                           struct dsd_wsp_trace_header* adsp_wth)
{
    BOOL bol_ret;
    int64_t ill_time;
    struct dsd_timer1_ret dsl_tr;
    struct dsd_wsp_trace_record* adsl_wtr;
    int inl_offset_hex;
    int inl_offset_char;
    int inl_cur;
    unsigned char ucl_c;
    char chrl_id[9];
    char chrl_text_buffer[78];
    bool bol_text_init = false;
    int inl_len;
    int inl_l;
    bool bol_cont;

    if ((TRACE_STREAM) == NULL || !*(TRACE_STREAM))
        return FALSE;

    bol_ret = amp_aux(vpp_userfld, DEF_AUX_GET_T_MSEC,
                      &ill_time, sizeof(ill_time));
    if (!bol_ret) {
        bol_ret = amp_aux(vpp_userfld, DEF_AUX_TIMER1_QUERY,
                          &dsl_tr, sizeof(dsl_tr));
        ill_time = dsl_tr.ilc_epoch;
    }
    if (!bol_ret) {
        ill_time = 0;
    }

    memcpy(chrl_id, &adsp_wth->chrc_wtrt_id, 8);
    chrl_id[8] = '\0';

    *(TRACE_STREAM) << "+++ SDH-TCP " << chrl_id
                    << " sno=" << adsp_wth->imc_wtrh_sno
                    << " userfld=" << vpp_userfld
                    << " time=" << ill_time << "ms\n";

    bol_cont = false;
    for (adsl_wtr = adsp_wth->adsc_wtrh_chain;
         adsl_wtr != NULL;
         adsl_wtr = adsl_wtr->adsc_next) {

        if (adsl_wtr->iec_wtrt == ied_wtrt_text) {
            (TRACE_STREAM)->write(adsl_wtr->achc_content, adsl_wtr->imc_length);

            bol_cont = adsl_wtr->boc_more &&
                adsl_wtr->adsc_next != NULL &&
                adsl_wtr->adsc_next->iec_wtrt == adsl_wtr->iec_wtrt;

            if (!bol_cont) {
                *(TRACE_STREAM) << "\n";
            }

            continue;
        }

        if (!bol_cont) {
            if (!bol_text_init) {
                chrl_text_buffer[4] = ' ';
                chrl_text_buffer[5] = ' ';
                chrl_text_buffer[8] = ' ';
                chrl_text_buffer[11] = ' ';
                chrl_text_buffer[14] = ' ';
                chrl_text_buffer[17] = ' ';
                chrl_text_buffer[18] = ' ';
                chrl_text_buffer[21] = ' ';
                chrl_text_buffer[24] = ' ';
                chrl_text_buffer[27] = ' ';
                chrl_text_buffer[30] = ' ';
                chrl_text_buffer[31] = ' ';
                chrl_text_buffer[34] = ' ';
                chrl_text_buffer[37] = ' ';
                chrl_text_buffer[40] = ' ';
                chrl_text_buffer[43] = ' ';
                chrl_text_buffer[44] = ' ';
                chrl_text_buffer[47] = ' ';
                chrl_text_buffer[50] = ' ';
                chrl_text_buffer[53] = ' ';
                chrl_text_buffer[56] = ' ';
                chrl_text_buffer[57] = ' ';
                chrl_text_buffer[58] = ' ';
                chrl_text_buffer[59] = '*';
                chrl_text_buffer[76] = '*';
                chrl_text_buffer[77] = '\0';
                bol_text_init = true;
            }

            chrl_text_buffer[0] = '0';
            chrl_text_buffer[1] = '0';
            chrl_text_buffer[2] = '0';
            chrl_text_buffer[3] = '0';

            inl_offset_hex = 6;
            inl_offset_char = 60;
            inl_len = 0;
        }

        inl_cur = 0;
        while (inl_cur < adsl_wtr->imc_length) {

            if (inl_offset_char == 76) {
                *(TRACE_STREAM) << chrl_text_buffer << "\n";
                inl_offset_hex = 6;
                inl_offset_char = 60;

                chrl_text_buffer[0] = chrs_char_hex[inl_len / 0x100 & 0xff][0];
                chrl_text_buffer[1] = chrs_char_hex[inl_len / 0x100 & 0xff][1];
                chrl_text_buffer[2] = chrs_char_hex[inl_len & 0xff][0];
                chrl_text_buffer[3] = chrs_char_hex[inl_len & 0xff][1];
            }

            inl_l = adsl_wtr->imc_length - inl_cur;
            if (inl_l > 76 - inl_offset_char)
                inl_l = 76 - inl_offset_char;

            inl_len += inl_l;

            while (inl_l-- > 0) {
                ucl_c = (unsigned char)adsl_wtr->achc_content[inl_cur++];
                chrl_text_buffer[inl_offset_hex++] = chrs_char_hex[ucl_c][0];
                chrl_text_buffer[inl_offset_hex++] = chrs_char_hex[ucl_c][1];
                ++inl_offset_hex;
                if (inl_offset_hex % 13 == 5)
                    ++inl_offset_hex;
                chrl_text_buffer[inl_offset_char++] = chrs_char[ucl_c];
            }
        }

        bol_cont = adsl_wtr->boc_more &&
            adsl_wtr->adsc_next != NULL &&
            adsl_wtr->adsc_next->iec_wtrt == adsl_wtr->iec_wtrt;

        if (!bol_cont) {
            if (inl_offset_char != 60) {
                while (inl_offset_hex < 56) {
                    chrl_text_buffer[inl_offset_hex++] = ' ';
                }
                while (inl_offset_char < 76) {
                    chrl_text_buffer[inl_offset_char++] = ' ';
                }
                *(TRACE_STREAM) << chrl_text_buffer << "\n";
            }
        }
    }

    (TRACE_STREAM)->flush();

    return TRUE;
}

#endif // TRACE_STREAM

static BOOL m_aux_wsp_trace(BOOL (*amp_aux)(void*, int, void*, int),
                            void* vpp_userfld,
                            const char* achp_wtrt_id,
                            int inp_sno, int inp_trace_level,
                            struct dsd_gather_i_1* adsp_data, int inp_data_len,
                            int inp_short_len,
                            const char* achp_message, ...)
{
    const int inl_trace_record_size = 16;
    struct dsd_wsp_trace_header dsl_wth;
    struct dsd_wsp_trace_record dsrl_wtr[inl_trace_record_size];
    struct dsd_wsp_trace_record* adsl_wtr = dsrl_wtr;
    struct dsd_wsp_trace_record** aadsl_wtr;
    int inl_wtr_space = inl_trace_record_size;
    char chrl_text_buffer[1024];
    struct dsd_aux_get_workarea dsl_agw;
    int inl_len;
    int inl_l;
    va_list ap;
    BOOL bol_ret = TRUE;

    if (adsp_data == NULL || inp_data_len < 0) {
        inp_data_len = 0;
    } else if ((inp_trace_level & HL_AUX_WT_DATA2) == 0) {
        if ((inp_trace_level & HL_AUX_WT_DATA1) == 0 ||
             inp_short_len <= 0) {

            inp_data_len = 0;
        } else if (inp_data_len > inp_short_len) {
            inp_data_len = inp_short_len;
        }
    }

    if (inp_data_len == 0 && achp_message == NULL)
        return bol_ret;

    memset(&dsl_wth, 0, sizeof(dsl_wth));
    memcpy(&dsl_wth.chrc_wtrt_id, achp_wtrt_id, sizeof(dsl_wth.chrc_wtrt_id));
    dsl_wth.imc_wtrh_sno = inp_sno;
    aadsl_wtr = &dsl_wth.adsc_wtrh_chain;

    if (achp_message != NULL) {
        va_start(ap, achp_message);
        inl_len = m_vsnprintf(chrl_text_buffer, sizeof(chrl_text_buffer),
                              achp_message, ap);
        va_end(ap);

        if (inl_len > 0) {
            if (inl_len >= sizeof(chrl_text_buffer)) {
                inl_len = sizeof(chrl_text_buffer) - 1;
                chrl_text_buffer[inl_len - 3] = '.';
                chrl_text_buffer[inl_len - 2] = '.';
                chrl_text_buffer[inl_len - 1] = '.';
            }

            *aadsl_wtr = adsl_wtr;
            aadsl_wtr = &adsl_wtr->adsc_next;
            memset(adsl_wtr, 0, sizeof(*adsl_wtr));
            adsl_wtr->iec_wtrt = ied_wtrt_text;
            adsl_wtr->achc_content = chrl_text_buffer;
            adsl_wtr->imc_length = inl_len;
            adsl_wtr->boc_more = FALSE;

            ++adsl_wtr;
            --inl_wtr_space;
        }
    }

    inl_len = inp_data_len;
    while (inl_len > 0) {
        while (adsp_data != NULL &&
               adsp_data->achc_ginp_cur >= adsp_data->achc_ginp_end) {

            adsp_data = adsp_data->adsc_next;
        }
        if (adsp_data == NULL)
            break;

        if (inl_wtr_space <= 0) {
            bol_ret = amp_aux(vpp_userfld, DEF_AUX_GET_WORKAREA,
                              &dsl_agw, sizeof(dsl_agw));
            if (!bol_ret)
                break;
            adsl_wtr = (struct dsd_wsp_trace_record*)dsl_agw.achc_work_area;
            inl_wtr_space = dsl_agw.imc_len_work_area / sizeof(*adsl_wtr);
            if (inl_wtr_space == 0) {
                bol_ret = FALSE;
                break;
            }
        }

        inl_l = adsp_data->achc_ginp_end - adsp_data->achc_ginp_cur;
        if (inl_l > inl_len)
            inl_l = inl_len;

        *aadsl_wtr = adsl_wtr;
        aadsl_wtr = &adsl_wtr->adsc_next;
        memset(adsl_wtr, 0, sizeof(*adsl_wtr));
        adsl_wtr->iec_wtrt = ied_wtrt_data;
        adsl_wtr->achc_content = adsp_data->achc_ginp_cur;
        adsl_wtr->imc_length = inl_l;
        adsl_wtr->boc_more = TRUE;

        ++adsl_wtr;
        --inl_wtr_space;

        adsp_data = adsp_data->adsc_next;
        inl_len -= inl_l;
    }

    if (adsl_wtr == dsrl_wtr) // nothing written
        return bol_ret;

    *aadsl_wtr = NULL;
    --adsl_wtr;
    adsl_wtr->boc_more = FALSE;

    // in case of failure allocating workarea, send to WSP trace anyway
#ifndef TRACE_STREAM
    bol_ret = amp_aux(vpp_userfld, DEF_AUX_WSP_TRACE, &dsl_wth, 0) && bol_ret;
#else
    bol_ret = m_stream_trace(amp_aux, vpp_userfld, &dsl_wth) && bol_ret;
#endif

    return bol_ret;
}

static bool m_trace_get_wa(struct dsd_sdh_tcp_1* adsp_st1,
                           char** aachp_begin, char** aachp_end)
{
    BOOL bol_ret;
    struct dsd_aux_get_workarea dsl_agw;

    bol_ret = adsp_st1->amc_aux(adsp_st1->vpc_userfld, DEF_AUX_GET_WORKAREA,
                                &dsl_agw, sizeof(dsl_agw));
    if (!bol_ret)
        return false;

    *aachp_begin = dsl_agw.achc_work_area;
    *aachp_end = dsl_agw.achc_work_area + dsl_agw.imc_len_work_area;
    return true;
}

static void m_interface_trace(struct dsd_sdh_tcp_1* adsp_st1,
                              bool bop_out,
                              bool* abop_init_seq, uint32_t* aump_seq,
                              bool* abop_init_ack, uint32_t* aump_ack)
{
    struct dsd_wsp_trace_header dsl_wth;
    struct dsd_wsp_trace_record dsl_wtr;
    struct dsd_wsp_trace_record* adsl_wtr;
    char chrl_buffer[2048];
    char* achl_begin;
    char* achl_end;
    int inl_len;
    int inl_l;

    const char* achl_action;
    const char* achl_state;
    char* achl_text;
    int inl_index;
    bool bol_tcp;
    struct dsd_tcp_data_contr_1* adsl_tdc1;
    struct dsd_gather_i_1* adsl_gai1;
    char* achl_head;
    char chrl_hbuf[20];

    achl_begin = chrl_buffer;
    achl_end = chrl_buffer + sizeof(chrl_buffer);

    dsl_wth.imc_wtrh_sno = adsp_st1->imc_sno;

    if (!bop_out) {
        memcpy(dsl_wth.chrc_wtrt_id, "SSDTC000", 8);

        switch (adsp_st1->imc_func) {
        case DEF_IFUNC_START:
            achl_action = "DEF_IFUNC_START";
            break;

        case DEF_IFUNC_CLOSE:
            achl_action = "DEF_IFUNC_CLOSE";
            break;

        case DEF_IFUNC_PREP_CLOSE:
            achl_action = "DEF_IFUNC_PREP_CLOSE";
            break;

        case DEF_IFUNC_FROMSERVER:
            achl_action = "DEF_IFUNC_FROMSERVER";
            break;

        case DEF_IFUNC_TOSERVER:
            achl_action = "DEF_IFUNC_TOSERVER";
            break;

        default:
            inl_len = m_snprintf(achl_begin, achl_end - achl_begin,
                                 "%d", (int)adsp_st1->imc_func);
            if (achl_begin + inl_len + 2 > achl_end) {
                // really?
                inl_len = achl_end - achl_begin - 2;
            }
            achl_action = achl_begin;
            achl_begin += inl_len + 1;
        }

        inl_len = m_snprintf(achl_begin, achl_end - achl_begin,
                             "SDH-TCP entering "
                             "ext=%p %s flags%s%s%s%s%s%s%s wa=%p(%d)",
                             adsp_st1->ac_ext, achl_action,
                             (adsp_st1->boc_timer_running ? " TR" : ""),
                             (adsp_st1->boc_is_client ? " IC" : ""),
                             (adsp_st1->boc_stop_receiving ? " SR" : ""),
                             (adsp_st1->boc_send_netw_blocked ? " NB" : ""),
                             (adsp_st1->iec_stfc == ied_stfc_tcp_tunnel_1 ?
                              " TT" : ""),
                             (adsp_st1->boc_syn_extern ? " SE" : ""),
                             (adsp_st1->boc_eof_client ? " EC" : ""),
                             adsp_st1->achc_work_area,
                             (int)adsp_st1->imc_len_work_area);
        if (achl_begin + inl_len + 1 > achl_end) {
            // really?
            inl_len = achl_end - achl_begin - 1;
        }
        achl_text = achl_begin;
        achl_begin += inl_len + 1;
    } else {
        memcpy(dsl_wth.chrc_wtrt_id, "SSDTC001", 8);

        switch (adsp_st1->imc_return) {
        case DEF_IRET_NORMAL:
            achl_action = "DEF_IRET_NORMAL";
            break;

        case DEF_IRET_END:
            achl_action = "DEF_IRET_END";
            break;

        case DEF_IRET_ERRAU:
            achl_action = "DEF_IRET_ERRAU";
            break;

        case DEF_IRET_INVDA:
            achl_action = "DEF_IRET_INVDA";
            break;

        case DEF_IRET_INT_ERROR:
            achl_action = "DEF_IRET_INT_ERROR";
            break;

        default:
            inl_len = m_snprintf(achl_begin, achl_end - achl_begin,
                                 "%d", (int)adsp_st1->imc_return);
            if (achl_begin + inl_len + 3 > achl_end) {
                // really?
                inl_len = achl_end - achl_begin - 3;
            }
            achl_action = achl_begin;
            achl_begin += inl_len + 1;
        }

        switch (adsp_st1->iec_sts) {
        case ied_sts_normal:
            achl_state = "ied_sts_normal";
            break;

        case ied_sts_recv_fin:
            achl_state = "ied_sts_recv_fin";
            break;

        case ied_sts_recv_rst:
            achl_state = "ied_sts_recv_rst";
            break;

        case ied_sts_timeout:
            achl_state = "ied_sts_timeout";
            break;

        default:
            inl_len = m_snprintf(achl_begin, achl_end - achl_begin,
                                 "%d", (int)adsp_st1->iec_sts);
            if (achl_begin + inl_len + 2 > achl_end) {
                // really?
                inl_len = achl_end - achl_begin - 2;
            }
            achl_action = achl_begin;
            achl_begin += inl_len + 1;
        }


        inl_len = m_snprintf(achl_begin, achl_end - achl_begin,
                             "SDH-TCP leaving "
                             "%s %s flags%s%s qsent=%d qbuf=%d",
                             achl_action, achl_state,
                             (adsp_st1->boc_notify_send_netw_possible ?
                              " NP" : ""),
                             (adsp_st1->boc_connection_established ?
                              " CE" : ""),
                             (int)adsp_st1->imc_queue_sent,
                             (int)adsp_st1->imc_queue_buffer);
        if (achl_begin + inl_len + 1 > achl_end) {
            // really?
            inl_len = achl_end - achl_begin - 1;
        }
        achl_text = achl_begin;
        achl_begin += inl_len + 1;
    }

    dsl_wth.adsc_wtrh_chain = &dsl_wtr;
    adsl_wtr = &dsl_wtr;

    adsl_wtr->iec_wtrt = ied_wtrt_text;
    adsl_wtr->achc_content = achl_text;
    adsl_wtr->imc_length = inl_len;
    adsl_wtr->boc_more = FALSE;

    if (!bop_out) {
        adsl_tdc1 = adsp_st1->adsc_tdc1_in;
        achl_action = "in";
        bol_tcp = adsp_st1->imc_func == DEF_IFUNC_FROMSERVER;
        inl_index = 0;
    } else {
        adsl_tdc1 = adsp_st1->adsc_tdc1_out_to_client;
        achl_action = "out_to_client";
        bol_tcp = false;
        inl_index = 0;
    }

    for (; ; adsl_tdc1 = adsl_tdc1->adsc_next) {
        if (adsl_tdc1 == NULL) {
            if (!bop_out)
                break;
            if (bol_tcp)
                break;
            adsl_tdc1 = adsp_st1->adsc_tdc1_out_to_server;
            if (adsl_tdc1 == NULL)
                break;
            achl_action = "out_to_server";
            bol_tcp = true;
            inl_index = 0;
        }

        ++inl_index;

        // we need space to write description
        if (achl_begin + 128 >= achl_end ||
            !m_trace_get_wa(adsp_st1, &achl_begin, &achl_end) ||
            achl_begin + 128 >= achl_end) {

                break;
        }

        inl_len = m_snprintf(achl_begin, achl_end - achl_begin,
                             "%s %d len=%d",
                             achl_action, inl_index,
                             (int)adsl_tdc1->imc_len_data);
        if (achl_begin + inl_len >= achl_end) {
            // really?
            break;
        }
        achl_text = achl_begin;
        achl_begin += inl_len + 1;

        if (bol_tcp) {
            adsl_gai1 = adsl_tdc1->adsc_gai1;
            if (adsl_tdc1->imc_len_data < 20 || adsl_gai1 == NULL) {
                achl_head = NULL;
            } else if (adsl_gai1->achc_ginp_cur + 20 <=
                       adsl_gai1->achc_ginp_end) {
                achl_head = adsl_gai1->achc_ginp_cur;
            } else {
                achl_head = chrl_hbuf;
                inl_len = 0;
                for (; ; ) {
                    inl_l = adsl_gai1->achc_ginp_end - adsl_gai1->achc_ginp_cur;
                    if (inl_len + inl_l > 20)
                        inl_l = 20 - inl_len;
                    memcpy(chrl_hbuf + inl_len,
                           adsl_gai1->achc_ginp_cur, inl_l);
                    inl_len += inl_l;
                    if (inl_len == 20)
                        break;

                    adsl_gai1 = adsl_gai1->adsc_next;
                    if (adsl_gai1 == NULL) {
                        achl_head = NULL;
                        break;
                    }
                }
            }

            if (achl_head != NULL) {
                // remove trailing '\0'
                --achl_begin;

                if (achl_begin + 8 >= achl_end) {
                    // really?
                    break;
                }
                *achl_begin++ = ' ';
                if (m_get_tcp_fin(achl_head))
                    *achl_begin++ = 'F';
                if (m_get_tcp_syn(achl_head))
                    *achl_begin++ = 'S';
                if (m_get_tcp_rst(achl_head))
                    *achl_begin++ = 'R';
                if (m_get_tcp_psh(achl_head))
                    *achl_begin++ = 'P';
                if (m_get_tcp_ack(achl_head))
                    *achl_begin++ = 'A';
                if (m_get_tcp_urg(achl_head))
                    *achl_begin++ = 'U';
                if (*(achl_begin - 1) != ' ')
                    *achl_begin++ = ' ';

                if (abop_init_seq != NULL && aump_seq != NULL &&
                    abop_init_ack != NULL && aump_ack != NULL) {
                    if (!*abop_init_seq) {
                        *abop_init_seq = true;
                        *aump_seq = m_get_tcp_seqn(achl_head);
                    }
                    if (m_get_tcp_ack(achl_head)) {
                        if (!*abop_init_ack) {
                            *abop_init_ack = true;
                            *aump_ack = m_get_tcp_ackn(achl_head);
                        }
                        inl_len =
                            m_snprintf(achl_begin, achl_end - achl_begin,
                                       "SEQ:%08X(rel=%u) "
                                       "ACK:%08X(rel=%u) WIN=%u",
                                       (unsigned)m_get_tcp_seqn(achl_head),
                                       (unsigned)(m_get_tcp_seqn(achl_head) -
                                                  *aump_seq),
                                       (unsigned)m_get_tcp_ackn(achl_head),
                                       (unsigned)(m_get_tcp_ackn(achl_head) -
                                                  *aump_ack),
                                       (unsigned)m_get_tcp_window(achl_head));
                    } else {
                        inl_len =
                            m_snprintf(achl_begin, achl_end - achl_begin,
                                       "SEQ:%08X(rel=%u)",
                                       (unsigned)m_get_tcp_seqn(achl_head),
                                       (unsigned)(m_get_tcp_seqn(achl_head) -
                                                  *aump_seq));
                    }
                } else {
                    if (m_get_tcp_ack(achl_head)) {
                        inl_len =
                            m_snprintf(achl_begin, achl_end - achl_begin,
                                       "SEQ:%08X ACK:%08X WIN=%u",
                                       (unsigned)m_get_tcp_seqn(achl_head),
                                       (unsigned)m_get_tcp_ackn(achl_head),
                                       (unsigned)m_get_tcp_window(achl_head));
                    } else {
                        inl_len =
                            m_snprintf(achl_begin, achl_end - achl_begin,
                                       "SEQ:%u",
                                       (unsigned)m_get_tcp_seqn(achl_head));
                    }
                }

                if (achl_begin + inl_len >= achl_end) {
                    // really?
                    break;
                }
                achl_begin += inl_len + 1;
            }
        } else { // !bol_tcp
            // remove trailing '\0'
            --achl_begin;

            if (achl_begin + 8 >= achl_end) {
                // really?
                break;
            }
            *achl_begin++ = ' ';
            if (m_get_tcp_flags_fin(adsl_tdc1->umc_flags))
                *achl_begin++ = 'F';
            if (m_get_tcp_flags_syn(adsl_tdc1->umc_flags))
                *achl_begin++ = 'S';
            if (m_get_tcp_flags_rst(adsl_tdc1->umc_flags))
                *achl_begin++ = 'R';
            if (m_get_tcp_flags_psh(adsl_tdc1->umc_flags))
                *achl_begin++ = 'P';
            if (m_get_tcp_flags_ack(adsl_tdc1->umc_flags))
                *achl_begin++ = 'A';
            if (m_get_tcp_flags_urg(adsl_tdc1->umc_flags))
                *achl_begin++ = 'U';
            if (*(achl_begin - 1) == ' ')
                --achl_begin;
            *achl_begin++ = '\0';
        }

        inl_len = achl_begin - 1 - achl_text;

        if (achl_begin + sizeof(struct dsd_wsp_trace_record) > achl_end) {
            if (!m_trace_get_wa(adsp_st1, &achl_begin, &achl_end))
                break;
            if (achl_begin + sizeof(struct dsd_wsp_trace_record) > achl_end)
                break;
        }

        adsl_wtr->adsc_next = (struct dsd_wsp_trace_record*)achl_end - 1;
        adsl_wtr = adsl_wtr->adsc_next;
        achl_end = (char*)adsl_wtr;

        adsl_wtr->iec_wtrt = ied_wtrt_text;
        adsl_wtr->achc_content = achl_text;
        adsl_wtr->imc_length = inl_len;
        adsl_wtr->boc_more = FALSE;

        inl_len = adsl_tdc1->imc_len_data;

        if (inl_len <= 0 || (adsp_st1->imc_trace_level &
                             (HL_AUX_WT_DATA1 | HL_AUX_WT_DATA2)) == 0) {

            continue;
        }

        if ((adsp_st1->imc_trace_level & HL_AUX_WT_DATA2) == 0 &&
            inl_len > 32) {

            inl_len = 32;
        }

        adsl_gai1 = adsl_tdc1->adsc_gai1;
        while (inl_len > 0) {
            while (adsl_gai1 != NULL &&
                   adsl_gai1->achc_ginp_cur >= adsl_gai1->achc_ginp_end) {

                adsl_gai1 = adsl_gai1->adsc_next;
            }
            if (adsl_gai1 == NULL)
                break;

            inl_l = adsl_gai1->achc_ginp_end - adsl_gai1->achc_ginp_cur;
            if (inl_l > inl_len)
                inl_l = inl_len;

            if (achl_begin + sizeof(struct dsd_wsp_trace_record) > achl_end) {
                if (!m_trace_get_wa(adsp_st1, &achl_begin, &achl_end) ||
                    achl_begin + sizeof(struct dsd_wsp_trace_record) >
                    achl_end) {

                    inl_len = -1;
                    break;
                }
            }

            adsl_wtr->adsc_next = (struct dsd_wsp_trace_record*)achl_end - 1;
            adsl_wtr = adsl_wtr->adsc_next;
            achl_end = (char*)adsl_wtr;

            adsl_wtr->iec_wtrt = ied_wtrt_data;
            adsl_wtr->achc_content = adsl_gai1->achc_ginp_cur;
            adsl_wtr->imc_length = inl_l;
            adsl_wtr->boc_more = TRUE;

            adsl_gai1 = adsl_gai1->adsc_next;
            inl_len -= inl_l;
        }
        adsl_wtr->boc_more = FALSE;
        if (inl_len < 0)
            break;
    }

    adsl_wtr->adsc_next = NULL;

#ifndef TRACE_STREAM
    adsp_st1->amc_aux(adsp_st1->vpc_userfld, DEF_AUX_WSP_TRACE, &dsl_wth, 0);
#else
    m_stream_trace(adsp_st1->amc_aux, adsp_st1->vpc_userfld, &dsl_wth);
#endif
}

void m_sdhtcp01(struct dsd_sdh_tcp_1* adsp_st1)
{
    struct dsd_sdh_tcp_ext* adsl_ste;
    struct dsd_htcp_status dsl_hs;
    BOOL bol_ret;
    struct dsd_buf_from_network* adsl_bfn;
    struct dsd_packet_from_network* adsl_pfn;
    struct dsd_tcp_data_contr_1* adsl_start_syn;
    bool* abol_trace_init_seq;
    uint32_t* auml_trace_seq;
    bool* abol_trace_init_ack;
    uint32_t* auml_trace_ack;

#if defined TRY_FORCE_WSP_TRACE_DATA_2
    adsp_st1->imc_trace_level = HL_AUX_WT_ALL | HL_AUX_WT_DATA2;
#elif defined TRY_FORCE_WSP_TRACE_DATA_1
    adsp_st1->imc_trace_level = HL_AUX_WT_ALL | HL_AUX_WT_DATA1;
#elif defined TRY_FORCE_WSP_TRACE_NO_DATA
    adsp_st1->imc_trace_level = HL_AUX_WT_ALL;
#elif defined TRY_FORCE_WSP_NO_TRACE
    adsp_st1->imc_trace_level = 0;
#endif

    if ((adsp_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
        if (adsp_st1->imc_func == DEF_IFUNC_FROMSERVER &&
            adsp_st1->ac_ext != NULL) {

            adsl_ste = (struct dsd_sdh_tcp_ext*)adsp_st1->ac_ext;
            abol_trace_init_seq = &adsl_ste->boc_tracing_init_seq_in;
            auml_trace_seq = &adsl_ste->umc_tracing_seq_in;
            abol_trace_init_ack = &adsl_ste->boc_tracing_init_seq_out;
            auml_trace_ack = &adsl_ste->umc_tracing_seq_out;
        } else {
            abol_trace_init_seq = NULL;
            auml_trace_seq = NULL;
            abol_trace_init_ack = NULL;
            auml_trace_ack = NULL;
        }

        m_interface_trace(adsp_st1, false,
                          abol_trace_init_seq, auml_trace_seq,
                          abol_trace_init_ack, auml_trace_ack);
    }

    adsp_st1->imc_return = DEF_IRET_NORMAL;
    adsp_st1->adsc_tdc1_out_to_client = NULL;
    adsp_st1->adsc_tdc1_out_to_server = NULL;
    adsp_st1->boc_notify_send_netw_possible = FALSE;

    adsl_start_syn = NULL;

    if (adsp_st1->imc_func == DEF_IFUNC_START) {
        if (adsp_st1->boc_syn_extern &&
            adsp_st1->boc_is_client &&
            adsp_st1->adsc_tdc1_in != NULL &&
            adsp_st1->adsc_tdc1_in->adsc_next == NULL &&
            adsp_st1->adsc_tdc1_in->imc_len_data == 0) {

            // We can receive SYN flag from peer during DEF_IFUNC_START
            // when using external SYN.

            adsl_start_syn = adsp_st1->adsc_tdc1_in;
            adsp_st1->adsc_tdc1_in = NULL;
        }

        adsl_ste = m_start(adsp_st1);
    } else {
        adsl_ste = (struct dsd_sdh_tcp_ext*)adsp_st1->ac_ext;

        if (adsl_ste == NULL) {
            m_sdhtcp_console(adsp_st1, __LINE__,
                             "SDH-TCP found ac_ext == NULL.");
            adsp_st1->imc_return = DEF_IRET_INVDA;
        } else {
            adsl_ste->adsc_st1 = adsp_st1;

            adsl_ste->adsc_wac = NULL;
            m_wa_init(adsl_ste,
                      adsp_st1->achc_work_area,
                      adsp_st1->imc_len_work_area);
        }
    }

    if (adsl_start_syn != NULL) {
        adsp_st1->imc_func = DEF_IFUNC_TOSERVER;
        adsp_st1->adsc_tdc1_in = adsl_start_syn;
    }

    if (adsp_st1->imc_func == DEF_IFUNC_START || adsl_ste == NULL) {

        // do nothing

    } else if (adsp_st1->boc_syn_extern &&
               adsl_ste->iec_ess != ied_ess_done) {

        m_external_syn(adsl_ste);

    } else {

        switch (adsp_st1->imc_func) {

        case DEF_IFUNC_PREP_CLOSE:
            m_sdhtcp_shutdown_rst(adsl_ste, DEF_IRET_END);
            break;

        case DEF_IFUNC_CLOSE:
            m_sdhtcp_shutdown(adsl_ste, DEF_IRET_END);
            break;

        case DEF_IFUNC_FROMSERVER:
        case DEF_IFUNC_TOSERVER:

            if (adsp_st1->imc_func == DEF_IFUNC_FROMSERVER) {
                if (!m_process_packets(adsl_ste, adsp_st1->adsc_tdc1_in))
                    break;
            } else { // DEF_IFUNC_TOSERVER
                if (!m_process_data(adsl_ste, adsp_st1->adsc_tdc1_in))
                    break;
            }

            if (!m_check_in_data(adsl_ste))
                break;

            if (!adsl_ste->boc_eof_sent &&
                adsp_st1->boc_eof_client) {

                adsl_ste->boc_eof_sent = true;
                m_htcp_out_send(&adsl_ste->dsc_hc, 0, false, true);
                if (adsl_ste->boc_shutdown)
                    break;
            }

            if (adsl_ste->boc_timer &&
                !adsp_st1->boc_timer_running) {

                adsl_ste->boc_timer = false;
                m_htcp_timeout(&adsl_ste->dsc_hc);
                if (adsl_ste->boc_shutdown)
                    break;
            }

            m_check_out_packets(adsl_ste);
            // no need to check adsl_ste->boc_shutdown - breaking anyway

            break;

        default:
            m_shutdown_msg(adsl_ste, DEF_IRET_END, __LINE__, "%s%d"
                           "m_sdhtcp01() unknown imc_func code: ",
                           adsp_st1->imc_func);
        }

    }

    // processing done, now clean up

    if (adsl_ste != NULL) {

        // mark workareas for input packets still in use
        while (adsl_ste->adsc_in_tmp != NULL) {
            ++adsl_ste->adsc_in_tmp->adsc_wac->imc_count;
            for (adsl_bfn = adsl_ste->adsc_in_tmp->adsc_bfn;
                 adsl_bfn != NULL;
                 adsl_bfn = adsl_bfn->adsc_next) {

                ++adsl_bfn->adsc_wac->imc_count;
                bol_ret = adsp_st1->amc_aux(adsp_st1->vpc_userfld,
                                            DEF_AUX_MARK_WORKAREA_INC,
                                            (void*)adsl_bfn->achc_buffer, 0);
                if ((adsp_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                    m_aux_wsp_trace(adsp_st1->amc_aux,
                                    adsp_st1->vpc_userfld,
                                    "SSDTC012",
                                    adsp_st1->imc_sno,
                                    adsp_st1->imc_trace_level,
                                    NULL, 0, 0,
                                    "SDH-TCP MARK_WORKAREA_INC %p%s",
                                    adsl_bfn->achc_buffer,
                                    (bol_ret ? "" : " failed"));
                }
                if (!bol_ret) {
                    m_shutdown_msg(adsl_ste, DEF_IRET_ERRAU, __LINE__, "%s%p%s",
                                   "DEF_AUX_MARK_WORKAREA_INC for ",
                                   adsl_bfn->achc_buffer, " failed");
                    break;
                }
            }

            adsl_pfn = adsl_ste->adsc_in_tmp;
            adsl_ste->adsc_in_tmp = adsl_pfn->adsc_next;
            adsl_pfn->adsc_next = adsl_pfn; // indicate no longer in list
        }

        if (!adsl_ste->boc_shutdown) {
            m_htcp_status(&adsl_ste->dsc_hc, &dsl_hs);
            // adsl_ste->boc_shutdown set if error
        }
        if (!adsl_ste->boc_shutdown) {
            adsp_st1->imc_queue_sent = dsl_hs.umc_out_in_flight;
            adsp_st1->imc_queue_buffer =
                dsl_hs.umc_out_queue_len - dsl_hs.umc_out_in_flight;
        }

        adsp_st1->boc_connection_established = adsl_ste->boc_established;
        adsp_st1->iec_sts = adsl_ste->iec_sts;

        while (adsl_ste->adsc_wac) {
            if (adsl_ste->adsc_wac->imc_count <= 0) {
                m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR, __LINE__, "%s",
                               "m_sdhtcp01() error in workarea management.");
            }

            if (--adsl_ste->adsc_wac->imc_count > 0) {
                bol_ret = adsp_st1->amc_aux(adsp_st1->vpc_userfld,
                                            DEF_AUX_MARK_WORKAREA_INC,
                                            adsl_ste->adsc_wac, 0);
                if (!bol_ret) {
                    m_shutdown_msg(adsl_ste, DEF_IRET_ERRAU, __LINE__, "%s"
                                   "m_sdhtcp01() cannot mark workarea.");
                }

                if ((adsp_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                    m_aux_wsp_trace(adsp_st1->amc_aux,
                                    adsp_st1->vpc_userfld,
                                    "SSDTC010",
                                    adsp_st1->imc_sno,
                                    adsp_st1->imc_trace_level,
                                    NULL, 0, 0,
                                    "SDH-TCP MARK_WORKAREA_INC %p%s",
                                    adsl_ste->adsc_wac,
                                    (bol_ret ? "" : " failed"));
                }
            }
            adsl_ste->adsc_wac = adsl_ste->adsc_wac->adsc_next;
        }

        if (adsl_ste->boc_shutdown) {
            adsp_st1->imc_queue_sent = 0;
            adsp_st1->imc_queue_buffer = 0;
            m_sdhtcp_free(adsl_ste);
            adsl_ste = NULL;
        }
    }

    if ((adsp_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
        if (adsl_ste != NULL) {
            abol_trace_init_seq = &adsl_ste->boc_tracing_init_seq_out;
            auml_trace_seq = &adsl_ste->umc_tracing_seq_out;
            abol_trace_init_ack = &adsl_ste->boc_tracing_init_seq_in;
            auml_trace_ack = &adsl_ste->umc_tracing_seq_in;
        } else {
            abol_trace_init_seq = NULL;
            auml_trace_seq = NULL;
            abol_trace_init_ack = NULL;
            auml_trace_ack = NULL;
        }

        m_interface_trace(adsp_st1, true,
                          abol_trace_init_seq, auml_trace_seq,
                          abol_trace_init_ack, auml_trace_ack);
    }
}

static void m_sdhtcp_free(struct dsd_sdh_tcp_ext* adsp_ste)
{
    struct dsd_sdh_tcp_1* adsl_st1 = adsp_ste->adsc_st1;
    BOOL bol_ret;

    /* adsp_ste->dsc_hc should already be closed - input queue freed */

    /* free output queue */
    while (adsp_ste->adsc_out_head) {

        if ((adsl_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsl_st1->amc_aux, adsl_st1->vpc_userfld,
                            "SSDTC023",
                            adsl_st1->imc_sno, adsl_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP MARK_WORKAREA_DEC %p in shutdown",
                            adsp_ste->adsc_out_head->achc_buffer);
        }

        bol_ret =adsl_st1->amc_aux(adsl_st1->vpc_userfld,
                                   DEF_AUX_MARK_WORKAREA_DEC,
                                   (void*)adsp_ste->adsc_out_head->achc_buffer,
                                   0);
        if (!bol_ret) {
            m_sdhtcp_console(adsl_st1, __LINE__, "%s",
                             "m_sdhtcp_free() DEF_AUX_MARK_WORKAREA_DEC"
                             " failed when freeing output buffer.");
        }

        if (adsp_ste->adsc_out_head->adsc_wac->imc_count <= 0) {
            m_sdhtcp_console(adsl_st1, __LINE__, "%s",
                             "m_sdhtcp_free() found output buffer "
                             "without positive count.");
        } else if (--adsp_ste->adsc_out_head->adsc_wac->imc_count == 0) {
            if ((adsl_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsl_st1->amc_aux, adsl_st1->vpc_userfld,
                                "SSDTC024",
                                adsl_st1->imc_sno, adsl_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP MARK_WORKAREA_DEC %p in shutdown",
                                adsp_ste->adsc_out_head->adsc_wac);
            }

            bol_ret = adsl_st1->amc_aux(adsl_st1->vpc_userfld,
                                        DEF_AUX_MARK_WORKAREA_DEC,
                                        &adsp_ste->adsc_out_head->adsc_wac, 0);
            if (!bol_ret) {
                m_sdhtcp_console(adsl_st1, __LINE__, "%s",
                                 "m_sdhtcp_free() DEF_AUX_MARK_WORKAREA_DEC"
                                 " failed when freeing output buffer.");
            }
        }

        adsp_ste->adsc_out_head = adsp_ste->adsc_out_head->adsc_next;
    }

    adsl_st1->iec_sts = adsp_ste->iec_sts;

    bol_ret = adsl_st1->amc_aux(adsl_st1->vpc_userfld, DEF_AUX_TIMER1_REL,
                                NULL, 0);
    if (!bol_ret) {
        m_sdhtcp_console(adsl_st1, __LINE__, "%s",
                         "m_sdhtcp_free() DEF_AUX_TIMER1_REL failed.");
    }

    if (adsp_ste->boc_free_ext) {
        if ((adsl_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsl_st1->amc_aux, adsl_st1->vpc_userfld,
                            "SSDTC003",
                            adsl_st1->imc_sno, adsl_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP deallocating ext=%p",
                            adsl_st1->ac_ext);
        }
        bol_ret = adsl_st1->amc_aux(adsl_st1->vpc_userfld, DEF_AUX_MEMFREE,
                                    &adsl_st1->ac_ext, 0);
        if (!bol_ret) {
            m_sdhtcp_console(adsl_st1, __LINE__, "%s",
                             "m_sdhtcp_free() DEF_AUX_MEMFREE"
                             " failed when freeing ac_ext structure");
        }
    }

    adsl_st1->ac_ext = NULL;
}

static void m_sdhtcp_shutdown(struct dsd_sdh_tcp_ext* adsp_ste, int inp_ret)
{
    // only shutdown once
    if (adsp_ste->boc_shutdown)
        return;

    m_htcp_abort(&adsp_ste->dsc_hc, false);
    /* m_htcp_abort() will free input queue (pending received packets) */

    adsp_ste->boc_shutdown = true;
    adsp_ste->adsc_st1->imc_return = inp_ret;
}

static void m_sdhtcp_shutdown_rst(struct dsd_sdh_tcp_ext* adsp_ste, int inp_ret)
{
    struct dsd_tcp_data_contr_1* adsl_tdc1;
    struct dsd_gather_i_1* adsl_gai1;
    char* achl_header;
    uint32_t uml_hlen;
    uint32_t uml_offset;
    uint32_t uml_dlen;
    bool bol_more;

    // only shutdown once
    if (adsp_ste->boc_shutdown)
        return;

    m_htcp_abort(&adsp_ste->dsc_hc, true);
    /* m_htcp_abort() will free input queue (pending received packets) */

    adsp_ste->boc_shutdown = true;
    adsp_ste->adsc_st1->imc_return = inp_ret;

    adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
        m_wa_malloc(adsp_ste, sizeof(struct dsd_tcp_data_contr_1));
    if (adsl_tdc1 == NULL)
        return;

    adsl_gai1 = (struct dsd_gather_i_1*)
        m_wa_malloc(adsp_ste, sizeof(struct dsd_gather_i_1));
    if (adsl_gai1 == NULL)
        return;

    achl_header = (char*)
        m_wa_malloc(adsp_ste, 60);
    if (achl_header == NULL)
        return;

    m_htcp_out_get_packet(&adsp_ste->dsc_hc, achl_header, &uml_hlen,
                          &uml_offset, &uml_dlen, &bol_more);

    if (uml_hlen == 0) {
        m_sdhtcp_console(adsp_ste->adsc_st1, __LINE__, "%s",
                         "could not generate RST segment.");
        return;
    }

    if (uml_dlen != 0 || m_get_tcp_rst(achl_header) == 0) {
        m_sdhtcp_console(adsp_ste->adsc_st1, __LINE__, "%s",
                         "could not generate correct RST segment.");
        return;
    }

    adsl_tdc1->adsc_next = NULL;
    adsl_tdc1->adsc_gai1 = adsl_gai1;
    adsl_tdc1->imc_len_data = uml_hlen;
    adsl_tdc1->umc_flags = 0;

    adsl_gai1->achc_ginp_cur = achl_header;
    adsl_gai1->achc_ginp_end = achl_header + uml_hlen;
    adsl_gai1->adsc_next = NULL;

    adsp_ste->adsc_st1->adsc_tdc1_out_to_server = adsl_tdc1;
}

static void m_sdhtcp_console_helper(struct dsd_sdh_tcp_1* adsp_st1,
                                    int inp_line,
                                    const char* achp_format, va_list ap)
{
    char chrl_buffer[160];
    int inl_space;
    int inl_r1;
    int inl_r2;

    inl_space = sizeof(chrl_buffer);

    inl_r1 = m_snprintf(chrl_buffer, inl_space, "xs-htcp-sdh-01.cpp:%04d ",
                        inp_line);
    if (inl_r1 < 0)
        return;
    if (inl_r1 >= inl_space)
        inl_r1 = inl_space - 1;
    inl_space -= inl_r1;

    inl_r2 = m_vsnprintf(chrl_buffer + inl_r1, inl_space, achp_format, ap);
    if (inl_r2 < 0)
        return;
    if (inl_r2 >= inl_space)
        inl_r2 = inl_space - 1;

    adsp_st1->amc_aux(adsp_st1->vpc_userfld, DEF_AUX_CONSOLE_OUT,
                      chrl_buffer, inl_r1 + inl_r2);
}

static void m_sdhtcp_console(struct dsd_sdh_tcp_1* adsp_st1,
                             int inp_line, const char* achp_format, ...)
{
    va_list ap;

    va_start(ap, achp_format);
    m_sdhtcp_console_helper(adsp_st1, inp_line, achp_format, ap);
    va_end(ap);
}

static void m_shutdown_msg(struct dsd_sdh_tcp_ext* adsp_ste, int inp_ret,
                           int inp_line, const char* achp_format, ...)
{
    va_list ap;

    va_start(ap, achp_format);
    m_sdhtcp_console_helper(adsp_ste->adsc_st1, inp_line, achp_format, ap);
    va_end(ap);

    m_sdhtcp_shutdown(adsp_ste, inp_ret);
}

bool m_wa_init(struct dsd_sdh_tcp_ext* adsp_ste,
               char* achp_wa, uint32_t ump_wa_len)
{
    struct dsd_workarea_control* adsl_wac;
    uint32_t uml_len;

    uml_len = DEF_ALIGN_LEN(sizeof(struct dsd_workarea_control));

    if (achp_wa == NULL || ump_wa_len <= uml_len)
        return false;

    adsl_wac = (struct dsd_workarea_control*)achp_wa;

    adsl_wac->imc_count = 1;
    adsl_wac->achc_buf = achp_wa + uml_len;
    adsl_wac->umc_size = ump_wa_len - uml_len;

    adsl_wac->adsc_next = adsp_ste->adsc_wac;
    adsp_ste->adsc_wac = adsl_wac;

    return true;
}

void* m_wa_malloc(struct dsd_sdh_tcp_ext* adsp_ste, uint32_t ump_size)
{
    BOOL bol_ret;
    struct dsd_aux_get_workarea dsl_agwa;
    void* al_buffer;
    uint32_t uml_len;

    uml_len = DEF_ALIGN_LEN(ump_size);

    if (adsp_ste->adsc_wac == NULL || ump_size > adsp_ste->adsc_wac->umc_size) {
        bol_ret = adsp_ste->adsc_st1->amc_aux(adsp_ste->adsc_st1->vpc_userfld,
                                              DEF_AUX_GET_WORKAREA,
                                              &dsl_agwa, sizeof(dsl_agwa));
        if (!bol_ret) {
            m_shutdown_msg(adsp_ste, DEF_IRET_ERRAU, __LINE__, "%s",
                           "m_wa_malloc() DEF_AUX_GET_WORKAREA failed");
            return NULL;
        }

        if (!m_wa_init(adsp_ste,
                       dsl_agwa.achc_work_area, dsl_agwa.imc_len_work_area)) {

            m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR, __LINE__, "%s",
                           "m_wa_malloc() workarea obtained by "
                           "DEF_AUX_GET_WORKAREA too small");
            return NULL;
        }

        if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                            adsp_ste->adsc_st1->vpc_userfld,
                            "SSDTC004",
                            adsp_ste->adsc_st1->imc_sno,
                            adsp_ste->adsc_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP GET_WORKAREA wa=%p(%d)",
                            dsl_agwa.achc_work_area,
                            (int)dsl_agwa.imc_len_work_area);
        }

        if (ump_size > adsp_ste->adsc_wac->umc_size) {
            m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR, __LINE__, "%s%u%s",
                           "m_wa_malloc() cannot fit ", ump_size,
                           " bytes in workarea");
            return NULL;
        }
    }

    al_buffer = adsp_ste->adsc_wac->achc_buf;
    adsp_ste->adsc_wac->achc_buf += uml_len;
    if (adsp_ste->adsc_wac->umc_size > uml_len)
      adsp_ste->adsc_wac->umc_size -= uml_len;
    else
        adsp_ste->adsc_wac->umc_size = 0;
    return al_buffer;
}

bool m_dec_wac(struct dsd_sdh_tcp_ext* adsp_ste,
               struct dsd_workarea_control* adsp_wac)
{
    BOOL bol_ret;

    if (adsp_wac->imc_count <= 0) {
        m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR, __LINE__, "%s%d",
                       "m_dec_wac() trying to unmark structure with count ",
                       adsp_wac->imc_count);
        return false;
    }

    if (--adsp_wac->imc_count == 0) {
        bol_ret = adsp_ste->adsc_st1->amc_aux(adsp_ste->adsc_st1->vpc_userfld,
                                              DEF_AUX_MARK_WORKAREA_DEC,
                                              adsp_wac, 0);
        if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                            adsp_ste->adsc_st1->vpc_userfld,
                            "SSDTC020",
                            adsp_ste->adsc_st1->imc_sno,
                            adsp_ste->adsc_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP MARK_WORKAREA_DEC %p", adsp_wac);
        }
        if (!bol_ret) {
            m_shutdown_msg(adsp_ste, DEF_IRET_ERRAU, __LINE__, "%s%p%s",
                           "m_dec_wac() DEF_AUX_MARK_WORKAREA_DEC for ",
                           adsp_wac, " failed");
            return false;
        }
    }

    return true;
}

bool m_dec_wac_no_shutdown(struct dsd_sdh_tcp_ext* adsp_ste,
                           struct dsd_workarea_control* adsp_wac)
{
    BOOL bol_ret;

    if (adsp_wac->imc_count <= 0) {
        m_sdhtcp_console(adsp_ste->adsc_st1, __LINE__, "%s%d",
                         "m_dec_wac_no_shutdown() "
                         "trying to unmark structure with count ",
                         adsp_wac->imc_count);
        return false;
    }

    if (--adsp_wac->imc_count == 0) {
        bol_ret = adsp_ste->adsc_st1->amc_aux(adsp_ste->adsc_st1->vpc_userfld,
                                              DEF_AUX_MARK_WORKAREA_DEC,
                                              adsp_wac, 0);
        if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                            adsp_ste->adsc_st1->vpc_userfld,
                            "SSDTC025",
                            adsp_ste->adsc_st1->imc_sno,
                            adsp_ste->adsc_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP MARK_WORKAREA_DEC %p",
                            adsp_wac);
        }
        if (!bol_ret) {
            m_sdhtcp_console(adsp_ste->adsc_st1, __LINE__, "%s%p%s",
                             "m_dec_wac_no_shutdown() "
                             "DEF_AUX_MARK_WORKAREA_DEC for ",
                             adsp_wac, " failed");
            return false;
        }
    }

    return true;
}

static void m_init(struct dsd_sdh_tcp_ext* adsp_ste, bool bop_free_ext)
{
    adsp_ste->adsc_out_head = NULL;
    adsp_ste->boc_established = false;
    adsp_ste->iec_ess = ied_ess_init;
    adsp_ste->achc_syn_packet = NULL;
    adsp_ste->inc_syn_length = 0;
    adsp_ste->boc_eof_sent = false;
    adsp_ste->iec_sts = ied_sts_normal;
    adsp_ste->umc_out_cache_offset = 0;
    adsp_ste->boc_timer = false;
    adsp_ste->adsc_in_tmp = NULL;
    adsp_ste->boc_shutdown = false;
    adsp_ste->boc_free_ext = bop_free_ext;
    adsp_ste->boc_packet_pending = false;
    adsp_ste->boc_tracing_init_seq_in = false;
    adsp_ste->boc_tracing_init_seq_out = false;
}

static bool m_process_data(struct dsd_sdh_tcp_ext* adsp_ste,
                           const struct dsd_tcp_data_contr_1* adsp_tdc1)
{
    uint32_t uml_total_len;
    int32_t iml_cur_len;
    struct dsd_buf_from_app* adsl_bfa;
    const struct dsd_gather_i_1* adsl_gai1;
    BOOL bol_ret;
    bool bol_push;

    uml_total_len = 0;
    bol_push = false;

    for (; adsp_tdc1 != NULL; adsp_tdc1 = adsp_tdc1->adsc_next) {
        uml_total_len += adsp_tdc1->imc_len_data;

        iml_cur_len = 0;
        for (adsl_gai1 = adsp_tdc1->adsc_gai1;
             iml_cur_len < adsp_tdc1->imc_len_data;
             adsl_gai1 = adsl_gai1->adsc_next) {
            if (adsl_gai1 == NULL) {
                m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR,
                               __LINE__, "%s%d%s%d%s",
                               " m_process_data() "
                               "ads_sdh_tcp_1->adsc_tdc1_in->adsc_gai1"
                               " points to ", iml_cur_len, " bytes, less than "
                               "ads_sdh_tcp_1->adsc_tdc1_in->imc_len_data = ",
                               adsp_tdc1->imc_len_data, " bytes");
                return false;
            }

            if (adsl_gai1->achc_ginp_cur >= adsl_gai1->achc_ginp_end)
                continue;

            adsl_bfa = (struct dsd_buf_from_app*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_buf_from_app));
            if (adsl_bfa == NULL)
                return false;
            adsl_bfa->adsc_wac = adsp_ste->adsc_wac;

            adsl_bfa->achc_buffer = adsl_gai1->achc_ginp_cur;
            adsl_bfa->umc_length =
                adsl_gai1->achc_ginp_end - adsl_gai1->achc_ginp_cur;
            iml_cur_len += adsl_bfa->umc_length;
            if (iml_cur_len > adsp_tdc1->imc_len_data)
                adsl_bfa->umc_length -= iml_cur_len - adsp_tdc1->imc_len_data;

            // There is no point in postponing marking the workareas for the
            // input data - there is no non-error scenario in which the data
            // will not be marked. HTCP will need the data to be available until
            // the respective ACK is received from the peer, which will be after
            // m_sdhtcp01() returns.

            bol_ret =
                adsp_ste->adsc_st1->amc_aux(adsp_ste->adsc_st1->vpc_userfld,
                                            DEF_AUX_MARK_WORKAREA_INC,
                                            (void*)adsl_bfa->achc_buffer, 0);
            if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                adsp_ste->adsc_st1->vpc_userfld,
                                "SSDTC011",
                                adsp_ste->adsc_st1->imc_sno,
                                adsp_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP MARK_WORKAREA_INC %p%s",
                                adsl_bfa->achc_buffer,
                                (bol_ret ? "" : " failed"));
            }
            if (!bol_ret) {
                m_shutdown_msg(adsp_ste, DEF_IRET_ERRAU, __LINE__, "%s%p%s",
                               "m_process_data() "
                               "DEF_AUX_MARK_WORKAREA_INC for ",
                               (void*)adsl_bfa->achc_buffer, " failed");
                return false;
            }

            ++adsl_bfa->adsc_wac->imc_count;

            adsl_bfa->adsc_next = NULL;
            if (adsp_ste->adsc_out_head == NULL)
                adsp_ste->adsc_out_head = adsl_bfa;
            else
                adsp_ste->adsc_out_tail->adsc_next = adsl_bfa;
            adsp_ste->adsc_out_tail = adsl_bfa;
        }

        bol_push = bol_push || (adsp_tdc1->umc_flags & utd_tcp_psh) != 0;
    }

    if (bol_push || uml_total_len > 0) {
        m_htcp_out_send(&adsp_ste->dsc_hc, uml_total_len, bol_push, false);
        if (adsp_ste->boc_shutdown)
            return false;
    }

    return true;
}

static bool m_process_packets(struct dsd_sdh_tcp_ext* adsp_ste,
                              const struct dsd_tcp_data_contr_1* adsp_tdc1)
{
    struct dsd_sdh_tcp_1* adsl_st1 = adsp_ste->adsc_st1;
    struct dsd_packet_from_network* adsl_pfn;
    struct dsd_buf_from_network* adsl_bfn;
    struct dsd_buf_from_network** aadsl_bfn_tail;
    struct dsd_gather_i_1* adsl_gai1;
    int32_t iml_cur_len;

    for (; adsp_tdc1 != NULL; adsp_tdc1 = adsp_tdc1->adsc_next) {

        adsl_pfn = (struct dsd_packet_from_network*)
            m_wa_malloc(adsp_ste, sizeof(struct dsd_packet_from_network));
        if (adsl_pfn == NULL)
            return false;
        adsl_pfn->adsc_wac = adsp_ste->adsc_wac;
        aadsl_bfn_tail = &adsl_pfn->adsc_bfn;

        adsl_pfn->boc_push = false;

        iml_cur_len = 0;
        for (adsl_gai1 = adsp_tdc1->adsc_gai1;
             iml_cur_len < adsp_tdc1->imc_len_data;
             adsl_gai1 = adsl_gai1->adsc_next) {

            if (adsl_gai1 == NULL) {
                m_shutdown_msg(adsp_ste, DEF_IRET_INVDA,
                               __LINE__, "%s%d%s%d%s",
                               " m_process_packets() "
                               "ads_sdh_tcp_1->adsc_tdc1_in->adsc_gai1"
                               " points to ", iml_cur_len, " bytes, less than "
                               "ads_sdh_tcp_1->adsc_tdc1_in->imc_len_data = ",
                               adsp_tdc1->imc_len_data, " bytes");
                return false;
            }

            if (adsl_gai1->achc_ginp_cur >= adsl_gai1->achc_ginp_end)
                continue;

            adsl_bfn = (struct dsd_buf_from_network*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_buf_from_network));
            if (adsl_bfn == NULL)
                return false;
            adsl_bfn->adsc_wac = adsp_ste->adsc_wac;

            adsl_bfn->achc_buffer = adsl_gai1->achc_ginp_cur;
            adsl_bfn->umc_length =
                adsl_gai1->achc_ginp_end - adsl_gai1->achc_ginp_cur;

            if (iml_cur_len < 14 && iml_cur_len + adsl_bfn->umc_length >= 14) {
                adsl_pfn->boc_push = (adsl_bfn->achc_buffer[13 - iml_cur_len] &
                                      utd_tcp_psh) != 0;
            }

            iml_cur_len += adsl_bfn->umc_length;
            if (iml_cur_len > adsp_tdc1->imc_len_data)
                adsl_bfn->umc_length -= iml_cur_len - adsp_tdc1->imc_len_data;

            *aadsl_bfn_tail = adsl_bfn;
            aadsl_bfn_tail = &(adsl_bfn->adsc_next);
        }
        *aadsl_bfn_tail = NULL;

        adsl_pfn->adsc_prev = NULL;
        adsl_pfn->adsc_next = adsp_ste->adsc_in_tmp;
        adsl_pfn->umc_cache_offset = 0;
        if (adsp_ste->adsc_in_tmp != NULL)
            adsp_ste->adsc_in_tmp->adsc_prev = adsl_pfn;
        adsp_ste->adsc_in_tmp = adsl_pfn;

        m_htcp_in_packet(&adsp_ste->dsc_hc, &adsl_pfn->dsc_hii,
                         adsp_tdc1->imc_len_data);
        if (adsp_ste->boc_shutdown)
            return false;
    }

    return true;
}

static bool m_check_in_data(struct dsd_sdh_tcp_ext* adsp_ste)
{
    struct dsd_sdh_tcp_1* adsl_st1 = adsp_ste->adsc_st1;
    struct dsd_tcp_data_contr_1* adsl_tdc1;
    struct dsd_tcp_data_contr_1* adsl_tdc1_head;
    struct dsd_tcp_data_contr_1** aadsl_tdc1;
    struct dsd_gather_i_1** aadsl_gai1;
    struct dsd_buf_from_network* adsl_bfn;
    struct dsd_packet_from_network* adsl_pfn;
    struct dsd_htcp_in_info* adsl_hii;
    uint32_t uml_offset;
    uint32_t uml_len;
    bool bol_push;
    bool bol_eof;
    bool bol_more;

    adsl_tdc1 = NULL;
    adsl_tdc1_head = NULL;
    aadsl_tdc1 = &adsl_tdc1_head;

    do {
        m_htcp_in_get_data(&adsp_ste->dsc_hc,
                           &adsl_hii, &uml_offset, &uml_len, &bol_push,
                           &bol_eof, &bol_more,
                           (bool)adsl_st1->boc_stop_receiving);
        if (adsp_ste->boc_shutdown)
            return false;

        if (adsl_hii == NULL)
            break;

        if (!m_stcb_in_rel(&adsp_ste->dsc_hc, adsl_hii))
            return false;

        if (adsl_tdc1 == NULL) {
            adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_tcp_data_contr_1));
            if (adsl_tdc1 == NULL)
                return false;

            adsl_tdc1->adsc_next = NULL;
            adsl_tdc1->imc_len_data = 0;
            adsl_tdc1->umc_flags = 0;

            aadsl_gai1 = &adsl_tdc1->adsc_gai1;
        }

        adsl_tdc1->imc_len_data += uml_len;

        adsl_pfn = DEF_HII2PFN(adsl_hii);

        if (uml_len > 0) {
            if (adsl_st1->boc_eof_client) {
                m_sdhtcp_console(adsl_st1, __LINE__, "%s",
                                 "received data while closing session.");
                m_sdhtcp_shutdown_rst(adsp_ste, DEF_IRET_END);
                return false;
            }

            if (adsl_pfn->umc_cache_offset > 0 &&
                uml_offset >= adsl_pfn->umc_cache_offset) {

                uml_offset -= adsl_pfn->umc_cache_offset;
                adsl_bfn = adsl_pfn->adsc_cache;
            } else {
                adsl_bfn = adsl_pfn->adsc_bfn;
            }

            /* skip offset */
            for (; ; ) {
                if (adsl_bfn == NULL) {
                    m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR, __LINE__,
                                   "%s%u%s", "m_check_in_data() gets ",
                                   uml_offset + uml_len,
                                   " bytes beyond available data from "
                                   "m_htcp_in_get_data()");
                    return false;
                }

                if (uml_offset < adsl_bfn->umc_length)
                    break;

                uml_offset -= adsl_bfn->umc_length;
                adsl_bfn = adsl_bfn->adsc_next;
            }

            /* get data */
            while (uml_len > 0) {

                if (adsl_bfn == NULL) {
                    m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR, __LINE__,
                                   "%s%u%s", "m_check_in_data() gets ",
                                   uml_offset + uml_len,
                                   " bytes beyond available data from "
                                   "m_htcp_in_get_data()");
                    return false;
                }

                *aadsl_gai1 = (struct dsd_gather_i_1*)
                    m_wa_malloc(adsp_ste, sizeof(struct dsd_gather_i_1));
                if (*aadsl_gai1 == NULL)
                    return false;

                (*aadsl_gai1)->achc_ginp_cur =
                    (char*)adsl_bfn->achc_buffer + uml_offset;
                (*aadsl_gai1)->achc_ginp_end = (*aadsl_gai1)->achc_ginp_cur +
                    adsl_bfn->umc_length - uml_offset;

                if ((*aadsl_gai1)->achc_ginp_end >=
                    (*aadsl_gai1)->achc_ginp_cur + uml_len) {

                    (*aadsl_gai1)->achc_ginp_end =
                        (*aadsl_gai1)->achc_ginp_cur + uml_len;
                    uml_len = 0;
                } else {
                    uml_len -= (*aadsl_gai1)->achc_ginp_end -
                        (*aadsl_gai1)->achc_ginp_cur;
                    adsl_bfn = adsl_bfn->adsc_next;
                }

                aadsl_gai1 = &(*aadsl_gai1)->adsc_next;

                uml_offset = 0;
            }
        }

        if (bol_push) {
            *aadsl_gai1 = NULL;
            adsl_tdc1->umc_flags = utd_tcp_psh;
            *aadsl_tdc1 = adsl_tdc1;
            aadsl_tdc1 = &adsl_tdc1->adsc_next;
            adsl_tdc1 = NULL;
        }

    } while (bol_more);

    if (adsl_tdc1 != NULL && adsl_tdc1->imc_len_data > 0) {
        *aadsl_gai1 = NULL;
        *aadsl_tdc1 = adsl_tdc1;
    }

    if (bol_eof && adsp_ste->iec_sts == ied_sts_normal) {
        adsp_ste->iec_sts = ied_sts_recv_fin;
        if (!adsp_ste->boc_eof_sent) {
            adsp_ste->boc_eof_sent = true;
            m_htcp_out_send(&adsp_ste->dsc_hc, 0, false, true);
            if (adsp_ste->boc_shutdown)
                return false;
        }
    }

    adsl_st1->adsc_tdc1_out_to_client = adsl_tdc1_head;
    return true;
}

static bool m_check_out_packets(struct dsd_sdh_tcp_ext* adsp_ste)
{
    struct dsd_tcp_data_contr_1* adsl_tdc1;
    struct dsd_tcp_data_contr_1* adsl_tdc1_head;
    struct dsd_tcp_data_contr_1** aadsl_tdc1;
    struct dsd_gather_i_1* adsl_gai1;
    char* achl_header;
    uint32_t uml_hlen;
    uint32_t uml_offset;
    uint32_t uml_dlen;
    bool bol_more;
    struct dsd_buf_from_app* adsl_bfa;
    uint32_t uml_end_offset;

    if (!adsp_ste->boc_packet_pending)
        return true;

    if (adsp_ste->adsc_st1->iec_stfc == ied_stfc_tcp_tunnel_1 &&
        adsp_ste->adsc_st1->boc_send_netw_blocked) {

        // adsp_ste->boc_packet_pending == true
        adsp_ste->adsc_st1->boc_notify_send_netw_possible = TRUE;
        return true;
    }

    aadsl_tdc1 = &adsl_tdc1_head;

    do {
        adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
            m_wa_malloc(adsp_ste, sizeof(struct dsd_tcp_data_contr_1));
        if (adsl_tdc1 == NULL)
            return false;

        adsl_gai1 = (struct dsd_gather_i_1*)
            m_wa_malloc(adsp_ste, sizeof(struct dsd_gather_i_1));
        if (adsl_gai1 == NULL)
            return false;

        achl_header = (char*)
            m_wa_malloc(adsp_ste, 60);
        if (achl_header == NULL)
            return false;

        m_htcp_out_get_packet(&adsp_ste->dsc_hc, achl_header, &uml_hlen,
                              &uml_offset, &uml_dlen, &bol_more);
        if (adsp_ste->boc_shutdown)
            return false;
        if (uml_hlen == 0) {
            m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR,
                           __LINE__, "%s",
                           "HTCP did not provide promised packet.");
            return false;
        }

        *aadsl_tdc1 = adsl_tdc1;
        aadsl_tdc1 = &adsl_tdc1->adsc_next;

        adsl_tdc1->adsc_gai1 = adsl_gai1;
        adsl_tdc1->imc_len_data = uml_hlen + uml_dlen;

        adsl_gai1->achc_ginp_cur = achl_header;
        adsl_gai1->achc_ginp_end = achl_header + uml_hlen;

        if (uml_dlen > 0) {
            uml_end_offset = uml_offset + uml_dlen;

            if (adsp_ste->umc_out_cache_offset > 0 &&
                uml_offset >= adsp_ste->umc_out_cache_offset) {

                uml_offset -= adsp_ste->umc_out_cache_offset;
                adsl_bfa = adsp_ste->adsc_out_cache;
            } else {
                adsl_bfa = adsp_ste->adsc_out_head;
            }

            /* skip offset */
            while (uml_offset > 0) {
                if (adsl_bfa == NULL) {
                    m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR, __LINE__,
                                   "%s%u%s",
                                   "m_check_out_packets() gets ",
                                   uml_offset + uml_dlen,
                                   " bytes beyond available data from "
                                   "m_htcp_out_get_packet()");
                    return false;
                }

                if (uml_offset < adsl_bfa->umc_length)
                    break;

                uml_offset -= adsl_bfa->umc_length;
                adsl_bfa = adsl_bfa->adsc_next;
            }

            /* get data */
            while (uml_dlen > 0) {
                if (adsl_bfa == NULL) {
                    m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR, __LINE__,
                                   "%s%u%s",
                                   "m_check_out_packets() gets ",
                                   uml_offset + uml_dlen,
                                   " bytes beyond available data from "
                                   "m_htcp_out_get_packet()");
                    return false;
                }

                adsl_gai1->adsc_next = (struct dsd_gather_i_1*)
                    m_wa_malloc(adsp_ste, sizeof(struct dsd_gather_i_1));
                adsl_gai1 = adsl_gai1->adsc_next;
                if (adsl_gai1 == NULL)
                    return false;

                adsl_gai1->achc_ginp_cur =
                    (char*)adsl_bfa->achc_buffer + uml_offset;
                adsl_gai1->achc_ginp_end =
                    (char*)adsl_bfa->achc_buffer + adsl_bfa->umc_length;

                if (adsl_gai1->achc_ginp_end >=
                    adsl_gai1->achc_ginp_cur + uml_dlen) {

                    adsl_gai1->achc_ginp_end =
                        adsl_gai1->achc_ginp_cur + uml_dlen;
                    uml_end_offset -= uml_offset + uml_dlen;
                    uml_dlen = 0;
                } else {
                    uml_dlen -=
                        adsl_gai1->achc_ginp_end - adsl_gai1->achc_ginp_cur;
                    adsl_bfa = adsl_bfa->adsc_next;
                }

                uml_offset = 0;
            }

            adsp_ste->adsc_out_cache = adsl_bfa;
            adsp_ste->umc_out_cache_offset = uml_end_offset;
        }

        adsl_gai1->adsc_next = NULL;


    } while (bol_more && adsp_ste->adsc_st1->iec_stfc != ied_stfc_tcp_tunnel_1);

    *aadsl_tdc1 = NULL;

    adsp_ste->adsc_st1->adsc_tdc1_out_to_server = adsl_tdc1_head;
    adsp_ste->adsc_st1->boc_notify_send_netw_possible = bol_more;
    adsp_ste->boc_packet_pending = bol_more;
    return true;
}

static struct dsd_sdh_tcp_ext* m_start(struct dsd_sdh_tcp_1* adsp_st1)
{
    struct dsd_sdh_tcp_ext* adsl_ste;
    BOOL bol_ret;
    bool bol_free_ext;
    struct dsd_htcp_config dsl_hconf;
    uint16_t usl_partial_chksum;

    if (adsp_st1->adsc_tdc1_in != NULL) {
        m_sdhtcp_console(adsp_st1, __LINE__,
                         "DEF_IFUNC_START received with data.");
        adsp_st1->imc_return = DEF_IRET_INVDA;
        return NULL;
    }

    if (adsp_st1->ac_ext == NULL) {
        bol_ret = adsp_st1->amc_aux(adsp_st1->vpc_userfld,
                                   DEF_AUX_MEMGET,
                                   &adsp_st1->ac_ext,
                                   sizeof(struct dsd_sdh_tcp_ext));
        if (!bol_ret || adsp_st1->ac_ext == NULL) {
            m_sdhtcp_console(adsp_st1, __LINE__,
                             "SDH-TCP could not allocate memory.");
            adsp_st1->imc_return = DEF_IRET_ERRAU;
            return NULL;
        }

        if ((adsp_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsp_st1->amc_aux, adsp_st1->vpc_userfld,
                            "SSDTC002",
                            adsp_st1->imc_sno, adsp_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP allocated ext=%p", adsp_st1->ac_ext);
        }

        bol_free_ext = true;
    } else {
        bol_free_ext = false;
    }

    adsl_ste = (struct dsd_sdh_tcp_ext*)adsp_st1->ac_ext;
    m_init(adsl_ste, bol_free_ext);

    adsl_ste->adsc_st1 = adsp_st1;

    adsl_ste->adsc_wac = NULL;
    m_wa_init(adsl_ste,
              adsp_st1->achc_work_area,
              adsp_st1->imc_len_work_area);

    usl_partial_chksum =
        m_calc_tcp_data_chksum(adsp_st1->chrc_header_info,
                               adsp_st1->imc_len_header_info, 6);

    memcpy(&dsl_hconf, &dsg_htcp_default_config, sizeof(dsl_hconf));
    if (adsp_st1->imc_tcp_mss_recv > 0)
        dsl_hconf.umc_in_mss = adsp_st1->imc_tcp_mss_recv;
    if (adsp_st1->imc_tcp_mss_send > 0)
        dsl_hconf.umc_out_mss_cap = adsp_st1->imc_tcp_mss_send;
#ifdef SDH_TCP_NO_CUBIC
    dsl_hconf.iec_cc_algorithm = ied_htcp_cca_newreno;
#endif // SDH_TCP_NO_CUBIC

    m_htcp_init(&adsl_ste->dsc_hc, &dsl_hconf, &dss_hcb,
                usl_partial_chksum,
                ntohs(adsp_st1->usc_port_client),
                ntohs(adsp_st1->usc_port_server));
    // adsl_ste->boc_shutdown set if error

    if (!adsl_ste->boc_shutdown &&
        !adsp_st1->boc_syn_extern &&
        adsp_st1->boc_is_client) {
        // active open

        m_htcp_out_send(&adsl_ste->dsc_hc, 0, false, false);
        // adsl_ste->boc_shutdown set if error

        if (!adsl_ste->boc_shutdown)
            m_check_out_packets(adsl_ste);
    }

    return adsl_ste;
}

static bool m_external_syn(struct dsd_sdh_tcp_ext* adsp_ste)
{
    struct dsd_tcp_data_contr_1* adsl_tdc1;
    BOOL bol_ret;
    uint32_t uml_hlen;
    uint32_t uml_offset;
    uint32_t uml_dlen;
    bool bol_more;

#ifdef TRACE_EXT_SYN
    if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
        m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                        adsp_ste->adsc_st1->vpc_userfld,
                        "SSDTC040",
                        adsp_ste->adsc_st1->imc_sno,
                        adsp_ste->adsc_st1->imc_trace_level,
                        NULL, 0, 0,
                        "SDH-TCP EXT SYN ext=%p entry func=%d state=%d",
                        adsp_ste, adsp_ste->adsc_st1->imc_func,
                        (int)adsp_ste->iec_ess);
    }
#endif

    if (adsp_ste->boc_timer && !adsp_ste->adsc_st1->boc_timer_running) {
        // connection timed out

#ifdef TRACE_EXT_SYN
        if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                            adsp_ste->adsc_st1->vpc_userfld,
                            "SSDTC041",
                            adsp_ste->adsc_st1->imc_sno,
                            adsp_ste->adsc_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP EXT SYN ext=%p timed out.", adsp_ste);
        }
#endif

        adsp_ste->boc_shutdown = true;
        adsp_ste->adsc_st1->imc_return = DEF_IRET_END;
        adsp_ste->adsc_st1->iec_sts = ied_sts_timeout;
        return true;
    }

    if (adsp_ste->adsc_st1->boc_eof_client &&
        (adsp_ste->adsc_st1->imc_func != DEF_IFUNC_TOSERVER ||
         adsp_ste->adsc_st1->adsc_tdc1_in == NULL ||
         adsp_ste->adsc_st1->adsc_tdc1_in->umc_flags != utd_tcp_rst)) {

        // peer closed, except when peer sent RST flag
        adsp_ste->boc_shutdown = true;
        adsp_ste->adsc_st1->imc_return = DEF_IRET_END;

        if (adsp_ste->iec_ess == ied_ess_rcvd_syn_from_peer) {
            // peer has timed out
            adsp_ste->iec_sts = ied_sts_timeout;
        } else {
            adsp_ste->iec_sts = ied_sts_normal;
        }

        return true;
    }

    if (adsp_ste->adsc_st1->adsc_tdc1_in == NULL) {
#ifdef TRACE_EXT_SYN
        if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                            adsp_ste->adsc_st1->vpc_userfld,
                            "SSDTC042",
                            adsp_ste->adsc_st1->imc_sno,
                            adsp_ste->adsc_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP EXT SYN ext=%p no input.", adsp_ste);
        }
#endif
        return true;
    }

    switch (adsp_ste->iec_ess) {

    case ied_ess_init:

        if (adsp_ste->adsc_st1->imc_func == DEF_IFUNC_FROMSERVER) {
            if (!m_process_packets(adsp_ste,
                                   adsp_ste->adsc_st1->adsc_tdc1_in)) {
#ifdef TRACE_EXT_SYN
                if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                    m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                    adsp_ste->adsc_st1->vpc_userfld,
                                    "SSDTC043",
                                    adsp_ste->adsc_st1->imc_sno,
                                    adsp_ste->adsc_st1->imc_trace_level,
                                    NULL, 0, 0,
                                    "SDH-TCP EXT SYN ext=%p bad input.",
                                    adsp_ste);
                }
#endif
                return false;
            }
            adsp_ste->iec_ess = ied_ess_rcvd_packet_from_netw;
            if (!adsp_ste->boc_packet_pending) {
                // syn ack not available
                m_shutdown_msg(adsp_ste, DEF_IRET_END,
                               __LINE__, "%s",
                               "connection not started by accepted SYN.");
                return false;
            }

            adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_tcp_data_contr_1));
            if (adsl_tdc1 == NULL)
                return false;
            adsl_tdc1->adsc_gai1 = NULL;
            adsl_tdc1->adsc_next = NULL;
            adsl_tdc1->imc_len_data = 0;
            adsl_tdc1->umc_flags = utd_tcp_syn;

            adsp_ste->adsc_st1->adsc_tdc1_out_to_client = adsl_tdc1;

            // start timeout timer - 1 minute
            bol_ret =
                adsp_ste->adsc_st1->amc_aux(adsp_ste->adsc_st1->vpc_userfld,
                                            DEF_AUX_TIMER1_SET, NULL, 60000);
            if (!bol_ret) {
                m_shutdown_msg(adsp_ste, DEF_IRET_ERRAU,
                               __LINE__, "%s",
                               "Could not set timer.");
                return false;
            }
            adsp_ste->boc_timer = true;

#ifdef TRACE_EXT_SYN
            if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                adsp_ste->adsc_st1->vpc_userfld,
                                "SSDTC044",
                                adsp_ste->adsc_st1->imc_sno,
                                adsp_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP EXT SYN ext=%p "
                                "sending first SYN to peer.",
                                adsp_ste);
            }
#endif

            return true;
        }

        if (adsp_ste->adsc_st1->imc_func == DEF_IFUNC_TOSERVER) {
            if (adsp_ste->adsc_st1->adsc_tdc1_in->umc_flags != utd_tcp_syn) {
                m_shutdown_msg(adsp_ste, DEF_IRET_END,
                               __LINE__, "%s",
                               "received data other than expected first SYN.");
                return false;
            }
            adsp_ste->iec_ess = ied_ess_rcvd_syn_from_peer;
            /* active open */
            m_htcp_out_send(&adsp_ste->dsc_hc, 0, false, false);
            if (adsp_ste->boc_shutdown)
                return false;

            adsp_ste->achc_syn_packet = (char*)m_wa_malloc(adsp_ste, 60);
            adsp_ste->inc_syn_length = 0;

            m_htcp_out_get_packet(&adsp_ste->dsc_hc,
                                  adsp_ste->achc_syn_packet, &uml_hlen,
                                  &uml_offset, &uml_dlen,
                                  &bol_more);
            if (uml_hlen < 20 || uml_hlen > 60 || uml_dlen > 0) {
                m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR,
                               __LINE__, "%s",
                               "bad SYN segment created.");
                return false;
            }
            adsp_ste->inc_syn_length = uml_hlen;

            bol_ret =
                adsp_ste->adsc_st1->amc_aux(adsp_ste->adsc_st1->vpc_userfld,
                                            DEF_AUX_MARK_WORKAREA_INC,
                                            adsp_ste->achc_syn_packet, 0);
            if (!bol_ret) {
                m_shutdown_msg(adsp_ste, DEF_IRET_ERRAU,
                               __LINE__, "%s",
                               "Could not mark workarea.");
                return false;
            }

            adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_tcp_data_contr_1));
            if (adsl_tdc1 == NULL)
                return false;
            adsl_tdc1->adsc_gai1 = (struct dsd_gather_i_1*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_gather_i_1));
            if (adsl_tdc1->adsc_gai1 == NULL)
                return false;

            adsl_tdc1->adsc_next = NULL;
            adsl_tdc1->imc_len_data = adsp_ste->inc_syn_length;
            adsl_tdc1->umc_flags = 0;
            adsl_tdc1->adsc_gai1->achc_ginp_cur = adsp_ste->achc_syn_packet;
            adsl_tdc1->adsc_gai1->achc_ginp_end =
                adsp_ste->achc_syn_packet + adsp_ste->inc_syn_length;
            adsl_tdc1->adsc_gai1->adsc_next = NULL;

            adsp_ste->adsc_st1->adsc_tdc1_out_to_server = adsl_tdc1;

#ifdef TRACE_EXT_SYN
            if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                adsp_ste->adsc_st1->vpc_userfld,
                                "SSDTC045",
                                adsp_ste->adsc_st1->imc_sno,
                                adsp_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP EXT SYN ext=%p "
                                "sending first SYN to network.",
                                adsp_ste);
            }
#endif

            return true;
        }

        // should not arrive here
        m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR,
                       __LINE__, "%s",
                       "logic error.");
        return false;

    case ied_ess_rcvd_packet_from_netw:

        if (adsp_ste->adsc_st1->imc_func == DEF_IFUNC_FROMSERVER) {
            // TODO: check that extra packet is SYN
            adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_tcp_data_contr_1));
            if (adsl_tdc1 == NULL)
                return false;

            adsl_tdc1->adsc_gai1 = NULL;
            adsl_tdc1->adsc_next = NULL;
            adsl_tdc1->imc_len_data = 0;
            adsl_tdc1->umc_flags = utd_tcp_syn;

            adsp_ste->adsc_st1->adsc_tdc1_out_to_client = adsl_tdc1;

#ifdef TRACE_EXT_SYN
            if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                adsp_ste->adsc_st1->vpc_userfld,
                                "SSDTC046",
                                adsp_ste->adsc_st1->imc_sno,
                                adsp_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP EXT SYN ext=%p resending SYN to peer.",
                                adsp_ste);
            }
#endif

            return true;
        }

        if (adsp_ste->adsc_st1->imc_func == DEF_IFUNC_TOSERVER) {
            adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_tcp_data_contr_1));
            if (adsl_tdc1 == NULL)
                return false;
            adsl_tdc1->adsc_gai1 = (struct dsd_gather_i_1*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_gather_i_1));
            if (adsl_tdc1->adsc_gai1 == NULL)
                return false;
            adsl_tdc1->adsc_gai1->achc_ginp_cur = (char*)
                m_wa_malloc(adsp_ste, 60);
            if (adsl_tdc1->adsc_gai1->achc_ginp_cur == NULL)
                return false;

            adsl_tdc1->adsc_next = NULL;
            adsl_tdc1->umc_flags = 0;
            adsl_tdc1->adsc_gai1->adsc_next = NULL;

            if (adsp_ste->adsc_st1->adsc_tdc1_in->umc_flags == utd_tcp_rst) {
                m_htcp_abort(&adsp_ste->dsc_hc, true);
                m_htcp_out_get_packet(&adsp_ste->dsc_hc,
                                      adsl_tdc1->adsc_gai1->achc_ginp_cur,
                                      &uml_hlen, &uml_offset, &uml_dlen,
                                      &bol_more);
                if (uml_hlen < 20 || uml_hlen > 60 || uml_dlen > 0) {
                    m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR,
                                   __LINE__, "%s",
                                   "bad RST segment created.");
                    return false;
                }
                adsl_tdc1->adsc_gai1->achc_ginp_end =
                    adsl_tdc1->adsc_gai1->achc_ginp_cur + uml_hlen;
                adsl_tdc1->imc_len_data = uml_hlen;

                adsp_ste->adsc_st1->adsc_tdc1_out_to_server = adsl_tdc1;

#ifdef TRACE_EXT_SYN
                if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                    m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                    adsp_ste->adsc_st1->vpc_userfld,
                                    "SSDTC047",
                                    adsp_ste->adsc_st1->imc_sno,
                                    adsp_ste->adsc_st1->imc_trace_level,
                                    NULL, 0, 0,
                                    "SDH-TCP EXT SYN ext=%p "
                                    "sending RST to network.",
                                    adsp_ste);
                }
#endif

                adsp_ste->boc_shutdown = true;
                adsp_ste->adsc_st1->imc_return = DEF_IRET_END;
                adsp_ste->iec_sts = ied_sts_recv_rst;
                return true;
            }

            if (adsp_ste->adsc_st1->adsc_tdc1_in->umc_flags !=
                utd_tcp_syn_ack) {

                m_shutdown_msg(adsp_ste, DEF_IRET_END,
                               __LINE__, "%s",
                               "received data other than expected SYN ACK.");
                return false;
            }

            adsp_ste->iec_ess = ied_ess_done;

#ifdef B130130 // timeout set when getting packet
            // change timer to SYN ACK timeout - 1s
            bol_ret =
                adsp_ste->adsc_st1->amc_aux(adsp_ste->adsc_st1->vpc_userfld,
                                            DEF_AUX_TIMER1_SET, NULL, 1000);
            if (!bol_ret) {
                m_shutdown_msg(adsp_ste, DEF_IRET_ERRAU,
                               __LINE__, "%s",
                               "Could not set timer.");
                return false;
            }
            adsp_ste->boc_timer = true; // redundant - should be true already
#endif // B130130 // timeout set when getting packet

            m_htcp_out_get_packet(&adsp_ste->dsc_hc,
                                  adsl_tdc1->adsc_gai1->achc_ginp_cur,
                                  &uml_hlen, &uml_offset, &uml_dlen,
                                  &bol_more);
            if (adsp_ste->boc_shutdown)
                return false;
            if (uml_hlen < 20 || uml_hlen > 60 || uml_dlen > 0 ||
                m_get_tcp_flags(adsl_tdc1->adsc_gai1->achc_ginp_cur) !=
                utd_tcp_syn_ack) {

                m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR,
                               __LINE__, "%s",
                               "bad SYN ACK segment created.");
                return false;
            }
            adsl_tdc1->adsc_gai1->achc_ginp_end =
                adsl_tdc1->adsc_gai1->achc_ginp_cur + uml_hlen;
            adsl_tdc1->imc_len_data = uml_hlen;

            adsp_ste->adsc_st1->adsc_tdc1_out_to_server = adsl_tdc1;

#ifdef TRACE_EXT_SYN
            if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                adsp_ste->adsc_st1->vpc_userfld,
                                "SSDTC048",
                                adsp_ste->adsc_st1->imc_sno,
                                adsp_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP EXT SYN ext=%p "
                                "sending first SYN ACK to network.",
                                adsp_ste);
            }
#endif

            adsp_ste->boc_packet_pending = bol_more;

            return true;
        }

        // should not arrive here
        m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR,
                       __LINE__, "%s",
                       "logic error.");
        return false;

    case ied_ess_rcvd_syn_from_peer:

        if (adsp_ste->adsc_st1->imc_func == DEF_IFUNC_FROMSERVER) {
            // m_stcb_established() will be expected inside m_process_packets()

            if (!m_process_packets(adsp_ste,
                                   adsp_ste->adsc_st1->adsc_tdc1_in)) {

#ifdef TRACE_EXT_SYN
                if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                    m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                    adsp_ste->adsc_st1->vpc_userfld,
                                    "SSDTC049",
                                    adsp_ste->adsc_st1->imc_sno,
                                    adsp_ste->adsc_st1->imc_trace_level,
                                    NULL, 0, 0,
                                    "SDH-TCP EXT SYN ext=%p session ended.",
                                    adsp_ste);
                }
#endif
                return false;
            }
#ifdef TRACE_EXT_SYN
            if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                adsp_ste->adsc_st1->vpc_userfld,
                                "SSDTC050",
                                adsp_ste->adsc_st1->imc_sno,
                                adsp_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP EXT SYN ext=%p "
                                "processed segment from network.",
                                adsp_ste);
            }
#endif
            return true;
        }

        if (adsp_ste->adsc_st1->imc_func == DEF_IFUNC_TOSERVER) {
            if (adsp_ste->adsc_st1->adsc_tdc1_in->umc_flags != utd_tcp_syn) {
                m_shutdown_msg(adsp_ste, DEF_IRET_END,
                               __LINE__, "%s",
                               "received data other than expected SYN.");
                return false;
            }

            adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_tcp_data_contr_1));
            if (adsl_tdc1 == NULL)
                return false;
            adsl_tdc1->adsc_gai1 = (struct dsd_gather_i_1*)
                m_wa_malloc(adsp_ste, sizeof(struct dsd_gather_i_1));
            if (adsl_tdc1->adsc_gai1 == NULL)
                return false;

            adsl_tdc1->adsc_next = NULL;
            adsl_tdc1->imc_len_data = adsp_ste->inc_syn_length;
            adsl_tdc1->umc_flags = 0;
            adsl_tdc1->adsc_gai1->achc_ginp_cur = adsp_ste->achc_syn_packet;
            adsl_tdc1->adsc_gai1->achc_ginp_end =
                adsp_ste->achc_syn_packet + adsp_ste->inc_syn_length;
            adsl_tdc1->adsc_gai1->adsc_next = NULL;

            adsp_ste->adsc_st1->adsc_tdc1_out_to_server = adsl_tdc1;

#ifdef TRACE_EXT_SYN
            if ((adsp_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsp_ste->adsc_st1->amc_aux,
                                adsp_ste->adsc_st1->vpc_userfld,
                                "SSDTC051",
                                adsp_ste->adsc_st1->imc_sno,
                                adsp_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP EXT SYN ext=%p "
                                "resending SYN to network.",
                                adsp_ste);
            }
#endif

            return true;
        }

        // should not arrive here
        m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR,
                       __LINE__, "%s",
                       "logic error.");
        return false;

    default:
        // should not arrive here

        m_shutdown_msg(adsp_ste, DEF_IRET_INT_ERROR,
                       __LINE__, "%s",
                       "logic error.");
        return false;
    }
}

static bool m_stcb_out_get(struct dsd_htcp_conn* adsp_hc,
                           uint32_t ump_offset,
                           const char** aachp_buf, uint32_t* aump_len)
{
    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);
    struct dsd_buf_from_app* adsl_bfa;
    uint32_t uml_offset = ump_offset;

    if (adsl_ste->umc_out_cache_offset > 0 &&
        uml_offset >= adsl_ste->umc_out_cache_offset) {

        uml_offset -= adsl_ste->umc_out_cache_offset;
        adsl_bfa = adsl_ste->adsc_out_cache;
    } else {
        adsl_bfa = adsl_ste->adsc_out_head;
    }

    while (adsl_bfa != NULL) {
        if (uml_offset < adsl_bfa->umc_length) {
            adsl_ste->adsc_out_cache = adsl_bfa;
            adsl_ste->umc_out_cache_offset = ump_offset - uml_offset;

            *aachp_buf = adsl_bfa->achc_buffer + uml_offset;
            *aump_len = adsl_bfa->umc_length - uml_offset;
            return true;
        }

        uml_offset -= adsl_bfa->umc_length;
        adsl_bfa = adsl_bfa->adsc_next;
    }

    if (uml_offset > 0) {
        m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR, __LINE__, "%s%u%s",
                       "m_stcb_out_get() called with offset ", uml_offset,
                       " bytes beyond end of available data");
        return false;
    }

    *aachp_buf = NULL;
    *aump_len = 0;
    return true;
}

static bool m_stcb_out_packets(struct dsd_htcp_conn* adsp_hc)
{
    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);

#ifdef TRACE_EXT_SYN
    if (adsl_ste->adsc_st1->boc_syn_extern &&
        adsl_ste->iec_ess != ied_ess_done) {

        if ((adsl_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsl_ste->adsc_st1->amc_aux,
                            adsl_ste->adsc_st1->vpc_userfld,
                            "SSDTC052",
                            adsl_ste->adsc_st1->imc_sno,
                            adsl_ste->adsc_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP EXT SYN ext=%p packet available.",
                            adsl_ste);
        }
    }
#endif

    adsl_ste->boc_packet_pending = true;
    return true;
}

static bool m_stcb_out_ack(struct dsd_htcp_conn* adsp_hc, uint32_t ump_len)
{
    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);
    struct dsd_workarea_control* adsl_wac;
    const char* achl_buf;
    BOOL bol_ret;

    if (adsl_ste->umc_out_cache_offset <= ump_len)
        adsl_ste->umc_out_cache_offset = 0;
    else
        adsl_ste->umc_out_cache_offset -= ump_len;

    while (ump_len > 0) {
        if (adsl_ste->adsc_out_head == NULL) {
            /* if we arrive here, some internal error has occured */
            m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR, __LINE__, "%s%u%s",
                           "m_stcb_out_ack() called to acknowledge ",
                           ump_len, " bytes more than available");
            return false;
        }

        if (ump_len >= adsl_ste->adsc_out_head->umc_length) {
            ump_len -= adsl_ste->adsc_out_head->umc_length;
            achl_buf = adsl_ste->adsc_out_head->achc_buffer;
            adsl_wac = adsl_ste->adsc_out_head->adsc_wac;
            adsl_ste->adsc_out_head = adsl_ste->adsc_out_head->adsc_next;

            bol_ret =
                adsl_ste->adsc_st1->amc_aux(adsl_ste->adsc_st1->vpc_userfld,
                                            DEF_AUX_MARK_WORKAREA_DEC,
                                            (void*)achl_buf, 0);
            if ((adsl_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsl_ste->adsc_st1->amc_aux,
                                adsl_ste->adsc_st1->vpc_userfld,
                                "SSDTC021",
                                adsl_ste->adsc_st1->imc_sno,
                                adsl_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP MARK_WORKAREA_DEC %p", achl_buf);
            }
            if (!bol_ret) {
                m_sdhtcp_console(adsl_ste->adsc_st1, __LINE__, "%s%p%s",
                                 "m_stcb_out_ack() "
                                 "DEF_AUX_MARK_WORKAREA_DEC for ",
                                 achl_buf, " failed");
                m_dec_wac_no_shutdown(adsl_ste, adsl_wac);
                m_sdhtcp_shutdown(adsl_ste, DEF_IRET_ERRAU);
                return false;
            }

            if (!m_dec_wac(adsl_ste, adsl_wac))
                return false;
        } else {
            adsl_ste->adsc_out_head->achc_buffer += ump_len;
            adsl_ste->adsc_out_head->umc_length -= ump_len;
            ump_len = 0;
        }
    }

    return true;
}

static bool m_stcb_in_get(struct dsd_htcp_conn* adsp_hc,
                          struct dsd_htcp_in_info* adsp_hii,
                          uint32_t ump_offset,
                          const char** aachp_buf, uint32_t* aump_len)
{
    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);
    struct dsd_packet_from_network* adsl_pfn = DEF_HII2PFN(adsp_hii);
    struct dsd_buf_from_network* adsl_bfn;
    uint32_t uml_offset = ump_offset;

    if (adsl_pfn->umc_cache_offset > 0 &&
        uml_offset >= adsl_pfn->umc_cache_offset) {

        uml_offset -= adsl_pfn->umc_cache_offset;
        adsl_bfn = adsl_pfn->adsc_cache;
    } else {
        adsl_bfn = adsl_pfn->adsc_bfn;
    }

    while (adsl_bfn != NULL) {
        if (uml_offset < adsl_bfn->umc_length) {
            adsl_pfn->adsc_cache = adsl_bfn;
            adsl_pfn->umc_cache_offset = ump_offset - uml_offset;

            *aachp_buf = adsl_bfn->achc_buffer + uml_offset;
            *aump_len = adsl_bfn->umc_length - uml_offset;
            return true;
        }

        uml_offset -= adsl_bfn->umc_length;
        adsl_bfn = adsl_bfn->adsc_next;
    }

    if (uml_offset == 0) {
        *aachp_buf = NULL;
        *aump_len = 0;
        return true;
    }

    m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR, __LINE__, "%s%u%s",
                   "m_stcb_in_get() called with offset ", uml_offset,
                   " bytes beyond end of available data");
    return false;
}

static bool m_stcb_in_rel(struct dsd_htcp_conn* adsp_hc,
                          struct dsd_htcp_in_info* adsp_hii)
{
    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);
    struct dsd_packet_from_network* adsl_pfn = DEF_HII2PFN(adsp_hii);
    struct dsd_buf_from_network* adsl_bfn;
    bool bol_ok;
    BOOL bol_ret;

    if (adsl_pfn->adsc_next == adsl_pfn) {
        /* workarea freeing */

        bol_ok = true;
        for (adsl_bfn = adsl_pfn->adsc_bfn;
             adsl_bfn != NULL;
             adsl_bfn = adsl_bfn->adsc_next) {

            bol_ret =
                adsl_ste->adsc_st1->amc_aux(adsl_ste->adsc_st1->vpc_userfld,
                                            DEF_AUX_MARK_WORKAREA_DEC,
                                            (void*)adsl_bfn->achc_buffer, 0);
            if ((adsl_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsl_ste->adsc_st1->amc_aux,
                                adsl_ste->adsc_st1->vpc_userfld,
                                "SSDTC022",
                                adsl_ste->adsc_st1->imc_sno,
                                adsl_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP MARK_WORKAREA_DEC %p",
                                adsl_bfn->achc_buffer);
            }
            if (!bol_ret) {
                m_sdhtcp_console(adsl_ste->adsc_st1, __LINE__, "%s%p%s",
                                 "m_stcb_in_rel() "
                                 "DEF_AUX_MARK_WORKAREA_DEC for ",
                                 adsl_bfn->achc_buffer, " failed");
            }
            bol_ok = m_dec_wac_no_shutdown(adsl_ste, adsl_pfn->adsc_wac) &&
                bol_ok;
        }
        bol_ok = m_dec_wac_no_shutdown(adsl_ste, adsl_pfn->adsc_wac) && bol_ok;

        return bol_ok;
    } else {
        /* workareas not yet marked, just remove from list */

        if (adsl_pfn->adsc_prev == NULL)
            adsl_ste->adsc_in_tmp = adsl_pfn->adsc_next;
        else
            adsl_pfn->adsc_prev->adsc_next = adsl_pfn->adsc_next;

        if (adsl_pfn->adsc_next != NULL)
            adsl_pfn->adsc_next->adsc_prev = adsl_pfn->adsc_prev;

        return true;
    }
}

static bool m_stcb_get_time(struct dsd_htcp_conn* adsp_hc, int64_t* ailp_time)
{
    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);
    struct dsd_timer1_ret dsl_tr;
    BOOL bol_ret;

    bol_ret = adsl_ste->adsc_st1->amc_aux(adsl_ste->adsc_st1->vpc_userfld,
                                          DEF_AUX_GET_T_MSEC,
                                          ailp_time, sizeof(*ailp_time));
    if (bol_ret)
        return true;

    bol_ret = adsl_ste->adsc_st1->amc_aux(adsl_ste->adsc_st1->vpc_userfld,
                                          DEF_AUX_TIMER1_QUERY,
                                          &dsl_tr, sizeof(dsl_tr));
    if (bol_ret) {
        *ailp_time = dsl_tr.ilc_epoch;
        return true;
    }

    return false;
}

static bool m_stcb_set_timer(struct dsd_htcp_conn* adsp_hc,
                             uint32_t ump_delay_ms)
{
    // TODO: optimize to avoid multiple DEF_AUX_TIMER1_SET in same call

    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);
    BOOL bol_ret;

    if (adsl_ste->adsc_st1->boc_syn_extern &&
        adsl_ste->iec_ess != ied_ess_done) {

        // do not set TCP timer in ext syn phase, timer used for timeout only
        return true;
    }

    bol_ret = adsl_ste->adsc_st1->amc_aux(adsl_ste->adsc_st1->vpc_userfld,
                                          DEF_AUX_TIMER1_SET,
                                          NULL, ump_delay_ms);

    if ((adsl_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
        m_aux_wsp_trace(adsl_ste->adsc_st1->amc_aux,
                        adsl_ste->adsc_st1->vpc_userfld,
                        "SSDTC030",
                        adsl_ste->adsc_st1->imc_sno,
                        adsl_ste->adsc_st1->imc_trace_level,
                        NULL, 0, 0,
                        "SDH-TCP TIMER1_SET %u%s",
                        (unsigned)ump_delay_ms,
                        (bol_ret ? "" : " failed"));
    }

    if (!bol_ret)
        return false;

    adsl_ste->boc_timer = true;
    return true;
}

static bool m_stcb_rel_timer(struct dsd_htcp_conn* adsp_hc)
{
    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);
    BOOL bol_ret;

    if (!adsl_ste->boc_timer)
        return true;

    if (adsl_ste->adsc_st1->boc_syn_extern &&
        adsl_ste->iec_ess != ied_ess_done) {

        // do not rel TCP timer in ext syn phase, timer used for timeout only
        return true;
    }
    adsl_ste->boc_timer = false;

    bol_ret = adsl_ste->adsc_st1->amc_aux(adsl_ste->adsc_st1->vpc_userfld,
                                          DEF_AUX_TIMER1_REL, NULL, 0);

    if ((adsl_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
        m_aux_wsp_trace(adsl_ste->adsc_st1->amc_aux,
                        adsl_ste->adsc_st1->vpc_userfld,
                        "SSDTC031",
                        adsl_ste->adsc_st1->imc_sno,
                        adsl_ste->adsc_st1->imc_trace_level,
                        NULL, 0, 0,
                        "SDH-TCP TIMER1_REL%s",
                        (bol_ret ? "" : " failed"));
    }

    if (!bol_ret)
        return false;

    return true;
}

static bool m_stcb_noop(struct dsd_htcp_conn* adsp_hc)
{
    return true;
}

static bool m_stcb_established(struct dsd_htcp_conn* adsp_hc)
{
    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);
    struct dsd_tcp_data_contr_1* adsl_tdc1;
    BOOL bol_ret;

    if (adsl_ste->adsc_st1->boc_syn_extern &&
        adsl_ste->iec_ess != ied_ess_done) {

#ifdef TRACE_EXT_SYN
        if ((adsl_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
            m_aux_wsp_trace(adsl_ste->adsc_st1->amc_aux,
                            adsl_ste->adsc_st1->vpc_userfld,
                            "SSDTC053",
                            adsl_ste->adsc_st1->imc_sno,
                            adsl_ste->adsc_st1->imc_trace_level,
                            NULL, 0, 0,
                            "SDH-TCP EXT SYN ext=%p established state=%d",
                            adsl_ste,
                            (int)adsl_ste->iec_ess);
        }
#endif

        if (adsl_ste->iec_ess == ied_ess_rcvd_syn_from_peer) {
            adsl_ste->iec_ess = ied_ess_done;
            adsl_ste->boc_established = true;

            bol_ret =
                adsl_ste->adsc_st1->amc_aux(adsl_ste->adsc_st1->vpc_userfld,
                                            DEF_AUX_MARK_WORKAREA_DEC,
                                            adsl_ste->achc_syn_packet, 0);
            if (!bol_ret) {
                m_shutdown_msg(adsl_ste, DEF_IRET_ERRAU,
                               __LINE__, "%s",
                               "could not unmark workarea.");
                return false;
            }

            adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
                m_wa_malloc(adsl_ste, sizeof(struct dsd_tcp_data_contr_1));
            if (adsl_tdc1 == NULL)
                return false;

            adsl_tdc1->adsc_gai1 = NULL;
            adsl_tdc1->adsc_next = NULL;
            adsl_tdc1->imc_len_data = 0;
            adsl_tdc1->umc_flags = utd_tcp_syn_ack;

            adsl_ste->adsc_st1->adsc_tdc1_out_to_client = adsl_tdc1;

#ifdef TRACE_EXT_SYN
            if ((adsl_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsl_ste->adsc_st1->amc_aux,
                                adsl_ste->adsc_st1->vpc_userfld,
                                "SSDTC054",
                                adsl_ste->adsc_st1->imc_sno,
                                adsl_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP EXT SYN ext=%p "
                                "sending SYN ACK to peer.",
                                adsl_ste);
            }
#endif

            // send ACK

            if (!adsl_ste->boc_packet_pending) {
                m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR,
                               __LINE__, "%s",
                               "cannot create ACK to reply SYN ACK.");
                return false;
            }

            if (!m_check_out_packets(adsl_ste))
                return false;

            return true;
        }

        // should not arrive here
        m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR,
                       __LINE__, "%s",
                       "logic error.");
        return false;
    }

    adsl_ste->boc_established = true;
    return true;
}

static void m_stcb_closed(struct dsd_htcp_conn* adsp_hc,
                          enum ied_htcp_close iep_htcpc)
{
    struct dsd_sdh_tcp_ext* adsl_ste = DEF_HC2STE(adsp_hc);
    struct dsd_tcp_data_contr_1* adsl_tdc1;
    char chrl_buffer[257];
    uint32_t uml_len = 256;

    if (adsl_ste->adsc_st1->boc_syn_extern &&
        adsl_ste->iec_ess == ied_ess_rcvd_syn_from_peer) {

        adsl_tdc1 = (struct dsd_tcp_data_contr_1*)
            m_wa_malloc(adsl_ste, sizeof(struct dsd_tcp_data_contr_1));

        adsl_ste->adsc_st1->adsc_tdc1_out_to_server = NULL;

        if (adsl_tdc1 == NULL) {
            m_sdhtcp_console(adsl_ste->adsc_st1, __LINE__,
                             "Could not use workarea while closing.");

#ifdef TRACE_EXT_SYN
            if ((adsl_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsl_ste->adsc_st1->amc_aux,
                                adsl_ste->adsc_st1->vpc_userfld,
                                "SSDTC055",
                                adsl_ste->adsc_st1->imc_sno,
                                adsl_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP EXT SYN ext=%p "
                                "cannot send RST to peer.",
                                adsl_ste);
            }
#endif

        } else {
            adsl_tdc1->adsc_gai1 = NULL;
            adsl_tdc1->adsc_next = NULL;
            adsl_tdc1->imc_len_data = 0;
            adsl_tdc1->umc_flags = utd_tcp_rst;

#ifdef TRACE_EXT_SYN
            if ((adsl_ste->adsc_st1->imc_trace_level & HL_AUX_WT_ALL) != 0) {
                m_aux_wsp_trace(adsl_ste->adsc_st1->amc_aux,
                                adsl_ste->adsc_st1->vpc_userfld,
                                "SSDTC056",
                                adsl_ste->adsc_st1->imc_sno,
                                adsl_ste->adsc_st1->imc_trace_level,
                                NULL, 0, 0,
                                "SDH-TCP EXT SYN ext=%p sending RST to peer.",
                                adsl_ste);
            }
#endif

        }

        adsl_ste->adsc_st1->adsc_tdc1_out_to_client = adsl_tdc1;

    }

    adsl_ste->boc_eof_sent = true; /* avoid trying to resend FIN */

    if (iep_htcpc != ied_htcpc_normal && iep_htcpc != ied_htcpc_local_reset) {
        m_htcp_describe_close(adsp_hc, NULL, 0, chrl_buffer, &uml_len);
        chrl_buffer[uml_len] = 0;
    }

    switch (iep_htcpc) {
    case ied_htcpc_normal:
        m_sdhtcp_shutdown(adsl_ste, DEF_IRET_END);
        break;

    case ied_htcpc_conn_refused:
        adsl_ste->iec_sts = ied_sts_recv_rst;
        m_shutdown_msg(adsl_ste, DEF_IRET_END, __LINE__, "%s%s",
                       "m_stcb_close(): connection refused - ",
                       chrl_buffer);
        break;

    case ied_htcpc_conn_timeout:
        adsl_ste->iec_sts = ied_sts_timeout;
        m_shutdown_msg(adsl_ste, DEF_IRET_END, __LINE__, "%s%s",
                       "m_stcb_close(): connection timed out - ",
                       chrl_buffer);
        break;

    case ied_htcpc_conn_error:
        adsl_ste->iec_sts = ied_sts_recv_rst;
        m_shutdown_msg(adsl_ste, DEF_IRET_END, __LINE__, "%s%s",
                       "m_stcb_close(): connection error - ",
                       chrl_buffer);
        break;

    case ied_htcpc_remote_reset:
        adsl_ste->iec_sts = ied_sts_recv_rst;
        m_shutdown_msg(adsl_ste, DEF_IRET_END, __LINE__, "%s%s",
                       "m_stcb_close(): connection reset by peer - ",
                       chrl_buffer);
        break;

    case ied_htcpc_local_reset:
        break;

    case ied_htcpc_error:
        m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR, __LINE__, "%s%s",
                       "m_stcb_close(): HTCP internal error - ",
                       chrl_buffer);
        break;

    case ied_htcpc_interface_error:
        m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR, __LINE__, "%s%s",
                       "m_stcb_close(): HTCP interface error - ",
                       chrl_buffer);
        break;

    case ied_htcpc_application_error:
        m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR, __LINE__, "%s%s",
                       "m_stcb_close(): application error - ",
                       chrl_buffer);
        break;

    default:
        m_shutdown_msg(adsl_ste, DEF_IRET_INT_ERROR, __LINE__, "%s%d%s%s",
                       "m_stcb_close(): unknown reason (", (int)iep_htcpc,
                       ") - ", chrl_buffer);
    }
}
