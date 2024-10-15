/******************************************************************************
 * File name: xs-htcp-hdr-01.cpp
 *
 * Implementation of non-inline functions for hob-htcp-hdr-01.h
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2011
 ******************************************************************************/

#include <string.h>

#ifndef DEF_INCLUDE_HEADERS
#define DEF_INCLUDE_HEADERS
#endif /* !DEF_INCLUDE_HEADERS */

#include "hob-htcp-int-01.h"
#include "hob-htcp-hdr-01.h"

static uint16_t m_calc_chksum(const char* achp_data, uint32_t ump_len,
                            bool bop_odd, uint16_t usp_part)
{
    uint16_t usl_buf = 0; /* declare as uint16_t to ensure proper alignment */
    uint8_t* const autl_buf = (uint8_t*)&usl_buf;
    uint32_t uml_chksum;
    uint32_t uml_i;

    if (ump_len == 0)
        return usp_part ? usp_part : 0xffff;

    if ((size_t)achp_data & 1) { /* check achp_data alignment */
        bop_odd = !bop_odd;

        autl_buf[1] = *achp_data;
        ++achp_data;
        --ump_len;
        if (ump_len & 1) {
            --ump_len;
            autl_buf[0] = achp_data[ump_len];
        }
    } else {
        if (ump_len & 1) {
            --ump_len;
            autl_buf[0] = achp_data[ump_len];
        }
    }
    ump_len /= 2;

    uml_chksum = usl_buf;
    if (bop_odd) {
        autl_buf[0] = usp_part & 0xff;
        autl_buf[1] = usp_part >> 8;
    } else {
        autl_buf[0] = usp_part >> 8;
        autl_buf[1] = usp_part & 0xff;
    }
    uml_chksum += usl_buf;

    /*
     * we have already included partial checksum and edge bytes
     * achp_data points to ump_len (which is even) 2-byte aligned bytes
     */

    for (; ump_len >= 0xffff; ump_len -= 0xffff) {
        /*
         *avoid overflow:
         * 32 bits contain maximum 0xffff * 0x10001
         * we must allow for 0x1fffe as current checksum
         * we cannot do more than for 0xffff additions
         */

        for (uml_i = 0; uml_i < 0xffff; ++uml_i) {
            uml_chksum += *(const uint16_t*)achp_data;
            achp_data += 2;
        }
        uml_chksum = (uml_chksum & 0xffff) + (uml_chksum >> 16);
    }

    for (; ump_len > 0; --ump_len) {
        uml_chksum += *(const uint16_t*)achp_data;
        achp_data += 2;
    }

    uml_chksum = (uml_chksum & 0xffff) + (uml_chksum >> 16);
    uml_chksum += uml_chksum >> 16;

    usl_buf = uml_chksum;

    if (bop_odd) {
        uml_chksum = autl_buf[1] << 8 | autl_buf[0];
    } else {
        uml_chksum = autl_buf[0] << 8 | autl_buf[1];
    }

    return uml_chksum ? uml_chksum : 0xffff;
}

uint16_t m_calc_ip_chksum(const char* achp_ip_header)
{
    uint16_t usl_part;
    uint32_t uml_len;

    uml_len = m_get_calc_ip_hlen(achp_ip_header);
    if (uml_len < 20)
        uml_len = 20;
    usl_part = m_calc_chksum(achp_ip_header, 10, false, 0);
    usl_part = m_calc_chksum(achp_ip_header + 12, uml_len - 12,
                             false, usl_part);

    return usl_part == 0xffff ? 0xffff : ~usl_part;
}

uint16_t m_calc_ip_tcp_pseudo_chksum(const char* achp_ip_header)
{
    return m_calc_chksum(achp_ip_header + 12, 8, false, 6);
}

uint16_t m_calc_ip6_tcp_pseudo_chksum(const char* achp_ip6_header)
{
    return m_calc_chksum(achp_ip6_header + 8, 32, false, 6);
}

uint16_t m_calc_tcp_data_chksum(const char* achp_data, uint32_t ump_len,
                                uint16_t usp_part)
{
    return m_calc_chksum(achp_data, ump_len, false, usp_part);
}

uint16_t m_calc_tcp_odd_data_chksum(const char* achp_data, uint32_t ump_len,
                                  uint16_t usp_part)
{
    return m_calc_chksum(achp_data, ump_len, true, usp_part);
}

uint16_t m_calc_tcp_chksum(const char* achp_tcp_header, uint32_t ump_data_len,
                           uint16_t usp_part)
{
    uint32_t uml_chksum;
    unsigned unl_hlen;

    unl_hlen = m_get_calc_tcp_hlen(achp_tcp_header);
    usp_part = m_calc_chksum(achp_tcp_header, 16, false, usp_part);
    usp_part = m_calc_chksum(achp_tcp_header + 18, unl_hlen - 18, false,
                             usp_part);

    ump_data_len += unl_hlen;
    uml_chksum = (ump_data_len & 0xffff) + (ump_data_len >> 16);
    uml_chksum += usp_part;
    usp_part = (uml_chksum & 0xffff) + (uml_chksum >> 16);

    return usp_part == 0xffff ? 0xffff : ~usp_part;
}

uint16_t m_tcp_chksum_add(uint16_t usp_chksum,
                          const char* achp_data, uint32_t ump_len)
{
    usp_chksum = m_calc_chksum(achp_data, ump_len, false, ~usp_chksum);
    return usp_chksum == 0xffff ? 0xffff : ~usp_chksum;
}

uint16_t m_tcp_chksum_odd_add(uint16_t usp_chksum,
                              const char* achp_data, uint32_t ump_len)
{
    usp_chksum = m_calc_chksum(achp_data, ump_len, true, ~usp_chksum);
    return usp_chksum == 0xffff ? 0xffff : ~usp_chksum;
}

uint16_t m_tcp_chksum_sub(uint16_t usp_chksum,
                          const char* achp_data, uint32_t ump_len)
{
    return m_calc_chksum(achp_data, ump_len, false, usp_chksum);
}

uint16_t m_tcp_chksum_odd_sub(uint16_t usp_chksum,
                              const char* achp_data, uint32_t ump_len)
{
    return m_calc_chksum(achp_data, ump_len, true, usp_chksum);
}

uint16_t m_tcp_chksum_odd_to_even(uint16_t usp_chksum,
                                  const char* achp_data, uint32_t ump_len)
{
    uint16_t usl_c;
    uint32_t uml_chksum = usp_chksum;

    usl_c = m_calc_chksum(achp_data, ump_len, true, 0);
    uml_chksum += usl_c;

    usl_c = ~usl_c;
    uml_chksum += ((usl_c & 0xff) << 8) | (usl_c >> 8);

    usl_c = (uml_chksum & 0xffff) + (uml_chksum >> 16);
    return usl_c ? usl_c : 0xffff;
}

uint16_t m_tcp_chksum_even_to_odd(uint16_t usp_chksum,
                                  const char* achp_data, uint32_t ump_len)
{
    uint16_t usl_c;
    uint32_t uml_chksum = usp_chksum;

    usl_c = m_calc_chksum(achp_data, ump_len, false, 0);
    uml_chksum += usl_c;

    usl_c = ~usl_c;
    uml_chksum += ((usl_c & 0xff) << 8) | (usl_c >> 8);

    usl_c = (uml_chksum & 0xffff) + (uml_chksum >> 16);
    return usl_c ? usl_c : 0xffff;
}

uint16_t m_tcp_chksum_change_len(uint16_t usp_chksum, int32_t ump_add_len)
{
    char chrl_buf[4];

    if (ump_add_len > 0) {
        chrl_buf[0] = ump_add_len >> 24;
        chrl_buf[1] = ump_add_len >> 16;
        chrl_buf[2] = ump_add_len >> 8;
        chrl_buf[3] = ump_add_len;
        return m_tcp_chksum_add(usp_chksum, chrl_buf, 4);
    } else if (ump_add_len < 0) {
        ump_add_len = -ump_add_len;
        chrl_buf[0] = ump_add_len >> 24;
        chrl_buf[1] = ump_add_len >> 16;
        chrl_buf[2] = ump_add_len >> 8;
        chrl_buf[3] = ump_add_len;
        return m_tcp_chksum_sub(usp_chksum, chrl_buf, 4);
    } else {
        return usp_chksum;
    }
}

bool m_is_ip_size_ok(const char* achp_ip_header, uint32_t ump_hsize)
{
    uint32_t uml_hlen;
    uint32_t uml_tlen;

    if (ump_hsize < 20)
        return false;

    if (m_get_ip_version(achp_ip_header) != 4)
        return false;

    uml_hlen = m_get_calc_ip_hlen(achp_ip_header);
    if (uml_hlen < 20)
        return false;

    uml_tlen = m_get_ip_tlen(achp_ip_header);
    if (uml_tlen < uml_hlen)
        return false;

    uml_tlen += m_get_calc_ip_fofs(achp_ip_header);
    if (uml_tlen > 0xffff)
        return false;

    return true;
}

bool m_is_ip6_size_ok(const char* achp_ip6_header, uint32_t ump_hsize)
{
    if (ump_hsize < 40)
        return false;

    if (m_get_ip6_version(achp_ip6_header) != 6)
        return false;

    return true;
}

bool m_is_tcp_size_ok(const char* achp_tcp_header, uint32_t ump_hsize,
                      uint32_t ump_segsize)
{
    uint32_t uml_hlen;

    if (ump_hsize < 20 || ump_segsize < 20)
        return false;

    uml_hlen = m_get_calc_tcp_hlen(achp_tcp_header);
    if (uml_hlen < 20 || uml_hlen > ump_hsize || uml_hlen > ump_segsize)
        return false;

    return true;
}

const char* m_first_tcp_option(const char* achp_tcp_header,
                               const char* achp_tcp_header_end)
{
    achp_tcp_header += 20;

    while (achp_tcp_header + 1 < achp_tcp_header_end) {
        switch (*achp_tcp_header) {
        case 0:
            return achp_tcp_header_end;

        case 1:
            ++achp_tcp_header;
            break;

        default:
            if (achp_tcp_header[1] < 2 ||
                achp_tcp_header + achp_tcp_header[1] > achp_tcp_header_end) {

                return achp_tcp_header_end;
            }
            return achp_tcp_header;
        }
    }

    return achp_tcp_header_end;
}

const char* m_next_tcp_option(const char* achp_tcp_option,
                              const char* achp_tcp_header_end)
{
    if (achp_tcp_option + 1 >= achp_tcp_header_end || achp_tcp_option[1] < 2)
        return achp_tcp_header_end;

    achp_tcp_option += achp_tcp_option[1];

    while (achp_tcp_option + 1 < achp_tcp_header_end) {
        switch (*achp_tcp_option) {
        case 0:
            return achp_tcp_header_end;

        case 1:
            ++achp_tcp_option;
            break;

        default:
            if (achp_tcp_option[1] < 2 ||
                achp_tcp_option + achp_tcp_option[1] > achp_tcp_header_end) {

                return achp_tcp_header_end;
            }
            return achp_tcp_option;
        }
    }

    return achp_tcp_header_end;
}

uint32_t m_ip_tcp_answer_reset(char* achp_answer, uint32_t ump_alen,
                               const char* achp_header, uint32_t ump_hlen,
                               uint16_t usp_id)
{
    uint32_t uml_ip_hlen;
    uint16_t usl_orig_dlen;
    uint16_t usl_part_chksum;
    uint16_t usl_hchksum;
    const char* achl_tcp_header;

    if (ump_alen < 40 || !m_is_ip_size_ok(achp_header, ump_hlen)) {
        return 0;
    }
    uml_ip_hlen = m_get_calc_ip_hlen(achp_header);
    usl_hchksum = m_get_ip_chksum(achp_header);
    achl_tcp_header = achp_header + uml_ip_hlen;
    if ((usl_hchksum != 0 && usl_hchksum != m_calc_ip_chksum(achp_header)) ||
        m_get_ip_prot(achp_header) != 6 ||
        ump_hlen < uml_ip_hlen + 20 ||
        !m_is_tcp_size_ok(achl_tcp_header, ump_hlen - uml_ip_hlen,
                          m_get_ip_tlen(achp_header) - uml_ip_hlen) ||
        m_get_tcp_rst(achl_tcp_header)) {

        return 0;
    }

    m_set_ip_version(achp_answer, 4);
    m_set_calc_ip_hlen(achp_answer, 20);
    m_set_ip_tos(achp_answer, 0);
    m_set_ip_tlen(achp_answer, 40);
    m_set_ip_id(achp_answer, usp_id);
    m_set_ip_flags(achp_answer, 0);
    m_set_ip_df(achp_answer, 1);
    m_set_calc_ip_fofs(achp_answer, 0);
    m_set_ip_ttl(achp_answer, 128);
    m_set_ip_prot(achp_answer, m_get_ip_prot(achp_header));
    m_set_ip_src_addr(achp_answer, m_get_ip_dst_addr(achp_header));
    m_set_ip_dst_addr(achp_answer, m_get_ip_src_addr(achp_header));

    m_set_ip_chksum(achp_answer, m_calc_ip_chksum(achp_answer));

    m_set_tcp_src_port(achp_answer + 20, m_get_tcp_dst_port(achl_tcp_header));
    m_set_tcp_dst_port(achp_answer + 20, m_get_tcp_src_port(achl_tcp_header));
    m_set_calc_tcp_hlen(achp_answer + 20, 20);
    m_set_tcp_resv(achp_answer + 20, 0);
    m_set_tcp_flags(achp_answer + 20, 0);
    m_set_tcp_rst(achp_answer + 20, 1);
    m_set_tcp_window(achp_answer + 20, 0);
    m_set_tcp_urgent(achp_answer + 20, 0);

    if (m_get_tcp_ack(achl_tcp_header)) {
        m_set_tcp_seqn(achp_answer + 20, m_get_tcp_ackn(achl_tcp_header));
        m_set_tcp_ackn(achp_answer + 20, 0);
    } else {
        usl_orig_dlen = m_get_ip_tlen(achp_header) -
            m_get_calc_ip_hlen(achp_header) -
            m_get_calc_tcp_hlen(achl_tcp_header);
	if (m_get_tcp_syn(achl_tcp_header))
	  ++usl_orig_dlen;
	if (m_get_tcp_fin(achl_tcp_header))
	  ++usl_orig_dlen;

        m_set_tcp_seqn(achp_answer + 20, 0);
        m_set_tcp_ackn(achp_answer + 20,
                       m_get_tcp_seqn(achl_tcp_header) + usl_orig_dlen);
        m_set_tcp_ack(achp_answer + 20, 1);
    }

    usl_part_chksum = m_calc_ip_tcp_pseudo_chksum(achp_answer);
    m_set_tcp_chksum(achp_answer + 20,
                     m_calc_tcp_chksum(achp_answer + 20, 0, usl_part_chksum));

    return 40;
}

uint32_t m_ip6_tcp_answer_reset(char* achp_answer, uint32_t ump_alen,
                                const char* achp_header, uint32_t ump_hlen)
{
    uint16_t usl_orig_dlen;
    uint16_t usl_part_chksum;

    if (ump_alen < 60 || ump_hlen < 60 ||
        !m_is_ip6_size_ok(achp_header, ump_hlen) ||
        m_get_ip6_nh(achp_header) != 6 ||
        !m_is_tcp_size_ok(achp_header + 40, ump_hlen - 40,
                          m_get_ip6_plen(achp_header)) ||
        m_get_tcp_rst(achp_header + 40)) {

        return 0;
    }

    m_set_ip6_version(achp_answer, 6);
    m_set_ip6_tcls(achp_answer, 0);
    m_set_ip6_flow(achp_answer, 0);
    m_set_ip6_plen(achp_answer, 20);
    m_set_ip6_nh(achp_answer, 6);
    m_set_ip6_hlim(achp_answer, 128);
    m_set_ip6_src_addr(achp_answer, m_get_ip6_dst_addr(achp_header));
    m_set_ip6_dst_addr(achp_answer, m_get_ip6_src_addr(achp_header));

    m_set_tcp_src_port(achp_answer + 40, m_get_tcp_dst_port(achp_header + 40));
    m_set_tcp_dst_port(achp_answer + 40, m_get_tcp_src_port(achp_header + 40));
    m_set_calc_tcp_hlen(achp_answer + 40, 20);
    m_set_tcp_resv(achp_answer + 40, 0);
    m_set_tcp_flags(achp_answer + 40, 0);
    m_set_tcp_rst(achp_answer + 40, 1);
    m_set_tcp_window(achp_answer + 40, 0);
    m_set_tcp_urgent(achp_answer + 40, 0);

    if (m_get_tcp_ack(achp_header + 40)) {
        m_set_tcp_seqn(achp_answer + 40, m_get_tcp_ackn(achp_header + 40));
        m_set_tcp_ackn(achp_answer + 40, 0);
    } else {
        usl_orig_dlen = m_get_ip6_plen(achp_header) -
            m_get_calc_tcp_hlen(achp_header + 40);
	if (m_get_tcp_syn(achp_header + 40))
	  ++usl_orig_dlen;
	if (m_get_tcp_fin(achp_header + 40))
	  ++usl_orig_dlen;

        m_set_tcp_seqn(achp_answer + 40, 0);
        m_set_tcp_ackn(achp_answer + 40,
                       m_get_tcp_seqn(achp_header + 40) + usl_orig_dlen);
        m_set_tcp_ack(achp_answer + 40, 1);
    }

    usl_part_chksum = m_calc_ip6_tcp_pseudo_chksum(achp_answer);
    m_set_tcp_chksum(achp_answer + 40,
                     m_calc_tcp_chksum(achp_answer + 40, 0, usl_part_chksum));

    return 60;
}
