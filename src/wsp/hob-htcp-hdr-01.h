/******************************************************************************
 * File name: hob-htcp-hdr-01.h
 *
 * Utility for handling TCP/IP headers.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2011
 ******************************************************************************/

#ifndef HOB_HTCP_HDR_01_H
#define HOB_HTCP_HDR_01_H


#ifdef DEF_INCLUDE_HEADERS
#include <string.h>
#include "hob-htcp-int-01.h"
#endif /* DEF_INCLUDE_HEADERS */

#ifdef DEF_TCPIP_INLINE
#error "DEF_TCPIP_INLINE already defined"
#elif defined __cplusplus
#define DEF_TCPIP_INLINE inline
#elif defined __GNUC__
#define DEF_TCPIP_INLINE __inline__
#elif defined _MSC_VER
#define DEF_TCPIP_INLINE __inline
#elif __STDC_VERSION__ >= 199901L /* C99 */
#define DEF_TCPIP_INLINE static inline
#else
#define DEF_TCPIP_INLINE static
#endif

/* IPv4 get */

DEF_TCPIP_INLINE uint8_t m_get_ip_version(const char* achp_ip_header)
{
    return ((uint8_t)achp_ip_header[0] >> 4) & 0x0f;
}

DEF_TCPIP_INLINE uint8_t m_get_ip_hlen_4(const char* achp_ip_header)
{
    return (uint8_t)achp_ip_header[0] & 0x0f;
}

DEF_TCPIP_INLINE uint8_t m_get_calc_ip_hlen(const char* achp_ip_header)
{
    return m_get_ip_hlen_4(achp_ip_header) * 4;
}

DEF_TCPIP_INLINE uint8_t m_get_ip_tos(const char* achp_ip_header)
{
    return (uint8_t)achp_ip_header[1];
}

DEF_TCPIP_INLINE uint16_t m_get_ip_tlen(const char* achp_ip_header)
{
    return ((uint8_t)achp_ip_header[2] << 8) | (uint8_t)achp_ip_header[3];
}

DEF_TCPIP_INLINE uint16_t m_get_calc_ip_plen(const char* achp_ip_header)
{
    return m_get_ip_tlen(achp_ip_header) - m_get_calc_ip_hlen(achp_ip_header);
}

DEF_TCPIP_INLINE uint16_t m_get_ip_id(const char* achp_ip_header)
{
    return ((uint8_t)achp_ip_header[4] << 8) | (uint8_t)achp_ip_header[5];
}

DEF_TCPIP_INLINE uint8_t m_get_ip_flags(const char* achp_ip_header)
{
    return ((uint8_t)achp_ip_header[6] >> 5) & 0x07;
}

DEF_TCPIP_INLINE uint8_t m_get_ip_df(const char* achp_ip_header)
{
    return ((uint8_t)achp_ip_header[6] >> 6) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_ip_mf(const char* achp_ip_header)
{
    return ((uint8_t)achp_ip_header[6] >> 5) & 0x01;
}

DEF_TCPIP_INLINE uint16_t m_get_ip_fofs_8(const char* achp_ip_header)
{
    return (((uint8_t)achp_ip_header[6] & 0x1f) << 8) |
	(uint8_t)achp_ip_header[7];
}

DEF_TCPIP_INLINE uint16_t m_get_calc_ip_fofs(const char* achp_ip_header)
{
    return m_get_ip_fofs_8(achp_ip_header) * 8;
}

DEF_TCPIP_INLINE uint8_t m_get_ip_ttl(const char* achp_ip_header)
{
    return (uint8_t)achp_ip_header[8];
}

DEF_TCPIP_INLINE uint8_t m_get_ip_prot(const char* achp_ip_header)
{
    return (uint8_t)achp_ip_header[9];
}

DEF_TCPIP_INLINE uint16_t m_get_ip_chksum(const char* achp_ip_header)
{
    return ((uint8_t)achp_ip_header[10] << 8) | (uint8_t)achp_ip_header[11];
}

DEF_TCPIP_INLINE uint32_t m_get_ip_src_addr(const char* achp_ip_header)
{
    return ((uint8_t)achp_ip_header[12] << 24) |
	((uint8_t)achp_ip_header[13] << 16) |
        ((uint8_t)achp_ip_header[14] << 8) |
	(uint8_t)achp_ip_header[15];
}

DEF_TCPIP_INLINE uint32_t m_get_ip_dst_addr(const char* achp_ip_header)
{
    return ((uint8_t)achp_ip_header[16] << 24) |
	((uint8_t)achp_ip_header[17] << 16) |
        ((uint8_t)achp_ip_header[18] << 8) |
	(uint8_t)achp_ip_header[19];
}

DEF_TCPIP_INLINE const char* m_get_ip_src_addr_buf(const char* achp_ip_header)
{
    return achp_ip_header + 12;
}

DEF_TCPIP_INLINE const char* m_get_ip_dst_addr_buf(const char* achp_ip_header)
{
    return achp_ip_header + 16;
}


/* IPv4 set */

DEF_TCPIP_INLINE void m_set_ip_version(char* achp_ip_header, uint8_t utp_ver)
{
    achp_ip_header[0] = ((uint8_t)achp_ip_header[0] & 0x0f) |
        ((utp_ver << 4) & 0xf0);
}

DEF_TCPIP_INLINE void m_set_ip_hlen_4(char* achp_ip_header, uint8_t utp_hl)
{
    achp_ip_header[0] = ((uint8_t)achp_ip_header[0] & 0xf0) | (utp_hl & 0x0f);
}

DEF_TCPIP_INLINE void m_set_calc_ip_hlen(char* achp_ip_header, uint8_t utp_hl)
{
    m_set_ip_hlen_4(achp_ip_header, utp_hl / 4);
}

DEF_TCPIP_INLINE void m_set_ip_tos(char* achp_ip_header, uint8_t utp_tos)
{
    achp_ip_header[1] = utp_tos;
}

DEF_TCPIP_INLINE void m_set_ip_tlen(char* achp_ip_header, uint16_t usp_tl)
{
    achp_ip_header[2] = usp_tl >> 8;
    achp_ip_header[3] = (char)usp_tl;
}

DEF_TCPIP_INLINE void m_set_ip_id(char* achp_ip_header, uint16_t usp_id)
{
    achp_ip_header[4] = usp_id >> 8;
    achp_ip_header[5] = (char)usp_id;
}

DEF_TCPIP_INLINE void m_set_ip_flags(char* achp_ip_header, uint8_t utp_fs)
{
    achp_ip_header[6] = ((uint8_t)achp_ip_header[6] & 0x1f) |
        ((utp_fs << 5) & 0xe0);
}

DEF_TCPIP_INLINE void m_set_ip_df(char* achp_ip_header, uint8_t utp_df)
{
    achp_ip_header[6] = ((uint8_t)achp_ip_header[6] & 0xbf) |
        ((utp_df << 6) & 0x40);
}

DEF_TCPIP_INLINE void m_set_ip_mf(char* achp_ip_header, uint8_t utp_mf)
{
    achp_ip_header[6] = ((uint8_t)achp_ip_header[6] & 0xdf) |
        ((utp_mf << 5) & 0x20);
}

DEF_TCPIP_INLINE void m_set_ip_fofs_8(char* achp_ip_header, uint16_t usp_ofs)
{
    achp_ip_header[6] = ((uint8_t)achp_ip_header[6] & 0xe0) |
        ((usp_ofs >> 8) & 0x1f);
    achp_ip_header[7] = (char)usp_ofs;
}

DEF_TCPIP_INLINE void m_set_calc_ip_fofs(char* achp_ip_header, uint16_t usp_ofs)
{
    m_set_ip_fofs_8(achp_ip_header, usp_ofs / 8);
}

DEF_TCPIP_INLINE void m_set_ip_ttl(char* achp_ip_header, uint8_t utp_ttl)
{
    achp_ip_header[8] = utp_ttl;
}

DEF_TCPIP_INLINE void m_set_ip_prot(char* achp_ip_header, uint8_t utp_prot)
{
    achp_ip_header[9] = utp_prot;
}

DEF_TCPIP_INLINE void m_set_ip_chksum(char* achp_ip_header, uint16_t usp_chksum)
{
    achp_ip_header[10] = usp_chksum >> 8;
    achp_ip_header[11] = (char)usp_chksum;
}

DEF_TCPIP_INLINE void m_set_ip_src_addr(char* achp_ip_header, uint32_t ump_addr)
{
    achp_ip_header[12] = ump_addr >> 24;
    achp_ip_header[13] = ump_addr >> 16;
    achp_ip_header[14] = ump_addr >> 8;
    achp_ip_header[15] = (char)ump_addr;
}

DEF_TCPIP_INLINE void m_set_ip_dst_addr(char* achp_ip_header, uint32_t ump_addr)
{
    achp_ip_header[16] = ump_addr >> 24;
    achp_ip_header[17] = ump_addr >> 16;
    achp_ip_header[18] = ump_addr >> 8;
    achp_ip_header[19] = (char)ump_addr;
}

DEF_TCPIP_INLINE void m_set_ip_src_addr_buf(char* achp_ip_header,
                                            const char* autp_addr)
{
    memcpy(achp_ip_header + 12, autp_addr, 4);
}

DEF_TCPIP_INLINE void m_set_ip_dst_addr_buf(char* achp_ip_header,
                                            const char* autp_addr)
{
    memcpy(achp_ip_header + 16, autp_addr, 4);
}


/* IPv6 get */

DEF_TCPIP_INLINE uint8_t m_get_ip6_version(const char* achp_ip6_header)
{
    return ((uint8_t)achp_ip6_header[0] >> 4) & 0x0f;
}

DEF_TCPIP_INLINE uint8_t m_get_ip6_tcls(const char* achp_ip6_header)
{
    return (((uint8_t)achp_ip6_header[0] << 4) & 0xf0) |
        (((uint8_t)achp_ip6_header[1] >> 4) & 0x0f);
}

DEF_TCPIP_INLINE uint32_t m_get_ip6_flow(const char* achp_ip6_header)
{
    return (((uint8_t)achp_ip6_header[1] << 16) & 0xf0000) |
        ((uint8_t)achp_ip6_header[2] << 8) | (uint8_t)achp_ip6_header[3];
}

DEF_TCPIP_INLINE uint16_t m_get_ip6_plen(const char* achp_ip6_header)
{
    return ((uint8_t)achp_ip6_header[4] << 8) | (uint8_t)achp_ip6_header[5];
}

DEF_TCPIP_INLINE uint8_t m_get_ip6_nh(const char* achp_ip6_header)
{
    return (uint8_t)achp_ip6_header[6];
}

DEF_TCPIP_INLINE uint8_t m_get_ip6_hlim(const char* achp_ip6_header)
{
    return (uint8_t)achp_ip6_header[7];
}

DEF_TCPIP_INLINE const char* m_get_ip6_src_addr(const char* achp_ip6_header)
{
    return achp_ip6_header + 8;
}

DEF_TCPIP_INLINE const char* m_get_ip6_dst_addr(const char* achp_ip6_header)
{
    return achp_ip6_header + 24;
}


/* IPv6 set */

DEF_TCPIP_INLINE void m_set_ip6_version(char* achp_ip6_header, uint8_t utp_ver)
{
    achp_ip6_header[0] = ((uint8_t)achp_ip6_header[0] & 0x0f) |
        ((utp_ver << 4) & 0xf0);
}

DEF_TCPIP_INLINE void m_set_ip6_tcls(char* achp_ip6_header, uint8_t utp_tcls)
{
    achp_ip6_header[0] = ((uint8_t)achp_ip6_header[0] & 0xf0) |
        ((utp_tcls >> 4) & 0x0f);
    achp_ip6_header[1] = ((uint8_t)achp_ip6_header[1] & 0x0f) |
        ((utp_tcls << 4) & 0xf0);
}

DEF_TCPIP_INLINE void m_set_ip6_flow(char* achp_ip6_header, uint32_t ump_flow)
{
    achp_ip6_header[1] = ((uint8_t)achp_ip6_header[1] & 0xf0) |
        ((ump_flow >> 16) & 0x0f);
    achp_ip6_header[2] = ump_flow >> 8;
    achp_ip6_header[3] = (char)ump_flow;
}

DEF_TCPIP_INLINE void m_set_ip6_plen(char* achp_ip6_header, uint16_t usp_plen)
{
    achp_ip6_header[4] = usp_plen >> 8;
    achp_ip6_header[5] = (char)usp_plen;
}

DEF_TCPIP_INLINE void m_set_ip6_nh(char* achp_ip6_header, uint8_t utp_nh)
{
    achp_ip6_header[6] = utp_nh;
}

DEF_TCPIP_INLINE void m_set_ip6_hlim(char* achp_ip6_header, uint8_t utp_hlim)
{
    achp_ip6_header[7] = utp_hlim;
}

DEF_TCPIP_INLINE void m_set_ip6_src_addr(char* achp_ip6_header,
                                         const char* autp_addr)
{
    memcpy(achp_ip6_header + 8, autp_addr, 16);
}

DEF_TCPIP_INLINE void m_set_ip6_dst_addr(char* achp_ip6_header,
                                         const char* autp_addr)
{
    memcpy(achp_ip6_header + 24, autp_addr, 16);
}


/* TCP get */

DEF_TCPIP_INLINE uint16_t m_get_tcp_src_port(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[0] << 8) | (uint8_t)achp_tcp_header[1];
}

DEF_TCPIP_INLINE uint16_t m_get_tcp_dst_port(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[2] << 8) | (uint8_t)achp_tcp_header[3];
}

DEF_TCPIP_INLINE uint32_t m_get_tcp_seqn(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[4] << 24) |
	((uint8_t)achp_tcp_header[5] << 16) |
        ((uint8_t)achp_tcp_header[6] << 8) |
	(uint8_t)achp_tcp_header[7];
}

DEF_TCPIP_INLINE uint32_t m_get_tcp_ackn(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[8] << 24) |
	((uint8_t)achp_tcp_header[9] << 16) |
        ((uint8_t)achp_tcp_header[10] << 8) |
	(uint8_t)achp_tcp_header[11];
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_hlen_4(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[12] >> 4) & 0x0f;
}

DEF_TCPIP_INLINE uint8_t m_get_calc_tcp_hlen(const char* achp_tcp_header)
{
    return m_get_tcp_hlen_4(achp_tcp_header) * 4;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_resv(const char* achp_tcp_header)
{
    return (((uint8_t)achp_tcp_header[12] << 2) & 0x3c) |
        (((uint8_t)achp_tcp_header[13] >> 6) & 0x03);
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_flags(const char* achp_tcp_header)
{
    return (uint8_t)achp_tcp_header[13] & 0x3f;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_urg(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[13] >> 5) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_ack(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[13] >> 4) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_psh(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[13] >> 3) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_rst(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[13] >> 2) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_syn(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[13] >> 1) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_fin(const char* achp_tcp_header)
{
    return (uint8_t)achp_tcp_header[13] & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_flags_urg(uint8_t utp_tcp_flags)
{
    return (utp_tcp_flags >> 5) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_flags_ack(uint8_t utp_tcp_flags)
{
    return (utp_tcp_flags >> 4) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_flags_psh(uint8_t utp_tcp_flags)
{
    return (utp_tcp_flags >> 3) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_flags_rst(uint8_t utp_tcp_flags)
{
    return (utp_tcp_flags >> 2) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_flags_syn(uint8_t utp_tcp_flags)
{
    return (utp_tcp_flags >> 1) & 0x01;
}

DEF_TCPIP_INLINE uint8_t m_get_tcp_flags_fin(uint8_t utp_tcp_flags)
{
    return utp_tcp_flags & 0x01;
}

DEF_TCPIP_INLINE uint16_t m_get_tcp_window(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[14] << 8) | (uint8_t)achp_tcp_header[15];
}

DEF_TCPIP_INLINE uint16_t m_get_tcp_chksum(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[16] << 8) | (uint8_t)achp_tcp_header[17];
}

DEF_TCPIP_INLINE uint16_t m_get_tcp_urgent(const char* achp_tcp_header)
{
    return ((uint8_t)achp_tcp_header[18] << 8) | (uint8_t)achp_tcp_header[19];
}


/* TCP set */

DEF_TCPIP_INLINE void m_set_tcp_src_port(char* achp_tcp_header,
                                         uint16_t asp_port)
{
    achp_tcp_header[0] = asp_port >> 8;
    achp_tcp_header[1] = (char)asp_port;
}

DEF_TCPIP_INLINE void m_set_tcp_dst_port(char* achp_tcp_header,
                                         uint16_t asp_port)
{
    achp_tcp_header[2] = asp_port >> 8;
    achp_tcp_header[3] = (char)asp_port;
}

DEF_TCPIP_INLINE void m_set_tcp_seqn(char* achp_tcp_header, uint32_t ump_seqn)
{
    achp_tcp_header[4] = ump_seqn >> 24;
    achp_tcp_header[5] = ump_seqn >> 16;
    achp_tcp_header[6] = ump_seqn >> 8;
    achp_tcp_header[7] = (char)ump_seqn;
}

DEF_TCPIP_INLINE void m_set_tcp_ackn(char* achp_tcp_header, uint32_t ump_ackn)
{
    achp_tcp_header[8] = ump_ackn >> 24;
    achp_tcp_header[9] = ump_ackn >> 16;
    achp_tcp_header[10] = ump_ackn >> 8;
    achp_tcp_header[11] = (char)ump_ackn;
}

DEF_TCPIP_INLINE void m_set_tcp_hlen_4(char* achp_tcp_header, uint8_t utp_hl)
{
    achp_tcp_header[12] = ((uint8_t)achp_tcp_header[12] & 0x0f) |
	((utp_hl << 4) & 0xf0);
}

DEF_TCPIP_INLINE void m_set_calc_tcp_hlen(char* achp_tcp_header, uint8_t utp_hl)
{
    m_set_tcp_hlen_4(achp_tcp_header, utp_hl / 4);
}

DEF_TCPIP_INLINE void m_set_tcp_resv(char* achp_tcp_header, uint8_t utp_res)
{
    achp_tcp_header[12] = ((uint8_t)achp_tcp_header[12] & 0xf0) |
        ((utp_res >> 2) & 0x0f);
    achp_tcp_header[13] = ((uint8_t)achp_tcp_header[13] & 0x3f) |
        ((utp_res << 6) & 0xc0);
}

DEF_TCPIP_INLINE void m_set_tcp_flags(char* achp_tcp_header, uint8_t utp_fs)
{
    achp_tcp_header[13] = ((uint8_t)achp_tcp_header[13] & 0xc0) |
        (utp_fs & 0x3f);
}

DEF_TCPIP_INLINE void m_set_tcp_urg(char* achp_tcp_header, uint8_t utp_urg)
{
    achp_tcp_header[13] = ((uint8_t)achp_tcp_header[13] & 0xdf) |
        ((utp_urg << 5) & 0x20);
}

DEF_TCPIP_INLINE void m_set_tcp_ack(char* achp_tcp_header, uint8_t utp_ack)
{
    achp_tcp_header[13] = ((uint8_t)achp_tcp_header[13] & 0xef) |
        ((utp_ack << 4) & 0x10);
}

DEF_TCPIP_INLINE void m_set_tcp_psh(char* achp_tcp_header, uint8_t utp_psh)
{
    achp_tcp_header[13] = ((uint8_t)achp_tcp_header[13] & 0xf7) |
        ((utp_psh << 3) & 0x08);
}

DEF_TCPIP_INLINE void m_set_tcp_rst(char* achp_tcp_header, uint8_t utp_rst)
{
    achp_tcp_header[13] = ((uint8_t)achp_tcp_header[13] & 0xfb) |
        ((utp_rst << 2) & 0x04);
}

DEF_TCPIP_INLINE void m_set_tcp_syn(char* achp_tcp_header, uint8_t utp_syn)
{
    achp_tcp_header[13] = ((uint8_t)achp_tcp_header[13] & 0xfd) |
        ((utp_syn << 1) & 0x02);
}

DEF_TCPIP_INLINE void m_set_tcp_fin(char* achp_tcp_header, uint8_t utp_fin)
{
    achp_tcp_header[13] = (achp_tcp_header[13] & 0xfe) | (utp_fin & 0x01);
}

DEF_TCPIP_INLINE uint8_t m_set_tcp_flags_urg(uint8_t utp_tcp_flags,
                                             uint8_t utp_urg)
{
    return (utp_tcp_flags & 0xdf) | ((utp_urg << 5) & 0x20);
}

DEF_TCPIP_INLINE uint8_t m_set_tcp_flags_ack(uint8_t utp_tcp_flags,
                                             uint8_t utp_ack)
{
    return (utp_tcp_flags & 0xef) | ((utp_ack << 4) & 0x10);
}

DEF_TCPIP_INLINE uint8_t m_set_tcp_flags_psh(uint8_t utp_tcp_flags,
                                             uint8_t utp_psh)
{
    return (utp_tcp_flags & 0xf7) | ((utp_psh << 3) & 0x08);
}

DEF_TCPIP_INLINE uint8_t m_set_tcp_flags_rst(uint8_t utp_tcp_flags,
                                             uint8_t utp_rst)
{
    return (utp_tcp_flags & 0xfb) | ((utp_rst << 2) & 0x04);
}

DEF_TCPIP_INLINE uint8_t m_set_tcp_flags_syn(uint8_t utp_tcp_flags,
                                             uint8_t utp_syn)
{
    return (utp_tcp_flags & 0xfd) | ((utp_syn << 1) & 0x02);
}

DEF_TCPIP_INLINE uint8_t m_set_tcp_flags_fin(uint8_t utp_tcp_flags,
                                             uint8_t utp_fin)
{
    return (utp_tcp_flags & 0xfe) | (utp_fin & 0x01);
}

DEF_TCPIP_INLINE void m_set_tcp_window(char* achp_tcp_header, uint16_t usp_win)
{
    achp_tcp_header[14] = usp_win >> 8;
    achp_tcp_header[15] = (char)usp_win;
}

DEF_TCPIP_INLINE void m_set_tcp_chksum(char* achp_tcp_header,
                                       uint16_t usp_chksum)
{
    achp_tcp_header[16] = usp_chksum >> 8;
    achp_tcp_header[17] = (char)usp_chksum;
}

DEF_TCPIP_INLINE void m_set_tcp_urgent(char* achp_tcp_header, uint16_t usp_urg)
{
    achp_tcp_header[18] = usp_urg >> 8;
    achp_tcp_header[19] = (char)usp_urg;
}

#undef DEF_TCPIP_INLINE

static const uint8_t utd_tcp_ack = 0x10;
static const uint8_t utd_tcp_syn = 0x02;
static const uint8_t utd_tcp_syn_ack = 0x12;
static const uint8_t utd_tcp_fin = 0x01;
static const uint8_t utd_tcp_fin_ack = 0x11;
static const uint8_t utd_tcp_rst = 0x04;
static const uint8_t utd_tcp_rst_ack = 0x14;
static const uint8_t utd_tcp_psh = 0x08;
static const uint8_t utd_tcp_psh_ack = 0x18;

#ifdef __cplusplus
extern "C" {
#endif
#if 0
} /* so as not to confuse auto-indentation */
#endif

/* others */

uint16_t m_calc_ip_chksum(const char* achp_ip_header);

/*
 * TCP checksum calculation:
 *
 * To calculate a TCP segment checksum, start with the partial checksum
 * for the pseudo header excluding the length. This is done using
 * m_calc_ip_tcp_pseudo_chksum() or m_calc_ip6_tcp_pseudo_chksum().
 *
 * Next, update the partial checksum for the TCP data. If the TCP data is
 * contiguous, this is done using one call to m_calc_tcp_data_chksum().
 * If the TCP data is in non-contiguous blocks, either
 * m_calc_tcp_data_chksum() or m_calc_tcp_odd_data_chksum() must be called
 * for each block. The offset for the first byte of each block should be
 * used to decide wether to choose the even or odd variant.
 *
 * Finally, m_calc_tcp_chksum() is called with the partial checksum and the
 * data length. The data length is used to complete the pseudo header.
 *
 * Note that m_calc_ip_tcp_pseudo_chksum() or m_calc_ip6_tcp_pseudo_chksum()
 * may be substituted with a call to m_calc_tcp_data_chksum(), with the data
 * and data length parameters pointing to the source and destination
 * IP or IPv6 addresses, and the initial partial checksum parameter set to 6.
 */

uint16_t m_calc_ip_tcp_pseudo_chksum(const char* achp_ip_header);
uint16_t m_calc_ip6_tcp_pseudo_chksum(const char* achp_ip6_header);

uint16_t m_calc_tcp_data_chksum(const char* achp_data, uint32_t ump_len,
                                uint16_t usp_part);
uint16_t m_calc_tcp_odd_data_chksum(const char* achp_data, uint32_t ump_len,
                                    uint16_t usp_part);
uint16_t m_calc_tcp_chksum(const char* achp_tcp_header, uint32_t ump_data_len,
                           uint16_t usp_part);

/*
 * If a TCP packet is modified, the checksum might be updated without a
 * complete recalculation.
 *
 * m_tcp_chksum_add() updates the checksum to include some data. The length
 * in the pseudo header is not updated here. If the data to add has an odd
 * offset, use m_tcp_chksum_odd_add() instead.
 *
 * m_tcp_chksum_sub() and m_tcp_chksum_odd_sub() update the checksum to exclude
 * some data which was previously included in the checksum.
 *
 * If a block of data had an odd offset and was shifted to an even offet,
 * m_tcp_chksum_odd_to_even() should be called. m_tcp_chksum_even_to_odd()
 * works similarly.
 *
 * If the data length of a TCP segment was changed, m_tcp_chksum_change_len()
 * should be called together with the functions described above. The order
 * does not matter.
 */
uint16_t m_tcp_chksum_add(uint16_t usp_chksum,
                          const char* achp_data, uint32_t ump_len);
uint16_t m_tcp_chksum_odd_add(uint16_t usp_chksum,
                              const char* achp_data, uint32_t ump_len);
uint16_t m_tcp_chksum_sub(uint16_t usp_chksum,
                          const char* achp_data, uint32_t ump_len);
uint16_t m_tcp_chksum_odd_sub(uint16_t usp_chksum,
                              const char* achp_data, uint32_t ump_len);
uint16_t m_tcp_chksum_odd_to_even(uint16_t usp_chksum,
                                  const char* achp_data, uint32_t ump_len);
uint16_t m_tcp_chksum_even_to_odd(uint16_t usp_chksum,
                                  const char* achp_data, uint32_t ump_len);
uint16_t m_tcp_chksum_change_len(uint16_t usp_chksum, int32_t ump_add_len);

bool m_is_ip_size_ok(const char* achp_ip_header, uint32_t ump_hsize);
bool m_is_ip6_size_ok(const char* achp_ip6_header, uint32_t ump_hsize);
bool m_is_tcp_size_ok(const char* achp_tcp_header, uint32_t ump_hsize,
                      uint32_t ump_segsize);

const char* m_first_tcp_option(const char* achp_tcp_header,
                               const char* achp_tcp_header_end);
const char* m_next_tcp_option(const char* achp_tcp_option,
                              const char* achp_tcp_header_end);

uint32_t m_ip_tcp_answer_reset(char* achp_answer, uint32_t ump_alen,
                               const char* achp_header, uint32_t ump_hlen,
                               uint16_t usp_id);

uint32_t m_ip6_tcp_answer_reset(char* achp_answer, uint32_t ump_alen,
                                const char* achp_header, uint32_t ump_hlen);

#if 0
{ /* so as not to confuse auto-indentation */
#endif
#ifdef __cplusplus
} /* extern "C" */
#endif


#endif /* HOB_HTCP_HDR_01_H */
