/******************************************************************************
 * File name: tcpip_hdr.cpp
 *
 * Implementation of non-inline functions for tcpip_hdr.h
 *
 * Requires C++.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/

// required for hob-tun01.h
#ifdef HL_UNIX
#include "hob-hunix01.h"
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include <iostream>

#ifdef B090317
#include "int_types.h"
#include "misc.h"
#include "tcpip_hdr.h"
#endif
#include "hob-avl03.h"
/* new 19.03.09 start */
#include <hob-xslhcla1.hpp>
#include <hob-netw-01.h>
#include <string>
//#include <map>
//#include <list>
#include <stddef.h>
#include <iostream>
//#include "hob-xslcontr.h"
#include "hob-tun01.h"
#include "hob-htcp-int-types.h"
#include "hob-htcp.h"
#include "hob-htcp-bit-reference.h"
#include "hob-htcp-tcpip-hdr.h"
#include "hob-htcp-misc.h"
//#include "hob-htcp-connection.h"
//#include "hob-session01.h"
//#include "hob-htcp-session.h"
//#include "hob-tun02.h"
/* new 19.03.09 end */

// IP

/**
 * \brief Checks the validity of the IP packet.
 *
 * The packet must have version 4, a valid header length (more than 5)
 * and a valid total length (more than four times the header
 * length). The header checksum is not checked by this function.
 *
 * \return true if the packet is valid, false otherwise.
 */
bool ip_packet::packet_ok(uint32 size) const
{
    if (size < 20)
        return false;

    if (version() != 4)
        return false;

    uint32 hlen = header_length();
    if (hlen < 5)
        return false;
    hlen *= 4;

    uint32 len = total_length();
    if (len > size || len < hlen)
        return false;

    len -= hlen;

    if (20 + fragment_offset() * 8 + len > 65535)
        return false;

    return true;
}

/**
 * \brief Calculates the IP header checksum for the IP packet.
 *
 * Note that 0x0000 and 0xffff are both equal to zero in ones
 * complement.
 *
 * \return the correct IP header checksum.
 */
uint16 ip_packet::calculate_checksum() const
{
    uint32 sum = 0;
    uint32 sumlo = 0;

    int len = real_header_length();
    const_pointer ptr = header();

    for (int i = 0; i < 10; i += 2) {
        sum += *ptr++;
        sumlo += *ptr++;
    }
    ptr+= 2;
    for (int i = 12; i < len; i += 2) {
        sum += *ptr++;
        sumlo += *ptr++;
    }

    sum <<= 8;
    sum += sumlo;

    sum = (sum & 0xffff) + (sum >> 16);
    sum += sum >> 16;

    return sum == 0xffff ? sum : ~sum & 0xffff;
}

ip_options::ip_options(const ip_packet& packet)
    : options(packet.options()),
      end_options(packet.data())
{
    check_if_end();
}

bool ip_options::end_of_options() const
{
    return options == end_options;
}

void ip_options::goto_next_option()
{
    options += option_length();
    check_if_end();
}

uint8 ip_options::option_type() const
{
    return *options;
}

uint8 ip_options::option_length() const
{
    if ((*options & 0x1f) == 1)
        return 1;
    return *(options + 1);
}

bool ip_options::option_copied() const
{
    return (option_type() & 0x80) == 0x80;
}

uint8 ip_options::option_class() const
{
    return (option_type() >> 5) & 0x03;
}

uint8 ip_options::option_number() const
{
    return option_type() & 0x1f;
}

ip_options::const_pointer ip_options::option() const
{
    return options;
}

void ip_options::check_if_end()
{
    if (options == end_options)
        return;

    switch (*options & 0x1f) {
    case 0:
        options = end_options;
        break;
    case 1:
        break;
    default:
        if (options + 1 == end_options ||
            options + *(options + 1) > end_options)
            options = end_options;
    }
}

// TCP

uint16 tcp_segment::calculate_tcp_checksum(const_pointer th) const
{
    uint32 sum = 0;
    uint32 sumlo = 0;

    const_pointer ptr = this->header() + 9;
    sumlo += *ptr;

    ptr += 3;
    for (int i = 12; i < 20; i += 2) {
        sum += *ptr++;
        sumlo += *ptr++;
    }

    uint16 len = tcp_total_length();
    sum += (len & 0xff00) >> 8;
    sumlo += len & 0x00ff;

    ptr = th;

    --len;
    for (int i = 0; i < 16; i += 2) {
        sum += *ptr++;
        sumlo += *ptr++;
    }
    ptr += 2;
    for (uint16 i = 18; i < len; i += 2) {
        sum += *ptr++;
        sumlo += *ptr++;
    }
    if (len % 2 == 0)
        sum += *ptr;

    sum <<= 8;
    sum += sumlo;

    sum = (sum & 0xffff) + (sum >> 16);
    sum += sum >> 16;

    return sum == 0xffff ? sum : ~sum & 0xffff;
}

uint16 tcp_segment::calculate_tcp_checksum(const_pointer th,
                                           dsd_gather_i_1* ads_payload,
                                           char* ach_cur) const
{
    uint32 sum = 0;
    uint32 sumlo = 0;

    const_pointer ptr = this->header() + 9;
    sumlo += *ptr;

    ptr += 3;
    for (int i = 12; i < 20; i += 2) {
        sum += *ptr++;
        sumlo += *ptr++;
    }

    uint16 len = tcp_total_length();
    sum += (len & 0xff00) >> 8;
    sumlo += len & 0x00ff;

    ptr = th;

    len = real_tcp_header_length(th);
    for (int i = 0; i < 16; i += 2) {
        sum += *ptr++;
        sumlo += *ptr++;
    }
    ptr += 2;
    for (uint16 i = 18; i < len; i += 2) {
        sum += *ptr++;
        sumlo += *ptr++;
    }

    len = tcp_data_length(th);

    if (len > 0) {
        for (uint16 i = 0; i < len; ++i) {
            while (ach_cur == ads_payload->achc_ginp_end) {
                ads_payload = ads_payload->adsc_next;
                ach_cur = ads_payload->achc_ginp_cur;
            }
            uint8 ut_c = static_cast<uint8>(*ach_cur++);
            if (i % 2 == 0)
                sum += ut_c;
            else
                sumlo += ut_c;
        }
    }

    sum <<= 8;
    sum += sumlo;

    sum = (sum & 0xffff) + (sum >> 16);
    sum += sum >> 16;

    return sum == 0xffff ? sum : ~sum & 0xffff;
}

bool tcp_segment::tcp_segment_ok() const
{
    if (this->protocol() != 6)
        return false;

    if (this->is_fragment())
        return false;

    const_pointer th = tcp_header();

    uint16 tcp_len = tcp_total_length();
    if (tcp_len < 20)
        return false;
    uint8 hlen = tcp_header_length(th);
    if (hlen < 5)
        return false;
    hlen *= 4;
    if (tcp_len < hlen)
        return false;

    return true;
}

tcp_options::tcp_options(const tcp_segment& segment)
    : options(segment.tcp_options()),
      end_options(segment.tcp_data())
{
    check_if_end();
}

tcp_options::tcp_options(const tcp_segment& segment, const_pointer th)
    : options(segment.tcp_options(th)),
      end_options(segment.tcp_data(th))
{
    check_if_end();
}

bool tcp_options::end_of_options() const
{
    return options == end_options;
}

void tcp_options::goto_next_option()
{
    options += option_length();
    check_if_end();
}

uint8 tcp_options::option_type() const
{
    return *options;
}

uint8 tcp_options::option_length() const
{
    return *(options + 1);
}

tcp_options::const_pointer tcp_options::option() const
{
    return options;
}

void tcp_options::check_if_end()
{
    while (options != end_options) {
        switch (*options) {
        case 0:
            options = end_options;
            break;
        case 1:
            ++options;
            break;
        default:
            if (options +1 == end_options ||
                options + *(options + 1) > end_options)
                options = end_options;
            return;
        }
    }
}

// output

std::ostream& operator<<(std::ostream& os, const ip_packet& packet)
{
    uint32 address = packet.source_address();
    os << ((address >> 24) & 0xff) << '.' << ((address >> 16) & 0xff) << '.'
       << ((address >> 8) & 0xff) << '.' << (address & 0xff) << '>';
    address = packet.destination_address();
    os << ((address >> 24) & 0xff) << '.' << ((address >> 16) & 0xff) << '.'
       << ((address >> 8) & 0xff) << '.' << (address & 0xff);

    os << ' ' << int(packet.protocol());

    os << ' ' << packet.total_length();
    if (packet.header_length() != 5)
        os << '(' << int(packet.header_length() * 4) << ')';

    if (packet.fragment_offset() != 0 || packet.mf() != 0) {
        os << ' ' << m_hex_0x(packet.identification(), 4)
           << ':' << packet.fragment_offset();
        if (packet.mf() != 0)
            os << " M";
    }
    if (packet.df() != 0)
        os << " D";

    if (!packet.checksum_ok())
        os << " CHK";

    return os;
}

std::ostream& putpacket(std::ostream& os, const ip_packet& packet)
{
    os << "Version               : " << int(packet.version()) << '\n';
    os << "Header length         : " << int(packet.header_length())
       << " x 4 octets\n";
    os << "Type of service       : " << m_hex_0x(packet.type_of_service(), 2)
       << '\n';
    os << "Total length          : " << packet.total_length() << " octets\n";
    os << "Identification        : " << m_hex_0x(packet.identification(), 4)
       << '\n';
    os << "Fragmentation flags   : " << m_hex_0x(packet.flags(), 1);
    if (packet.flags() != 0) {
        std::string comma = "";
        os << " (";
        if (packet.df() != 0) {
            os << "DF";
            comma = ", ";
        }
        if (packet.mf() != 0) {
            os << comma << "MF";
        }
        os << ")";
    }
    os << '\n';
    os << "Fragment offset       : " << packet.fragment_offset()
       << " x 8 octets\n";
    os << "Time to live          : " << int(packet.time_to_live()) << '\n';
    os << "Protocol              : " << int(packet.protocol()) << '\n';
    os << "Header checksum       : " << m_hex_0x(packet.checksum(), 4) << ' '
       << (packet.checksum_ok() ? "(OK)" : "(error)") << '\n';
    uint32 address = packet.source_address();
    os << "Source IP address     : "
       << ((address >> 24) & 0xff) << '.' << ((address >> 16) & 0xff) << '.'
       << ((address >> 8) & 0xff) << '.' << (address & 0xff) << '\n';
    address = packet.destination_address();
    os << "Destination IP address: "
       << ((address >> 24) & 0xff) << '.' << ((address >> 16) & 0xff) << '.'
       << ((address >> 8) & 0xff) << '.' << (address & 0xff) << '\n';

    if (!packet.packet_ok())
        return os;

    ip_options options(packet);
    if (!options.end_of_options()) {
        os << "\nIP header options:\n";
        do {
            uint8 len = options.option_length();
            uint8 code = options.option_number();
            const uint8* p = options.option();
            os << (code < 10 ? " " : "") << int(code) << ":";
            for (uint8 i = 0; i < len; ++i)
                os << ' ' << m_hex(*p++, 2);
            os << '\n';
            options.goto_next_option();
        } while (!options.end_of_options());
    }

    ip_packet::const_pointer ptr = packet.get();
    uint16 length = packet.total_length();
    for (uint16 i = 0; i < length; ++i) {
        switch (i % 16) {
        case 0:
            os << '\n' << m_hex(i, 4) << ':';
            break;
        case 8:
            os << ' ';
            break;
        }
        os << ' ' << m_hex(*ptr++, 2);
    }
    os << '\n';

    return os;
}

std::ostream& operator<<(std::ostream& os, const tcp_segment& packet)
{
    ip_packet::const_pointer ptr = packet.tcp_header();

    uint32 address = packet.source_address();
    os << ((address >> 24) & 0xff) << '.' << ((address >> 16) & 0xff) << '.'
       << ((address >> 8) & 0xff) << '.' << (address & 0xff)
       << ':' << packet.source_port(ptr) << '>';
    address = packet.destination_address();
    os << ((address >> 24) & 0xff) << '.' << ((address >> 16) & 0xff) << '.'
       << ((address >> 8) & 0xff) << '.' << (address & 0xff)
       << ':' << packet.destination_port(ptr);

    os << ' ' << packet.total_length();
    if (packet.header_length() != 5 || packet.tcp_header_length(ptr) != 5)
        os << '(' << int(packet.header_length() * 4)
           << ',' << int(packet.tcp_header_length(ptr) * 4) << ')';

    if (packet.syn(ptr) != 0)
        os << " S";
    os << ' ' << packet.sequence_number(ptr);

    if (packet.ack(ptr) != 0)
        os << " A" << packet.acknowledgement_number(ptr)
           << 'w' << packet.window_size(ptr);

    if (packet.urg(ptr) != 0)
        os << " U" << packet.urgent_pointer(ptr);

    if (packet.fin(ptr) || packet.psh(ptr) || packet.rst(ptr))
        os << ' ';
    if (packet.fin(ptr))
        os << 'F';
    if (packet.psh(ptr))
        os << 'P';
    if (packet.rst(ptr))
        os << 'R';

    if (!packet.checksum_ok())
        os << " CHK";
    if (!packet.tcp_checksum_ok(ptr))
        os << " TCPCHK";

    return os;
}

std::ostream& putsegment(std::ostream& os, const tcp_segment& packet)
{
    os << "Version               : " << int(packet.version()) << '\n';
    os << "Header length         : " << int(packet.header_length())
       << " x 4 octets\n";
    os << "Type of service       : " << m_hex_0x(packet.type_of_service(), 2)
       << '\n';
    os << "Total length          : " << packet.total_length() << " octets\n";
    os << "Identification        : " << m_hex_0x(packet.identification(), 4)
       << '\n';
    os << "Fragmentation flags   : " << m_hex_0x(packet.flags(), 1);
    if (packet.flags() != 0) {
        std::string comma = "";
        os << " (";
        if (packet.df() != 0) {
            os << "DF";
            comma = ", ";
        }
        if (packet.mf() != 0) {
            os << comma << "MF";
        }
        os << ")";
    }
    os << '\n';
    os << "Fragment offset       : " << packet.fragment_offset()
       << " x 8 octets\n";
    os << "Time to live          : " << int(packet.time_to_live()) << '\n';
    os << "Protocol              : " << int(packet.protocol()) << '\n';
    os << "Header checksum       : " << m_hex_0x(packet.checksum(), 4)
       << ' ' << (packet.checksum_ok() ? "(OK)" : "(error)") << '\n';
    uint32 address = packet.source_address();
    os << "Source IP address     : "
       << ((address >> 24) & 0xff) << '.' << ((address >> 16) & 0xff) << '.'
       << ((address >> 8) & 0xff) << '.' << (address & 0xff) << '\n';
    address = packet.destination_address();
    os << "Destination IP address: "
       << ((address >> 24) & 0xff) << '.' << ((address >> 16) & 0xff) << '.'
       << ((address >> 8) & 0xff) << '.' << (address & 0xff) << '\n';

    if (!packet.packet_ok())
        return os;

    ip_options options(packet);
    if (!options.end_of_options()) {
        os << "\nIP header options:\n";
        do {
            uint8 len = options.option_length();
            uint8 code = options.option_number();
            const uint8* p = options.option();
            os << (code < 10 ? " " : "") << int(code) << ":";
            for (uint8 i = 0; i < len; ++i)
                os << ' ' << m_hex(*p++, 2);
            os << '\n';
            options.goto_next_option();
        } while (!options.end_of_options());
    }

    if (packet.tcp_segment_ok()) {
        tcp_segment::const_pointer ptr = packet.tcp_header();

        os << "Source port           : " << packet.source_port(ptr) << '\n';
        os << "Destination port      : "
           << packet.destination_port(ptr) << '\n';
        os << "Sequence number       : " << packet.sequence_number(ptr) << '\n';
        os << "Acknowledgement number: "
           << packet.acknowledgement_number(ptr) << '\n';
        os << "TCP header length     : "
           << int(packet.tcp_header_length(ptr)) << " x 4 octets\n";
        os << "Reserved bits         : "
           << m_hex_0x(packet.tcp_reserved(ptr), 2) << '\n';
        os << "TCP flags             : " << m_hex_0x(packet.tcp_flags(ptr), 2);
        if (packet.tcp_flags(ptr) != 0) {
            std::string comma = "";
            os << " (";
            if (packet.urg(ptr) != 0) {
                os << "URG";
                comma = ", ";
            }
            if (packet.ack(ptr) != 0) {
                os << comma << "ACK";
                comma = ", ";
            }
            if (packet.psh(ptr) != 0) {
                os << comma << "PSH";
                comma = ", ";
            }
            if (packet.rst(ptr) != 0) {
                os << comma << "RST";
                comma = ", ";
            }
            if (packet.syn(ptr) != 0) {
                os << comma << "SYN";
                comma = ", ";
            }
            if (packet.fin(ptr) != 0) {
                os << comma << "FIN";
            }
            os << ")";
        }
        os << '\n';
        os << "Window size           : " << packet.window_size(ptr) << '\n';
        os << "TCP checksum          : "
           << m_hex_0x(packet.tcp_checksum(ptr), 4) << ' '
           << (packet.tcp_checksum_ok(ptr) ? "(OK)" : "(error)") << '\n';
        os << "Urgent pointer        : " << packet.urgent_pointer(ptr) << '\n';


        tcp_options options(packet);
        if (!options.end_of_options()) {
            os << "\nTCP header options:\n";
            do {
                uint8 len = options.option_length();
                uint8 code = options.option_type();
                const uint8* p = options.option();
                os << (code < 100 ? " " : "") << (code < 10 ? " " : "")
                   << int(code) << ":";
                for (uint8 i = 0; i < len; ++i)
                    os << ' ' << m_hex(*p++, 2);
                os << '\n';
                options.goto_next_option();
            } while (!options.end_of_options());
        }
    }

    tcp_segment::const_pointer ptr = packet.get();
    uint16 length = packet.total_length();
    for (uint16 i = 0; i < length; ++i) {
        switch (i % 16) {
        case 0:
            os << '\n' << m_hex(i, 4) << ':';
            break;
        case 8:
            os << ' ';
            break;
        }
        os << ' ' << m_hex(*ptr++, 2);
    }
    os << '\n';

    return os;
}
