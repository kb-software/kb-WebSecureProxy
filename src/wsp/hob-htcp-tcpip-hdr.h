/******************************************************************************
 * File name: tcpip_hdr.h
 *
 * C++ utility for handling TCP/IP headers.
 *
 * Requires C++.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/
// TODO: IPv6

#ifndef HTCP_TCPIP_HDR_H
#define HTCP_TCPIP_HDR_H

#ifdef DOES_INCL_HEADERS
#include <iostream>
#include <cstddef>

#include "int_types.h"
#include "bit_reference.h"
#include "misc.h"
#include "hob-tun01.h" // for gather
#endif

class ip_packet {

public:

    typedef uint8* pointer;
    typedef const uint8* const_pointer;

    typedef bit_reference<pointer, 0, 8> bitref_0_8;
    typedef bit_reference<pointer, 0, 16> bitref_0_16;
    typedef bit_reference<pointer, 0, 32> bitref_0_32;
    typedef bit_reference<pointer, 0, 4> bitref_0_4;
    typedef bit_reference<pointer, 4, 4> bitref_4_4;
    typedef bit_reference<pointer, 0, 3> bitref_0_3;
    typedef bit_reference<pointer, 1, 1> bitref_1_1;
    typedef bit_reference<pointer, 2, 1> bitref_2_1;
    typedef bit_reference<pointer, 3, 13> bitref_3_13;

    typedef const_bit_reference<const_pointer, 0, 8> const_bitref_0_8;
    typedef const_bit_reference<const_pointer, 0, 16> const_bitref_0_16;
    typedef const_bit_reference<const_pointer, 0, 32> const_bitref_0_32;
    typedef const_bit_reference<const_pointer, 0, 4> const_bitref_0_4;
    typedef const_bit_reference<const_pointer, 4, 4> const_bitref_4_4;
    typedef const_bit_reference<const_pointer, 0, 3> const_bitref_0_3;
    typedef const_bit_reference<const_pointer, 1, 1> const_bitref_1_1;
    typedef const_bit_reference<const_pointer, 2, 1> const_bitref_2_1;
    typedef const_bit_reference<const_pointer, 3, 13> const_bitref_3_13;

    ip_packet();
    ip_packet(pointer p);
    void reset();
    void reset(pointer p);
    const_pointer get() const;
    pointer get();
    operator bool() const;

    pointer pointer_at(std::ptrdiff_t index);
    uint8& at(std::ptrdiff_t index);

    const_pointer pointer_at(std::ptrdiff_t index) const;
    const uint8& at(std::ptrdiff_t index) const;

    const_bitref_0_4 version() const;
    const_bitref_4_4 header_length() const;
    const_bitref_0_8 type_of_service() const;
    const_bitref_0_16 total_length() const;
    const_bitref_0_16 identification() const;
    const_bitref_0_3 flags() const;
    const_bitref_3_13 fragment_offset() const;
    const_bitref_0_8 time_to_live() const;
    const_bitref_0_8 protocol() const;
    const_bitref_0_16 checksum() const;
    const_bitref_0_32 source_address() const;
    const_bitref_0_32 destination_address() const;

    const_bitref_1_1 df() const;
    const_bitref_2_1 mf() const;

    bitref_0_4 version();
    bitref_4_4 header_length();
    bitref_0_8 type_of_service();
    bitref_0_16 total_length();
    bitref_0_16 identification();
    bitref_0_3 flags();
    bitref_3_13 fragment_offset();
    bitref_0_8 time_to_live();
    bitref_0_8 protocol();
    bitref_0_16 checksum();
    bitref_0_32 source_address();
    bitref_0_32 destination_address();

    bitref_1_1 df();
    bitref_2_1 mf();

    bool packet_ok() const;
    bool packet_ok(uint32 size) const;

    bool is_fragment() const;

    uint16 calculate_checksum() const;
    bool checksum_ok() const;
    void update_checksum();

    uint16 real_header_length() const;
    uint16 options_length() const;
    uint16 data_length() const;

    const_pointer header() const;
    const_pointer options() const;
    const_pointer data() const;
    const_pointer packet_end() const;

    pointer header();
    pointer options();
    pointer data();
    pointer packet_end();

protected:

    pointer packet;

};

class ip_options {

public:

    typedef ip_packet::const_pointer const_pointer;

    ip_options(const ip_packet& packet);

    bool end_of_options() const;
    void goto_next_option();

    uint8 option_type() const;
    uint8 option_length() const;
    bool option_copied() const;
    uint8 option_class() const;
    uint8 option_number() const;
    const_pointer option() const;

private:

    const_pointer options;
    const_pointer end_options;

    void check_if_end();

};

class tcp_segment : public ip_packet {

public:

    typedef ip_packet::pointer pointer;
    typedef ip_packet::const_pointer const_pointer;

    typedef bit_reference<pointer, 0, 16> bitref_0_16;
    typedef bit_reference<pointer, 0, 32> bitref_0_32;
    typedef bit_reference<pointer, 0, 4> bitref_0_4;
    typedef bit_reference<pointer, 4, 6> bitref_4_6;
    typedef bit_reference<pointer, 2, 6> bitref_2_6;
    typedef bit_reference<pointer, 2, 1> bitref_2_1;
    typedef bit_reference<pointer, 3, 1> bitref_3_1;
    typedef bit_reference<pointer, 4, 1> bitref_4_1;
    typedef bit_reference<pointer, 5, 1> bitref_5_1;
    typedef bit_reference<pointer, 6, 1> bitref_6_1;
    typedef bit_reference<pointer, 7, 1> bitref_7_1;

    typedef const_bit_reference<const_pointer, 0, 16> const_bitref_0_16;
    typedef const_bit_reference<const_pointer, 0, 32> const_bitref_0_32;
    typedef const_bit_reference<const_pointer, 0, 4> const_bitref_0_4;
    typedef const_bit_reference<const_pointer, 4, 6> const_bitref_4_6;
    typedef const_bit_reference<const_pointer, 2, 6> const_bitref_2_6;
    typedef const_bit_reference<const_pointer, 2, 1> const_bitref_2_1;
    typedef const_bit_reference<const_pointer, 3, 1> const_bitref_3_1;
    typedef const_bit_reference<const_pointer, 4, 1> const_bitref_4_1;
    typedef const_bit_reference<const_pointer, 5, 1> const_bitref_5_1;
    typedef const_bit_reference<const_pointer, 6, 1> const_bitref_6_1;
    typedef const_bit_reference<const_pointer, 7, 1> const_bitref_7_1;

    tcp_segment();
    tcp_segment(pointer p);
    tcp_segment(const ip_packet& ipp);

    const_bitref_0_16 source_port(const_pointer th) const;
    const_bitref_0_16 destination_port(const_pointer th) const;
    const_bitref_0_32 sequence_number(const_pointer th) const;
    const_bitref_0_32 acknowledgement_number(const_pointer th) const;
    const_bitref_0_4 tcp_header_length(const_pointer th) const;
    const_bitref_4_6 tcp_reserved(const_pointer th) const;
    const_bitref_2_6 tcp_flags(const_pointer th) const;
    const_bitref_0_16 window_size(const_pointer th) const;
    const_bitref_0_16 tcp_checksum(const_pointer th) const;
    const_bitref_0_16 urgent_pointer(const_pointer th) const;

    const_bitref_2_1 urg(const_pointer th) const;
    const_bitref_3_1 ack(const_pointer th) const;
    const_bitref_4_1 psh(const_pointer th) const;
    const_bitref_5_1 rst(const_pointer th) const;
    const_bitref_6_1 syn(const_pointer th) const;
    const_bitref_7_1 fin(const_pointer th) const;

    bitref_0_16 source_port(pointer th);
    bitref_0_16 destination_port(pointer th);
    bitref_0_32 sequence_number(pointer th);
    bitref_0_32 acknowledgement_number(pointer th);
    bitref_0_4 tcp_header_length(pointer th);
    bitref_4_6 tcp_reserved(pointer th);
    bitref_2_6 tcp_flags(pointer th);
    bitref_0_16 window_size(pointer th);
    bitref_0_16 tcp_checksum(pointer th);
    bitref_0_16 urgent_pointer(pointer th);

    bitref_2_1 urg(pointer th);
    bitref_3_1 ack(pointer th);
    bitref_4_1 psh(pointer th);
    bitref_5_1 rst(pointer th);
    bitref_6_1 syn(pointer th);
    bitref_7_1 fin(pointer th);

    uint16 calculate_tcp_checksum(const_pointer th) const;
    bool tcp_checksum_ok(const_pointer th) const;
    void update_tcp_checksum(pointer th);

    uint16 calculate_tcp_checksum(const_pointer th,
                                  dsd_gather_i_1* ads_payload,
                                  char* ach_cur) const;
    bool tcp_checksum_ok(const_pointer th,
                         dsd_gather_i_1* ads_payload, char* ach_cur) const;
    void update_tcp_checksum(pointer th,
                             dsd_gather_i_1* ads_payload, char* ach_cur);

    uint16 real_tcp_header_length(const_pointer th) const;
    uint16 tcp_options_length(const_pointer th) const;
    uint16 tcp_data_length(const_pointer th) const;

    const_pointer tcp_options(const_pointer th) const;
    const_pointer tcp_data(const_pointer th) const;
    const_pointer tcp_segment_end(const_pointer th) const;

    pointer tcp_options(pointer th);
    pointer tcp_data(pointer th);
    pointer tcp_segment_end(pointer th);

    const_bitref_0_16 source_port() const;
    const_bitref_0_16 destination_port() const;
    const_bitref_0_32 sequence_number() const;
    const_bitref_0_32 acknowledgement_number() const;
    const_bitref_0_4 tcp_header_length() const;
    const_bitref_4_6 tcp_reserved() const;
    const_bitref_2_6 tcp_flags() const;
    const_bitref_0_16 window_size() const;
    const_bitref_0_16 tcp_checksum() const;
    const_bitref_0_16 urgent_pointer() const;

    const_bitref_2_1 urg() const;
    const_bitref_3_1 ack() const;
    const_bitref_4_1 psh() const;
    const_bitref_5_1 rst() const;
    const_bitref_6_1 syn() const;
    const_bitref_7_1 fin() const;

    bitref_0_16 source_port();
    bitref_0_16 destination_port();
    bitref_0_32 sequence_number();
    bitref_0_32 acknowledgement_number();
    bitref_0_4 tcp_header_length();
    bitref_4_6 tcp_reserved();
    bitref_2_6 tcp_flags();
    bitref_0_16 window_size();
    bitref_0_16 tcp_checksum();
    bitref_0_16 urgent_pointer();

    bitref_2_1 urg();
    bitref_3_1 ack();
    bitref_4_1 psh();
    bitref_5_1 rst();
    bitref_6_1 syn();
    bitref_7_1 fin();

    bool tcp_segment_ok() const; // given packet_ok()

    uint16 calculate_tcp_checksum() const;
    bool tcp_checksum_ok() const;
    void update_tcp_checksum();

    uint16 calculate_tcp_checksum(dsd_gather_i_1* ads_payload,
                                  char* ach_cur) const;
    bool tcp_checksum_ok(dsd_gather_i_1* ads_payload, char* ach_cur) const;
    void update_tcp_checksum(dsd_gather_i_1* ads_payload, char* ach_cur);

    uint16 tcp_total_length() const;
    uint16 real_tcp_header_length() const;
    uint16 tcp_options_length() const;
    uint16 tcp_data_length() const;

    const_pointer tcp_header() const;
    const_pointer tcp_options() const;
    const_pointer tcp_data() const;
    const_pointer tcp_segment_end() const;

    pointer tcp_header();
    pointer tcp_options();
    pointer tcp_data();
    pointer tcp_segment_end();

};

class tcp_options {

public:

    typedef tcp_segment::const_pointer const_pointer;

    tcp_options(const tcp_segment& packet);
    tcp_options(const tcp_segment& packet, const_pointer th);

    bool end_of_options() const;
    void goto_next_option();

    uint8 option_type() const;
    uint8 option_length() const;
    const_pointer option() const;

private:

    const_pointer options;
    const_pointer end_options;

    void check_if_end();

};

std::ostream& operator<<(std::ostream& os, const ip_packet& packet);
std::ostream& putpacket(std::ostream& os, const ip_packet& packet);
std::ostream& operator<<(std::ostream& os, const tcp_segment& packet);
std::ostream& putsegment(std::ostream& os, const tcp_segment& packet);

// IP implementation

inline ip_packet::ip_packet()
    : packet(0)
{
}

inline ip_packet::ip_packet(pointer p)
    : packet(p)
{
}

inline void ip_packet::reset()
{
    packet = 0;
}

inline void ip_packet::reset(pointer p)
{
    packet = p;
}

inline ip_packet::const_pointer ip_packet::get() const
{
    return packet;
}

inline ip_packet::pointer ip_packet::get()
{
    return packet;
}

inline ip_packet::operator bool() const
{
    return packet != 0;
}

inline ip_packet::pointer ip_packet::pointer_at(std::ptrdiff_t index)
{
    return packet + index;
}

inline uint8& ip_packet::at(std::ptrdiff_t index)
{
    return *pointer_at(index);
}

inline ip_packet::const_pointer
ip_packet::pointer_at(std::ptrdiff_t index) const
{
    return packet + index;
}

inline const uint8& ip_packet::at(std::ptrdiff_t index) const
{
    return *pointer_at(index);
}

inline ip_packet::const_bitref_0_4 ip_packet::version() const
{
    return const_bitref_0_4(pointer_at(0));
}

inline ip_packet::const_bitref_4_4 ip_packet::header_length() const
{
    return const_bitref_4_4(pointer_at(0));
}

inline ip_packet::const_bitref_0_8 ip_packet::type_of_service() const
{
    return const_bitref_0_8(pointer_at(1));
}

inline ip_packet::const_bitref_0_16 ip_packet::total_length() const
{
    return const_bitref_0_16(pointer_at(2));
}

inline ip_packet::const_bitref_0_16 ip_packet::identification() const
{
    return const_bitref_0_16(pointer_at(4));
}

inline ip_packet::const_bitref_0_3 ip_packet::flags() const
{
    return const_bitref_0_3(pointer_at(6));
}

inline ip_packet::const_bitref_3_13 ip_packet::fragment_offset() const
{
    return const_bitref_3_13(pointer_at(6));
}

inline ip_packet::const_bitref_0_8 ip_packet::time_to_live() const
{
    return const_bitref_0_8(pointer_at(8));
}

inline ip_packet::const_bitref_0_8 ip_packet::protocol() const
{
    return const_bitref_0_8(pointer_at(9));
}

inline ip_packet::const_bitref_0_16 ip_packet::checksum() const
{
    return const_bitref_0_16(pointer_at(10));
}

inline ip_packet::const_bitref_0_32 ip_packet::source_address() const
{
    return const_bitref_0_32(pointer_at(12));
}

inline ip_packet::const_bitref_0_32 ip_packet::destination_address() const
{
    return const_bitref_0_32(pointer_at(16));
}

inline ip_packet::const_bitref_1_1 ip_packet::df() const
{
    return const_bitref_1_1(pointer_at(6));
}

inline ip_packet::const_bitref_2_1 ip_packet::mf() const
{
    return const_bitref_2_1(pointer_at(6));
}

inline ip_packet::bitref_0_4 ip_packet::version()
{
    return bitref_0_4(pointer_at(0));
}

inline ip_packet::bitref_4_4 ip_packet::header_length()
{
    return bitref_4_4(pointer_at(0));
}

inline ip_packet::bitref_0_8 ip_packet::type_of_service()
{
    return bitref_0_8(pointer_at(1));
}

inline ip_packet::bitref_0_16 ip_packet::total_length()
{
    return bitref_0_16(pointer_at(2));
}

inline ip_packet::bitref_0_16 ip_packet::identification()
{
    return bitref_0_16(pointer_at(4));
}

inline ip_packet::bitref_0_3 ip_packet::flags()
{
    return bitref_0_3(pointer_at(6));
}

inline ip_packet::bitref_3_13 ip_packet::fragment_offset()
{
    return bitref_3_13(pointer_at(6));
}

inline ip_packet::bitref_0_8 ip_packet::time_to_live()
{
    return bitref_0_8(pointer_at(8));
}

inline ip_packet::bitref_0_8 ip_packet::protocol()
{
    return bitref_0_8(pointer_at(9));
}

inline ip_packet::bitref_0_16 ip_packet::checksum()
{
    return bitref_0_16(pointer_at(10));
}

inline ip_packet::bitref_0_32 ip_packet::source_address()
{
    return bitref_0_32(pointer_at(12));
}

inline ip_packet::bitref_0_32 ip_packet::destination_address()
{
    return bitref_0_32(pointer_at(16));
}

inline ip_packet::bitref_1_1 ip_packet::df()
{
    return bitref_1_1(pointer_at(6));
}

inline ip_packet::bitref_2_1 ip_packet::mf()
{
    return bitref_2_1(pointer_at(6));
}

inline bool ip_packet::packet_ok() const
{
    return packet_ok(65535);
}

/**
 * \brief Checks if the IP packet is a fragment.
 *
 * \return true if the more fragments flag is set or if the fragment
 * offset is not zero, flase otherwise.
 */
inline bool ip_packet::is_fragment() const
{
    return mf() != 0 || fragment_offset() != 0;
}

/**
 * \brief Checks if the IP header checksum is correct.
 *
 * \return true if the checksum is correct, false otherwise.
 */
inline bool ip_packet::checksum_ok() const
{
    uint16 chksum = checksum();
    uint16 calc = calculate_checksum();
    return chksum == calc || chksum == 0x0000;
}

/**
 * \brief Recalculates and updates the IP header checksum.
 */
inline void ip_packet::update_checksum()
{
    checksum() = calculate_checksum();
}

inline uint16 ip_packet::real_header_length() const
{
    return header_length() * 4;
}

/**
 * \brief Gets the length of the options section in the IP header.
 *
 * \return the options length in octets.
 */
inline uint16 ip_packet::options_length() const
{
    return real_header_length() - 20;
}

/**
 * \brief Gets the length of the data section in the IP packet.
 *
 * \return the data length in octets.
 */
inline uint16 ip_packet::data_length() const
{
    return total_length() - real_header_length();
}

/**
 * \brief Gets a pointer to the packet IP header, which is also the
 * start of the packet.
 *
 * \return a pointer to the packet header.
 */
inline ip_packet::const_pointer ip_packet::header() const
{
    return pointer_at(0);
}

/**
 * \brief Gets a pointer to the options in the IP header.
 *
 * \return a pointer to the IP header options.
 */
inline ip_packet::const_pointer ip_packet::options() const
{
    return pointer_at(20);
}

/**
 * \brief Gets a pointer to the data section in the IP paket.
 *
 * \return a pointer to the data section.
 */
inline ip_packet::const_pointer ip_packet::data() const
{
    return pointer_at(real_header_length());
}

inline ip_packet::const_pointer ip_packet::packet_end() const
{
    return pointer_at(total_length());
}

/**
 * \brief Gets a pointer to the packet IP header, which is also the
 * start of the packet.
 *
 * \return a pointer to the packet header.
 */
inline ip_packet::pointer ip_packet::header()
{
    return pointer_at(0);
}

/**
 * \brief Gets a pointer to the options in the IP header.
 *
 * \return a pointer to the IP header options.
 */
inline ip_packet::pointer ip_packet::options()
{
    return pointer_at(20);
}

/**
 * \brief Gets a pointer to the data section in the IP paket.
 *
 * \return a pointer to the data section.
 */
inline ip_packet::pointer ip_packet::data()
{
    return pointer_at(real_header_length());
}

inline ip_packet::pointer ip_packet::packet_end()
{
    return pointer_at(total_length());
}

// TCP implementation

inline tcp_segment::tcp_segment()
    : ip_packet()
{
}

inline tcp_segment::tcp_segment(pointer p)
    : ip_packet(p)
{
}

inline tcp_segment::tcp_segment(const ip_packet& ipp)
    : ip_packet(ipp)
{
}

inline tcp_segment::const_bitref_0_16
tcp_segment::source_port(const_pointer th) const
{
    return const_bitref_0_16(th + 0);
}

inline tcp_segment::const_bitref_0_16
tcp_segment::destination_port(const_pointer th) const
{
    return const_bitref_0_16(th + 2);
}

inline tcp_segment::const_bitref_0_32
tcp_segment::sequence_number(const_pointer th) const
{
    return const_bitref_0_32(th + 4);
}

inline tcp_segment::const_bitref_0_32
tcp_segment::acknowledgement_number(const_pointer th) const
{
    return const_bitref_0_32(th + 8);
}

inline tcp_segment::const_bitref_0_4
tcp_segment::tcp_header_length(const_pointer th) const
{
    return const_bitref_0_4(th + 12);
}

inline tcp_segment::const_bitref_4_6
tcp_segment::tcp_reserved(const_pointer th) const
{
    return const_bitref_4_6(th + 12);
}

inline tcp_segment::const_bitref_2_6
tcp_segment::tcp_flags(const_pointer th) const
{
    return const_bitref_2_6(th + 13);
}

inline tcp_segment::const_bitref_0_16
tcp_segment::window_size(const_pointer th) const
{
    return const_bitref_0_16(th + 14);
}

inline tcp_segment::const_bitref_0_16
tcp_segment::tcp_checksum(const_pointer th) const
{
    return const_bitref_0_16(th + 16);
}

inline tcp_segment::const_bitref_0_16
tcp_segment::urgent_pointer(const_pointer th) const
{
    return const_bitref_0_16(th + 18);
}

inline tcp_segment::const_bitref_2_1 tcp_segment::urg(const_pointer th) const
{
    return const_bitref_2_1(th + 13);
}

inline tcp_segment::const_bitref_3_1 tcp_segment::ack(const_pointer th) const
{
    return const_bitref_3_1(th + 13);
}

inline tcp_segment::const_bitref_4_1 tcp_segment::psh(const_pointer th) const
{
    return const_bitref_4_1(th + 13);
}

inline tcp_segment::const_bitref_5_1 tcp_segment::rst(const_pointer th) const
{
    return const_bitref_5_1(th + 13);
}

inline tcp_segment::const_bitref_6_1 tcp_segment::syn(const_pointer th) const
{
    return const_bitref_6_1(th + 13);
}

inline tcp_segment::const_bitref_7_1 tcp_segment::fin(const_pointer th) const
{
    return const_bitref_7_1(th + 13);
}

inline tcp_segment::bitref_0_16 tcp_segment::source_port(pointer th)
{
    return bitref_0_16(th + 0);
}

inline tcp_segment::bitref_0_16 tcp_segment::destination_port(pointer th)
{
    return bitref_0_16(th + 2);
}

inline tcp_segment::bitref_0_32 tcp_segment::sequence_number(pointer th)
{
    return bitref_0_32(th + 4);
}

inline tcp_segment::bitref_0_32 tcp_segment::acknowledgement_number(pointer th)
{
    return bitref_0_32(th + 8);
}

inline tcp_segment::bitref_0_4 tcp_segment::tcp_header_length(pointer th)
{
    return bitref_0_4(th + 12);
}

inline tcp_segment::bitref_4_6 tcp_segment::tcp_reserved(pointer th)
{
    return bitref_4_6(th + 12);
}

inline tcp_segment::bitref_2_6 tcp_segment::tcp_flags(pointer th)
{
    return bitref_2_6(th + 13);
}

inline tcp_segment::bitref_0_16 tcp_segment::window_size(pointer th)
{
    return bitref_0_16(th + 14);
}

inline tcp_segment::bitref_0_16 tcp_segment::tcp_checksum(pointer th)
{
    return bitref_0_16(th + 16);
}

inline tcp_segment::bitref_0_16 tcp_segment::urgent_pointer(pointer th)
{
    return bitref_0_16(th + 18);
}

inline tcp_segment::bitref_2_1 tcp_segment::urg(pointer th)
{
    return bitref_2_1(th + 13);
}

inline tcp_segment::bitref_3_1 tcp_segment::ack(pointer th)
{
    return bitref_3_1(th + 13);
}

inline tcp_segment::bitref_4_1 tcp_segment::psh(pointer th)
{
    return bitref_4_1(th + 13);
}

inline tcp_segment::bitref_5_1 tcp_segment::rst(pointer th)
{
    return bitref_5_1(th + 13);
}

inline tcp_segment::bitref_6_1 tcp_segment::syn(pointer th)
{
    return bitref_6_1(th + 13);
}

inline tcp_segment::bitref_7_1 tcp_segment::fin(pointer th)
{
    return bitref_7_1(th + 13);
}

inline bool tcp_segment::tcp_checksum_ok(const_pointer th) const
{
    uint16 chksum = tcp_checksum(th);
    uint16 calc = calculate_tcp_checksum(th);
    return chksum == calc || (chksum == 0x0000 && calc == 0xffff);
}

inline void tcp_segment::update_tcp_checksum(pointer th)
{
    tcp_checksum(th) = calculate_tcp_checksum(th);
}

inline bool tcp_segment::
tcp_checksum_ok(const_pointer th,
                dsd_gather_i_1* ads_payload, char* ach_cur) const
{
    uint16 chksum = tcp_checksum(th);
    uint16 calc = calculate_tcp_checksum(th, ads_payload, ach_cur);
    return chksum == calc || (chksum == 0x0000 && calc == 0xffff);
}

inline void tcp_segment::
update_tcp_checksum(pointer th, dsd_gather_i_1* ads_payload, char* ach_cur)
{
    tcp_checksum(th) = calculate_tcp_checksum(th, ads_payload, ach_cur);
}

inline uint16 tcp_segment::real_tcp_header_length(const_pointer th) const
{
    return tcp_header_length(th) * 4;
}

inline uint16 tcp_segment::tcp_options_length(const_pointer th) const
{
    return real_tcp_header_length(th) - 20;
}

inline uint16 tcp_segment::tcp_data_length(const_pointer th) const
{
    return tcp_total_length() - real_tcp_header_length(th);
}

inline tcp_segment::const_pointer
tcp_segment::tcp_options(const_pointer th) const
{
    return th + 20;
}

inline tcp_segment::const_pointer tcp_segment::tcp_data(const_pointer th) const
{
    return th + real_tcp_header_length(th);
}

inline tcp_segment::const_pointer
tcp_segment::tcp_segment_end(const_pointer th) const
{
    return th + tcp_total_length();
}

inline tcp_segment::pointer tcp_segment::tcp_options(pointer th)
{
    return th + 20;
}

inline tcp_segment::pointer tcp_segment::tcp_data(pointer th)
{
    return th + real_tcp_header_length(th);
}

inline tcp_segment::pointer tcp_segment::tcp_segment_end(pointer th)
{
    return th + tcp_total_length();
}

inline tcp_segment::const_bitref_0_16 tcp_segment::source_port() const
{
    return source_port(tcp_header());
}

inline tcp_segment::const_bitref_0_16 tcp_segment::destination_port() const
{
    return destination_port(tcp_header());
}

inline tcp_segment::const_bitref_0_32 tcp_segment::sequence_number() const
{
    return sequence_number(tcp_header());
}

inline tcp_segment::const_bitref_0_32
tcp_segment::acknowledgement_number() const
{
    return acknowledgement_number(tcp_header());
}

inline tcp_segment::const_bitref_0_4 tcp_segment::tcp_header_length() const
{
    return tcp_header_length(tcp_header());
}

inline tcp_segment::const_bitref_4_6 tcp_segment::tcp_reserved() const
{
    return tcp_reserved(tcp_header());
}

inline tcp_segment::const_bitref_2_6 tcp_segment::tcp_flags() const
{
    return tcp_flags(tcp_header());
}

inline tcp_segment::const_bitref_0_16 tcp_segment::window_size() const
{
    return window_size(tcp_header());
}

inline tcp_segment::const_bitref_0_16 tcp_segment::tcp_checksum() const
{
    return tcp_checksum(tcp_header());
}

inline tcp_segment::const_bitref_0_16 tcp_segment::urgent_pointer() const
{
    return urgent_pointer(tcp_header());
}

inline tcp_segment::const_bitref_2_1 tcp_segment::urg() const
{
    return urg(tcp_header());
}

inline tcp_segment::const_bitref_3_1 tcp_segment::ack() const
{
    return ack(tcp_header());
}

inline tcp_segment::const_bitref_4_1 tcp_segment::psh() const
{
    return psh(tcp_header());
}

inline tcp_segment::const_bitref_5_1 tcp_segment::rst() const
{
    return rst(tcp_header());
}

inline tcp_segment::const_bitref_6_1 tcp_segment::syn() const
{
    return syn(tcp_header());
}

inline tcp_segment::const_bitref_7_1 tcp_segment::fin() const
{
    return fin(tcp_header());
}

inline tcp_segment::bitref_0_16 tcp_segment::source_port()
{
    return source_port(tcp_header());
}

inline tcp_segment::bitref_0_16 tcp_segment::destination_port()
{
    return destination_port(tcp_header());
}

inline tcp_segment::bitref_0_32 tcp_segment::sequence_number()
{
    return sequence_number(tcp_header());
}

inline tcp_segment::bitref_0_32 tcp_segment::acknowledgement_number()
{
    return acknowledgement_number(tcp_header());
}

inline tcp_segment::bitref_0_4 tcp_segment::tcp_header_length()
{
    return tcp_header_length(tcp_header());
}

inline tcp_segment::bitref_4_6 tcp_segment::tcp_reserved()
{
    return tcp_reserved(tcp_header());
}

inline tcp_segment::bitref_2_6 tcp_segment::tcp_flags()
{
    return tcp_flags(tcp_header());
}

inline tcp_segment::bitref_0_16 tcp_segment::window_size()
{
    return window_size(tcp_header());
}

inline tcp_segment::bitref_0_16 tcp_segment::tcp_checksum()
{
    return tcp_checksum(tcp_header());
}

inline tcp_segment::bitref_0_16 tcp_segment::urgent_pointer()
{
    return urgent_pointer(tcp_header());
}

inline tcp_segment::bitref_2_1 tcp_segment::urg()
{
    return urg(tcp_header());
}

inline tcp_segment::bitref_3_1 tcp_segment::ack()
{
    return ack(tcp_header());
}

inline tcp_segment::bitref_4_1 tcp_segment::psh()
{
    return psh(tcp_header());
}

inline tcp_segment::bitref_5_1 tcp_segment::rst()
{
    return rst(tcp_header());
}

inline tcp_segment::bitref_6_1 tcp_segment::syn()
{
    return syn(tcp_header());
}

inline tcp_segment::bitref_7_1 tcp_segment::fin()
{
    return fin(tcp_header());
}

inline uint16 tcp_segment::calculate_tcp_checksum() const
{
    return calculate_tcp_checksum(tcp_header());
}

inline bool tcp_segment::tcp_checksum_ok() const
{
    return tcp_checksum_ok(tcp_header());
}

inline void tcp_segment::update_tcp_checksum()
{
    update_tcp_checksum(tcp_header());
}

inline uint16 tcp_segment::
calculate_tcp_checksum(dsd_gather_i_1* ads_payload, char* ach_cur) const
{
    return calculate_tcp_checksum(tcp_header(), ads_payload, ach_cur);
}

inline bool tcp_segment::
tcp_checksum_ok(dsd_gather_i_1* ads_payload, char* ach_cur) const
{
    return tcp_checksum_ok(tcp_header(), ads_payload, ach_cur);
}

inline void tcp_segment::
update_tcp_checksum(dsd_gather_i_1* ads_payload, char* ach_cur)
{
    update_tcp_checksum(tcp_header(), ads_payload, ach_cur);
}

inline uint16 tcp_segment::tcp_total_length() const
{
    return this->data_length();
}

inline uint16 tcp_segment::real_tcp_header_length() const
{
    return real_tcp_header_length(tcp_header());
}

inline uint16 tcp_segment::tcp_options_length() const
{
    return tcp_options_length(tcp_header());
}

inline uint16 tcp_segment::tcp_data_length() const
{
    return tcp_data_length(tcp_header());
}

inline tcp_segment::const_pointer tcp_segment::tcp_header() const
{
    return this->data();
}

inline tcp_segment::const_pointer tcp_segment::tcp_options() const
{
    return tcp_options(tcp_header());
}

inline tcp_segment::const_pointer tcp_segment::tcp_data() const
{
    return tcp_data(tcp_header());
}

inline tcp_segment::const_pointer tcp_segment::tcp_segment_end() const
{
    return tcp_segment_end(tcp_header());
}

inline tcp_segment::pointer tcp_segment::tcp_header()
{
    return this->data();
}

inline tcp_segment::pointer tcp_segment::tcp_options()
{
    return tcp_options(tcp_header());
}

inline tcp_segment::pointer tcp_segment::tcp_data()
{
    return tcp_data(tcp_header());
}

inline tcp_segment::pointer tcp_segment::tcp_segment_end()
{
    return tcp_segment_end(tcp_header());
}

#endif // HTCP_TCPIP_HDR_H
