/******************************************************************************
 * File name: bit_reference.h
 *
 * C++ utility to read and write integers across byte boundaries,
 * with the integers having variable number of bits and not necessarily
 * starting/stopping on a byte boundary. Network byte order is used.
 * When compiled with optimization on, the resulting assembly code is
 * similar to assembly code obtained when compiling hand-written code.
 *
 * Requires C++.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/

// Template parameters:
// ByteIter: method used to access bytes in memory, usually uint8*
// FirstBit: the offset of the first bit within the first memory byte
//               - 0 means the first bit is the most significant bit
// BitCount: the total number of bits
//
// Operators supported:
// & | ^ + - ~ == != < >= > <= = &= |= ^= += -=
// Operands on may be bit_reference or native integer on either side.
//
// Examples:
// <uint8*, 3, 12>: ...xxxxx xxxxxxx.
// <uint8*, 0, 4> : xxxx....
// <uint8*, 4, 4> : ....xxxx
// <uint8*, 7, 10>: .......x xxxxxxxx x.......
//
// typedef bit_reference<uint8*, 3, 12> br_3_12;
// inline br_3_12 test(uint8* ptr)
// {
//      return br_3_12(ptr);
// }
// uint8 data[2] = {0};
// test(data) = 0xd5a; // 110101011010
// assert(data[0] == 0x1a); // ...11010
// assert(data[1] == 0xb4); // 1011010.
// test(data) ^= 0xbfc; // 101111111100
// assert(test(data) == 0x6a6); // 0xd5a ^ 0xbfc gives 011010100110


#ifndef HTCP_BIT_REFERENCE_H
#define HTCP_BIT_REFERENCE_H

#ifdef DOES_INCL_HEADERS
#include "int_types.h"
#endif

// Depending on number of bits, variable-length integer may be represented
// by 8/16/32/64-bit integer.
template<int BitCount> struct bit_count_word_type {};
template<> struct bit_count_word_type<1> { typedef uint8 word; };
template<> struct bit_count_word_type<2> { typedef uint8 word; };
template<> struct bit_count_word_type<3> { typedef uint8 word; };
template<> struct bit_count_word_type<4> { typedef uint8 word; };
template<> struct bit_count_word_type<5> { typedef uint8 word; };
template<> struct bit_count_word_type<6> { typedef uint8 word; };
template<> struct bit_count_word_type<7> { typedef uint8 word; };
template<> struct bit_count_word_type<8> { typedef uint8 word; };
template<> struct bit_count_word_type<9> { typedef uint16 word; };
template<> struct bit_count_word_type<10> { typedef uint16 word; };
template<> struct bit_count_word_type<11> { typedef uint16 word; };
template<> struct bit_count_word_type<12> { typedef uint16 word; };
template<> struct bit_count_word_type<13> { typedef uint16 word; };
template<> struct bit_count_word_type<14> { typedef uint16 word; };
template<> struct bit_count_word_type<15> { typedef uint16 word; };
template<> struct bit_count_word_type<16> { typedef uint16 word; };
template<> struct bit_count_word_type<17> { typedef uint32 word; };
template<> struct bit_count_word_type<18> { typedef uint32 word; };
template<> struct bit_count_word_type<19> { typedef uint32 word; };
template<> struct bit_count_word_type<20> { typedef uint32 word; };
template<> struct bit_count_word_type<21> { typedef uint32 word; };
template<> struct bit_count_word_type<22> { typedef uint32 word; };
template<> struct bit_count_word_type<23> { typedef uint32 word; };
template<> struct bit_count_word_type<24> { typedef uint32 word; };
template<> struct bit_count_word_type<25> { typedef uint32 word; };
template<> struct bit_count_word_type<26> { typedef uint32 word; };
template<> struct bit_count_word_type<27> { typedef uint32 word; };
template<> struct bit_count_word_type<28> { typedef uint32 word; };
template<> struct bit_count_word_type<29> { typedef uint32 word; };
template<> struct bit_count_word_type<30> { typedef uint32 word; };
template<> struct bit_count_word_type<31> { typedef uint32 word; };
template<> struct bit_count_word_type<32> { typedef uint32 word; };
template<> struct bit_count_word_type<33> { typedef uint64 word; };
template<> struct bit_count_word_type<34> { typedef uint64 word; };
template<> struct bit_count_word_type<35> { typedef uint64 word; };
template<> struct bit_count_word_type<36> { typedef uint64 word; };
template<> struct bit_count_word_type<37> { typedef uint64 word; };
template<> struct bit_count_word_type<38> { typedef uint64 word; };
template<> struct bit_count_word_type<39> { typedef uint64 word; };
template<> struct bit_count_word_type<40> { typedef uint64 word; };
template<> struct bit_count_word_type<41> { typedef uint64 word; };
template<> struct bit_count_word_type<42> { typedef uint64 word; };
template<> struct bit_count_word_type<43> { typedef uint64 word; };
template<> struct bit_count_word_type<44> { typedef uint64 word; };
template<> struct bit_count_word_type<45> { typedef uint64 word; };
template<> struct bit_count_word_type<46> { typedef uint64 word; };
template<> struct bit_count_word_type<47> { typedef uint64 word; };
template<> struct bit_count_word_type<48> { typedef uint64 word; };
template<> struct bit_count_word_type<49> { typedef uint64 word; };
template<> struct bit_count_word_type<50> { typedef uint64 word; };
template<> struct bit_count_word_type<51> { typedef uint64 word; };
template<> struct bit_count_word_type<52> { typedef uint64 word; };
template<> struct bit_count_word_type<53> { typedef uint64 word; };
template<> struct bit_count_word_type<54> { typedef uint64 word; };
template<> struct bit_count_word_type<55> { typedef uint64 word; };
template<> struct bit_count_word_type<56> { typedef uint64 word; };
template<> struct bit_count_word_type<57> { typedef uint64 word; };
template<> struct bit_count_word_type<58> { typedef uint64 word; };
template<> struct bit_count_word_type<59> { typedef uint64 word; };
template<> struct bit_count_word_type<60> { typedef uint64 word; };
template<> struct bit_count_word_type<61> { typedef uint64 word; };
template<> struct bit_count_word_type<62> { typedef uint64 word; };
template<> struct bit_count_word_type<63> { typedef uint64 word; };
template<> struct bit_count_word_type<64> { typedef uint64 word; };

template<class ByteIter, int FirstBit, int BitCount>
class bit_reference_base;

template<class ByteIter, int FirstBit, int BitCount>
typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator&(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator|(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator^(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator+(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator-(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator~(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0);

template<class ByteIter, int FirstBit, int BitCount>
bool operator==(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
bool operator!=(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
bool operator< (const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
bool operator>=(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
bool operator> (const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

template<class ByteIter, int FirstBit, int BitCount>
bool operator<=(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                const bit_reference_base<ByteIter, FirstBit, BitCount>& b1);

// TODO: correct handling of const

template<class ByteIter, int FirstBit, int BitCount>
class bit_reference_base {

public:

        typedef typename bit_count_word_type<BitCount>::word word;

        bit_reference_base(ByteIter p);

        operator word() const;

        friend bool operator== <>(const bit_reference_base& b0,
                                  const bit_reference_base& b1);

protected:

        const ByteIter ptr;

        // use
        // ((x << s - 1) - 1 << 1) + 1
        // rather than
        // (x << s) - 1
        // to avoid overflow

        static const int bytes = (FirstBit + BitCount + 7) / 8;
        static const int bytesm1 = bytes - 1;
        static const bool single_byte = bytes == 1;
        static const int shift = (single_byte ?
                                  8 - FirstBit - BitCount :
                                  7 - (FirstBit + BitCount + 7) % 8);
        static const uint8 first_mask = (single_byte ?
                                         ((((word(1) << (BitCount - 1)) - 1) << 1) + 1) << shift :
                                         (((word(1) << (7 - FirstBit)) - 1) << 1) + 1);
        static const uint8 last_mask = (single_byte ?
                                        first_mask :
                                        0x100 - (1 << shift));
        static const word word_mask = (((word(1) << (BitCount - 1)) - 1) << 1) + 1;

};

template<class ByteIter, int FirstBit, int BitCount>
class const_bit_reference : public bit_reference_base<ByteIter, FirstBit, BitCount> {

public:

        typedef bit_reference_base<ByteIter, FirstBit, BitCount> base;
        typedef typename base::word word;

        const_bit_reference(ByteIter p);

protected:

        static const int bytes = base::bytes;
        static const int bytesm1 = base::bytesm1;
        static const bool single_byte = base::single_byte;
        static const int shift = base::shift;
        static const uint8 first_mask = base::first_mask;
        static const uint8 last_mask = base::last_mask;
        static const word word_mask = base::word_mask;

};

template<class ByteIter, int FirstBit, int BitCount>
class bit_reference : public bit_reference_base<ByteIter, FirstBit, BitCount> {

public:

        typedef bit_reference_base<ByteIter, FirstBit, BitCount> base;
        typedef typename base::word word;

        bit_reference(ByteIter p);

        bit_reference& operator=(word bits);
        bit_reference& operator&=(word bits);
        bit_reference& operator|=(word bits);
        bit_reference& operator^=(word bits);
        bit_reference& operator+=(word bits);
        bit_reference& operator-=(word bits);

        bit_reference& operator=(const bit_reference& bits);
        bit_reference& operator=(const base& bits);
        bit_reference& operator&=(const base& bits);
        bit_reference& operator|=(const base& bits);
        bit_reference& operator^=(const base& bits);
        bit_reference& operator+=(const base& bits);
        bit_reference& operator-=(const base& bits);
        bit_reference& flip();

protected:

        static const int bytes = base::bytes;
        static const int bytesm1 = base::bytesm1;
        static const bool single_byte = base::single_byte;
        static const int shift = base::shift;
        static const uint8 first_mask = base::first_mask;
        static const uint8 last_mask = base::last_mask;
        static const word word_mask = base::word_mask;

};

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference_base<ByteIter, FirstBit, BitCount>::bit_reference_base(ByteIter p)
        : ptr(p)
{
}

template<class ByteIter, int FirstBit, int BitCount>
inline const_bit_reference<ByteIter, FirstBit, BitCount>::const_bit_reference(ByteIter p)
        : bit_reference_base<ByteIter, FirstBit, BitCount>(p)
{
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>::bit_reference(ByteIter p)
        : bit_reference_base<ByteIter, FirstBit, BitCount>(p)
{
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference_base<ByteIter, FirstBit, BitCount>::operator
typename bit_reference_base<ByteIter, FirstBit, BitCount>::word() const
{
        if (single_byte)
                return (*ptr & first_mask) >> shift;

        ByteIter p = ptr;
        word ret = *p++ & first_mask;

        for (int i = 1; i < bytesm1; ++i) {
                ret <<= 8;
                ret |= *p++ & 0xff;
        }

        ret <<= 8 - shift;
        ret |= (*p & last_mask) >> shift;

        return ret;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator=(word bits)
{
        if (single_byte) {
                *this->ptr &= uint8(~first_mask);
                *this->ptr |= (bits << shift) & first_mask;
                return *this;
        }

        ByteIter p = this->ptr + bytesm1;

        *p &= uint8(~last_mask);
        *p-- |= (bits << shift) & last_mask;
        bits >>= 8 - shift;

        for (int i = bytesm1 - 1; i > 0; --i) {
                *p-- = bits & 0xff;
                bits >>= 8;
        }

        *p &= uint8(~first_mask);
        *p |= bits & first_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator&=(word bits)
{
        if (single_byte) {
                *this->ptr &= ~first_mask | (bits << shift) & first_mask;
                return *this;
        }

        ByteIter p = this->ptr + bytesm1;

        *p-- &= ~last_mask | (bits << shift) & last_mask;
        bits >>= 8 - shift;

        for (int i = bytesm1 - 1; i > 0; --i) {
                *p-- &= bits & 0xff;
                bits >>= 8;
        }

        *p &= ~first_mask |= bits & first_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator|=(word bits)
{
        if (single_byte) {
                *this->ptr |= (bits << shift) & first_mask;
                return *this;
        }

        ByteIter p = this->ptr + bytesm1;

        *p-- |= (bits << shift) & last_mask;
        bits >>= 8 - shift;

        for (int i = bytesm1 - 1; i > 0; --i) {
                *p-- |= bits & 0xff;
                bits >>= 8;
        }

        *p |= bits & first_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator^=(word bits)
{
        if (single_byte) {
                *this->ptr ^= (bits << shift) & first_mask;
                return *this;
        }

        ByteIter p = this->ptr + bytesm1;

        *p-- ^= (bits << shift) & last_mask;
        bits >>= 8 - shift;

        for (int i = bytesm1 - 1; i > 0; --i) {
                *p-- ^= bits & 0xff;
                bits >>= 8;
        }

        *p-- ^= bits & first_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator+=(word bits)
{
        word w = *this;
        w += bits;
        return *this = w;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator-=(word bits)
{
        word w = *this;
        w -= bits;
        return *this = w;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator=(const bit_reference& bits)
{
//      return *this = base(bits);
        if (single_byte) {
            *this->ptr &= uint8(~first_mask);
                *this->ptr |= *bits.ptr & first_mask;
                return *this;
        }

        ByteIter p = this->ptr;
        ByteIter bp = bits.ptr;

        *p &= uint8(~first_mask);
        *p++ |= *bp++ & first_mask;

        for (int i = 1; i < bytesm1; ++i)
                *p++ = *bp++ & 0xff;

        *p &= uint8(~last_mask);
        *p |= *bp & last_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator=(const base& bits)
{
        if (single_byte) {
                *this->ptr &= ~first_mask;
                *this->ptr |= *bits.ptr & first_mask;
                return *this;
        }

        ByteIter p = this->ptr;
        ByteIter bp = bits.ptr;

        *p &= ~first_mask;
        *p++ |= *bp++ & first_mask;

        for (int i = 1; i < bytesm1; ++i)
                *p++ = *bp++ & 0xff;

        *p &= ~last_mask;
        *p |= *bp & last_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator&=(const base& bits)
{
        if (single_byte) {
                *this->ptr &= ~first_mask | *bits.ptr & first_mask;
                return *this;
        }

        ByteIter p = this->ptr;
        ByteIter bp = bits.ptr;

        *p++ &= ~first_mask | *bp++ & first_mask;

        for (int i = 1; i < bytesm1; ++i)
                *p++ &= *bp++ & 0xff;

        *p &= ~last_mask | *bp & last_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator|=(const base& bits)
{
        if (single_byte) {
                *this->ptr |= *bits.ptr & first_mask;
                return *this;
        }

        ByteIter p = this->ptr;
        ByteIter bp = bits.ptr;

        *p++ |= *bp++ & first_mask;

        for (int i = 1; i < bytesm1; ++i)
                *p++ |= *bp++ & 0xff;

        *p |= *bp & last_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator^=(const base& bits)
{
        if (single_byte) {
                *this->ptr ^= *bits.ptr & first_mask;
                return *this;
        }

        ByteIter p = this->ptr;
        ByteIter bp = bits.ptr;

        *p++ ^= *bp++ & first_mask;

        for (int i = 1; i < bytesm1; ++i)
                *p++ ^= *bp++ & 0xff;

        *p ^= *bp & last_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator+=(const base& bits)
{
        word w = *this;
        w += bits;
        return *this = w;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::operator-=(const base& bits)
{
        word w = *this;
        w -= bits;
        return *this = w;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bit_reference<ByteIter, FirstBit, BitCount>&
bit_reference<ByteIter, FirstBit, BitCount>::flip()
{
        if (single_byte) {
                *this->ptr ^= first_mask;
                return *this;
        }

        ByteIter p = this->ptr;

        *p++ ^= first_mask;

        for (int i = 1; i < bytesm1; ++i)
                *p++ ^= 0xff;

        *p ^= last_mask;

        return *this;
}

template<class ByteIter, int FirstBit, int BitCount>
inline typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator&(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w0 = b0;
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w1 = b1;
        return w0 & w1;
}

template<class ByteIter, int FirstBit, int BitCount>
inline typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator|(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w0 = b0;
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w1 = b1;
        return w0 | w1;
}

template<class ByteIter, int FirstBit, int BitCount>
inline typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator^(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w0 = b0;
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w1 = b1;
        return w0 ^ w1;
}

template<class ByteIter, int FirstBit, int BitCount>
inline typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator+(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w0 = b0;
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w1 = b1;
        return (w0 + w1) & bit_reference_base<ByteIter, FirstBit, BitCount>::word_mask;
}

template<class ByteIter, int FirstBit, int BitCount>
inline typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator-(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
          const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w0 = b0;
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w1 = b1;
        return (w0 - w1) & bit_reference_base<ByteIter, FirstBit, BitCount>::word_mask;
}

template<class ByteIter, int FirstBit, int BitCount>
inline typename bit_reference_base<ByteIter, FirstBit, BitCount>::word
operator~(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0)
{
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w0 = b0;
        return w0 ^ bit_reference_base<ByteIter, FirstBit, BitCount>::word_mask;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bool operator==(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                       const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        const bool single_byte = bit_reference_base<ByteIter, FirstBit, BitCount>::single_byte;
        const int bytesm1 = bit_reference_base<ByteIter, FirstBit, BitCount>::bytesm1;
        const int first_mask = bit_reference_base<ByteIter, FirstBit, BitCount>::first_mask;
        const int last_mask = bit_reference_base<ByteIter, FirstBit, BitCount>::last_mask;

        if (single_byte)
                return (*b0.ptr & first_mask) == (*b1.ptr & first_mask);

        ByteIter p0 = b0.ptr;
        ByteIter p1 = b1.ptr;

        if ((*p0++ & first_mask) != (*p1++ & first_mask))
                return false;

        for (int i = 1; i < bytesm1; ++i)
                if ((*p0++ & 0xff) != (*p1++ & 0xff))
                        return false;

        if ((*p0 & last_mask) != (*p1 & last_mask))
                return false;

        return true;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bool operator!=(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                       const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        return !(b0 == b1);
}

template<class ByteIter, int FirstBit, int BitCount>
inline bool operator< (const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                       const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w0 = b0;
        typename bit_reference_base<ByteIter, FirstBit, BitCount>::word w1 = b1;
        return w0 < w1;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bool operator>=(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                       const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        return !(b0 < b1);
}

template<class ByteIter, int FirstBit, int BitCount>
inline bool operator> (const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                       const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        return b1 < b0;
}

template<class ByteIter, int FirstBit, int BitCount>
inline bool operator<=(const bit_reference_base<ByteIter, FirstBit, BitCount>& b0,
                       const bit_reference_base<ByteIter, FirstBit, BitCount>& b1)
{
        return !(b1 < b0);
}

// bit_reference<const uint8*, 0, 32> bitrefc32(const uint8* p)
// {
//     return bit_reference<const uint8*, 0, 32>(p);
// }

// bit_reference<uint8*, 0, 32> bitref32(uint8* p)
// {
//     return bit_reference<uint8*, 0, 32>(p);
// }

#endif // HTCP_BIT_REFERENCE_H
