/******************************************************************************
 * File name: misc.cpp
 *
 * Implementation of misc.h.
 *
 * Requires C++.
 * Section 5 requires WIN32 or HL_UNIX.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/

#include <string>
#include <cstdlib>
#include <assert.h>

#ifdef B090317
#include "int_types.h"
#include "misc.h"
#endif
#include "hob-avl03.h"
/* new 19.03.09 start */
#include <windows.h>
#include <hob-xslhcla1.hpp>
//#include <hob-netw-01.h>
#include <string>
//#include <map>
//#include <list>
//#include <stddef.h>
#include <iostream>
//#include "hob-xslcontr.h"
//#include "hob-tun01.h"
#include "hob-htcp-int-types.h"
//#include "hob-htcp.h"
//#include "hob-htcp-bit-reference.h"
//#include "hob-htcp-tcpip-hdr.h"
#include "hob-htcp-misc.h"
//#include "hob-htcp-connection.h"
//#include "hob-session01.h"
//#include "hob-htcp-session.h"
//#include "hob-tun02.h"
/* new 19.03.09 end */

//////////////////////////////////////////////////////////////////////
// 1. Format hexadecimal numbers.

/**
 * \brief Converts an integer to a hexadecimal string.
 *
 * \param number the integer.
 * \param width the minimum number of digits required.
 * \return the hexadecimal representation of the number.
 */
std::string m_hex(uint32 im_number, int in_width)
{
    std::string ds_s;
    while (--in_width >= 0 || im_number > 0) {
        char ch_t = im_number & 0xf;
        im_number >>= 4;
        ch_t += ch_t < 10 ? '0' : 'a' - 10;
        ds_s = ch_t + ds_s;
    }
    return ds_s;
}

/**
 * \brief Converts an integer to a hexadecimal string,
 * prepending "0x".
 *
 * \param number the integer.
 * \param width the minimum number of digits required.
 * \return the hexadecimal representation of the number.
 */
std::string m_hex_0x(uint32 im_number, int in_width)
{
    return "0x" + m_hex(im_number, in_width);
}

//////////////////////////////////////////////////////////////////////
// 2. Obtain 32-bit random numbers.

#if ((RAND_MAX & 1) != 1) || ((((RAND_MAX >> 1) + 1) & (RAND_MAX >> 1)) != 0)
#error RAND_MAX is not 2^n - 1
#endif

#if RAND_MAX >= 0xffffffff
uint32 m_random32()
{
    return uint32(rand());
}
#elif RAND_MAX >= 0xffff
uint32 m_random32()
{
    uint32 um_ret;
    int in_rnd = rand();
    um_ret = in_rnd;
    um_ret <<= 16;
    in_rnd = rand();
    um_ret |= in_rnd & 0xffff;
    return um_ret;
}
#elif RAND_MAX >= 0x7ff
uint32 m_random32()
{
    uint32 um_ret;
    int in_rnd = rand();
    um_ret = in_rnd;
    um_ret <<= 11;
    in_rnd = rand();
    um_ret |= in_rnd & 0x7ff;
    um_ret <<= 11;
    in_rnd = rand();
    um_ret |= in_rnd & 0x7ff;
    return um_ret;
}
#else
#error RAND_MAX too small
#endif

//////////////////////////////////////////////////////////////////////
// 3. Allocate/deallocate spaces for use in TCP/IP packet headers.

// TCP/IP headers (128-byte maximum)

// Use "new" to allocate a block of new headers.
// Deallocated headers are not freed using "delete", but pushed on a pool
// of vacant headers for future use.

static dsd_mutex_lock ds_headlock;

static const unsigned um_create_headsize = 128;
static const unsigned um_header_block = 512;

union dsd_header_node {
    dsd_header_node* ads_next;
    uint8 byr_header[um_create_headsize];
};

static dsd_header_node* ads_vacant_headers = 0;

uint8* m_allocate_header()
{
    dsd_mutex_locker ds_l(&ds_headlock);

    if (!ads_vacant_headers) {
        // allocate
        dsd_header_node* ads_new_block = new dsd_header_node[um_header_block];
        for (unsigned un_i = 0; un_i < um_header_block - 1; ++un_i)
            ads_new_block[un_i].ads_next = &ads_new_block[un_i + 1];
        ads_new_block[um_header_block - 1].ads_next = 0;
        ads_vacant_headers = ads_new_block;
    }

    uint8* aby_ret = ads_vacant_headers->byr_header;
    ads_vacant_headers = ads_vacant_headers->ads_next;
    return aby_ret;
}

void m_deallocate_header(uint8* aut_header)
{
    dsd_mutex_locker ds_l(&ds_headlock);
    dsd_header_node* ads_hn = (dsd_header_node*)aut_header;
    ads_hn->ads_next = ads_vacant_headers;
    ads_vacant_headers = ads_hn;
}

//////////////////////////////////////////////////////////////////////
// 4. Handle mutexes / critical sections.

// Implemented as inline in misc.h

//////////////////////////////////////////////////////////////////////
// 5. Handle times / delays.

#if defined WIN32

#include <windows.h>

#ifdef _WIN32_WINNT
#if _WIN32_WINNT >= 0x0600
#define USE_GETTICKCOUNT64
#endif
#endif

#ifdef USE_GETTICKCOUNT64

dsd_duration m_monotonic_time()
{
    return m_duration_m(GetTickCount64());
}

#else // !USE_GETTICKCOUNT64

// we must handle GetTickCount() wrap which occurs every 50 days

struct dsd_mt_data_t {

    dsd_duration ds_offset;
    volatile bool bo_late_half;
    CRITICAL_SECTION ds_lock;

    dsd_mt_data_t()
        : ds_offset(0),
          bo_late_half(GetTickCount() >= 0x80000000)
    {
        InitializeCriticalSection(&ds_lock);
    }

    ~dsd_mt_data_t()
    {
        DeleteCriticalSection(&ds_lock);
    }

};

static dsd_mt_data_t ds_mt_data;
static const dsd_duration ds_offset_increment(4294967, 296000000); // 2^32 ms

// Must be called at least every 24 days to avoid wraparound problems.
dsd_duration m_monotonic_time()
{
    uint32 um_t = GetTickCount();
    bool bo_late = (um_t >= 0x80000000);
    bool bo_late_half = ds_mt_data.bo_late_half;
    dsd_duration ds_offset = ds_mt_data.ds_offset;

    // now ensure that no wraparound occurs between call to
    // GetTickCount() and reading mt_data.offset
    if (um_t > 0xffff0000) { // less than about 1 minute remaining
        uint32 um_t2 = GetTickCount();
        if (um_t2 < um_t) { // wraparound occured
            um_t = um_t2;
            bo_late = false;
            bo_late_half = ds_mt_data.bo_late_half;
            ds_offset = ds_mt_data.ds_offset;
        }
    }

    if (bo_late && !bo_late_half) {
        ds_mt_data.bo_late_half = true;
    } else  if (!bo_late && bo_late_half) {
        EnterCriticalSection(&ds_mt_data.ds_lock);
        if (ds_mt_data.bo_late_half) {
            ds_mt_data.ds_offset += ds_offset_increment;
            ds_mt_data.bo_late_half = false;
        }
        LeaveCriticalSection(&ds_mt_data.ds_lock);
        ds_offset = ds_mt_data.ds_offset;
    }

    return ds_offset + m_duration_m(um_t);
}

#endif // !USE_GETTICKCOUNT64

dsd_duration m_system_time()
{
    SYSTEMTIME ds_st;
    FILETIME ds_ft;
    GetSystemTime(&ds_st);
    if (SystemTimeToFileTime(&ds_st, &ds_ft) == 0)
        assert(false);
    uint64 ul_t = ds_ft.dwHighDateTime;
    ul_t <<= 32;
    ul_t |= ds_ft.dwLowDateTime;
    ul_t *= 100;
    return m_duration_n(ul_t);
}

void m_sleep_for(dsd_duration ds_d)
{
    ds_d += m_duration_n(999999);
    int64 il_m = ds_d.m_in_m();
    if (il_m < 0)
        return;
    // sleep for over 24 days?
    while (il_m > 0x7fffffff) {
        Sleep(0x7fffffff);
        il_m -= 0x7fffffff;
    }
    Sleep(uint32(il_m));
}

#elif defined HL_UNIX

#include <cerrno>
#include <time.h>

dsd_duration m_monotonic_time()
{
    timespec ds_t;
    if (clock_gettime(CLOCK_MONOTONIC, &ds_t) != 0)
        assert(false);
    return dsd_duration(ds_t.tv_sec, ds_t.tv_nsec);
}

dsd_duration m_system_time()
{
    timespec ds_t;
    if (clock_gettime(CLOCK_REALTIME, &ds_t) != 0)
        assert(false);
    return dsd_duration(ds_t.tv_sec, ds_t.tv_nsec);
}

void m_sleep_for(dsd_duration ds_d)
{
    if (ds_d < 0)
        return;

    timespec ds_ts;
    ds_ts.tv_sec = ds_d.m_get_s();
    ds_ts.tv_nsec = ds_d.m_get_ns();

    timespec ds_rem;

    while (nanosleep(&ds_ts, &ds_rem) != 0) {
        assert(errno == EINTR);
        ds_ts = ds_rem;
    }
}

#else // !defined WIN32 && !define HL_UNIX
#error misc.cpp needs either WIN32 or HL_UNIX
#endif // !defined WIN32 && !define HL_UNIX
