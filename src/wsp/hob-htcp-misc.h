/******************************************************************************
 * File name: misc.h
 *
 * Utilities to:
 * 1. Format hexadecimal numbers.
 * 2. Obtain 32-bit random numbers.
 * 3. Allocate/deallocate spaces for use in TCP/IP packet headers.
 * 4. Handle mutexes / critical sections.
 * 5. Handle times / delays.
 *
 * Requires C++.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/

// Section 4 example usage:
//
// dsd_mutex_lock ds_lock; // &ds_lock may be passed to use lock
//
// {
//      dsd_mutex_locker ds_locker(&ds_lock); // acquire lock on ds_lock
//      // ...
//      ds_locker.m_reset(); // release ds_lock
//      // ...
//      ds_locker.m_reset(&ds_lock); // reacquire ds_lock
//      // ...
// } // ds_locker out of scope => ds_locker destroyed, ds_lock released

#ifndef HTCP_MISC_H
#define HTCP_MISC_H

#ifdef DOES_INCL_HEADERS
#include <string>

#include "int_types.h"
#endif

//////////////////////////////////////////////////////////////////////
// 1. Format hexadecimal numbers.

// convert number to string with given field width
std::string m_hex(uint32 um_number, int in_width);
// convert number to string with given field width, inserting '0x' prefix
std::string m_hex_0x(uint32 um_number, int in_width);

//////////////////////////////////////////////////////////////////////
// 2. Obtain 32-bit random numbers.

uint32 m_random32();

//////////////////////////////////////////////////////////////////////
// 3. Allocate/deallocate spaces for use in TCP/IP packet headers.

uint8* m_allocate_header();
void m_deallocate_header(uint8* aut_header);

//////////////////////////////////////////////////////////////////////
// 4. Handle mutexes / critical sections.

#ifdef DOES_INCL_HEADERS
#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#include "hob-xslhcla1.hpp"
#endif

// TODO: maybe remove wrapper
// Wrapper was introduced to start using hob-xslhcla1.hpp
// without changing other code.
// Optimization should remove wrapper overhead anyway.
class dsd_mutex_lock {

public:

    dsd_mutex_lock()
    {
        dsd_cs.m_create();
    }

    ~dsd_mutex_lock()
    {
        dsd_cs.m_close();
    }

private:

    // not allowed
    dsd_mutex_lock(const dsd_mutex_lock& ds_other);
    dsd_mutex_lock& operator=(const dsd_mutex_lock& ds_other);

    void m_acquire()
    {
        dsd_cs.m_enter();
    }

    void m_release()
    {
        dsd_cs.m_leave();
    }

    dsd_hcla_critsect_1 dsd_cs;


    friend class dsd_mutex_locker;

};

class dsd_mutex_locker {

public:

    dsd_mutex_locker()
        : ads_lck(0)
    {
    }

    dsd_mutex_locker(dsd_mutex_lock* ads_l)
        : ads_lck(0)
    {
        m_reset(ads_l);
    }

    ~dsd_mutex_locker()
    {
        m_reset();
    }

    void m_reset()
    {
        if (ads_lck != 0) {
            ads_lck->m_release();
            ads_lck = 0;
        }
    }

    // First acquire lock on l, then release current lock.
    // For different order, do: m_reset(); m_reset(ads_l);
    bool m_reset(dsd_mutex_lock* ads_l)
    {
        if (ads_l == ads_lck)
            return true;

        ads_l->m_acquire();
        m_reset();
        ads_lck = ads_l;
        return true;
    }

private:

    // not allowed
    dsd_mutex_locker(const dsd_mutex_locker& ds_other);
    dsd_mutex_locker& operator=(const dsd_mutex_locker& ds_other);

    dsd_mutex_lock* ads_lck;

};

//////////////////////////////////////////////////////////////////////
// 5. Handle times / delays.

// dsd_duration stores a time in seconds and fractions of a second
class dsd_duration {

public:

        // 0 seconds
        dsd_duration();

        // im_s seconds
        dsd_duration(int32 im_s);

        // im_s seconds + um_ns nanoseconds
        dsd_duration(int32 im_s, uint32 um_ns);

        // im_s seconds + us_m milli + us_u micro + us_n nano
        dsd_duration(int32 im_s, uint16 us_m, uint16 us_u, uint16 us_n);

        // gets seconds, discarding fraction
        int32 m_get_s() const;

        // gets fraction in milliseconds
        uint32 m_get_ms() const;

        // gets fraction in microseconds
        uint32 m_get_us() const;

        // gets fraction in nanoseconds
        uint32 m_get_ns() const;

        // gets milliseconds, ignoring seconds (0-999)
        uint16 m_get_m() const;

        // gets microseconds, ignoring milliseconds (0-999)
        uint16 m_get_u() const;

        // gets nanoseconds, ignoring microseconds (0-999)
        uint16 m_get_n() const;

        // gets duration in seconds, truncating milliseconds
        int32 m_in_s() const;

        // gets duration in milliseconds, truncating microseconds
        int64 m_in_m() const;

        // gets duration in microseconds, truncating nanoseconds
        int64 m_in_u() const;

        // gets duration in nanoseconds
        int64 m_in_n() const;

        dsd_duration& operator+=(const dsd_duration& ds_d);
        dsd_duration& operator-=(const dsd_duration& ds_d);

private:

        int32 im_seconds;
        uint32 um_nanos;

};

// a new dsd_duration having im_s seconds
dsd_duration m_duration_s(int32 im_s);

// a new dsd_duration having il_m milliseconds
dsd_duration m_duration_m(int64 il_m);

// a new dsd_duration having il_u microseconds
dsd_duration m_duration_u(int64 il_u);

// a new dsd_duration having il_n nanoseconds
dsd_duration m_duration_n(int64 il_n);

dsd_duration operator+(const dsd_duration& ds_d0, const dsd_duration& ds_d1);
dsd_duration operator-(const dsd_duration& ds_d0, const dsd_duration& ds_d1);

bool operator==(const dsd_duration& ds_d0, const dsd_duration& ds_d1);
bool operator!=(const dsd_duration& ds_d0, const dsd_duration& ds_d1);
bool operator<(const dsd_duration& ds_d0, const dsd_duration& ds_d1);
bool operator>=(const dsd_duration& ds_d0, const dsd_duration& ds_d1);
bool operator>(const dsd_duration& ds_d0, const dsd_duration& ds_d1);
bool operator<=(const dsd_duration& ds_d0, const dsd_duration& ds_d1);

// monotonic time - guaranteed to go go upwards only
dsd_duration m_monotonic_time();

// system time - may go down when system time is adjusted
dsd_duration m_system_time();

void m_sleep_for(dsd_duration ds_d);

inline dsd_duration::dsd_duration()
        : im_seconds(0),
          um_nanos(0)
{
}

inline dsd_duration::dsd_duration(int32 im_s)
        : im_seconds(im_s),
          um_nanos(0)
{
}

inline dsd_duration::dsd_duration(int32 im_s, uint32 um_ns)
        : im_seconds(im_s),
          um_nanos(um_ns)
{
        if (um_nanos > 1000000000) {
                im_seconds += um_nanos / 1000000000;
                um_nanos %= 1000000000;
        }
}

inline dsd_duration::dsd_duration(int32 im_s, uint16 us_m, uint16 us_u, uint16 us_n)
{
        uint32 ns = us_m;
        ns *= 1000;
        ns += us_u;
        ns *= 1000;
        ns += us_n;
        if (ns > 1000000000) {
                im_s += ns / 1000000000;
                ns %= 1000000000;
        }
        im_seconds = im_s;
        um_nanos = ns;
}

inline int32 dsd_duration::m_get_s() const
{
        return im_seconds;
}

inline uint32 dsd_duration::m_get_ms() const
{
    return um_nanos / 1000000;
}

inline uint32 dsd_duration::m_get_us() const
{
    return um_nanos / 1000;
}

inline uint32 dsd_duration::m_get_ns() const
{
        return um_nanos;
}

inline uint16 dsd_duration::m_get_m() const
{
        return uint16(um_nanos / 1000000);
}

inline uint16 dsd_duration::m_get_u() const
{
        return uint16((um_nanos / 1000) % 1000);
}

inline uint16 dsd_duration::m_get_n() const
{
        return uint16(um_nanos % 1000);
}

inline int32 dsd_duration::m_in_s() const
{
        return im_seconds;
}

inline int64 dsd_duration::m_in_m() const
{
        int64 il_d = im_seconds;
        il_d *= 1000;
        il_d += um_nanos / 1000000;
        return il_d;
}

inline int64 dsd_duration::m_in_u() const
{
        int64 il_d = im_seconds;
        il_d *= 1000000;
        il_d += um_nanos / 1000;
        return il_d;
}

inline int64 dsd_duration::m_in_n() const
{
        int64 il_d = im_seconds;
        il_d *= 1000000000;
        il_d += um_nanos;
        return il_d;
}

inline dsd_duration& dsd_duration::operator+=(const dsd_duration& ds_d)
{
        im_seconds += ds_d.im_seconds;
        um_nanos += ds_d.um_nanos;
        if (um_nanos > 1000000000) {
                um_nanos -= 1000000000;
                ++im_seconds;
        }
        return *this;
}

inline dsd_duration& dsd_duration::operator-=(const dsd_duration& ds_d)
{
        im_seconds -= ds_d.im_seconds;
        if (um_nanos < ds_d.um_nanos) {
                um_nanos += 1000000000;
                --im_seconds;
        }
        um_nanos -= ds_d.um_nanos;
        return *this;
}

inline dsd_duration m_duration_s(int32 im_s)
{
        return dsd_duration(im_s, 0);
}

inline dsd_duration m_duration_m(int64 il_m)
{
        int32 im_s = int32(il_m / 1000);
        int32 im_ns = int32(il_m % 1000) * 1000000;
        if (im_ns < 0) {
                --im_s;
                im_ns += 1000000000;
        }
        return dsd_duration(im_s, im_ns);
}

inline dsd_duration m_duration_u(int64 il_u)
{
        int32 im_s = int32(il_u / 1000000);
        int32 im_ns = int32(il_u % 1000000) * 1000;
        if (im_ns < 0) {
                --im_s;
                im_ns += 1000000000;
        }
        return dsd_duration(im_s, im_ns);
}

inline dsd_duration m_duration_n(int64 il_n)
{
        int32 im_s = int32(il_n / 1000000000);
        int32 im_ns = int32(il_n % 1000000000);
        if (im_ns < 0) {
                --im_s;
                im_ns += 1000000000;
        }
        return dsd_duration(im_s, im_ns);
}

inline dsd_duration operator+(const dsd_duration& ds_d0, const dsd_duration& ds_d1)
{
        dsd_duration ds_r = ds_d0;
        ds_r += ds_d1;
        return ds_r;
}

inline dsd_duration operator-(const dsd_duration& ds_d0, const dsd_duration& ds_d1)
{
        dsd_duration ds_r = ds_d0;
        ds_r -= ds_d1;
        return ds_r;
}

inline bool operator==(const dsd_duration& ds_d0, const dsd_duration& ds_d1)
{
        return ds_d0.m_get_s() == ds_d1.m_get_s() && ds_d0.m_get_ns() == ds_d1.m_get_ns();
}

inline bool operator!=(const dsd_duration& ds_d0, const dsd_duration& ds_d1)
{
        return !(ds_d0 == ds_d1);
}

inline bool operator<(const dsd_duration& ds_d0, const dsd_duration& ds_d1)
{
        // use "a - b < 0" rather than "a < b" because of the following:
        // - duration b is very large, close to integer wrap around
        // - duration a is (b + x), where x is +ve and small, but large enough to cause wrap
        // then, a < b is true (giving incorrect result)
        //       a - b wraps again giving +ve (giving correct result)
        return (ds_d0.m_get_s() - ds_d1.m_get_s() < 0) ||
            (ds_d0.m_get_s() == ds_d1.m_get_s() && ds_d0.m_get_ns() < ds_d1.m_get_ns());
}

inline bool operator>=(const dsd_duration& ds_d0, const dsd_duration& ds_d1)
{
        return !(ds_d0 < ds_d1);
}

inline bool operator>(const dsd_duration& ds_d0, const dsd_duration& ds_d1)
{
        return ds_d1 < ds_d0;
}

inline bool operator<=(const dsd_duration& ds_d0, const dsd_duration& ds_d1)
{
        return !(ds_d1 < ds_d0);
}

#endif // HTCP_MISC_H
