/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| PROGRAM NAME: xsltime1                                              |*/
/*| -------------                                                       |*/
/*|  Source File of HOB Time Library                                    |*/
/*|    with date and time functions                                     |*/
/*|  KB 10.11.04                                                        |*/
/*|  J.Frank 12.11.04                                                   |*/
/*|  MJ Nov 2010                                                        |*/
/*|                                                                     |*/
/*| COPYRIGHT:                                                          |*/
/*| ----------                                                          |*/
/*|  Copyright (C) HOB 2004                                             |*/
/*|  Copyright (C) HOB 2010                                             |*/
/*|  Copyright (C) HOB 2011                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

// MJ       16.11.10  we are now using own converters to avoid the timezone
//                    and daylight saving time problems
//                    additional return value added
// J.Frank  24.09.09  m_win_epoch_from_filetime(): If there was an invalid input (e.g. il_sec_1970 is 0),
//                    we must return, because the following calculations will be incorrect.
//                    Ticket[14827]: more sophisticated checkings
// J.Frank  02.04.08  Ticket[14458]: correction for daylight saving did not correctly work at summer time
// J.Frank  19.02.08  Ticket[14458]: correction for daylight saving

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#ifdef HL_UNIX
    #include <stdlib.h>
    #include <string.h>
    #include <limits.h>
    #include "hob-unix01.h"
#else
    #include <windows.h>
#endif
#include <time.h>
#include <math.h>
#include "hob-xsltime1.h"

#ifndef PTYPE
    #ifdef __cplusplus
        #define PTYPE "C"
    #else
        #define PTYPE
    #endif
#endif

/*+---------------------------------------------------------------------+*/
/*| constants:                                                          |*/
/*+---------------------------------------------------------------------+*/
#define DEF_YEAR_BASE        1900
#define DEF_SECS_PER_MIN       60
#define DEF_SECS_PER_HOUR    3600 /* 60 * 60 */
#define DEF_SECS_PER_DAY    86400 /* 24 * 60 * 60 */
#define DEF_MINS_PER_HOUR      60
#define DEF_HOURS_PER_DAY      24
#define DEF_DAYS_PER_WEEK       7
#define DEF_MONTHS_PER_YEAR    12
#define DEF_FEBRUARY            1

#define DEF_YEAR_TABLE_BASE    70 /* 1970 - 1900 */
#define DEF_YEAR_TABLE_MAX  ((int)(sizeof(ils_years_in_sec)/sizeof(time_t)))

/*+---------------------------------------------------------------------+*/
/*| constants:                                                          |*/
/*+---------------------------------------------------------------------+*/
static const char* achr_month_abbr[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};
static const char* achr_day_abbr[7] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};
static const char* achr_day_full[7] = {
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
};
static const int ins_days_per_month[2][DEF_MONTHS_PER_YEAR] = {
    { 31, /* jan */ 28, /* feb */ 31, /* mar */ 30, /* apr */
      31, /* may */ 30, /* jun */ 31, /* jul */ 31, /* aug */
      30, /* seb */ 31, /* oct */ 30, /* nov */ 31  /* dec */ },
    { 31, /* jan */ 29, /* feb */ 31, /* mar */ 30, /* apr */
      31, /* may */ 30, /* jun */ 31, /* jul */ 31, /* aug */
      30, /* seb */ 31, /* oct */ 30, /* nov */ 31  /* dec */ },
};

// years in seconds table
static const time_t ils_years_in_sec[] = {
             0, /* 01 Jan 1970 00:00:00 GMT*/
      31536000, /* 01 Jan 1971 00:00:00 GMT*/
      63072000, /* 01 Jan 1972 00:00:00 GMT*/
      94694400, /* 01 Jan 1973 00:00:00 GMT*/
     126230400, /* 01 Jan 1974 00:00:00 GMT*/
     157766400, /* 01 Jan 1975 00:00:00 GMT*/
     189302400, /* 01 Jan 1976 00:00:00 GMT*/
     220924800, /* 01 Jan 1977 00:00:00 GMT*/
     252460800, /* 01 Jan 1978 00:00:00 GMT*/
     283996800, /* 01 Jan 1979 00:00:00 GMT*/
     315532800, /* 01 Jan 1980 00:00:00 GMT*/
     347155200, /* 01 Jan 1981 00:00:00 GMT*/
     378691200, /* 01 Jan 1982 00:00:00 GMT*/
     410227200, /* 01 Jan 1983 00:00:00 GMT*/
     441763200, /* 01 Jan 1984 00:00:00 GMT*/
     473385600, /* 01 Jan 1985 00:00:00 GMT*/
     504921600, /* 01 Jan 1986 00:00:00 GMT*/
     536457600, /* 01 Jan 1987 00:00:00 GMT*/
     567993600, /* 01 Jan 1988 00:00:00 GMT*/
     599616000, /* 01 Jan 1989 00:00:00 GMT*/
     631152000, /* 01 Jan 1990 00:00:00 GMT*/
     662688000, /* 01 Jan 1991 00:00:00 GMT*/
     694224000, /* 01 Jan 1992 00:00:00 GMT*/
     725846400, /* 01 Jan 1993 00:00:00 GMT*/
     757382400, /* 01 Jan 1994 00:00:00 GMT*/
     788918400, /* 01 Jan 1995 00:00:00 GMT*/
     820454400, /* 01 Jan 1996 00:00:00 GMT*/
     852076800, /* 01 Jan 1997 00:00:00 GMT*/
     883612800, /* 01 Jan 1998 00:00:00 GMT*/
     915148800, /* 01 Jan 1999 00:00:00 GMT*/
     946684800, /* 01 Jan 2000 00:00:00 GMT*/
     978307200, /* 01 Jan 2001 00:00:00 GMT*/
    1009843200, /* 01 Jan 2002 00:00:00 GMT*/
    1041379200, /* 01 Jan 2003 00:00:00 GMT*/
    1072915200, /* 01 Jan 2004 00:00:00 GMT*/
    1104537600, /* 01 Jan 2005 00:00:00 GMT*/
    1136073600, /* 01 Jan 2006 00:00:00 GMT*/
    1167609600, /* 01 Jan 2007 00:00:00 GMT*/
    1199145600, /* 01 Jan 2008 00:00:00 GMT*/
    1230768000, /* 01 Jan 2009 00:00:00 GMT*/
    1262304000, /* 01 Jan 2010 00:00:00 GMT*/
    1293840000, /* 01 Jan 2011 00:00:00 GMT*/
    1325376000, /* 01 Jan 2012 00:00:00 GMT*/
    1356998400, /* 01 Jan 2013 00:00:00 GMT*/
    1388534400, /* 01 Jan 2014 00:00:00 GMT*/
    1420070400, /* 01 Jan 2015 00:00:00 GMT*/
    1451606400, /* 01 Jan 2016 00:00:00 GMT*/
    1483228800, /* 01 Jan 2017 00:00:00 GMT*/
    1514764800, /* 01 Jan 2018 00:00:00 GMT*/
    1546300800, /* 01 Jan 2019 00:00:00 GMT*/
    1577836800, /* 01 Jan 2020 00:00:00 GMT*/
    1609459200, /* 01 Jan 2021 00:00:00 GMT*/
    1640995200, /* 01 Jan 2022 00:00:00 GMT*/
    1672531200, /* 01 Jan 2023 00:00:00 GMT*/
    1704067200, /* 01 Jan 2024 00:00:00 GMT*/
    1735689600, /* 01 Jan 2025 00:00:00 GMT*/
    1767225600, /* 01 Jan 2026 00:00:00 GMT*/
    1798761600, /* 01 Jan 2027 00:00:00 GMT*/
    1830297600, /* 01 Jan 2028 00:00:00 GMT*/
    1861920000, /* 01 Jan 2029 00:00:00 GMT*/
    1893456000, /* 01 Jan 2030 00:00:00 GMT*/
    1924992000, /* 01 Jan 2031 00:00:00 GMT*/
    1956528000, /* 01 Jan 2032 00:00:00 GMT*/
    1988150400, /* 01 Jan 2033 00:00:00 GMT*/
    2019686400, /* 01 Jan 2034 00:00:00 GMT*/
    2051222400, /* 01 Jan 2035 00:00:00 GMT*/
    2082758400, /* 01 Jan 2036 00:00:00 GMT*/
    2114380800, /* 01 Jan 2037 00:00:00 GMT*/
    2145916800  /* 01 Jan 2038 00:00:00 GMT*/
};

/* month in seconds table: */
static const time_t ils_months_in_sec[2][DEF_MONTHS_PER_YEAR] = {
    /* normal year */
    {
               0, /* 01 Jan 00:00:00 GMT */
         2678400, /* 01 Feb 00:00:00 GMT */
         5097600, /* 01 Mar 00:00:00 GMT */
         7776000, /* 01 Apr 00:00:00 GMT */
        10368000, /* 01 May 00:00:00 GMT */
        13046400, /* 01 Jun 00:00:00 GMT */
        15638400, /* 01 Jul 00:00:00 GMT */
        18316800, /* 01 Aug 00:00:00 GMT */
        20995200, /* 01 Sep 00:00:00 GMT */
        23587200, /* 01 Oct 00:00:00 GMT */
        26265600, /* 01 Nov 00:00:00 GMT */
        28857600, /* 01 Dec 00:00:00 GMT */
    },
    /* leap year */
    {
               0, /* 01 Jan 00:00:00 GMT */
         2678400, /* 01 Feb 00:00:00 GMT */
         5184000, /* 01 Mar 00:00:00 GMT */
         7862400, /* 01 Apr 00:00:00 GMT */
        10454400, /* 01 May 00:00:00 GMT */
        13132800, /* 01 Jun 00:00:00 GMT */
        15724800, /* 01 Jul 00:00:00 GMT */
        18403200, /* 01 Aug 00:00:00 GMT */
        21081600, /* 01 Sep 00:00:00 GMT */
        23673600, /* 01 Oct 00:00:00 GMT */
        26352000, /* 01 Nov 00:00:00 GMT */
        28944000  /* 01 Dec 00:00:00 GMT */
    }
};

static const time_t ils_secs_per_year[2] = {
    365 * DEF_SECS_PER_DAY, /* normal year */
    366 * DEF_SECS_PER_DAY  /* leap year */
};

/*
   Year table for doomsday algorithm.
   See http://en.wikipedia.org/wiki/Calculating_the_day_of_the_week

   Since the Gregorian Calendar repeats every 400
   years we only needs to remember four centuries
*/
static const int ins_dd_centuries[][2] = {
    {  99, 0 }, /* 1999 in years since 1900 */
    { 199, 6 }, /* 2099 in years since 1900 */
    { 299, 4 }, /* 2199 in years since 1900 */
    { 399, 2 }  /* 2299 in years since 1900 */
};

/*
   month table for doomsday algorithm.
   See http://en.wikipedia.org/wiki/Calculating_the_day_of_the_week
*/
static const int ins_dd_months[2][DEF_MONTHS_PER_YEAR] = {
    { 0, 3, 3, 6, 1, 4, 6, 2, 5, 0, 3, 5 },
    { 6, 2, 3, 6, 1, 4, 6, 2, 5, 0, 3, 5 }
};

#ifndef HL_UNIX
    // Explanation: difference between Windows epoch (01.01.1601) and UNIX epoch (01.01.1970)
    // Both epochs are Gregorian. 1970 - 1601 = 369. Assuming a leap
    // year every four years, 369 / 4 = 92. However, 1700, 1800, and 1900
    // were NOT leap years, so 89 leap years, 280 non-leap years.
    // 89 * 366 + 280 * 365 = 134744 days between epochs. Of course
    // 60 * 60 * 24 = 86400 seconds per day, so 134744 * 86400 =
    // 11644473600 seconds between epochs
    static __int64 il_secs_between_epochs = 11644473600;
    static __int64 il_secs_to_100ns = 10000000; // 10^7
#endif

/*+---------------------------------------------------------------------+*/
/*| function declarations:                                              |*/
/*+---------------------------------------------------------------------+*/
static enum ied_hl_aux_epoch_ret m_parse_rfc_1123( const char* achp_time,
                                                   int inp_len,
                                                   struct tm* adsp_out );
static enum ied_hl_aux_epoch_ret m_parse_rfc_1036( const char* achp_time,
                                                   int inp_len,
                                                   struct tm* adsp_out );
static enum ied_hl_aux_epoch_ret m_parse_asctime ( const char* achp_time,
                                                   int inp_len,
                                                   struct tm* adsp_out );

static BOOL m_check_mday    ( struct tm* adsp_time );
static BOOL m_calc_wday     ( struct tm* adsp_time );
static void m_tm_normalize  ( struct tm* adsp_time );
static time_t m_calc_epoch  ( struct tm* adsp_time );
static BOOL m_calc_tm       ( time_t ilp_epoch, struct tm* adsp_time );


/*+---------------------------------------------------------------------+*/
/*| public functions:                                                   |*/
/*+---------------------------------------------------------------------+*/
/**
 * public function m_string_from_epoch
 * make RFC 1123 string from epoch
 *
 * @param[in]   struct dsd_hl_aux_epoch_1*  adsp_epoch
 *                  with input fields:
 *                          adsp_epoch->ac_epoch_str    pointer to ouput buffer
 *                          adsp_epoch->iec_chs_epoch   requested character set
 *                          adsp_epoch->inc_len_epoch   length of output buffer
 *                          adsp_epoch->imc_epoch_val   epoch value
 *                          adsp_epoch->iec_ep_mode     ignored
 * @return      BOOL                                    TRUE = success
 *                                                      FALSE otherwise
*/
extern PTYPE BOOL m_string_from_epoch( struct dsd_hl_aux_epoch_1* adsp_epoch )
{
    // initialize some variables:
    int       inl_max_buffer;
    struct tm dsl_time;
    BOOL      bol_ret;

    //-------------------------------------------
    // check input:
    //-------------------------------------------
    inl_max_buffer = adsp_epoch->inc_len_epoch;
    if ( inl_max_buffer < 30 ) {
        return FALSE;
    }
    if (    adsp_epoch->iec_chs_epoch != ied_chs_utf_8
         && adsp_epoch->iec_chs_epoch != ied_chs_ascii_850
         && adsp_epoch->iec_chs_epoch != ied_chs_ansi_819 ) {
        // til now we support only these formats
        return FALSE;
    }

    //-------------------------------------------
    // calculate time:
    //-------------------------------------------
    bol_ret = m_calc_tm( adsp_epoch->imc_epoch_val, &dsl_time );
    if ( bol_ret == FALSE ) {
        adsp_epoch->inc_len_epoch = 0;
        return FALSE;
    }

    //-------------------------------------------
    // format as string:
    //-------------------------------------------
    adsp_epoch->inc_len_epoch = (int)strftime( (char*)adsp_epoch->ac_epoch_str,
                                               inl_max_buffer,
                                               "%a, %d %b %Y %H:%M:%S GMT",
                                               &dsl_time );
    return ( adsp_epoch->inc_len_epoch != 0 );
} // end of m_string_from_epoch


/**
 * public function m_epoch_from_string
 * converts a time string (formatted according to RFC 822/RFC 1123
 *                                             or RFC 850/RFC 1036
 *                                             or ANSI C's asctime)
 * to epoch (time in seconds since 01 Jan 1970 00:00:00 GMT)
 * HTTP date is case sensitive (RFC2616-3.3.1)
 *
 * @param[in]   struct dsd_hl_aux_epoch_1*  adsp_epoch
 *                  with input fields:
 *                          adsp_epoch->ac_epoch_str    pointer to input buffer
 *                          adsp_epoch->iec_chs_epoch   character set of input
 *                          adsp_epoch->inc_len_epoch   length of input buffer
 *                          adsp_epoch->imc_epoch_val   output epoch value
 *                          adsp_epoch->iec_ep_mode     parse mode
 * @return      BOOL                                    TRUE = success
 *                                                      FALSE otherwise
*/
extern PTYPE BOOL m_epoch_from_string( struct dsd_hl_aux_epoch_1 *adsp_epoch )
{
    // initialize some variables:
    char*     achl_time;                    // pointer to time string
    int       inl_len;                      // length of time string
    struct tm dsl_time;                     // result of parsing
    time_t    ill_time;                     // unix epoch
    BOOL      bol_ret;                      // return for some function calls


    if (    adsp_epoch->iec_chs_epoch != ied_chs_utf_8
         && adsp_epoch->iec_chs_epoch != ied_chs_ascii_850
         && adsp_epoch->iec_chs_epoch != ied_chs_ansi_819  ) {
        adsp_epoch->imc_epoch_val = -1;
        return FALSE;
    }

    achl_time = (char*)adsp_epoch->ac_epoch_str;
    inl_len = adsp_epoch->inc_len_epoch;
    // skip leading spaces:
    while ( *achl_time == ' ' ) {
        if ( inl_len == 0 ) {
            adsp_epoch->imc_epoch_val = -1;
            return FALSE;
        }
        achl_time++;
        inl_len--;
    }
    if ( inl_len < 4 ) {
        adsp_epoch->imc_epoch_val = -1;
        return FALSE; // to short -> invalid length
    }

    //-------------------------------------------
    // parse given string:
    //-------------------------------------------
    /*allowed date formats
       (1)  Sun, 06 Nov 1994 08:49:37 GMT   RFC 822; updated by RFC 1123
       (2)  Sunday, 06-Nov-94 08:49:37 GMT  RFC 850; obsoleted by RFC 1036
       (3)  Sun Nov  6 08:49:37 1994        ANSI C's asctime() format
       we read char at position 3; it must be
        (1) ','
        (2) {'d', 's','n', 'r', 'u'}
        (3) 0x20
    */

    if ( achl_time[3] == ',' ) {
        // Sun, 06 Nov 1994 08:49:37 GMT
        adsp_epoch->iec_parse_ret = m_parse_rfc_1123( achl_time, inl_len, &dsl_time );
    } else if (    achl_time[3] == 'd'
                || achl_time[3] == 'n'
                || achl_time[3] == 'r'
                || achl_time[3] == 's'
                || achl_time[3] == 'u' ) {
        // Sunday, 06-Nov-94 08:49:37 GMT
        adsp_epoch->iec_parse_ret = m_parse_rfc_1036( achl_time, inl_len, &dsl_time );
    } else if ( achl_time[3] == ' ' ) {
        // Sun Nov  6 08:49:37 1994
        adsp_epoch->iec_parse_ret = m_parse_asctime( achl_time, inl_len, &dsl_time );
    } else {
        // unknown or unsupported time format
        adsp_epoch->iec_parse_ret = ied_hl_aux_ep_failed;
    }

    if ( adsp_epoch->iec_parse_ret == ied_hl_aux_ep_failed ) {
        adsp_epoch->imc_epoch_val = -1;
        return FALSE;
    }

    //-------------------------------------------
    // validate given time:
    //-------------------------------------------
    if ( adsp_epoch->iec_parse_ret == ied_hl_aux_ep_ok ) {
        // check correct day in month:
        bol_ret = m_check_mday( &dsl_time );
        if ( bol_ret == TRUE ) {
            // check correct week day:
            if ( dsl_time.tm_wday != m_calc_wday(&dsl_time) ) {
                adsp_epoch->iec_parse_ret = ied_hl_aux_ep_inv_wday;
            }
        } else {
            adsp_epoch->iec_parse_ret = ied_hl_aux_ep_inv_mday;
        }
    }

    //-------------------------------------------
    // calculate epoch:
    //-------------------------------------------
    m_tm_normalize( &dsl_time );
    ill_time = m_calc_epoch( &dsl_time );
    // SM_CHANGED
    if(ill_time > INT_MAX)
        ill_time = INT_MAX;
    adsp_epoch->imc_epoch_val = (int)ill_time;
    return TRUE;
} // end of m_epoch_from_string


#ifdef HL_WINALL1
/**
 * public function m_win_epoch_from_filetime
 * takes a win32 FILETIME structure, returns the equivalent epoch value
 *
 * @param[in]   struct _FILETIME*   adsp_filetime   windows filetime
 * @return      int                                 unix epoch
*/
extern PTYPE int m_win_epoch_from_filetime( struct _FILETIME *adsp_filetime ) {
    // get the full win32 value, in 100ns-elements
    __int64 il_sec_1970 = ((__int64)adsp_filetime->dwHighDateTime << 32) + adsp_filetime->dwLowDateTime;

    // 24.09.09 If there was an invalid input (e.g. il_sec_1970 is 0),
    // we must return, because the following calculations will be incorrect.
    if ( il_sec_1970 < 1 ) {
        return 0;
    }

    // convert to nanosec since 1970
    il_sec_1970 -= (il_secs_between_epochs * il_secs_to_100ns);
    // now convert to seconds
    il_sec_1970 /= il_secs_to_100ns;

    return (int)il_sec_1970;
} // end of m_win_epoch_from_filetime
#endif

/*+---------------------------------------------------------------------+*/
/*| private functions:                                                  |*/
/*+---------------------------------------------------------------------+*/
/**
 * private function m_parse_rfc_1123
 * parse an rfc 822/rfc 1123 string and return struct tm
 * format will be: Sun, 06 Nov 1994 08:49:37 GMT
 *
 * @param[in]   const char*                 achp_time   time string
 * @param[in]   int                         inp_len     length of time string
 * @param[out]  struct tm*                  adsp_out    output tm struct
 * @return      enum ied_hl_aux_epoch_ret
*/
static enum ied_hl_aux_epoch_ret m_parse_rfc_1123( const char* achp_time,
                                                   int inp_len,
                                                   struct tm* adsp_out )
{
    // initialize some variables:
    enum ied_hl_aux_epoch_ret iel_ret;          // return code
    int                       inl_count;        // counter for some loops
    int                       inl_offset;       // offset in time string
    char*                     achl_end;         // end pointer for strtol func

    //-------------------------------------------
    // check min length:
    //-------------------------------------------
    iel_ret = ied_hl_aux_ep_ok;
    if ( inp_len < 28 ) {
        return ied_hl_aux_ep_failed;
    }

    //-------------------------------------------
    // get day of week:
    //-------------------------------------------
    adsp_out->tm_wday = -1;
    for ( inl_count = 0; inl_count < DEF_DAYS_PER_WEEK; inl_count++ ) {
        if ( strncmp(achp_time, achr_day_abbr[inl_count], 3) == 0 ) {
            adsp_out->tm_wday = inl_count;
            break;
        }
    }
    if ( adsp_out->tm_wday == -1 ) {
        return ied_hl_aux_ep_failed;
    }

    // behind "," a space is following:
    inl_offset = 4;
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read day of month:
    //-------------------------------------------
    adsp_out->tm_mday = (int)strtol( &achp_time[inl_offset], &achl_end, 10 );
    if (    adsp_out->tm_mday < 1
         || adsp_out->tm_mday > 31 ) {
        return ied_hl_aux_ep_failed;
    }
    // should have two digits
    if ( (int)( achl_end - &achp_time[inl_offset] ) < 2 ) {
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset += (int)( achl_end - &achp_time[inl_offset] );

    // space should follow
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read month-string:
    //-------------------------------------------
    adsp_out->tm_mon = -1;
    for ( inl_count = 0; inl_count < DEF_MONTHS_PER_YEAR; inl_count++ ) {
        if ( strncmp(&achp_time[inl_offset], achr_month_abbr[inl_count], 3) == 0 ) {
            adsp_out->tm_mon = inl_count;
            break;
        }
    }
    if ( adsp_out->tm_mon == -1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 3;

    // space should follow:
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read 4 digit year:
    //-------------------------------------------
    // check for numeric values:
    if (    achp_time[inl_offset]     < '0'
         || achp_time[inl_offset]     > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9'
         || achp_time[inl_offset + 2] < '0'
         || achp_time[inl_offset + 2] > '9'
         || achp_time[inl_offset + 3] < '0'
         || achp_time[inl_offset + 3] > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    // adsp_out->tm_year is years since 1900
    adsp_out->tm_year = atoi( &achp_time[inl_offset] ) - 1900;
    if ( adsp_out->tm_year < 70 ) {
        return ied_hl_aux_ep_inv_year;
    }
    inl_offset += 4;

    // space should follow:
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read hours:
    //-------------------------------------------
    // check for numeric values:
    if (    achp_time[inl_offset    ] < '0'
         || achp_time[inl_offset    ] > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_hour = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_hour < 0
         || adsp_out->tm_hour > DEF_HOURS_PER_DAY - 1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // ':' must follow:
    if ( achp_time[inl_offset] != ':' ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset++;

    //-------------------------------------------
    // read minutes:
    //-------------------------------------------
    // check for numeric values:
    if (    achp_time[inl_offset    ] < '0'
         || achp_time[inl_offset    ] > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_min = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_min < 0
         || adsp_out->tm_min > DEF_MINS_PER_HOUR - 1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // ':' must follow:
    if ( achp_time[inl_offset] != ':' ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset++;

    //-------------------------------------------
    // read seconds:
    //-------------------------------------------
    // check for numeric values:
    if (    achp_time[inl_offset    ] < '0'
         || achp_time[inl_offset    ] > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_sec = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_sec < 0
         || adsp_out->tm_sec > DEF_SECS_PER_MIN - 1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // space should follow:
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read timezone:
    //-------------------------------------------
    // "GMT" should follow
    if ( achp_time[inl_offset] == 'G' ) {
        inl_offset++;
        if (    achp_time[inl_offset++] != 'M'
             || achp_time[inl_offset]   != 'T' ) {
            return ied_hl_aux_ep_failed;
        }
    } else if ( achp_time[inl_offset] == 'U' ) {
        inl_offset++;
        if (    achp_time[inl_offset++] != 'T'
             || achp_time[inl_offset]   != 'C' ) {
            return ied_hl_aux_ep_failed;
        }
    } else {
        return ied_hl_aux_ep_failed;
    }
    return iel_ret;
} // end of m_parse_rfc_1123


/**
 * private function m_parse_rfc_1036
 * parse an rfc 850/rfc 1036 string and return struct tm
 * format will be: Sunday, 06-Nov-94 08:49:37 GMT
 *
 * @param[in]   const char*                 achp_time   time string
 * @param[in]   int                         inp_len     length of time string
 * @param[out]  struct tm*                  adsp_out    output tm struct
 * @return      enum ied_hl_aux_epoch_ret
*/
static enum ied_hl_aux_epoch_ret m_parse_rfc_1036( const char* achp_time,
                                                   int inp_len,
                                                   struct tm* adsp_out )
{
    // initialize some variables:
    enum ied_hl_aux_epoch_ret iel_ret;          // return code
    int                       inl_count;        // counter for some loops
    int                       inl_offset;       // offset in time string

    //-------------------------------------------
    // get day of week:
    //-------------------------------------------
    iel_ret    = ied_hl_aux_ep_ok;
    inl_offset = -1;
    for ( inl_count = 0; inl_count < inp_len; inl_count++ ) {
        if ( achp_time[inl_count] == ',' ) {
            inl_offset = inl_count;
            break;
        }
    }
    if ( inl_offset < 0 ) {
        return ied_hl_aux_ep_failed;
    }

    adsp_out->tm_wday = -1;
    for ( inl_count = 0; inl_count < DEF_DAYS_PER_WEEK; inl_count++ ) {
        if (    inl_offset == (int)strlen( achr_day_full[inl_count] )
             && strncmp(achp_time, achr_day_full[inl_count], inl_offset) == 0 ) {
            adsp_out->tm_wday = inl_count;
            break;
        }
    }
    if ( adsp_out->tm_wday == -1 ) {
        return ied_hl_aux_ep_failed;
    }

    //-------------------------------------------
    // check minimum length:
    //-------------------------------------------
    if ( inp_len < inl_offset + 24 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset++;

    // space should follow:
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read day:
    //-------------------------------------------
    if (    achp_time[inl_offset]     < '0'
         || achp_time[inl_offset]     > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_mday = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_mday < 1
         || adsp_out->tm_mday > 31 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // '-' should follow:
    if ( achp_time[inl_offset] != '-' ) {
        if (    achp_time[inl_offset] != ' '
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read month-string:
    //-------------------------------------------
    adsp_out->tm_mon = -1;
    for ( inl_count = 0; inl_count < DEF_MONTHS_PER_YEAR; inl_count++ ) {
        if ( strncmp( &achp_time[inl_offset], achr_month_abbr[inl_count], 3) == 0 ) {
            adsp_out->tm_mon = inl_count;
            break;
        }
    }
    if ( adsp_out->tm_mon == -1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 3;

    // '-' should follow:
    if ( achp_time[inl_offset] != '-' ) {
        if (    achp_time[inl_offset] != ' '
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read year (should have 2 digits):
    //-------------------------------------------
    if (    achp_time[inl_offset]      < '0'
         || achp_time[inl_offset]      > '9'
         || achp_time[inl_offset + 1]  < '0'
         || achp_time[inl_offset + 1]  > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_year = atoi( &achp_time[inl_offset] );
    if ( adsp_out->tm_year > 99 ) {
        adsp_out->tm_year -= 1900;
        inl_offset += 2;
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    if ( adsp_out->tm_year < 0 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // space should follow:
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read hours:
    //-------------------------------------------
    if (    achp_time[inl_offset]      < '0'
         || achp_time[inl_offset]      > '9'
         || achp_time[inl_offset + 1]  < '0'
         || achp_time[inl_offset + 1]  > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_hour = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_hour < 0
         || adsp_out->tm_hour > DEF_HOURS_PER_DAY - 1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    //  ":" must follow
    if ( achp_time[inl_offset] != ':' ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset++;

    //-------------------------------------------
    // read minutes:
    //-------------------------------------------
    if (    achp_time[inl_offset]      < '0'
         || achp_time[inl_offset]      > '9'
         || achp_time[inl_offset + 1]  < '0'
         || achp_time[inl_offset + 1]  > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_min = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_min <  0
         || adsp_out->tm_min > DEF_MINS_PER_HOUR - 1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    //  ":" must follow
    if ( achp_time[inl_offset] != ':' ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset++;

    //-------------------------------------------
    // read seconds:
    //-------------------------------------------
    if (    achp_time[inl_offset]      < '0'
         || achp_time[inl_offset]      > '9'
         || achp_time[inl_offset + 1]  < '0'
         || achp_time[inl_offset + 1]  > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_sec = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_sec <  0
         || adsp_out->tm_sec > DEF_SECS_PER_MIN - 1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // space should follow:
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read timezone:
    //-------------------------------------------
    // "GMT" should follow
    if ( achp_time[inl_offset] == 'G' ) {
        inl_offset++;
        if (    achp_time[inl_offset++] != 'M'
             || achp_time[inl_offset]   != 'T' ) {
            return ied_hl_aux_ep_failed;
        }
    } else if ( achp_time[inl_offset] == 'U' ) {
        inl_offset++;
        if (    achp_time[inl_offset++] != 'T'
             || achp_time[inl_offset]   != 'C' ) {
            return ied_hl_aux_ep_failed;
        }
    } else {
        return ied_hl_aux_ep_failed;
    }
    return iel_ret;
} // end of m_parse_rfc_1036


/**
 * private function m_parse_asctime
 * parse an ANSI C's asctime() format string and return struct tm
 * format will be: Sun Nov  6 08:49:37 1994
 *
 * @param[in]   const char*                 achp_time   time string
 * @param[in]   int                         inp_len     length of time string
 * @param[out]  struct tm*                  adsp_out    output tm struct
 * @return      enum ied_hl_aux_epoch_ret
*/
static enum ied_hl_aux_epoch_ret m_parse_asctime( const char* achp_time,
                                                  int inp_len,
                                                  struct tm* adsp_out )
{
    // initialize some variables:
    enum ied_hl_aux_epoch_ret iel_ret;          // return code
    int                       inl_count;        // counter for some loops
    int                       inl_offset;       // offset in time string

    //-------------------------------------------
    // check min length:
    //-------------------------------------------
    iel_ret = ied_hl_aux_ep_ok;
    if ( inp_len < 24 ) {
        return ied_hl_aux_ep_failed;
    }

    //-------------------------------------------
    // get day of week:
    //-------------------------------------------
    adsp_out->tm_wday = -1;
    for ( inl_count = 0; inl_count < DEF_DAYS_PER_WEEK; inl_count++ ) {
        if ( strncmp(achp_time, achr_day_abbr[inl_count], 3) == 0 ) {
            adsp_out->tm_wday = inl_count;
            break;
        }
    }
    if ( adsp_out->tm_wday == -1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset = 4;

    //-------------------------------------------
    // get month:
    //-------------------------------------------
    adsp_out->tm_mon = -1;
    for ( inl_count = 0; inl_count < DEF_MONTHS_PER_YEAR; inl_count++ ) {
        if ( strncmp(&achp_time[inl_offset], achr_month_abbr[inl_count], 3) == 0 ) {
            adsp_out->tm_mon = inl_count;
            break;
        }
    }
    if ( adsp_out->tm_mon == -1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 3;

    // space should follow:
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read day:
    //-------------------------------------------
    if (    achp_time[inl_offset]     < '0'
         || achp_time[inl_offset]     > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9' ) {
        if (achp_time[inl_offset] != ' ') { // first character may be 0x20
            return ied_hl_aux_ep_failed;
        }
    }
    adsp_out->tm_mday = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_mday <  1
         || adsp_out->tm_mday > 31 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // space should follow:
    if ( achp_time[inl_offset] != ' ' ) {
        if (    achp_time[inl_offset] != '-'
             && achp_time[inl_offset] != '/' ) {
            return ied_hl_aux_ep_failed;
        }
        iel_ret = ied_hl_aux_ep_inv_format;
    }
    inl_offset++;

    //-------------------------------------------
    // read hour:
    //-------------------------------------------
    if (    achp_time[inl_offset]     < '0'
         || achp_time[inl_offset]     > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_hour = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_hour < 0
         || adsp_out->tm_hour > DEF_HOURS_PER_DAY - 1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // ":" must follow:
    if ( achp_time[inl_offset] != ':' ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset++;

    //-------------------------------------------
    // read minutes:
    //-------------------------------------------
    if (    achp_time[inl_offset]     < '0'
         || achp_time[inl_offset]     > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_min = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_min < 0
         || adsp_out->tm_min > DEF_MINS_PER_HOUR - 1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // ":" must follow:
    if ( achp_time[inl_offset] != ':' ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset++;

    //-------------------------------------------
    // read secondes:
    //-------------------------------------------
    if (    achp_time[inl_offset]     < '0'
         || achp_time[inl_offset]     > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    adsp_out->tm_sec = atoi( &achp_time[inl_offset] );
    if (    adsp_out->tm_sec < 0
         || adsp_out->tm_sec > DEF_SECS_PER_MIN - 1 ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset += 2;

    // space must follow:
    if ( achp_time[inl_offset] != ' ' ) {
        return ied_hl_aux_ep_failed;
    }
    inl_offset++;

    //-------------------------------------------
    // read year:
    //-------------------------------------------
    if (    achp_time[inl_offset]     < '0'
         || achp_time[inl_offset]     > '9'
         || achp_time[inl_offset + 1] < '0'
         || achp_time[inl_offset + 1] > '9'
         || achp_time[inl_offset + 2] < '0'
         || achp_time[inl_offset + 2] > '9'
         || achp_time[inl_offset + 3] < '0'
         || achp_time[inl_offset + 3] > '9' ) {
        return ied_hl_aux_ep_failed;
    }
    // Attention: ds_tm.tm_year is years since 1900
    adsp_out->tm_year = atoi( &achp_time[inl_offset] ) - 1900;
    if ( adsp_out->tm_year < 0 ) {
        return ied_hl_aux_ep_inv_year;
    }
    return iel_ret;
} // end of m_parse_asctime


/**
 * private function m_is_leap_year
 * check if given year is a leap year
 *
 * @param[in]   int     inp_year        year since 1900
 * @return      BOOL                    TRUE  = is leap year
 *                                      FALSE = no leap year
*/
static BOOL m_is_leap_year( int inp_year )
{
    inp_year += DEF_YEAR_BASE;
    /*
        leap year:
            is divisable by 4 and not by 100
            is divisable by 400
    */
    if (    (     inp_year % 4   == 0
               && inp_year % 100 != 0 )
         ||       inp_year % 400 == 0 ) {
        return TRUE;
    }
    return FALSE;
} // end of m_is_leap_year


/**
 * private function m_check_mday
 * check if given day is valid for in this month
 *
 * @param[in]   struct tm*  adsp_time
 * @return      BOOL                    TRUE = day is valid
*/
static BOOL m_check_mday( struct tm* adsp_time )
{
    BOOL bol_leap = m_is_leap_year( adsp_time->tm_year );
    if (    adsp_time->tm_mday < 1
         || adsp_time->tm_mday > ins_days_per_month[bol_leap][adsp_time->tm_mon] ) {
        return FALSE;
    }
    return TRUE;
} // end of m_check_mday


/**
 * private function m_check_wday
 * calculate weekday frim given timestamp
 *
 * @param[in]   struct tm*  adsp_time
 * @return      int                     weekday
*/
static int m_calc_wday( struct tm* adsp_time )
{
    // initialize some variables:
    int  inl_count;
    int  inl_year;
    int  inl_century = -1;
    int  inl_month;
    BOOL bol_leap;

    //-------------------------------------------
    // get entry from century table:
    //-------------------------------------------
    inl_year = adsp_time->tm_year;
    while ( inl_year > 399 ) {
        inl_year -= 400;
    }
    for ( inl_count = 0; inl_count < 4; inl_count++ ) {
        if ( inl_year < ins_dd_centuries[inl_count][0] ) {
            inl_year    -= inl_count * 100;
            inl_century  = ins_dd_centuries[inl_count][1];
            break;
        }
    }
    if ( inl_century < 0 ) {
        return -1;
    }

    bol_leap  = m_is_leap_year( adsp_time->tm_year );
    inl_month = ins_dd_months[bol_leap][ adsp_time->tm_mon ];

    return (inl_century + inl_year + (int)floor((float)inl_year/4) + inl_month + adsp_time->tm_mday)%7;
} // end of m_calc_wday


/**
 * private function m_calc_epoch
 * calculate unix epoch from given time in GMT!
 *
 * @param[in]   struct tm*  adsp_time       time to be calculated
 * @return      time_t                      unix epoch
*/
static time_t m_calc_epoch( struct tm* adsp_time )
{
    // initialize some variables:
    time_t ill_epoch;                       // unix epoch
    int    inl_index;                       // table index
    int    inl_count;                       // loop counter
    BOOL   bol_leap;                        // is leap year

    inl_index = adsp_time->tm_year - DEF_YEAR_TABLE_BASE;
    if ( inl_index < 0 ) {
        return -1;
    }

    //-------------------------------------------
    // get epoch from year:
    //-------------------------------------------
    if ( inl_index < DEF_YEAR_TABLE_MAX ) {
        ill_epoch = ils_years_in_sec[inl_index];
    } else {
        ill_epoch = ils_years_in_sec[DEF_YEAR_TABLE_MAX - 1];
        // we have to calculate the missing years in our table by hand
        for ( inl_count = DEF_YEAR_TABLE_MAX + DEF_YEAR_TABLE_BASE; inl_count <= adsp_time->tm_year; inl_count++ ) {
            bol_leap = m_is_leap_year( inl_count );
            ill_epoch += ils_secs_per_year[bol_leap];
        }
    }

    //-------------------------------------------
    // add epoch for months:
    //-------------------------------------------
    bol_leap   = m_is_leap_year( adsp_time->tm_year );
    ill_epoch += ils_months_in_sec[bol_leap][adsp_time->tm_mon];

    //-------------------------------------------
    // add epoch for day, hour, min, sec:
    //-------------------------------------------
    ill_epoch +=   (adsp_time->tm_mday - 1) * DEF_SECS_PER_DAY  /* days    */
                  + adsp_time->tm_hour      * DEF_SECS_PER_HOUR /* hours   */
                  + adsp_time->tm_min       * DEF_SECS_PER_MIN  /* minutes */
                  + adsp_time->tm_sec;                          /* seconds */
    return ill_epoch;
} // end of m_calc_epoch


/**
 * private function m_calc_tm
 * calculate time in GMT from given unix epoch
 *
 * @param[in]   time_t      ilp_epoch       unix epoch
 * @param[out]  struct tm*  adsp_time       time to be calculated
 * @return      BOOL                        TRUE = success
*/
static BOOL m_calc_tm( time_t ilp_epoch, struct tm* adsp_time )
{
    // initialize some variables:
    int  inl_index;
    BOOL bol_leap;

    //-------------------------------------------
    // get year:
    //-------------------------------------------
    inl_index = (int)(ilp_epoch/ils_secs_per_year[0]);
    if (    inl_index < DEF_YEAR_TABLE_MAX                        /* we are in table */
         || ilp_epoch < ils_years_in_sec[DEF_YEAR_TABLE_MAX - 1]  /* index is over table,
                                                                     but we are still in */ ) {
        if ( inl_index > DEF_YEAR_TABLE_MAX - 1 ) {
            inl_index = DEF_YEAR_TABLE_MAX - 1;
        }

        // this index might be big (leap years)
        while ( ilp_epoch < ils_years_in_sec[inl_index] ) {
            inl_index--;
            if ( inl_index < 0 ) {
                return FALSE;
            }
        }

        ilp_epoch          -= ils_years_in_sec[inl_index];
        adsp_time->tm_year  = inl_index + DEF_YEAR_TABLE_BASE;
    } else {
        ilp_epoch -= ils_years_in_sec[DEF_YEAR_TABLE_MAX - 1];

        // we have to calculate the missing years in our table by hand
        for ( adsp_time->tm_year = DEF_YEAR_TABLE_MAX + DEF_YEAR_TABLE_BASE; adsp_time->tm_year > 0; adsp_time->tm_year++ ) {
            bol_leap = m_is_leap_year( adsp_time->tm_year );
            if ( ilp_epoch < ils_secs_per_year[bol_leap] ) {
                adsp_time->tm_year--;
                break;
            }
            ilp_epoch -= ils_secs_per_year[bol_leap];
        }
    }

    //-------------------------------------------
    // get day in year:
    //-------------------------------------------
    adsp_time->tm_yday = (int)(ilp_epoch/DEF_SECS_PER_DAY);

    //-------------------------------------------
    // get month:
    //-------------------------------------------
    bol_leap = m_is_leap_year( adsp_time->tm_year );
    adsp_time->tm_mon = DEF_MONTHS_PER_YEAR - 1;
    while ( ilp_epoch < ils_months_in_sec[bol_leap][adsp_time->tm_mon] ) {
        adsp_time->tm_mon--;
    }
    ilp_epoch -= ils_months_in_sec[bol_leap][adsp_time->tm_mon];

    //-------------------------------------------
    // get mday, hours, minutes and seconds:
    //-------------------------------------------
    adsp_time->tm_mday = (int)(ilp_epoch/DEF_SECS_PER_DAY) + 1; /* range 1 - 31 */
    ilp_epoch          = ilp_epoch%DEF_SECS_PER_DAY;
    adsp_time->tm_hour = (int)(ilp_epoch/DEF_SECS_PER_HOUR);
    ilp_epoch          = ilp_epoch%DEF_SECS_PER_HOUR;
    adsp_time->tm_min  = (int)(ilp_epoch/DEF_SECS_PER_MIN);
    ilp_epoch          = ilp_epoch%DEF_SECS_PER_MIN;
    adsp_time->tm_sec  = (int)ilp_epoch;

    //-------------------------------------------
    // get weekday:
    //-------------------------------------------
    adsp_time->tm_wday = m_calc_wday( adsp_time );
    if ( adsp_time->tm_wday < 0 ) {
        return FALSE;
    }

    adsp_time->tm_isdst = 0;
    return TRUE;
} // end of m_calc_tm


/**
 * static function m_normalize
 * normalize lower unit
 *
 * @param[in/out]   int*    ainp_high           higher unit
 * @param[in/out]   int*    ainp_low            lower unit
 * @param[in]       int     inp_max             max value for lower unit
*/
static void m_normalize( int* ainp_high, int* ainp_low, int inp_max )
{
	if (*ainp_low >= inp_max) {
		*ainp_high += *ainp_low / inp_max;
		*ainp_low %= inp_max;
	} else if (*ainp_low < 0) {
		--*ainp_high;
		*ainp_low += inp_max;
		if (*ainp_low < 0) {
			*ainp_high -= 1 + (-*ainp_low) / inp_max;
			*ainp_low = inp_max - (-*ainp_low) % inp_max;
		}
	}
} // end of m_normalize


/**
 * private function m_tm_normalize
 * normalize given structure
 *
 * @param[in/out]   struct tm*  adsp_time
*/
static void m_tm_normalize( struct tm* adsp_time )
{
    // initialize some variables:
    int inl_days;

    /* normalize seconds, minutes, hours and month */
    m_normalize( &adsp_time->tm_min,  &adsp_time->tm_sec,  DEF_SECS_PER_MIN    );
    m_normalize( &adsp_time->tm_hour, &adsp_time->tm_min,  DEF_MINS_PER_HOUR   );
    m_normalize( &adsp_time->tm_mday, &adsp_time->tm_hour, DEF_HOURS_PER_DAY   );
    m_normalize( &adsp_time->tm_year, &adsp_time->tm_mon,  DEF_MONTHS_PER_YEAR );

    /*
        days of month has to be normalized manually,
        cause we have a different number of days per month
    */
    while ( adsp_time->tm_mday < 1 ) {
        adsp_time->tm_mon--;
        if ( adsp_time->tm_mon < 0 ) {
            adsp_time->tm_mon = DEF_MONTHS_PER_YEAR - 1;
            adsp_time->tm_year--;
        }
        if (    adsp_time->tm_mon == DEF_FEBRUARY
             && m_is_leap_year( adsp_time->tm_year ) ) {
            adsp_time->tm_mday += ins_days_per_month[1][DEF_FEBRUARY];
        } else {
            adsp_time->tm_mday += ins_days_per_month[0][adsp_time->tm_mon];
        }
    }

    for ( ; ; ) {
        if (    adsp_time->tm_mon == DEF_FEBRUARY
             && m_is_leap_year( adsp_time->tm_year ) ) {
            inl_days = ins_days_per_month[1][DEF_FEBRUARY];
        } else {
            inl_days = ins_days_per_month[0][adsp_time->tm_mon];
        }
        if ( adsp_time->tm_mday <= inl_days ) {
            break;
        }
        adsp_time->tm_mday -= inl_days;
        adsp_time->tm_mon++;
        if ( adsp_time->tm_mon >= DEF_MONTHS_PER_YEAR ) {
            adsp_time->tm_mon = 0;
            adsp_time->tm_year++;
        }
    }
} // end of m_tm_normalize
