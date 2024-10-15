/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsltime1                                            |*/
/*| -------------                                                     |*/
/*|  Source File of HOB Time Library                                  |*/
/*|    with date and time functions                                   |*/
/*|  KB 10.11.04                                                      |*/
/*|  J.Frank 12.11.04                                                 |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

// J.Frank  16.06.08  Ticket[14827]: more sophisticated checkings
// J.Frank  02.04.08  Ticket[14458]: correction for daylight saving did not correctly work at summer time
// J.Frank  19.02.08  Ticket[14458]: correction for daylight saving

// MJ 16.06.08:
#define FOR_WEBSERVER_GATE

#if defined WIN32 || defined WIN64
#ifndef HL_WINALL1
#define HL_WINALL1
#endif
#endif

#ifdef HL_WINALL1
#include <windows.h>
#endif

#ifdef FOR_WEBSERVER_GATE // MJ 16.02.08 use one(!) header file
#include "hob-xsltime1.h"
#endif

#ifndef HL_UNIX
    #ifndef FOR_WEBSERVER_GATE
        #include "./xsltime1.h"
    #endif
#else
    #include <stdlib.h>
    #include <pthread.h>
    #include "hob-hunix01.h"
    #ifndef FOR_WEBSERVER_GATE
        #include "hob-xsltime1.h"
    #endif
#endif

#include <time.h>

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#if defined HL_HPUX
extern "C" char * strchr(const char *, int);
#endif

static char* achr_month_abbr[12] = {
  (char *) "Jan",
  (char *) "Feb",
  (char *) "Mar",
  (char *) "Apr",
  (char *) "May",
  (char *) "Jun",
  (char *) "Jul",
  (char *) "Aug",
  (char *) "Sep",
  (char *) "Oct",
  (char *) "Nov",
  (char *) "Dec"};

static char* achr_day_abbr[7] = {
  (char *) "Sun",
  (char *) "Mon",
  (char *) "Tue",
  (char *) "Wed",
  (char *) "Thu",
  (char *) "Fri",
  (char *) "Sat"};

static char* achr_day_full[7] = {
  (char *) "Sunday",
  (char *) "Monday",
  (char *) "Tuesday",
  (char *) "Wednesday",
  (char *) "Thursday",
  (char *) "Friday",
  (char *) "Saturday"};

#ifdef HL_WINALL1
    static __int64 il_secs_between_epochs = 11644473600;
    static __int64 il_secs_to_100ns = 10000000; // 10^7
#else // UNIX
    static pthread_mutex_t dsd_time_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static int m_get_diff_to_utc(time_t& dsl_time_t);
//static int m_get_daylight_saving(time_t& dsl_time_t); // JF 19.02.08
static bool m_check_day_in_month(int in_month, int in_day); // JF 16.06.08 Ticket[14827]


/* make RFC 1123 string from epoch (time in seconds)                   */
#ifndef FOR_WEBSERVER_GATE
extern PTYPE BOOL m_string_from_epoch( struct dsd_hl_aux_epoch_1 *adsp_epoch ) {
#else // wsg definitions:
bool m_string_from_epoch( struct dsd_hl_aux_epoch_1 *adsp_epoch ) {
#endif // FOR_WEBSERVER_GATE
   time_t     dsl_time;

#if !defined HL_UNIX
   int        inl_rc;                       /* return error            */
   struct tm  dsl_tm;
#else
   struct tm* ads_tm;
#endif

    int in_maxsize = adsp_epoch->inc_len_epoch;
    if (in_maxsize < 30) {
        return false;
    }
   if (   (adsp_epoch->iec_chs_epoch != ied_chs_utf_8)
       && (adsp_epoch->iec_chs_epoch != ied_chs_ascii_850)
       && (adsp_epoch->iec_chs_epoch != ied_chs_ansi_819)) { // til now we support only these formats
     return false;
   }
        
    dsl_time = (time_t) adsp_epoch->imc_epoch_val;


#if !defined HL_UNIX
    inl_rc = gmtime_s( &dsl_tm, &dsl_time );
    if (inl_rc != 0) { // some error occured
        return false;
    }
    adsp_epoch->inc_len_epoch = (int)strftime((char*)adsp_epoch->ac_epoch_str,
              in_maxsize, "%a, %d %b %Y %H:%M:%S GMT", &dsl_tm );
#else // HL_UNIX
    pthread_mutex_lock(&dsd_time_mutex);

    ads_tm = gmtime( &dsl_time );
    adsp_epoch->inc_len_epoch = (int)strftime((char*)adsp_epoch->ac_epoch_str,
              (time_t) in_maxsize, "%a, %d %b %Y %H:%M:%S GMT", ads_tm );
    pthread_mutex_unlock(&dsd_time_mutex);
#endif // HL_UNIX

    return (adsp_epoch->inc_len_epoch != 0);
}



// converts a time string (formatted according to RFC 822/RFC 1123 or RFC 850/RFC 1036 or
// ANSI C's asctime()) to epoch (time in seconds)
// HTTP date is case sensitive (RFC2616-3.3.1)
// function returns false in case of error
#ifndef FOR_WEBSERVER_GATE
extern PTYPE BOOL m_epoch_from_string( struct dsd_hl_aux_epoch_1 *adsp_epoch ) {
#else // wsg definitions:
bool m_epoch_from_string( struct dsd_hl_aux_epoch_1 *adsp_epoch ) {
#endif // FOR_WEBSERVER_GATE

   if (   (adsp_epoch->iec_chs_epoch != ied_chs_utf_8)
       && (adsp_epoch->iec_chs_epoch != ied_chs_ascii_850)
       && (adsp_epoch->iec_chs_epoch != ied_chs_ansi_819)) {
     return false;
   }

    int in_off, in_read, in_digits;
    struct tm ds_tm;
    time_t il_ret = -100;

    // allowed date formats
    // (1)  Sun, 06 Nov 1994 08:49:37 GMT   RFC 822; updated by RFC 1123
    // (2)  Sunday, 06-Nov-94 08:49:37 GMT  RFC 850; obsoleted by RFC 1036
    // (3)  Sun Nov  6 08:49:37 1994        ANSI C's asctime() format
    // we read char at position 3; it must be
    //  (1) ','
    //  (2) {'d', 's','n', 'r', 'u'}
    //  (3) 0x20

    // minimum length
    int in_len = adsp_epoch->inc_len_epoch;
    if (in_len < 24) { // to short -> invalid length
        return false;
    }

    char* ach_http_time = (char*)adsp_epoch->ac_epoch_str;

    // JF 01.09.05: skip leading blanks
    while (*ach_http_time == ' ') {
        ach_http_time++;
    }

#ifdef HL_UNIX
    char* ach_tz = NULL;
#endif // HL_UNIX

    const int in_len_day_of_week_3chars = 3;
    char ch_day_of_week_3chars[in_len_day_of_week_3chars+1]; // 1 for zero-terminated
    memset(&ch_day_of_week_3chars[0], 0, in_len_day_of_week_3chars+1);
    in_off = 0;

    //---------------------------------------------------------
    // RFC 822 / RFC 1123:  Sun, 06 Nov 1994 08:49:37 GMT
    //---------------------------------------------------------
    if (ach_http_time[3] == ',') {
        // get day of week
        int in_day_of_week = -1;
        for (int in_idx=0; in_idx < 7; in_idx++) {
            if (strncmp(ach_http_time + in_off, achr_day_abbr[in_idx], in_len_day_of_week_3chars) == 0) {
                in_day_of_week = in_idx;
                break;
            }
        }
        if (in_day_of_week == -1) { // invalid day of week
            return false;
        }
        ds_tm.tm_wday = in_day_of_week;
        
        // save day of week 
        memmove(&ch_day_of_week_3chars[0], &ach_http_time[0], in_len_day_of_week_3chars);

        in_off = 5; // start with day
        in_read = 0;
        in_digits = 2;

        // read day
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_mday = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_mday <= 0) || (ds_tm.tm_mday > 31) ) {
            return false;
        }

#ifndef FOR_WEBSERVER_GATE
        // next character must be a SP
        in_off += 2;
        if (ach_http_time[in_off++] != ' ') {
            return false;
        }
#else // wsg needs a "nicer" parsing
        // next character must be a SP or a '-'
        in_off += 2;
        if (ach_http_time[in_off] != ' ' && ach_http_time[in_off] != '-') {
            return false;
        }
        in_off++;

#endif

        // read month-string
        int in_month = -1;
        for (int in_idx=0; in_idx < 12; in_idx++) {
            if (strncmp(ach_http_time + in_off, achr_month_abbr[in_idx], 3) == 0) {
                in_month = in_idx;
                break;
            }
        }
        if (in_month == -1) { // invalid month name
            return false;
        }
        ds_tm.tm_mon = in_month;

        // check for correct day in month (e.g. 31.09. does not exist)
        if (!m_check_day_in_month(ds_tm.tm_mon, ds_tm.tm_mday)) {
            return false;
        }

#ifndef FOR_WEBSERVER_GATE
        // next character must be a SP
        in_off += 3;
        if (ach_http_time[in_off++] != ' ') {
            return false;
        }
#else // wsg needs a "nicer" parsing
        // next character must be a SP or a '-'
        in_off += 3;
        if (ach_http_time[in_off] != ' ' && ach_http_time[in_off] != '-') {
            return false;
        }
        in_off++;

#endif

        // read year (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9')
          || (ach_http_time[in_off+2] < '0') || (ach_http_time[in_off+2] > '9')
          || (ach_http_time[in_off+3] < '0') || (ach_http_time[in_off+3] > '9') ) {
            return false;
        }
        ds_tm.tm_year = atoi(ach_http_time + in_off) - 1900;
        if ( (ds_tm.tm_year <= 0) || (ds_tm.tm_year > (3000-1900)) ) {
            return false;
        }

        // next character must be a SP
        in_off += 4;
        if (ach_http_time[in_off++] != ' ') {
            return false;
        }

        // read hour (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_hour = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_hour < 0) || (ds_tm.tm_hour > 23) ) {
            return false;
        }

        // next character must be a ":"
        in_off += 2;
        if (ach_http_time[in_off++] != ':') {
            return false;
        }

        // read minutes (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_min = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_min < 0) || (ds_tm.tm_min > 59) ) {
            return false;
        }

        // next character must be a ":"
        in_off += 2;
        if (ach_http_time[in_off++] != ':') {
            return false;
        }

        // read secondes (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_sec = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_sec < 0) || (ds_tm.tm_sec > 59) ) {
            return false;
        }

        // next character must be a SP
        in_off += 2;
        if (ach_http_time[in_off++] != ' ') {
            return false;
        }

#ifndef FOR_WEBSERVER_GATE
        // "GMT" must follow
        if ( (ach_http_time[in_off++] != 'G') || (ach_http_time[in_off++] != 'M') ||
              (ach_http_time[in_off++] != 'T') ) {
            return false;
        }
#endif

////        // MSDN says: When specifying a tm structure time, set the tm_isdst field to 0
////        // to indicate that standard time is in effect, or to a value greater than 0
////        // to indicate that daylight savings time is in effect, or to a value less than zero
////        // to have the C run-time library code compute whether standard time or daylight
////        // savings time is in effect.
////        ds_tm.tm_isdst = -1;
////
////#if defined HL_LINUX
////        ach_tz = getenv("TZ");
////        if (ach_tz == NULL){
////            setenv("TZ","0",0);
////        }
////#endif
////        //ds_tm.tm_wday =3;
////        il_ret = mktime(&ds_tm);
////        if (il_ret == (time_t)-1) { // JF 15.02.08 MS ArticleID 148790: For time zones that are ahead of Coordinated Universal Time (Greenwich Mean Time), if you call the mktime function with the argument set to correspond to January 1, 1970 00:00:00 (midnight), mktime returns -1 (failure).
////            return false;
////        }
    } // RFC 822 / RFC 1123

    //---------------------------------------------------------
    // RFC 850 / RFC 1036:  Sunday, 06-Nov-94 08:49:37 GMT
    //---------------------------------------------------------
    else if ( (ach_http_time[3] == 'd') || (ach_http_time[3] == 'n') ||
              (ach_http_time[3] == 'r') || (ach_http_time[3] == 's') ||
              (ach_http_time[3] == 'u')                                 ) {
        // ATTENTION: names of weekdays have different length
        // find first blank -> after this day follows
        char * ach_dest = strchr(ach_http_time, ' ');
        if (ach_dest == NULL)    { // no SP found -> error
            return false;
        }

        // get day of week and day of week (whole word)
        const int in_len_day_of_week = 10;
        char ch_day_of_week[in_len_day_of_week]; // Wednesday+1 for zero-terminated
        memset(&ch_day_of_week[0], 0, in_len_day_of_week);
        memmove(&ch_day_of_week[0], &ach_http_time[0], (int) (ach_dest - ach_http_time - 1));
        int in_day_of_week = -1;
        for (int in_idx=0; in_idx < 7; in_idx++) {
            if (strncmp(&ch_day_of_week[0], achr_day_full[in_idx], strlen(&ch_day_of_week[0])) == 0) {
                in_day_of_week = in_idx;
                break;
            }
        }
        if (in_day_of_week == -1) { // invalid day of week
            return false;
        }
        ds_tm.tm_wday = in_day_of_week;
        
        // save day of week 
        memmove(&ch_day_of_week_3chars[0], &ach_http_time[0], in_len_day_of_week_3chars);


        in_off = (int) (ach_dest - ach_http_time) + 1; // hop behind ' '; start with day
        
        // read day
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_mday = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_mday <= 0) || (ds_tm.tm_mday > 31) ) {
            return false;
        }

        // next character must be a '-'
        in_off += 2;
        if (ach_http_time[in_off++] != '-') {
            return false;
        }

        // read month-string
        int in_month = -1;
        for (int in_idx=0; in_idx < 12; in_idx++) {
            if (strncmp(ach_http_time + in_off, achr_month_abbr[in_idx], 3) == 0) {
                in_month = in_idx;
                break;
            }
        }
        if (in_month == -1) { // invalid month name
            return false;
        }
        ds_tm.tm_mon = in_month;

        // check for correct day in month (e.g. 31.09. does not exist)
        if (!m_check_day_in_month(ds_tm.tm_mon, ds_tm.tm_mday)) {
            return false;
        }

        // next character must be a '-'
        in_off += 3;
        if (ach_http_time[in_off++] != '-') {
            return false;
        }

        // read year (2 digits!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_year = atoi(ach_http_time + in_off);
#ifndef FOR_WEBSERVER_GATE
        if ( (ds_tm.tm_year < 0) || (ds_tm.tm_year > 99) ) {
            return false;
        }
        // next character must be a SP
        in_off += 2; 
#else // wsg needs some "nicer" parsing
        if ( (ds_tm.tm_year < 0) ) {
            return false;
        }
        if ( ds_tm.tm_year > 99 ) {
            ds_tm.tm_year -= 1900;
            in_off +=4;
        } else {
            in_off += 2;
        }
#endif // FOR_WEBSERVER_GATE
        
        // next character must be a SP
        if (ach_http_time[in_off++] != ' ') {
            return false;
        }

        // read hour (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_hour = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_hour < 0) || (ds_tm.tm_hour > 23) ) {
            return false;
        }

        // next character must be a ":"
        in_off += 2;
        if (ach_http_time[in_off++] != ':') {
            return false;
        }

        // read minutes (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_min = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_min < 0) || (ds_tm.tm_min > 59) ) {
            return false;
        }

        // next character must be a ":"
        in_off += 2;
        if (ach_http_time[in_off++] != ':') {
            return false;
        }

        // read secondes (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_sec = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_sec < 0) || (ds_tm.tm_sec > 59) ) {
            return false;
        }

        // next character must be a SP
        in_off += 2;
        if (ach_http_time[in_off++] != ' ') {
            return false;
        }

#ifndef FOR_WEBSERVER_GATE
        // "GMT" must follow
        if ( (ach_http_time[in_off++] != 'G') || (ach_http_time[in_off++] != 'M') ||
              (ach_http_time[in_off++] != 'T') ) {
            return false;
        }
#endif

////        // MSDN says: When specifying a tm structure time, set the tm_isdst field to 0
////        // to indicate that standard time is in effect, or to a value greater than 0
////        // to indicate that daylight savings time is in effect, or to a value less than zero
////        // to have the C run-time library code compute whether standard time or daylight
////        // savings time is in effect.
////        ds_tm.tm_isdst = -1;
////
////#if defined HL_LINUX
////        ach_tz = getenv("TZ");
////        if (ach_tz == NULL){
////            setenv("TZ","0",0);
////        }
////#endif
////        il_ret = mktime(&ds_tm);
////        if (il_ret == (time_t)-1) {
////            return false;
////        }
    } // RFC 850 / RFC 1036

    //---------------------------------------------------------
    // ANSI C's asctime() format:  Sun Nov  6 08:49:37 1994
    //---------------------------------------------------------
    else if (ach_http_time[3] == ' ') {
        // get day of week
        int in_day_of_week = -1;
        for (int in_idx=0; in_idx < 7; in_idx++) {
            if (strncmp(ach_http_time + in_off, achr_day_abbr[in_idx], in_len_day_of_week_3chars) == 0) {
                in_day_of_week = in_idx;
                break;
            }
        }
        if (in_day_of_week == -1) { // invalid day of week
            return false;
        }
        ds_tm.tm_wday = in_day_of_week;
        
        // save day of week 
        memmove(&ch_day_of_week_3chars[0], &ach_http_time[0], in_len_day_of_week_3chars);


        in_off = 4;

        // read month-string
        int in_month = -1;
        for (int in_idx=0; in_idx < 12; in_idx++) {
            if (strncmp(ach_http_time + in_off, achr_month_abbr[in_idx], 3) == 0) {
                in_month = in_idx;
                break;
            }
        }
        if (in_month == -1) { // invalid month name
            return false;
        }
        ds_tm.tm_mon = in_month;

        // next character must be a SP
        in_off += 3;
        if (ach_http_time[in_off++] != ' ') {
            return false;
        }

        // read day
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
              if (ach_http_time[in_off] != ' ') { // first character of day may be 0x20
                  return false;
              }
        }
        ds_tm.tm_mday = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_mday <= 0) || (ds_tm.tm_mday > 31) ) {
            return false;
        }

        // check for correct day in month (e.g. 31.09. does not exist)
        if (!m_check_day_in_month(ds_tm.tm_mon, ds_tm.tm_mday)) {
            return false;
        }

        // next character must be a SP
        in_off += 2;
        if (ach_http_time[in_off++] != ' ') {
            return false;
        }

        // read hour (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_hour = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_hour < 0) || (ds_tm.tm_hour > 23) ) {
            return false;
        }

        // next character must be a ":"
        in_off += 2;
        if (ach_http_time[in_off++] != ':') {
            return false;
        }

        // read minutes (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_min = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_min < 0) || (ds_tm.tm_min > 59) ) {
            return false;
        }

        // next character must be a ":"
        in_off += 2;
        if (ach_http_time[in_off++] != ':') {
            return false;
        }

        // read secondes (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9') ) {
            return false;
        }
        ds_tm.tm_sec = atoi(ach_http_time + in_off);
        if ( (ds_tm.tm_sec < 0) || (ds_tm.tm_sec > 59) ) {
            return false;
        }

        // next character must be a SP
        in_off += 2;
        if (ach_http_time[in_off++] != ' ') {
            return false;
        }

        // read year (PROBLEM: return of 0 can mean error or value is 0!!)
        if ( (ach_http_time[in_off] < '0') || (ach_http_time[in_off] > '9')
          || (ach_http_time[in_off+1] < '0') || (ach_http_time[in_off+1] > '9')
          || (ach_http_time[in_off+2] < '0') || (ach_http_time[in_off+2] > '9')
          || (ach_http_time[in_off+3] < '0') || (ach_http_time[in_off+3] > '9') ) {
            return false;
        }
        ds_tm.tm_year = atoi(ach_http_time + in_off) - 1900;
        if ( (ds_tm.tm_year <= 0) || (ds_tm.tm_year > (3000-1900)) ) {
            return false;
        }

////        // MSDN says: When specifying a tm structure time, set the tm_isdst field to 0
////        // to indicate that standard time is in effect, or to a value greater than 0
////        // to indicate that daylight savings time is in effect, or to a value less than zero
////        // to have the C run-time library code compute whether standard time or daylight
////        // savings time is in effect.
////        ds_tm.tm_isdst = -1;
////#if defined HL_LINUX
////        ach_tz = getenv("TZ");
////        if (ach_tz == NULL){
////            setenv("TZ","0",0);
////        }
////#endif
////        il_ret = mktime(&ds_tm);
////        if (il_ret == (time_t)-1) {
////            return false;
////        }
    }
    else { // unknown or unsupported time format
        return false;
    }


    // MSDN says: When specifying a tm structure time, set the tm_isdst field to 0
    // to indicate that standard time is in effect, or to a value greater than 0
    // to indicate that daylight savings time is in effect, or to a value less than zero
    // to have the C run-time library code compute whether standard time or daylight
    // savings time is in effect.
    ds_tm.tm_isdst = -1;

#if defined HL_LINUX
    ach_tz = getenv("TZ");
    if (ach_tz == NULL){
        setenv("TZ","0",0);
    }
#endif
    il_ret = mktime(&ds_tm);
    if (il_ret == (time_t)-1) { // JF 15.02.08 MS ArticleID 148790: For time zones that are ahead of Coordinated Universal Time (Greenwich Mean Time), if you call the mktime function with the argument set to correspond to January 1, 1970 00:00:00 (midnight), mktime returns -1 (failure).
#ifdef FOR_WEBSERVER_GATE
        adsp_epoch->imc_epoch_val = 0;
        return true;
#else 
        return false;
#endif
    }

    // correct for time-difference to UTC
    // this value must be fetched each time this method is called to avoid wrong time differences
    // if WSP is started before day light saving time changed
//printf("m_get_diff_to_utc(il_ret) %d\n",m_get_diff_to_utc(il_ret));
    il_ret += m_get_diff_to_utc(il_ret);

#if defined HL_LINUX
        if (ach_tz == NULL) { // we set TZ -> unset now
            unsetenv("TZ");
        }
#endif
    // JF 19.02.08 Ticket[14458]: we must correct for daylight saving, too
    //il_ret += m_get_daylight_saving(il_ret);

#ifndef FOR_WEBSERVER_GATE
    // check for correct day of week Ticket[14827]
    struct dsd_hl_aux_epoch_1 adsp_epoch_test;
    memset(&adsp_epoch_test, 0, sizeof(struct dsd_hl_aux_epoch_1));
    adsp_epoch_test.iec_chs_epoch = ied_chs_ascii_850;
    adsp_epoch_test.imc_epoch_val = (int)il_ret;
    const int in_len_buf = 30;
    adsp_epoch_test.inc_len_epoch = in_len_buf;
    char ch_buf[in_len_buf]; 
    adsp_epoch_test.ac_epoch_str = &ch_buf[0];
    BOOL bo_ret = m_string_from_epoch( &adsp_epoch_test );
    if (bo_ret == (time_t)-1) {
        return false;
    }
    if (strncmp((char*)adsp_epoch_test.ac_epoch_str, &ch_day_of_week_3chars[0], in_len_day_of_week_3chars) != 0) {
        return false;
    }
#endif

    
    // set the return value
    adsp_epoch->imc_epoch_val = (int)il_ret;

   return true;
}


// check for correct day in month (e.g. 31.09. does not exist)
// return true, if all is ok
static bool m_check_day_in_month(int in_month, int in_day) {
    switch (in_day) {
        case 31:
            if ( (in_month==0) || (in_month==2) || (in_month==4) || (in_month==6) || (in_month==7) || (in_month==9) || (in_month==11) ) {
                return true;
            }
            return false;
        case 30:
            if ( (in_month==3) || (in_month==5) || (in_month==8) || (in_month==10) ) {
                return true;
            }
            return false;
        case 29:
        case 28: // Attention: leap-years are not taken into consideration !!
            if (in_month==1) {
                return true;
            }
        default:
            break; 
    }

    return true;
}


// get time-difference between local time and UTC time in seconds
static int m_get_diff_to_utc(time_t& dsl_time_t)
{
    bool bo_utc_plus = true; // true means we are in a timezone ahead UTC (like UTC+2)
#if !defined HL_UNIX
   int        inl_rc;                       /* return error            */
   struct tm  dsl_tm_utc;
   struct tm  dsl_tm_local;
#else
   int        in_utc, in_local;
   struct tm* adsl_tm;
#endif

#if !defined HL_UNIX
    inl_rc = gmtime_s( &dsl_tm_utc, &dsl_time_t );
    if (inl_rc) { // some error occured
        return 0;
    }
    inl_rc = localtime_s( &dsl_tm_local, &dsl_time_t);
    if (inl_rc) { // some error occured
        return 0;
    }

    //printf("dsl_tm_local.tm_min %d\n", dsl_tm_local.tm_min);
    //printf("dsl_tm_local.tm_hour %d\n", dsl_tm_local.tm_hour);
    //printf("dsl_tm_local.tm_mday %d\n", dsl_tm_local.tm_mday);
    //printf("dsl_tm_local.tm_mon %d\n", dsl_tm_local.tm_mon);
    //printf("dsl_tm_local.tm_year %d\n", dsl_tm_local.tm_year);

    //printf("dsl_tm_utc.tm_min %d\n", dsl_tm_utc.tm_min);
    //printf("dsl_tm_utc.tm_hour %d\n", dsl_tm_utc.tm_hour);
    //printf("dsl_tm_utc.tm_mday %d\n", dsl_tm_utc.tm_mday);
    //printf("dsl_tm_utc.tm_mon %d\n", dsl_tm_utc.tm_mon);
    //printf("dsl_tm_utc.tm_year %d\n", dsl_tm_utc.tm_year);

    // determine, whether we are before or after UTC
    // Attention: if the difference between localtime and UTC is less than 1 hour -> we have a problem! (but there is no known timezone)
    if (dsl_tm_local.tm_mday == dsl_tm_utc.tm_mday) {
        if (dsl_tm_local.tm_hour < dsl_tm_utc.tm_hour) {
            bo_utc_plus = false;
        }
    }
    else {
        if (dsl_tm_local.tm_mon == dsl_tm_utc.tm_mon) {
            if (dsl_tm_local.tm_mday < dsl_tm_utc.tm_mday) {
                bo_utc_plus = false;
            }
        }
        else {
            if (dsl_tm_local.tm_year == dsl_tm_utc.tm_year) {
                if (dsl_tm_local.tm_mon < dsl_tm_utc.tm_mon) {
                    bo_utc_plus = false;
                }
            }
            else {
                if (dsl_tm_local.tm_year < dsl_tm_utc.tm_year) {
                    bo_utc_plus = false;
                }
            }
        }
    }
//printf("bo_utc_plus %d\n", bo_utc_plus);

    int in_hours_offset = 0;
    if (dsl_tm_local.tm_mday != dsl_tm_utc.tm_mday) {
        if (bo_utc_plus) {        
            in_hours_offset = 24; 
        }
        else {
            in_hours_offset = -24; 
        }
    }
    return (dsl_tm_local.tm_hour - dsl_tm_utc.tm_hour + in_hours_offset) * 3600  +  (dsl_tm_local.tm_min - dsl_tm_utc.tm_min) * 60;
#else // HL_UNIX

   // 03.04.08:  there seems to be a bug in gmtime/mktime for dates before 1973 -> we ignore it
    pthread_mutex_lock(&dsd_time_mutex);

    adsl_tm = gmtime(&dsl_time_t );
    in_utc   = adsl_tm->tm_hour;
    int in_utc_year = adsl_tm->tm_year;
    int in_utc_mon = adsl_tm->tm_mon;
    int in_utc_day = adsl_tm->tm_mday;
    // JF 22.09.08 not used int in_utc_hour = adsl_tm->tm_hour;
    int in_utc_min = adsl_tm->tm_min;
    //printf("in_utc_min %d\n", in_utc_min);
    //printf("in_utc_hour %d\n", in_utc_hour);
    //printf("in_utc_day %d\n", in_utc_day);
    //printf("in_utc_mon %d\n", in_utc_mon);
    //printf("in_utc_year %d\n", in_utc_year);

    adsl_tm  = localtime(&dsl_time_t );
    in_local = adsl_tm->tm_hour;
    int in_local_year = adsl_tm->tm_year;
    int in_local_mon = adsl_tm->tm_mon;
    int in_local_day = adsl_tm->tm_mday;
    // JF 22.09.08 not used int in_local_hour = adsl_tm->tm_hour;
    int in_local_min = adsl_tm->tm_min;
    //printf("in_local_min %d\n", in_local_min);
    //printf("in_local_hour %d\n", in_local_hour);
    //printf("in_local_day %d\n", in_local_day);
    //printf("in_local_mon %d\n", in_local_mon);
    //printf("in_local_year %d\n", in_local_year);

    // determine, whether we are before or after UTC
    if (in_local_day == in_utc_day) {
        if (in_local < in_utc) {
            bo_utc_plus = false;
        }
    }
    else {
        if (in_local_mon == in_utc_mon) {
            if (in_local_day < in_utc_day) {
                bo_utc_plus = false;
            }
        }
        else {
            if (in_local_year == in_utc_year) {
                if (in_local_mon < in_utc_mon) {
                    bo_utc_plus = false;
                }
            }
            else {
                if (in_local_year < in_utc_year) {
                    bo_utc_plus = false;
                }
            }
        }
    }

    int in_hours_offset = 0;
    if (in_local_day != in_utc_day) {
        if (bo_utc_plus) {
            in_hours_offset = 24; 
        }
        else {
            in_hours_offset = -24; 
        }
    }

    pthread_mutex_unlock(&dsd_time_mutex);

    return (in_local - in_utc + in_hours_offset) * 3600  +  (in_local_min - in_utc_min) * 60;
#endif
}
////static int m_get_diff_to_utc()
////{
////#if !defined HL_UNIX
////   int        inl_rc;                       /* return error            */
////   struct tm  dsl_tm_utc;
////   struct tm  dsl_tm_local;
////#else
////   int        in_utc, in_local;
////   struct tm* adsl_tm;
////#endif
////
////   time_t     l_time_now;
////
////   time(&l_time_now);
////
////#if !defined HL_UNIX
////    inl_rc = gmtime_s( &dsl_tm_utc, &l_time_now );
////    if (inl_rc) { // some error occured
////        return 0;
////    }
////    inl_rc = localtime_s( &dsl_tm_local, &l_time_now);
////    if (inl_rc) { // some error occured
////        return 0;
////    }
////    return (dsl_tm_local.tm_hour - dsl_tm_utc.tm_hour) * 3600;
////#else // HL_UNIX
////    pthread_mutex_lock(&dsd_time_mutex);
////
////    adsl_tm = gmtime(&l_time_now );
////    in_utc   = adsl_tm->tm_hour; // we must save to another variable because gmtime() and
////    adsl_tm  = localtime(&l_time_now );
////    in_local = adsl_tm->tm_hour; // we must save to another variable because gmtime() and
////
////    pthread_mutex_unlock(&dsd_time_mutex);
////
////    return (in_local - in_utc) * 3600;
////#endif
////}


// get time-difference resulting from daylight saving in seconds
//static int m_get_daylight_saving(time_t& dsl_time_t)
//{
//    int in_ret = 0;
//
//#if !defined HL_UNIX
//    struct tm  dsl_tm;
//    localtime_s( &dsl_tm, &dsl_time_t);
//    if (dsl_tm.tm_isdst > 0) {
//        in_ret = 3600;
//    }
//#else // HL_UNIX
//    pthread_mutex_lock(&dsd_time_mutex);
//    struct tm* adsl_tm = localtime(&dsl_time_t );
//    if (adsl_tm->tm_isdst > 0) {
//        in_ret = 3600;
//    }
//    pthread_mutex_unlock(&dsd_time_mutex);
//#endif
//    return in_ret;
//}



#ifdef HL_WINALL1
// takes a win32 FILETIME structure, returns the equivalent int value
// ATTENTION: a 32-bit int is only capable of representing dates between
// 13 December 1901 and 19 January 2038
#ifndef FOR_WEBSERVER_GATE
extern PTYPE int m_win_epoch_from_filetime( struct _FILETIME *adsp_filetime ) {
#else // wsg definition:
int m_win_epoch_from_filetime( struct _FILETIME *adsp_filetime ) {
#endif // FOR_WEBSERVER_GATE
   //return 123456;
    __int64 il_sec_1970;
    // Explanation:
    // Both epochs are Gregorian. 1970 - 1601 = 369. Assuming a leap
    // year every four years, 369 / 4 = 92. However, 1700, 1800, and 1900
    // were NOT leap years, so 89 leap years, 280 non-leap years.
    // 89 * 366 + 280 * 365 = 134744 days between epochs. Of course
    // 60 * 60 * 24 = 86400 seconds per day, so 134744 * 86400 =
    // 11644473600 seconds between epochs

   // get the full win32 value, in 100ns-elements
    il_sec_1970 = ((__int64)adsp_filetime->dwHighDateTime << 32) + adsp_filetime->dwLowDateTime;

   // convert to nanosec since 1970
    il_sec_1970 -= (il_secs_between_epochs * il_secs_to_100ns);
    // now convert to seconds
    il_sec_1970 /= il_secs_to_100ns;

   return (int)il_sec_1970;
}
#endif
