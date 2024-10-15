//#define DEBUG_080502
//#define TRACEHL1
//#define DEBUG_120831_01                     /* problem cout corrupted  */
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsllog01                                            |*/
/*| -------------                                                     |*/
/*|  Log in memory for HOB server programs                            |*/
/*|  KB 22.03.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#if defined WIN32 || defined WIN64
#ifndef HL_WINALL1
#define HL_WINALL1
#endif
#endif

#ifdef HL_WINALL1
#include <windows.h>
#endif

#ifndef HL_UNIX
#include <sys/timeb.h>
#include <hob-llog01.h>
#else
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include "hob-unix01.h"
#include "hob-llog01.h"
#endif
#include <hob-xslhcla1.hpp>
#include <hob-xslunic1.h>

#include <stdio.h>
#include <time.h>

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#ifdef __FreeBSD__
#define MAP_ANONYMOUS MAP_ANON
#endif

#define MAC_GET_EPOCH( IMP_POS ) (((HL_LONGLONG) (*((unsigned char *) IMP_POS + 2 + 0)) << 40) \
                       | ((HL_LONGLONG) (*((unsigned char *) IMP_POS + 2 + 1)) << 32)          \
                       | ((HL_LONGLONG) (*((unsigned char *) IMP_POS + 2 + 2)) << 24)          \
                       | ((HL_LONGLONG) (*((unsigned char *) IMP_POS + 2 + 3)) << 16)          \
                       | ((HL_LONGLONG) (*((unsigned char *) IMP_POS + 2 + 4)) << 8)           \
                       | ((HL_LONGLONG) *((unsigned char *) IMP_POS + 2 + 5)) )

typedef time_t dsd_time_1;

#ifdef B100908
#define D_SIZE_LOG_HEADER                   (1 + 1 + sizeof(int))
#endif
#define D_SIZE_LOG_HEADER                   (1 + 1 + 6)
/**
   the log header of each entry contains:
   the length of the message in one single byte,
   the length of the previous entry in one single byte,
   followed by the epoch in big endian.
   Messages may be up to 510 bytes long.
   The message length is halve of the length, rounded up.
   The log is filled with UTF-8 characters.
*/

#ifdef OLD01
#ifndef NO_GW08
extern PTYPE int m_hlnew_printf( int, char *, ... );
#define HLOG_XYZ1              0            /* to be replaced later    */
#define HLOG_EMER1             1            /* emergency output        */
#endif
#endif

static HL_LONGLONG m_get_epoch_ms( void );
extern "C" int m_hl1_printf( char *aptext, ... );
extern "C" BOOL m_search_regex_exists( const char *achp_search_in, int imp_search_len,
                                       const char *achp_regexp, int imp_len_regexp );

struct dsd_mem_log_1 {                      /* memory log              */
   HL_LONGLONG ilc_size;                    /* size of memory log      */
   int        imc_count_filled;             /* count how often filled  */
   char *     achc_end_cur;                 /* current position end    */
   char *     achc_end_prev;                /* previous part position end */
   char *     achc_start_prev;              /* start of previous part  */
   char       chc_length_previous;          /* length of previous entry */
};

static struct dsd_mem_log_1 *adss_mem_log_1 = NULL;  /* storage for log */
static struct dsd_log_new_call *adss_lnc_anchor = NULL;  /* chain of callback routines */
static class dsd_hcla_critsect_1 dss_critsect_log;  /* critical section for log */
static BOOL   bos_critsect_act = FALSE;     /* critical section active */

/** create a log in memory of specified size                           */
extern "C" BOOL m_create_log( HL_LONGLONG ilp_size ) {
   int        iml_rc1;                      /* Return Code 1           */
   BOOL       bol1;                         /* working variable        */
   char       *achl_to, *achl_fr, *achl_w1;  /* copy to, copy from, working variable */
   struct dsd_mem_log_1 *adsl_t_mem_log_1_w1;  /* temporary storage for log */
   struct dsd_mem_log_1 *adsl_t_mem_log_1_w2;  /* temporary storage for log */
   HL_LONGLONG ill1;                        /* working variable        */
#ifndef HL_UNIX
   SYSTEM_INFO dwl_sys_info;
#endif
#ifdef HL_UNIX
   int        iml_size_mem;                 /* size of one page        */
#endif

   if (adss_mem_log_1) {                    /* log already allocated   */
     goto p_realloc_00;                     /* change size of log      */
   }
   if (ilp_size < 0X1000) return FALSE;
   if (bos_critsect_act == FALSE) {         /* critical section not active */
     iml_rc1 = dss_critsect_log.m_create();
     if (iml_rc1 < 0) {                     /* error occured           */
       m_hl1_printf( "xsllog01-l%05d-W m_create_log() dss_critsect_log m_create Return Code %d",
                     __LINE__, iml_rc1 );
       return FALSE;                        /* could not start resource */
     }
     bos_critsect_act = TRUE;               /* critical section active now */
   }
#ifdef B081213
   adss_mem_log_1 = (struct dsd_mem_log_1 *) malloc( sizeof(struct dsd_mem_log_1) + ilp_size );
   if (adss_mem_log_1 == NULL) return FALSE;
   memset( adss_mem_log_1, 0, sizeof(struct dsd_mem_log_1) );
   adss_mem_log_1->ilc_size = ilp_size;
#else
#ifndef HL_UNIX
   GetSystemInfo( &dwl_sys_info );
   ill1 = (HL_LONGLONG) (sizeof(struct dsd_mem_log_1) + ilp_size + dwl_sys_info.dwPageSize - 1)
            & (HL_LONGLONG) (0 - dwl_sys_info.dwPageSize);
   adss_mem_log_1 = (struct dsd_mem_log_1 *) VirtualAlloc( NULL, ill1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
   if (adss_mem_log_1 == NULL) {            /* memory not available    */
     m_hl1_printf( "xsllog01-l%05d-W m_create_log() VirtualAlloc( size %lld ) Return Code %d.",
                   __LINE__, ill1, GetLastError() );
     return FALSE;                          /* could not start resource */
   }
   adss_mem_log_1->ilc_size = ill1 - sizeof(struct dsd_mem_log_1);
#endif
#ifdef HL_UNIX
   iml_size_mem = sysconf( _SC_PAGESIZE );
   ill1 = (HL_LONGLONG) (sizeof(struct dsd_mem_log_1) + ilp_size + iml_size_mem - 1)
            & (HL_LONGLONG) (0 - iml_size_mem);
   adss_mem_log_1 = (struct dsd_mem_log_1 *) mmap( NULL, ill1, PROT_READ | PROT_WRITE,
                                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
   if (adss_mem_log_1 == MAP_FAILED) {      /* memory not available    */
     m_hl1_printf( "xsllog01-l%05d-W m_create_log() mmap( size %lld ) Return Code %d.",
                   __LINE__, ill1, errno );
     return FALSE;                          /* could not start resource */
   }
   adss_mem_log_1->ilc_size = ill1 - sizeof(struct dsd_mem_log_1);
#endif
#endif
   adss_mem_log_1->achc_end_cur = (char *) (adss_mem_log_1 + 1);
   return TRUE;

   p_realloc_00:                            /* change size of log      */
   if (ilp_size < 0X1000) goto p_realloc_40;  /* remove the log        */
#ifndef HL_UNIX
   GetSystemInfo( &dwl_sys_info );
   ill1 = (HL_LONGLONG) (sizeof(struct dsd_mem_log_1) + ilp_size + dwl_sys_info.dwPageSize - 1)
            & (HL_LONGLONG) (0 - dwl_sys_info.dwPageSize);
   if ((adss_mem_log_1) && ((ill1 - sizeof(struct dsd_mem_log_1)) == adss_mem_log_1->ilc_size)) {
     return TRUE;                           /* still same size         */
   }
   adsl_t_mem_log_1_w1 = (struct dsd_mem_log_1 *) VirtualAlloc( NULL, ill1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
   if (adsl_t_mem_log_1_w1 == NULL) {       /* memory not available    */
     m_hl1_printf( "xsllog01-l%05d-W m_create_log() VirtualAlloc( size %lld ) Return Code %d.",
                   __LINE__, ill1, GetLastError() );
     return FALSE;                          /* could not start resource */
   }
   adsl_t_mem_log_1_w1->ilc_size = ill1 - sizeof(struct dsd_mem_log_1);
#endif
#ifdef HL_UNIX
   iml_size_mem = sysconf( _SC_PAGESIZE );
   ill1 = (HL_LONGLONG) (sizeof(struct dsd_mem_log_1) + ilp_size + iml_size_mem - 1)
            & (HL_LONGLONG) (0 - iml_size_mem);
   if ((adss_mem_log_1) && ((ill1 - sizeof(struct dsd_mem_log_1)) == adss_mem_log_1->ilc_size)) {
     return TRUE;                           /* still same size         */
   }
   adsl_t_mem_log_1_w1 = (struct dsd_mem_log_1 *) mmap( NULL, ill1, PROT_READ | PROT_WRITE,
                                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
   if (adsl_t_mem_log_1_w1 == MAP_FAILED) {  /* memory not available   */
     m_hl1_printf( "xsllog01-l%05d-W m_create_log() mmap( size %lld ) Return Code %d.",
                   __LINE__, ill1, errno );
     return FALSE;                          /* could not start resource */
   }
   adsl_t_mem_log_1_w1->ilc_size = ill1 - sizeof(struct dsd_mem_log_1);
#endif
   dss_critsect_log.m_enter();
   /* copy the content from old memory to new memory                   */
   achl_to = (char *) (adsl_t_mem_log_1_w1 + 1);
   if (adss_mem_log_1->achc_end_cur == (char *) (adss_mem_log_1 + 1)) {
     goto p_realloc_36;                     /* log still empty         */
   }
   adsl_t_mem_log_1_w1->imc_count_filled = adss_mem_log_1->imc_count_filled + 1;  /* count how often filled  */
   adsl_t_mem_log_1_w1->chc_length_previous = adss_mem_log_1->chc_length_previous;  /* length of previous entry */
   achl_fr = adss_mem_log_1->achc_start_prev;  /* here is last message */
   ill1 = (HL_LONGLONG) (adss_mem_log_1->achc_end_prev - adss_mem_log_1->achc_start_prev)
            + (HL_LONGLONG) (adss_mem_log_1->achc_end_cur - ((char *) (adss_mem_log_1 + 1)));
   if (ill1 <= adsl_t_mem_log_1_w1->ilc_size) {
     goto p_realloc_28;                     /* copy previous entries   */
   }
   ill1 = adss_mem_log_1->achc_end_cur - ((char *) (adss_mem_log_1 + 1));
   if (ill1 > adsl_t_mem_log_1_w1->ilc_size) {
     goto p_realloc_20;                     /* search where in current entries */
   }
   achl_fr = adss_mem_log_1->achc_end_prev;
   achl_w1 = (char *) (adss_mem_log_1 + 1);
   while (TRUE) {
     ill1 += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_w1 + 1) << 1);
     if (ill1 > adsl_t_mem_log_1_w1->ilc_size) {
       goto p_realloc_28;                   /* copy previous entries   */
     }
     achl_fr -= D_SIZE_LOG_HEADER + (*((unsigned char *) achl_w1 + 1) << 1);
     achl_w1 = achl_fr;
   }

   p_realloc_20:                            /* search where in current entries */
   achl_fr = (char *) (adss_mem_log_1 + 1);
   while (TRUE) {
     ill1 -= D_SIZE_LOG_HEADER + (*((unsigned char *) achl_fr + 0) << 1);
     achl_fr += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_fr + 0) << 1);
     if (ill1 <= adsl_t_mem_log_1_w1->ilc_size) {
       goto p_realloc_32;                   /* copy current entries    */
     }
   }

   p_realloc_28:                            /* copy previous entries   */
   if (achl_fr < adss_mem_log_1->achc_end_prev) {
#ifdef DEBUG_120831_01                      /* problem cout corrupted  */
     if (((char *) achl_to + (adss_mem_log_1->achc_end_prev - achl_fr))
           > ((char *) (adsl_t_mem_log_1_w1 + 1) + adsl_t_mem_log_1_w1->ilc_size)) {
       while (TRUE) {
         printf( "xsllog01-l%05d-E overflow\n", __LINE__ );
         fflush( stdout );
#ifndef HL_UNIX
         Sleep( 15000 );
#else
         sleep( 15 );
#endif
       }
     }
#endif
     memcpy( achl_to, achl_fr, adss_mem_log_1->achc_end_prev - achl_fr );
     achl_to += adss_mem_log_1->achc_end_prev - achl_fr;
   }
   achl_fr = (char *) (adss_mem_log_1 + 1);

   p_realloc_32:                            /* copy current entries    */
#ifdef DEBUG_120831_01                      /* problem cout corrupted  */
   if (((char *) achl_to + (adss_mem_log_1->achc_end_prev - achl_fr))
         > ((char *) (adsl_t_mem_log_1_w1 + 1) + adsl_t_mem_log_1_w1->ilc_size)) {
     while (TRUE) {
       printf( "xsllog01-l%05d-E overflow\n", __LINE__ );
       fflush( stdout );
#ifndef HL_UNIX
       Sleep( 15000 );
#else
       sleep( 15 );
#endif
     }
   }
#endif
   memcpy( achl_to, achl_fr, adss_mem_log_1->achc_end_cur - achl_fr );
   achl_to += adss_mem_log_1->achc_end_cur - achl_fr;

   p_realloc_36:                            /* end of copy content     */
   adsl_t_mem_log_1_w1->achc_end_cur = achl_to;  /* end of valid data  */
   adsl_t_mem_log_1_w2 = adss_mem_log_1;    /* get memory to free      */
   adss_mem_log_1 = adsl_t_mem_log_1_w1;    /* set new memory          */
   dss_critsect_log.m_leave();
   if (adsl_t_mem_log_1_w2 == NULL) return TRUE;  /* no memory to free */
#ifndef HL_UNIX
   bol1 = VirtualFree( adsl_t_mem_log_1_w2, adsl_t_mem_log_1_w2->ilc_size + sizeof(struct dsd_mem_log_1), MEM_RELEASE );
   if (bol1 == FALSE) {                     /* function failed         */
     m_hl1_printf( "xsllog01-l%05d-W m_create_log() VirtualFree() Error Code %d.",
                   __LINE__, GetLastError() );
     return FALSE;                          /* error occured           */
   }
#endif
#ifdef HL_UNIX
#ifndef HL_SOLARIS
   iml_rc1 = munmap( adsl_t_mem_log_1_w2, adsl_t_mem_log_1_w2->ilc_size + sizeof(struct dsd_mem_log_1) );
#else
   iml_rc1 = munmap( (char *) adsl_t_mem_log_1_w2, adsl_t_mem_log_1_w2->ilc_size + sizeof(struct dsd_mem_log_1) );
#endif
   if (iml_rc1 != 0) {                      /* function failed         */
     m_hl1_printf( "xsllog01-l%05d-W m_create_log() munmap() returned %d Error Code %d.",
                   __LINE__, iml_rc1, errno );
     return FALSE;                          /* error occured           */
   }
#endif
   return TRUE;

   p_realloc_40:                            /* remove the log          */
   if (adss_mem_log_1 == NULL) return TRUE;
   dss_critsect_log.m_enter();
   adsl_t_mem_log_1_w2 = adss_mem_log_1;    /* get memory to free      */
   adss_mem_log_1 = NULL;                   /* set no new memory       */
   dss_critsect_log.m_leave();
#ifndef HL_UNIX
   bol1 = VirtualFree( adsl_t_mem_log_1_w2, adsl_t_mem_log_1_w2->ilc_size + sizeof(struct dsd_mem_log_1), MEM_RELEASE );
   if (bol1 == FALSE) {                     /* function failed         */
     m_hl1_printf( "xsllog01-l%05d-W m_create_log() VirtualFree() Return Code %d.",
                   __LINE__, GetLastError() );
     return FALSE;                          /* error occured           */
   }
#endif
#ifdef HL_UNIX
#ifndef HL_SOLARIS
   iml_rc1 = munmap( adsl_t_mem_log_1_w2, adsl_t_mem_log_1_w2->ilc_size + sizeof(struct dsd_mem_log_1) );
#else
   iml_rc1 = munmap( (char *) adsl_t_mem_log_1_w2, adsl_t_mem_log_1_w2->ilc_size + sizeof(struct dsd_mem_log_1) );
#endif
   if (iml_rc1 != 0) {                      /* function failed         */
     m_hl1_printf( "xsllog01-l%05d-W m_create_log() munmap() returned %d Error Code %d.",
                   __LINE__, iml_rc1, errno );
     return FALSE;                          /* error occured           */
   }
#endif
   return TRUE;
} /* end m_create_log()                                                */

/** write a message to log in memory                                   */
extern "C" BOOL m_write_log( int imp_msg_type, char *achp_text, int imp_length ) {
   char       *achl_end_log;
   char       *achl_end_cur;
   unsigned char chl_this_length;           /* this length             */
   int        iml_this_len_1;               /* length this entry       */
   int        iml_this_len_2;               /* rounded up              */
   struct dsd_log_new_call *adsl_lnc_w1;    /* callback routines       */
#ifdef B100908
   dsd_time_1 dsl_time_cur;                 /* current time            */
#endif
   HL_LONGLONG ill_time_cur;                /* retrieve current time   */
   struct dsd_log_new_pass dsl_lnp;         /* pass parameters new log message */

   if (imp_length <= 0) return FALSE;
   if (imp_length > 0X01FE) return FALSE;   /* text is too long        */
   if (adss_mem_log_1 == NULL) return FALSE;
#ifdef XYZ1
   iml_this_len_2 = 0;                      /* start at first character */
   iml_this_len_1 = 0;                      /* no character found yet  */
   do {                                     /* loop to remove blanks and zeroes */
     if (*((signed char *) achp_text + iml_this_len_2) >= 0) {  /* MSB not set, single character */
       iml_this_len_2++;                    /* after this character    */
       if (   (*((unsigned char *) achp_text + iml_this_len_2 - 1) != 0)  /* not zero */
           && (*((unsigned char *) achp_text + iml_this_len_2 - 1) != 0X20)) {  /* not blank */
         iml_this_len_1 = iml_this_len_2;   /* save length             */
       } else {
         iml_this_len_2 += chrs_trail_u8l[ *((unsigned char *) achp_text + iml_this_len_2) ] + 1;
         iml_this_len_1 = iml_this_len_2;   /* save length             */
       }
     }
   } while (iml_this_len_2 < imp_length);
   if (iml_this_len_1 <= 0) return FALSE;   /* no valid text found     */
#endif
   iml_this_len_1 = imp_length;             /* get length              */
   while (TRUE) {                           /* loop to remove spaces at the end */
     if (iml_this_len_1 <= 0) return FALSE;  /* no text found          */
     if (*((unsigned char *) achp_text + iml_this_len_1 - 1) > 0X20) break;  /* valid character found */
     iml_this_len_1--;                      /* one character less      */
   }
   iml_this_len_2 = iml_this_len_1 + 1;     /* length this entry       */
   iml_this_len_2 &= 0XFFFE;                /* set last bit zero       */
   chl_this_length = (unsigned char) (iml_this_len_2 >> 1);  /* this length */
   dsl_lnp.imc_msg_type = imp_msg_type;     /* message type            */
   dss_critsect_log.m_enter();
   achl_end_log = (char *) (adss_mem_log_1 + 1) + adss_mem_log_1->ilc_size;
   achl_end_cur = adss_mem_log_1->achc_end_cur + D_SIZE_LOG_HEADER + iml_this_len_2;
#ifdef TRACEHL1
   printf( "xsllog1.cpp l%05d m_write_log() achl_end_cur=%p achl_end_log=%p\n",
           __LINE__, achl_end_cur, achl_end_log );
#endif
   if (achl_end_cur > achl_end_log) {
     goto p_wri_log_20;                     /* has to do next fill     */
   }
   if (adss_mem_log_1->achc_start_prev == NULL) {
     goto p_wri_log_40;                     /* write record now        */
   }
   if (achl_end_cur <= adss_mem_log_1->achc_start_prev) {
     goto p_wri_log_40;                     /* write record now        */
   }
   goto p_wri_log_24;                       /* remove old entries      */

   p_wri_log_20:                            /* has to do next fill     */
#ifdef XYZ1
   if (adss_mem_log_1->achc_end_cur < achl_end_log) {
     *adss_mem_log_1->achc_end_cur = 0;
   }
#endif
   adss_mem_log_1->achc_end_prev = adss_mem_log_1->achc_end_cur;
   adss_mem_log_1->imc_count_filled++;      /* count how often filled  */
   adss_mem_log_1->achc_start_prev = (char *) (adss_mem_log_1 + 1);
   adss_mem_log_1->achc_end_cur = (char *) (adss_mem_log_1 + 1);
   achl_end_cur = adss_mem_log_1->achc_end_cur + D_SIZE_LOG_HEADER + iml_this_len_2;

   p_wri_log_24:                            /* remove old entries      */
   if (adss_mem_log_1->achc_start_prev >= adss_mem_log_1->achc_end_prev) {  /* at end of log */
     adss_mem_log_1->achc_start_prev = (char *) (adss_mem_log_1 + 1);
     adss_mem_log_1->achc_end_prev = NULL;  /* no more records in old fill stage */
     goto p_wri_log_40;                     /* write record now        */
   }
   adss_mem_log_1->achc_start_prev
     += (*((unsigned char *) adss_mem_log_1->achc_start_prev) << 1) + D_SIZE_LOG_HEADER;
   if (achl_end_cur > adss_mem_log_1->achc_start_prev) {
     goto p_wri_log_24;                     /* remove old entries      */
   }

   p_wri_log_40:                            /* write record now        */
   *adss_mem_log_1->achc_end_cur = (unsigned char) chl_this_length;  /* this length */
   *(adss_mem_log_1->achc_end_cur + 1) = (unsigned char) adss_mem_log_1->chc_length_previous;  /* length of previous entry */
#ifdef B100908
   /* set current time, epoch in seconds, big endian                   */
   dsl_time_cur = time( NULL );
   *(adss_mem_log_1->achc_end_cur + 2 + 0) = (unsigned char) (dsl_time_cur >> 24);
   *(adss_mem_log_1->achc_end_cur + 2 + 1) = (unsigned char) (dsl_time_cur >> 16);
   *(adss_mem_log_1->achc_end_cur + 2 + 2) = (unsigned char) (dsl_time_cur >> 8);
   *(adss_mem_log_1->achc_end_cur + 2 + 3) = (unsigned char) dsl_time_cur;
   dsl_lnp.imc_epoch = (int) dsl_time_cur;  /* set epoch for pass      */
#endif
   /* set current time, epoch in milli-seconds, big endian             */
   ill_time_cur = m_get_epoch_ms();
   *(adss_mem_log_1->achc_end_cur + 2 + 0) = (unsigned char) (ill_time_cur >> 40);
   *(adss_mem_log_1->achc_end_cur + 2 + 1) = (unsigned char) (ill_time_cur >> 32);
   *(adss_mem_log_1->achc_end_cur + 2 + 2) = (unsigned char) (ill_time_cur >> 24);
   *(adss_mem_log_1->achc_end_cur + 2 + 3) = (unsigned char) (ill_time_cur >> 16);
   *(adss_mem_log_1->achc_end_cur + 2 + 4) = (unsigned char) (ill_time_cur >> 8);
   *(adss_mem_log_1->achc_end_cur + 2 + 5) = (unsigned char) ill_time_cur;
   dsl_lnp.ilc_epoch = ill_time_cur;        /* set epoch for pass      */
   dsl_lnp.ilc_position = adss_mem_log_1->achc_end_cur - (char *) (adss_mem_log_1 + 1);  /* position where to read */
   dsl_lnp.imc_count_filled = adss_mem_log_1->imc_count_filled;  /* count how often filled */
   dsl_lnp.imc_len_record = iml_this_len_1;  /* length of record returned */
   dsl_lnp.achc_area = adss_mem_log_1->achc_end_cur + D_SIZE_LOG_HEADER;  /* area with log record */
#ifdef DEBUG_120831_01                      /* problem cout corrupted  */
   if ((adss_mem_log_1->achc_end_cur + D_SIZE_LOG_HEADER + iml_this_len_1)
         > ((char *) (adss_mem_log_1 + 1) + adss_mem_log_1->ilc_size)) {
     while (TRUE) {
       printf( "xsllog01-l%05d-E overflow\n", __LINE__ );
       fflush( stdout );
#ifndef HL_UNIX
       Sleep( 15000 );
#else
       sleep( 15 );
#endif
     }
   }
#endif
   memcpy( adss_mem_log_1->achc_end_cur + D_SIZE_LOG_HEADER, achp_text, iml_this_len_1 );
   if (iml_this_len_1 < iml_this_len_2) {   /* has to fill with space  */
#ifdef DEBUG_120831_01                      /* problem cout corrupted  */
     if ((adss_mem_log_1->achc_end_cur + D_SIZE_LOG_HEADER + iml_this_len_1 + 1)
           > ((char *) (adss_mem_log_1 + 1) + adss_mem_log_1->ilc_size)) {
       while (TRUE) {
         printf( "xsllog01-l%05d-E overflow\n", __LINE__ );
         fflush( stdout );
  #ifndef HL_UNIX
         Sleep( 15000 );
  #else
         sleep( 15 );
  #endif
       }
     }
#endif
     *(adss_mem_log_1->achc_end_cur + D_SIZE_LOG_HEADER + iml_this_len_1) = 0X20;
   }
   adss_mem_log_1->achc_end_cur = achl_end_cur;  /* set new end        */
   adss_mem_log_1->chc_length_previous = (unsigned char) chl_this_length;  /* this length */
   dss_critsect_log.m_leave();
   adsl_lnc_w1 = adss_lnc_anchor;           /* chain of callback routines */
   while (adsl_lnc_w1) {                    /* loop over all callback routines */
     adsl_lnc_w1->amc_log_new_call( adsl_lnc_w1, &dsl_lnp );
     adsl_lnc_w1 = adsl_lnc_w1->adsc_next;  /* get next in chain       */
   }
   return TRUE;
} /* end m_write_log()                                                 */

/** request against memory log                                         */
extern "C" void m_mem_log_1_req( struct dsd_log_requ_1 *adsp_lq1 ) {
   BOOL       bol_error;                    /* error occured           */
   int        iml_count_filled;             /* value count filled current record */
   int        iml_search_count_filled;      /* value search count filled current record */
#ifdef B100908
   int        iml_epoch;                    /* epoch of current record */
#endif
   HL_LONGLONG ill_epoch;                   /* epoch of current record */
   char       *achl_pos;                    /* position in memory log  */
   char       *achl_search_pos;             /* search position in memory log */
   char       chl_length_previous;          /* length of previous entry */
   struct dsd_ml_search_1 dsl_ml_search_1;  /* search in memory log    */
   char       chrl_sub_str[ D_MEM_LOG_MAX_LEN_REC ];  /* sub-string for compare */

   if (adsp_lq1->iec_logreq1_def == ied_lreq1d_invalid) {
     adsp_lq1->iec_logreq1_ret = ied_lreq1r_invalid;
     return;
   }
   if (adss_mem_log_1 == NULL) {            /* log not open            */
     adsp_lq1->iec_logreq1_ret = ied_lreq1r_not_open;  /* log not opened */
     return;
   }
   if (   (adsp_lq1->iec_logreq1_def != ied_lreq1d_epoch_first)  /* retrieve first position log with this epoch */
       && (adsp_lq1->iec_logreq1_def != ied_lreq1d_epoch_last)) {  /* retrieve last position log with this epoch */
     if (adsp_lq1->imc_count_filled > adss_mem_log_1->imc_count_filled) {
       adsp_lq1->iec_logreq1_ret = ied_lreq1r_invalid;
       return;
     }
   }
   if (adsp_lq1->iec_logreq1_def == ied_lreq1d_cur_pos) {  /* return current position */
     dss_critsect_log.m_enter();            /* critical section        */
     adsp_lq1->imc_count_filled = adss_mem_log_1->imc_count_filled;
     adsp_lq1->ilc_position = adss_mem_log_1->achc_end_cur - ((char *) (adss_mem_log_1 + 1));
     dss_critsect_log.m_leave();            /* critical section        */
     adsp_lq1->imc_len_record = 0;          /* length of record returned */
#ifdef B100908
     adsp_lq1->imc_epoch = 0;               /* epoch / time of log record */
#endif
     adsp_lq1->ilc_epoch = 0;               /* epoch / time of log record */
     adsp_lq1->iec_logreq1_ret = ied_lreq1r_ok;  /* request processed o.k. */
     return;
   }
   if (adsp_lq1->iec_chs_area == ied_chs_invalid) {
     adsp_lq1->iec_logreq1_ret = ied_lreq1r_invalid;
     return;
   }
   if (   (adsp_lq1->iec_logreq1_def == ied_lreq1d_search_f)  /* search forward */
       || (adsp_lq1->iec_logreq1_def == ied_lreq1d_search_b)  /* search backward */
       || (adsp_lq1->iec_logreq1_def == ied_lreq1d_s_regex_f) /* regexp forward  */
       || (adsp_lq1->iec_logreq1_def == ied_lreq1d_s_regex_b)) {  /* regexp backward */
     if (adsp_lq1->imc_len_search_a == 0) {  /* length of search area, elements */
       adsp_lq1->iec_logreq1_ret = ied_lreq1r_invalid;
       return;
     }
     if (adsp_lq1->iec_chs_search == ied_chs_invalid) {  /* character set search */
       adsp_lq1->iec_logreq1_ret = ied_lreq1r_invalid;
       return;
     }
     memset( &dsl_ml_search_1, 0, sizeof(struct dsd_ml_search_1) );  /* search in memory log */
     if (   (adsp_lq1->iec_chs_search == ied_chs_utf_8)  /* transform not necessary */
         && (adsp_lq1->imc_len_search_a > 0)) {
       dsl_ml_search_1.achc_cmp_str = adsp_lq1->achc_search_a;  /* string to compare */
       dsl_ml_search_1.imc_len_cmp_str = adsp_lq1->imc_len_search_a;
     } else {
       dsl_ml_search_1.imc_len_cmp_str = m_cpy_vx_vx( chrl_sub_str,
                                                      sizeof(chrl_sub_str),
                                                      ied_chs_utf_8,
                                                      adsp_lq1->achc_search_a,
                                                      adsp_lq1->imc_len_search_a,
                                                      adsp_lq1->iec_chs_search );
       if (dsl_ml_search_1.imc_len_cmp_str <= 0) {
         adsp_lq1->iec_logreq1_ret = ied_lreq1r_invalid;
         return;
       }
       dsl_ml_search_1.achc_cmp_str = chrl_sub_str;  /* string to compare */
     }
     dsl_ml_search_1.chc_fchar_1 = *dsl_ml_search_1.achc_cmp_str;
     if ((dsl_ml_search_1.chc_fchar_1 >= 'A') && (dsl_ml_search_1.chc_fchar_1 <= 'Z')) {
       dsl_ml_search_1.chc_fchar_2 = dsl_ml_search_1.chc_fchar_1 + 0X20;
     } else if ((dsl_ml_search_1.chc_fchar_1 >= 'a') && (dsl_ml_search_1.chc_fchar_1 <= 'z')) {
       dsl_ml_search_1.chc_fchar_2 = dsl_ml_search_1.chc_fchar_1 - 0X20;
     }
   }
   if (   (adsp_lq1->iec_logreq1_def != ied_lreq1d_epoch_first)  /* retrieve first position log with this epoch */
       && (adsp_lq1->iec_logreq1_def != ied_lreq1d_epoch_last)) {  /* retrieve last position log with this epoch */
     if (adsp_lq1->ilc_position >= adss_mem_log_1->ilc_size) {
       adsp_lq1->iec_logreq1_ret = ied_lreq1r_invalid;
       return;
     }
     if (adsp_lq1->ilc_position < 0) {
       adsp_lq1->iec_logreq1_ret = ied_lreq1r_invalid;
       return;
     }
   }
   dss_critsect_log.m_enter();              /* critical section        */
   achl_pos = (char *) (adss_mem_log_1 + 1) + adsp_lq1->ilc_position;
   /* check position too old                                           */
   if (   (adsp_lq1->iec_logreq1_def != ied_lreq1d_epoch_first)  /* retrieve first position log with this epoch */
       && (adsp_lq1->iec_logreq1_def != ied_lreq1d_epoch_last)) {  /* retrieve last position log with this epoch */
     if (   (   (adsp_lq1->imc_count_filled != adss_mem_log_1->imc_count_filled))
             && (achl_pos < adss_mem_log_1->achc_start_prev)
         || (adsp_lq1->imc_count_filled < (adss_mem_log_1->imc_count_filled - 1))) {
       dss_critsect_log.m_leave();          /* critical section        */
       adsp_lq1->imc_len_record = 0;        /* length of record returned */
#ifdef B100908
       adsp_lq1->imc_epoch = 0;             /* epoch / time of log record */
#endif
       adsp_lq1->ilc_epoch = 0;             /* epoch / time of log record */
       adsp_lq1->iec_logreq1_ret = ied_lreq1r_pos_old;  /* position request too old */
       return;
     }
   }
   iml_count_filled = adss_mem_log_1->imc_count_filled;  /* value count filled current record */
   bol_error = FALSE;                       /* no error yet            */
   switch (adsp_lq1->iec_logreq1_def) {
     case ied_lreq1d_read_f:                /* read forward            */
       if (adsp_lq1->imc_count_filled == iml_count_filled) {
         if (achl_pos < adss_mem_log_1->achc_end_cur) {
           achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
           if (achl_pos < adss_mem_log_1->achc_end_cur) break;
         }
         adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
         bol_error = TRUE;                  /* error occured           */
         break;
       }
       /* check if wrap around                                         */
       if (achl_pos >= adss_mem_log_1->achc_end_prev) {
         achl_pos = (char *) (adss_mem_log_1 + 1);
#ifndef B080502
         iml_count_filled++;                /* is in records after last wrap */
#endif
         if (achl_pos < adss_mem_log_1->achc_end_cur) break;
         adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
         bol_error = TRUE;                  /* error occured           */
         break;
       }
#ifdef B080502
       iml_count_filled--;                  /* is in records before last wrap */
#endif
       achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
       break;
     case ied_lreq1d_read_b:                /* read backward           */
       if (adsp_lq1->imc_count_filled == iml_count_filled) {
         if (achl_pos > ((char *) (adss_mem_log_1 + 1))) {
           chl_length_previous = adss_mem_log_1->chc_length_previous;
           if (achl_pos < adss_mem_log_1->achc_end_cur) {
             chl_length_previous = *(achl_pos + 1);
           }
           achl_pos -= D_SIZE_LOG_HEADER + (((unsigned char) chl_length_previous) << 1);
           break;
         }
#ifdef B080502
         if (adss_mem_log_1->achc_end_cur > ((char *) (adss_mem_log_1 + 1))) {
#ifdef FORKEDIT
         }
#endif
#else
         if (   (adss_mem_log_1->achc_end_cur > ((char *) (adss_mem_log_1 + 1)))
             && (adss_mem_log_1->achc_start_prev)) {  /* filled before */
#endif
           iml_count_filled--;              /* is in records before last wrap */
           achl_pos = adss_mem_log_1->achc_end_prev
                        -  D_SIZE_LOG_HEADER - (*((unsigned char *) (adss_mem_log_1 + 1) + 1) << 1);
           break;
         }
         adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
         bol_error = TRUE;                  /* error occured           */
         break;
       }
#ifdef B080502
       iml_count_filled--;                  /* is in records before last wrap */
#endif
       if (achl_pos > adss_mem_log_1->achc_start_prev) {
         achl_pos -= D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 1) << 1);
         break;
       }
       adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
       bol_error = TRUE;                    /* error occured           */
       break;
     case ied_lreq1d_search_f:              /* search forward          */
#ifdef B140805
       while (TRUE) {                       /* loop records from here  */
         do {                               /* pseudo-loop to read next record */
           if (adsp_lq1->imc_count_filled == iml_count_filled) {
             if (achl_pos < adss_mem_log_1->achc_end_cur) {
               achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
               if (achl_pos < adss_mem_log_1->achc_end_cur) break;
             }
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             break;
           }
           /* check if wrap around                                         */
           if (achl_pos >= adss_mem_log_1->achc_end_prev) {
             achl_pos = (char *) (adss_mem_log_1 + 1);
#ifndef B080502
             iml_count_filled++;            /* is in records after last wrap */
#endif
             if (achl_pos < adss_mem_log_1->achc_end_cur) break;
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             break;
           }
#ifdef B080502
           iml_count_filled--;              /* is in records before last wrap */
#endif
           achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
         } while (FALSE);
         if (bol_error) break;              /* error occured           */
#ifdef DEBUG_080502
         if (!memcmp( achl_pos + D_SIZE_LOG_HEADER, "test line", 9 )) {
           printf( "DEBUG_080502 l%05d.\n", __LINE__ );
         }
#endif
         if (m_search_utf8_1( achl_pos + D_SIZE_LOG_HEADER, *((unsigned char *) achl_pos + 0) << 1, &dsl_ml_search_1 )) break;
       }
#endif
#ifndef B140805
       iml_search_count_filled = adsp_lq1->imc_count_filled;  /* get where we start from */
       while (TRUE) {                       /* loop records from here  */
         while (TRUE) {                     /* loop to read next record */
           if (iml_search_count_filled == iml_count_filled) {
             if (achl_pos < adss_mem_log_1->achc_end_cur) {
               achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
               if (achl_pos < adss_mem_log_1->achc_end_cur) break;
             }
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             break;
           }
           /* check if wrap around                                         */
           if (achl_pos >= adss_mem_log_1->achc_end_prev) {
             achl_pos = (char *) (adss_mem_log_1 + 1);
             iml_count_filled++;            /* is in records after last wrap */
             iml_search_count_filled = iml_count_filled;  /* compare with current records */
             if (achl_pos < adss_mem_log_1->achc_end_cur) break;
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             break;
           }
           achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
           if (achl_pos < adss_mem_log_1->achc_end_prev) break;
         }
         if (bol_error) break;              /* error occured           */
#ifdef DEBUG_080502
         if (!memcmp( achl_pos + D_SIZE_LOG_HEADER, "test line", 9 )) {
           printf( "DEBUG_080502 l%05d.\n", __LINE__ );
         }
#endif
         if (m_search_utf8_1( achl_pos + D_SIZE_LOG_HEADER, *((unsigned char *) achl_pos + 0) << 1, &dsl_ml_search_1 )) break;
       }
#endif
       break;
     case ied_lreq1d_search_b:              /* search backward         */
       while (TRUE) {                       /* loop records from here  */
         do {                               /* pseudo-loop to read previous record */
           if (adsp_lq1->imc_count_filled == iml_count_filled) {
             if (achl_pos > ((char *) (adss_mem_log_1 + 1))) {
               chl_length_previous = adss_mem_log_1->chc_length_previous;
               if (achl_pos < adss_mem_log_1->achc_end_cur) {
                 chl_length_previous = *(achl_pos + 1);
               }
               achl_pos -= D_SIZE_LOG_HEADER + (((unsigned char) chl_length_previous) << 1);
               break;
             }
             if (   (adss_mem_log_1->achc_end_cur > ((char *) (adss_mem_log_1 + 1)))
                 && (adss_mem_log_1->achc_start_prev)) {  /* filled before */
               iml_count_filled--;          /* is in records before last wrap */
               achl_pos = adss_mem_log_1->achc_end_prev
                            -  D_SIZE_LOG_HEADER - (*((unsigned char *) (adss_mem_log_1 + 1) + 1) << 1);
               break;
             }
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             /* return last record                                     */
             adsp_lq1->imc_count_filled = iml_count_filled;  /* value count filled current record */
             adsp_lq1->ilc_position = achl_pos - ((char *) (adss_mem_log_1 + 1));
             break;
           }
#ifdef B080502
           iml_count_filled--;              /* is in records before last wrap */
#endif
           if (achl_pos > adss_mem_log_1->achc_start_prev) {
             achl_pos -= D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 1) << 1);
             break;
           }
           adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
           bol_error = TRUE;                /* error occured           */
           /* return last record                                       */
           adsp_lq1->imc_count_filled = iml_count_filled;  /* value count filled current record */
           adsp_lq1->ilc_position = achl_pos - ((char *) (adss_mem_log_1 + 1));
         } while (FALSE);
         if (bol_error) break;              /* error occured           */
#ifdef DEBUG_080502
         if (!memcmp( achl_pos + D_SIZE_LOG_HEADER, "test line", 9 )) {
           printf( "DEBUG_080502 l%05d.\n", __LINE__ );
         }
#endif
         if (m_search_utf8_1( achl_pos + D_SIZE_LOG_HEADER, *((unsigned char *) achl_pos + 0) << 1, &dsl_ml_search_1 )) break;
       }
       break;
     case ied_lreq1d_s_regex_f:             /* search regular expression forward */
#ifdef B140813
       while (TRUE) {                       /* loop records from here  */
         do {                               /* pseudo-loop to read next record */
           if (adsp_lq1->imc_count_filled == iml_count_filled) {
             if (achl_pos < adss_mem_log_1->achc_end_cur) {
               achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
               if (achl_pos < adss_mem_log_1->achc_end_cur) break;
             }
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             break;
           }
           /* check if wrap around                                         */
           if (achl_pos >= adss_mem_log_1->achc_end_prev) {
             achl_pos = (char *) (adss_mem_log_1 + 1);
             iml_count_filled++;            /* is in records after last wrap */
             if (achl_pos < adss_mem_log_1->achc_end_cur) break;
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             break;
           }
           achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
         } while (FALSE);
         if (bol_error) break;              /* error occured           */
#ifdef DEBUG_080502
         if (!memcmp( achl_pos + D_SIZE_LOG_HEADER, "test line", 9 )) {
           printf( "DEBUG_080502 l%05d.\n", __LINE__ );
         }
#endif
// to-do 21.09.10 KB - call program of Mr. Jakobs
//       if (m_search_utf8_1( achl_pos + D_SIZE_LOG_HEADER, *((unsigned char *) achl_pos + 0) << 1, &dsl_ml_search_1 )) break;
         if (m_search_regex_exists( achl_pos + D_SIZE_LOG_HEADER, *((unsigned char *) achl_pos + 0) << 1,
                                    dsl_ml_search_1.achc_cmp_str, dsl_ml_search_1.imc_len_cmp_str )) {
           break;
         }
       }
#endif
#ifndef B140813
       iml_search_count_filled = adsp_lq1->imc_count_filled;  /* get where we start from */
       while (TRUE) {                       /* loop records from here  */
         while (TRUE) {                     /* loop to read next record */
           if (iml_search_count_filled == iml_count_filled) {
             if (achl_pos < adss_mem_log_1->achc_end_cur) {
               achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
               if (achl_pos < adss_mem_log_1->achc_end_cur) break;
             }
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             break;
           }
           /* check if wrap around                                         */
           if (achl_pos >= adss_mem_log_1->achc_end_prev) {
             achl_pos = (char *) (adss_mem_log_1 + 1);
             iml_count_filled++;            /* is in records after last wrap */
             iml_search_count_filled = iml_count_filled;  /* compare with current records */
             if (achl_pos < adss_mem_log_1->achc_end_cur) break;
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             break;
           }
           achl_pos += D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 0) << 1);
           if (achl_pos < adss_mem_log_1->achc_end_prev) break;
         }
         if (bol_error) break;              /* error occured           */
#ifdef DEBUG_080502
         if (!memcmp( achl_pos + D_SIZE_LOG_HEADER, "test line", 9 )) {
           printf( "DEBUG_080502 l%05d.\n", __LINE__ );
         }
#endif
// to-do 21.09.10 KB - call program of Mr. Jakobs
//       if (m_search_utf8_1( achl_pos + D_SIZE_LOG_HEADER, *((unsigned char *) achl_pos + 0) << 1, &dsl_ml_search_1 )) break;
         if (m_search_regex_exists( achl_pos + D_SIZE_LOG_HEADER, *((unsigned char *) achl_pos + 0) << 1,
                                    dsl_ml_search_1.achc_cmp_str, dsl_ml_search_1.imc_len_cmp_str )) {
           break;
         }
       }
#endif
       break;
     case ied_lreq1d_s_regex_b:             /* search regular expression backward */
       while (TRUE) {                       /* loop records from here  */
         do {                               /* pseudo-loop to read previous record */
           if (adsp_lq1->imc_count_filled == iml_count_filled) {
             if (achl_pos > ((char *) (adss_mem_log_1 + 1))) {
               chl_length_previous = adss_mem_log_1->chc_length_previous;
               if (achl_pos < adss_mem_log_1->achc_end_cur) {
                 chl_length_previous = *(achl_pos + 1);
               }
               achl_pos -= D_SIZE_LOG_HEADER + (((unsigned char) chl_length_previous) << 1);
               break;
             }
             if (   (adss_mem_log_1->achc_end_cur > ((char *) (adss_mem_log_1 + 1)))
                 && (adss_mem_log_1->achc_start_prev)) {  /* filled before */
               iml_count_filled--;          /* is in records before last wrap */
               achl_pos = adss_mem_log_1->achc_end_prev
                            -  D_SIZE_LOG_HEADER - (*((unsigned char *) (adss_mem_log_1 + 1) + 1) << 1);
               break;
             }
             adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
             bol_error = TRUE;              /* error occured           */
             /* return last record                                     */
             adsp_lq1->imc_count_filled = iml_count_filled;  /* value count filled current record */
             adsp_lq1->ilc_position = achl_pos - ((char *) (adss_mem_log_1 + 1));
             break;
           }
           if (achl_pos > adss_mem_log_1->achc_start_prev) {
             achl_pos -= D_SIZE_LOG_HEADER + (*((unsigned char *) achl_pos + 1) << 1);
             break;
           }
           adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
           bol_error = TRUE;                /* error occured           */
           /* return last record                                       */
           adsp_lq1->imc_count_filled = iml_count_filled;  /* value count filled current record */
           adsp_lq1->ilc_position = achl_pos - ((char *) (adss_mem_log_1 + 1));
         } while (FALSE);
         if (bol_error) break;              /* error occured           */
#ifdef DEBUG_080502
         if (!memcmp( achl_pos + D_SIZE_LOG_HEADER, "test line", 9 )) {
           printf( "DEBUG_080502 l%05d.\n", __LINE__ );
         }
#endif
// to-do 21.09.10 KB - call program of Mr. Jakobs
//       if (m_search_utf8_1( achl_pos + D_SIZE_LOG_HEADER, *((unsigned char *) achl_pos + 0) << 1, &dsl_ml_search_1 )) break;
         if (m_search_regex_exists( achl_pos + D_SIZE_LOG_HEADER, *((unsigned char *) achl_pos + 0) << 1,
                                    dsl_ml_search_1.achc_cmp_str, dsl_ml_search_1.imc_len_cmp_str )) {
           break;
         }
       }
       break;
     case ied_lreq1d_epoch_first:           /* retrieve first position log with this epoch */
       achl_search_pos = adss_mem_log_1->achc_end_cur;  /* get current position */
       achl_pos = NULL;                     /* record not yet found    */
       iml_search_count_filled = iml_count_filled;  /* get current count filled */
       while (TRUE) {                       /* loop read backward current count filled */
         if (achl_search_pos <= ((char *) (adss_mem_log_1 + 1))) {
           iml_search_count_filled--;
           break;
         }
         chl_length_previous = adss_mem_log_1->chc_length_previous;
         if (achl_search_pos < adss_mem_log_1->achc_end_cur) {
           chl_length_previous = *(achl_search_pos + 1);
         }
         achl_search_pos -= D_SIZE_LOG_HEADER + (((unsigned char) chl_length_previous) << 1);
#ifdef B100908
         iml_epoch = (((unsigned char) *(achl_search_pos + 2 + 0)) << 24)
                       | (((unsigned char) *(achl_search_pos + 2 + 1)) << 16)
                       | (((unsigned char) *(achl_search_pos + 2 + 2)) << 8)
                       | ((unsigned char) *(achl_search_pos + 2 + 3));
#endif
#ifdef XYZ1
         ill_epoch = (*((unsigned char *) achl_search_pos + 2 + 0) << 40)
                       | (*((unsigned char *) achl_search_pos + 2 + 1) << 32)
                       | (*((unsigned char *) achl_search_pos + 2 + 2) << 24)
                       | (*((unsigned char *) achl_search_pos + 2 + 3) << 16)
                       | (*((unsigned char *) achl_search_pos + 2 + 4) << 8)
                       | *((unsigned char *) achl_search_pos + 2 + 5);
#endif
         ill_epoch = MAC_GET_EPOCH( achl_search_pos );
         if (achl_pos == NULL) {            /* record not yet found    */
#ifdef B100908
           if (adsp_lq1->imc_epoch < iml_epoch) continue;
#endif
           if (adsp_lq1->ilc_epoch < ill_epoch) continue;
           achl_pos = achl_search_pos;      /* save position record with epoch found */
#ifdef B100908
           if (adsp_lq1->imc_epoch != iml_epoch) break;
#endif
           if (adsp_lq1->ilc_epoch != ill_epoch) break;
           continue;
         }
#ifdef B100908
         if (adsp_lq1->imc_epoch != iml_epoch) break;
#endif
         if (adsp_lq1->ilc_epoch != ill_epoch) break;
         achl_pos = achl_search_pos;        /* save position record with epoch found */
       }
       if (iml_search_count_filled == iml_count_filled) break; /* compare current count filled */
       if (adss_mem_log_1->achc_start_prev == NULL) {  /* not filled before */
         if (achl_pos) break;               /* requested record found  */
         adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
         bol_error = TRUE;                  /* error occured           */
         break;
       }
       achl_search_pos = adss_mem_log_1->achc_end_prev;  /* start from end */
       chl_length_previous = *((unsigned char *) (adss_mem_log_1 + 1) + 1);
       while (TRUE) {                       /* loop read backward previous count filled */
         if (achl_search_pos <= adss_mem_log_1->achc_start_prev) break;
         achl_search_pos -= D_SIZE_LOG_HEADER + (((unsigned char) chl_length_previous) << 1);
         chl_length_previous = *(achl_search_pos + 1);
#ifdef B100908
         iml_epoch = (((unsigned char) *(achl_search_pos + 2 + 0)) << 24)
                       | (((unsigned char) *(achl_search_pos + 2 + 1)) << 16)
                       | (((unsigned char) *(achl_search_pos + 2 + 2)) << 8)
                       | ((unsigned char) *(achl_search_pos + 2 + 3));
#endif
         ill_epoch = MAC_GET_EPOCH( achl_search_pos );
         if (achl_pos == NULL) {            /* record not yet found    */
#ifdef B100908
// to-do 08.09.10 KB - is break or continue missing ???
           if (adsp_lq1->imc_epoch < iml_epoch)
           achl_pos = achl_search_pos;      /* save position record with epoch found */
#endif
           if (adsp_lq1->ilc_epoch < ill_epoch) {
             achl_pos = achl_search_pos;    /* save position record with epoch found */
           }
           iml_count_filled = iml_search_count_filled;  /* set count filled */
#ifdef B100908
           if (adsp_lq1->imc_epoch != iml_epoch) break;
#endif
           if (adsp_lq1->ilc_epoch != ill_epoch) break;
           continue;
         }
#ifdef B100908
         if (adsp_lq1->imc_epoch != iml_epoch) break;
#endif
         if (adsp_lq1->ilc_epoch != ill_epoch) break;
         achl_pos = achl_search_pos;        /* save position record with epoch found */
         iml_count_filled = iml_search_count_filled;  /* set count filled */
       }
       if (achl_pos) break;                 /* requested record found  */
       adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
       bol_error = TRUE;                    /* error occured           */
       break;
     case ied_lreq1d_epoch_last:            /* retrieve last position log with this epoch */
       achl_search_pos = adss_mem_log_1->achc_end_cur;  /* get current position */
       achl_pos = NULL;                     /* record not yet found    */
       iml_search_count_filled = iml_count_filled;  /* get current count filled */
       while (TRUE) {                       /* loop read backward current count filled */
         if (achl_search_pos <= ((char *) (adss_mem_log_1 + 1))) {
           iml_search_count_filled--;
           break;
         }
         chl_length_previous = adss_mem_log_1->chc_length_previous;
         if (achl_search_pos < adss_mem_log_1->achc_end_cur) {
           chl_length_previous = *(achl_search_pos + 1);
         }
         achl_search_pos -= D_SIZE_LOG_HEADER + (((unsigned char) chl_length_previous) << 1);
#ifdef B100908
         iml_epoch = (((unsigned char) *(achl_search_pos + 2 + 0)) << 24)
                       | (((unsigned char) *(achl_search_pos + 2 + 1)) << 16)
                       | (((unsigned char) *(achl_search_pos + 2 + 2)) << 8)
                       | ((unsigned char) *(achl_search_pos + 2 + 3));
#endif
         ill_epoch = MAC_GET_EPOCH( achl_search_pos );
#ifdef B100908
         if (adsp_lq1->imc_epoch < iml_epoch) continue;
#endif
         if (adsp_lq1->ilc_epoch < ill_epoch) continue;
         achl_pos = achl_search_pos;        /* save position record with epoch found */
         break;
       }
       if (iml_search_count_filled == iml_count_filled) break; /* compare current count filled */
       if (adss_mem_log_1->achc_start_prev == NULL) {  /* not filled before */
         adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
         bol_error = TRUE;                  /* error occured           */
         break;
       }
       achl_search_pos = adss_mem_log_1->achc_end_prev;  /* start from end */
       chl_length_previous = *((unsigned char *) (adss_mem_log_1 + 1) + 1);
       while (TRUE) {                       /* loop read backward previous count filled */
         if (achl_search_pos <= adss_mem_log_1->achc_start_prev) break;
         achl_search_pos -= D_SIZE_LOG_HEADER + (((unsigned char) chl_length_previous) << 1);
         chl_length_previous = *(achl_search_pos + 1);
#ifdef B100908
         iml_epoch = (((unsigned char) *(achl_search_pos + 2 + 0)) << 24)
                       | (((unsigned char) *(achl_search_pos + 2 + 1)) << 16)
                       | (((unsigned char) *(achl_search_pos + 2 + 2)) << 8)
                       | ((unsigned char) *(achl_search_pos + 2 + 3));
#endif
         ill_epoch = MAC_GET_EPOCH( achl_search_pos );
#ifdef B100908
         if (adsp_lq1->imc_epoch < iml_epoch) continue;
#endif
         if (adsp_lq1->ilc_epoch < ill_epoch) continue;
         achl_pos = achl_search_pos;        /* save position record with epoch found */
         iml_count_filled = iml_search_count_filled;  /* set count filled */
         break;
       }
       if (achl_pos) break;                 /* requested record found  */
       adsp_lq1->iec_logreq1_ret = ied_lreq1r_eof;  /* end of file found */
       bol_error = TRUE;                    /* error occured           */
       break;
   }
   if (bol_error) {                         /* error occured           */
     dss_critsect_log.m_leave();            /* critical section        */
     adsp_lq1->imc_len_record = 0;          /* length of record returned */
#ifdef B100908
     adsp_lq1->imc_epoch = 0;               /* epoch / time of log record */
#endif
     adsp_lq1->ilc_epoch = 0;               /* epoch / time of log record */
     return;                                /* all done                */
   }
   /* move the record now                                              */
   if (adsp_lq1->iec_chs_area == ied_chs_utf_8) {  /* transform not necessary */
     adsp_lq1->imc_len_record = *((unsigned char *) achl_pos + 0) << 1;  /* length of record returned */
     if (adsp_lq1->achc_area) {
       if (adsp_lq1->imc_len_record > adsp_lq1->imc_len_area) {
         adsp_lq1->imc_len_record = adsp_lq1->imc_len_area;
       }
       memcpy( adsp_lq1->achc_area, achl_pos + D_SIZE_LOG_HEADER, adsp_lq1->imc_len_record );
     }
   } else {                                 /* character set needs to be transformed */
     if (adsp_lq1->achc_area) {
       adsp_lq1->imc_len_record = m_cpy_vx_vx( adsp_lq1->achc_area,
                                               adsp_lq1->imc_len_area,
                                               adsp_lq1->iec_chs_area,
                                               achl_pos + D_SIZE_LOG_HEADER,
                                               *((unsigned char *) achl_pos + 0) << 1,
                                               ied_chs_utf_8 );
     } else {
       adsp_lq1->imc_len_record = m_len_vx_vx( adsp_lq1->iec_chs_area,
                                               achl_pos + D_SIZE_LOG_HEADER,
                                               *((unsigned char *) achl_pos + 0) << 1,
                                               ied_chs_utf_8 );
     }
   }
#ifdef B100908
   adsp_lq1->imc_epoch = (*((unsigned char *) achl_pos + 2 + 0) << 24)
                           | (*((unsigned char *) achl_pos + 2 + 1) << 16)
                           | (*((unsigned char *) achl_pos + 2 + 2) << 8)
                           | *((unsigned char *) achl_pos + 2 + 3);
#endif
#ifdef XYZ1
   adsp_lq1->ilc_epoch = (*((unsigned char *) achl_pos + 2 + 0) << 40)
                           | (*((unsigned char *) achl_pos + 2 + 1) << 32)
                           | (*((unsigned char *) achl_pos + 2 + 2) << 24)
                           | (*((unsigned char *) achl_pos + 2 + 3) << 16)
                           | (*((unsigned char *) achl_pos + 2 + 4) << 8)
                           | *((unsigned char *) achl_pos + 2 + 5);
#endif
   adsp_lq1->ilc_epoch = MAC_GET_EPOCH( achl_pos );
   adsp_lq1->imc_count_filled = iml_count_filled;  /* value count filled current record */
   adsp_lq1->ilc_position = achl_pos - ((char *) (adss_mem_log_1 + 1));
   adsp_lq1->iec_logreq1_ret = ied_lreq1r_ok;  /* request processed o.k. */
   dss_critsect_log.m_leave();              /* critical section        */
} /* end m_mem_log_1_req()                                             */

/** search a sub-string, not case sensitive                            */
extern "C" BOOL m_search_utf8_1( char *achp_string, int imp_len_string,
                                 struct dsd_ml_search_1 *adsp_ml_search_1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml_cmp;                      /* result compare          */
   char       *achl_w1, *achl_w2;           /* working-variables       */
   char       *achl_end;                    /* last position input     */

   if (adsp_ml_search_1->imc_len_cmp_str > imp_len_string) return FALSE;
   achl_end = achp_string + imp_len_string - adsp_ml_search_1->imc_len_cmp_str + 1;
   do {                                     /* loop to search sub-string */
     achl_w1 = (char *) memchr( achp_string, adsp_ml_search_1->chc_fchar_1, achl_end - achp_string );
     if ((adsp_ml_search_1->chc_fchar_2) && (achl_w1 != achp_string)) {
       achl_w2 = (char *) memchr( achp_string, adsp_ml_search_1->chc_fchar_2, achl_end - achp_string );
       if (achl_w2) {
         if ((achl_w1 == NULL) || (achl_w1 > achl_w2)) achl_w1 = achl_w2;
       }
     }
     if (achl_w1 == NULL) return FALSE;
     bol1 = m_cmpi_vx_vx( &iml_cmp,
                          achl_w1, adsp_ml_search_1->imc_len_cmp_str, ied_chs_utf_8,
                          adsp_ml_search_1->achc_cmp_str, adsp_ml_search_1->imc_len_cmp_str, ied_chs_utf_8 );
     if (bol1 && (iml_cmp == 0)) return TRUE;  /* sub-string found     */
     achp_string = achl_w1 + 1;             /* start from next character */
   } while (achp_string < achl_end);
   return FALSE;
} /* end m_search_utf8_1()                                             */

/** register log new pass callback                                     */
extern "C" BOOL m_log_new_p_register( struct dsd_log_new_call *adsp_lnc ) {
   if (adss_mem_log_1 == NULL) return FALSE;  /* log not open          */
   dss_critsect_log.m_enter();              /* critical section        */
   adsp_lnc->adsc_next = adss_lnc_anchor;   /* get chain of callback routines */
   adss_lnc_anchor = adsp_lnc;              /* set new chain of callback routines */
   dss_critsect_log.m_leave();              /* critical section        */
   return TRUE;
} /* end m_log_new_p_register()                                        */

/** un-register log new pass callback                                  */
extern "C" BOOL m_log_new_p_unreg( struct dsd_log_new_call *adsp_lnc ) {
   struct dsd_log_new_call *adsl_lnc_cur;   /* current in chain        */
   struct dsd_log_new_call *adsl_lnc_last;  /* last in chain           */

   adsl_lnc_last = NULL;                    /* clear last in chain     */
   dss_critsect_log.m_enter();              /* critical section        */
   adsl_lnc_cur = adss_lnc_anchor;          /* get chain of callback routines */
   while (adsl_lnc_cur) {                   /* loop over all registered callback routines */
     if (adsl_lnc_cur == adsp_lnc) {        /* position to remove found */
       if (adsl_lnc_last == NULL) {         /* at beginning of chain   */
         adss_lnc_anchor = adsp_lnc->adsc_next;  /* remove from chain  */
         break;
       }
       adsl_lnc_last->adsc_next = adsp_lnc->adsc_next;  /* remove from chain */
       break;
     }
     adsl_lnc_last = adsl_lnc_cur;          /* save last in chain      */
     adsl_lnc_cur = adsl_lnc_cur->adsc_next;  /* get next in chain     */
   }
   dss_critsect_log.m_leave();              /* critical section        */
   if (adsl_lnc_cur) return TRUE;           /* position to remove found */
   return FALSE;
} /* end m_log_new_p_unreg()                                           */

#ifndef HL_UNIX
/** return the Epoch value in milliseconds                             */
static HL_LONGLONG m_get_epoch_ms( void ) {
   struct __timeb64 timebuffer;

   _ftime64( &timebuffer );

   return ( timebuffer.time * 1000 + timebuffer.millitm );
} /* end m_get_epoch_ms()                                              */
#endif
#ifdef HL_UNIX
/** return the Epoch value in milliseconds                             */
static HL_LONGLONG m_get_epoch_ms( void ) {
   struct timeval dsl_timeval;

   gettimeofday( &dsl_timeval, NULL );
   return (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000);
} /* end m_get_epoch_ms()                                              */
#endif
