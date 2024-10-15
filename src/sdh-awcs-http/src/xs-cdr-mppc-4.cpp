//#define D_LONG_SHIFT
//#define D_SHORT_AUX_STORE
//#define TRACEHL1
//#define TRACEHL2 3086
//#define TRACEHL3 2214
//#define DEBUG_110418_01
#define TRY_110418_01
#define TRY_110418_02
#define TRY_110418_04
#define TRY_110516_01
#define TRY_110523_01
//#define DEBUG_110516_01
//#define DEBUG_110516_02
//#define DEBUG_110519_01
//#define DEBUG_110519_02                   /* previous character      */
//#define DEBUG_110519_03
//#define DEBUG_110521_01
//#define DEBUG_110731_01                     /* RDP6.0 only literals    */
//#define DEBUG_110803_01                     /* RDP6.0 display length-of-match */
//#define DEBUG_110804_01                     /* RDP6.0 no cache offset  */
//#define DEBUG_110815_01                     /* RDP6.0 packet at front  */
//define TRACEHL1
#ifdef TO_DO
using little memory - wrong, 16-bit index
#endif
/*+--------------------------------------------------------------------------+*/
/*|                                                                          |*/
/*| PROGRAM NAME: xs-cdr-mppc-4                                              |*/
/*| -------------                                                            |*/
/*|  Subroutine compression MPPC for RDP.                                    |*/
/*|    RDP4, RDP5, RDP6.0, using little memory                               |*/
/*|  created 24.07.11 KB                                                     |*/
/*|                                                                          |*/
/*| COPYRIGHT:                                                               |*/
/*| ----------                                                               |*/
/*|  Copyright (C) HOB Germany 2011                                          |*/
/*|  Copyright (C) HOB Germany 2013                                          |*/
/*|  Copyright (C) HOB Germany 2016                                          |*/
/*|                                                                          |*/
/*| WHAT THIS PROGRAM DOES:                                                  |*/
/*| -----------------------                                                  |*/
/*|  This program is a subroutine to other programs and                      |*/
/*|  compresses data.                                                        |*/
/*|                                                                          |*/
/*| WHAT YOU NEED TO COMPILE THIS PROGRAM:                                   |*/
/*| --------------------------------------                                   |*/
/*|                                                                          |*/
/*| REQUIRED FILES:                                                          |*/
/*| ---------------                                                          |*/
/*|                                                                          |*/
/*|   xs-cdr-mppc-4.cpp - Source code                                        |*/
/*|   hob-cd-record-1.h - Application header file                            |*/
/*|                                                                          |*/
/*|   for Windows:                                                           |*/
/*|   windows.h         - Standard Windows header file                       |*/
/*|                                                                          |*/
/*|   for Unix / Linux / FreeBSD                                             |*/
/*|   hob-unix01.h      - Standard HOB Unix header file                      |*/
/*|                                                                          |*/
/*|   it is not clear if the other header files are really needed            |*/
/*|                                                                          |*/
/*| when compiling for Unix, set the precompiler variable HL_UNIX            |*/
/*|                                                                          |*/
/*+--------------------------------------------------------------------------+*/

/**
   RDP4:
     8 KB history buffer
     Copy-offset
       0...63          1111 + lower 6 bits of copy-offset
       64...319        1110 + lower 8 bits of (copy-offset - 64)
       320...8191      110  + lower 13 bits of (copy-offset - 320)
     Length-of-Match
       3               0
       4...7           10 + 2 lower bits of L-o-M
       8...15          110 + 3 lower bits of L-o-M
       16...31         1110 + 4 lower bits of L-o-M
       32...64         11110 + 5 lower bits of L-o-M
       64...127        111110 + 6 lower bits of L-o-M
       128...255       1111110 + 7 lower bits of L-o-M
       256...511       11111110 + 8 lower bits of L-o-M
       512...1023      111111110 + 9 lower bits of L-o-M
       1024...2047     1111111110 + 10 lower bits of L-o-M
       2048...4095     11111111110 + 11 lower bits of L-o-M
       4096...8191     111111111110 + 12 lower bits of L-o-M
   RDP5:
     64 KB history buffer
     Copy-offset
       0...63          11111 + lower 6 bits of copy-offset
       64...319        11110 + lower 8 bits of (copy-offset - 64)
       320...2367      1110  + lower 11 bits of (copy-offset - 320)
       2368+           110   + lower 16 bits of (copy-offset - 2368)
     Length-of-Match
       3               0
       4...7           10 + 2 lower bits of L-o-M
       8...15          110 + 3 lower bits of L-o-M
       16...31         1110 + 4 lower bits of L-o-M
       32...64         11110 + 5 lower bits of L-o-M
       64...127        111110 + 6 lower bits of L-o-M
       128...255       1111110 + 7 lower bits of L-o-M
       256...511       11111110 + 8 lower bits of L-o-M
       512...1023      111111110 + 9 lower bits of L-o-M
       1024...2047     1111111110 + 10 lower bits of L-o-M
       2048...4095     11111111110 + 11 lower bits of L-o-M
       4096...8191     111111111110 + 12 lower bits of L-o-M
       8192...16383    1111111111110 + 13 lower bits of L-o-M
       16384...32767   11111111111110 + 14 lower bits of L-o-M
       32768...65535   111111111111110 + 15 lower bits of L-o-M

   The compression can only start when all input data is present,
   that means adsp_cdr_ctrl->boc_mp_flush is set.
   So before all input data needs to be saved in temporary memory.

   For compression (encode) this program provides an history buffer
   and a tree (chain) where all equal characters in the history buffer
   are chained together. But only every second (on even position) character
   in the history buffer is in this chain.
   For all 256 possible values of a byte there are 256 chains.
   When walking thru the chain to search for the longest match,
   the character before the start of the new string is also compared.
   During encoding, the new data are not copied into the history buffer,
   but the tree (chain) is already built with the new strings.
   When transparent output is shorter, the stored original input is passed
   as output. The tree (chain) is reconstructed from the strings that are
   still in the history buffer.
   When compressed output is shorter, the input is copied to the
   history buffer after all compression has been done.
*/

#ifndef HL_COMP_MULTI
#define D_M_CDX_ENC m_cdr_enc
#define D_M_CDX_DEC m_cdr_dec
#else
#define D_M_CDX_ENC m_cdr_mppc_4_enc
#define D_M_CDX_DEC m_cdr_mppc_4_dec
#endif

#define HL_RDP_PACKET_COMPRESSED  0X20
#define HL_RDP_PACKET_AT_FRONT    0X40
#define HL_RDP_PACKET_FLUSHED     0X80

/*+--------------------------------------------------------------------------+*/
/*| System and library header files.                                         |*/
/*+--------------------------------------------------------------------------+*/

#ifndef HL_UNIX
#include <windows.h>
#else
#include <hob-unix01.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*+-------------------------------------------------------------------+*/
/*| Application header files.                                         |*/
/*+-------------------------------------------------------------------+*/

#define VAL_BYTE        8                   /* character size (bits)   */
#define D_MAX_BYTE      256                 /* 2 ** bits of byte       */
#define VAL_TAB_R60_D1_L   13               /* RDP6.0 decode 1 length  */
#define VAL_TAB_R60_D1_M   6                /* RDP6.0 decode 1 minumum literal */
#define VAL_TAB_R60_D1_END 0X0100           /* RDP6.0 end              */
#define VAL_TAB_R60_D1_OFF 0X0101           /* RDP6.0 beginning of offset */
#define VAL_TAB_R60_D1_CAC 0X0121           /* RDP6.0 beginning of cache offset */
#define VAL_TAB_R60_D2_L   9                /* RDP6.0 decode 2 length  */
#define VAL_CACHE_OFF   4                   /* RDP6.0 cache offset     */

#ifndef D_SHORT_AUX_STORE
#define LEN_AUX_STOR       8192             /* length auxiliary stor   */
#else
#define LEN_AUX_STOR       256              /* length auxiliary stor   */
#endif

#define UCDRPROG
#include <hob-cd-record-1.h>

struct dsd_entry_r4a5 {                     /* entry RDP4 and RDP5     */
   short int  isc_son;                      /* son                     */
};

struct dsd_node_r4a5 {                      /* node RDP4 and RDP5      */
   short int  isc_dad;                      /* dad                     */
   short int  isc_son;                      /* son                     */
};

struct dsd_stor_ext {                       /* external storage acquired */
   struct dsd_stor_ext *adsc_next;          /* next in chain           */
#ifdef XYZ1
   unsigned short int usc_len_out;          /* length output area      */
   unsigned short int usc_len_inp;          /* length input area       */
#endif
};

struct dsd_inp_st {                         /* input storage           */
   struct dsd_inp_st *adsc_next;            /* next in chain           */
   unsigned short int usc_len_inp;          /* length input area       */
};

struct dsd_out_1 {                          /* output pointers         */
   char       *achc_out_cur;                /* current output          */
   char       *achc_out_end;                /* end of output           */
   struct dsd_gather_i_1 *adsc_gai1_in_saved;  /* input data saved     */
   struct dsd_gather_i_1 *adsc_gai1_in_new;  /* input data new in last call */
   struct dsd_gather_i_1 *adsc_gai1_out_last;  /* last gather output   */
};

struct dsd_enc_int {                        /* encoding / compression intern */
   struct dsd_entry_r4a5 *adsc_entry_r4a5;  /* entry RDP4/5            */
   struct dsd_node_r4a5 *adsc_node_r4a5;    /* node RDP4/5             */
   char       *achc_histbu_cur;             /* current position in history buffer */
   char       *achc_histbu_max;             /* maximum reached position in history buffer */
   struct dsd_gather_i_1 *adsc_gai1_in_saved;  /* input data saved     */
   struct dsd_gather_i_1 *adsc_gai1_out_saved;  /* output data saved   */
   struct dsd_stor_ext *adsc_stor_ext;      /* external storage acquired */
   BOOL       boc_rdp60_at_front;           /* RDP 6.0 packet at front */
#ifndef B120403
   char       chc_comp_header;              /* value for compression header */
#endif
};

enum ied_dec_cont {                         /* where to continue decode */
   ied_dc_dcbu00 = 0,                       /* start of new packet     */
   ied_dc_dcbu20,                           /* continue compressed packet */
   ied_dc_dcco64,                           /* continue output match   */
   ied_dc_dcco72,                           /* continue start calculating Length-of-Match */
   ied_dc_dcco80                            /* continue bits for Length-of-Match */
};

struct dsd_dec_int {                        /* decoding / decompression intern */
   enum ied_dec_cont iec_dec_cont;          /* where to continue decode */
   char       *achc_histbu_end;             /* end of history buffer   */
   char       *achc_histbu_cur;             /* current position in history buffer */
   char       *achc_histbu_max;             /* maximum position in history buffer */
   int        imc_save_1;                   /* save value              */
   int        imc_save_2;                   /* save value              */
   int        imc_shift_v;                  /* shift-value             */
   int        imc_shift_c;                  /* shift-count             */
#ifdef DEBUG_110519_03
   char       *achc_histbu_debug;           /* debug position in history buffer */
#endif
};

/*+--------------------------------------------------------------------------+*/
/*| Internal function prototypes.                                            |*/
/*+--------------------------------------------------------------------------+*/

static inline BOOL m_enc_output( struct dsd_cdr_ctrl *, struct dsd_enc_int *, struct dsd_out_1 *, unsigned char );
#ifdef TRACEHL1
static BOOL m_sr_check_1( struct dsd_cdr_ctrl *, struct dsd_enc_int *, int, BOOL );
#endif

#ifdef TRACEHL1
static void m_console_out( char *achp_buff, int implength );
static void m_console_gather( struct dsd_gather_i_1 * );

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
#endif

/*+--------------------------------------------------------------------------+*/
/*| Static global variables and local constants.                             |*/
/*+--------------------------------------------------------------------------+*/

static unsigned char ucrs_leading_bits[256] = {
   0,    0,    0,    0,    0,    0,    0,    0,     /* 00 - 07         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 08 - 0F         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 10 - 07         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 18 - 1F         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 20 - 27         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 28 - 2F         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 30 - 37         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 38 - 3F         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 40 - 47         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 48 - 4F         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 50 - 57         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 58 - 5F         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 60 - 67         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 68 - 6F         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 70 - 77         */
   0,    0,    0,    0,    0,    0,    0,    0,     /* 78 - 7F         */
   1,    1,    1,    1,    1,    1,    1,    1,     /* 80 - 87         */
   1,    1,    1,    1,    1,    1,    1,    1,     /* 88 - 8F         */
   1,    1,    1,    1,    1,    1,    1,    1,     /* 90 - 97         */
   1,    1,    1,    1,    1,    1,    1,    1,     /* 98 - 9F         */
   1,    1,    1,    1,    1,    1,    1,    1,     /* A0 - A7         */
   1,    1,    1,    1,    1,    1,    1,    1,     /* A8 - AF         */
   1,    1,    1,    1,    1,    1,    1,    1,     /* B0 - B7         */
   1,    1,    1,    1,    1,    1,    1,    1,     /* B8 - BF         */
   2,    2,    2,    2,    2,    2,    2,    2,     /* C0 - C7         */
   2,    2,    2,    2,    2,    2,    2,    2,     /* C8 - CF         */
   2,    2,    2,    2,    2,    2,    2,    2,     /* D0 - D7         */
   2,    2,    2,    2,    2,    2,    2,    2,     /* D8 - DF         */
   3,    3,    3,    3,    3,    3,    3,    3,     /* E0 - E7         */
   3,    3,    3,    3,    3,    3,    3,    3,     /* E8 - EF         */
   4,    4,    4,    4,    4,    4,    4,    4,     /* F0 - F7         */
   5,    5,    5,    5,    6,    6,    7,    8      /* F8 - FF         */
};

static unsigned char ucrs_trailing_bits[256] = {
   0,    1,    2,    2,    3,    3,    3,    3,     /* 00 - 07         */
   4,    4,    4,    4,    4,    4,    4,    4,     /* 08 - 0F         */
   5,    5,    5,    5,    5,    5,    5,    5,     /* 10 - 07         */
   5,    5,    5,    5,    5,    5,    5,    5,     /* 18 - 0F         */
   6,    6,    6,    6,    6,    6,    6,    6,     /* 20 - 27         */
   6,    6,    6,    6,    6,    6,    6,    6,     /* 28 - 2F         */
   6,    6,    6,    6,    6,    6,    6,    6,     /* 30 - 37         */
   6,    6,    6,    6,    6,    6,    6,    6,     /* 38 - 3F         */
   7,    7,    7,    7,    7,    7,    7,    7,     /* 40 - 47         */
   7,    7,    7,    7,    7,    7,    7,    7,     /* 48 - 4F         */
   7,    7,    7,    7,    7,    7,    7,    7,     /* 50 - 57         */
   7,    7,    7,    7,    7,    7,    7,    7,     /* 58 - 5F         */
   7,    7,    7,    7,    7,    7,    7,    7,     /* 60 - 67         */
   7,    7,    7,    7,    7,    7,    7,    7,     /* 68 - 6F         */
   7,    7,    7,    7,    7,    7,    7,    7,     /* 70 - 77         */
   7,    7,    7,    7,    7,    7,    7,    7,     /* 78 - 7F         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* 80 - 87         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* 88 - 8F         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* 90 - 97         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* 98 - 9F         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* A0 - A7         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* A8 - AF         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* B0 - B7         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* B8 - BF         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* C0 - C7         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* C8 - CF         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* D0 - D7         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* D8 - DF         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* E0 - E7         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* E8 - EF         */
   8,    8,    8,    8,    8,    8,    8,    8,     /* F0 - F7         */
   8,    8,    8,    8,    8,    8,    8,    8      /* F8 - FF         */
};

static int imrs_rdp4_co_off_len_total[ 8 + 1 ] = {
   0,                                       /* zero, invalid           */
   VAL_BYTE + 1 - 1,                        /* 1, single byte          */
   16,                                      /* 2                       */
   12,                                      /* 3                       */
   10,                                      /* 4                       */
   10,                                      /* 5                       */
   10,                                      /* 6                       */
   10,                                      /* 7                       */
   10                                       /* 8                       */
};

static int imrs_rdp4_co_off_lead_bits[ 8 + 1 ] = {
   0,                                       /* zero, invalid           */
   0,                                       /* 1, invalid              */
   3,                                       /* 2                       */
   4,                                       /* 3                       */
   4,                                       /* 4                       */
   4,                                       /* 5                       */
   4,                                       /* 6                       */
   4,                                       /* 7                       */
   4                                        /* 8                       */
};

static int imrs_rdp4_co_off_add[ 8 + 1 ] = {
   0,                                       /* zero, invalid           */
   0,                                       /* 1, invalid              */
   320,                                     /* 2                       */
   64,                                      /* 3                       */
   0,                                       /* 4                       */
   0,                                       /* 5                       */
   0,                                       /* 6                       */
   0,                                       /* 7                       */
   0                                        /* 8                       */
};

static int imrs_rdp5_co_off_len_total[ 8 + 1 ] = {
   0,                                       /* zero, invalid           */
   VAL_BYTE + 1 - 1,                        /* 1, single byte          */
   19,                                      /* 2                       */
   15,                                      /* 3                       */
   13,                                      /* 4                       */
   11,                                      /* 5                       */
   11,                                      /* 6                       */
   11,                                      /* 7                       */
   11                                       /* 8                       */
};

static int imrs_rdp5_co_off_lead_bits[ 8 + 1 ] = {
   0,                                       /* zero, invalid           */
   0,                                       /* 1, invalid              */
   3,                                       /* 2                       */
   4,                                       /* 3                       */
   5,                                       /* 4                       */
   5,                                       /* 5                       */
   5,                                       /* 6                       */
   5,                                       /* 7                       */
   5                                        /* 8                       */
};

static int imrs_rdp5_co_off_add[ 8 + 1 ] = {
   0,                                       /* zero, invalid           */
   0,                                       /* 1, invalid              */
   2368,                                    /* 2                       */
   320,                                     /* 3                       */
   64,                                      /* 4                       */
   0,                                       /* 5                       */
   0,                                       /* 6                       */
   0,                                       /* 7                       */
   0                                        /* 8                       */
};

/**
   RDP 6.0 static Hufman encoding
   see [MS-RDPEGDI] v20110204 chapter 3.1.8.1.4.1 (pages from 134)
*/

static const unsigned char ucrs_rdp60_encode_1[] = {
    6,  6,  6,  7,  7,  7,  7,  7,          /* 0X00 - 0X07             */
    7,  7,  7,  8,  8,  8,  8,  8,          /* 0X08 - 0X0F             */
    8,  8,  9,  8,  9,  9,  9,  9,          /* 0X10 - 0X17             */
    8,  8,  9,  9,  9,  9,  9,  9,          /* 0X18 - 0X1F             */
    8,  9,  9, 10,  9,  9,  9,  9,          /* 0X20 - 0X27             */
    9,  9,  9, 10,  9, 10, 10, 10,          /* 0X28 - 0X2F             */
    9,  9, 10,  9, 10,  9, 10,  9,          /* 0X30 - 0X37             */
    9,  9, 10, 10,  9, 10,  9,  9,          /* 0X38 - 0X3F             */
    8,  9,  9,  9,  9, 10, 10, 10,          /* 0X40 - 0X47             */
    9,  9, 10, 10, 10, 10, 10, 10,          /* 0X48 - 0X4F             */
    9,  9, 10, 10, 10, 10, 10, 10,          /* 0X50 - 0X57             */
   10,  9, 10, 10, 10, 10, 10, 10,          /* 0X58 - 0X5F             */
    8, 10, 10, 10, 10, 10, 10, 10,          /* 0X60 - 0X67             */
   10, 10, 10, 10, 10, 10, 10, 10,          /* 0X68 - 0X6F             */
    9, 10, 10, 10, 10, 10, 10, 10,          /* 0X70 - 0X77             */
    9, 10, 10, 10, 10, 10, 10,  9,          /* 0X78 - 0X7F             */
    7,  9,  9, 10,  9, 10, 10, 10,          /* 0X80 - 0X87             */
    9, 10, 10, 10, 10, 10, 10, 10,          /* 0X88 - 0X8F             */
    9, 10, 10, 10, 10, 10, 10, 10,          /* 0X90 - 0X97             */
   10, 10, 10, 10, 10, 10, 10, 10,          /* 0X98 - 0X9F             */
   10, 10, 10, 10, 10, 10, 10, 10,          /* 0XA0 - 0XA7             */
   10, 10, 10, 13, 10, 10, 10, 10,          /* 0XA8 - 0XAF             */
   10, 10, 11, 10, 10, 10, 10, 10,          /* 0XB0 - 0XB7             */
   10, 10, 10, 10, 10, 10, 10, 10,          /* 0XB8 - 0XBF             */
    9, 10, 10, 10, 10, 10,  9, 10,          /* 0XC0 - 0XC7             */
   10, 10, 10, 10,  9, 10, 10, 10,          /* 0XC8 - 0XCF             */
    9, 10, 10, 10, 10, 10, 10, 10,          /* 0XD0 - 0XD7             */
   10, 10, 10, 10, 10, 10, 10, 10,          /* 0XD8 - 0XDF             */
    9, 10, 10, 10, 10, 10, 10, 10,          /* 0XE0 - 0XE7             */
   10, 10, 10, 10, 10, 10,  9, 10,          /* 0XE8 - 0XEF             */
    8,  9,  9, 10,  9, 10, 10, 10,          /* 0XF0 - 0XF7             */
    9, 10, 10, 10,  9,  9,  8,  7,          /* 0XF8 - 0XFF             */
   13, 13,  7,  7, 10,  7,  7,  6,          /* 0X0100 - 0X0107         */
    6,  6,  6,  5,  6,  6,  6,  5,          /* 0X0108 - 0X010F         */
    6,  5,  6,  6,  6,  6,  6,  6,          /* 0X0110 - 0X0117         */
    6,  6,  6,  6,  6,  6,  6,  6,          /* 0X0118 - 0X011F         */
    8,  5,  6,  7,  7, 13                   /* 0X0120 - 0X0125         */
};

static const unsigned short int usrs_rdp60_encode_2[] = {
   0X0004, 0X0024, 0X0014, 0X0011, 0X0051, 0X0031, 0X0071, 0X0009,  /* 0X00 - 0X07 */
   0X0049, 0X0029, 0X0069, 0X0015, 0X0095, 0X0055, 0X00D5, 0X0035,  /* 0X08 - 0X0F */
   0X00B5, 0X0075, 0X001D, 0X00F5, 0X011D, 0X009D, 0X019D, 0X005D,  /* 0X10 - 0X17 */
   0X000D, 0X008D, 0X015D, 0X00DD, 0X01DD, 0X003D, 0X013D, 0X00BD,  /* 0X18 - 0X1F */
   0X004D, 0X01BD, 0X007D, 0X006B, 0X017D, 0X00FD, 0X01FD, 0X0003,  /* 0X20 - 0X27 */
   0X0103, 0X0083, 0X0183, 0X026B, 0X0043, 0X016B, 0X036B, 0X00EB,  /* 0X28 - 0X2F */
   0X0143, 0X00C3, 0X02EB, 0X01C3, 0X01EB, 0X0023, 0X03EB, 0X0123,  /* 0X30 - 0X37 */
   0X00A3, 0X01A3, 0X001B, 0X021B, 0X0063, 0X011B, 0X0163, 0X00E3,  /* 0X38 - 0X3F */
   0X00CD, 0X01E3, 0X0013, 0X0113, 0X0093, 0X031B, 0X009B, 0X029B,  /* 0X40 - 0X47 */
   0X0193, 0X0053, 0X019B, 0X039B, 0X005B, 0X025B, 0X015B, 0X035B,  /* 0X48 - 0X4F */
   0X0153, 0X00D3, 0X00DB, 0X02DB, 0X01DB, 0X03DB, 0X003B, 0X023B,  /* 0X50 - 0X57 */
   0X013B, 0X01D3, 0X033B, 0X00BB, 0X02BB, 0X01BB, 0X03BB, 0X007B,  /* 0X58 - 0X5F */
   0X002D, 0X027B, 0X017B, 0X037B, 0X00FB, 0X02FB, 0X01FB, 0X03FB,  /* 0X60 - 0X67 */
   0X0007, 0X0207, 0X0107, 0X0307, 0X0087, 0X0287, 0X0187, 0X0387,  /* 0X68 - 0X6F */
   0X0033, 0X0047, 0X0247, 0X0147, 0X0347, 0X00C7, 0X02C7, 0X01C7,  /* 0X70 - 0X77 */
   0X0133, 0X03C7, 0X0027, 0X0227, 0X0127, 0X0327, 0X00A7, 0X00B3,  /* 0X78 - 0X7F */
   0X0019, 0X01B3, 0X0073, 0X02A7, 0X0173, 0X01A7, 0X03A7, 0X0067,  /* 0X80 - 0X87 */
   0X00F3, 0X0267, 0X0167, 0X0367, 0X00E7, 0X02E7, 0X01E7, 0X03E7,  /* 0X88 - 0X8F */
   0X01F3, 0X0017, 0X0217, 0X0117, 0X0317, 0X0097, 0X0297, 0X0197,  /* 0X90 - 0X97 */
   0X0397, 0X0057, 0X0257, 0X0157, 0X0357, 0X00D7, 0X02D7, 0X01D7,  /* 0X98 - 0X9F */
   0X03D7, 0X0037, 0X0237, 0X0137, 0X0337, 0X00B7, 0X02B7, 0X01B7,  /* 0XA0 - 0XA7 */
   0X03B7, 0X0077, 0X0277, 0X07FF, 0X0177, 0X0377, 0X00F7, 0X02F7,  /* 0XA8 - 0XAF */
   0X01F7, 0X03F7, 0X03FF, 0X000F, 0X020F, 0X010F, 0X030F, 0X008F,  /* 0XB0 - 0XB7 */
   0X028F, 0X018F, 0X038F, 0X004F, 0X024F, 0X014F, 0X034F, 0X00CF,  /* 0XB8 - 0XBF */
   0X000B, 0X02CF, 0X01CF, 0X03CF, 0X002F, 0X022F, 0X010B, 0X012F,  /* 0XC0 - 0XC7 */
   0X032F, 0X00AF, 0X02AF, 0X01AF, 0X008B, 0X03AF, 0X006F, 0X026F,  /* 0XC8 - 0XCF */
   0X018B, 0X016F, 0X036F, 0X00EF, 0X02EF, 0X01EF, 0X03EF, 0X001F,  /* 0XD0 - 0XD7 */
   0X021F, 0X011F, 0X031F, 0X009F, 0X029F, 0X019F, 0X039F, 0X005F,  /* 0XD8 - 0XDF */
   0X004B, 0X025F, 0X015F, 0X035F, 0X00DF, 0X02DF, 0X01DF, 0X03DF,  /* 0XE0 - 0XE7 */
   0X003F, 0X023F, 0X013F, 0X033F, 0X00BF, 0X02BF, 0X014B, 0X01BF,  /* 0XE8 - 0XEF */
   0X00AD, 0X00CB, 0X01CB, 0X03BF, 0X002B, 0X007F, 0X027F, 0X017F,  /* 0XF0 - 0XF7 */
   0X012B, 0X037F, 0X00FF, 0X02FF, 0X00AB, 0X01AB, 0X006D, 0X0059,  /* 0XF8 - 0XFF */
   0X17FF, 0X0FFF, 0X0039, 0X0079, 0X01FF, 0X0005, 0X0045, 0X0034,  /* 0X0100 - 0X0107 */
   0X000C, 0X002C, 0X001C, 0X0000, 0X003C, 0X0002, 0X0022, 0X0010,  /* 0X0108 - 0X010F */
   0X0012, 0X0008, 0X0032, 0X000A, 0X002A, 0X001A, 0X003A, 0X0006,  /* 0X0110 - 0X0117 */
   0X0026, 0X0016, 0X0036, 0X000E, 0X002E, 0X001E, 0X003E, 0X0001,  /* 0X0118 - 0X011F */
   0X00ED, 0X0018, 0X0021, 0X0025, 0X0065, 0X1FFF                   /* 0X0120 - 0X0125 */
};

/**
   first step, 4 nibbles each 4 bits
   first nibble (most significant) : number of bits
   second nibble : type of processing
*/
static const unsigned short int usrs_rdp60_decode_1[ 1 << VAL_TAB_R60_D1_L ] = {
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA068,  /* 0X0000 - 0X0007 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B3,  /* 0X0008 - 0X000F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA091,  /* 0X0010 - 0X0017 */
   0X5300, 0X7080, 0X6229, 0XA03A, 0X6233, 0X9012, 0X622D, 0XA0D7,  /* 0X0018 - 0X001F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07A,  /* 0X0020 - 0X0027 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C4,  /* 0X0028 - 0X002F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A1,  /* 0X0030 - 0X0037 */
   0X5300, 0X7210, 0X6239, 0XA056, 0X6234, 0X901D, 0X623D, 0XA0E8,  /* 0X0038 - 0X003F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA071,  /* 0X0040 - 0X0047 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BB,  /* 0X0048 - 0X004F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA099,  /* 0X0050 - 0X0057 */
   0X5300, 0X70FF, 0X6229, 0XA04C, 0X6233, 0X9017, 0X622D, 0XA0DF,  /* 0X0058 - 0X005F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA087,  /* 0X0060 - 0X0067 */
   0X5227, 0X700A, 0X6238, 0XA023, 0X6223, 0X80FE, 0X623C, 0XA0CE,  /* 0X0068 - 0X006F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0A9,  /* 0X0070 - 0X0077 */
   0X5300, 0X7220, 0X6239, 0XA05F, 0X6234, 0X9022, 0X623D, 0XA0F5,  /* 0X0078 - 0X007F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06C,  /* 0X0080 - 0X0087 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B7,  /* 0X0088 - 0X008F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA095,  /* 0X0090 - 0X0097 */
   0X5300, 0X7080, 0X6229, 0XA046, 0X6233, 0X9015, 0X622D, 0XA0DB,  /* 0X0098 - 0X009F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA07E,  /* 0X00A0 - 0X00A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0C9,  /* 0X00A8 - 0X00AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A5,  /* 0X00B0 - 0X00B7 */
   0X5300, 0X7210, 0X6239, 0XA05B, 0X6234, 0X901F, 0X623D, 0XA0EC,  /* 0X00B8 - 0X00BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA075,  /* 0X00C0 - 0X00C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0BF,  /* 0X00C8 - 0X00CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09D,  /* 0X00D0 - 0X00D7 */
   0X5300, 0X70FF, 0X6229, 0XA052, 0X6233, 0X901B, 0X622D, 0XA0E4,  /* 0X00D8 - 0X00DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08C,  /* 0X00E0 - 0X00E7 */
   0X5227, 0X700A, 0X6238, 0XA02F, 0X6223, 0X823E, 0X623C, 0XA0D3,  /* 0X00E8 - 0X00EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AE,  /* 0X00F0 - 0X00F7 */
   0X5300, 0X7220, 0X6239, 0XA064, 0X6234, 0X9025, 0X623D, 0XA0FA,  /* 0X00F8 - 0X00FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06A,  /* 0X0100 - 0X0107 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B5,  /* 0X0108 - 0X010F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA093,  /* 0X0110 - 0X0117 */
   0X5300, 0X7080, 0X6229, 0XA03D, 0X6233, 0X9014, 0X622D, 0XA0D9,  /* 0X0118 - 0X011F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07C,  /* 0X0120 - 0X0127 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C7,  /* 0X0128 - 0X012F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A3,  /* 0X0130 - 0X0137 */
   0X5300, 0X7210, 0X6239, 0XA058, 0X6234, 0X901E, 0X623D, 0XA0EA,  /* 0X0138 - 0X013F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA073,  /* 0X0140 - 0X0147 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BD,  /* 0X0148 - 0X014F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09B,  /* 0X0150 - 0X0157 */
   0X5300, 0X70FF, 0X6229, 0XA04E, 0X6233, 0X901A, 0X622D, 0XA0E2,  /* 0X0158 - 0X015F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08A,  /* 0X0160 - 0X0167 */
   0X5227, 0X700A, 0X6238, 0XA02D, 0X6223, 0X80FE, 0X623C, 0XA0D1,  /* 0X0168 - 0X016F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AC,  /* 0X0170 - 0X0177 */
   0X5300, 0X7220, 0X6239, 0XA062, 0X6234, 0X9024, 0X623D, 0XA0F7,  /* 0X0178 - 0X017F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06E,  /* 0X0180 - 0X0187 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0B9,  /* 0X0188 - 0X018F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA097,  /* 0X0190 - 0X0197 */
   0X5300, 0X7080, 0X6229, 0XA04A, 0X6233, 0X9016, 0X622D, 0XA0DD,  /* 0X0198 - 0X019F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA085,  /* 0X01A0 - 0X01A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CB,  /* 0X01A8 - 0X01AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A7,  /* 0X01B0 - 0X01B7 */
   0X5300, 0X7210, 0X6239, 0XA05D, 0X6234, 0X9021, 0X623D, 0XA0EF,  /* 0X01B8 - 0X01BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA077,  /* 0X01C0 - 0X01C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C2,  /* 0X01C8 - 0X01CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA09F,  /* 0X01D0 - 0X01D7 */
   0X5300, 0X70FF, 0X6229, 0XA054, 0X6233, 0X901C, 0X622D, 0XA0E6,  /* 0X01D8 - 0X01DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08E,  /* 0X01E0 - 0X01E7 */
   0X5227, 0X700A, 0X6238, 0XA034, 0X6223, 0X823E, 0X623C, 0XA0D5,  /* 0X01E8 - 0X01EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B0,  /* 0X01F0 - 0X01F7 */
   0X5300, 0X7220, 0X6239, 0XA066, 0X6234, 0X9026, 0X623D, 0XA230,  /* 0X01F8 - 0X01FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA069,  /* 0X0200 - 0X0207 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B4,  /* 0X0208 - 0X020F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA092,  /* 0X0210 - 0X0217 */
   0X5300, 0X7080, 0X6229, 0XA03B, 0X6233, 0X9012, 0X622D, 0XA0D8,  /* 0X0218 - 0X021F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07B,  /* 0X0220 - 0X0227 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C5,  /* 0X0228 - 0X022F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A2,  /* 0X0230 - 0X0237 */
   0X5300, 0X7210, 0X6239, 0XA057, 0X6234, 0X901D, 0X623D, 0XA0E9,  /* 0X0238 - 0X023F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA072,  /* 0X0240 - 0X0247 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BC,  /* 0X0248 - 0X024F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA09A,  /* 0X0250 - 0X0257 */
   0X5300, 0X70FF, 0X6229, 0XA04D, 0X6233, 0X9017, 0X622D, 0XA0E1,  /* 0X0258 - 0X025F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA089,  /* 0X0260 - 0X0267 */
   0X5227, 0X700A, 0X6238, 0XA02B, 0X6223, 0X80FE, 0X623C, 0XA0CF,  /* 0X0268 - 0X026F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0AA,  /* 0X0270 - 0X0277 */
   0X5300, 0X7220, 0X6239, 0XA061, 0X6234, 0X9022, 0X623D, 0XA0F6,  /* 0X0278 - 0X027F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06D,  /* 0X0280 - 0X0287 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B8,  /* 0X0288 - 0X028F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA096,  /* 0X0290 - 0X0297 */
   0X5300, 0X7080, 0X6229, 0XA047, 0X6233, 0X9015, 0X622D, 0XA0DC,  /* 0X0298 - 0X029F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA083,  /* 0X02A0 - 0X02A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0CA,  /* 0X02A8 - 0X02AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A6,  /* 0X02B0 - 0X02B7 */
   0X5300, 0X7210, 0X6239, 0XA05C, 0X6234, 0X901F, 0X623D, 0XA0ED,  /* 0X02B8 - 0X02BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA076,  /* 0X02C0 - 0X02C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0C1,  /* 0X02C8 - 0X02CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09E,  /* 0X02D0 - 0X02D7 */
   0X5300, 0X70FF, 0X6229, 0XA053, 0X6233, 0X901B, 0X622D, 0XA0E5,  /* 0X02D8 - 0X02DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08D,  /* 0X02E0 - 0X02E7 */
   0X5227, 0X700A, 0X6238, 0XA032, 0X6223, 0X823E, 0X623C, 0XA0D4,  /* 0X02E8 - 0X02EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AF,  /* 0X02F0 - 0X02F7 */
   0X5300, 0X7220, 0X6239, 0XA065, 0X6234, 0X9025, 0X623D, 0XA0FB,  /* 0X02F8 - 0X02FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06B,  /* 0X0300 - 0X0307 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B6,  /* 0X0308 - 0X030F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA094,  /* 0X0310 - 0X0317 */
   0X5300, 0X7080, 0X6229, 0XA045, 0X6233, 0X9014, 0X622D, 0XA0DA,  /* 0X0318 - 0X031F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07D,  /* 0X0320 - 0X0327 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C8,  /* 0X0328 - 0X032F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A4,  /* 0X0330 - 0X0337 */
   0X5300, 0X7210, 0X6239, 0XA05A, 0X6234, 0X901E, 0X623D, 0XA0EB,  /* 0X0338 - 0X033F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA074,  /* 0X0340 - 0X0347 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BE,  /* 0X0348 - 0X034F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09C,  /* 0X0350 - 0X0357 */
   0X5300, 0X70FF, 0X6229, 0XA04F, 0X6233, 0X901A, 0X622D, 0XA0E3,  /* 0X0358 - 0X035F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08B,  /* 0X0360 - 0X0367 */
   0X5227, 0X700A, 0X6238, 0XA02E, 0X6223, 0X80FE, 0X623C, 0XA0D2,  /* 0X0368 - 0X036F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AD,  /* 0X0370 - 0X0377 */
   0X5300, 0X7220, 0X6239, 0XA063, 0X6234, 0X9024, 0X623D, 0XA0F9,  /* 0X0378 - 0X037F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06F,  /* 0X0380 - 0X0387 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0BA,  /* 0X0388 - 0X038F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA098,  /* 0X0390 - 0X0397 */
   0X5300, 0X7080, 0X6229, 0XA04B, 0X6233, 0X9016, 0X622D, 0XA0DE,  /* 0X0398 - 0X039F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA086,  /* 0X03A0 - 0X03A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CD,  /* 0X03A8 - 0X03AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A8,  /* 0X03B0 - 0X03B7 */
   0X5300, 0X7210, 0X6239, 0XA05E, 0X6234, 0X9021, 0X623D, 0XA0F3,  /* 0X03B8 - 0X03BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA079,  /* 0X03C0 - 0X03C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C3,  /* 0X03C8 - 0X03CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA0A0,  /* 0X03D0 - 0X03D7 */
   0X5300, 0X70FF, 0X6229, 0XA055, 0X6233, 0X901C, 0X622D, 0XA0E7,  /* 0X03D8 - 0X03DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08F,  /* 0X03E0 - 0X03E7 */
   0X5227, 0X700A, 0X6238, 0XA036, 0X6223, 0X823E, 0X623C, 0XA0D6,  /* 0X03E8 - 0X03EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B1,  /* 0X03F0 - 0X03F7 */
   0X5300, 0X7220, 0X6239, 0XA067, 0X6234, 0X9026, 0X623D, 0XB0B2,  /* 0X03F8 - 0X03FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA068,  /* 0X0400 - 0X0407 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B3,  /* 0X0408 - 0X040F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA091,  /* 0X0410 - 0X0417 */
   0X5300, 0X7080, 0X6229, 0XA03A, 0X6233, 0X9012, 0X622D, 0XA0D7,  /* 0X0418 - 0X041F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07A,  /* 0X0420 - 0X0427 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C4,  /* 0X0428 - 0X042F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A1,  /* 0X0430 - 0X0437 */
   0X5300, 0X7210, 0X6239, 0XA056, 0X6234, 0X901D, 0X623D, 0XA0E8,  /* 0X0428 - 0X042F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA071,  /* 0X0440 - 0X0447 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BB,  /* 0X0448 - 0X044F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA099,  /* 0X0450 - 0X0457 */
   0X5300, 0X70FF, 0X6229, 0XA04C, 0X6233, 0X9017, 0X622D, 0XA0DF,  /* 0X0458 - 0X045F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA087,  /* 0X0460 - 0X0467 */
   0X5227, 0X700A, 0X6238, 0XA023, 0X6223, 0X80FE, 0X623C, 0XA0CE,  /* 0X0468 - 0X046F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0A9,  /* 0X0470 - 0X0477 */
   0X5300, 0X7220, 0X6239, 0XA05F, 0X6234, 0X9022, 0X623D, 0XA0F5,  /* 0X0478 - 0X047F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06C,  /* 0X0480 - 0X0487 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B7,  /* 0X0488 - 0X048F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA095,  /* 0X0490 - 0X0497 */
   0X5300, 0X7080, 0X6229, 0XA046, 0X6233, 0X9015, 0X622D, 0XA0DB,  /* 0X0498 - 0X049F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA07E,  /* 0X04A0 - 0X04A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0C9,  /* 0X04A8 - 0X04AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A5,  /* 0X04B0 - 0X04B7 */
   0X5300, 0X7210, 0X6239, 0XA05B, 0X6234, 0X901F, 0X623D, 0XA0EC,  /* 0X04B8 - 0X04BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA075,  /* 0X04C0 - 0X04C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0BF,  /* 0X04C8 - 0X04CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09D,  /* 0X04D0 - 0X04D7 */
   0X5300, 0X70FF, 0X6229, 0XA052, 0X6233, 0X901B, 0X622D, 0XA0E4,  /* 0X04D8 - 0X04DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08C,  /* 0X04E0 - 0X04E7 */
   0X5227, 0X700A, 0X6238, 0XA02F, 0X6223, 0X823E, 0X623C, 0XA0D3,  /* 0X04E8 - 0X04EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AE,  /* 0X04F0 - 0X04F7 */
   0X5300, 0X7220, 0X6239, 0XA064, 0X6234, 0X9025, 0X623D, 0XA0FA,  /* 0X04F8 - 0X04FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06A,  /* 0X0500 - 0X0507 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B5,  /* 0X0508 - 0X050F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA093,  /* 0X0510 - 0X0517 */
   0X5300, 0X7080, 0X6229, 0XA03D, 0X6233, 0X9014, 0X622D, 0XA0D9,  /* 0X0518 - 0X051F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07C,  /* 0X0520 - 0X0527 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C7,  /* 0X0528 - 0X052F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A3,  /* 0X0530 - 0X0537 */
   0X5300, 0X7210, 0X6239, 0XA058, 0X6234, 0X901E, 0X623D, 0XA0EA,  /* 0X0538 - 0X053F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA073,  /* 0X0540 - 0X0547 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BD,  /* 0X0548 - 0X054F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09B,  /* 0X0550 - 0X0557 */
   0X5300, 0X70FF, 0X6229, 0XA04E, 0X6233, 0X901A, 0X622D, 0XA0E2,  /* 0X0558 - 0X055F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08A,  /* 0X0560 - 0X0567 */
   0X5227, 0X700A, 0X6238, 0XA02D, 0X6223, 0X80FE, 0X623C, 0XA0D1,  /* 0X0568 - 0X056F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AC,  /* 0X0570 - 0X0577 */
   0X5300, 0X7220, 0X6239, 0XA062, 0X6234, 0X9024, 0X623D, 0XA0F7,  /* 0X0578 - 0X057F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06E,  /* 0X0580 - 0X0587 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0B9,  /* 0X0588 - 0X058F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA097,  /* 0X0590 - 0X0597 */
   0X5300, 0X7080, 0X6229, 0XA04A, 0X6233, 0X9016, 0X622D, 0XA0DD,  /* 0X0598 - 0X059F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA085,  /* 0X05A0 - 0X05A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CB,  /* 0X05A8 - 0X05AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A7,  /* 0X05B0 - 0X05B7 */
   0X5300, 0X7210, 0X6239, 0XA05D, 0X6234, 0X9021, 0X623D, 0XA0EF,  /* 0X05B8 - 0X05BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA077,  /* 0X05C0 - 0X05C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C2,  /* 0X05C8 - 0X05CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA09F,  /* 0X05D0 - 0X05D7 */
   0X5300, 0X70FF, 0X6229, 0XA054, 0X6233, 0X901C, 0X622D, 0XA0E6,  /* 0X05D8 - 0X05DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08E,  /* 0X05E0 - 0X05E7 */
   0X5227, 0X700A, 0X6238, 0XA034, 0X6223, 0X823E, 0X623C, 0XA0D5,  /* 0X05E8 - 0X05EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B0,  /* 0X05F0 - 0X05F7 */
   0X5300, 0X7220, 0X6239, 0XA066, 0X6234, 0X9026, 0X623D, 0XA230,  /* 0X05F8 - 0X05FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA069,  /* 0X0600 - 0X0607 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B4,  /* 0X0608 - 0X060F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA092,  /* 0X0610 - 0X0617 */
   0X5300, 0X7080, 0X6229, 0XA03B, 0X6233, 0X9012, 0X622D, 0XA0D8,  /* 0X0618 - 0X061F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07B,  /* 0X0620 - 0X0627 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C5,  /* 0X0628 - 0X062F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A2,  /* 0X0630 - 0X0637 */
   0X5300, 0X7210, 0X6239, 0XA057, 0X6234, 0X901D, 0X623D, 0XA0E9,  /* 0X0638 - 0X063F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA072,  /* 0X0640 - 0X0647 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BC,  /* 0X0648 - 0X064F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA09A,  /* 0X0650 - 0X0657 */
   0X5300, 0X70FF, 0X6229, 0XA04D, 0X6233, 0X9017, 0X622D, 0XA0E1,  /* 0X0658 - 0X065F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA089,  /* 0X0660 - 0X0667 */
   0X5227, 0X700A, 0X6238, 0XA02B, 0X6223, 0X80FE, 0X623C, 0XA0CF,  /* 0X0668 - 0X066F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0AA,  /* 0X0670 - 0X0677 */
   0X5300, 0X7220, 0X6239, 0XA061, 0X6234, 0X9022, 0X623D, 0XA0F6,  /* 0X0678 - 0X067F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06D,  /* 0X0680 - 0X0687 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B8,  /* 0X0688 - 0X068F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA096,  /* 0X0690 - 0X0697 */
   0X5300, 0X7080, 0X6229, 0XA047, 0X6233, 0X9015, 0X622D, 0XA0DC,  /* 0X0698 - 0X069F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA083,  /* 0X06A0 - 0X06A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0CA,  /* 0X06A8 - 0X06AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A6,  /* 0X06B0 - 0X06B7 */
   0X5300, 0X7210, 0X6239, 0XA05C, 0X6234, 0X901F, 0X623D, 0XA0ED,  /* 0X06B8 - 0X06BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA076,  /* 0X06C0 - 0X06C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0C1,  /* 0X06C8 - 0X06CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09E,  /* 0X06D0 - 0X06D7 */
   0X5300, 0X70FF, 0X6229, 0XA053, 0X6233, 0X901B, 0X622D, 0XA0E5,  /* 0X06D8 - 0X06DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08D,  /* 0X06E0 - 0X06E7 */
   0X5227, 0X700A, 0X6238, 0XA032, 0X6223, 0X823E, 0X623C, 0XA0D4,  /* 0X06E8 - 0X06EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AF,  /* 0X06F0 - 0X06F7 */
   0X5300, 0X7220, 0X6239, 0XA065, 0X6234, 0X9025, 0X623D, 0XA0FB,  /* 0X06F8 - 0X06FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06B,  /* 0X0700 - 0X0707 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B6,  /* 0X0708 - 0X070F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA094,  /* 0X0710 - 0X0717 */
   0X5300, 0X7080, 0X6229, 0XA045, 0X6233, 0X9014, 0X622D, 0XA0DA,  /* 0X0718 - 0X071F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07D,  /* 0X0720 - 0X0727 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C8,  /* 0X0728 - 0X072F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A4,  /* 0X0730 - 0X0737 */
   0X5300, 0X7210, 0X6239, 0XA05A, 0X6234, 0X901E, 0X623D, 0XA0EB,  /* 0X0738 - 0X073F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA074,  /* 0X0740 - 0X0747 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BE,  /* 0X0748 - 0X074F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09C,  /* 0X0750 - 0X0757 */
   0X5300, 0X70FF, 0X6229, 0XA04F, 0X6233, 0X901A, 0X622D, 0XA0E3,  /* 0X0758 - 0X075F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08B,  /* 0X0760 - 0X0767 */
   0X5227, 0X700A, 0X6238, 0XA02E, 0X6223, 0X80FE, 0X623C, 0XA0D2,  /* 0X0768 - 0X076F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AD,  /* 0X0770 - 0X0777 */
   0X5300, 0X7220, 0X6239, 0XA063, 0X6234, 0X9024, 0X623D, 0XA0F9,  /* 0X0778 - 0X077F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06F,  /* 0X0780 - 0X0787 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0BA,  /* 0X0788 - 0X078F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA098,  /* 0X0790 - 0X0797 */
   0X5300, 0X7080, 0X6229, 0XA04B, 0X6233, 0X9016, 0X622D, 0XA0DE,  /* 0X0798 - 0X079F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA086,  /* 0X07A0 - 0X07A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CD,  /* 0X07A8 - 0X07AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A8,  /* 0X07B0 - 0X07B7 */
   0X5300, 0X7210, 0X6239, 0XA05E, 0X6234, 0X9021, 0X623D, 0XA0F3,  /* 0X07B8 - 0X07BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA079,  /* 0X07C0 - 0X07C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C3,  /* 0X07C8 - 0X07CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA0A0,  /* 0X07D0 - 0X07D7 */
   0X5300, 0X70FF, 0X6229, 0XA055, 0X6233, 0X901C, 0X622D, 0XA0E7,  /* 0X07D8 - 0X07DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08F,  /* 0X07E0 - 0X07E7 */
   0X5227, 0X700A, 0X6238, 0XA036, 0X6223, 0X823E, 0X623C, 0XA0D6,  /* 0X07E8 - 0X07EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B1,  /* 0X07F0 - 0X07F7 */
   0X5300, 0X7220, 0X6239, 0XA067, 0X6234, 0X9026, 0X623D, 0XD0AB,  /* 0X07F8 - 0X07FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA068,  /* 0X0800 - 0X0807 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B3,  /* 0X0808 - 0X080F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA091,  /* 0X0810 - 0X0817 */
   0X5300, 0X7080, 0X6229, 0XA03A, 0X6233, 0X9012, 0X622D, 0XA0D7,  /* 0X0818 - 0X081F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07A,  /* 0X0820 - 0X0827 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C4,  /* 0X0828 - 0X082F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A1,  /* 0X0830 - 0X0837 */
   0X5300, 0X7210, 0X6239, 0XA056, 0X6234, 0X901D, 0X623D, 0XA0E8,  /* 0X0838 - 0X083F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA071,  /* 0X0840 - 0X0847 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BB,  /* 0X0848 - 0X084F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA099,  /* 0X0850 - 0X0857 */
   0X5300, 0X70FF, 0X6229, 0XA04C, 0X6233, 0X9017, 0X622D, 0XA0DF,  /* 0X0858 - 0X085F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA087,  /* 0X0860 - 0X0867 */
   0X5227, 0X700A, 0X6238, 0XA023, 0X6223, 0X80FE, 0X623C, 0XA0CE,  /* 0X0868 - 0X086F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0A9,  /* 0X0870 - 0X0877 */
   0X5300, 0X7220, 0X6239, 0XA05F, 0X6234, 0X9022, 0X623D, 0XA0F5,  /* 0X0878 - 0X087F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06C,  /* 0X0880 - 0X0887 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B7,  /* 0X0888 - 0X088F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA095,  /* 0X0890 - 0X0897 */
   0X5300, 0X7080, 0X6229, 0XA046, 0X6233, 0X9015, 0X622D, 0XA0DB,  /* 0X0898 - 0X089F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA07E,  /* 0X08A0 - 0X08A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0C9,  /* 0X08A8 - 0X08AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A5,  /* 0X08B0 - 0X08B7 */
   0X5300, 0X7210, 0X6239, 0XA05B, 0X6234, 0X901F, 0X623D, 0XA0EC,  /* 0X08B8 - 0X08BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA075,  /* 0X08C0 - 0X08C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0BF,  /* 0X08C8 - 0X08CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09D,  /* 0X08D0 - 0X08D7 */
   0X5300, 0X70FF, 0X6229, 0XA052, 0X6233, 0X901B, 0X622D, 0XA0E4,  /* 0X08D8 - 0X08DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08C,  /* 0X08E0 - 0X08E7 */
   0X5227, 0X700A, 0X6238, 0XA02F, 0X6223, 0X823E, 0X623C, 0XA0D3,  /* 0X08E8 - 0X08EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AE,  /* 0X08F0 - 0X08F7 */
   0X5300, 0X7220, 0X6239, 0XA064, 0X6234, 0X9025, 0X623D, 0XA0FA,  /* 0X08F8 - 0X08FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06A,  /* 0X0900 - 0X0907 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B5,  /* 0X0908 - 0X090F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA093,  /* 0X0910 - 0X0917 */
   0X5300, 0X7080, 0X6229, 0XA03D, 0X6233, 0X9014, 0X622D, 0XA0D9,  /* 0X0918 - 0X091F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07C,  /* 0X0920 - 0X0927 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C7,  /* 0X0928 - 0X092F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A3,  /* 0X0930 - 0X0937 */
   0X5300, 0X7210, 0X6239, 0XA058, 0X6234, 0X901E, 0X623D, 0XA0EA,  /* 0X0938 - 0X093F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA073,  /* 0X0940 - 0X0947 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BD,  /* 0X0948 - 0X094F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09B,  /* 0X0950 - 0X0957 */
   0X5300, 0X70FF, 0X6229, 0XA04E, 0X6233, 0X901A, 0X622D, 0XA0E2,  /* 0X0958 - 0X095F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08A,  /* 0X0960 - 0X0967 */
   0X5227, 0X700A, 0X6238, 0XA02D, 0X6223, 0X80FE, 0X623C, 0XA0D1,  /* 0X0968 - 0X096F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AC,  /* 0X0970 - 0X0977 */
   0X5300, 0X7220, 0X6239, 0XA062, 0X6234, 0X9024, 0X623D, 0XA0F7,  /* 0X0978 - 0X097F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06E,  /* 0X0980 - 0X0987 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0B9,  /* 0X0988 - 0X098F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA097,  /* 0X0990 - 0X0997 */
   0X5300, 0X7080, 0X6229, 0XA04A, 0X6233, 0X9016, 0X622D, 0XA0DD,  /* 0X0998 - 0X099F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA085,  /* 0X09A0 - 0X09A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CB,  /* 0X09A8 - 0X09AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A7,  /* 0X09B0 - 0X09B7 */
   0X5300, 0X7210, 0X6239, 0XA05D, 0X6234, 0X9021, 0X623D, 0XA0EF,  /* 0X09B8 - 0X09BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA077,  /* 0X09C0 - 0X09C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C2,  /* 0X09C8 - 0X09CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA09F,  /* 0X09D0 - 0X09D7 */
   0X5300, 0X70FF, 0X6229, 0XA054, 0X6233, 0X901C, 0X622D, 0XA0E6,  /* 0X09D8 - 0X09DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08E,  /* 0X09E0 - 0X09E7 */
   0X5227, 0X700A, 0X6238, 0XA034, 0X6223, 0X823E, 0X623C, 0XA0D5,  /* 0X09E8 - 0X09EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B0,  /* 0X09F0 - 0X09F7 */
   0X5300, 0X7220, 0X6239, 0XA066, 0X6234, 0X9026, 0X623D, 0XA230,  /* 0X09F8 - 0X09FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA069,  /* 0X0A00 - 0X0A07 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B4,  /* 0X0A08 - 0X0A0F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA092,  /* 0X0A10 - 0X0A17 */
   0X5300, 0X7080, 0X6229, 0XA03B, 0X6233, 0X9012, 0X622D, 0XA0D8,  /* 0X0A18 - 0X0A1F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07B,  /* 0X0A20 - 0X0A27 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C5,  /* 0X0A28 - 0X0A2F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A2,  /* 0X0A30 - 0X0A37 */
   0X5300, 0X7210, 0X6239, 0XA057, 0X6234, 0X901D, 0X623D, 0XA0E9,  /* 0X0A38 - 0X0A3F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA072,  /* 0X0A40 - 0X0A47 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BC,  /* 0X0A48 - 0X0A4F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA09A,  /* 0X0A50 - 0X0A57 */
   0X5300, 0X70FF, 0X6229, 0XA04D, 0X6233, 0X9017, 0X622D, 0XA0E1,  /* 0X0A58 - 0X0A5F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA089,  /* 0X0A60 - 0X0A67 */
   0X5227, 0X700A, 0X6238, 0XA02B, 0X6223, 0X80FE, 0X623C, 0XA0CF,  /* 0X0A68 - 0X0A6F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0AA,  /* 0X0A70 - 0X0A77 */
   0X5300, 0X7220, 0X6239, 0XA061, 0X6234, 0X9022, 0X623D, 0XA0F6,  /* 0X0A78 - 0X0A7F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06D,  /* 0X0A80 - 0X0A87 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B8,  /* 0X0A88 - 0X0A8F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA096,  /* 0X0A90 - 0X0A97 */
   0X5300, 0X7080, 0X6229, 0XA047, 0X6233, 0X9015, 0X622D, 0XA0DC,  /* 0X0A98 - 0X0A9F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA083,  /* 0X0AA0 - 0X0AA7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0CA,  /* 0X0AA8 - 0X0AAF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A6,  /* 0X0AB0 - 0X0AB7 */
   0X5300, 0X7210, 0X6239, 0XA05C, 0X6234, 0X901F, 0X623D, 0XA0ED,  /* 0X0AB8 - 0X0ABF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA076,  /* 0X0AC0 - 0X0AC7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0C1,  /* 0X0AC8 - 0X0ACF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09E,  /* 0X0AD0 - 0X0AD7 */
   0X5300, 0X70FF, 0X6229, 0XA053, 0X6233, 0X901B, 0X622D, 0XA0E5,  /* 0X0AD8 - 0X0ADF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08D,  /* 0X0AE0 - 0X0AE7 */
   0X5227, 0X700A, 0X6238, 0XA032, 0X6223, 0X823E, 0X623C, 0XA0D4,  /* 0X0AE8 - 0X0AEF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AF,  /* 0X0AF0 - 0X0AF7 */
   0X5300, 0X7220, 0X6239, 0XA065, 0X6234, 0X9025, 0X623D, 0XA0FB,  /* 0X0AF8 - 0X0AFF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06B,  /* 0X0B00 - 0X0B07 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B6,  /* 0X0B08 - 0X0B0F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA094,  /* 0X0B10 - 0X0B17 */
   0X5300, 0X7080, 0X6229, 0XA045, 0X6233, 0X9014, 0X622D, 0XA0DA,  /* 0X0B18 - 0X0B1F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07D,  /* 0X0B20 - 0X0B27 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C8,  /* 0X0B28 - 0X0B2F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A4,  /* 0X0B30 - 0X0B37 */
   0X5300, 0X7210, 0X6239, 0XA05A, 0X6234, 0X901E, 0X623D, 0XA0EB,  /* 0X0B38 - 0X0B3F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA074,  /* 0X0B40 - 0X0B47 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BE,  /* 0X0B48 - 0X0B4F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09C,  /* 0X0B50 - 0X0B57 */
   0X5300, 0X70FF, 0X6229, 0XA04F, 0X6233, 0X901A, 0X622D, 0XA0E3,  /* 0X0B58 - 0X0B5F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08B,  /* 0X0B60 - 0X0B67 */
   0X5227, 0X700A, 0X6238, 0XA02E, 0X6223, 0X80FE, 0X623C, 0XA0D2,  /* 0X0B68 - 0X0B6F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AD,  /* 0X0B70 - 0X0B77 */
   0X5300, 0X7220, 0X6239, 0XA063, 0X6234, 0X9024, 0X623D, 0XA0F9,  /* 0X0B78 - 0X0B7F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06F,  /* 0X0B80 - 0X0B87 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0BA,  /* 0X0B88 - 0X0B8F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA098,  /* 0X0B90 - 0X0B97 */
   0X5300, 0X7080, 0X6229, 0XA04B, 0X6233, 0X9016, 0X622D, 0XA0DE,  /* 0X0B98 - 0X0B9F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA086,  /* 0X0BA0 - 0X0BA7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CD,  /* 0X0BA8 - 0X0BAF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A8,  /* 0X0BB0 - 0X0BB7 */
   0X5300, 0X7210, 0X6239, 0XA05E, 0X6234, 0X9021, 0X623D, 0XA0F3,  /* 0X0BB8 - 0X0BBF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA079,  /* 0X0BC0 - 0X0BC7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C3,  /* 0X0BC8 - 0X0BCF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA0A0,  /* 0X0BD0 - 0X0BD7 */
   0X5300, 0X70FF, 0X6229, 0XA055, 0X6233, 0X901C, 0X622D, 0XA0E7,  /* 0X0BD8 - 0X0BDF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08F,  /* 0X0BE0 - 0X0BE7 */
   0X5227, 0X700A, 0X6238, 0XA036, 0X6223, 0X823E, 0X623C, 0XA0D6,  /* 0X0BE8 - 0X0BEF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B1,  /* 0X0BF0 - 0X0BF7 */
   0X5300, 0X7220, 0X6239, 0XA067, 0X6234, 0X9026, 0X623D, 0XB0B2,  /* 0X0BF8 - 0X0BFF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA068,  /* 0X0C00 - 0X0C07 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B3,  /* 0X0C08 - 0X0C0F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA091,  /* 0X0C10 - 0X0C17 */
   0X5300, 0X7080, 0X6229, 0XA03A, 0X6233, 0X9012, 0X622D, 0XA0D7,  /* 0X0C18 - 0X0C1F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07A,  /* 0X0C20 - 0X0C27 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C4,  /* 0X0C28 - 0X0C2F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A1,  /* 0X0C30 - 0X0C37 */
   0X5300, 0X7210, 0X6239, 0XA056, 0X6234, 0X901D, 0X623D, 0XA0E8,  /* 0X0C38 - 0X0C3F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA071,  /* 0X0C40 - 0X0C47 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BB,  /* 0X0C48 - 0X0C4F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA099,  /* 0X0C50 - 0X0C57 */
   0X5300, 0X70FF, 0X6229, 0XA04C, 0X6233, 0X9017, 0X622D, 0XA0DF,  /* 0X0C58 - 0X0C5F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA087,  /* 0X0C60 - 0X0C67 */
   0X5227, 0X700A, 0X6238, 0XA023, 0X6223, 0X80FE, 0X623C, 0XA0CE,  /* 0X0C68 - 0X0C6F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0A9,  /* 0X0C70 - 0X0C77 */
   0X5300, 0X7220, 0X6239, 0XA05F, 0X6234, 0X9022, 0X623D, 0XA0F5,  /* 0X0C78 - 0X0C7F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06C,  /* 0X0C80 - 0X0C87 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B7,  /* 0X0C88 - 0X0C8F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA095,  /* 0X0C90 - 0X0C97 */
   0X5300, 0X7080, 0X6229, 0XA046, 0X6233, 0X9015, 0X622D, 0XA0DB,  /* 0X0C98 - 0X0C9F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA07E,  /* 0X0CA0 - 0X0CA7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0C9,  /* 0X0CA8 - 0X0CAF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A5,  /* 0X0CB0 - 0X0CB7 */
   0X5300, 0X7210, 0X6239, 0XA05B, 0X6234, 0X901F, 0X623D, 0XA0EC,  /* 0X0CB8 - 0X0CBF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA075,  /* 0X0CC0 - 0X0CC7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0BF,  /* 0X0CC8 - 0X0CCF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09D,  /* 0X0CD0 - 0X0CD7 */
   0X5300, 0X70FF, 0X6229, 0XA052, 0X6233, 0X901B, 0X622D, 0XA0E4,  /* 0X0CD8 - 0X0CDF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08C,  /* 0X0CE0 - 0X0CE7 */
   0X5227, 0X700A, 0X6238, 0XA02F, 0X6223, 0X823E, 0X623C, 0XA0D3,  /* 0X0CE8 - 0X0CEF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AE,  /* 0X0CF0 - 0X0CF7 */
   0X5300, 0X7220, 0X6239, 0XA064, 0X6234, 0X9025, 0X623D, 0XA0FA,  /* 0X0CF8 - 0X0CFF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06A,  /* 0X0D00 - 0X0D07 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B5,  /* 0X0D08 - 0X0D0F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA093,  /* 0X0D10 - 0X0D17 */
   0X5300, 0X7080, 0X6229, 0XA03D, 0X6233, 0X9014, 0X622D, 0XA0D9,  /* 0X0D18 - 0X0D1F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07C,  /* 0X0D20 - 0X0D27 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C7,  /* 0X0D28 - 0X0D2F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A3,  /* 0X0D30 - 0X0D37 */
   0X5300, 0X7210, 0X6239, 0XA058, 0X6234, 0X901E, 0X623D, 0XA0EA,  /* 0X0D38 - 0X0D3F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA073,  /* 0X0D40 - 0X0D47 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BD,  /* 0X0D48 - 0X0D4F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09B,  /* 0X0D50 - 0X0D57 */
   0X5300, 0X70FF, 0X6229, 0XA04E, 0X6233, 0X901A, 0X622D, 0XA0E2,  /* 0X0D58 - 0X0D5F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08A,  /* 0X0D60 - 0X0D67 */
   0X5227, 0X700A, 0X6238, 0XA02D, 0X6223, 0X80FE, 0X623C, 0XA0D1,  /* 0X0D68 - 0X0D6F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AC,  /* 0X0D70 - 0X0D77 */
   0X5300, 0X7220, 0X6239, 0XA062, 0X6234, 0X9024, 0X623D, 0XA0F7,  /* 0X0D78 - 0X0D7F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06E,  /* 0X0D80 - 0X0D87 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0B9,  /* 0X0D88 - 0X0D8F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA097,  /* 0X0D90 - 0X0D97 */
   0X5300, 0X7080, 0X6229, 0XA04A, 0X6233, 0X9016, 0X622D, 0XA0DD,  /* 0X0D98 - 0X0D9F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA085,  /* 0X0DA0 - 0X0DA7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CB,  /* 0X0DA8 - 0X0DAF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A7,  /* 0X0DB0 - 0X0DB7 */
   0X5300, 0X7210, 0X6239, 0XA05D, 0X6234, 0X9021, 0X623D, 0XA0EF,  /* 0X0DB8 - 0X0DBF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA077,  /* 0X0DC0 - 0X0DC7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C2,  /* 0X0DC8 - 0X0DCF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA09F,  /* 0X0DD0 - 0X0DD7 */
   0X5300, 0X70FF, 0X6229, 0XA054, 0X6233, 0X901C, 0X622D, 0XA0E6,  /* 0X0DD8 - 0X0DDF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08E,  /* 0X0DE0 - 0X0DE7 */
   0X5227, 0X700A, 0X6238, 0XA034, 0X6223, 0X823E, 0X623C, 0XA0D5,  /* 0X0DE8 - 0X0DEF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B0,  /* 0X0DF0 - 0X0DF7 */
   0X5300, 0X7220, 0X6239, 0XA066, 0X6234, 0X9026, 0X623D, 0XA230,  /* 0X0DF8 - 0X0DFF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA069,  /* 0X0E00 - 0X0E07 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B4,  /* 0X0E08 - 0X0E0F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA092,  /* 0X0E10 - 0X0E17 */
   0X5300, 0X7080, 0X6229, 0XA03B, 0X6233, 0X9012, 0X622D, 0XA0D8,  /* 0X0E18 - 0X0E1F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07B,  /* 0X0E20 - 0X0E27 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C5,  /* 0X0E28 - 0X0E2F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A2,  /* 0X0E30 - 0X0E37 */
   0X5300, 0X7210, 0X6239, 0XA057, 0X6234, 0X901D, 0X623D, 0XA0E9,  /* 0X0E38 - 0X0E3F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA072,  /* 0X0E40 - 0X0E47 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BC,  /* 0X0E48 - 0X0E4F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA09A,  /* 0X0E50 - 0X0E57 */
   0X5300, 0X70FF, 0X6229, 0XA04D, 0X6233, 0X9017, 0X622D, 0XA0E1,  /* 0X0E58 - 0X0E5F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA089,  /* 0X0E60 - 0X0E67 */
   0X5227, 0X700A, 0X6238, 0XA02B, 0X6223, 0X80FE, 0X623C, 0XA0CF,  /* 0X0E68 - 0X0E6F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0AA,  /* 0X0E70 - 0X0E77 */
   0X5300, 0X7220, 0X6239, 0XA061, 0X6234, 0X9022, 0X623D, 0XA0F6,  /* 0X0E78 - 0X0E7F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06D,  /* 0X0E80 - 0X0E87 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B8,  /* 0X0E88 - 0X0E8F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA096,  /* 0X0E90 - 0X0E97 */
   0X5300, 0X7080, 0X6229, 0XA047, 0X6233, 0X9015, 0X622D, 0XA0DC,  /* 0X0E98 - 0X0E9F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA083,  /* 0X0EA0 - 0X0EA7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0CA,  /* 0X0EA8 - 0X0EAF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A6,  /* 0X0EB0 - 0X0EB7 */
   0X5300, 0X7210, 0X6239, 0XA05C, 0X6234, 0X901F, 0X623D, 0XA0ED,  /* 0X0EB8 - 0X0EBF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA076,  /* 0X0EC0 - 0X0EC7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0C1,  /* 0X0EC8 - 0X0ECF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09E,  /* 0X0ED0 - 0X0ED7 */
   0X5300, 0X70FF, 0X6229, 0XA053, 0X6233, 0X901B, 0X622D, 0XA0E5,  /* 0X0ED8 - 0X0EDF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08D,  /* 0X0EE0 - 0X0EE7 */
   0X5227, 0X700A, 0X6238, 0XA032, 0X6223, 0X823E, 0X623C, 0XA0D4,  /* 0X0EE8 - 0X0EEF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AF,  /* 0X0EF0 - 0X0EF7 */
   0X5300, 0X7220, 0X6239, 0XA065, 0X6234, 0X9025, 0X623D, 0XA0FB,  /* 0X0EF8 - 0X0EFF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06B,  /* 0X0F00 - 0X0F07 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B6,  /* 0X0F08 - 0X0F0F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA094,  /* 0X0F10 - 0X0F17 */
   0X5300, 0X7080, 0X6229, 0XA045, 0X6233, 0X9014, 0X622D, 0XA0DA,  /* 0X0F18 - 0X0F1F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07D,  /* 0X0F20 - 0X0F27 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C8,  /* 0X0F28 - 0X0F2F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A4,  /* 0X0F30 - 0X0F37 */
   0X5300, 0X7210, 0X6239, 0XA05A, 0X6234, 0X901E, 0X623D, 0XA0EB,  /* 0X0F38 - 0X0F3F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA074,  /* 0X0F40 - 0X0F47 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BE,  /* 0X0F48 - 0X0F4F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09C,  /* 0X0F50 - 0X0F57 */
   0X5300, 0X70FF, 0X6229, 0XA04F, 0X6233, 0X901A, 0X622D, 0XA0E3,  /* 0X0F58 - 0X0F5F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08B,  /* 0X0F60 - 0X0F67 */
   0X5227, 0X700A, 0X6238, 0XA02E, 0X6223, 0X80FE, 0X623C, 0XA0D2,  /* 0X0F68 - 0X0F6F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AD,  /* 0X0F70 - 0X0F77 */
   0X5300, 0X7220, 0X6239, 0XA063, 0X6234, 0X9024, 0X623D, 0XA0F9,  /* 0X0F78 - 0X0F7F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06F,  /* 0X0F80 - 0X0F87 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0BA,  /* 0X0F88 - 0X0F8F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA098,  /* 0X0F90 - 0X0F97 */
   0X5300, 0X7080, 0X6229, 0XA04B, 0X6233, 0X9016, 0X622D, 0XA0DE,  /* 0X0F98 - 0X0F9F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA086,  /* 0X0FA0 - 0X0FA7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CD,  /* 0X0FA8 - 0X0FAF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A8,  /* 0X0FB0 - 0X0FB7 */
   0X5300, 0X7210, 0X6239, 0XA05E, 0X6234, 0X9021, 0X623D, 0XA0F3,  /* 0X0FB8 - 0X0FBF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA079,  /* 0X0FC0 - 0X0FC7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C3,  /* 0X0FC8 - 0X0FCF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA0A0,  /* 0X0FD0 - 0X0FD7 */
   0X5300, 0X70FF, 0X6229, 0XA055, 0X6233, 0X901C, 0X622D, 0XA0E7,  /* 0X0FD8 - 0X0FDF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08F,  /* 0X0FE0 - 0X0FE7 */
   0X5227, 0X700A, 0X6238, 0XA036, 0X6223, 0X823E, 0X623C, 0XA0D6,  /* 0X0FE8 - 0X0FEF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B1,  /* 0X0FF0 - 0X0FF7 */
   0X5300, 0X7220, 0X6239, 0XA067, 0X6234, 0X9026, 0X623D, 0XD200,  /* 0X0FF8 - 0X0FFF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA068,  /* 0X1000 - 0X1007 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B3,  /* 0X1008 - 0X100F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA091,  /* 0X1010 - 0X1017 */
   0X5300, 0X7080, 0X6229, 0XA03A, 0X6233, 0X9012, 0X622D, 0XA0D7,  /* 0X1018 - 0X101F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07A,  /* 0X1020 - 0X1027 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C4,  /* 0X1028 - 0X102F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A1,  /* 0X1030 - 0X1037 */
   0X5300, 0X7210, 0X6239, 0XA056, 0X6234, 0X901D, 0X623D, 0XA0E8,  /* 0X1038 - 0X103F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA071,  /* 0X1040 - 0X1047 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BB,  /* 0X1048 - 0X104F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA099,  /* 0X1050 - 0X1057 */
   0X5300, 0X70FF, 0X6229, 0XA04C, 0X6233, 0X9017, 0X622D, 0XA0DF,  /* 0X1058 - 0X105F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA087,  /* 0X1060 - 0X1067 */
   0X5227, 0X700A, 0X6238, 0XA023, 0X6223, 0X80FE, 0X623C, 0XA0CE,  /* 0X1068 - 0X106F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0A9,  /* 0X1070 - 0X1077 */
   0X5300, 0X7220, 0X6239, 0XA05F, 0X6234, 0X9022, 0X623D, 0XA0F5,  /* 0X1078 - 0X107F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06C,  /* 0X1080 - 0X1087 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B7,  /* 0X1088 - 0X108F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA095,  /* 0X1090 - 0X1097 */
   0X5300, 0X7080, 0X6229, 0XA046, 0X6233, 0X9015, 0X622D, 0XA0DB,  /* 0X1098 - 0X109F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA07E,  /* 0X10A0 - 0X10A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0C9,  /* 0X10A8 - 0X10AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A5,  /* 0X10B0 - 0X10B7 */
   0X5300, 0X7210, 0X6239, 0XA05B, 0X6234, 0X901F, 0X623D, 0XA0EC,  /* 0X10B8 - 0X10BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA075,  /* 0X10C0 - 0X10C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0BF,  /* 0X10C8 - 0X10CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09D,  /* 0X10D0 - 0X10D7 */
   0X5300, 0X70FF, 0X6229, 0XA052, 0X6233, 0X901B, 0X622D, 0XA0E4,  /* 0X10D8 - 0X10DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08C,  /* 0X10E0 - 0X10E7 */
   0X5227, 0X700A, 0X6238, 0XA02F, 0X6223, 0X823E, 0X623C, 0XA0D3,  /* 0X10E8 - 0X10EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AE,  /* 0X10F0 - 0X10F7 */
   0X5300, 0X7220, 0X6239, 0XA064, 0X6234, 0X9025, 0X623D, 0XA0FA,  /* 0X10F8 - 0X10FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06A,  /* 0X1100 - 0X1107 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B5,  /* 0X1108 - 0X110F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA093,  /* 0X1110 - 0X1117 */
   0X5300, 0X7080, 0X6229, 0XA03D, 0X6233, 0X9014, 0X622D, 0XA0D9,  /* 0X1118 - 0X111F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07C,  /* 0X1120 - 0X1127 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C7,  /* 0X1128 - 0X112F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A3,  /* 0X1130 - 0X1137 */
   0X5300, 0X7210, 0X6239, 0XA058, 0X6234, 0X901E, 0X623D, 0XA0EA,  /* 0X1138 - 0X113F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA073,  /* 0X1140 - 0X1147 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BD,  /* 0X1148 - 0X114F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09B,  /* 0X1150 - 0X1157 */
   0X5300, 0X70FF, 0X6229, 0XA04E, 0X6233, 0X901A, 0X622D, 0XA0E2,  /* 0X1158 - 0X115F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08A,  /* 0X1160 - 0X1167 */
   0X5227, 0X700A, 0X6238, 0XA02D, 0X6223, 0X80FE, 0X623C, 0XA0D1,  /* 0X1168 - 0X116F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AC,  /* 0X1170 - 0X1177 */
   0X5300, 0X7220, 0X6239, 0XA062, 0X6234, 0X9024, 0X623D, 0XA0F7,  /* 0X1178 - 0X117F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06E,  /* 0X1180 - 0X1187 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0B9,  /* 0X1188 - 0X118F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA097,  /* 0X1190 - 0X1197 */
   0X5300, 0X7080, 0X6229, 0XA04A, 0X6233, 0X9016, 0X622D, 0XA0DD,  /* 0X1198 - 0X119F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA085,  /* 0X11A0 - 0X11A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CB,  /* 0X11A8 - 0X11AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A7,  /* 0X11B0 - 0X11B7 */
   0X5300, 0X7210, 0X6239, 0XA05D, 0X6234, 0X9021, 0X623D, 0XA0EF,  /* 0X11B8 - 0X11BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA077,  /* 0X11C0 - 0X11C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C2,  /* 0X11C8 - 0X11CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA09F,  /* 0X11D0 - 0X11D7 */
   0X5300, 0X70FF, 0X6229, 0XA054, 0X6233, 0X901C, 0X622D, 0XA0E6,  /* 0X11D8 - 0X11DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08E,  /* 0X11E0 - 0X11E7 */
   0X5227, 0X700A, 0X6238, 0XA034, 0X6223, 0X823E, 0X623C, 0XA0D5,  /* 0X11E8 - 0X11EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B0,  /* 0X11F0 - 0X11F7 */
   0X5300, 0X7220, 0X6239, 0XA066, 0X6234, 0X9026, 0X623D, 0XA230,  /* 0X11F8 - 0X11FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA069,  /* 0X1200 - 0X1207 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B4,  /* 0X1208 - 0X120F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA092,  /* 0X1210 - 0X1217 */
   0X5300, 0X7080, 0X6229, 0XA03B, 0X6233, 0X9012, 0X622D, 0XA0D8,  /* 0X1218 - 0X121F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07B,  /* 0X1220 - 0X1227 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C5,  /* 0X1228 - 0X122F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A2,  /* 0X1230 - 0X1237 */
   0X5300, 0X7210, 0X6239, 0XA057, 0X6234, 0X901D, 0X623D, 0XA0E9,  /* 0X1238 - 0X123F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA072,  /* 0X1240 - 0X1247 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BC,  /* 0X1248 - 0X124F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA09A,  /* 0X1250 - 0X1257 */
   0X5300, 0X70FF, 0X6229, 0XA04D, 0X6233, 0X9017, 0X622D, 0XA0E1,  /* 0X1258 - 0X125F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA089,  /* 0X1260 - 0X1267 */
   0X5227, 0X700A, 0X6238, 0XA02B, 0X6223, 0X80FE, 0X623C, 0XA0CF,  /* 0X1268 - 0X126F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0AA,  /* 0X1270 - 0X1277 */
   0X5300, 0X7220, 0X6239, 0XA061, 0X6234, 0X9022, 0X623D, 0XA0F6,  /* 0X1278 - 0X127F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06D,  /* 0X1280 - 0X1287 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B8,  /* 0X1288 - 0X128F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA096,  /* 0X1290 - 0X1297 */
   0X5300, 0X7080, 0X6229, 0XA047, 0X6233, 0X9015, 0X622D, 0XA0DC,  /* 0X1298 - 0X129F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA083,  /* 0X12A0 - 0X12A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0CA,  /* 0X12A8 - 0X12AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A6,  /* 0X12B0 - 0X12B7 */
   0X5300, 0X7210, 0X6239, 0XA05C, 0X6234, 0X901F, 0X623D, 0XA0ED,  /* 0X12B8 - 0X12BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA076,  /* 0X12C0 - 0X12C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0C1,  /* 0X12C8 - 0X12CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09E,  /* 0X12D0 - 0X12D7 */
   0X5300, 0X70FF, 0X6229, 0XA053, 0X6233, 0X901B, 0X622D, 0XA0E5,  /* 0X12D8 - 0X12DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08D,  /* 0X12E0 - 0X12E7 */
   0X5227, 0X700A, 0X6238, 0XA032, 0X6223, 0X823E, 0X623C, 0XA0D4,  /* 0X12E8 - 0X12EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AF,  /* 0X12F0 - 0X12F7 */
   0X5300, 0X7220, 0X6239, 0XA065, 0X6234, 0X9025, 0X623D, 0XA0FB,  /* 0X12F8 - 0X12FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06B,  /* 0X1300 - 0X1307 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B6,  /* 0X1308 - 0X130F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA094,  /* 0X1310 - 0X1317 */
   0X5300, 0X7080, 0X6229, 0XA045, 0X6233, 0X9014, 0X622D, 0XA0DA,  /* 0X1318 - 0X131F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07D,  /* 0X1320 - 0X1327 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C8,  /* 0X1328 - 0X132F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A4,  /* 0X1330 - 0X1337 */
   0X5300, 0X7210, 0X6239, 0XA05A, 0X6234, 0X901E, 0X623D, 0XA0EB,  /* 0X1338 - 0X133F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA074,  /* 0X1340 - 0X1347 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BE,  /* 0X1348 - 0X134F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09C,  /* 0X1350 - 0X1357 */
   0X5300, 0X70FF, 0X6229, 0XA04F, 0X6233, 0X901A, 0X622D, 0XA0E3,  /* 0X1358 - 0X135F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08B,  /* 0X1360 - 0X1367 */
   0X5227, 0X700A, 0X6238, 0XA02E, 0X6223, 0X80FE, 0X623C, 0XA0D2,  /* 0X1368 - 0X136F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AD,  /* 0X1370 - 0X1377 */
   0X5300, 0X7220, 0X6239, 0XA063, 0X6234, 0X9024, 0X623D, 0XA0F9,  /* 0X1378 - 0X137F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06F,  /* 0X1380 - 0X1387 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0BA,  /* 0X1388 - 0X138F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA098,  /* 0X1390 - 0X1397 */
   0X5300, 0X7080, 0X6229, 0XA04B, 0X6233, 0X9016, 0X622D, 0XA0DE,  /* 0X1398 - 0X139F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA086,  /* 0X13A0 - 0X13A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CD,  /* 0X13A8 - 0X13AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A8,  /* 0X13B0 - 0X13B7 */
   0X5300, 0X7210, 0X6239, 0XA05E, 0X6234, 0X9021, 0X623D, 0XA0F3,  /* 0X13B8 - 0X13BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA079,  /* 0X13C0 - 0X13C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C3,  /* 0X13C8 - 0X13CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA0A0,  /* 0X13D0 - 0X13D7 */
   0X5300, 0X70FF, 0X6229, 0XA055, 0X6233, 0X901C, 0X622D, 0XA0E7,  /* 0X13D8 - 0X13DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08F,  /* 0X13E0 - 0X13E7 */
   0X5227, 0X700A, 0X6238, 0XA036, 0X6223, 0X823E, 0X623C, 0XA0D6,  /* 0X13E8 - 0X13EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B1,  /* 0X13F0 - 0X13F7 */
   0X5300, 0X7220, 0X6239, 0XA067, 0X6234, 0X9026, 0X623D, 0XB0B2,  /* 0X13F8 - 0X13FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA068,  /* 0X1400 - 0X1407 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B3,  /* 0X1408 - 0X140F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA091,  /* 0X1410 - 0X1417 */
   0X5300, 0X7080, 0X6229, 0XA03A, 0X6233, 0X9012, 0X622D, 0XA0D7,  /* 0X1418 - 0X141F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07A,  /* 0X1420 - 0X1427 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C4,  /* 0X1428 - 0X142F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A1,  /* 0X1430 - 0X1437 */
   0X5300, 0X7210, 0X6239, 0XA056, 0X6234, 0X901D, 0X623D, 0XA0E8,  /* 0X1438 - 0X143F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA071,  /* 0X1440 - 0X1447 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BB,  /* 0X1448 - 0X144F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA099,  /* 0X1450 - 0X1457 */
   0X5300, 0X70FF, 0X6229, 0XA04C, 0X6233, 0X9017, 0X622D, 0XA0DF,  /* 0X1458 - 0X145F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA087,  /* 0X1460 - 0X1467 */
   0X5227, 0X700A, 0X6238, 0XA023, 0X6223, 0X80FE, 0X623C, 0XA0CE,  /* 0X1468 - 0X146F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0A9,  /* 0X1470 - 0X1477 */
   0X5300, 0X7220, 0X6239, 0XA05F, 0X6234, 0X9022, 0X623D, 0XA0F5,  /* 0X1478 - 0X147F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06C,  /* 0X1480 - 0X1487 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B7,  /* 0X1488 - 0X148F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA095,  /* 0X1490 - 0X1497 */
   0X5300, 0X7080, 0X6229, 0XA046, 0X6233, 0X9015, 0X622D, 0XA0DB,  /* 0X1498 - 0X149F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA07E,  /* 0X14A0 - 0X14A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0C9,  /* 0X14A8 - 0X14AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A5,  /* 0X14B0 - 0X14B7 */
   0X5300, 0X7210, 0X6239, 0XA05B, 0X6234, 0X901F, 0X623D, 0XA0EC,  /* 0X14B8 - 0X14BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA075,  /* 0X14C0 - 0X14C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0BF,  /* 0X14C8 - 0X14CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09D,  /* 0X14D0 - 0X14D7 */
   0X5300, 0X70FF, 0X6229, 0XA052, 0X6233, 0X901B, 0X622D, 0XA0E4,  /* 0X14D8 - 0X14DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08C,  /* 0X14E0 - 0X14E7 */
   0X5227, 0X700A, 0X6238, 0XA02F, 0X6223, 0X823E, 0X623C, 0XA0D3,  /* 0X14E8 - 0X14EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AE,  /* 0X14F0 - 0X14F7 */
   0X5300, 0X7220, 0X6239, 0XA064, 0X6234, 0X9025, 0X623D, 0XA0FA,  /* 0X14F8 - 0X14FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06A,  /* 0X1500 - 0X1507 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B5,  /* 0X1508 - 0X150F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA093,  /* 0X1510 - 0X1517 */
   0X5300, 0X7080, 0X6229, 0XA03D, 0X6233, 0X9014, 0X622D, 0XA0D9,  /* 0X1518 - 0X151F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07C,  /* 0X1520 - 0X1527 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C7,  /* 0X1528 - 0X152F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A3,  /* 0X1530 - 0X1537 */
   0X5300, 0X7210, 0X6239, 0XA058, 0X6234, 0X901E, 0X623D, 0XA0EA,  /* 0X1538 - 0X153F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA073,  /* 0X1540 - 0X1547 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BD,  /* 0X1548 - 0X154F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09B,  /* 0X1550 - 0X1557 */
   0X5300, 0X70FF, 0X6229, 0XA04E, 0X6233, 0X901A, 0X622D, 0XA0E2,  /* 0X1558 - 0X155F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08A,  /* 0X1560 - 0X1567 */
   0X5227, 0X700A, 0X6238, 0XA02D, 0X6223, 0X80FE, 0X623C, 0XA0D1,  /* 0X1568 - 0X156F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AC,  /* 0X1570 - 0X1577 */
   0X5300, 0X7220, 0X6239, 0XA062, 0X6234, 0X9024, 0X623D, 0XA0F7,  /* 0X1578 - 0X157F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06E,  /* 0X1580 - 0X1587 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0B9,  /* 0X1588 - 0X158F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA097,  /* 0X1590 - 0X1597 */
   0X5300, 0X7080, 0X6229, 0XA04A, 0X6233, 0X9016, 0X622D, 0XA0DD,  /* 0X1598 - 0X159F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA085,  /* 0X15A0 - 0X15A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CB,  /* 0X15A8 - 0X15AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A7,  /* 0X15B0 - 0X15B7 */
   0X5300, 0X7210, 0X6239, 0XA05D, 0X6234, 0X9021, 0X623D, 0XA0EF,  /* 0X15B8 - 0X15BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA077,  /* 0X15C0 - 0X15C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C2,  /* 0X15C8 - 0X15CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA09F,  /* 0X15D0 - 0X15D7 */
   0X5300, 0X70FF, 0X6229, 0XA054, 0X6233, 0X901C, 0X622D, 0XA0E6,  /* 0X15D8 - 0X15DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08E,  /* 0X15E0 - 0X15E7 */
   0X5227, 0X700A, 0X6238, 0XA034, 0X6223, 0X823E, 0X623C, 0XA0D5,  /* 0X15E8 - 0X15EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B0,  /* 0X15F0 - 0X15F7 */
   0X5300, 0X7220, 0X6239, 0XA066, 0X6234, 0X9026, 0X623D, 0XA230,  /* 0X15F8 - 0X15FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA069,  /* 0X1600 - 0X1607 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B4,  /* 0X1608 - 0X160F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA092,  /* 0X1610 - 0X1617 */
   0X5300, 0X7080, 0X6229, 0XA03B, 0X6233, 0X9012, 0X622D, 0XA0D8,  /* 0X1618 - 0X161F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07B,  /* 0X1620 - 0X1627 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C5,  /* 0X1628 - 0X162F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A2,  /* 0X1630 - 0X1637 */
   0X5300, 0X7210, 0X6239, 0XA057, 0X6234, 0X901D, 0X623D, 0XA0E9,  /* 0X1638 - 0X163F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA072,  /* 0X1640 - 0X1647 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BC,  /* 0X1648 - 0X164F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA09A,  /* 0X1650 - 0X1657 */
   0X5300, 0X70FF, 0X6229, 0XA04D, 0X6233, 0X9017, 0X622D, 0XA0E1,  /* 0X1658 - 0X165F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA089,  /* 0X1660 - 0X1667 */
   0X5227, 0X700A, 0X6238, 0XA02B, 0X6223, 0X80FE, 0X623C, 0XA0CF,  /* 0X1668 - 0X166F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0AA,  /* 0X1670 - 0X1677 */
   0X5300, 0X7220, 0X6239, 0XA061, 0X6234, 0X9022, 0X623D, 0XA0F6,  /* 0X1678 - 0X167F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06D,  /* 0X1680 - 0X1687 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B8,  /* 0X1688 - 0X168F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA096,  /* 0X1690 - 0X1697 */
   0X5300, 0X7080, 0X6229, 0XA047, 0X6233, 0X9015, 0X622D, 0XA0DC,  /* 0X1698 - 0X169F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA083,  /* 0X16A0 - 0X16A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0CA,  /* 0X16A8 - 0X16AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A6,  /* 0X16B0 - 0X16B7 */
   0X5300, 0X7210, 0X6239, 0XA05C, 0X6234, 0X901F, 0X623D, 0XA0ED,  /* 0X16B8 - 0X16BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA076,  /* 0X16C0 - 0X16C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0C1,  /* 0X16C8 - 0X16CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09E,  /* 0X16D0 - 0X16D7 */
   0X5300, 0X70FF, 0X6229, 0XA053, 0X6233, 0X901B, 0X622D, 0XA0E5,  /* 0X16D8 - 0X16DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08D,  /* 0X16E0 - 0X16E7 */
   0X5227, 0X700A, 0X6238, 0XA032, 0X6223, 0X823E, 0X623C, 0XA0D4,  /* 0X16E8 - 0X16EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AF,  /* 0X16F0 - 0X16F7 */
   0X5300, 0X7220, 0X6239, 0XA065, 0X6234, 0X9025, 0X623D, 0XA0FB,  /* 0X16F8 - 0X16FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06B,  /* 0X1700 - 0X1707 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B6,  /* 0X1708 - 0X170F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA094,  /* 0X1710 - 0X1717 */
   0X5300, 0X7080, 0X6229, 0XA045, 0X6233, 0X9014, 0X622D, 0XA0DA,  /* 0X1718 - 0X171F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07D,  /* 0X1720 - 0X1727 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C8,  /* 0X1728 - 0X172F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A4,  /* 0X1730 - 0X1737 */
   0X5300, 0X7210, 0X6239, 0XA05A, 0X6234, 0X901E, 0X623D, 0XA0EB,  /* 0X1738 - 0X173F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA074,  /* 0X1740 - 0X1747 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BE,  /* 0X1748 - 0X174F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09C,  /* 0X1750 - 0X1757 */
   0X5300, 0X70FF, 0X6229, 0XA04F, 0X6233, 0X901A, 0X622D, 0XA0E3,  /* 0X1758 - 0X175F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08B,  /* 0X1760 - 0X1767 */
   0X5227, 0X700A, 0X6238, 0XA02E, 0X6223, 0X80FE, 0X623C, 0XA0D2,  /* 0X1768 - 0X176F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AD,  /* 0X1770 - 0X1777 */
   0X5300, 0X7220, 0X6239, 0XA063, 0X6234, 0X9024, 0X623D, 0XA0F9,  /* 0X1778 - 0X177F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06F,  /* 0X1780 - 0X1787 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0BA,  /* 0X1788 - 0X178F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA098,  /* 0X1790 - 0X1797 */
   0X5300, 0X7080, 0X6229, 0XA04B, 0X6233, 0X9016, 0X622D, 0XA0DE,  /* 0X1798 - 0X179F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA086,  /* 0X17A0 - 0X17A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CD,  /* 0X17A8 - 0X17AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A8,  /* 0X17B0 - 0X17B7 */
   0X5300, 0X7210, 0X6239, 0XA05E, 0X6234, 0X9021, 0X623D, 0XA0F3,  /* 0X17B8 - 0X17BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA079,  /* 0X17C0 - 0X17C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C3,  /* 0X17C8 - 0X17CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA0A0,  /* 0X17D0 - 0X17D7 */
   0X5300, 0X70FF, 0X6229, 0XA055, 0X6233, 0X901C, 0X622D, 0XA0E7,  /* 0X17D8 - 0X17DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08F,  /* 0X17E0 - 0X17E7 */
   0X5227, 0X700A, 0X6238, 0XA036, 0X6223, 0X823E, 0X623C, 0XA0D6,  /* 0X17E8 - 0X17EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B1,  /* 0X17F0 - 0X17F7 */
   0X5300, 0X7220, 0X6239, 0XA067, 0X6234, 0X9026, 0X623D, 0XD100,  /* 0X17F8 - 0X17FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA068,  /* 0X1800 - 0X1807 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B3,  /* 0X1808 - 0X180F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA091,  /* 0X1810 - 0X1817 */
   0X5300, 0X7080, 0X6229, 0XA03A, 0X6233, 0X9012, 0X622D, 0XA0D7,  /* 0X1818 - 0X181F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07A,  /* 0X1820 - 0X1827 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C4,  /* 0X1828 - 0X182F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A1,  /* 0X1830 - 0X1837 */
   0X5300, 0X7210, 0X6239, 0XA056, 0X6234, 0X901D, 0X623D, 0XA0E8,  /* 0X1838 - 0X183F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA071,  /* 0X1840 - 0X1847 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BB,  /* 0X1848 - 0X184F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA099,  /* 0X1850 - 0X1857 */
   0X5300, 0X70FF, 0X6229, 0XA04C, 0X6233, 0X9017, 0X622D, 0XA0DF,  /* 0X1858 - 0X185F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA087,  /* 0X1860 - 0X1867 */
   0X5227, 0X700A, 0X6238, 0XA023, 0X6223, 0X80FE, 0X623C, 0XA0CE,  /* 0X1868 - 0X186F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0A9,  /* 0X1870 - 0X1877 */
   0X5300, 0X7220, 0X6239, 0XA05F, 0X6234, 0X9022, 0X623D, 0XA0F5,  /* 0X1878 - 0X187F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06C,  /* 0X1880 - 0X1887 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B7,  /* 0X1888 - 0X188F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA095,  /* 0X1890 - 0X1897 */
   0X5300, 0X7080, 0X6229, 0XA046, 0X6233, 0X9015, 0X622D, 0XA0DB,  /* 0X1898 - 0X189F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA07E,  /* 0X18A0 - 0X18A7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0C9,  /* 0X18A8 - 0X18AF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A5,  /* 0X18B0 - 0X18B7 */
   0X5300, 0X7210, 0X6239, 0XA05B, 0X6234, 0X901F, 0X623D, 0XA0EC,  /* 0X18B8 - 0X18BF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA075,  /* 0X18C0 - 0X18C7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0BF,  /* 0X18C8 - 0X18CF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09D,  /* 0X18D0 - 0X18D7 */
   0X5300, 0X70FF, 0X6229, 0XA052, 0X6233, 0X901B, 0X622D, 0XA0E4,  /* 0X18D8 - 0X18DF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08C,  /* 0X18E0 - 0X18E7 */
   0X5227, 0X700A, 0X6238, 0XA02F, 0X6223, 0X823E, 0X623C, 0XA0D3,  /* 0X18E8 - 0X18EF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AE,  /* 0X18F0 - 0X18F7 */
   0X5300, 0X7220, 0X6239, 0XA064, 0X6234, 0X9025, 0X623D, 0XA0FA,  /* 0X18F8 - 0X18FF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06A,  /* 0X1900 - 0X1907 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B5,  /* 0X1908 - 0X190F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA093,  /* 0X1910 - 0X1917 */
   0X5300, 0X7080, 0X6229, 0XA03D, 0X6233, 0X9014, 0X622D, 0XA0D9,  /* 0X1918 - 0X191F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07C,  /* 0X1920 - 0X1927 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C7,  /* 0X1928 - 0X192F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A3,  /* 0X1930 - 0X1937 */
   0X5300, 0X7210, 0X6239, 0XA058, 0X6234, 0X901E, 0X623D, 0XA0EA,  /* 0X1938 - 0X193F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA073,  /* 0X1940 - 0X1947 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BD,  /* 0X1948 - 0X194F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09B,  /* 0X1950 - 0X1957 */
   0X5300, 0X70FF, 0X6229, 0XA04E, 0X6233, 0X901A, 0X622D, 0XA0E2,  /* 0X1958 - 0X195F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08A,  /* 0X1960 - 0X1967 */
   0X5227, 0X700A, 0X6238, 0XA02D, 0X6223, 0X80FE, 0X623C, 0XA0D1,  /* 0X1968 - 0X196F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AC,  /* 0X1970 - 0X1977 */
   0X5300, 0X7220, 0X6239, 0XA062, 0X6234, 0X9024, 0X623D, 0XA0F7,  /* 0X1978 - 0X197F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06E,  /* 0X1980 - 0X1987 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0B9,  /* 0X1988 - 0X198F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA097,  /* 0X1990 - 0X1997 */
   0X5300, 0X7080, 0X6229, 0XA04A, 0X6233, 0X9016, 0X622D, 0XA0DD,  /* 0X1998 - 0X199F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA085,  /* 0X19A0 - 0X19A7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CB,  /* 0X19A8 - 0X19AF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A7,  /* 0X19B0 - 0X19B7 */
   0X5300, 0X7210, 0X6239, 0XA05D, 0X6234, 0X9021, 0X623D, 0XA0EF,  /* 0X19B8 - 0X19BF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA077,  /* 0X19C0 - 0X19C7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C2,  /* 0X19C8 - 0X19CF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA09F,  /* 0X19D0 - 0X19D7 */
   0X5300, 0X70FF, 0X6229, 0XA054, 0X6233, 0X901C, 0X622D, 0XA0E6,  /* 0X19D8 - 0X19DF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08E,  /* 0X19E0 - 0X19E7 */
   0X5227, 0X700A, 0X6238, 0XA034, 0X6223, 0X823E, 0X623C, 0XA0D5,  /* 0X19E8 - 0X19EF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B0,  /* 0X19F0 - 0X19F7 */
   0X5300, 0X7220, 0X6239, 0XA066, 0X6234, 0X9026, 0X623D, 0XA230,  /* 0X19F8 - 0X19FF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA069,  /* 0X1A00 - 0X1A07 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B4,  /* 0X1A08 - 0X1A0F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA092,  /* 0X1A10 - 0X1A17 */
   0X5300, 0X7080, 0X6229, 0XA03B, 0X6233, 0X9012, 0X622D, 0XA0D8,  /* 0X1A18 - 0X1A1F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07B,  /* 0X1A20 - 0X1A27 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C5,  /* 0X1A28 - 0X1A2F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A2,  /* 0X1A30 - 0X1A37 */
   0X5300, 0X7210, 0X6239, 0XA057, 0X6234, 0X901D, 0X623D, 0XA0E9,  /* 0X1A38 - 0X1A3F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA072,  /* 0X1A40 - 0X1A47 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BC,  /* 0X1A48 - 0X1A4F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA09A,  /* 0X1A50 - 0X1A57 */
   0X5300, 0X70FF, 0X6229, 0XA04D, 0X6233, 0X9017, 0X622D, 0XA0E1,  /* 0X1A58 - 0X1A5F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA089,  /* 0X1A60 - 0X1A67 */
   0X5227, 0X700A, 0X6238, 0XA02B, 0X6223, 0X80FE, 0X623C, 0XA0CF,  /* 0X1A68 - 0X1A6F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0AA,  /* 0X1A70 - 0X1A77 */
   0X5300, 0X7220, 0X6239, 0XA061, 0X6234, 0X9022, 0X623D, 0XA0F6,  /* 0X1A78 - 0X1A7F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06D,  /* 0X1A80 - 0X1A87 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B8,  /* 0X1A88 - 0X1A8F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA096,  /* 0X1A90 - 0X1A97 */
   0X5300, 0X7080, 0X6229, 0XA047, 0X6233, 0X9015, 0X622D, 0XA0DC,  /* 0X1A98 - 0X1A9F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA083,  /* 0X1AA0 - 0X1AA7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0CA,  /* 0X1AA8 - 0X1AAF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A6,  /* 0X1AB0 - 0X1AB7 */
   0X5300, 0X7210, 0X6239, 0XA05C, 0X6234, 0X901F, 0X623D, 0XA0ED,  /* 0X1AB8 - 0X1ABF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA076,  /* 0X1AC0 - 0X1AC7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0C1,  /* 0X1AC8 - 0X1ACF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09E,  /* 0X1AD0 - 0X1AD7 */
   0X5300, 0X70FF, 0X6229, 0XA053, 0X6233, 0X901B, 0X622D, 0XA0E5,  /* 0X1AD8 - 0X1ADF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08D,  /* 0X1AE0 - 0X1AE7 */
   0X5227, 0X700A, 0X6238, 0XA032, 0X6223, 0X823E, 0X623C, 0XA0D4,  /* 0X1AE8 - 0X1AEF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AF,  /* 0X1AF0 - 0X1AF7 */
   0X5300, 0X7220, 0X6239, 0XA065, 0X6234, 0X9025, 0X623D, 0XA0FB,  /* 0X1AF8 - 0X1AFF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06B,  /* 0X1B00 - 0X1B07 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B6,  /* 0X1B08 - 0X1B0F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA094,  /* 0X1B10 - 0X1B17 */
   0X5300, 0X7080, 0X6229, 0XA045, 0X6233, 0X9014, 0X622D, 0XA0DA,  /* 0X1B18 - 0X1B1F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07D,  /* 0X1B20 - 0X1B27 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C8,  /* 0X1B28 - 0X1B2F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A4,  /* 0X1B30 - 0X1B37 */
   0X5300, 0X7210, 0X6239, 0XA05A, 0X6234, 0X901E, 0X623D, 0XA0EB,  /* 0X1B38 - 0X1B3F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA074,  /* 0X1B40 - 0X1B47 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BE,  /* 0X1B48 - 0X1B4F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09C,  /* 0X1B50 - 0X1B57 */
   0X5300, 0X70FF, 0X6229, 0XA04F, 0X6233, 0X901A, 0X622D, 0XA0E3,  /* 0X1B58 - 0X1B5F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08B,  /* 0X1B60 - 0X1B67 */
   0X5227, 0X700A, 0X6238, 0XA02E, 0X6223, 0X80FE, 0X623C, 0XA0D2,  /* 0X1B68 - 0X1B6F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AD,  /* 0X1B70 - 0X1B77 */
   0X5300, 0X7220, 0X6239, 0XA063, 0X6234, 0X9024, 0X623D, 0XA0F9,  /* 0X1B78 - 0X1B7F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06F,  /* 0X1B80 - 0X1B87 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0BA,  /* 0X1B88 - 0X1B8F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA098,  /* 0X1B90 - 0X1B97 */
   0X5300, 0X7080, 0X6229, 0XA04B, 0X6233, 0X9016, 0X622D, 0XA0DE,  /* 0X1B98 - 0X1B9F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA086,  /* 0X1BA0 - 0X1BA7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CD,  /* 0X1BA8 - 0X1BAF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A8,  /* 0X1BB0 - 0X1BB7 */
   0X5300, 0X7210, 0X6239, 0XA05E, 0X6234, 0X9021, 0X623D, 0XA0F3,  /* 0X1BB8 - 0X1BBF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA079,  /* 0X1BC0 - 0X1BC7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C3,  /* 0X1BC8 - 0X1BCF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA0A0,  /* 0X1BD0 - 0X1BD7 */
   0X5300, 0X70FF, 0X6229, 0XA055, 0X6233, 0X901C, 0X622D, 0XA0E7,  /* 0X1BD8 - 0X1BDF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08F,  /* 0X1BE0 - 0X1BE7 */
   0X5227, 0X700A, 0X6238, 0XA036, 0X6223, 0X823E, 0X623C, 0XA0D6,  /* 0X1BE8 - 0X1BEF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B1,  /* 0X1BF0 - 0X1BF7 */
   0X5300, 0X7220, 0X6239, 0XA067, 0X6234, 0X9026, 0X623D, 0XB0B2,  /* 0X1BF8 - 0X1BFF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA068,  /* 0X1C00 - 0X1C07 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B3,  /* 0X1C08 - 0X1C0F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA091,  /* 0X1C10 - 0X1C17 */
   0X5300, 0X7080, 0X6229, 0XA03A, 0X6233, 0X9012, 0X622D, 0XA0D7,  /* 0X1C18 - 0X1C1F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07A,  /* 0X1C20 - 0X1C27 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C4,  /* 0X1C28 - 0X1C2F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A1,  /* 0X1C30 - 0X1C37 */
   0X5300, 0X7210, 0X6239, 0XA056, 0X6234, 0X901D, 0X623D, 0XA0E8,  /* 0X1C38 - 0X1C3F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA071,  /* 0X1C40 - 0X1C47 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BB,  /* 0X1C48 - 0X1C4F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA099,  /* 0X1C50 - 0X1C57 */
   0X5300, 0X70FF, 0X6229, 0XA04C, 0X6233, 0X9017, 0X622D, 0XA0DF,  /* 0X1C58 - 0X1C5F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA087,  /* 0X1C60 - 0X1C67 */
   0X5227, 0X700A, 0X6238, 0XA023, 0X6223, 0X80FE, 0X623C, 0XA0CE,  /* 0X1C68 - 0X1C6F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0A9,  /* 0X1C70 - 0X1C77 */
   0X5300, 0X7220, 0X6239, 0XA05F, 0X6234, 0X9022, 0X623D, 0XA0F5,  /* 0X1C78 - 0X1C7F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06C,  /* 0X1C80 - 0X1C87 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B7,  /* 0X1C88 - 0X1C8F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA095,  /* 0X1C90 - 0X1C97 */
   0X5300, 0X7080, 0X6229, 0XA046, 0X6233, 0X9015, 0X622D, 0XA0DB,  /* 0X1C98 - 0X1C9F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA07E,  /* 0X1CA0 - 0X1CA7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0C9,  /* 0X1CA8 - 0X1CAF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A5,  /* 0X1CB0 - 0X1CB7 */
   0X5300, 0X7210, 0X6239, 0XA05B, 0X6234, 0X901F, 0X623D, 0XA0EC,  /* 0X1CB8 - 0X1CBF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA075,  /* 0X1CC0 - 0X1CC7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0BF,  /* 0X1CC8 - 0X1CCF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09D,  /* 0X1CD0 - 0X1CD7 */
   0X5300, 0X70FF, 0X6229, 0XA052, 0X6233, 0X901B, 0X622D, 0XA0E4,  /* 0X1CD8 - 0X1CDF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08C,  /* 0X1CE0 - 0X1CE7 */
   0X5227, 0X700A, 0X6238, 0XA02F, 0X6223, 0X823E, 0X623C, 0XA0D3,  /* 0X1CE8 - 0X1CEF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AE,  /* 0X1CF0 - 0X1CF7 */
   0X5300, 0X7220, 0X6239, 0XA064, 0X6234, 0X9025, 0X623D, 0XA0FA,  /* 0X1CF8 - 0X1CFF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06A,  /* 0X1D00 - 0X1D07 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B5,  /* 0X1D08 - 0X1D0F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA093,  /* 0X1D10 - 0X1D17 */
   0X5300, 0X7080, 0X6229, 0XA03D, 0X6233, 0X9014, 0X622D, 0XA0D9,  /* 0X1D18 - 0X1D1F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07C,  /* 0X1D20 - 0X1D27 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C7,  /* 0X1D28 - 0X1D2F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A3,  /* 0X1D30 - 0X1D37 */
   0X5300, 0X7210, 0X6239, 0XA058, 0X6234, 0X901E, 0X623D, 0XA0EA,  /* 0X1D38 - 0X1D3F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA073,  /* 0X1D40 - 0X1D47 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BD,  /* 0X1D48 - 0X1D4F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09B,  /* 0X1D50 - 0X1D57 */
   0X5300, 0X70FF, 0X6229, 0XA04E, 0X6233, 0X901A, 0X622D, 0XA0E2,  /* 0X1D58 - 0X1D5F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08A,  /* 0X1D60 - 0X1D67 */
   0X5227, 0X700A, 0X6238, 0XA02D, 0X6223, 0X80FE, 0X623C, 0XA0D1,  /* 0X1D68 - 0X1D6F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AC,  /* 0X1D70 - 0X1D77 */
   0X5300, 0X7220, 0X6239, 0XA062, 0X6234, 0X9024, 0X623D, 0XA0F7,  /* 0X1D78 - 0X1D7F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06E,  /* 0X1D80 - 0X1D87 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0B9,  /* 0X1D88 - 0X1D8F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA097,  /* 0X1D90 - 0X1D97 */
   0X5300, 0X7080, 0X6229, 0XA04A, 0X6233, 0X9016, 0X622D, 0XA0DD,  /* 0X1D98 - 0X1D9F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA085,  /* 0X1DA0 - 0X1DA7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CB,  /* 0X1DA8 - 0X1DAF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A7,  /* 0X1DB0 - 0X1DB7 */
   0X5300, 0X7210, 0X6239, 0XA05D, 0X6234, 0X9021, 0X623D, 0XA0EF,  /* 0X1DB8 - 0X1DBF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA077,  /* 0X1DC0 - 0X1DC7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C2,  /* 0X1DC8 - 0X1DCF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA09F,  /* 0X1DD0 - 0X1DD7 */
   0X5300, 0X70FF, 0X6229, 0XA054, 0X6233, 0X901C, 0X622D, 0XA0E6,  /* 0X1DD8 - 0X1DDF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08E,  /* 0X1DE0 - 0X1DE7 */
   0X5227, 0X700A, 0X6238, 0XA034, 0X6223, 0X823E, 0X623C, 0XA0D5,  /* 0X1DE8 - 0X1DEF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B0,  /* 0X1DF0 - 0X1DF7 */
   0X5300, 0X7220, 0X6239, 0XA066, 0X6234, 0X9026, 0X623D, 0XA230,  /* 0X1DF8 - 0X1DFF */
   0X5224, 0X622E, 0X6225, 0X9027, 0X6000, 0X7221, 0X622A, 0XA069,  /* 0X1E00 - 0X1E07 */
   0X5227, 0X7007, 0X6228, 0X90C0, 0X6232, 0X8018, 0X622C, 0XA0B4,  /* 0X1E08 - 0X1E0F */
   0X5226, 0X7003, 0X6236, 0X9042, 0X6002, 0X800B, 0X622B, 0XA092,  /* 0X1E10 - 0X1E17 */
   0X5300, 0X7080, 0X6229, 0XA03B, 0X6233, 0X9012, 0X622D, 0XA0D8,  /* 0X1E18 - 0X1E1F */
   0X5224, 0X6301, 0X6235, 0X9035, 0X6001, 0X7302, 0X623A, 0XA07B,  /* 0X1E20 - 0X1E27 */
   0X5227, 0X7009, 0X6238, 0X90F4, 0X6223, 0X8060, 0X623C, 0XA0C5,  /* 0X1E28 - 0X1E2F */
   0X5226, 0X7005, 0X6237, 0X9070, 0X6222, 0X800F, 0X623B, 0XA0A2,  /* 0X1E30 - 0X1E37 */
   0X5300, 0X7210, 0X6239, 0XA057, 0X6234, 0X901D, 0X623D, 0XA0E9,  /* 0X1E38 - 0X1E3F */
   0X5224, 0X622E, 0X6225, 0X902C, 0X6000, 0X7231, 0X622A, 0XA072,  /* 0X1E40 - 0X1E47 */
   0X5227, 0X7008, 0X6228, 0X90E0, 0X6232, 0X8020, 0X622C, 0XA0BC,  /* 0X1E48 - 0X1E4F */
   0X5226, 0X7004, 0X6236, 0X9049, 0X6002, 0X800D, 0X622B, 0XA09A,  /* 0X1E50 - 0X1E57 */
   0X5300, 0X70FF, 0X6229, 0XA04D, 0X6233, 0X9017, 0X622D, 0XA0E1,  /* 0X1E58 - 0X1E5F */
   0X5224, 0X6301, 0X6235, 0X903C, 0X6001, 0X7303, 0X623A, 0XA089,  /* 0X1E60 - 0X1E67 */
   0X5227, 0X700A, 0X6238, 0XA02B, 0X6223, 0X80FE, 0X623C, 0XA0CF,  /* 0X1E68 - 0X1E6F */
   0X5226, 0X7006, 0X6237, 0X9082, 0X6222, 0X8011, 0X623B, 0XA0AA,  /* 0X1E70 - 0X1E77 */
   0X5300, 0X7220, 0X6239, 0XA061, 0X6234, 0X9022, 0X623D, 0XA0F6,  /* 0X1E78 - 0X1E7F */
   0X5224, 0X622E, 0X6225, 0X9029, 0X6000, 0X7221, 0X622A, 0XA06D,  /* 0X1E80 - 0X1E87 */
   0X5227, 0X7007, 0X6228, 0X90CC, 0X6232, 0X8019, 0X622C, 0XA0B8,  /* 0X1E88 - 0X1E8F */
   0X5226, 0X7003, 0X6236, 0X9044, 0X6002, 0X800C, 0X622B, 0XA096,  /* 0X1E90 - 0X1E97 */
   0X5300, 0X7080, 0X6229, 0XA047, 0X6233, 0X9015, 0X622D, 0XA0DC,  /* 0X1E98 - 0X1E9F */
   0X5224, 0X6301, 0X6235, 0X9038, 0X6001, 0X7302, 0X623A, 0XA083,  /* 0X1EA0 - 0X1EA7 */
   0X5227, 0X7009, 0X6238, 0X90FC, 0X6223, 0X80F0, 0X623C, 0XA0CA,  /* 0X1EA8 - 0X1EAF */
   0X5226, 0X7005, 0X6237, 0X907F, 0X6222, 0X8010, 0X623B, 0XA0A6,  /* 0X1EB0 - 0X1EB7 */
   0X5300, 0X7210, 0X6239, 0XA05C, 0X6234, 0X901F, 0X623D, 0XA0ED,  /* 0X1EB8 - 0X1EBF */
   0X5224, 0X622E, 0X6225, 0X9031, 0X6000, 0X7231, 0X622A, 0XA076,  /* 0X1EC0 - 0X1EC7 */
   0X5227, 0X7008, 0X6228, 0X90F1, 0X6232, 0X8040, 0X622C, 0XA0C1,  /* 0X1EC8 - 0X1ECF */
   0X5226, 0X7004, 0X6236, 0X9051, 0X6002, 0X800E, 0X622B, 0XA09E,  /* 0X1ED0 - 0X1ED7 */
   0X5300, 0X70FF, 0X6229, 0XA053, 0X6233, 0X901B, 0X622D, 0XA0E5,  /* 0X1ED8 - 0X1EDF */
   0X5224, 0X6301, 0X6235, 0X903F, 0X6001, 0X7303, 0X623A, 0XA08D,  /* 0X1EE0 - 0X1EE7 */
   0X5227, 0X700A, 0X6238, 0XA032, 0X6223, 0X823E, 0X623C, 0XA0D4,  /* 0X1EE8 - 0X1EEF */
   0X5226, 0X7006, 0X6237, 0X9088, 0X6222, 0X8013, 0X623B, 0XA0AF,  /* 0X1EF0 - 0X1EF7 */
   0X5300, 0X7220, 0X6239, 0XA065, 0X6234, 0X9025, 0X623D, 0XA0FB,  /* 0X1EF8 - 0X1EFF */
   0X5224, 0X622E, 0X6225, 0X9028, 0X6000, 0X7221, 0X622A, 0XA06B,  /* 0X1F00 - 0X1F07 */
   0X5227, 0X7007, 0X6228, 0X90C6, 0X6232, 0X8018, 0X622C, 0XA0B6,  /* 0X1F08 - 0X1F0F */
   0X5226, 0X7003, 0X6236, 0X9043, 0X6002, 0X800B, 0X622B, 0XA094,  /* 0X1F10 - 0X1F17 */
   0X5300, 0X7080, 0X6229, 0XA045, 0X6233, 0X9014, 0X622D, 0XA0DA,  /* 0X1F18 - 0X1F1F */
   0X5224, 0X6301, 0X6235, 0X9037, 0X6001, 0X7302, 0X623A, 0XA07D,  /* 0X1F20 - 0X1F27 */
   0X5227, 0X7009, 0X6238, 0X90F8, 0X6223, 0X8060, 0X623C, 0XA0C8,  /* 0X1F28 - 0X1F2F */
   0X5226, 0X7005, 0X6237, 0X9078, 0X6222, 0X800F, 0X623B, 0XA0A4,  /* 0X1F30 - 0X1F37 */
   0X5300, 0X7210, 0X6239, 0XA05A, 0X6234, 0X901E, 0X623D, 0XA0EB,  /* 0X1F38 - 0X1F3F */
   0X5224, 0X622E, 0X6225, 0X9030, 0X6000, 0X7231, 0X622A, 0XA074,  /* 0X1F40 - 0X1F47 */
   0X5227, 0X7008, 0X6228, 0X90EE, 0X6232, 0X8020, 0X622C, 0XA0BE,  /* 0X1F48 - 0X1F4F */
   0X5226, 0X7004, 0X6236, 0X9050, 0X6002, 0X800D, 0X622B, 0XA09C,  /* 0X1F50 - 0X1F57 */
   0X5300, 0X70FF, 0X6229, 0XA04F, 0X6233, 0X901A, 0X622D, 0XA0E3,  /* 0X1F58 - 0X1F5F */
   0X5224, 0X6301, 0X6235, 0X903E, 0X6001, 0X7303, 0X623A, 0XA08B,  /* 0X1F60 - 0X1F67 */
   0X5227, 0X700A, 0X6238, 0XA02E, 0X6223, 0X80FE, 0X623C, 0XA0D2,  /* 0X1F68 - 0X1F6F */
   0X5226, 0X7006, 0X6237, 0X9084, 0X6222, 0X8011, 0X623B, 0XA0AD,  /* 0X1F70 - 0X1F77 */
   0X5300, 0X7220, 0X6239, 0XA063, 0X6234, 0X9024, 0X623D, 0XA0F9,  /* 0X1F78 - 0X1F7F */
   0X5224, 0X622E, 0X6225, 0X902A, 0X6000, 0X7221, 0X622A, 0XA06F,  /* 0X1F80 - 0X1F87 */
   0X5227, 0X7007, 0X6228, 0X90D0, 0X6232, 0X8019, 0X622C, 0XA0BA,  /* 0X1F88 - 0X1F8F */
   0X5226, 0X7003, 0X6236, 0X9048, 0X6002, 0X800C, 0X622B, 0XA098,  /* 0X1F90 - 0X1F97 */
   0X5300, 0X7080, 0X6229, 0XA04B, 0X6233, 0X9016, 0X622D, 0XA0DE,  /* 0X1F98 - 0X1F9F */
   0X5224, 0X6301, 0X6235, 0X9039, 0X6001, 0X7302, 0X623A, 0XA086,  /* 0X1FA0 - 0X1FA7 */
   0X5227, 0X7009, 0X6238, 0X90FD, 0X6223, 0X80F0, 0X623C, 0XA0CD,  /* 0X1FA8 - 0X1FAF */
   0X5226, 0X7005, 0X6237, 0X9081, 0X6222, 0X8010, 0X623B, 0XA0A8,  /* 0X1FB0 - 0X1FB7 */
   0X5300, 0X7210, 0X6239, 0XA05E, 0X6234, 0X9021, 0X623D, 0XA0F3,  /* 0X1FB8 - 0X1FBF */
   0X5224, 0X622E, 0X6225, 0X9033, 0X6000, 0X7231, 0X622A, 0XA079,  /* 0X1FC0 - 0X1FC7 */
   0X5227, 0X7008, 0X6228, 0X90F2, 0X6232, 0X8040, 0X622C, 0XA0C3,  /* 0X1FC8 - 0X1FCF */
   0X5226, 0X7004, 0X6236, 0X9059, 0X6002, 0X800E, 0X622B, 0XA0A0,  /* 0X1FD0 - 0X1FD7 */
   0X5300, 0X70FF, 0X6229, 0XA055, 0X6233, 0X901C, 0X622D, 0XA0E7,  /* 0X1FD8 - 0X1FDF */
   0X5224, 0X6301, 0X6235, 0X9041, 0X6001, 0X7303, 0X623A, 0XA08F,  /* 0X1FE0 - 0X1FE7 */
   0X5227, 0X700A, 0X6238, 0XA036, 0X6223, 0X823E, 0X623C, 0XA0D6,  /* 0X1FE8 - 0X1FEF */
   0X5226, 0X7006, 0X6237, 0X9090, 0X6222, 0X8013, 0X623B, 0XA0B1,  /* 0X1FF0 - 0X1FF7 */
   0X5300, 0X7220, 0X6239, 0XA067, 0X6234, 0X9026, 0X623D, 0XD925   /* 0X1FF8 - 0X1FFF */
};

/**
   second step
*/
static const unsigned short int usrs_rdp60_decode_2[ 1 << VAL_TAB_R60_D2_L ] = {
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0000 - 0X0007 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7052,  /* 0X0008 - 0X000F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6071,  /* 0X0010 - 0X0017 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X8063,  /* 0X0018 - 0X001F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0020 - 0X0027 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7043,  /* 0X0028 - 0X002F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6042,  /* 0X0030 - 0X0037 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9026,  /* 0X0028 - 0X003F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0040 - 0X0047 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7062,  /* 0X0048 - 0X004F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6071,  /* 0X0050 - 0X0057 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9073,  /* 0X0058 - 0X005F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0060 - 0X0067 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X8072,  /* 0X0068 - 0X006F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6042,  /* 0X0070 - 0X0077 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X900E,  /* 0X0078 - 0X007F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0080 - 0X0087 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7052,  /* 0X0088 - 0X008F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6071,  /* 0X0090 - 0X0097 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X8054,  /* 0X0098 - 0X009F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X00A0 - 0X00A7 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7043,  /* 0X00A8 - 0X00AF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6042,  /* 0X00B0 - 0X00B7 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9018,  /* 0X00B8 - 0X00BF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X00C0 - 0X00C7 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7062,  /* 0X00C8 - 0X00CF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6071,  /* 0X00D0 - 0X00D7 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9064,  /* 0X00D8 - 0X00DF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X00E0 - 0X00E7 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X8053,  /* 0X00E8 - 0X00EF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6042,  /* 0X00F0 - 0X00F7 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9000,  /* 0X00F8 - 0X00FF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0100 - 0X0107 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7052,  /* 0X0108 - 0X010F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6071,  /* 0X0110 - 0X0117 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X8063,  /* 0X0118 - 0X011F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0120 - 0X0127 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7043,  /* 0X0128 - 0X012F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6042,  /* 0X0130 - 0X0137 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9036,  /* 0X0138 - 0X013F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0140 - 0X0147 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7062,  /* 0X0148 - 0X014F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6071,  /* 0X0150 - 0X0157 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9044,  /* 0X0158 - 0X015F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0160 - 0X0167 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X8072,  /* 0X0168 - 0X016F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6042,  /* 0X0170 - 0X0177 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X900E,  /* 0X0178 - 0X017F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X0180 - 0X0187 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7052,  /* 0X0188 - 0X018F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6071,  /* 0X0190 - 0X0197 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X8054,  /* 0X0198 - 0X019F */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X01A0 - 0X01A7 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7043,  /* 0X01A8 - 0X01AF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6042,  /* 0X01B0 - 0X01B7 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9028,  /* 0X01B8 - 0X01BF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X01C0 - 0X01C7 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X7062,  /* 0X01C8 - 0X01CF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6071,  /* 0X01D0 - 0X01D7 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9074,  /* 0X01D8 - 0X01DF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X5061,  /* 0X01E0 - 0X01E7 */
   0X2010, 0X4030, 0X3020, 0X5070, 0X2010, 0X4060, 0X3040, 0X8053,  /* 0X01E8 - 0X01EF */
   0X2010, 0X4000, 0X3020, 0X4041, 0X2010, 0X4050, 0X3040, 0X6042,  /* 0X01F0 - 0X01F7 */
   0X2010, 0X4030, 0X3020, 0X5051, 0X2010, 0X4060, 0X3040, 0X9000   /* 0X01F8 - 0X01FF */
};

static const unsigned short int usrs_rdp60_offset_1[] = {
   0X0000, 0X0001, 0X0002, 0X0003, 0X0004, 0X0006, 0X0008, 0X000C,  /* 0X00 - 0X07 */
   0X0010, 0X0018, 0X0020, 0X0030, 0X0040, 0X0060, 0X0080, 0X00C0,  /* 0X08 - 0X10 */
   0X0100, 0X0180, 0X0200, 0X0300, 0X0400, 0X0600, 0X0800, 0X0C00,  /* 0X10 - 0X17 */
   0X1000, 0X1800, 0X2000, 0X3000, 0X4000, 0X6000, 0X8000, 0XC000   /* 0X18 - 0X1F */
};

static const unsigned char ucrs_rdp60_offset_2[] = {
    0,  0,  0,  0,  1,  1,  2,  2,          /* 0X00 - 0X07             */
    3,  3,  4,  4,  5,  5,  6,  6,          /* 0X08 - 0X0F             */
    7,  7,  8,  8,  9,  9, 10, 10,          /* 0X10 - 0X17             */
   11, 11, 12, 12, 13, 13, 14, 14           /* 0X18 - 0X1F             */
};

#ifdef XYZ1
static const unsigned short int usrs_rdp60_length_1[] = {
   0X0002, 0X0003, 0X0004, 0X0005, 0X0006, 0X0007, 0X0008, 0X0009,  /* 0X00 - 0X07 */
   0X000A, 0X000C, 0X000E, 0X0010, 0X0012, 0X0016, 0X001A, 0X001E,  /* 0X08 - 0X10 */
   0X0022, 0X002A, 0X0032, 0X003A, 0X0042, 0X0052, 0X0062, 0X0072,  /* 0X10 - 0X17 */
   0X0082, 0X00C2, 0X0102, 0X0202                                   /* 0X18 - 0X1B */
};

static const unsigned char ucrs_rdp60_length_2[] = {
    0,  0,  0,  0,  0,  0,  0,  0,          /* 0X00 - 0X07             */
    1,  1,  1,  1,  2,  2,  2,  2,          /* 0X08 - 0X0F             */
    3,  3,  3,  3,  4,  4,  4,  4,          /* 0X10 - 0X17             */
    6,  6,  8,  8, 14                       /* 0X18 - 0X1C             */
};

static const unsigned char ucrs_rdp60_length_3[] = {
    4,  2,  3,  4,  3,  4,  4,  5,          /* 0X00 - 0X07             */
    4,  5,  5,  6,  6,  7,  7,  8,          /* 0X08 - 0X0F             */
    7,  8,  8,  9,  9,  8,  9,  9,          /* 0X10 - 0X17             */
    9,  9,  9,  9,  9                       /* 0X18 - 0X1C             */
};

static const unsigned short int usrs_rdp60_length_4[] = {
   0X0001, 0X0000, 0X0002, 0X0009, 0X0006, 0X0005, 0X000D, 0X000B,  /* 0X00 - 0X07 */
   0X0003, 0X001B, 0X0007, 0X0017, 0X0037, 0X000F, 0X004F, 0X006F,  /* 0X08 - 0X10 */
   0X002F, 0X00EF, 0X001F, 0X005F, 0X015F, 0X009F, 0X00DF, 0X01DF,  /* 0X10 - 0X17 */
   0X003F, 0X013F, 0X00BF, 0X01BF                                   /* 0X18 - 0X1B */
};
#endif
/* attention, last value is special encoding                           */
static const unsigned short int usrs_rdp60_length_1[] = {
   0X0002, 0X0003, 0X0004, 0X0005, 0X0006, 0X0007, 0X0008, 0X0009,  /* 0X00 - 0X07 */
   0X000A, 0X000C, 0X000E, 0X0010, 0X0012, 0X0016, 0X001A, 0X001E,  /* 0X08 - 0X10 */
   0X0022, 0X002A, 0X0032, 0X003A, 0X0042, 0X0052, 0X0062, 0X0072,  /* 0X10 - 0X17 */
   0X0082, 0X00C2, 0X0102, 0X0202, 0X0002                           /* 0X18 - 0X1C */
};

static const unsigned char ucrs_rdp60_length_2[] = {
    0,  0,  0,  0,  0,  0,  0,  0,          /* 0X00 - 0X07             */
    1,  1,  1,  1,  2,  2,  2,  2,          /* 0X08 - 0X0F             */
    3,  3,  3,  3,  4,  4,  4,  4,          /* 0X10 - 0X17             */
    6,  6,  8,  8, 14                       /* 0X18 - 0X1C             */
};

static const unsigned char ucrs_rdp60_length_3[] = {
    4,  2,  3,  4,  3,  4,  4,  5,          /* 0X00 - 0X07             */
    4,  5,  5,  6,  6,  7,  7,  8,          /* 0X08 - 0X0F             */
    7,  8,  8,  9,  9,  8,  9,  9,          /* 0X10 - 0X17             */
    9,  9,  9,  9,  9                       /* 0X18 - 0X1C             */
};

static const unsigned short int usrs_rdp60_length_4[] = {
   0X0001, 0X0000, 0X0002, 0X0009, 0X0006, 0X0005, 0X000D, 0X000B,  /* 0X00 - 0X07 */
   0X0003, 0X001B, 0X0007, 0X0017, 0X0037, 0X000F, 0X004F, 0X006F,  /* 0X08 - 0X10 */
   0X002F, 0X00EF, 0X001F, 0X005F, 0X015F, 0X009F, 0X00DF, 0X01DF,  /* 0X10 - 0X17 */
   0X003F, 0X013F, 0X00BF, 0X01BF, 0X007F                           /* 0X18 - 0X1C */
};

#ifdef TRACEHL2
static int    ims_tracehl2 = 0;
#endif
#ifdef TRACEHL3
static int    ims_tracehl3 = 0;
#endif
#ifdef DEBUG_110519_03
static int    ims_match_enc = 0;
static int    ims_match_dec = 0;
#endif
#ifdef XYZ1
#define CHAR_CR        0X0D                 /* carriage-return         */
#define CHAR_LF        0X0A                 /* line-feed               */

static struct dsd_gather_i_1 dss_gai1_empty = { NULL, NULL, NULL };
#endif

/*+--------------------------------------------------------------------------+*/
/*| Main control procedure.                                                  |*/
/*+--------------------------------------------------------------------------+*/

extern "C" void D_M_CDX_ENC( struct dsd_cdr_ctrl *adsp_cdr_ctrl )  /* encode = compression */
{
   /* The encoder function builds the compressed data in the
      output area. If the compressed data is larger than the
      transparent data, the transparent data is moved to the output
      area.                                                            */
   /* Declare local variables.                                         */
   struct dsd_enc_int *adsl_enc_int;        /* fields for encode       */
   struct dsd_gather_i_1 *adsl_gai1_in_w1;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_in_w2;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_in_w3;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_in_w4;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_in_base;  /* base to compare       */
   struct dsd_gather_i_1 *adsl_gai1_in_all;  /* all input data         */
   struct dsd_stor_ext *adsl_stor_ext_w1;   /* external storage acquired */
   struct dsd_stor_ext *adsl_stor_ext_w2;   /* external storage acquired */
   int        *aimrl_rdp4o5_co_off_len_total;
   int        *aimrl_rdp4o5_co_off_lead_bits;
   int        *aimrl_rdp4o5_co_off_add;
   unsigned char ucl_w1;                    /* working variable        */
   unsigned char ucl_inp_cur;               /* current input           */
   unsigned char ucl_inp_previous;          /* previous input          */
   unsigned char ucl_hist_previous;         /* previous character in history buffer */
#ifdef DEBUG_110519_01
   unsigned char ucl_debug_previous;        /* previous character in history buffer */
   int        iml_debug_line_1;
   int        iml_debug_line_2;
#endif
#ifdef DEBUG_110519_03
   int        iml_save_match_enc;
#endif
   int        iml_rdp4o5_co_off_add_max;
   int        iml_len_hist_bu;              /* length history buffer   */
   int        iml_len_inp;                  /* length of input         */
   int        iml_len_out;                  /* length of output        */
   int        iml_match_min_m1;             /* minimum match searched (minus one) */
   int        iml_match_max;                /* maximum match encoded   */
#ifndef D_LONG_SHIFT
   int        iml_shift_v;                  /* shift-value             */
#else
   long long int iml_shift_v;               /* shift-value             */
#endif
   int        iml_shift_c;                  /* shift-count             */
   int        iml_cur_pos;                  /* current position        */
   int        iml_copy_pos;                 /* copy position           */
   int        iml1, iml2, iml3, iml4, iml5;  /* working variables      */
   int        iml_cmp_max;                  /* compare maximum found   */
   int        iml_cmp_now;                  /* current compare length  */
   BOOL       bol_out_huffman;              /* output is huffman encoded */
   BOOL       bol_previous_char;            /* previous character filled */
   BOOL       bol_previous_fit;             /* previous character fits */
#ifdef XYZ1
   short int  isl1;                         /* working variable        */
   short int  isl2;                         /* working variable        */
#endif
   char       *achl_inp;                    /* current input           */
   char       *achl_base;                   /* base to compare         */
   char       *achl_w1, *achl_w2;           /* working variables       */
#ifdef XYZ1
   char       *achl1;                       /* working variable        */
   char       *achl2;                       /* working variable        */
#endif
   char       *achl_cmp_c1;                 /* for compare             */
   char       *achl_cmp_c2;                 /* for compare             */
   char       *achl_cmp_end;                /* end of compare          */
   BOOL       bol1;                         /* working variable        */
   struct dsd_stor_ext *adsl_aux_st_w1;     /* auxiliary storage       */
#ifdef TRACEHL1
   struct dsd_stor_ext *adsl_aux_st_w2;     /* auxiliary storage       */
#endif
#ifdef XYZ1
   struct dsd_inp_st *adsl_inp_st_w1;       /* input storage           */
   struct dsd_inp_st *adsl_inp_st_w2;       /* input storage           */
#endif
// char       *achl_histbu_end;             /* end of history buffer   */
   char       *achl_histbu_cur;             /* current position in history buffer */
   char       *achl_histbu_max;             /* maximum reached position in history buffer */
   char       *achl_histbu_proc;            /* processing history buffer till here */
   char       *achl_saved_histbu_cur;       /* saved current position in history buffer */
   char       *achl_saved_histbu_max;       /* saved maximum reached position in history buffer */
   struct dsd_entry_r4a5 *adsl_entry_r4a5_start;  /* entry RDP4 and RDP5 start */
   struct dsd_entry_r4a5 *adsl_entry_r4a5_cur;  /* entry RDP4 and RDP5 current */
   struct dsd_node_r4a5 *adsl_node_r4a5;    /* node RDP4 and RDP5      */
   int        imrl_cache_off[ VAL_CACHE_OFF + 1 ];  /* RDP6.0 cache offset */
   struct dsd_out_1 dsl_out_1;              /* output pointers         */
#ifdef TRACEHL1
   char *achl_cmp_end_trace_02 = NULL;
   char *achl_histbu_cur_trace_02 = NULL;
   char *achl_cmp_c2_trace_02 = NULL;
   char *achl_cmp_c1_trace_02 = NULL;
   int iml_cmp_now_trace_02 = 0;
#endif

   if (adsp_cdr_ctrl->imc_func == DEF_IFUNC_CONT) goto pecco00;
   if (adsp_cdr_ctrl->imc_func != DEF_IFUNC_START) goto pecfunc;
   /* function start                                                   */
#define D_SIZE_RDP60 (64 * 1024 \
                        + D_MAX_BYTE * sizeof(struct dsd_entry_r4a5) \
                        + (64 * 1024) / 2 * sizeof(struct dsd_node_r4a5) \
                        + sizeof(imrl_cache_off))

   switch (adsp_cdr_ctrl->imc_param_1) {    /* type of compression     */
     case 40:                               /* RDP4                    */
       iml_len_hist_bu = 8192;              /* size history buffer RDP4 */
       iml1 = 8192 + D_MAX_BYTE * sizeof(struct dsd_entry_r4a5)
                + 8192 / 2 * sizeof(struct dsd_node_r4a5);
       break;
     case 50:                               /* RDP5                    */
       iml_len_hist_bu = 64 * 1024;
       iml1 = 64 * 1024
                + D_MAX_BYTE * sizeof(struct dsd_entry_r4a5)
                + (64 * 1024) / 2 * sizeof(struct dsd_node_r4a5);
       break;
     case 60:                               /* RDP6.0                  */
       iml_len_hist_bu = 64 * 1024;
       iml1 = D_SIZE_RDP60;
       break;
     default:
#ifdef TRACEHL1
       printf( "ENC l%05d start imc_param_1=%d invalid value / allowed: 40 50 60.\n",
               __LINE__, adsp_cdr_ctrl->imc_param_1 );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error   */
       return;                              /* return to main-prog     */
   }
   bol1 = (*adsp_cdr_ctrl->amc_aux)( adsp_cdr_ctrl->vpc_userfld,  /* get memory */
                                     DEF_AUX_MEMGET,
                                     &adsl_enc_int,
                                     sizeof(struct dsd_enc_int)
                                       + iml1 );  /* history buffer and nodes */
   if (bol1 == FALSE) {
     adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error     */
     return;                                /* return to main-prog     */
   }
   memset( adsl_enc_int, 0, sizeof(struct dsd_enc_int) );  /* clear buffer */
   adsl_enc_int->adsc_entry_r4a5
     = (struct dsd_entry_r4a5 *) ((char *) (adsl_enc_int + 1) + iml_len_hist_bu);  /* entry RDP4/5 */
   adsl_enc_int->adsc_node_r4a5
     = (struct dsd_node_r4a5 *) ((char *) (adsl_enc_int + 1) + iml_len_hist_bu
                                          + D_MAX_BYTE * sizeof(struct dsd_entry_r4a5));  /* node RDP4/5 */
   memset( adsl_enc_int->adsc_entry_r4a5, 0XFF, D_MAX_BYTE * sizeof(struct dsd_entry_r4a5) );
   adsl_enc_int->achc_histbu_cur = (char *) (adsl_enc_int + 1);  /* current position in history buffer */
   adsl_enc_int->achc_histbu_max = (char *) (adsl_enc_int + 1);  /* maximum reached position in history buffer */
   adsp_cdr_ctrl->ac_ext = adsl_enc_int;    /* store address of fields */
   adsp_cdr_ctrl->imc_len_header = 1;       /* length of header data   */
   adsp_cdr_ctrl->boc_compressed = TRUE;    /* output always compressed */
   adsp_cdr_ctrl->imc_func = DEF_IFUNC_CONT;  /* next call continue    */
   adsp_cdr_ctrl->imc_return = DEF_IRET_NORMAL;  /* call subroutine again */
#ifdef TRACEHLH
   adsl_enc_int->icountx = 0;
#endif
#ifndef B120403
   adsl_enc_int->chc_comp_header = 0;       /* value for compression header */
   if (adsp_cdr_ctrl->imc_param_1 == 50) {  /* not RDP5                */
     adsl_enc_int->chc_comp_header = 1;     /* value for compression header */
   }
#endif
   if (adsp_cdr_ctrl->imc_param_1 != 60) return;  /* not RDP6.0        */
#ifndef B120403
   adsl_enc_int->chc_comp_header = 2;       /* value for compression header */
#endif
   /* prepare RDP6.0 cache offset                                      */
   memset( (char *) (adsl_enc_int + 1) + D_SIZE_RDP60 - sizeof(imrl_cache_off),
           0XFF,
           sizeof(imrl_cache_off) - sizeof(int) );
   *((int *) ((char *) (adsl_enc_int + 1) + D_SIZE_RDP60 - sizeof(int))) = 0;
   return;                                  /* return to main program  */

   pecfunc:                                 /* other function received */
   adsp_cdr_ctrl->imc_return = DEF_IRET_END;  /* all done              */
   if (adsp_cdr_ctrl->imc_func != DEF_IFUNC_END) {
#ifdef TRACEHL1
     printf( "ENC l%05d invalid function %d.\n", __LINE__, adsp_cdr_ctrl->imc_func );
#endif
     adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error     */
   }
   while (((struct dsd_enc_int *) adsp_cdr_ctrl->ac_ext)->adsc_stor_ext) {
     adsl_aux_st_w1 = ((struct dsd_enc_int *) adsp_cdr_ctrl->ac_ext)->adsc_stor_ext;
     ((struct dsd_enc_int *) adsp_cdr_ctrl->ac_ext)->adsc_stor_ext = adsl_aux_st_w1->adsc_next;
     bol1 = (*adsp_cdr_ctrl->amc_aux)( adsp_cdr_ctrl->vpc_userfld, DEF_AUX_MEMFREE, &adsl_aux_st_w1, LEN_AUX_STOR );
     if (bol1 == FALSE) {
       adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error   */
       return;                              /* return to main-prog     */
     }
   }
   bol1 = (*adsp_cdr_ctrl->amc_aux)( adsp_cdr_ctrl->vpc_userfld,
                                     DEF_AUX_MEMFREE,
                                     &adsp_cdr_ctrl->ac_ext,
                                     0 );   /* free memory             */
   if (bol1 == FALSE) {
     adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error     */
     return;                                /* return to main-prog     */
   }
   return;                                  /* return to main program  */

   pecco00:                                 /* continue encode         */
   adsl_enc_int = (struct dsd_enc_int *) adsp_cdr_ctrl->ac_ext;  /* get address of fields */
   bol_out_huffman = FALSE;                 /* output is not huffman encoded */
   iml_match_min_m1 = 3 - 1;                /* minimum match searched (minus one) */
   switch (adsp_cdr_ctrl->imc_param_1) {    /* type of compression     */
     case 40:                               /* RDP4                    */
       iml_len_hist_bu = 8192;
       iml_match_max = 8192 - 1;            /* maximum match encoded   */
#ifndef B120403
       adsl_enc_int->chc_comp_header = 0;   /* value for compression header */
#endif
       break;
     case 50:                               /* RDP5                    */
       iml_len_hist_bu = 64 * 1024;
       iml_match_max = 64 * 1024 - 1;       /* maximum match encoded   */
#ifndef B120403
       adsl_enc_int->chc_comp_header = 1;   /* value for compression header */
#endif
       break;
     case 60:                               /* RDP6.0                  */
       iml_len_hist_bu = 64 * 1024;
       bol_out_huffman = TRUE;              /* output is huffman encoded */
       iml_match_min_m1 = 2 - 1;            /* minimum match searched (minus one) */
       iml_match_max = 16385;               /* maximum match encoded   */
       /* copy RDP6.0 cache offset                                     */
       memcpy( imrl_cache_off,
               (char *) (adsl_enc_int + 1)
                 + 64 * 1024
                 + D_MAX_BYTE * sizeof(struct dsd_entry_r4a5)
                 + (64 * 1024) / 2 * sizeof(struct dsd_node_r4a5),
               sizeof(imrl_cache_off) );
       break;
     default:
#ifdef TRACEHL1
       printf( "ENC l%05d pecco00 imc_param_1=%d invalid value / allowed: 40 50 60.\n",
               __LINE__, adsp_cdr_ctrl->imc_param_1 );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error   */
       return;                              /* return to main-prog     */
   }
   adsl_gai1_in_w1 = adsp_cdr_ctrl->adsc_gai1_in;  /* get input data   */
   while (   (adsl_gai1_in_w1)
          && (adsl_gai1_in_w1->achc_ginp_cur >= adsl_gai1_in_w1->achc_ginp_end)) {
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
   }
   adsl_gai1_in_w2 = adsl_gai1_in_w1;       /* get input data          */
   iml_len_inp = 0;                         /* clear length of input   */
   while (adsl_gai1_in_w1) {                /* loop over all gather input */
     iml_len_inp += adsl_gai1_in_w1->achc_ginp_end - adsl_gai1_in_w1->achc_ginp_cur;
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
   }
#ifdef TRACEHL1
   printf( "ENC l%05d pecco00 new input length=%d/0X%p boc_mp_flush=%d.\n",
           __LINE__,
           iml_len_inp,
           iml_len_inp,
           adsp_cdr_ctrl->boc_mp_flush );
   if (adsl_gai1_in_w2) {                   /* input given             */
     m_console_gather( adsl_gai1_in_w2 );
   }
#endif
#ifdef TRY_110516_01
   adsp_cdr_ctrl->boc_sr_flush = FALSE;     /* not at end of data      */
#endif
   if (adsl_enc_int->adsc_gai1_out_saved) {  /* output data saved      */
     goto p_ecco_out_20;                    /* pass saved output data  */
   }
   if (adsp_cdr_ctrl->boc_mp_flush) {       /* all input data passed   */
     goto pecco40;                          /* start compression       */
   }
#ifndef TRY_110516_01
   adsp_cdr_ctrl->boc_sr_flush = FALSE;     /* not at end of data      */
#endif
   if (iml_len_inp <= 0) {                  /* no input                */
     return;                                /* return to main program  */
   }
   adsl_gai1_in_w3 = adsl_enc_int->adsc_gai1_in_saved;  /* input data saved */
   while (adsl_gai1_in_w3) {                /* loop over all saved gather */
     iml_len_inp += adsl_gai1_in_w3->achc_ginp_end - adsl_gai1_in_w3->achc_ginp_cur;
     adsl_gai1_in_w1 = adsl_gai1_in_w3;     /* save last in chain      */
     adsl_gai1_in_w3 = adsl_gai1_in_w3->adsc_next;  /* get next in chain */
   }
   if (iml_len_inp > iml_len_hist_bu) {     /* input data too long     */
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error     */
     return;                                /* report error            */
   }
   bol1 = FALSE;                            /* do not use start chain external storage */
   if (adsl_gai1_in_w1) {                   /* we have saved data      */
     bol1 = TRUE;                           /* use start chain external storage */
   }
   if (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1))) {
     adsl_gai1_in_w3 = (struct dsd_gather_i_1 *) adsp_cdr_ctrl->achc_save_mp;
     if (adsl_gai1_in_w1 == NULL) {         /* first time to save data */
       memset( adsl_gai1_in_w3, 0, sizeof(struct dsd_gather_i_1) );
       adsl_gai1_in_w3->achc_ginp_cur = adsl_gai1_in_w3->achc_ginp_end = (char *) (adsl_gai1_in_w3 + 1);
       adsl_enc_int->adsc_gai1_in_saved = adsl_gai1_in_w1 = adsl_gai1_in_w3;  /* set for next call */
     }
     iml1                                   /* space in area given     */
       = (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given)
           - adsl_gai1_in_w3->achc_ginp_end;
     if (iml1 > 0) {                        /* we can save data here   */
       while (TRUE) {
         while (adsl_gai1_in_w2->achc_ginp_cur >= adsl_gai1_in_w2->achc_ginp_end) {
           adsl_gai1_in_w2 = adsl_gai1_in_w2->adsc_next;
           if (adsl_gai1_in_w2 == NULL) {   /* end of input reached    */
#ifdef TRACEHL1
             goto pec_tr_00;                /* display areas of memory saved */
#else
             return;                        /* return to main program  */
#endif
           }
         }
         if (iml1 <= 0) break;
         iml2 = adsl_gai1_in_w2->achc_ginp_end - adsl_gai1_in_w2->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
         if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
             && ((adsl_gai1_in_w3->achc_ginp_end + iml2) > (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))
             && (adsl_gai1_in_w3->achc_ginp_end < (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
           printf( "l%05d output *** corrupting memory save-mp-given\n",
                   __LINE__ );
           adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
           return;                          /* return to main program  */
         }
#endif
#endif
         memcpy( adsl_gai1_in_w3->achc_ginp_end,
                 adsl_gai1_in_w2->achc_ginp_cur,
                 iml2 );
         adsl_gai1_in_w3->achc_ginp_end += iml2;
         adsl_gai1_in_w2->achc_ginp_cur += iml2;
         iml1 -= iml2;
       }
     }
     if (adsl_gai1_in_w1 == adsl_gai1_in_w3) {  /* last gather in storage given */
       bol1 = FALSE;                        /* do not use start chain external storage */
     }
   }
   if (   (bol1 == FALSE)                   /* do not use start chain external storage */
       && (adsl_enc_int->adsc_stor_ext)) {  /* external storage acquired */
#ifdef TRACEHL1
     printf( "ENC l%05d prepare store data in first external storage - addr=%p.\n",
             __LINE__, adsl_enc_int->adsc_stor_ext );
#endif
     adsl_gai1_in_w1 = (struct dsd_gather_i_1 *) (adsl_enc_int->adsc_stor_ext + 1);
#ifdef TRACEHL1
     printf( "ENC l%05d append storage first acquired before to addr=%p.\n",
             __LINE__, adsl_gai1_in_w3 );
#endif
     if (adsl_gai1_in_w3) {                 /* we need to append to save-mp-given */
       adsl_gai1_in_w3->adsc_next = adsl_gai1_in_w1;  /* set chain     */
     }
     memset( adsl_gai1_in_w1, 0, sizeof(struct dsd_gather_i_1) );
     adsl_gai1_in_w1->achc_ginp_cur = adsl_gai1_in_w1->achc_ginp_end = (char *) (adsl_gai1_in_w1 + 1);
     if (adsl_enc_int->adsc_gai1_in_saved == NULL) {
       adsl_enc_int->adsc_gai1_in_saved = adsl_gai1_in_w1;  /* set for next call */
     }
     bol1 = TRUE;                           /* we have external storage */
   }
   adsl_stor_ext_w1 = adsl_stor_ext_w2 = NULL;  /* external storage acquired */
   if (    (bol1)                           /* we have external storage */
       &&  (adsl_gai1_in_w1)) {             /* last in chain set       */
#ifdef B110506
     if (adsl_gai1_in_w3) {                 /* we need to append to save-mp-given */
       adsl_gai1_in_w3->adsc_next = adsl_gai1_in_w1;  /* set chain     */
       adsl_gai1_in_w3 = NULL;              /* no more append to chain */
     }
#endif
#define ADSL_STOR_EXT_L1 ((struct dsd_stor_ext *) ((char *) adsl_gai1_in_w1 - sizeof(struct dsd_stor_ext)))
     adsl_stor_ext_w1 = ADSL_STOR_EXT_L1;   /* external storage acquired */
#undef ADSL_STOR_EXT_L1
#ifdef TRACEHL1
     printf( "ENC l%05d store data in last used external storage - addr=%p.\n",
             __LINE__, adsl_stor_ext_w1 );
#endif
     adsl_stor_ext_w2 = adsl_stor_ext_w1->adsc_next;  /* get next in chain */
     iml1 = ((char *) adsl_stor_ext_w1 + LEN_AUX_STOR) - adsl_gai1_in_w1->achc_ginp_end;
     if (iml1 > 0) {                        /* we can save data here   */
       while (TRUE) {
         while (adsl_gai1_in_w2->achc_ginp_cur >= adsl_gai1_in_w2->achc_ginp_end) {
           adsl_gai1_in_w2 = adsl_gai1_in_w2->adsc_next;
           if (adsl_gai1_in_w2 == NULL) {   /* end of input reached    */
#ifdef TRACEHL1
             goto pec_tr_00;                /* display areas of memory saved */
#else
             return;                        /* return to main program  */
#endif
           }
         }
         if (iml1 <= 0) break;
         iml2 = adsl_gai1_in_w2->achc_ginp_end - adsl_gai1_in_w2->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
         if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
             && ((adsl_gai1_in_w1->achc_ginp_end + iml2) > (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))
             && (adsl_gai1_in_w1->achc_ginp_end < (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
           printf( "l%05d output *** corrupting memory save-mp-given\n",
                   __LINE__ );
           adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
           return;                          /* return to main program  */
         }
#endif
#endif
         memcpy( adsl_gai1_in_w1->achc_ginp_end,
                 adsl_gai1_in_w2->achc_ginp_cur,
                 iml2 );
         adsl_gai1_in_w1->achc_ginp_end += iml2;
         adsl_gai1_in_w2->achc_ginp_cur += iml2;
         iml1 -= iml2;
       }
     }
     adsl_gai1_in_w3 = adsl_gai1_in_w1;     /* set last gather already used */
   }
   while (adsl_stor_ext_w2) {               /* loop over storage acquired and not used */
#ifdef TRACEHL1
     printf( "ENC l%05d store data in external storage not used before - addr=%p.\n",
             __LINE__, adsl_stor_ext_w2 );
#endif
#ifdef TRACEHL1
     printf( "ENC l%05d append storage not used before to addr=%p.\n",
             __LINE__, adsl_gai1_in_w3 );
#endif
//   if (adsl_gai1_in_w3) {                 /* we need to append to save-mp-given */
       adsl_gai1_in_w3->adsc_next = (struct dsd_gather_i_1 *) (adsl_stor_ext_w2 + 1);
//   }
     adsl_gai1_in_w3 = (struct dsd_gather_i_1 *) (adsl_stor_ext_w2 + 1);
     memset( adsl_gai1_in_w3, 0, sizeof(struct dsd_gather_i_1) );
     adsl_gai1_in_w3->achc_ginp_cur = adsl_gai1_in_w3->achc_ginp_end = (char *) (adsl_gai1_in_w3 + 1);
#ifdef B110506
     adsl_gai1_in_w1->adsc_next = adsl_gai1_in_w3;  /* append to chain gather input */
     adsl_gai1_in_w1 = adsl_gai1_in_w3;     /* this is last now        */
#endif
     iml1
       = ((char *) adsl_stor_ext_w2 + LEN_AUX_STOR)
           - ((char *) (adsl_gai1_in_w3 + 1));
     while (TRUE) {
       while (adsl_gai1_in_w2->achc_ginp_cur >= adsl_gai1_in_w2->achc_ginp_end) {
         adsl_gai1_in_w2 = adsl_gai1_in_w2->adsc_next;
         if (adsl_gai1_in_w2 == NULL) {     /* end of input reached    */
#ifdef TRACEHL1
           goto pec_tr_00;                  /* display areas of memory saved */
#else
           return;                          /* return to main program  */
#endif
         }
       }
       if (iml1 <= 0) break;
       iml2 = adsl_gai1_in_w2->achc_ginp_end - adsl_gai1_in_w2->achc_ginp_cur;
       if (iml2 > iml1) iml2 = iml1;
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
       if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
           && ((adsl_gai1_in_w3->achc_ginp_end + iml2) > (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))
           && (adsl_gai1_in_w3->achc_ginp_end < (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
         printf( "l%05d output *** corrupting memory save-mp-given\n",
                 __LINE__ );
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* return to main program  */
       }
#endif
#endif
       memcpy( adsl_gai1_in_w3->achc_ginp_end,
               adsl_gai1_in_w2->achc_ginp_cur,
               iml2 );
       adsl_gai1_in_w3->achc_ginp_end += iml2;
       adsl_gai1_in_w2->achc_ginp_cur += iml2;
       iml1 -= iml2;
     }
     adsl_stor_ext_w1 = adsl_stor_ext_w2;   /* save last in chain      */
     adsl_stor_ext_w2 = adsl_stor_ext_w2->adsc_next;  /* get next in chain */
   }
   while (TRUE) {
     bol1 = (*adsp_cdr_ctrl->amc_aux)( adsp_cdr_ctrl->vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &adsl_stor_ext_w2,
                                       LEN_AUX_STOR );
     if (bol1 == FALSE) {                   /* error                   */
       adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error   */
       return;                              /* return to main-prog     */
     }
#ifdef TRACEHL1
     printf( "ENC l%05d acquired external storage - addr=%p.\n",
             __LINE__, adsl_stor_ext_w2 );
#endif
     if (adsl_stor_ext_w1) adsl_stor_ext_w1->adsc_next = adsl_stor_ext_w2;
     else adsl_enc_int->adsc_stor_ext = adsl_stor_ext_w2;
     adsl_stor_ext_w1 = adsl_stor_ext_w2;   /* this is last in chain now */
     adsl_stor_ext_w2->adsc_next = NULL;    /* new one last in chain   */
#ifdef TRACEHL1
     printf( "ENC l%05d append new storage to addr=%p.\n",
             __LINE__, adsl_gai1_in_w3 );
#endif
     if (adsl_gai1_in_w3) {                 /* we need to append to save-mp-given */
       adsl_gai1_in_w3->adsc_next = (struct dsd_gather_i_1 *) (adsl_stor_ext_w2 + 1);
     }
     adsl_gai1_in_w3 = (struct dsd_gather_i_1 *) (adsl_stor_ext_w2 + 1);
     memset( adsl_gai1_in_w3, 0, sizeof(struct dsd_gather_i_1) );
     adsl_gai1_in_w3->achc_ginp_cur = adsl_gai1_in_w3->achc_ginp_end = (char *) (adsl_gai1_in_w3 + 1);
#ifdef B110506
     adsl_gai1_in_w1->adsc_next = adsl_gai1_in_w3;  /* append to chain gather input */
     adsl_gai1_in_w1 = adsl_gai1_in_w3;     /* this is last now        */
#endif
     iml1
       = ((char *) adsl_stor_ext_w2 + LEN_AUX_STOR)
           - ((char *) (adsl_gai1_in_w3 + 1));
     while (TRUE) {
       while (adsl_gai1_in_w2->achc_ginp_cur >= adsl_gai1_in_w2->achc_ginp_end) {
         adsl_gai1_in_w2 = adsl_gai1_in_w2->adsc_next;
         if (adsl_gai1_in_w2 == NULL) {     /* end of input reached    */
#ifdef TRACEHL1
#ifdef DEBUG_110516_02
           adsl_aux_st_w1 = adsl_enc_int->adsc_stor_ext;  /* external storage acquired */
           adsl_aux_st_w2 = NULL;
           while (adsl_aux_st_w1) {         /* loop to check external storage */
             adsl_aux_st_w2 = adsl_aux_st_w1;
             adsl_aux_st_w1 = adsl_aux_st_w1->adsc_next;  /* get next in chain */
           }
#endif
           goto pec_tr_00;                  /* display areas of memory saved */
#else
           return;                          /* return to main program  */
#endif
         }
       }
       if (iml1 <= 0) break;
       iml2 = adsl_gai1_in_w2->achc_ginp_end - adsl_gai1_in_w2->achc_ginp_cur;
       if (iml2 > iml1) iml2 = iml1;
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
       if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
           && ((adsl_gai1_in_w3->achc_ginp_end + iml2) > (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))
           && (adsl_gai1_in_w3->achc_ginp_end < (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
         printf( "l%05d output *** corrupting memory save-mp-given\n",
                 __LINE__ );
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* return to main program  */
       }
#endif
#endif
       memcpy( adsl_gai1_in_w3->achc_ginp_end,
               adsl_gai1_in_w2->achc_ginp_cur,
               iml2 );
       adsl_gai1_in_w3->achc_ginp_end += iml2;
       adsl_gai1_in_w2->achc_ginp_cur += iml2;
       iml1 -= iml2;
     }
   }
   /* the program should never come here                               */
   adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error       */
   return;                                  /* return to main program  */

#ifdef TRACEHL1
   pec_tr_00:                               /* display areas of memory saved */
   iml_len_inp = 0;                         /* clear counter           */
   adsl_gai1_in_w1 = adsl_enc_int->adsc_gai1_in_saved;  /* input data saved */
   adsl_gai1_in_w4 = NULL;                  /* no last chain           */
   while (adsl_gai1_in_w1) {                /* loop over all saved gather */
     iml1 = adsl_gai1_in_w1->achc_ginp_end - adsl_gai1_in_w1->achc_ginp_cur;
#ifdef TRACEHL1
     printf( "ENC l%05d pec_tr_00 saved gather at addr=%p len=%d/0X%X.\n",
             __LINE__, adsl_gai1_in_w1, iml1, iml1 );
#endif
     iml_len_inp += iml1;
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;  /* get next in chain */
   }
   printf( "ENC l%05d pec_tr_00 total length saved=%d/0X%X.\n",
             __LINE__, iml_len_inp, iml_len_inp );

   return;                                  /* return to main program  */
#endif

   pecco40:                                 /* start compression       */
#ifdef DEBUG_110519_03
   iml_save_match_enc = ims_match_enc;
#endif
   adsl_gai1_in_w1 = adsl_gai1_in_w3 = adsl_enc_int->adsc_gai1_in_saved;  /* input data saved */
   adsl_gai1_in_w4 = NULL;                  /* no last chain           */
   while (adsl_gai1_in_w3) {                /* loop over all saved gather */
#ifdef TRACEHL1
     printf( "ENC l%05d pecco40 saved gather at addr=%p.\n",
             __LINE__, adsl_gai1_in_w3 );
#endif
     iml_len_inp += adsl_gai1_in_w3->achc_ginp_end - adsl_gai1_in_w3->achc_ginp_cur;
     adsl_gai1_in_w4 = adsl_gai1_in_w3;     /* save last in chain      */
     adsl_gai1_in_w3 = adsl_gai1_in_w3->adsc_next;  /* get next in chain */
   }
   if (iml_len_inp > iml_len_hist_bu) {     /* input data too long     */
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error     */
     return;                                /* report error            */
   }
   if (adsl_gai1_in_w4) {                   /* found last in chain     */
     adsl_gai1_in_w4->adsc_next = adsl_gai1_in_w2;  /* append new input data */
   } else {                                 /* no input data saved     */
     adsl_gai1_in_w1 = adsl_gai1_in_w2;     /* start with new input    */
   }
   adsl_entry_r4a5_start = adsl_enc_int->adsc_entry_r4a5;  /* entry RDP4/5 */
   adsl_node_r4a5 = adsl_enc_int->adsc_node_r4a5;  /* node RDP4/5        */
   dsl_out_1.achc_out_cur = adsp_cdr_ctrl->achc_out_cur;  /* start of output */
   dsl_out_1.achc_out_end = adsp_cdr_ctrl->achc_out_end;  /* end of output */
   dsl_out_1.adsc_gai1_in_saved = adsl_enc_int->adsc_gai1_in_saved;  /* input data saved */
   dsl_out_1.adsc_gai1_in_new = adsl_gai1_in_w2;  /* input data new in last call */
   dsl_out_1.adsc_gai1_out_last = NULL;     /* clear last gather output */
   iml_shift_c = 0;                         /* nothing in buffer       */
   /* for compiler only                                                */
   iml_shift_v = 0;                         /* clear the value         */
   bol_previous_char = FALSE;               /* previous character filled */
   achl_histbu_cur = adsl_enc_int->achc_histbu_cur;  /* current position in history buffer */
   achl_histbu_max = adsl_enc_int->achc_histbu_max;  /* maximum reached position in history buffer */
   achl_histbu_proc = achl_histbu_cur + iml_len_inp;  /* processing history buffer till here */
#ifdef B110815
   if (achl_histbu_proc > ((char *) (adsl_enc_int + 1) + iml_len_hist_bu)) {
     achl_histbu_cur = (char *) (adsl_enc_int + 1);  /* start of history buffer */
     achl_histbu_proc = (char *) (adsl_enc_int + 1) + iml_len_inp;  /* processing history buffer till here */
   }
#endif
#ifdef B120403
   adsp_cdr_ctrl->chrc_header[0] = (unsigned char) (HL_RDP_PACKET_COMPRESSED | 1);
#else
   adsp_cdr_ctrl->chrc_header[0] = (unsigned char) (HL_RDP_PACKET_COMPRESSED | adsl_enc_int->chc_comp_header);  /* value for compression header */
#endif
   if (adsl_enc_int->boc_rdp60_at_front) {  /* RDP 6.0 packet at front */
     adsp_cdr_ctrl->chrc_header[0] |= HL_RDP_PACKET_AT_FRONT;
     goto pecco48;                          /* history buffer has been prepared */
   }
#ifdef B170116_DD
   if (achl_histbu_proc <= ((char *) (adsl_enc_int + 1) + iml_len_hist_bu)) {
#else
   if (achl_histbu_proc < ((char *) (adsl_enc_int + 1) + iml_len_hist_bu)) {
#endif
     goto pecco48;                          /* history buffer has been prepared */
   }
   if (   (adsp_cdr_ctrl->imc_param_1 != 60)  /* not RDP6.0            */
       || (achl_histbu_cur == ((char *) (adsl_enc_int + 1)))) {  /* current position in history buffer */
     achl_histbu_cur = (char *) (adsl_enc_int + 1);  /* start of history buffer */
     achl_histbu_proc = (char *) (adsl_enc_int + 1) + iml_len_inp;  /* processing history buffer till here */
     goto pecco48;                          /* history buffer has been prepared */
   }
   if (iml_len_inp > (64 * 1024 / 2)) {     /* input data too long     */
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error     */
     return;                                /* report error            */
   }
   adsp_cdr_ctrl->chrc_header[0] |= HL_RDP_PACKET_AT_FRONT;
   adsl_enc_int->boc_rdp60_at_front = TRUE;  /* RDP 6.0 packet at front */
   memmove( adsl_enc_int + 1,
            achl_histbu_cur - 64 * 1024 / 2,
            64 * 1024 / 2 );
   achl_histbu_cur = achl_histbu_max = (char *) (adsl_enc_int + 1) + 64 * 1024 / 2;  /* start of history buffer */
   achl_histbu_proc = (char *) (adsl_enc_int + 1) + 64 * 1024 / 2 + iml_len_inp;  /* processing history buffer till here */
   memset( adsl_enc_int->adsc_entry_r4a5, 0XFF, D_MAX_BYTE * sizeof(struct dsd_entry_r4a5) );
   adsl_enc_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
   adsl_enc_int->achc_histbu_max = achl_histbu_max;  /* maximum reached position in history buffer */

   /* make new entries in chain for history buffer                     */
   achl_w1 = (char *) (adsl_enc_int + 1);   /* start of history buffer */

   pecco44:                                 /* add entry to chain      */
   iml1 = (achl_w1 - ((char *) (adsl_enc_int + 1))) >> 1;
   adsl_entry_r4a5_cur = adsl_entry_r4a5_start + ((unsigned char) *achl_w1);  /* entry to array */
   iml2 = adsl_entry_r4a5_cur->isc_son;
   adsl_entry_r4a5_cur->isc_son = iml1;
   (adsl_node_r4a5 + iml1)->isc_dad = -1;
   (adsl_node_r4a5 + iml1)->isc_son = iml2;
   if (iml2 >= 0) {
     (adsl_node_r4a5 + iml2)->isc_dad = iml1;
   }
   achl_w1 += 2;                            /* next even position      */
   if (achl_w1 < achl_histbu_cur) {         /* need to change tree     */
     goto pecco44;                          /* add entry to chain      */
   }

   pecco48:                                 /* history buffer has been prepared */
#ifdef TRACEHL1
   iml1 = achl_histbu_cur - ((char *) (adsl_enc_int + 1));  /* position in history buffer */
   printf( "ENC l%05d pecco40 len-input=%d/0X%p pos-hist-bu=%d/0X%X.\n",
           __LINE__, iml_len_inp, iml_len_inp, iml1, iml1 );
   m_console_gather( adsl_gai1_in_w1 );
#endif
   achl_saved_histbu_cur = achl_histbu_cur;  /* saved current position in history buffer */
   achl_saved_histbu_max = achl_histbu_max;  /* saved maximum reached position in history buffer */
#ifdef B160113
   if (achl_histbu_cur == ((char *) (adsl_enc_int + 1))) {  /* is now start of history buffer */
     adsp_cdr_ctrl->chrc_header[0] |= HL_RDP_PACKET_AT_FRONT;
   }
#endif
#ifndef B160113
   if (   (achl_histbu_cur == ((char *) (adsl_enc_int + 1)))  /* is now start of history buffer */
       && (adsp_cdr_ctrl->imc_param_1 != 60)) {  /* not RDP6.0         */
     adsp_cdr_ctrl->chrc_header[0] |= HL_RDP_PACKET_AT_FRONT;
   }
#endif
   if (iml_len_inp <= 0) {                  /* no input                */
     goto p_ec_r4o5_ret_00;                 /* RDP4/5 all processed    */
   }
   achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input        */
   adsl_gai1_in_all = adsl_gai1_in_w1;      /* all input data          */
   iml_len_out = 0;                         /* length of output        */
   aimrl_rdp4o5_co_off_len_total = imrs_rdp4_co_off_len_total;
   aimrl_rdp4o5_co_off_lead_bits = imrs_rdp4_co_off_lead_bits;
   aimrl_rdp4o5_co_off_add = imrs_rdp4_co_off_add;
   iml_rdp4o5_co_off_add_max = 4;
   if (adsp_cdr_ctrl->imc_param_1 == 50) {  /* RDP5 compression        */
     aimrl_rdp4o5_co_off_len_total = imrs_rdp5_co_off_len_total;
     aimrl_rdp4o5_co_off_lead_bits = imrs_rdp5_co_off_lead_bits;
     aimrl_rdp4o5_co_off_add = imrs_rdp5_co_off_add;
     iml_rdp4o5_co_off_add_max = 5;
   }

   p_ec_r4o5_cmp_00:                        /* RDP4/5 new character    */
   while (achl_inp >= adsl_gai1_in_w1->achc_ginp_end) {
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
     if (adsl_gai1_in_w1 == NULL) {         /* end of input reached    */
       goto p_ec_r4o5_ret_00;               /* RDP5 all processed      */
     }
     achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input      */
   }
   ucl_inp_cur = (unsigned char) *achl_inp;  /* get current input character */
   adsl_entry_r4a5_cur = adsl_entry_r4a5_start + ucl_inp_cur;  /* entry to array */
#ifdef DEBUG_110731_01                      /* RDP6.0 only literals    */
   iml_len_out = 0;                         /* clear length of output  */
   goto p_ec_r4o5_out_80;                   /* output normal character */
#endif
   iml1 = adsl_entry_r4a5_cur->isc_son;
   if (iml1 < 0) goto p_ec_r4o5_out_80;     /* output normal character */
   iml_cmp_max = 0;                         /* no match till now       */
   /* for compiler only                                                */
   bol_previous_fit = FALSE;                /* previous character fits */
   achl_base = achl_inp + 1;                /* base to compare         */
   adsl_gai1_in_base = adsl_gai1_in_w1;     /* base to compare         */
   while (achl_base >= adsl_gai1_in_base->achc_ginp_end) {
     adsl_gai1_in_base = adsl_gai1_in_base->adsc_next;
     if (adsl_gai1_in_base == NULL) {       /* end of input reached    */
       goto p_ec_r4o5_out_80;               /* output normal character */
     }
     achl_base = adsl_gai1_in_base->achc_ginp_cur;  /* here to compare */
   }

   p_ec_r4o5_cmp_20:                        /* RDP4/5 compare strings  */
   achl_cmp_c2 = achl_base;                 /* here to compare         */
#ifdef TRACEHL1
   if (achl_cmp_c2 > adsl_gai1_in_base->achc_ginp_end) {  /* after input area */
     printf( "ENC l%05d p_ec_r4o5_cmp_20 start compare after input area\n",
             __LINE__ );
   }
#endif
   adsl_gai1_in_w2 = adsl_gai1_in_base;     /* get gather input        */
   iml_cmp_now = 0;                         /* compare now minus one   */
   iml_cur_pos = iml1 << 1;                 /* current position        */
   achl_cmp_c1 = (char *) (adsl_enc_int + 1) + iml_cur_pos + 1;  /* here is string plus one */
   achl_cmp_end = achl_histbu_max;          /* end of compare          */
#ifdef NOT_TRANSPARENT
   if (iml_cur_pos < (achl_histbu_cur - ((char *) (adsl_enc_int + 1)))) {  /* before this new entry */
     achl_cmp_end = achl_histbu_cur;        /* end of compare          */
   }
#endif
   if (iml_cur_pos > 0) {                   /* not at start of history buffer */
     ucl_hist_previous = (*((unsigned char *) (adsl_enc_int + 1) + iml_cur_pos - 1));  /* previous character in history buffer */
#ifdef DEBUG_110519_01
     iml_debug_line_1 = __LINE__;
#endif
   }
   if (iml_cur_pos >= (achl_histbu_cur - ((char *) (adsl_enc_int + 1)))) {  /* after this new entry */
     goto p_ec_r4o5_cmp_24;                 /* compare direct with history buffer */
   }
   if (iml_cur_pos < (achl_saved_histbu_cur - ((char *) (adsl_enc_int + 1)))) {  /* before this new entry */
     achl_cmp_end = achl_saved_histbu_cur;  /* end of compare          */
     goto p_ec_r4o5_cmp_24;                 /* compare direct with history buffer */
   }
   /* compute number of characters we overread in input                */
   iml2 = ((((char *) (adsl_enc_int + 1)) + iml_cur_pos) - achl_saved_histbu_cur) - 1;
   adsl_gai1_in_w3 = adsl_gai1_in_all;      /* get gather input all    */
   /* first we set previous character                                  */
   achl_cmp_c1 = adsl_gai1_in_w3->achc_ginp_cur;  /* here to compare   */
   if (iml2 >= 0) {                         /* we can save previous character */
     while (iml2 > 0) {
       iml3 = adsl_gai1_in_w3->achc_ginp_end - achl_cmp_c1;
       if (iml3 > iml2) {                   /* start in this gather    */
         achl_cmp_c1 = adsl_gai1_in_w3->achc_ginp_cur + iml2;  /* here to compare */
         break;
       }
       iml2 -= iml3;                        /* subtract number of characters in this gather */
       adsl_gai1_in_w3 = adsl_gai1_in_w3->adsc_next;
       if (adsl_gai1_in_w3 == NULL) {       /* end of input reached    */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
       }
       achl_cmp_c1 = adsl_gai1_in_w3->achc_ginp_cur;  /* here to compare */
     }
     ucl_hist_previous = *((unsigned char *) achl_cmp_c1);  /* previous character in history buffer */
#ifdef DEBUG_110519_01
     iml_debug_line_1 = __LINE__;
#endif
     achl_cmp_c1++;                         /* overread character before */
   }
   while (achl_cmp_c1 >= adsl_gai1_in_w3->achc_ginp_end) {
     adsl_gai1_in_w3 = adsl_gai1_in_w3->adsc_next;
     if (adsl_gai1_in_w3 == NULL) {         /* end of input reached    */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
     achl_cmp_c1 = adsl_gai1_in_w3->achc_ginp_cur;  /* here to compare */
   }
#ifdef TRACEHL1
   if (*((unsigned char *) achl_cmp_c1) != ucl_inp_cur) {  /* not current input character */
     printf( "ENC l%05d p_ec_r4o5_cmp_20 old char does not fit to current input character\n",
             __LINE__ );
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error     */
     return;                                /* report error            */
   }
#endif
   achl_cmp_c1++;                           /* overread character that matches thru tree */
   while (achl_cmp_c1 >= adsl_gai1_in_w3->achc_ginp_end) {
     adsl_gai1_in_w3 = adsl_gai1_in_w3->adsc_next;
     if (adsl_gai1_in_w3 == NULL) {         /* end of input reached    */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
     achl_cmp_c1 = adsl_gai1_in_w3->achc_ginp_cur;  /* here to compare */
   }
#ifdef TRACEHL1
   achl_cmp_c1_trace_02 = achl_cmp_c1;
   if (achl_cmp_c1 == achl_cmp_c2) {        /* we compare same character */
     printf( "ENC l%05d p_ec_r4o5_cmp_20 achl_cmp_c1=%p achl_cmp_c2=%p.\n",
             __LINE__, achl_cmp_c1, achl_cmp_c2 );
   }
#endif
   goto p_ec_r4o5_cmp_48;                   /* compare if string in new input */

   p_ec_r4o5_cmp_24:                        /* compare direct with history buffer */
   while (achl_cmp_c2 >= adsl_gai1_in_w2->achc_ginp_end) {
     adsl_gai1_in_w2 = adsl_gai1_in_w2->adsc_next;
     if (adsl_gai1_in_w2 == NULL) {         /* end of input reached    */
       goto p_ec_r4o5_cmp_60;                 /* strings have been compared */
     }
     achl_cmp_c2 = adsl_gai1_in_w2->achc_ginp_cur;  /* here to compare */
   }

   p_ec_r4o5_cmp_28:                          /* compare in gather input */
   iml2 = adsl_gai1_in_w2->achc_ginp_end - achl_cmp_c2;
   iml3 = achl_cmp_end - achl_cmp_c1;
   if (iml2 > iml3) iml2 = iml3;            /* maximum length          */
   iml4 = iml2;                             /* save length maximum     */
   while (iml2 > 0) {                       /* compare all characters  */
     if (*achl_cmp_c1 != *achl_cmp_c2) break;  /* do not compare       */
     achl_cmp_c1++;                         /* increment input         */
     achl_cmp_c2++;                         /* increment input         */
     iml2--;                                /* decrement length        */
   }
   iml_cmp_now += iml4 - iml2;              /* compare now minus one   */
   if (iml2 > 0) goto p_ec_r4o5_cmp_60;       /* strings have been compared */
   if (achl_cmp_c1 >= achl_cmp_end) {       /* end of compare          */
     goto p_ec_r4o5_cmp_40;                 /* compare if string continued in new input */
   }
   adsl_gai1_in_w2 = adsl_gai1_in_w2->adsc_next;

   p_ec_r4o5_cmp_32:                        /* compare next gather input */
   if (adsl_gai1_in_w2 == NULL) {           /* no more input data      */
     goto p_ec_r4o5_cmp_60;                   /* strings have been compared */
   }
   if (adsl_gai1_in_w2->achc_ginp_cur < adsl_gai1_in_w2->achc_ginp_end) {
     achl_cmp_c2 = adsl_gai1_in_w2->achc_ginp_cur;  /* here to compare */
     goto p_ec_r4o5_cmp_28;                   /* compare in gather input */
   }
   adsl_gai1_in_w2 = adsl_gai1_in_w2->adsc_next;  /* get next in chain */
   goto p_ec_r4o5_cmp_32;                   /* compare next gather input */

   p_ec_r4o5_cmp_40:                        /* compare if string continued in new input */
#ifdef TRACEHL1
   achl_cmp_end_trace_02 = achl_cmp_end;
   achl_histbu_cur_trace_02 = achl_histbu_cur;
   achl_cmp_c2_trace_02 = achl_cmp_c2;
   achl_cmp_c1_trace_02 = NULL;
   iml_cmp_now_trace_02 = iml_cmp_now;
#endif
   if (achl_cmp_end != achl_saved_histbu_cur) {  /* was not old position history buffer */
     goto p_ec_r4o5_cmp_60;                   /* strings have been compared */
   }
   while (achl_cmp_c2 >= adsl_gai1_in_w2->achc_ginp_end) {
     adsl_gai1_in_w2 = adsl_gai1_in_w2->adsc_next;
     if (adsl_gai1_in_w2 == NULL) {         /* end of input reached    */
       goto p_ec_r4o5_cmp_60;                 /* strings have been compared */
     }
     achl_cmp_c2 = adsl_gai1_in_w2->achc_ginp_cur;  /* here to compare */
   }
   adsl_gai1_in_w3 = adsl_gai1_in_all;      /* get gather input all    */
   achl_cmp_c1 = adsl_gai1_in_w3->achc_ginp_cur;  /* here to compare   */
#ifdef TRACEHL1
   achl_cmp_c1_trace_02 = achl_cmp_c1;
   if (achl_cmp_c1 == achl_cmp_c2) {        /* we compare same character */
     printf( "ENC l%05d p_ec_r4o5_cmp_40 achl_cmp_c1=%p achl_cmp_c2=%p.\n",
             __LINE__, achl_cmp_c1, achl_cmp_c2 );
   }
#endif

   p_ec_r4o5_cmp_48:                        /* compare one part        */
   iml2 = adsl_gai1_in_w2->achc_ginp_end - achl_cmp_c2;
   iml3 = adsl_gai1_in_w3->achc_ginp_end - achl_cmp_c1;
   if (iml2 > iml3) iml2 = iml3;            /* maximum length          */
#ifdef TRACEHL1
   if (iml2 <= 0) {                         /* length too short        */
     printf( "ENC l%05d p_ec_r4o5_cmp_48 length compare too short\n",
             __LINE__ );
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error     */
     return;                                /* report error            */
   }
#endif
   iml4 = iml2;                             /* save length maximum     */
   do {                                     /* compare all characters  */
     if (*achl_cmp_c1 != *achl_cmp_c2) break;  /* do not compare       */
     achl_cmp_c1++;                         /* increment input         */
     achl_cmp_c2++;                         /* increment input         */
     iml2--;                                /* decrement length        */
   } while (iml2 > 0);
   iml_cmp_now += iml4 - iml2;              /* compare now minus one   */
   if (iml2 > 0) goto p_ec_r4o5_cmp_60;     /* strings have been compared */
   while (achl_cmp_c2 >= adsl_gai1_in_w2->achc_ginp_end) {
     adsl_gai1_in_w2 = adsl_gai1_in_w2->adsc_next;
     if (adsl_gai1_in_w2 == NULL) {         /* end of input reached    */
       goto p_ec_r4o5_cmp_60;               /* strings have been compared */
     }
     achl_cmp_c2 = adsl_gai1_in_w2->achc_ginp_cur;  /* here to compare */
   }
   while (achl_cmp_c1 >= adsl_gai1_in_w3->achc_ginp_end) {
     adsl_gai1_in_w3 = adsl_gai1_in_w3->adsc_next;
     if (adsl_gai1_in_w3 == NULL) {         /* end of input reached    */
       goto p_ec_r4o5_cmp_60;               /* strings have been compared */
     }
     achl_cmp_c1 = adsl_gai1_in_w3->achc_ginp_cur;  /* here to compare */
   }
   goto p_ec_r4o5_cmp_48;                   /* compare one part        */

   p_ec_r4o5_cmp_60:                        /* strings have been compared */
   bol1 = FALSE;                            /* not with previous character */
#ifndef DEBUG_110519_02
   if (   (bol_previous_char)               /* previous character filled */
       && (iml_cur_pos > 0)                 /* not at beginning of history buffer */
       && (iml_cur_pos != (achl_histbu_cur - ((char *) (adsl_enc_int + 1))))  /* not this new entry */
       && (ucl_inp_previous == ucl_hist_previous)) {  /* previous input */
     iml_cmp_now++;                         /* compare now minus one   */
     iml_cur_pos--;                         /* one position before     */
     bol1 = TRUE;                           /* with previous character */
   }
#endif
   if (iml_cmp_now > iml_cmp_max) goto p_ec_r4o5_cmp_68;  /* this fits better */
   if (iml_cmp_now < iml_cmp_max) goto p_ec_r4o5_cmp_80;  /* this character compared */
   if (bol1 == bol_previous_fit) goto p_ec_r4o5_cmp_80;  /* this character compared */

   p_ec_r4o5_cmp_68:                        /* this fits better        */
#ifdef TRACEHL1
   if (iml_cmp_now >= iml_len_inp) {        /* what fits is too long   */
     printf( "ENC l%05d p_ec_r4o5_cmp_68 len-input=%d/0X%X cmp-now=%d/0X%X.\n",
             __LINE__, iml_len_inp, iml_len_inp, iml_cmp_now, iml_cmp_now );
     printf( "ENC l%05d p_ec_r4o5_cmp_68 achl_cmp_end_trace_02=%p achl_histbu_cur_trace_02=%p achl_cmp_c2_trace_02=%p achl_cmp_c1_trace_02=%p.\n",
             __LINE__,
             achl_cmp_end_trace_02,
             achl_histbu_cur_trace_02,
             achl_cmp_c2_trace_02,
             achl_cmp_c1_trace_02 );
     printf( "ENC l%05d p_ec_r4o5_cmp_68 iml_cmp_now_trace_02=%d.\n",
             __LINE__, iml_cmp_now_trace_02 );
   }
#endif
   iml_cmp_max = iml_cmp_now;               /* longest match           */
   iml_copy_pos = iml_cur_pos;              /* copy position           */
   bol_previous_fit = bol1;                 /* previous character fits */
#ifdef DEBUG_110519_01
   if (bol1) {
     ucl_debug_previous = ucl_hist_previous;  /* previous character in history buffer */
     iml_debug_line_2 = iml_debug_line_1;
   }
#endif

   p_ec_r4o5_cmp_80:                        /* this character compared */
   iml1 = (adsl_node_r4a5 + iml1)->isc_son;
   if (iml1 >= 0) goto p_ec_r4o5_cmp_20;    /* RDP4/5 compare strings  */

   /* we did compare all positions in the history buffer with the same character */
   if (iml_cmp_max < iml_match_min_m1) {    /* longest match not long enough */
     goto p_ec_r4o5_out_80;                 /* output normal character */
   }
#ifdef DEBUG_110519_01
   if (bol_previous_fit) {                  /* previous character fits */
     printf( "ENC l%05d p_ec_r4o5_cmp_80 ucl_debug_previous=%02X line=%d.\n",
             __LINE__, ucl_debug_previous, iml_debug_line_2 );
   }
#endif
   iml1 = iml_cmp_max;                      /* longest match minus one */
   if (bol_previous_fit == FALSE) {         /* not previous character fits */
     iml1++;                                /* longest match exactly   */
   }
   if (iml1 > iml_match_max) {              /* data longer than can be encoded */
     iml_cmp_max -= iml1 - iml_match_max;   /* adjust longest match minus one */
     iml1 = iml_match_max;                  /* only as long as can be encoded */
   }
   iml4 = iml5 = iml1;                      /* save length match for later */
#ifdef TRACEHL1
   printf( "ENC l%05d p_ec_r4o5_cmp_80 longest-match=%d/0X%X.\n",
           __LINE__, iml1, iml1 );
#endif
   achl_w1 = achl_histbu_cur;               /* start to remove from tree */
   if (((achl_w1 - ((char *) (adsl_enc_int + 1))) & 1) != 0) {  /* position in tree odd */
     achl_w1++;                             /* remove at next even     */
   }
   achl_w2 = achl_histbu_cur + iml1;        /* end to remove from tree */
   if (achl_w2 > achl_histbu_max) {
     achl_w2 = achl_histbu_max;             /* maximum reached position in history buffer */
   }
   if (achl_w1 >= achl_w2) {                /* nothing to remove       */
     goto p_ec_r4o5_out_20;                 /* removed from tree       */
   }

   p_ec_r4o5_out_08:                        /* remove character from tree */
   ucl_w1 = (unsigned char) *achl_w1;       /* get character to remove */
   iml1 = (achl_w1 - ((char *) (adsl_enc_int + 1))) >> 1;
   iml2 = (adsl_node_r4a5 + iml1)->isc_dad;
   iml3 = (adsl_node_r4a5 + iml1)->isc_son;
   if (iml2 >= 0) {                         /* dad is valid entry      */
     (adsl_node_r4a5 + iml2)->isc_son = iml3;
   } else {
     (adsl_entry_r4a5_start + ucl_w1)->isc_son = iml3;
   }
   if (iml3 >= 0) {                         /* son is valid entry      */
     (adsl_node_r4a5 + iml3)->isc_dad = iml2;
   }
   achl_w1 += 2;                            /* next even position      */
   if (achl_w1 < achl_w2) {                 /* more to remove          */
     goto p_ec_r4o5_out_08;                 /* remove character from tree */
   }

   p_ec_r4o5_out_20:                        /* removed from tree       */
   iml2 = (achl_histbu_cur + iml5 - iml4) - ((char *) (adsl_enc_int + 1));
   if (iml2 & 1) {                          /* history buffer position is odd */
     iml2++;                                /* next position history buffer */
     iml4--;                                /* character has been processed */
     achl_inp++;                            /* current input           */
     while (achl_inp >= adsl_gai1_in_w1->achc_ginp_end) {
       adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
#ifdef B110524
       if (adsl_gai1_in_w1 == NULL) {       /* end of input reached    */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
       }
#else
       if (adsl_gai1_in_w1 == NULL) {       /* end of input reached    */
#ifdef B110718
         goto p_ecco_out_20;                /* pass saved output data  */
#endif
#ifndef B110718
#ifdef B110719
         goto p_ec_r4o5_ret_00;             /* RDP4/5 all processed    */
#else
         break;
#endif
#endif
       }
#endif
       achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input    */
     }
     if (iml4 <= 0) {                       /* nothing to add to tree  */
       goto p_ec_r4o5_out_28;               /* new nodes added to tree */
     }
   }
   iml2 >>= 1;                              /* only every second byte in tree */

   p_ec_r4o5_out_24:                        /* add to tree             */
   ucl_w1 = (unsigned char) *achl_inp++;    /* get character to add    */
   iml1 = (adsl_entry_r4a5_start + ucl_w1)->isc_son;
   (adsl_entry_r4a5_start + ucl_w1)->isc_son = iml2;
   (adsl_node_r4a5 + iml2)->isc_dad = -1;
   (adsl_node_r4a5 + iml2)->isc_son = iml1;
   if (iml1 >= 0) {
     (adsl_node_r4a5 + iml1)->isc_dad = iml2;
   }
#ifdef B110719
   while (achl_inp >= adsl_gai1_in_w1->achc_ginp_end) {
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
     if (adsl_gai1_in_w1 == NULL) {         /* end of input reached    */
       break;                               /* input has been processed */
     }
     achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input      */
   }
#endif
#ifndef B110719
   if (adsl_gai1_in_w1) {                   /* more input data         */
     while (achl_inp >= adsl_gai1_in_w1->achc_ginp_end) {
       adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
       if (adsl_gai1_in_w1 == NULL) {       /* end of input reached    */
         break;                             /* input has been processed */
       }
       achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input    */
     }
   }
#endif
   iml4--;                                  /* character has been processed */
   if (iml4 > 0) {                          /* more characters to add to tree */
     if (adsl_gai1_in_w1 == NULL) {         /* end of input reached    */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
     achl_inp++;                            /* current input           */
     while (achl_inp >= adsl_gai1_in_w1->achc_ginp_end) {
       adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
       if (adsl_gai1_in_w1 == NULL) {       /* end of input reached    */
         break;                             /* input has been processed */
       }
       achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input    */
     }
     iml4--;                                /* character has been processed */
     if (iml4 > 0) {                        /* more characters to add to tree */
       iml2++;                              /* next even position in history buffer */
       if (adsl_gai1_in_w1) {               /* not yet end of input reached */
         goto p_ec_r4o5_out_24;             /* add to tree             */
       }
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
#ifdef XYZ1
#ifdef TRY_110603_01                        /* achl_inp one position too early */
     achl_inp++;                            /* current input           */
#endif
#endif
   }

   p_ec_r4o5_out_28:                        /* new nodes added to tree */
   achl_histbu_cur += iml5;                 /* history buffer          */
   if (achl_histbu_cur > achl_histbu_max) {
     achl_histbu_max = achl_histbu_cur;     /* maximum reached position in history buffer */
   }
#ifdef TRACEHL1
   bol1 = m_sr_check_1( adsp_cdr_ctrl, adsl_enc_int, achl_histbu_max - ((char *) (adsl_enc_int + 1)), FALSE );
   if (bol1 == FALSE) {
     iml1 = achl_histbu_cur - ((char *) (adsl_enc_int + 1));
     printf( "ENC l%05d p_ec_r4o5_out_28 match character history buffer corrupted / pos=%d/0X%X.\n",
             __LINE__, iml1, iml1 );
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error     */
     return;                                /* report error            */
   }
#endif
#ifdef DEBUG_110519_03
   /* output of characters that match                                  */
   ims_match_enc++;
#ifdef B110520
   iml1 = iml_copy_pos - ((int) bol_previous_fit);
#else
   iml1 = iml_copy_pos;
#endif
   iml2 = iml_cmp_max + 1;                  /* longest match exactly   */
#ifdef B110520
   iml3 = (achl_histbu_cur - ((char *) (adsl_enc_int + 1))) - iml5;
#else
   iml3 = (achl_histbu_cur - ((char *) (adsl_enc_int + 1))) - iml5 - ((int) bol_previous_fit);
#endif
   printf( "ENC l%05d p_ec_r4o5_out_28 match-no=%d pos=%d/0X%X length=%d/0X%X new-pos=%d/0X%X.\n",
           __LINE__, ims_match_enc, iml1, iml1, iml2, iml2, iml3, iml3 );
   iml3 = 16;
   achl_w1 = ((char *) (adsl_enc_int + 1)) + iml1;
   achl_w2 = achl_w1 + iml2;
   adsl_gai1_in_w3 = NULL;                  /* no gather               */
   while (   (achl_w2 > achl_saved_histbu_cur)
          && (achl_w1 < achl_histbu_cur)) {
     adsl_gai1_in_w3 = adsl_gai1_in_all;    /* all input data          */
     iml4 = achl_saved_histbu_cur - achl_w1;
     if (iml4 > 0) {
       achl_w2 = achl_saved_histbu_cur;     /* set end                 */
       break;
     }
     /* attention: negative logic                                      */
     while (TRUE) {
       iml3 = adsl_gai1_in_w3->achc_ginp_cur - adsl_gai1_in_w3->achc_ginp_end;
       if (iml3 != 0) {
         if (iml3 < iml4) {
           achl_w1 = adsl_gai1_in_w3->achc_ginp_cur - iml4;
           achl_w2 = adsl_gai1_in_w3->achc_ginp_end;
           adsl_gai1_in_w3 = adsl_gai1_in_w3->adsc_next;
           break;
         }
         iml4 -= iml3;
       }
       adsl_gai1_in_w3 = adsl_gai1_in_w3->adsc_next;
     }
     break;
   }
   iml3 = 16;
   while (TRUE) {
     printf( " %02X", *((unsigned char *) achl_w1) );
     iml2--;
     if (iml2 <= 0) break;
     iml3--;
     if (iml3 <= 0) {
       printf( "\n" );
       iml3 = 16;
     }
     achl_w1++;
     if (achl_w1 >= achl_w2) {
       achl_w1 = adsl_gai1_in_w3->achc_ginp_cur;
       achl_w2 = adsl_gai1_in_w3->achc_ginp_end;
       adsl_gai1_in_w3 = adsl_gai1_in_w3->adsc_next;
     }
   }
   printf( "\n" );
#endif
   iml1 = ((achl_histbu_cur - iml5) - ((char *) (adsl_enc_int + 1)))
            - iml_copy_pos                  /* copy position           */
            - ((int) bol_previous_fit);     /* previous character fits */
   if (iml1 < 0) {                          /* after new position      */
     iml1 += iml_len_hist_bu;               /* add length history buffer */
   }
#ifdef TRACEHL1
   iml2 = iml_cmp_max + 1;                  /* longest match exactly   */
   iml3 = achl_histbu_cur - ((char *) (adsl_enc_int + 1));
   printf( "ENC l%05d copy-offset=%d/0X%p len-of-match=%d/0X%p pos-histbu-cur=%d/0X%p.\n",
           __LINE__, iml1, iml1, iml2, iml2, iml3, iml3 );
#endif
   if (bol_out_huffman) {                   /* output is huffman encoded */
     goto p_ec_r4o5_out_40;                 /* output RDP 6.0          */
   }
   if (   (bol_previous_char)               /* previous character filled */
       && (bol_previous_fit == FALSE)) {    /* not previous character fits */
     if (((signed char) ucl_inp_previous) >= 0) {
       iml_shift_v <<= VAL_BYTE;            /* shift old bits          */
       iml_shift_v |= ucl_inp_previous;     /* get new bits            */
       iml_shift_c += VAL_BYTE;             /* shift-count             */
     } else {
       iml_shift_v <<= VAL_BYTE + 1;        /* shift old bits          */
       iml_shift_v |= 0X0100 | (ucl_inp_previous & 0X7F);  /* get new bits */
       iml_shift_c += VAL_BYTE + 1;         /* shift-count             */
     }
     while (iml_shift_c >= VAL_BYTE) {      /* shift-count at least byte */
       iml_len_out++;                       /* increment length of output */
       if (iml_len_out >= iml_len_inp) {    /* compressed is longer than original */
         goto p_ec_trans_00;                /* output transparent      */
       }
       iml_shift_c -= VAL_BYTE;             /* shift-count             */
       bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) (iml_shift_v >> iml_shift_c) );
       if (bol1 == FALSE) {                 /* error occured           */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
       }
     }
   }
   iml2 = 2;                                /* first position table    */
   while (TRUE) {                           /* check where we are in table */
     iml3 = *(aimrl_rdp4o5_co_off_add + iml2);
     if (iml1 >= iml3) break;
     iml2++;                                /* next table entry        */
   }
   iml1 -= iml3;                            /* only bits needed        */
   iml3 = *(aimrl_rdp4o5_co_off_len_total + iml2);
   iml4 = *(aimrl_rdp4o5_co_off_lead_bits + iml2);
   iml5 = iml4;
   if (iml2 != iml_rdp4o5_co_off_add_max) iml5--;
#ifdef DEBUG_110418_01
   printf( "ENC l%05d copy-offset value=%d/0X%p total=%d lead=%d set-one=%d or=%p and=%p or+and=%p.\n",
           __LINE__,
           iml1, iml1, iml3, iml4, iml5,
           ((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml3),
           (((unsigned int) -1) << (iml3 - iml5)),
           ((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml3)
             & (((unsigned int) -1) << (iml3 - iml5)) );
   printf( "ENC l%05d before applying copy-offset iml_shift_c=%d iml_shift_v=%08X iml2=%d iml_rdp4o5_co_off_add_max=%d iml5=%d.\n",
           __LINE__, iml_shift_c, iml_shift_v, iml2, iml_rdp4o5_co_off_add_max, iml5 );
#endif
   iml_shift_v <<= iml3;                    /* shift old bits          */
   iml_shift_v |= ((((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml3))
                        & (((unsigned int) -1) << (iml3 - iml5)))
                      | iml1;               /* get new bits            */
   iml_shift_c += iml3;                     /* shift-count             */
   while (iml_shift_c >= VAL_BYTE) {        /* shift-count at least byte */
     iml_len_out++;                         /* increment length of output */
     if (iml_len_out >= iml_len_inp) {      /* compressed is longer than original */
       goto p_ec_trans_00;                  /* output transparent      */
     }
     iml_shift_c -= VAL_BYTE;               /* shift-count             */
     bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) (iml_shift_v >> iml_shift_c) );
     if (bol1 == FALSE) {                   /* error occured           */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
   }
#ifdef DEBUG_110418_01
   printf( "ENC l%05d after  applying copy-offset iml_shift_c=%d iml_shift_v=%08X.\n",
           __LINE__, iml_shift_c, iml_shift_v );
#endif
   iml1 = iml_cmp_max + 1;                  /* longest match exactly   */
   iml2 = ucrs_trailing_bits[ (unsigned char) (iml1 >> 8) ];
   if (iml2 == 0) {                         /* no bits found           */
     iml2 = ucrs_trailing_bits[ (unsigned char) iml1 ];
   } else {
     iml2 += VAL_BYTE;
   }
   iml2--;
   iml3 = iml2 * 2;                         /* number of bits total    */
   if (iml2 == 1) {
     iml3 = 1;
     iml2 = 0;
     iml1 = 1;
   }
#ifdef DEBUG_110418_01
   iml5 = iml1 - (1 << iml2);
   printf( "ENC l%05d len-of-match-1 value=%d/0X%p iml2(pos-table-2)=%d total=%d or=%p and=%p or+and=%p.\n",
           __LINE__,
           iml1, iml1, iml2, iml3,
           ((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml3),
           (((unsigned int) -1) << (iml3 - iml2 + 1)),
           ((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml3)
             & (((unsigned int) -1) << (iml3 - iml2 + 1)) );
   printf( "ENC l%05d len-of-match-2 or-value=%d/0X%p subtract=%d/0X%p.\n",
           __LINE__,
           iml5, iml5,
           1 << iml2,
           1 << iml2 );
#endif
#ifdef TRACEHL3
   ims_tracehl3++;
   printf( "ENC l%05d ims_tracehl3=%d iml3=%d.\n", __LINE__, ims_tracehl3, iml3 );
   if (ims_tracehl3 == TRACEHL3) {
     printf( "ENC l%05d debug point reached\n", __LINE__ );
   }
#endif
#ifndef TRY_110523_01
   iml_shift_v <<= iml3;                    /* shift old bits          */
   iml_shift_v |= ((((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml3))
                        & (((unsigned int) -1) << (iml3 - iml2 + 1)))
                      | (iml1 - (1 << iml2));
   iml_shift_c += iml3;                     /* shift-count             */
#else
   iml4 = iml3;                             /* save number of bits to shift */
   if (iml3 > (VAL_BYTE * 2)) {             /* prevent overflow iml_shift_v */
     iml_len_out++;                         /* increment length of output */
     if (iml_len_out >= iml_len_inp) {      /* compressed is longer than original */
       goto p_ec_trans_00;                  /* output transparent      */
     }
     iml_shift_v <<= VAL_BYTE;              /* shift old bits          */
     iml_shift_v |= 0XFF;                   /* apply all ones          */
//   iml_shift_c -= VAL_BYTE;               /* shift-count             */
     bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) (iml_shift_v >> iml_shift_c) );
     if (bol1 == FALSE) {                   /* error occured           */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
     iml3 -= VAL_BYTE;                      /* later apply fewer bits  */
   }
   iml_shift_v <<= iml3;                    /* shift old bits          */
   iml_shift_v |= ((((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml4))
                        & (((unsigned int) -1) << (iml4 - iml2 + 1)))
                      | (iml1 - (1 << iml2));
   iml_shift_c += iml3;                     /* shift-count             */
#endif
#ifdef DEBUG_110418_01
   printf( "ENC l%05d after applying len-of-match iml_shift_c=%d iml_shift_v=%08X.\n",
           __LINE__, iml_shift_c, iml_shift_v );
#endif
   while (iml_shift_c >= VAL_BYTE) {        /* shift-count at least byte */
     iml_len_out++;                         /* increment length of output */
     if (iml_len_out >= iml_len_inp) {      /* compressed is longer than original */
       goto p_ec_trans_00;                  /* output transparent      */
     }
     iml_shift_c -= VAL_BYTE;               /* shift-count             */
     bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) (iml_shift_v >> iml_shift_c) );
     if (bol1 == FALSE) {                   /* error occured           */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
   }
   bol_previous_char = FALSE;               /* previous character not filled */
   if (adsl_gai1_in_w1) {                   /* not yet end of input reached */
     goto p_ec_r4o5_cmp_00;                 /* RDP4/5 new character    */
   }
   goto p_ec_r4o5_ret_00;                   /* RDP4/5 all processed    */

   p_ec_r4o5_out_40:                        /* output RDP 6.0          */
   if (   (bol_previous_char)               /* previous character filled */
       && (bol_previous_fit == FALSE)) {    /* not previous character fits */
     iml2 = ucrs_rdp60_encode_1[ ucl_inp_previous ];  /* get number of bits */
     iml_shift_v |= usrs_rdp60_encode_2[ ucl_inp_previous ] << iml_shift_c;  /* get new bits */
     iml_shift_c += iml2;                   /* shift-count             */
     while (iml_shift_c >= VAL_BYTE) {      /* shift-count at least byte */
       iml_len_out++;                       /* increment length of output */
       if (iml_len_out >= iml_len_inp) {    /* compressed is longer than original */
         goto p_ec_trans_00;                /* output transparent      */
       }
       bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) iml_shift_v );
       if (bol1 == FALSE) {                 /* error occured           */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
       }
       iml_shift_v >>= VAL_BYTE;            /* remove the bits         */
       iml_shift_c -= VAL_BYTE;             /* shift-count             */
     }
   }

   /* the offset is in iml1                                            */

   /* first search in cache                                            */
#ifndef DEBUG_110804_01                     /* RDP6.0 no cache offset  */
   iml2 = 0;                                /* index of table          */
   do {                                     /* loop over table entries */
     if (iml1 == imrl_cache_off[ iml2 ]) {  /* found in cache          */
       iml3 = VAL_TAB_R60_D1_CAC + ((imrl_cache_off[ VAL_CACHE_OFF ] - iml2) & (VAL_CACHE_OFF - 1));  /* compute index */
       iml_shift_v |= usrs_rdp60_encode_2[ iml3 ] << iml_shift_c;  /* get new bits */
       iml_shift_c += ucrs_rdp60_encode_1[ iml3 ];  /* shift-count add number of bits */
       if (iml2 != imrl_cache_off[ VAL_CACHE_OFF ]) {  /* we need to exchange the values */
         iml3 = imrl_cache_off[ imrl_cache_off[ VAL_CACHE_OFF ] ];  /* save value */
         imrl_cache_off[ imrl_cache_off[ VAL_CACHE_OFF ] ]
           = imrl_cache_off[ iml2 ];
         imrl_cache_off[ iml2 ] = iml3;
       }
       goto p_ec_r4o5_out_48;               /* offset has been encoded */
     }
     iml2++;                                /* next index              */
   } while (iml2 < VAL_CACHE_OFF);          /* RDP6.0 cache offset     */
#endif

   /* put new entry in cache                                           */
#ifdef B130701
   imrl_cache_off[ imrl_cache_off[ VAL_CACHE_OFF ] ] = iml1;  /* put value in cache */
#endif
   imrl_cache_off[ VAL_CACHE_OFF ]++;       /* increment cache index   */
   imrl_cache_off[ VAL_CACHE_OFF ] &= (VAL_CACHE_OFF - 1);  /* wrap around */
#ifndef B130701
   imrl_cache_off[ imrl_cache_off[ VAL_CACHE_OFF ] ] = iml1;  /* put value in cache */
#endif

   iml2 = 0;                                /* index of table          */
   do {                                     /* loop over table entries */
     if (iml1 < usrs_rdp60_offset_1[ iml2 + 1 ]) break;
     iml2++;                                /* next index              */
   } while (iml2 < (sizeof(usrs_rdp60_offset_1) / sizeof(usrs_rdp60_offset_1[0]) - 1));
   iml_shift_v |= usrs_rdp60_encode_2[ VAL_TAB_R60_D1_OFF + iml2 ] << iml_shift_c;  /* get new bits */
   iml_shift_c += ucrs_rdp60_encode_1[ VAL_TAB_R60_D1_OFF + iml2 ];  /* shift-count add number of bits */
   iml3 = ucrs_rdp60_offset_2[ iml2 ];      /* get extra number of bits */
   if (iml3 > 0) {                          /* we need extra bits      */
     iml_shift_v |= (iml1 - usrs_rdp60_offset_1[ iml2 ]) << iml_shift_c;  /* get new bits */
     iml_shift_c += iml3;                   /* shift-count add number of bits */
   }

   p_ec_r4o5_out_48:                        /* offset has been encoded */
   while (iml_shift_c >= VAL_BYTE) {        /* shift-count at least byte */
     iml_len_out++;                         /* increment length of output */
     if (iml_len_out >= iml_len_inp) {      /* compressed is longer than original */
       goto p_ec_trans_00;                  /* output transparent      */
     }
     bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) iml_shift_v );
     if (bol1 == FALSE) {                   /* error occured           */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
     iml_shift_v >>= VAL_BYTE;              /* remove the bits         */
     iml_shift_c -= VAL_BYTE;               /* shift-count             */
   }

   /* the length minus one is in iml_cmp_max                           */
   iml1 = iml_cmp_max + 1;                  /* longest match exactly   */
   iml2 = 0;                                /* index of table          */
   do {                                     /* loop over table entries */
     if (iml1 < usrs_rdp60_length_1[ iml2 + 1 ]) break;
     iml2++;                                /* next index              */
   } while (iml2 < (sizeof(usrs_rdp60_length_1) / sizeof(usrs_rdp60_length_1[0]) - 1));
   iml_shift_v |= usrs_rdp60_length_4[ iml2 ] << iml_shift_c;  /* get new bits */
   iml_shift_c += ucrs_rdp60_length_3[ iml2 ];  /* shift-count add number of bits */
   iml3 = ucrs_rdp60_length_2[ iml2 ];      /* get extra number of bits */
   if (iml3 > 0) {                          /* we need extra bits      */
     iml_shift_v |= (iml1 - usrs_rdp60_length_1[ iml2 ]) << iml_shift_c;  /* get new bits */
     iml_shift_c += iml3;                   /* shift-count add number of bits */
   }
#ifdef DEBUG_110803_01                      /* RDP6.0 display length-of-match */
   printf( "ENC l%05d length-of-match iml1=0X%04X iml2=0X%04X iml3=0X%04X usrs_rdp60_length_1[ iml2 ]=0X%04X iml_shift_v=0X%08X.\n",
           __LINE__, iml1, iml2, iml3, usrs_rdp60_length_1[ iml2 ], (unsigned int) iml_shift_v );
#endif
   while (iml_shift_c >= VAL_BYTE) {        /* shift-count at least byte */
     iml_len_out++;                         /* increment length of output */
     if (iml_len_out >= iml_len_inp) {      /* compressed is longer than original */
       goto p_ec_trans_00;                  /* output transparent      */
     }
     bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) iml_shift_v );
     if (bol1 == FALSE) {                   /* error occured           */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
     iml_shift_v >>= VAL_BYTE;              /* remove the bits         */
     iml_shift_c -= VAL_BYTE;               /* shift-count             */
   }
   bol_previous_char = FALSE;               /* previous character not filled */
   if (adsl_gai1_in_w1) {                   /* not yet end of input reached */
     goto p_ec_r4o5_cmp_00;                 /* RDP4/5 new character    */
   }
   goto p_ec_r4o5_ret_00;                   /* RDP4/5 all processed    */

   p_ec_r4o5_out_80:                        /* output normal character */
   if (bol_previous_char) {                 /* previous character filled */
#ifdef TRACEHL1
     printf( "ENC l%05d p_ec_r4o5_out_80 output ucl_inp_previous %02X.\n",
             __LINE__, (unsigned char) ucl_inp_previous );
#endif
     if (bol_out_huffman == FALSE) {        /* output is not huffman encoded */
       if (((signed char) ucl_inp_previous) >= 0) {
         iml_shift_v <<= VAL_BYTE;          /* shift old bits          */
         iml_shift_v |= ucl_inp_previous;   /* get new bits            */
         iml_shift_c += VAL_BYTE;           /* shift-count             */
       } else {
         iml_shift_v <<= VAL_BYTE + 1;      /* shift old bits          */
         iml_shift_v |= 0X0100 | (ucl_inp_previous & 0X7F);  /* get new bits */
         iml_shift_c += VAL_BYTE + 1;       /* shift-count             */
       }
       while (iml_shift_c >= VAL_BYTE) {    /* shift-count at least byte */
         iml_len_out++;                     /* increment length of output */
         if (iml_len_out >= iml_len_inp) {  /* compressed is longer than original */
           goto p_ec_trans_00;              /* output transparent      */
         }
         iml_shift_c -= VAL_BYTE;           /* shift-count             */
         bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) (iml_shift_v >> iml_shift_c) );
         if (bol1 == FALSE) {               /* error occured           */
           adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
           return;                          /* report error            */
         }
       }
     } else {                               /* output is huffman encoded */
       iml1 = ucrs_rdp60_encode_1[ ucl_inp_previous ];  /* get number of bits */
       iml_shift_v |= usrs_rdp60_encode_2[ ucl_inp_previous ] << iml_shift_c;  /* get new bits */
       iml_shift_c += iml1;                 /* shift-count             */
       while (iml_shift_c >= VAL_BYTE) {    /* shift-count at least byte */
         iml_len_out++;                     /* increment length of output */
         if (iml_len_out >= iml_len_inp) {  /* compressed is longer than original */
           goto p_ec_trans_00;              /* output transparent      */
         }
         bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) iml_shift_v );
         if (bol1 == FALSE) {               /* error occured           */
           adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
           return;                          /* report error            */
         }
         iml_shift_v >>= VAL_BYTE;          /* remove the bits         */
         iml_shift_c -= VAL_BYTE;           /* shift-count             */
       }
     }
   }
   if (((achl_histbu_cur - ((char *) (adsl_enc_int + 1))) & 1) == 0) {  /* position in tree even */
     iml1 = (achl_histbu_cur - ((char *) (adsl_enc_int + 1))) >> 1;
     if (achl_histbu_cur < achl_histbu_max) {  /* need to remove entry */
       ucl_w1 = (unsigned char) *achl_histbu_cur;
       iml2 = (adsl_node_r4a5 + iml1)->isc_dad;
       iml3 = (adsl_node_r4a5 + iml1)->isc_son;
       if (iml2 >= 0) {                     /* dad is valid entry      */
         (adsl_node_r4a5 + iml2)->isc_son = iml3;
       } else {
         (adsl_entry_r4a5_start + ucl_w1)->isc_son = iml3;
       }
       if (iml3 >= 0) {                     /* son is valid entry      */
         (adsl_node_r4a5 + iml3)->isc_dad = iml2;
       }
     }
     iml2 = adsl_entry_r4a5_cur->isc_son;
     adsl_entry_r4a5_cur->isc_son = iml1;
     (adsl_node_r4a5 + iml1)->isc_dad = -1;
     (adsl_node_r4a5 + iml1)->isc_son = iml2;
     if (iml2 >= 0) {
       (adsl_node_r4a5 + iml2)->isc_dad = iml1;
     }
   }
#ifdef NOT_TRANSPARENT
   *achl_histbu_cur++ = ucl_inp_cur;        /* current input in history buffer */
#endif
   achl_histbu_cur++;                       /* next position history buffer */
   if (achl_histbu_cur > achl_histbu_max) {
     achl_histbu_max = achl_histbu_cur;     /* maximum reached position in history buffer */
   }
#ifdef TRACEHL1
   if ((achl_histbu_cur - ((char *) (adsl_enc_int + 1))) & 1) {  /* position in tree was even */
     bol1 = m_sr_check_1( adsp_cdr_ctrl, adsl_enc_int, achl_histbu_max - ((char *) (adsl_enc_int + 1)), FALSE );
     if (bol1 == FALSE) {
       iml1 = achl_histbu_cur - ((char *) (adsl_enc_int + 1));
       printf( "ENC l%05d p_ec_r4o5_out_80 single character history buffer corrupted / pos=%d/0X%X.\n",
               __LINE__, iml1, iml1 );
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
   }
#endif
   ucl_inp_previous = ucl_inp_cur;          /* save as previous input  */
   achl_inp++;                              /* input has been processed */
   bol_previous_char = TRUE;                /* previous character filled */
   goto p_ec_r4o5_cmp_00;                     /* RDP5 new character      */

   p_ec_r4o5_ret_00:                        /* RDP4/5 all processed    */
   if (bol_previous_char) {                 /* previous character filled */
#ifdef TRACEHL1
     printf( "ENC l%05d p_ec_r4o5_ret_00 output ucl_inp_previous %02X.\n",
             __LINE__, (unsigned char) ucl_inp_previous );
#endif
     if (bol_out_huffman == FALSE) {        /* output is not huffman encoded */
       if (((signed char) ucl_inp_previous) >= 0) {
         iml_shift_v <<= VAL_BYTE;          /* shift old bits          */
         iml_shift_v |= ucl_inp_previous;   /* get new bits            */
         iml_shift_c += VAL_BYTE;           /* shift-count             */
       } else {
         iml_shift_v <<= VAL_BYTE + 1;      /* shift old bits          */
         iml_shift_v |= 0X0100 | (ucl_inp_previous & 0X7F);  /* get new bits */
         iml_shift_c += VAL_BYTE + 1;       /* shift-count             */
       }
     } else {                               /* output is huffman encoded */
       iml1 = ucrs_rdp60_encode_1[ ucl_inp_previous ];  /* get number of bits */
       iml_shift_v |= usrs_rdp60_encode_2[ ucl_inp_previous ] << iml_shift_c;  /* get new bits */
       iml_shift_c += iml1;                 /* shift-count             */
     }
   }
   if (bol_out_huffman == FALSE) {          /* output is not huffman encoded */
     while (iml_shift_c > 0) {              /* output all bits         */
       iml_len_out++;                       /* increment length of output */
       if (iml_len_out >= iml_len_inp) {    /* compressed is longer than original */
         goto p_ec_trans_00;                /* output transparent      */
       }
       iml_shift_c -= VAL_BYTE;             /* shift-count             */
       ucl_w1 = (unsigned char) (iml_shift_v >> iml_shift_c);
       if (iml_shift_c < 0) {
         ucl_w1 = (unsigned char) (iml_shift_v << (0 - iml_shift_c));
       }
       bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, ucl_w1 );
       if (bol1 == FALSE) {                 /* error occured           */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
       }
     }
   } else {                                 /* output is huffman encoded */
     /* bits may be 7 + 13 + 13, too many for iml_shift_v              */
     if (iml_shift_c >= VAL_BYTE) {         /* shift-count at least byte */
       iml_len_out++;                       /* increment length of output */
       if (iml_len_out >= iml_len_inp) {    /* compressed is longer than original */
         goto p_ec_trans_00;                /* output transparent      */
       }
       bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) iml_shift_v );
       if (bol1 == FALSE) {                 /* error occured           */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
       }
       iml_shift_v >>= VAL_BYTE;            /* remove the bits         */
       iml_shift_c -= VAL_BYTE;             /* shift-count             */
     }
     iml1 = ucrs_rdp60_encode_1[ VAL_TAB_R60_D1_END ];  /* get number of bits */
     iml_shift_v |= usrs_rdp60_encode_2[ VAL_TAB_R60_D1_END ] << iml_shift_c;  /* get new bits */
     iml_shift_c += iml1;                   /* shift-count             */
     while (iml_shift_c > 0) {              /* output all bits         */
       iml_len_out++;                       /* increment length of output */
       if (iml_len_out >= iml_len_inp) {    /* compressed is longer than original */
         goto p_ec_trans_00;                /* output transparent      */
       }
       bol1 = m_enc_output( adsp_cdr_ctrl, adsl_enc_int, &dsl_out_1, (unsigned char) iml_shift_v );
       if (bol1 == FALSE) {                 /* error occured           */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
       }
       iml_shift_v >>= VAL_BYTE;            /* remove the bits         */
       iml_shift_c -= VAL_BYTE;             /* shift-count             */
     }
     /* copy RDP6.0 cache offset                                       */
     memcpy( (char *) (adsl_enc_int + 1)
               + 64 * 1024
               + D_MAX_BYTE * sizeof(struct dsd_entry_r4a5)
               + (64 * 1024) / 2 * sizeof(struct dsd_node_r4a5),
             imrl_cache_off,
             sizeof(imrl_cache_off) );
   }
   adsl_enc_int->boc_rdp60_at_front = FALSE;  /* not RDP 6.0 packet at front */
   /* copy input to history buffer                                     */
   adsl_gai1_in_w1 = adsl_enc_int->adsc_gai1_in_saved;  /* input data saved */
   if (adsl_gai1_in_w1 == NULL) {           /* no input data saved     */
     adsl_gai1_in_w1 = dsl_out_1.adsc_gai1_in_new;  /* input data new in last call */
   }
   do {                                     /* loop over all gather input */
     iml1 = adsl_gai1_in_w1->achc_ginp_end - adsl_gai1_in_w1->achc_ginp_cur;
     if (iml1 > 0) {                        /* something to copy       */
       memcpy( achl_saved_histbu_cur, adsl_gai1_in_w1->achc_ginp_cur, iml1 );
       achl_saved_histbu_cur += iml1;       /* increment position in history buffer */
       adsl_gai1_in_w1->achc_ginp_cur = adsl_gai1_in_w1->achc_ginp_end;
     }
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;  /* get next in chain */
   } while (adsl_gai1_in_w1);
#ifdef DEBUG_110516_01
#ifdef TRACEHL1
   printf( "ENC l%05d p_ec_r4o5_ret_00 hist-bu=%p achl_histbu_cur=%p achl_histbu_max=%p.\n",
           __LINE__, (char *) (adsl_enc_int + 1), achl_histbu_cur, achl_histbu_max );
   m_console_out( (char *) (adsl_enc_int + 1), achl_histbu_max - (char *) (adsl_enc_int + 1) );
#endif
#endif
#ifdef TRACEHL1
   bol1 = m_sr_check_1( adsp_cdr_ctrl, adsl_enc_int, achl_histbu_max - ((char *) (adsl_enc_int + 1)), TRUE );
   if (bol1 == FALSE) {
     printf( "ENC l%05d p_ec_r4o5_ret_00 history buffer corrupted\n",
             __LINE__ );
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error     */
     return;                                /* report error            */
   }
#endif
   adsl_enc_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
   adsl_enc_int->achc_histbu_max = achl_histbu_max;  /* maximum reached position in history buffer */
   adsl_enc_int->adsc_gai1_in_saved = NULL;  /* clear input data saved */
   if (dsl_out_1.adsc_gai1_out_last == NULL) {  /* no last gather output */
     adsp_cdr_ctrl->achc_out_cur = dsl_out_1.achc_out_cur;  /* current output */
     adsp_cdr_ctrl->boc_sr_flush = TRUE;    /* at end of data          */
     return;                                /* return to main program  */
   }
   dsl_out_1.adsc_gai1_out_last->adsc_next = NULL;  /* is last in chain */
   dsl_out_1.adsc_gai1_out_last->achc_ginp_end = dsl_out_1.achc_out_cur;  /* current output */
   adsp_cdr_ctrl->achc_out_cur = adsp_cdr_ctrl->achc_out_end;  /* buffer of main program was filled */
#ifdef TRACEHL1
   printf( "ENC l%05d p_ec_r4o5_ret_00 output longer than given from main program\n",
           __LINE__ );
   printf( "ENC l%05d p_ec_r4o5_ret_00 adsp_cdr_ctrl->boc_sr_flush=%d.\n",
           __LINE__, adsp_cdr_ctrl->boc_sr_flush );
   iml1 = 0;
   adsl_gai1_in_w1 = adsl_enc_int->adsc_gai1_out_saved;
   adsl_gai1_in_w2 = NULL;
   do {
     iml1++;
     iml2 = adsl_gai1_in_w1->achc_ginp_end - adsl_gai1_in_w1->achc_ginp_cur;
     printf( "ENC l%05d out-saved no=%d addr=%p achc_ginp_cur=%p achc_ginp_end=%p length=%d/0X%X.\n",
             __LINE__, iml1, adsl_gai1_in_w1, adsl_gai1_in_w1->achc_ginp_cur, adsl_gai1_in_w1->achc_ginp_end, iml2, iml2 );
     adsl_gai1_in_w2 = adsl_gai1_in_w1;     /* save this entry         */
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;  /* get next in chain */
   } while (adsl_gai1_in_w1);
   if (adsl_gai1_in_w2 != dsl_out_1.adsc_gai1_out_last) {
     printf( "ENC l%05d p_ec_r4o5_ret_00 chain corrupted\n",
             __LINE__ );
   }
#endif
   return;                                  /* return to main program  */

   p_ec_trans_00:                           /* output transparent      */
#ifdef TRACEHL1
   printf( "ENC l%05d p_ec_trans_00\n",
           __LINE__ );
#endif
#ifdef DEBUG_110519_03
   ims_match_enc = iml_save_match_enc;
#endif
#ifdef B120403
   adsp_cdr_ctrl->chrc_header[0] = 1;
#else
   adsp_cdr_ctrl->chrc_header[0] = adsl_enc_int->chc_comp_header;  /* value for compression header */
#endif
   /* remove the new nodes from the tree                               */
   adsl_gai1_in_w1 = adsl_enc_int->adsc_gai1_in_saved;  /* input data saved */
   adsl_enc_int->adsc_gai1_in_saved = NULL;  /* no more input data saved */
   if (adsl_gai1_in_w1 == NULL) {           /* no input data saved     */
     adsl_gai1_in_w1 = dsl_out_1.adsc_gai1_in_new;  /* input data new in last call */
   }
#ifdef B110519
   while (adsl_gai1_in_w1->achc_ginp_cur >= adsl_gai1_in_w1->achc_ginp_end) {
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
     if (adsl_gai1_in_w1 == NULL) {         /* end of input reached    */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
   }
#endif
   adsl_enc_int->adsc_gai1_out_saved = adsl_gai1_in_w1;  /* data to give back to main as output */
#ifdef TRACEHL1
   iml1 = 0;
   while (adsl_gai1_in_w1) {
     iml1 += adsl_gai1_in_w1->achc_ginp_end - adsl_gai1_in_w1->achc_ginp_cur;
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
   }
   printf( "ENC l%05d p_ec_trans_00 length-input=%d/0X%X.\n",
           __LINE__, iml1, iml1 );
   adsl_gai1_in_w1 = adsl_enc_int->adsc_gai1_out_saved;  /* data to give back to main as output */
#endif
   achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input        */
   achl_w1 = achl_saved_histbu_cur;         /* saved current position in history buffer */
   if (((long long int) achl_w1) & 1) {     /* history buffer position is odd */
     achl_w1++;                             /* next position history buffer */
     achl_inp++;                            /* current input           */
     while (achl_inp >= adsl_gai1_in_w1->achc_ginp_end) {
       adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
       if (adsl_gai1_in_w1 == NULL) {       /* end of input reached    */
#ifdef B110603
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
#else
         goto p_ecco_out_20;                /* pass saved output data  */
#endif
       }
       achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input    */
     }
   }
   if (achl_w1 >= achl_histbu_cur) {        /* no need to change tree  */
#ifdef TRACEHL1
     printf( "ENC l%05d p_ec_trans_00 no need to change history buffer\n",
             __LINE__ );
#endif
     goto p_ecco_out_20;                    /* pass saved output data  */
   }
   achl_w2 = achl_w1;                       /* save position for later */

   p_ec_trans_20:                           /* remove node from tree   */
   iml1 = (achl_w1 - ((char *) (adsl_enc_int + 1))) >> 1;
   ucl_w1 = (unsigned char) *achl_inp;
   iml2 = (adsl_node_r4a5 + iml1)->isc_dad;
   iml3 = (adsl_node_r4a5 + iml1)->isc_son;
   if (iml2 >= 0) {                         /* dad is valid entry      */
     (adsl_node_r4a5 + iml2)->isc_son = iml3;
   } else {
     (adsl_entry_r4a5_start + ucl_w1)->isc_son = iml3;
   }
   if (iml3 >= 0) {                         /* son is valid entry      */
     (adsl_node_r4a5 + iml3)->isc_dad = iml2;
   }
   achl_w1 += 2;                            /* next even position      */
   if (achl_w1 < achl_histbu_cur) {         /* still need to change tree */
     achl_inp++;                            /* current input           */
     while (achl_inp >= adsl_gai1_in_w1->achc_ginp_end) {
       adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
       if (adsl_gai1_in_w1 == NULL) {       /* end of input reached    */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
       }
       achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input    */
     }
     achl_inp++;                            /* current input           */
     while (achl_inp >= adsl_gai1_in_w1->achc_ginp_end) {
       adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
       if (adsl_gai1_in_w1 == NULL) {       /* end of input reached    */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
         return;                            /* report error            */
       }
       achl_inp = adsl_gai1_in_w1->achc_ginp_cur;  /* current input    */
     }
     goto p_ec_trans_20;                    /* remove node from tree   */
   }

   /* now add old entries to tree again                                */
   if (achl_w2 >= achl_saved_histbu_max) {  /* no need to add to tree  */
#ifdef TRACEHL1
     printf( "ENC l%05d p_ec_trans_00 position greater achl_saved_histbu_max\n",
             __LINE__ );
#endif
     goto p_ecco_out_20;                    /* pass saved output data  */
   }
#ifndef B110519
   achl_w1 = achl_histbu_cur;               /* changed up to here      */
   if (achl_w1 > achl_saved_histbu_max) {   /* not in old area         */
     achl_w1 = achl_saved_histbu_max;       /* only in old area        */
   }
#endif

   p_ec_trans_40:                           /* add node to tree        */
   iml1 = (achl_w2 - ((char *) (adsl_enc_int + 1))) >> 1;
#ifdef B110519
   ucl_w1 = (unsigned char) *achl_w2;
   iml2 = (adsl_entry_r4a5_start + ucl_w1)->isc_son;
   (adsl_entry_r4a5_start + ucl_w1)->isc_son = iml1;
#else
   adsl_entry_r4a5_cur = adsl_entry_r4a5_start + ((unsigned char) *achl_w2);  /* entry to array */
   iml2 = adsl_entry_r4a5_cur->isc_son;
   adsl_entry_r4a5_cur->isc_son = iml1;
#endif
   (adsl_node_r4a5 + iml1)->isc_dad = -1;
   (adsl_node_r4a5 + iml1)->isc_son = iml2;
   if (iml2 >= 0) {
     (adsl_node_r4a5 + iml2)->isc_dad = iml1;
   }
   achl_w2 += 2;                            /* next even position      */
#ifdef B110519
   if (   (achl_w2 < achl_histbu_cur)       /* need to change tree     */
       && (achl_w2 < achl_saved_histbu_max)) {  /* still in old area   */
     goto p_ec_trans_40;                    /* add node to tree        */
   }
#else
   if (achl_w2 < achl_w1) {                 /* need to change tree     */
     goto p_ec_trans_40;                    /* add node to tree        */
   }
#endif

   p_ecco_out_20:                           /* pass saved output data  */
#ifdef TRACEHL1
   iml1 = adsl_enc_int->achc_histbu_cur - ((char *) (adsl_enc_int + 1));
   iml2 = adsl_enc_int->achc_histbu_max - ((char *) (adsl_enc_int + 1));
   printf( "ENC l%05d p_ecco_out_20 pos-histbu-cur=%d/0X%X pos-histbuf-max=%d/0X%X.\n",
           __LINE__, iml1, iml1, iml2, iml2 );
   bol1 = m_sr_check_1( adsp_cdr_ctrl, adsl_enc_int, adsl_enc_int->achc_histbu_max - ((char *) (adsl_enc_int + 1)), TRUE );
   if (bol1 == FALSE) {
     printf( "ENC l%05d p_ecco_out_20 history buffer corrupted\n",
             __LINE__ );
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error     */
     return;                                /* report error            */
   }
#endif
   iml1 = adsp_cdr_ctrl->achc_out_end - adsp_cdr_ctrl->achc_out_cur;
   if (iml1 <= 0) return;                   /* no space in output area */

   p_ecco_out_40:                           /* next piece of saved output data */
   iml2 = adsl_enc_int->adsc_gai1_out_saved->achc_ginp_end - adsl_enc_int->adsc_gai1_out_saved->achc_ginp_cur;  /* length this gather input */
   if (iml2 > iml1) iml2 = iml1;            /* only as much as match   */
   memcpy( adsp_cdr_ctrl->achc_out_cur, adsl_enc_int->adsc_gai1_out_saved->achc_ginp_cur, iml2 );  /* copy to output area */
   adsp_cdr_ctrl->achc_out_cur += iml2;     /* increment output        */
   adsl_enc_int->adsc_gai1_out_saved->achc_ginp_cur += iml2;  /* increment input */
   iml1 -= iml2;                            /* length remaining space output area */
   if (adsl_enc_int->adsc_gai1_out_saved->achc_ginp_cur < adsl_enc_int->adsc_gai1_out_saved->achc_ginp_end) {
     return;                                /* wait for more space in output area */
   }
   adsl_enc_int->adsc_gai1_out_saved = adsl_enc_int->adsc_gai1_out_saved->adsc_next;  /* get next in chain */
   if (adsl_enc_int->adsc_gai1_out_saved) {  /* more data follow       */
     if (iml1 > 0) goto p_ecco_out_40;      /* next piece of saved output data */
     return;                                /* wait for more space in output area */
   }
   adsp_cdr_ctrl->boc_sr_flush = TRUE;      /* at end of data          */
   return;                                  /* all done                */
} /* end m_cdr_enc()                                                   */

static inline BOOL m_enc_output( struct dsd_cdr_ctrl *adsp_cdr_ctrl,
                                 struct dsd_enc_int *adsp_enc_int,
                                 struct dsd_out_1 *adsp_out_1,
                                 unsigned char chp1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_in_w1;  /* input data              */
   struct dsd_stor_ext *adsl_aux_st_w1;     /* auxiliary storage       */
   struct dsd_stor_ext *adsl_aux_st_w2;     /* auxiliary storage       */

#ifdef TRACEHL1
   printf( "l%05d output char=%02X achc_out_cur=%p.\n",
           __LINE__, chp1, adsp_out_1->achc_out_cur );
#endif
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
   adsl_gai1_in_w1 = adsp_out_1->adsc_gai1_in_saved;  /* input data saved */
   while (adsl_gai1_in_w1) {                /* loop over all input saved */
     iml1 = adsl_gai1_in_w1->achc_ginp_end - adsl_gai1_in_w1->achc_ginp_cur;
     if ((iml1 < 0) || (iml1 > (64 * 1024))) {
       printf( "l%05d output adsp_out_1->adsc_gai1_out_last=%p adsp_out_1->adsc_gai1_in_saved=%p iml1=%d/0X%X.\n",
                 __LINE__, adsp_out_1->adsc_gai1_out_last, adsp_out_1->adsc_gai1_in_saved, iml1, iml1 );
       return FALSE;
     }
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;  /* get next in chain */
   }
   adsl_gai1_in_w1 = adsp_enc_int->adsc_gai1_out_saved;  /* output data saved */
   while (adsl_gai1_in_w1) {                /* loop over all input saved */
     iml1 = adsl_gai1_in_w1->achc_ginp_end - adsl_gai1_in_w1->achc_ginp_cur;
     if ((iml1 <= 0) || (iml1 > LEN_AUX_STOR)) {
       printf( "l%05d output adsp_out_1->adsc_gai1_out_last=%p adsp_enc_int->adsc_gai1_out_saved=%p iml1=%d/0X%X.\n",
                 __LINE__, adsp_out_1->adsc_gai1_out_last, adsp_enc_int->adsc_gai1_out_saved, iml1, iml1 );
       printf( "l%05d output achc_save_mp=%p length=%d.\n",
               __LINE__, adsp_cdr_ctrl->achc_save_mp, adsp_cdr_ctrl->imc_save_mp_given );
       adsl_gai1_in_w1 = adsp_out_1->adsc_gai1_in_saved;  /* input data saved */
       while (adsl_gai1_in_w1) {            /* loop over all input saved */
         iml1 = adsl_gai1_in_w1->achc_ginp_end - adsl_gai1_in_w1->achc_ginp_cur;
         printf( "l%05d output saved gather %p achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%X.\n",
                 __LINE__, adsl_gai1_in_w1, adsl_gai1_in_w1->achc_ginp_cur, adsl_gai1_in_w1->achc_ginp_end, iml1, iml1 );
         adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;  /* get next in chain */
       }
       adsl_aux_st_w1 = adsp_enc_int->adsc_stor_ext;  /* external storage acquired */
       while (adsl_aux_st_w1) {             /* loop to print external storage */
         printf( "l%05d output externat storage adsl_aux_st_w1=%p end=%p.\n",
                 __LINE__, adsl_aux_st_w1, (char *) adsl_aux_st_w1 + LEN_AUX_STOR );
         adsl_aux_st_w1 = adsl_aux_st_w1->adsc_next;  /* get next in chain */
       }
       return FALSE;
     }
     adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;  /* get next in chain */
   }
   if (   (adsp_out_1->adsc_gai1_out_last == NULL)
       && (adsp_enc_int->adsc_gai1_out_saved)) {
     printf( "l%05d output adsp_out_1->adsc_gai1_out_last=%p adsp_enc_int->adsc_gai1_out_saved=%p.\n",
               __LINE__, adsp_out_1->adsc_gai1_out_last, adsp_enc_int->adsc_gai1_out_saved );
     return FALSE;
   }
   if (   (adsp_out_1->achc_out_cur < adsp_out_1->achc_out_end)
       && (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
       && (adsp_out_1->achc_out_cur == (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
     printf( "l%05d output *** corrupting memory save-mp-given at adsp_out_1->achc_out_cur=%p / end=%p.\n",
               __LINE__, adsp_out_1->achc_out_cur, adsp_out_1->achc_out_end );
     return FALSE;
   }
#endif
#endif
   if (adsp_out_1->achc_out_cur < adsp_out_1->achc_out_end) {
     *adsp_out_1->achc_out_cur++ = chp1;    /* insert character        */
     return TRUE;                           /* all done                */
   }
#ifdef TRACEHL1
   printf( "l%05d output area full adsp_out_1->adsc_gai1_out_last = %p adsp_out_1->achc_out_cur = %p adsp_out_1->achc_out_end = %p.\n",
           __LINE__, adsp_out_1->adsc_gai1_out_last, adsp_out_1->achc_out_cur, adsp_out_1->achc_out_end );
#endif
   adsl_aux_st_w1 = NULL;                   /* last auxiliary storage  */
   if (adsp_out_1->adsc_gai1_out_last == NULL) {  /* not yet last output */
     adsl_gai1_in_w1 = adsp_out_1->adsc_gai1_in_saved;  /* input data saved */
     if (adsl_gai1_in_w1 == NULL) {         /* we did not save input data */
       if (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1))) {
         adsp_enc_int->adsc_gai1_out_saved = adsp_out_1->adsc_gai1_out_last
           = (struct dsd_gather_i_1 *) adsp_cdr_ctrl->achc_save_mp;
         adsp_out_1->achc_out_cur = adsp_out_1->adsc_gai1_out_last->achc_ginp_cur
           = (char *) (adsp_out_1->adsc_gai1_out_last + 1);
         adsp_out_1->achc_out_end = adsp_out_1->adsc_gai1_out_last->achc_ginp_end
           = adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given;
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
         if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
             && (adsp_out_1->achc_out_cur == (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
           printf( "l%05d output *** corrupting memory save-mp-given at adsp_out_1->achc_out_cur=%p / end=%p.\n",
                     __LINE__, adsp_out_1->achc_out_cur, adsp_out_1->achc_out_end );
           return FALSE;
         }
#endif
#endif
         *adsp_out_1->achc_out_cur++ = chp1;  /* insert character      */
#ifdef DEBUG_110516_02
         adsp_out_1->adsc_gai1_out_last->adsc_next = NULL;
#endif
         return TRUE;                       /* all done                */
       }
       if (adsp_enc_int->adsc_stor_ext) {   /* external storage acquired */
         adsp_enc_int->adsc_gai1_out_saved = adsp_out_1->adsc_gai1_out_last
           = (struct dsd_gather_i_1 *) (adsp_enc_int->adsc_stor_ext + 1);
         adsp_out_1->achc_out_cur = adsp_out_1->adsc_gai1_out_last->achc_ginp_cur
           = (char *) (adsp_out_1->adsc_gai1_out_last + 1);
         adsp_out_1->achc_out_end = adsp_out_1->adsc_gai1_out_last->achc_ginp_end
#ifdef B140630
           = adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given;
#endif
#ifndef B140630
           = (char *) adsp_enc_int->adsc_stor_ext + LEN_AUX_STOR;
#endif
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
         if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
             && (adsp_out_1->achc_out_cur == (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
           printf( "l%05d output *** corrupting memory save-mp-given at adsp_out_1->achc_out_cur=%p / end=%p.\n",
                     __LINE__, adsp_out_1->achc_out_cur, adsp_out_1->achc_out_end );
           return FALSE;
         }
#endif
#endif
         *adsp_out_1->achc_out_cur++ = chp1;  /* insert character      */
#ifdef DEBUG_110516_02
         adsp_out_1->adsc_gai1_out_last->adsc_next = NULL;
#endif
         return TRUE;                       /* all done                */
       }
       /* we need to acquire a new block of external storage           */
     } else {                               /* we have input data      */
#ifdef B110516
       while (adsl_gai1_in_w1->adsc_next) adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
#else
       while (adsl_gai1_in_w1->adsc_next != adsp_out_1->adsc_gai1_in_new) {
         adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;
       }
#endif
       bol1 = FALSE;                        /* not in save-mp-given    */
       if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
           && (((char *) adsl_gai1_in_w1) == adsp_cdr_ctrl->achc_save_mp)) {
         iml1 = (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given)
                  - adsl_gai1_in_w1->achc_ginp_end
                  - sizeof(struct dsd_gather_i_1);
         iml1 &= 0 - sizeof(void *);        /* make aligned            */
         if (iml1 > 0) {
           adsp_enc_int->adsc_gai1_out_saved = adsp_out_1->adsc_gai1_out_last
             = (struct dsd_gather_i_1 *)
                 (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given
                   - iml1 - sizeof(struct dsd_gather_i_1));
           adsp_out_1->achc_out_cur = adsp_out_1->adsc_gai1_out_last->achc_ginp_cur
             = (char *) (adsp_out_1->adsc_gai1_out_last + 1);
           adsp_out_1->achc_out_end = adsp_out_1->adsc_gai1_out_last->achc_ginp_end
             = adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given;
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
           if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
               && (adsp_out_1->achc_out_cur == (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
             printf( "l%05d output *** corrupting memory save-mp-given at adsp_out_1->achc_out_cur=%p / end=%p.\n",
                       __LINE__, adsp_out_1->achc_out_cur, adsp_out_1->achc_out_end );
             return FALSE;
           }
#endif
#endif
           *adsp_out_1->achc_out_cur++ = chp1;  /* insert character    */
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
           printf( "l%05d output adsp_out_1->adsc_gai1_out_last=%p.\n",
                   __LINE__, adsp_out_1->adsc_gai1_out_last );
#endif
           adsp_out_1->adsc_gai1_out_last->adsc_next = NULL;
#endif
           return TRUE;                     /* all done                */
         }
         bol1 = TRUE;                       /* was in save-mp-given    */
       }
#define ADSL_STOR_EXT_L1 ((struct dsd_stor_ext *) ((char *) adsl_gai1_in_w1 - sizeof(struct dsd_stor_ext)))
       if (bol1 == FALSE) {                 /* not in save-mp-given    */
         iml1 = (char *) ADSL_STOR_EXT_L1 + LEN_AUX_STOR
                  - adsl_gai1_in_w1->achc_ginp_end
                  - sizeof(struct dsd_gather_i_1);
         iml1 &= 0 - sizeof(void *);        /* make aligned            */
         if (iml1 > 0) {
           adsp_enc_int->adsc_gai1_out_saved = adsp_out_1->adsc_gai1_out_last
             = (struct dsd_gather_i_1 *)
                 ((char *) ADSL_STOR_EXT_L1 + LEN_AUX_STOR
                    - iml1 - sizeof(struct dsd_gather_i_1));
           adsp_out_1->achc_out_cur = adsp_out_1->adsc_gai1_out_last->achc_ginp_cur
             = (char *) (adsp_out_1->adsc_gai1_out_last + 1);
           adsp_out_1->achc_out_end = adsp_out_1->adsc_gai1_out_last->achc_ginp_end
             = (char *) ADSL_STOR_EXT_L1 + LEN_AUX_STOR;
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
           if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
               && (adsp_out_1->achc_out_cur == (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
             printf( "l%05d output *** corrupting memory save-mp-given at adsp_out_1->achc_out_cur=%p / end=%p.\n",
                       __LINE__, adsp_out_1->achc_out_cur, adsp_out_1->achc_out_end );
             return FALSE;
           }
#endif
#endif
           *adsp_out_1->achc_out_cur++ = chp1;  /* insert character    */
#ifdef DEBUG_110516_02
           adsp_out_1->adsc_gai1_out_last->adsc_next = NULL;
#ifdef TRACEHL1
           printf( "l%05d output adsl_gai1_in_w1=%p achc_ginp_end=%p.\n",
                   __LINE__, adsl_gai1_in_w1, adsl_gai1_in_w1->achc_ginp_end );
           printf( "l%05d output adsp_out_1->adsc_gai1_out_last=%p achc_ginp_cur=%p achc_ginp_end=%p.\n",
                   __LINE__, adsp_out_1->adsc_gai1_out_last, adsp_out_1->adsc_gai1_out_last->achc_ginp_cur, adsp_out_1->adsc_gai1_out_last->achc_ginp_end );
           adsl_gai1_in_w1 = adsp_out_1->adsc_gai1_in_saved;  /* input data saved */
           while (adsl_gai1_in_w1) {        /* loop over all input saved */
             iml1 = adsl_gai1_in_w1->achc_ginp_end - adsl_gai1_in_w1->achc_ginp_cur;
             printf( "l%05d output saved gather %p achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%X.\n",
                     __LINE__, adsl_gai1_in_w1, adsl_gai1_in_w1->achc_ginp_cur, adsl_gai1_in_w1->achc_ginp_end, iml1, iml1 );
             adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;  /* get next in chain */
           }
           adsl_aux_st_w1 = adsp_enc_int->adsc_stor_ext;  /* external storage acquired */
           while (adsl_aux_st_w1) {         /* loop to print external storage */
             printf( "l%05d output externat storage adsl_aux_st_w1=%p end=%p.\n",
                     __LINE__, adsl_aux_st_w1, (char *) adsl_aux_st_w1 + LEN_AUX_STOR );
             adsl_aux_st_w1 = adsl_aux_st_w1->adsc_next;  /* get next in chain */
           }
#endif
#endif
           return TRUE;                     /* all done                */
         }
         adsl_aux_st_w1 = ADSL_STOR_EXT_L1;  /* last auxiliary storage */
       }
#undef ADSL_STOR_EXT_L1
     }
   } else {                                 /* not first gather output */
     adsl_aux_st_w1 = adsp_enc_int->adsc_stor_ext;  /* external storage acquired */
     if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
         && (((char *) adsp_out_1->adsc_gai1_out_last) >= adsp_cdr_ctrl->achc_save_mp)
         && (((char *) adsp_out_1->adsc_gai1_out_last) < (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
       if (adsl_aux_st_w1) {                /* external storage acquired */
         adsp_out_1->adsc_gai1_out_last->adsc_next
           = (struct dsd_gather_i_1 *) (adsl_aux_st_w1 + 1);
         adsp_out_1->adsc_gai1_out_last
           = (struct dsd_gather_i_1 *) (adsl_aux_st_w1 + 1);
         adsp_out_1->achc_out_cur = adsp_out_1->adsc_gai1_out_last->achc_ginp_cur
           = (char *) (adsp_out_1->adsc_gai1_out_last + 1);
#ifdef B110516
         adsp_out_1->achc_out_end = adsp_out_1->adsc_gai1_out_last->achc_ginp_end
           = adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given;
#else
         adsp_out_1->achc_out_end = adsp_out_1->adsc_gai1_out_last->achc_ginp_end
           = (char *) adsl_aux_st_w1 + LEN_AUX_STOR;
#endif
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
         if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
             && (adsp_out_1->achc_out_cur == (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
           printf( "l%05d output *** corrupting memory save-mp-given at adsp_out_1->achc_out_cur=%p / end=%p.\n",
                     __LINE__, adsp_out_1->achc_out_cur, adsp_out_1->achc_out_end );
           return FALSE;
         }
#endif
#endif
         *adsp_out_1->achc_out_cur++ = chp1;  /* insert character      */
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
         printf( "l%05d output adsp_out_1->adsc_gai1_out_last=%p achc_ginp_cur=%p achc_ginp_end=%p.\n",
                 __LINE__, adsp_out_1->adsc_gai1_out_last, adsp_out_1->adsc_gai1_out_last->achc_ginp_cur, adsp_out_1->adsc_gai1_out_last->achc_ginp_end );
#endif
         adsp_out_1->adsc_gai1_out_last->adsc_next = NULL;
#endif
         return TRUE;                       /* all done                */
       }
     } else {                               /* last was not in save main given */
       while (TRUE) {                       /* loop to search external storage last used */
         if (   (((char *) adsp_out_1->adsc_gai1_out_last) > ((char *) adsl_aux_st_w1))
             && (((char *) adsp_out_1->adsc_gai1_out_last) < ((char *) adsl_aux_st_w1 + LEN_AUX_STOR))) {
           break;
         }
         adsl_aux_st_w1 = adsl_aux_st_w1->adsc_next;  /* get next in chain */
#ifndef DEBUG_110516_02
         if (adsl_aux_st_w1 == NULL) return FALSE;
#else
         if (adsl_aux_st_w1 == NULL) {
#ifdef TRACEHL1
           printf( "l%05d output last not found in chain adsp_out_1->adsc_gai1_out_last=%p.\n",
                   __LINE__, adsp_out_1->adsc_gai1_out_last );
           printf( "l%05d output achc_save_mp=%p length=%d.\n",
                   __LINE__, adsp_cdr_ctrl->achc_save_mp, adsp_cdr_ctrl->imc_save_mp_given );
           adsl_aux_st_w1 = adsp_enc_int->adsc_stor_ext;  /* external storage acquired */
           while (adsl_aux_st_w1) {         /* loop to print external storage */
             printf( "l%05d output external storage adsl_aux_st_w1=%p.\n",
                     __LINE__, adsl_aux_st_w1 );
             adsl_aux_st_w1 = adsl_aux_st_w1->adsc_next;  /* get next in chain */
           }
#endif
           return FALSE;
         }
#endif
       }
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
         printf( "l%05d output adsp_out_1->adsc_gai1_out_last=%p achc_ginp_cur=%p achc_ginp_end=%p.\n",
                 __LINE__, adsp_out_1->adsc_gai1_out_last, adsp_out_1->adsc_gai1_out_last->achc_ginp_cur, adsp_out_1->adsc_gai1_out_last->achc_ginp_end );
#endif
#endif
     }
   }
   adsl_gai1_in_w1 = adsp_out_1->adsc_gai1_out_last;  /* save last used gather */
   adsl_aux_st_w2 = adsp_enc_int->adsc_stor_ext;  /* external storage acquired */
   if (adsl_aux_st_w1) {                    /* last auxiliary storage  */
     adsl_aux_st_w2 = adsl_aux_st_w1->adsc_next;  /* we can take next one, if exists */
   }
   if (adsl_aux_st_w2) {                    /* we have full external block */
     adsp_out_1->adsc_gai1_out_last
       = (struct dsd_gather_i_1 *) (adsl_aux_st_w2 + 1);
     if (adsl_gai1_in_w1 == NULL) {         /* was first block used    */
       adsp_enc_int->adsc_gai1_out_saved = adsp_out_1->adsc_gai1_out_last;
     } else {                               /* append to chain         */
       adsl_gai1_in_w1->adsc_next = adsp_out_1->adsc_gai1_out_last;
     }
     adsp_out_1->achc_out_cur = adsp_out_1->adsc_gai1_out_last->achc_ginp_cur
       = (char *) (adsp_out_1->adsc_gai1_out_last + 1);
     adsp_out_1->achc_out_end = adsp_out_1->adsc_gai1_out_last->achc_ginp_end
       = (char *) adsl_aux_st_w2 + LEN_AUX_STOR;
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
     if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
         && (adsp_out_1->achc_out_cur == (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
       printf( "l%05d output *** corrupting memory save-mp-given at adsp_out_1->achc_out_cur=%p / end=%p.\n",
                 __LINE__, adsp_out_1->achc_out_cur, adsp_out_1->achc_out_end );
       return FALSE;
     }
#endif
#endif
     *adsp_out_1->achc_out_cur++ = chp1;    /* insert character        */
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
     printf( "l%05d output found adsl_aux_st_w2=%p.\n",
             __LINE__, adsl_aux_st_w2 );
     printf( "l%05d output adsp_out_1->adsc_gai1_out_last=%p achc_ginp_cur=%p achc_ginp_end=%p.\n",
             __LINE__, adsp_out_1->adsc_gai1_out_last, adsp_out_1->adsc_gai1_out_last->achc_ginp_cur, adsp_out_1->adsc_gai1_out_last->achc_ginp_end );
#endif
     adsl_aux_st_w1 = adsp_enc_int->adsc_stor_ext;  /* external storage acquired */
     adsl_aux_st_w2 = NULL;
     while (adsl_aux_st_w1) {               /* loop to check external storage */
       adsl_aux_st_w2 = adsl_aux_st_w1;
       adsl_aux_st_w1 = adsl_aux_st_w1->adsc_next;  /* get next in chain */
     }
     adsp_out_1->adsc_gai1_out_last->adsc_next = NULL;
#endif
     return TRUE;                           /* all done                */
   }
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
   if ((adsp_enc_int->adsc_stor_ext) && (adsl_aux_st_w1 == NULL)) {
     printf( "l%05d output *** ERROR *** forget blocks\n",
             __LINE__ );
   }
#endif
#endif
   bol1 = (*adsp_cdr_ctrl->amc_aux)( adsp_cdr_ctrl->vpc_userfld, DEF_AUX_MEMGET, &adsl_aux_st_w2, LEN_AUX_STOR );
   if (bol1 == FALSE) return FALSE;         /* error                   */
   if (adsl_aux_st_w1) adsl_aux_st_w1->adsc_next = adsl_aux_st_w2;
   else adsp_enc_int->adsc_stor_ext = adsl_aux_st_w2;
   adsl_aux_st_w2->adsc_next = NULL;
   adsp_out_1->adsc_gai1_out_last
     = (struct dsd_gather_i_1 *) (adsl_aux_st_w2 + 1);
   if (adsl_gai1_in_w1 == NULL) {           /* was first block acquired */
     adsp_enc_int->adsc_gai1_out_saved = adsp_out_1->adsc_gai1_out_last;
   } else {                                 /* append to chain         */
     adsl_gai1_in_w1->adsc_next = adsp_out_1->adsc_gai1_out_last;
   }
   adsp_out_1->achc_out_cur = adsp_out_1->adsc_gai1_out_last->achc_ginp_cur
     = (char *) (adsp_out_1->adsc_gai1_out_last + 1);
   adsp_out_1->achc_out_end = adsp_out_1->adsc_gai1_out_last->achc_ginp_end
     = (char *) adsl_aux_st_w2 + LEN_AUX_STOR;
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
   if (   (adsp_cdr_ctrl->imc_save_mp_given > (sizeof(struct dsd_gather_i_1)))
       && (adsp_out_1->achc_out_cur == (adsp_cdr_ctrl->achc_save_mp + adsp_cdr_ctrl->imc_save_mp_given))) {
     printf( "l%05d output *** corrupting memory save-mp-given at adsp_out_1->achc_out_cur=%p / end=%p.\n",
               __LINE__, adsp_out_1->achc_out_cur, adsp_out_1->achc_out_end );
     return FALSE;
   }
#endif
#endif
   *adsp_out_1->achc_out_cur++ = chp1;      /* insert character        */
#ifdef DEBUG_110516_02
#ifdef TRACEHL1
   printf( "l%05d output found adsl_aux_st_w2=%p.\n",
           __LINE__, adsl_aux_st_w2 );
   printf( "l%05d output adsp_out_1->adsc_gai1_out_last=%p achc_ginp_cur=%p achc_ginp_end=%p.\n",
           __LINE__, adsp_out_1->adsc_gai1_out_last, adsp_out_1->adsc_gai1_out_last->achc_ginp_cur, adsp_out_1->adsc_gai1_out_last->achc_ginp_end );
#endif
   adsl_aux_st_w1 = adsp_enc_int->adsc_stor_ext;  /* external storage acquired */
   adsl_aux_st_w2 = NULL;
   while (adsl_aux_st_w1) {               /* loop to check external storage */
     adsl_aux_st_w2 = adsl_aux_st_w1;
     adsl_aux_st_w1 = adsl_aux_st_w1->adsc_next;  /* get next in chain */
   }
   adsp_out_1->adsc_gai1_out_last->adsc_next = NULL;
#endif
   return TRUE;
} /* end m_enc_output()                                                */

#ifdef TRACEHL1
static BOOL m_sr_check_1( struct dsd_cdr_ctrl *adsp_cdr_ctrl, struct dsd_enc_int *adsp_enc_int, int imp_len_hist_bu, BOOL bop_check_char )
{
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_end_hist_bu;              /* end compare history buffer */
   int        iml_count_node;               /* count the nodes         */
   struct dsd_enc_int *adsl_enc_int;        /* fields for encode       */
   int        iml_len_hist_bu;              /* length history buffer   */
#ifndef HL_FREEBSD
   union {
     struct {
#endif
       struct dsd_entry_r4a5 *adsl_entry_r4a5_start;  /* entry RDP5 start  */
       struct dsd_entry_r4a5 *adsl_entry_r4a5_cur;  /* entry RDP5 current  */
       struct dsd_node_r4a5 *adsl_node_r4a5;    /* node RDP5               */
#ifndef HL_FREEBSD
     };
   };
#endif

   adsl_enc_int = (struct dsd_enc_int *) adsp_cdr_ctrl->ac_ext;  /* get address of fields */
   switch (adsp_cdr_ctrl->imc_param_1) {    /* type of compression     */
     case 40:                               /* RDP4                    */
       iml_len_hist_bu = 8192;              /* size history buffer RDP4 */
       break;
     case 50:                               /* RDP5                    */
       iml_len_hist_bu = 64 * 1024;
       break;
     case 60:                               /* RDP6.0                  */
       iml_len_hist_bu = 64 * 1024;
       break;
     default:
#ifdef TRACEHL1
       printf( "ENC l%05d start imc_param_1=%d invalid value / allowed: 40 50 60.\n",
               __LINE__, adsp_cdr_ctrl->imc_param_1 );
#endif
       return FALSE;                        /* return to calling program */
   }
   iml_end_hist_bu = (imp_len_hist_bu + 1) >> 1;  /* end compare history buffer */
   iml_count_node = 0;                      /* count the nodes         */
   adsl_entry_r4a5_start = adsl_enc_int->adsc_entry_r4a5;  /* entry RDP5   */
   adsl_node_r4a5 = adsl_enc_int->adsc_node_r4a5;  /* node RDP5            */
   iml1 = 0;                                /* clear character         */

   p_ch_00:                                 /* loop to check           */
   adsl_entry_r4a5_cur = adsl_entry_r4a5_start + iml1;  /* entry to array  */
   iml2 = adsl_entry_r4a5_cur->isc_son;
   if (iml2 >= 0) {
     iml3 = -1;                             /* set dad                 */
     do {
       if (iml2 >= iml_end_hist_bu) {
         printf( "ENC l%05d m_sr_check_1() position too high %d/0X%X compared to %d/0X%X.\n",
                 __LINE__, iml2, iml2, iml_end_hist_bu, iml_end_hist_bu );
         return FALSE;
       }
       if (   (bop_check_char)
           && (*((unsigned char *) (adsl_enc_int + 1) + (iml2 << 1)) != ((unsigned char) iml1))) {
         printf( "ENC l%05d m_sr_check_1() character in history buffer %02X at %d/0X%X not equal to index %02X.\n",
                 __LINE__,
                 *((unsigned char *) (adsl_enc_int + 1) + (iml2 << 1)),
                 iml2,
                 iml2,
                 ((unsigned char) iml1) );
         return FALSE;
       }
       if ((adsl_node_r4a5 + iml2)->isc_dad != iml3) {
         printf( "ENC l%05d m_sr_check_1() dad at %d/0X%X invalid / %d/0X%X - should be %d/0X%X.\n",
                 __LINE__,
                 iml2,
                 iml2,
                 (adsl_node_r4a5 + iml2)->isc_dad,
                 (adsl_node_r4a5 + iml2)->isc_dad,
                 iml3,
                 iml3 );
         return FALSE;
       }
       iml3 = iml2;
       iml2 = (adsl_node_r4a5 + iml2)->isc_son;
       iml_count_node++;                    /* count the nodes         */
     } while (iml2 >= 0);
   }
   iml1++;                                  /* increment character     */
   if (iml1 < 0X0100) {                     /* valid character         */
     goto p_ch_00;                          /* loop to check           */
   }
   if (iml_count_node != iml_end_hist_bu) {  /* count the nodes        */
     printf( "ENC l%05d m_sr_check_1() nodes found %d/0X%X - should be %d/0X%X.\n",
             __LINE__,
             iml_count_node,
             iml_count_node,
             iml_end_hist_bu,
             iml_end_hist_bu );
     return FALSE;
   }
   return TRUE;
} /* end m_sr_check_1()                                                */
#endif

extern "C" void D_M_CDX_DEC( struct dsd_cdr_ctrl *adsp_cdr_ctrl )  /* decode = decompression */
{
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_copy_offset;              /* copy-offset             */
   int        iml_len_of_match;             /* Length-of-Match         */
   char       chl_w1;                       /* working variable        */
#ifndef D_LONG_SHIFT
   int        iml_shift_v;                  /* shift-value             */
#else
   long long int iml_shift_v;               /* shift-value             */
#endif
   int        iml_shift_c;                  /* shift-count             */
   char       *achl_w1;                     /* working variable        */
   char       *achl_histbu_end;             /* end of history buffer   */
   char       *achl_histbu_cur;             /* current position in history buffer */
   char       *achl_histbu_max;             /* maximum position in history buffer */
   char       *achl_out_cur;                /* current end of output data */
   char       *achl_out_end;                /* end of buffer for output data */
   struct dsd_dec_int *adsl_dec_int;        /* fields for decode       */
   struct dsd_gather_i_1 *adsl_gai1_in;     /* input data              */

#define IMRL_CACHE_OFF ((int *) ((char *) (adsl_dec_int + 1) + 64 * 1024))

   if (adsp_cdr_ctrl->imc_func == DEF_IFUNC_CONT) goto pdcfc00;
   if (adsp_cdr_ctrl->imc_func != DEF_IFUNC_START) goto pdcfunc;

   /* function start                                                   */
   switch (adsp_cdr_ctrl->imc_param_1) {    /* type of decompression   */
     case 40:                               /* RDP4                    */
       iml1 = iml2 = 8192;
       break;
     case 50:                               /* RDP5                    */
       iml1 = iml2 = 64 * 1024;
       break;
     case 60:                               /* RDP6.0                  */
       iml1 = 64 * 1024 + (VAL_CACHE_OFF + 1) * sizeof(int);
       iml2 = 64 * 1024;
       break;
     default:
#ifdef TRACEHL1
       printf( "DEC l%05d start imc_param_1=%d invalid value / allowed: 40 50 60.\n",
               __LINE__, adsp_cdr_ctrl->imc_param_1 );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error   */
       return;                              /* return to main-prog     */
   }

   bol1 = (*adsp_cdr_ctrl->amc_aux)( adsp_cdr_ctrl->vpc_userfld, DEF_AUX_MEMGET, &adsl_dec_int,
                                     sizeof(struct dsd_dec_int) + iml1 );
                                            /* get memory              */
   if (bol1 == FALSE) {
     adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error     */
     return;                                /* return to main-prog     */
   }
   memset( adsl_dec_int, 0, sizeof(struct dsd_dec_int) );  /* clear buffer */
   adsl_dec_int->achc_histbu_end = (char *) (adsl_dec_int + 1) + iml2;  /* end of history buffer */
   adsl_dec_int->achc_histbu_cur = (char *) (adsl_dec_int + 1);  /* current position in history buffer */
   adsl_dec_int->achc_histbu_max = (char *) (adsl_dec_int + 1);  /* current position in history buffer */
   adsp_cdr_ctrl->imc_len_header = 1;       /* length of header data   */
   adsp_cdr_ctrl->boc_compressed = TRUE;    /* always compressed       */
   adsp_cdr_ctrl->imc_save_mp_needed = 0;   /* do not use save-area mp */
   adsp_cdr_ctrl->ac_ext = adsl_dec_int;    /* store address of fields */
   adsp_cdr_ctrl->imc_func = DEF_IFUNC_CONT;  /* next call continue    */
   adsp_cdr_ctrl->imc_return = DEF_IRET_NORMAL;  /* call subroutine again */
   if (adsp_cdr_ctrl->imc_param_1 != 60) return;  /* not RDP6.0        */
   /* prepare RDP6.0 cache offset                                      */
   memset( IMRL_CACHE_OFF,
           0XFF,
           VAL_CACHE_OFF * sizeof(int) );
   *(IMRL_CACHE_OFF + VAL_CACHE_OFF) = 0;
   return;                                  /* return to main program  */

   pdcfunc:                                 /* other function received */
   adsp_cdr_ctrl->imc_return = DEF_IRET_END;  /* all done              */
   if (adsp_cdr_ctrl->imc_func != DEF_IFUNC_END) {
#ifdef TRACEHL1
     printf( "DEC l%05d invalid function %d.\n",
             __LINE__, adsp_cdr_ctrl->imc_func );
#endif
     adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error     */
   }
#ifdef B110520
   bol1 = (*adsp_cdr_ctrl->amc_aux)( adsp_cdr_ctrl->vpc_userfld, DEF_AUX_MEMFREE, &adsp_cdr_ctrl->ac_ext,
                            sizeof(struct dsd_enc_int)
                            + adsp_cdr_ctrl->imc_param_2
                            + ((1 << adsp_cdr_ctrl->imc_param_1) - VAL_N5) * sizeof(struct dsd_dict_2) );
                                            /* get memory              */
#else
   bol1 = (*adsp_cdr_ctrl->amc_aux)( adsp_cdr_ctrl->vpc_userfld,
                                     DEF_AUX_MEMFREE,
                                     &adsp_cdr_ctrl->ac_ext,
                                     sizeof(struct dsd_dec_int) );
#endif
   if (bol1 == FALSE) {
     adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error     */
     return;                                /* return to main-prog     */
   }
   return;                                  /* return to main-prog     */

   pdcfc00:                                 /* function continue       */
   adsl_dec_int = (struct dsd_dec_int *) adsp_cdr_ctrl->ac_ext;  /* get address of fields */
#ifdef XYZ1
   adsp_cdr_ctrl->boc_sr_flush = FALSE;     /* not yet end of record   */
#endif
#ifdef TRACEHL1
   {
     char *achh_w1 = NULL;
     adsl_gai1_in = adsp_cdr_ctrl->adsc_gai1_in;  /* get input data    */
     iml1 = 0;
     while (adsl_gai1_in) {
       iml1 += adsl_gai1_in->achc_ginp_end - adsl_gai1_in->achc_ginp_cur;
       if (   (achh_w1 == NULL)
           && (adsl_gai1_in->achc_ginp_cur < adsl_gai1_in->achc_ginp_end)) {
           achh_w1 = adsl_gai1_in->achc_ginp_cur;
       }
       adsl_gai1_in = adsl_gai1_in->adsc_next;
     }
     iml2 = adsp_cdr_ctrl->achc_out_end - adsp_cdr_ctrl->achc_out_cur;
     printf( "DEC l%05d start length-input=%d/0X%p length-output=%d/0X%p cont=%d header=0X%02X hist-buf=%p boc_mp_flush=%d st-inp=%p.\n",
             __LINE__, iml1, iml1, iml2, iml2,
             adsl_dec_int->iec_dec_cont,
             (unsigned char) adsp_cdr_ctrl->chrc_header[0],
             adsl_dec_int->achc_histbu_cur    /* current position in history buffer */
               - ((char *) (adsl_dec_int + 1)),  /* begin of history buffer */
             adsp_cdr_ctrl->boc_mp_flush,
             achh_w1 );
   }
#endif
   adsl_gai1_in = adsp_cdr_ctrl->adsc_gai1_in;  /* get input data      */
   while (   (adsl_gai1_in)
          && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {
     adsl_gai1_in = adsl_gai1_in->adsc_next;
   }
   adsp_cdr_ctrl->boc_sr_flush = adsp_cdr_ctrl->boc_mp_flush;  /* set FLUSH as input */
#ifdef B110515
#ifndef TRY_110418_01
   if (adsl_gai1_in == NULL) return;
#else
   if (adsl_gai1_in == NULL) {
     if (adsp_cdr_ctrl->boc_mp_flush == FALSE) return;
     adsl_dec_int->imc_shift_c = 0;         /* shift-count             */
     return;
   }
#endif
#else
   if (adsl_gai1_in == NULL) {
#ifdef B110516
     if (adsl_dec_int->iec_dec_cont != ied_dc_dcco64) {  /* continue output match */
       if (adsp_cdr_ctrl->boc_mp_flush == FALSE) return;
       if (adsl_dec_int->iec_dec_cont == ied_dc_dcbu20) {  /* continue compressed packet */
         adsl_dec_int->iec_dec_cont = ied_dc_dcbu00;  /* start of new packet */
#ifdef DEBUG_110516_01
#ifdef TRACEHL1
         printf( "DEC l%05d ret hist-bu=%p achl_histbu_cur=%p achl_histbu_max=%p.\n",
                 __LINE__, (char *) (adsl_dec_int + 1), adsl_dec_int->achc_histbu_cur, adsl_dec_int->achc_histbu_max );
         m_console_out( (char *) (adsl_dec_int + 1), adsl_dec_int->achc_histbu_max - (char *) (adsl_dec_int + 1) );
#endif
#endif
         return;                            /* wait for new packet     */
       }
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;
     }
#else
     if (   (adsl_dec_int->iec_dec_cont != ied_dc_dcco64)  /* continue output match */
         && !(   (adsl_dec_int->iec_dec_cont == ied_dc_dcbu20)  /* continue compressed packet */
              && (adsl_dec_int->imc_shift_c >= VAL_BYTE))) {
       if (adsp_cdr_ctrl->boc_mp_flush == FALSE) return;
       if (adsl_dec_int->iec_dec_cont == ied_dc_dcbu20) {  /* continue compressed packet */
         adsl_dec_int->iec_dec_cont = ied_dc_dcbu00;  /* start of new packet */
         return;                            /* wait for new packet     */
       }
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;
     }
#endif
   }
#endif
   achl_out_cur = adsp_cdr_ctrl->achc_out_cur;  /* current end of output data */
   achl_out_end = adsp_cdr_ctrl->achc_out_end;  /* end of buffer for output data */
   if (achl_out_cur >= achl_out_end) {      /* no space for output data */
     adsp_cdr_ctrl->boc_sr_flush = FALSE;   /* did not reach end of input */
     return;
   }
   iml_copy_offset = 0;                     /* for compiler only, copy-offset */
   iml_len_of_match = 0;                    /* for compiler only, Length-of-Match */
   switch (adsl_dec_int->iec_dec_cont) {    /* where to continue decode */
     case ied_dc_dcbu00:                    /* start of new packet     */
       goto pdcbu00;                        /* start of new packet     */
     case ied_dc_dcbu20:                    /* continue compressed packet */
       goto pdcbu20;                        /* continue compressed packet */
     case ied_dc_dcco64:                    /* continue output match   */
       goto pdcco64;                        /* we have more output area */
     case ied_dc_dcco72:                    /* continue start calculating Length-of-Match */
       goto pdcco72;                        /* we have more output area */
     case ied_dc_dcco80:                    /* continue bits for Length-of-Match */
       goto pdcco80;                        /* continue bits for Length-of-Match */
   }
   /* the program should never come here                               */
   adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error       */
   return;

   pdcbu00:                                 /* start of new packet     */
   if ((adsp_cdr_ctrl->chrc_header[0] & HL_RDP_PACKET_COMPRESSED) == 0) {
     goto pdc_trans_00;                     /* input data transparent  */
   }
   adsl_dec_int->iec_dec_cont = ied_dc_dcbu20;  /* continue compressed packet */
   achl_histbu_end = adsl_dec_int->achc_histbu_end;  /* end of history buffer */
   achl_histbu_cur = adsl_dec_int->achc_histbu_cur;  /* current position in history buffer */
   achl_histbu_max = adsl_dec_int->achc_histbu_max;  /* maximum position in history buffer */
#ifdef DEBUG_110815_01                      /* RDP6.0 packet at front  */
   if (adsp_cdr_ctrl->chrc_header[0] & HL_RDP_PACKET_AT_FRONT) {
     printf( "DEC l%05d HL_RDP_PACKET_AT_FRONT set\n",
             __LINE__ );
   }
#endif
   if (   (adsp_cdr_ctrl->chrc_header[0] & HL_RDP_PACKET_AT_FRONT)
       && (adsp_cdr_ctrl->imc_param_1 == 60)  /* RDP6.0                */
       && (achl_histbu_cur != ((char *) (adsl_dec_int + 1)))) {  /* current position in history buffer */
     achl_w1 = (char *) (adsl_dec_int + 1) + 64 * 1024 / 2;  /* here is halve of history buffer */
     iml1 = achl_histbu_cur - achl_w1;      /* compute filled more than halve */
     if (iml1 < 0) {                        /* position was in first part of history buffer */
#ifdef TRACEHL1
       printf( "DEC l%05d difference postion history buffer and halve: %d.\n",
               __LINE__, iml1 );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
     if (iml1 > 0) {                        /* we copy part of history buffer */
       memmove( adsl_dec_int + 1,
                achl_histbu_cur - 64 * 1024 / 2,
                64 * 1024 / 2 );
     }
     achl_histbu_cur = achl_histbu_max = achl_w1;  /* set new pointer history buffer */
   } else if (adsp_cdr_ctrl->chrc_header[0] & (HL_RDP_PACKET_AT_FRONT | HL_RDP_PACKET_FLUSHED)) {
     achl_histbu_cur = (char *) (adsl_dec_int + 1);  /* current position in history buffer */
   }
   iml_shift_c = 0;                         /* shift-count             */
   /* for compiler only                                                */
   iml_shift_v = 0;                         /* clear the value         */
#ifdef TRACEHL1
   printf( "DEC l%05d pdcbu00 iml_shift_c=%d iml_shift_v=0X%08X.\n",
           __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
   switch (adsp_cdr_ctrl->imc_param_1) {    /* type of decompression   */
     case 40:                               /* RDP4                    */
       goto p_dcco_r4_00;                   /* get codeword RDP4       */
     case 50:                               /* RDP5                    */
       goto p_dcco_r5_00;                   /* get codeword RDP5       */
     case 60:                               /* RDP6.0                  */
       goto p_dcco_r6_00;                   /* get codeword RDP6.0     */
   }
#ifdef TRACEHL1
   printf( "DEC l%05d continue imc_param_1=%d invalid value / allowed: 40 50 60.\n",
           __LINE__, adsp_cdr_ctrl->imc_param_1 );
#endif
   adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error       */
   return;                                  /* return to main-prog     */

   pdcbu20:                                 /* continue compressed packet */
   iml_shift_v = adsl_dec_int->imc_shift_v;  /* shift-value            */
   iml_shift_c = adsl_dec_int->imc_shift_c;  /* shift-count            */
   achl_histbu_end = adsl_dec_int->achc_histbu_end;  /* end of history buffer */
   achl_histbu_cur = adsl_dec_int->achc_histbu_cur;  /* current position in history buffer */
   achl_histbu_max = adsl_dec_int->achc_histbu_max;  /* maximum position in history buffer */
#ifdef TRACEHL1
   printf( "DEC l%05d pdcbu20 iml_shift_c=%d iml_shift_v=0X%08X.\n",
           __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
   switch (adsp_cdr_ctrl->imc_param_1) {    /* type of decompression   */
     case 40:                               /* RDP4                    */
       goto p_dcco_r4_00;                   /* get codeword RDP4       */
     case 50:                               /* RDP5                    */
       goto p_dcco_r5_00;                   /* get codeword RDP5       */
     case 60:                               /* RDP6.0                  */
       goto p_dcco_r6_00;                   /* get codeword RDP6.0     */
   }
#ifdef TRACEHL1
   printf( "DEC l%05d pdcbu20 imc_param_1=%d invalid value / allowed: 40 50 60.\n",
           __LINE__, adsp_cdr_ctrl->imc_param_1 );
#endif
   adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error       */
   return;                                  /* return to main-prog     */

   p_dcco_r4_00:                            /* get codeword RDP4       */
   if (iml_shift_c >= VAL_BYTE) {           /* check if full byte      */
     goto p_dcco_r4_08;                     /* we have the codeword    */
   }
   while (   (adsl_gai1_in)                 /* we have gather          */
          && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
     adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain     */
   }
   if (adsl_gai1_in == NULL) {              /* end of input            */
#ifdef TRACEHL1
     printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
     adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
     adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
     adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
     adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
     adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
     if (adsp_cdr_ctrl->boc_mp_flush == FALSE) return;
#ifdef DEBUG_110516_01
#ifdef TRACEHL1
     printf( "DEC l%05d ret hist-bu=%p achl_histbu_cur=%p achl_histbu_max=%p.\n",
             __LINE__, (char *) (adsl_dec_int + 1), achl_histbu_cur, achl_histbu_max );
     m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_max - (char *) (adsl_dec_int + 1) );
#endif
#endif
     adsl_dec_int->iec_dec_cont = ied_dc_dcbu00;  /* start of new packet */
     return;                                /* wait for new packet     */
   }
   iml_shift_v <<= VAL_BYTE;                /* space for new bits      */
   iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
   iml_shift_c += VAL_BYTE;                 /* add bits                */

   p_dcco_r4_08:                            /* we have the codeword    */
   chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - VAL_BYTE));
   iml1 = ucrs_leading_bits[ (unsigned char) chl_w1 ];
   if (iml1 == 0) {                         /* MSB bit not set         */
     if (achl_histbu_cur >= achl_histbu_end) {
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
     if (achl_out_cur >= achl_out_end) {
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       adsp_cdr_ctrl->boc_sr_flush = FALSE;  /* did not reach end of input */
       return;
     }
     iml_shift_c -= VAL_BYTE;               /* subtract bits           */
     *achl_histbu_cur++ = chl_w1;           /* current position in history buffer */
     if (achl_histbu_cur > achl_histbu_max) {  /* new maximum reached  */
       achl_histbu_max = achl_histbu_cur;   /* set new maximum         */
     }
     *achl_out_cur++ = chl_w1;              /* output character        */
     goto p_dcco_r4_00;                     /* get codeword            */
   }
   iml2 = imrs_rdp4_co_off_len_total[ iml1 ];
   while (iml2 >= iml_shift_c) {            /* we need at least (iml2 + 1) bits */
     while (   (adsl_gai1_in)               /* we have gather          */
            && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
     }
     if (adsl_gai1_in == NULL) {            /* end of input            */
#ifdef TRACEHL1
       printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
               __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       if (adsp_cdr_ctrl->boc_mp_flush) {   /* if FLUSH input set      */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
       }
       return;
     }
     iml_shift_v <<= VAL_BYTE;              /* space for new bits      */
     iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
   if (iml1 == 1) {
     if (achl_histbu_cur >= achl_histbu_end) {
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
     if (achl_out_cur >= achl_out_end) {
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       adsp_cdr_ctrl->boc_sr_flush = FALSE;  /* did not reach end of input */
       return;
     }
     chl_w1 = (unsigned char) ((iml_shift_v >> (iml_shift_c - (VAL_BYTE + 1))) | 0X80);
     iml_shift_c -= VAL_BYTE + 1;           /* subtract bits           */
     *achl_histbu_cur++ = chl_w1;           /* current position in history buffer */
     if (achl_histbu_cur > achl_histbu_max) {  /* new maximum reached  */
       achl_histbu_max = achl_histbu_cur;   /* set new maximum         */
     }
     *achl_out_cur++ = chl_w1;              /* output character        */
     goto p_dcco_r4_00;                     /* get codeword            */
   }
#ifdef TRACEHL2
   ims_tracehl2++;
   printf( "DEC l%05d ims_tracehl2=%d.\n", __LINE__, ims_tracehl2 );
   if (ims_tracehl2 == TRACEHL2) {
     printf( "DEC l%05d debug point reached\n", __LINE__ );
   }
#endif
#ifdef B110507
   iml2 = imrs_rdp4_co_off_len_total[ iml1 ];
   while (iml2 > iml_shift_c) {
     while (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
       if (adsl_gai1_in == NULL) {          /* end of input            */
#ifdef TRACEHL1
         printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
                 __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
         adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value      */
         adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count      */
         adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
         adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
         adsp_cdr_ctrl->boc_sr_flush = FALSE;  /* did not reach end of input */
         return;
       }
     }
     iml_shift_v <<= VAL_BYTE;              /* space for new bits      */
     iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
#endif
   iml3 = imrs_rdp4_co_off_lead_bits[ iml1 ];
   iml2 -= iml3;                            /* number of bits for match */
   iml_shift_c -= iml3;                     /* number of bits for match */
#ifdef DEBUG_110418_01
   printf( "DEC l%05d copy-offset iml1=%d no=%p and=%p add=%p pos-hist-before=%p.\n",
           __LINE__,
           iml1,
           (iml_shift_v >> (iml_shift_c - iml2)),
           (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml2)),
           imrs_rdp4_co_off_add[ iml1 ],
           achl_histbu_cur - ((char *) (adsl_dec_int + 1)) );
#endif
   iml_copy_offset = ((iml_shift_v >> (iml_shift_c - iml2))
                        & (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml2)))
                       + imrs_rdp4_co_off_add[ iml1 ];
   iml_shift_c -= iml2;                     /* subtract bits           */

   p_dcco_r4_12:                            /* start calculating Length-of-Match */
   if (iml_shift_c <= 0) {                  /* we need more bits for Length-of-Match */
     while (   (adsl_gai1_in)               /* we have gather          */
            && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
     }
     if (adsl_gai1_in == NULL) {            /* end of input            */
#ifdef TRACEHL1
       printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
               __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset     */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->iec_dec_cont = ied_dc_dcco72;  /* continue start calculating Length-of-Match */
       if (adsp_cdr_ctrl->boc_mp_flush) {   /* if FLUSH input set      */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
       }
       return;
     }
     iml_shift_v <<= VAL_BYTE;              /* space for new bits      */
     iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
   if (iml_shift_c >= VAL_BYTE) {
     chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - VAL_BYTE));
   } else {
     chl_w1 = (unsigned char) (iml_shift_v << (VAL_BYTE - iml_shift_c));
   }
   iml1 = ucrs_leading_bits[ (unsigned char) chl_w1 ];
   if (iml1 < iml_shift_c) {                /* check if we need more bits for Length-of-Match */
     if (iml1 == 0) {                       /* no leading bits         */
       iml_shift_c--;                       /* subtract bit            */
       iml_len_of_match = 3;                /* Length-of-Match         */
       goto p_dcco_r4_40;                   /* Length-of-Match calculated */
     }
#ifdef B110521
     goto p_dcco_r4_20;                     /* enough bits for bits for Length-of-Match */
#else
     if (iml1 < VAL_BYTE) {                 /* not one full byte with ones */
       goto p_dcco_r4_20;                   /* enough bits for bits for Length-of-Match */
     }
// to-do 21.05.11 KB ??? should be jump behind get new byte?
#endif
   }
   while (   (adsl_gai1_in)                 /* we have gather          */
          && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
     adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain     */
   }
   if (adsl_gai1_in == NULL) {              /* end of input            */
#ifdef TRACEHL1
     printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
     adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value          */
     adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count          */
     adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset       */
     adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
     adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
     adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
     adsl_dec_int->iec_dec_cont = ied_dc_dcco72;  /* continue start calculating Length-of-Match */
     if (adsp_cdr_ctrl->boc_mp_flush) {     /* if FLUSH input set      */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
     }
     return;                                /* return to main-prog     */
   }
   iml_shift_v <<= VAL_BYTE;                /* space for new bits      */
   iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
   iml_shift_c += VAL_BYTE;                 /* add bits                */
   chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - VAL_BYTE));
   iml1 = ucrs_leading_bits[ (unsigned char) chl_w1 ];
   if (iml1 < VAL_BYTE) {                   /* not one full byte with ones */
     goto p_dcco_r4_20;                     /* enough bits for bits for Length-of-Match */
   }
   if (iml_shift_c >= (VAL_BYTE * 2)) {
     chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - (VAL_BYTE * 2)));
   } else {
     chl_w1 = (unsigned char) (iml_shift_v << ((VAL_BYTE * 2) - iml_shift_c));
   }
   iml1 = VAL_BYTE + ucrs_leading_bits[ (unsigned char) chl_w1 ];
   if (iml1 < iml_shift_c) {                /* check if we need more bits for Length-of-Match */
     goto p_dcco_r4_16;                     /* check if more than maximum number of leading bits */
   }
   while (   (adsl_gai1_in)                 /* we have gather          */
          && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
     adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain     */
   }
   if (adsl_gai1_in == NULL) {              /* end of input            */
#ifdef TRACEHL1
     printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
     adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value          */
     adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count          */
     adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset       */
     adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
     adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
     adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
     adsl_dec_int->iec_dec_cont = ied_dc_dcco72;  /* continue start calculating Length-of-Match */
     if (adsp_cdr_ctrl->boc_mp_flush) {     /* if FLUSH input set      */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
     }
     return;                                /* return to main-prog     */
   }
   iml_shift_v <<= VAL_BYTE;                /* space for new bits      */
   iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
   iml_shift_c += VAL_BYTE;                 /* add bits                */
   chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - (VAL_BYTE * 2)));
   iml1 = VAL_BYTE + ucrs_leading_bits[ (unsigned char) chl_w1 ];

   p_dcco_r4_16:                            /* check if more than maximum number of leading bits */
   if (iml1 > 11) iml1 = 11;                /* maximum number of leading bits */

   p_dcco_r4_20:                            /* enough bits for bits for Length-of-Match */
   iml1++;                                  /* number of valid bits    */
   iml_shift_c -= iml1;                     /* subtract leading bits   */

   p_dcco_r4_24:                            /* continue bits for Length-of-Match */
   while (iml_shift_c < iml1) {             /* check if we need more bits for Length-of-Match */
     while (   (adsl_gai1_in)               /* we have gather          */
            && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
     }
     if (adsl_gai1_in == NULL) {            /* end of input            */
#ifdef TRACEHL1
       printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
               __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset     */
       adsl_dec_int->imc_save_2 = iml1;     /* bits for Length-of-Match */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->iec_dec_cont = ied_dc_dcco80;  /* continue bits for Length-of-Match */
       if (adsp_cdr_ctrl->boc_mp_flush) {   /* if FLUSH input set      */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
       }
       return;
     }
     iml_shift_v <<= VAL_BYTE;              /* space for new bits      */
     iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
#ifdef TRACEHL1
   printf( "DEC l%05d calc match bits=%d no=%p and=%p add=%p.\n",
           __LINE__,
           iml1,
           (iml_shift_v >> (iml_shift_c - iml1)),
           (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml1)),
           (1 << iml1) );
#endif
#ifndef TRY_110418_02
   iml_len_of_match                         /* Length-of-Match         */
     = ((iml_shift_v >> (iml_shift_c - iml1))
                        & (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml1)))
                       + (1 << iml1);
#else
   iml_len_of_match                         /* Length-of-Match         */
     = ((iml_shift_v >> (iml_shift_c - iml1))
                        & (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml1)))
                       + (1 << iml1);
#endif
   iml_shift_c -= iml1;                     /* subtract bits           */

   p_dcco_r4_40:                            /* Length-of-Match calculated */
#ifdef TRACEHL1
   printf( "DEC l%05d iml_copy_offset=%d/0X%p iml_len_of_match=%d/0X%p disp=0X%X hist-bu=%d/0X%X.\n",
           __LINE__, iml_copy_offset, iml_copy_offset, iml_len_of_match, iml_len_of_match,
          achl_out_cur - adsp_cdr_ctrl->achc_out_cur,
          (achl_histbu_cur - ((char *) (adsl_dec_int + 1))) + iml_len_of_match,
          (achl_histbu_cur - ((char *) (adsl_dec_int + 1))) + iml_len_of_match );
#endif
   if ((achl_histbu_cur + iml_len_of_match) > achl_histbu_end) {
#ifdef TRACEHL1
     printf( "DEC l%05d data after end of history buffer\n",
             __LINE__ );
#endif
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
     return;
   }
   if ((achl_histbu_cur - iml_copy_offset) < ((char *) (adsl_dec_int + 1))) {
#ifndef TRY_110418_04
#ifdef TRACEHL1
     printf( "DEC l%05d data before start of history buffer\n",
             __LINE__ );
     iml1 = achl_out_cur - adsp_cdr_ctrl->achc_out_cur;
     printf( "DEC l%05d length output=%d/0X%p.\n",
             __LINE__, iml1, iml1 );
     m_console_out( adsp_cdr_ctrl->achc_out_cur, iml1 );
     m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_end - (char *) (adsl_dec_int + 1) );
#endif
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
     return;
#else
     iml_copy_offset -= achl_histbu_end - (char *) (adsl_dec_int + 1);
     if ((achl_histbu_cur - iml_copy_offset + iml_len_of_match) > achl_histbu_end) {
#ifdef TRACEHL1
       printf( "DEC l%05d data before start / after end of history buffer\n",
               __LINE__ );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
     if ((achl_histbu_cur - iml_copy_offset) >= achl_histbu_max) {
#ifdef TRACEHL1
       printf( "DEC l%05d data after maximum of history buffer\n",
               __LINE__ );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
#endif
   }
#ifdef DEBUG_110519_03
   adsl_dec_int->achc_histbu_debug = achl_histbu_cur;  /* debug position in history buffer */
#endif

   p_dcco_r4_44:                                 /* continue output match   */
   iml1 = iml_len_of_match;
#ifdef TRACEHL1
   printf( "DEC l%05d p_dcco_r4_44 len-of-match=%d/0X%X.\n",
           __LINE__, iml_len_of_match, iml_len_of_match );
#endif
   if ((achl_out_cur + iml_len_of_match) >= achl_out_end) {
     iml1 = achl_out_end - achl_out_cur;
     if (iml1 <= 0) goto pdcco60;           /* we need more output area */
   }
   iml_len_of_match -= iml1;                /* length-of-match after output */
   do {                                     /* loop fill history buffer and output characters */
     *achl_histbu_cur = *(achl_histbu_cur - iml_copy_offset);
     *achl_out_cur++ = *achl_histbu_cur;
     achl_histbu_cur++;
     iml1--;
   } while (iml1);
   if (iml_len_of_match) {                  /* not all characters processed */
     goto pdcco60;                          /* we need more output area */
   }
   if (achl_histbu_cur > achl_histbu_max) {  /* new maximum reached    */
     achl_histbu_max = achl_histbu_cur;     /* set new maximum         */
   }
// to-do 15.05.11 KB adsl_gai1_in == NULL
#ifdef DEBUG_110519_03
   ims_match_dec++;
   iml1 = achl_histbu_cur - adsl_dec_int->achc_histbu_debug;
   iml2 = (achl_histbu_cur - ((char *) (adsl_dec_int + 1))) - iml_copy_offset - iml1;
   printf( "DEC l%05d p_dcco_r4_44 match-no=%d len=%d/0X%X pos=%d/0X%X.\n",
           __LINE__, ims_match_dec, iml1, iml1, iml2, iml2 );
   m_console_out( adsl_dec_int->achc_histbu_debug, iml1 );
#endif
   goto p_dcco_r4_00;                       /* get codeword            */

   p_dcco_r5_00:                            /* get codeword RDP5       */
   if (iml_shift_c >= VAL_BYTE) {           /* check if full byte      */
     goto p_dcco_r5_08;                     /* we have the codeword    */
   }
   while (   (adsl_gai1_in)                 /* we have gather          */
          && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
     adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain     */
   }
   if (adsl_gai1_in == NULL) {              /* end of input            */
#ifdef TRACEHL1
     printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
     adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
     adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
     adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
     adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
     adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
     if (adsp_cdr_ctrl->boc_mp_flush == FALSE) return;
#ifdef DEBUG_110516_01
#ifdef TRACEHL1
     printf( "DEC l%05d ret hist-bu=%p achl_histbu_cur=%p achl_histbu_max=%p.\n",
             __LINE__, (char *) (adsl_dec_int + 1), achl_histbu_cur, achl_histbu_max );
     m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_max - (char *) (adsl_dec_int + 1) );
#endif
#endif
     adsl_dec_int->iec_dec_cont = ied_dc_dcbu00;  /* start of new packet */
     return;                                /* wait for new packet     */
   }
   iml_shift_v <<= VAL_BYTE;                /* space for new bits      */
   iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
   iml_shift_c += VAL_BYTE;                 /* add bits                */

   p_dcco_r5_08:                            /* we have the codeword    */
   chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - VAL_BYTE));
   iml1 = ucrs_leading_bits[ (unsigned char) chl_w1 ];
   if (iml1 == 0) {                         /* MSB bit not set         */
     if (achl_histbu_cur >= achl_histbu_end) {
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
     if (achl_out_cur >= achl_out_end) {
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       adsp_cdr_ctrl->boc_sr_flush = FALSE;  /* did not reach end of input */
       return;
     }
     iml_shift_c -= VAL_BYTE;               /* subtract bits           */
     *achl_histbu_cur++ = chl_w1;           /* current position in history buffer */
     if (achl_histbu_cur > achl_histbu_max) {  /* new maximum reached  */
       achl_histbu_max = achl_histbu_cur;   /* set new maximum         */
     }
     *achl_out_cur++ = chl_w1;              /* output character        */
     goto p_dcco_r5_00;                          /* get codeword            */
   }
   iml2 = imrs_rdp5_co_off_len_total[ iml1 ];
   while (iml2 >= iml_shift_c) {            /* we need at least (iml2 + 1) bits */
     while (   (adsl_gai1_in)               /* we have gather          */
            && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
     }
     if (adsl_gai1_in == NULL) {            /* end of input            */
#ifdef TRACEHL1
       printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
               __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       if (adsp_cdr_ctrl->boc_mp_flush) {   /* if FLUSH input set      */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
       }
       return;
     }
     iml_shift_v <<= VAL_BYTE;              /* space for new bits      */
     iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
   if (iml1 == 1) {
     if (achl_histbu_cur >= achl_histbu_end) {
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
     if (achl_out_cur >= achl_out_end) {
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       adsp_cdr_ctrl->boc_sr_flush = FALSE;  /* did not reach end of input */
       return;
     }
     chl_w1 = (unsigned char) ((iml_shift_v >> (iml_shift_c - (VAL_BYTE + 1))) | 0X80);
     iml_shift_c -= VAL_BYTE + 1;           /* subtract bits           */
     *achl_histbu_cur++ = chl_w1;           /* current position in history buffer */
     if (achl_histbu_cur > achl_histbu_max) {  /* new maximum reached  */
       achl_histbu_max = achl_histbu_cur;   /* set new maximum         */
     }
     *achl_out_cur++ = chl_w1;              /* output character        */
     goto p_dcco_r5_00;                     /* get codeword            */
   }
#ifdef TRACEHL2
   ims_tracehl2++;
   printf( "DEC l%05d ims_tracehl2=%d.\n", __LINE__, ims_tracehl2 );
   if (ims_tracehl2 == TRACEHL2) {
     printf( "DEC l%05d debug point reached\n", __LINE__ );
   }
#endif
#ifdef B110507
   iml2 = imrs_rdp5_co_off_len_total[ iml1 ];
   while (iml2 > iml_shift_c) {
     while (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
       if (adsl_gai1_in == NULL) {          /* end of input            */
#ifdef TRACEHL1
         printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
                 __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
         adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value      */
         adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count      */
         adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
         adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
         adsp_cdr_ctrl->boc_sr_flush = FALSE;  /* did not reach end of input */
         return;
       }
     }
     iml_shift_v <<= VAL_BYTE;              /* space for new bits      */
     iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
#endif
   iml3 = imrs_rdp5_co_off_lead_bits[ iml1 ];
   iml2 -= iml3;                            /* number of bits for match */
   iml_shift_c -= iml3;                     /* number of bits for match */
#ifdef DEBUG_110418_01
   printf( "DEC l%05d copy-offset iml1=%d no=%p and=%p add=%p pos-hist-before=%p.\n",
           __LINE__,
           iml1,
           (iml_shift_v >> (iml_shift_c - iml2)),
           (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml2)),
           imrs_rdp5_co_off_add[ iml1 ],
           achl_histbu_cur - ((char *) (adsl_dec_int + 1)) );
#endif
   iml_copy_offset = ((iml_shift_v >> (iml_shift_c - iml2))
                        & (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml2)))
                       + imrs_rdp5_co_off_add[ iml1 ];
   iml_shift_c -= iml2;                     /* subtract bits           */

   p_dcco_r5_12:                            /* start calculating Length-of-Match */
   if (iml_shift_c <= 0) {                  /* we need more bits for Length-of-Match */
     while (   (adsl_gai1_in)               /* we have gather          */
            && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
     }
     if (adsl_gai1_in == NULL) {            /* end of input            */
#ifdef TRACEHL1
       printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
               __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset     */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->iec_dec_cont = ied_dc_dcco72;  /* continue start calculating Length-of-Match */
       if (adsp_cdr_ctrl->boc_mp_flush) {   /* if FLUSH input set      */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
       }
       return;
     }
     iml_shift_v <<= VAL_BYTE;              /* space for new bits      */
     iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
   if (iml_shift_c >= VAL_BYTE) {
     chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - VAL_BYTE));
   } else {
     chl_w1 = (unsigned char) (iml_shift_v << (VAL_BYTE - iml_shift_c));
   }
   iml1 = ucrs_leading_bits[ (unsigned char) chl_w1 ];
#ifdef DEBUG_110521_01
#ifdef DEBUG_110519_03
   if (ims_match_enc >= 38670) {
     printf( "DEC l%05d p_dcco_r5_12-A iml_shift_c=%d iml_shift_v=0X%08X leading-bits(iml1)=%d.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v, iml1 );
   }
#endif
#endif
   if (iml1 < iml_shift_c) {                /* check if we need more bits for Length-of-Match */
     if (iml1 == 0) {                       /* no leading bits         */
       iml_shift_c--;                       /* subtract bit            */
       iml_len_of_match = 3;                /* Length-of-Match         */
       goto p_dcco_r5_40;                   /* Length-of-Match calculated */
     }
#ifdef DEBUG_110521_01
#ifdef DEBUG_110519_03
     if (ims_match_enc >= 38670) {
       printf( "DEC l%05d jump to p_dcco_r5_20 iml_shift_c=%d iml_shift_v=0X%08X leading-bits(iml1)=%d.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v, iml1 );
     }
#endif
#endif
#ifdef B110521
     goto p_dcco_r5_20;                     /* enough bits for bits for Length-of-Match */
#else
     if (iml1 < VAL_BYTE) {                 /* not one full byte with ones */
       goto p_dcco_r5_20;                   /* enough bits for bits for Length-of-Match */
     }
// to-do 21.05.11 KB ??? should be jump behind get new byte?
#endif
   }
   while (   (adsl_gai1_in)                 /* we have gather          */
          && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
     adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain     */
   }
   if (adsl_gai1_in == NULL) {              /* end of input            */
#ifdef TRACEHL1
     printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
     adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value          */
     adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count          */
     adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset       */
     adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
     adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
     adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
     adsl_dec_int->iec_dec_cont = ied_dc_dcco72;  /* continue start calculating Length-of-Match */
     if (adsp_cdr_ctrl->boc_mp_flush) {     /* if FLUSH input set      */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
     }
     return;                                /* return to main-prog     */
   }
   iml_shift_v <<= VAL_BYTE;                /* space for new bits      */
   iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
   iml_shift_c += VAL_BYTE;                 /* add bits                */
   chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - VAL_BYTE));
   iml1 = ucrs_leading_bits[ (unsigned char) chl_w1 ];
#ifdef DEBUG_110521_01
#ifdef DEBUG_110519_03
   if (ims_match_enc >= 38670) {
     printf( "DEC l%05d p_dcco_r5_12-B iml_shift_c=%d iml_shift_v=0X%08X leading-bits(iml1)=%d.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v, iml1 );
   }
#endif
#endif
   if (iml1 < VAL_BYTE) {                   /* not one full byte with ones */
     goto p_dcco_r5_20;                     /* enough bits for bits for Length-of-Match */
   }
   if (iml_shift_c >= (VAL_BYTE * 2)) {
     chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - (VAL_BYTE * 2)));
   } else {
     chl_w1 = (unsigned char) (iml_shift_v << ((VAL_BYTE * 2) - iml_shift_c));
   }
   iml1 = VAL_BYTE + ucrs_leading_bits[ (unsigned char) chl_w1 ];
#ifdef DEBUG_110521_01
#ifdef DEBUG_110519_03
   if (ims_match_enc >= 38670) {
     printf( "DEC l%05d p_dcco_r5_12-C iml_shift_c=%d iml_shift_v=0X%08X leading-bits(iml1)=%d.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v, iml1 );
   }
#endif
#endif
   if (iml1 < iml_shift_c) {                /* check if we need more bits for Length-of-Match */
     goto p_dcco_r5_16;                     /* check if more than maximum number of leading bits */
   }
   while (   (adsl_gai1_in)                 /* we have gather          */
          && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
     adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain     */
   }
   if (adsl_gai1_in == NULL) {              /* end of input            */
#ifdef TRACEHL1
     printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
     adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value          */
     adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count          */
     adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset       */
     adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
     adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
     adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
     adsl_dec_int->iec_dec_cont = ied_dc_dcco72;  /* continue start calculating Length-of-Match */
     if (adsp_cdr_ctrl->boc_mp_flush) {     /* if FLUSH input set      */
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
     }
     return;                                /* return to main-prog     */
   }
   iml_shift_v <<= VAL_BYTE;                /* space for new bits      */
   iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
   iml_shift_c += VAL_BYTE;                 /* add bits                */
   chl_w1 = (unsigned char) (iml_shift_v >> (iml_shift_c - (VAL_BYTE * 2)));
   iml1 = VAL_BYTE + ucrs_leading_bits[ (unsigned char) chl_w1 ];
#ifdef DEBUG_110521_01
#ifdef DEBUG_110519_03
   if (ims_match_enc >= 38670) {
     printf( "DEC l%05d p_dcco_r5_12-D iml_shift_c=%d iml_shift_v=0X%08X leading-bits(iml1)=%d.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v, iml1 );
   }
#endif
#endif

   p_dcco_r5_16:                            /* check if more than maximum number of leading bits */
#ifdef DEBUG_110521_01
#ifdef DEBUG_110519_03
   if (ims_match_enc >= 38670) {
     printf( "DEC l%05d p_dcco_r5_16 iml_shift_c=%d iml_shift_v=0X%08X leading-bits(iml1)=%d.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v, iml1 );
   }
#endif
#endif
   if (iml1 > 14) iml1 = 14;                /* maximum number of leading bits */

   p_dcco_r5_20:                            /* enough bits for bits for Length-of-Match */
#ifdef DEBUG_110521_01
#ifdef DEBUG_110519_03
   if (ims_match_enc >= 38670) {
     printf( "DEC l%05d p_dcco_r5_20 iml_shift_c=%d iml_shift_v=0X%08X leading-bits(iml1)=%d.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v, iml1 );
   }
#endif
#endif
   iml1++;                                  /* number of valid bits    */
   iml_shift_c -= iml1;                     /* subtract leading bits   */

   p_dcco_r5_24:                            /* continue bits for Length-of-Match */
#ifdef DEBUG_110521_01
#ifdef DEBUG_110519_03
   if (ims_match_enc >= 38670) {
     printf( "DEC l%05d p_dcco_r5_24 iml_shift_c=%d iml_shift_v=0X%08X leading-bits(iml1)=%d.\n",
             __LINE__, iml_shift_c, (unsigned int) iml_shift_v, iml1 );
   }
#endif
#endif
   while (iml_shift_c < iml1) {             /* check if we need more bits for Length-of-Match */
     while (   (adsl_gai1_in)               /* we have gather          */
            && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
     }
     if (adsl_gai1_in == NULL) {            /* end of input            */
#ifdef TRACEHL1
       printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X iml_copy_offset=%d/0X%X.\n",
               __LINE__, iml_shift_c, (unsigned int) iml_shift_v, iml_copy_offset, iml_copy_offset );
#endif
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset     */
       adsl_dec_int->imc_save_2 = iml1;     /* bits for Length-of-Match */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->iec_dec_cont = ied_dc_dcco80;  /* continue bits for Length-of-Match */
       if (adsp_cdr_ctrl->boc_mp_flush) {   /* if FLUSH input set      */
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
       }
       return;
     }
     iml_shift_v <<= VAL_BYTE;              /* space for new bits      */
     iml_shift_v |= (unsigned char) *adsl_gai1_in->achc_ginp_cur++;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
#ifdef TRACEHL1
   printf( "DEC l%05d calc match bits=%d no=%p and=%p add=%p.\n",
           __LINE__,
           iml1,
           (iml_shift_v >> (iml_shift_c - iml1)),
           (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml1)),
           (1 << iml1) );
#endif
#ifndef TRY_110418_02
   iml_len_of_match                         /* Length-of-Match         */
     = ((iml_shift_v >> (iml_shift_c - iml1))
                        & (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml1)))
                       + (1 << iml1);
#else
   iml_len_of_match                         /* Length-of-Match         */
     = ((iml_shift_v >> (iml_shift_c - iml1))
                        & (((unsigned int) -1) >> ((sizeof(iml_shift_v) * VAL_BYTE) - iml1)))
                       + (1 << iml1);
#endif
   iml_shift_c -= iml1;                     /* subtract bits           */

   p_dcco_r5_40:                            /* Length-of-Match calculated */
#ifdef TRACEHL1
   printf( "DEC l%05d iml_copy_offset=%d/0X%p iml_len_of_match=%d/0X%p disp=0X%X hist-bu=%d/0X%X.\n",
           __LINE__, iml_copy_offset, iml_copy_offset, iml_len_of_match, iml_len_of_match,
          achl_out_cur - adsp_cdr_ctrl->achc_out_cur,
          (achl_histbu_cur - ((char *) (adsl_dec_int + 1))) + iml_len_of_match,
          (achl_histbu_cur - ((char *) (adsl_dec_int + 1))) + iml_len_of_match );
#endif
   if ((achl_histbu_cur + iml_len_of_match) > achl_histbu_end) {
#ifdef TRACEHL1
     printf( "DEC l%05d data after end of history buffer\n",
             __LINE__ );
#endif
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
     return;
   }
   if ((achl_histbu_cur - iml_copy_offset) < ((char *) (adsl_dec_int + 1))) {
#ifndef TRY_110418_04
#ifdef TRACEHL1
     printf( "DEC l%05d data before start of history buffer\n",
             __LINE__ );
     iml1 = achl_out_cur - adsp_cdr_ctrl->achc_out_cur;
     printf( "DEC l%05d length output=%d/0X%p.\n",
             __LINE__, iml1, iml1 );
     m_console_out( adsp_cdr_ctrl->achc_out_cur, iml1 );
     m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_end - (char *) (adsl_dec_int + 1) );
#endif
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
     return;
#else
     iml_copy_offset -= achl_histbu_end - (char *) (adsl_dec_int + 1);
     if ((achl_histbu_cur - iml_copy_offset + iml_len_of_match) > achl_histbu_end) {
#ifdef TRACEHL1
       printf( "DEC l%05d data before start / after end of history buffer\n",
               __LINE__ );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
     if ((achl_histbu_cur - iml_copy_offset) >= achl_histbu_max) {
#ifdef TRACEHL1
       printf( "DEC l%05d data after maximum of history buffer\n",
               __LINE__ );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
#endif
   }
#ifdef DEBUG_110519_03
   adsl_dec_int->achc_histbu_debug = achl_histbu_cur;  /* debug position in history buffer */
#endif

   p_dcco_r5_44:                            /* continue output match   */
   iml1 = iml_len_of_match;
#ifdef TRACEHL1
   printf( "DEC l%05d p_dcco_r5_44 len-of-match=%d/0X%X.\n",
           __LINE__, iml_len_of_match, iml_len_of_match );
#endif
   if ((achl_out_cur + iml_len_of_match) >= achl_out_end) {
     iml1 = achl_out_end - achl_out_cur;
     if (iml1 <= 0) goto pdcco60;           /* we need more output area */
   }
   iml_len_of_match -= iml1;                /* length-of-match after output */
   do {                                     /* loop fill history buffer and output characters */
     *achl_histbu_cur = *(achl_histbu_cur - iml_copy_offset);
     *achl_out_cur++ = *achl_histbu_cur;
     achl_histbu_cur++;
     iml1--;
   } while (iml1);
   if (iml_len_of_match) {                  /* not all characters processed */
     goto pdcco60;                          /* we need more output area */
   }
   if (achl_histbu_cur > achl_histbu_max) {  /* new maximum reached    */
     achl_histbu_max = achl_histbu_cur;     /* set new maximum         */
   }
// to-do 15.05.11 KB adsl_gai1_in == NULL
#ifdef DEBUG_110519_03
   ims_match_dec++;
   iml1 = achl_histbu_cur - adsl_dec_int->achc_histbu_debug;
   iml2 = (achl_histbu_cur - ((char *) (adsl_dec_int + 1))) - iml_copy_offset - iml1;
   printf( "DEC l%05d p_dcco_r5_44 match-no=%d len=%d/0X%X pos=%d/0X%X.\n",
           __LINE__, ims_match_dec, iml1, iml1, iml2, iml2 );
   m_console_out( adsl_dec_int->achc_histbu_debug, iml1 );
#endif
   goto p_dcco_r5_00;                       /* get codeword            */

   p_dcco_r6_00:                            /* get codeword RDP6.0     */
   while (iml_shift_c < ((sizeof(int) - 1) * 8)) {  /* check if enough bits */
     while (   (adsl_gai1_in)               /* we have gather          */
            && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
     }
     if (adsl_gai1_in == NULL) {            /* end of input            */
       if (iml_shift_c >= VAL_TAB_R60_D1_L) break;  /* check if full codeword */
       if (   (iml_shift_c >= VAL_TAB_R60_D1_M)  /* check if minimum literal */
           && (achl_out_cur < achl_out_end)) {  /* space in output area */
         iml1 = usrs_rdp60_decode_1[ (iml_shift_v << (VAL_TAB_R60_D1_L - iml_shift_c)) & ((1 << VAL_TAB_R60_D1_L) - 1) ];
         if (((iml1 >> 8) & 3) == 0) {      /* second nibble zero, literal */
           iml2 = iml1 >> 12;               /* get first nibble        */
           if (iml2 >= iml_shift_c) {       /* is full codeword        */
             iml_shift_v >>= iml2;          /* remove the bits         */
             iml_shift_c -= iml2;           /* subtract bits           */
             *achl_histbu_cur++ = (unsigned char) iml1;  /* current position in history buffer */
             if (achl_histbu_cur > achl_histbu_max) {  /* new maximum reached */
               achl_histbu_max = achl_histbu_cur;  /* set new maximum  */
             }
             *achl_out_cur++ = (unsigned char) iml1;  /* output character */
           }
         }
       }
#ifdef TRACEHL1
       printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
               __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       if (adsp_cdr_ctrl->boc_mp_flush == FALSE) return;
#ifdef DEBUG_110516_01
#ifdef TRACEHL1
       printf( "DEC l%05d ret hist-bu=%p achl_histbu_cur=%p achl_histbu_max=%p.\n",
               __LINE__, (char *) (adsl_dec_int + 1), achl_histbu_cur, achl_histbu_max );
       m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_max - (char *) (adsl_dec_int + 1) );
#endif
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
     iml_shift_v |= ((unsigned char) *adsl_gai1_in->achc_ginp_cur++) << iml_shift_c;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
   iml1 = usrs_rdp60_decode_1[ iml_shift_v & ((1 << VAL_TAB_R60_D1_L) - 1) ];
   iml2 = iml1 >> 12;                       /* get first nibble        */
   switch ((iml1 >> 8) & 3) {               /* second nibble           */
     case 0:                                /* output byte direct      */
       if (achl_histbu_cur >= achl_histbu_end) {
#ifdef TRACEHL1
         printf( "DEC l%05d p_dcco_r6_00 after history buffer\n",
                 __LINE__ );
         adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
#endif
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
         return;
       }
       if (achl_out_cur >= achl_out_end) {
         adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value      */
         adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count      */
         adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
         adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
         adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
         adsp_cdr_ctrl->boc_sr_flush = FALSE;  /* did not reach end of input */
#ifdef TRACEHL1
         printf( "DEC l%05d p_dcco_r6_00 output buffer full\n",
                 __LINE__ );
#endif
         return;
       }
       iml_shift_v >>= iml2;                /* remove the bits         */
       iml_shift_c -= iml2;                 /* subtract bits           */
       *achl_histbu_cur++ = (unsigned char) iml1;  /* current position in history buffer */
       if (achl_histbu_cur > achl_histbu_max) {  /* new maximum reached */
         achl_histbu_max = achl_histbu_cur;   /* set new maximum       */
       }
       *achl_out_cur++ = (unsigned char) iml1;  /* output character    */
       goto p_dcco_r6_00;                   /* get codeword RDP6.0     */
     case 1:                                /* end of input data       */
       while (   (adsl_gai1_in)             /* we have gather          */
              && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
         adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain */
       }
       if (   (adsl_gai1_in == NULL)        /* end of input            */
           && (adsp_cdr_ctrl->boc_mp_flush)) {
#ifdef TRACEHL1
         printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
                 __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
#ifdef XYZ1
         adsl_dec_int->imc_shift_v = 0;     /* shift-value             */
         adsl_dec_int->imc_shift_c = 0;     /* shift-count             */
#endif
         adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
         adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
         adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
         adsl_dec_int->iec_dec_cont = ied_dc_dcbu00;  /* start of new packet */
         return;                            /* all done                */
       }
//#ifdef DEBUG_110516_01
#ifdef TRACEHL1
       printf( "DEC l%05d ret hist-bu=%p achl_histbu_cur=%p achl_histbu_max=%p.\n",
               __LINE__, (char *) (adsl_dec_int + 1), achl_histbu_cur, achl_histbu_max );
//     m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_max - (char *) (adsl_dec_int + 1) );
#endif
//#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     case 2:                                /* decode offset           */
       iml3 = iml1 & 0X0F;                  /* get last four bits      */
       if ((iml2 + iml3) > iml_shift_c) {   /* not enough bits         */
#ifdef TRACEHL1
         printf( "DEC l%05d p_dcco_r6_00 type=%d codeword=0X%04X.\n",
                 __LINE__, (iml1 >> 8) & 3, (unsigned int) iml1 );
#endif
         adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value      */
         adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count      */
         adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
         adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
         adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
         if (adsp_cdr_ctrl->boc_mp_flush == FALSE) return;
#ifdef DEBUG_110516_01
#ifdef TRACEHL1
         printf( "DEC l%05d ret hist-bu=%p achl_histbu_cur=%p achl_histbu_max=%p.\n",
                 __LINE__, (char *) (adsl_dec_int + 1), achl_histbu_cur, achl_histbu_max );
         m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_max - (char *) (adsl_dec_int + 1) );
#endif
#endif
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
         return;
       }
       iml_shift_v >>= iml2;                /* remove the bits         */
       iml_shift_c -= iml2;                 /* subtract bits           */
       iml2 = iml3 - 4;                     /* minus special value     */
       if (iml2 > 0) {                      /* check shift value       */
         iml_copy_offset = (iml1 & 0X00F0) << iml2;
       } else {
         iml_copy_offset = (iml1 & 0X00F0) >> (4 - iml3);
       }
       if (iml3 > 0) {                      /* remaining part of offset */
         iml_copy_offset |= iml_shift_v & ((1 << iml3) - 1);
         iml_shift_v >>= iml3;              /* remove the bits         */
         iml_shift_c -= iml3;               /* subtract bits           */
       }
       /* put new entry in cache                                       */
#ifdef B130701
       IMRL_CACHE_OFF[ IMRL_CACHE_OFF[ VAL_CACHE_OFF ] ] = iml_copy_offset;  /* put value in cache */
#endif
       IMRL_CACHE_OFF[ VAL_CACHE_OFF ]++;   /* increment cache index   */
       IMRL_CACHE_OFF[ VAL_CACHE_OFF ] &= (VAL_CACHE_OFF - 1);  /* wrap around */
#ifndef B130701
       IMRL_CACHE_OFF[ IMRL_CACHE_OFF[ VAL_CACHE_OFF ] ] = iml_copy_offset;  /* put value in cache */
#endif
       break;                               /* offset has been calculated */
     case 3:                                /* look in cache           */
       iml3 = (IMRL_CACHE_OFF[ VAL_CACHE_OFF ] - iml1) & (VAL_CACHE_OFF - 1);   /* this is the index */
       iml_copy_offset = IMRL_CACHE_OFF[ iml3 ];
       if (iml_copy_offset < 0) {           /* value not initialized   */
#ifdef TRACEHL1
         printf( "DEC l%05d p_dcco_r6_00 type=%d codeword=0X%04X.\n",
                 __LINE__, (iml1 >> 8) & 3, (unsigned int) iml1 );
#endif
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
         return;
       }
       iml_shift_v >>= iml2;                /* remove the bits         */
       iml_shift_c -= iml2;                 /* subtract bits           */
       if (iml3 == IMRL_CACHE_OFF[ VAL_CACHE_OFF ]) break;  /* no need to exchange the values */
       iml2 = IMRL_CACHE_OFF[ IMRL_CACHE_OFF[ VAL_CACHE_OFF ] ];  /* save value */
       IMRL_CACHE_OFF[ IMRL_CACHE_OFF[ VAL_CACHE_OFF ] ]
         = IMRL_CACHE_OFF[ iml3 ];
       IMRL_CACHE_OFF[ iml3 ] = iml2;
       break;                               /* offset has been calculated */
   }

   p_dcco_r6_20:                            /* retrieve length of match */
   while (iml_shift_c < ((sizeof(int) - 1) * 8)) {  /* check if enough bits */
     while (   (adsl_gai1_in)               /* we have gather          */
            && (adsl_gai1_in->achc_ginp_cur >= adsl_gai1_in->achc_ginp_end)) {  /* end of this gather */
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
     }
     if (adsl_gai1_in == NULL) {            /* end of input            */
       if (iml_shift_c >= VAL_TAB_R60_D2_L) break;  /* check if full codeword */
#ifdef TRACEHL1
       printf( "DEC l%05d return iml_shift_c=%d iml_shift_v=0X%08X.\n",
               __LINE__, iml_shift_c, (unsigned int) iml_shift_v );
#endif
       adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value        */
       adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count        */
       adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset     */
       adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
       adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
       adsl_dec_int->iec_dec_cont = ied_dc_dcco72;  /* continue start calculating Length-of-Match */
       if (adsp_cdr_ctrl->boc_mp_flush) {   /* if FLUSH input set      */
#ifdef DEBUG_110516_01
#ifdef TRACEHL1
         printf( "DEC l%05d ret hist-bu=%p achl_histbu_cur=%p achl_histbu_max=%p.\n",
                 __LINE__, (char *) (adsl_dec_int + 1), achl_histbu_cur, achl_histbu_max );
         m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_max - (char *) (adsl_dec_int + 1) );
#endif
#endif
         adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error */
       }
       return;
     }
     iml_shift_v |= ((unsigned char) *adsl_gai1_in->achc_ginp_cur++) << iml_shift_c;  /* get new bits */
     iml_shift_c += VAL_BYTE;               /* add bits                */
   }
   iml1 = usrs_rdp60_decode_2[ iml_shift_v & ((1 << VAL_TAB_R60_D2_L) - 1) ];
   iml2 = iml1 >> 12;                       /* get first nibble        */
   iml3 = iml1 & 0X0F;                      /* get number of additional bits */
   if ((iml2 + iml3) > iml_shift_c) {       /* we need more bits       */
     adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value          */
     adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count          */
     adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset       */
     adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
     adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
     adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
     adsl_dec_int->iec_dec_cont = ied_dc_dcco72;  /* continue start calculating Length-of-Match */
     if (adsp_cdr_ctrl->boc_mp_flush) {     /* if FLUSH input set      */
#ifdef DEBUG_110516_01
#ifdef TRACEHL1
         printf( "DEC l%05d ret hist-bu=%p achl_histbu_cur=%p achl_histbu_max=%p.\n",
                 __LINE__, (char *) (adsl_dec_int + 1), achl_histbu_cur, achl_histbu_max );
         m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_max - (char *) (adsl_dec_int + 1) );
#endif
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
     }
     return;
   }
   iml_shift_v >>= iml2;                    /* remove the bits         */
   iml_shift_c -= iml2;                     /* subtract bits           */
   iml2 = iml3 - 4;                         /* number of bits minus special value */
   if (iml2 > 0) {                          /* check shift value       */
     iml_len_of_match = (iml1 & 0X00F0) << iml2;
   } else {
     iml_len_of_match = (iml1 & 0X00F0) >> (4 - iml3);
   }
#ifdef DEBUG_110803_01                      /* RDP6.0 display length-of-match */
   printf( "DEC l%05d length-of-match codeword=0X%04X len-of-match=0X%04X.\n",
           __LINE__, iml1, iml_len_of_match );
#endif
   if (iml3 > 0) {                          /* we need more bits       */
     if (iml_shift_c < iml3) {              /* not enough bits         */
#ifdef TRACEHL1
       printf( "DEC l%05d p_dcco_r6_00 type=%d.\n",
               __LINE__, (iml1 >> 8) & 3 );
       adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* message error   */
       return;                              /* report error            */
     }
     iml_len_of_match |= iml_shift_v & ((1 << iml3) - 1);
     iml_shift_v >>= iml3;                  /* remove the bits         */
     iml_shift_c -= iml3;                   /* subtract bits           */
#ifdef DEBUG_110803_01                      /* RDP6.0 display length-of-match */
     printf( "DEC l%05d after applying bits len-of-match=0X%04X.\n",
             __LINE__, iml_len_of_match );
#endif
   }
   iml_len_of_match += 2;                   /* add minimum value       */

   /* Length-of-Match calculated                                       */
#ifdef TRACEHL1
   printf( "DEC l%05d iml_copy_offset=%d/0X%p iml_len_of_match=%d/0X%p disp=0X%X hist-bu=%d/0X%X.\n",
           __LINE__, iml_copy_offset, iml_copy_offset, iml_len_of_match, iml_len_of_match,
          achl_out_cur - adsp_cdr_ctrl->achc_out_cur,
          (achl_histbu_cur - ((char *) (adsl_dec_int + 1))) + iml_len_of_match,
          (achl_histbu_cur - ((char *) (adsl_dec_int + 1))) + iml_len_of_match );
#endif
   if ((achl_histbu_cur + iml_len_of_match) > achl_histbu_end) {
#ifdef TRACEHL1
     printf( "DEC l%05d data after end of history buffer\n",
             __LINE__ );
#endif
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
     return;
   }
   if ((achl_histbu_cur - iml_copy_offset) < ((char *) (adsl_dec_int + 1))) {
#ifndef TRY_110418_04
#ifdef TRACEHL1
     printf( "DEC l%05d data before start of history buffer\n",
             __LINE__ );
     iml1 = achl_out_cur - adsp_cdr_ctrl->achc_out_cur;
     printf( "DEC l%05d length output=%d/0X%p.\n",
             __LINE__, iml1, iml1 );
     m_console_out( adsp_cdr_ctrl->achc_out_cur, iml1 );
     m_console_out( (char *) (adsl_dec_int + 1), achl_histbu_end - (char *) (adsl_dec_int + 1) );
#endif
     adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
     return;
#else
     iml_copy_offset -= achl_histbu_end - (char *) (adsl_dec_int + 1);
     if ((achl_histbu_cur - iml_copy_offset + iml_len_of_match) > achl_histbu_end) {
#ifdef TRACEHL1
       printf( "DEC l%05d data before start / after end of history buffer\n",
               __LINE__ );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
     if ((achl_histbu_cur - iml_copy_offset) >= achl_histbu_max) {
#ifdef TRACEHL1
       printf( "DEC l%05d data after maximum of history buffer\n",
               __LINE__ );
#endif
       adsp_cdr_ctrl->imc_return = DEF_IRET_INVDA;  /* invalid data found */
       return;
     }
#endif
   }
#ifdef DEBUG_110519_03
   adsl_dec_int->achc_histbu_debug = achl_histbu_cur;  /* debug position in history buffer */
#endif

   p_dcco_r6_44:                            /* continue output match   */
   iml1 = iml_len_of_match;
#ifdef TRACEHL1
   printf( "DEC l%05d p_dcco_r6_44 len-of-match=%d/0X%X.\n",
           __LINE__, iml_len_of_match, iml_len_of_match );
#endif
   if ((achl_out_cur + iml_len_of_match) >= achl_out_end) {
     iml1 = achl_out_end - achl_out_cur;
     if (iml1 <= 0) goto pdcco60;           /* we need more output area */
   }
   iml_len_of_match -= iml1;                /* length-of-match after output */
   do {                                     /* loop fill history buffer and output characters */
     *achl_histbu_cur = *(achl_histbu_cur - iml_copy_offset);
     *achl_out_cur++ = *achl_histbu_cur;
     achl_histbu_cur++;
     iml1--;
   } while (iml1);
   if (iml_len_of_match) {                  /* not all characters processed */
     goto pdcco60;                          /* we need more output area */
   }
   if (achl_histbu_cur > achl_histbu_max) {  /* new maximum reached    */
     achl_histbu_max = achl_histbu_cur;     /* set new maximum         */
   }
// to-do 15.05.11 KB adsl_gai1_in == NULL
#ifdef DEBUG_110519_03
   ims_match_dec++;
   iml1 = achl_histbu_cur - adsl_dec_int->achc_histbu_debug;
   iml2 = (achl_histbu_cur - ((char *) (adsl_dec_int + 1))) - iml_copy_offset - iml1;
   printf( "DEC l%05d p_dcco_r6_44 match-no=%d len=%d/0X%X pos=%d/0X%X.\n",
           __LINE__, ims_match_dec, iml1, iml1, iml2, iml2 );
   m_console_out( adsl_dec_int->achc_histbu_debug, iml1 );
#endif
   goto p_dcco_r6_00;                       /* get codeword            */

   pdcco60:                                 /* we need more output area */
#ifdef TRACEHL1
   printf( "DEC l%05d pdcco60\n",
           __LINE__ );
#endif
   adsl_dec_int->imc_shift_v = iml_shift_v;  /* shift-value            */
   adsl_dec_int->imc_shift_c = iml_shift_c;  /* shift-count            */
   adsl_dec_int->imc_save_1 = iml_copy_offset;  /* copy-offset         */
   adsl_dec_int->imc_save_2 = iml_len_of_match;  /* remaining Length-of-Match */
   adsl_dec_int->achc_histbu_cur = achl_histbu_cur;  /* current position in history buffer */
   adsl_dec_int->achc_histbu_max = achl_histbu_max;  /* maximum position in history buffer */
   adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
   adsl_dec_int->iec_dec_cont = ied_dc_dcco64;  /* continue output match */
   adsp_cdr_ctrl->boc_sr_flush = FALSE;     /* did not reach end of input */
   return;

   pdcco64:                                 /* we have more output area */
   iml_shift_v = adsl_dec_int->imc_shift_v;  /* shift-value            */
   iml_shift_c = adsl_dec_int->imc_shift_c;  /* shift-count            */
   achl_histbu_end = adsl_dec_int->achc_histbu_end;  /* end of history buffer */
   achl_histbu_cur = adsl_dec_int->achc_histbu_cur;  /* current position in history buffer */
   achl_histbu_max = adsl_dec_int->achc_histbu_max;  /* maximum position in history buffer */
   iml_copy_offset = adsl_dec_int->imc_save_1;  /* copy-offset         */
   iml_len_of_match = adsl_dec_int->imc_save_2;  /* Length-of-Match    */
   adsl_dec_int->iec_dec_cont = ied_dc_dcbu20;  /* continue compressed packet */
   switch (adsp_cdr_ctrl->imc_param_1) {    /* type of decompression   */
     case 40:                               /* RDP4                    */
       goto p_dcco_r4_44;                   /* continue output match RDP4 */
     case 50:                               /* RDP5                    */
       goto p_dcco_r5_44;                   /* continue output match RDP5*/
     case 60:                               /* RDP6.0                  */
       goto p_dcco_r6_44;                   /* continue output match RDP6.0 */
   }
#ifdef TRACEHL1
   printf( "DEC l%05d pdcbu20 imc_param_1=%d invalid value / allowed: 40 50 60.\n",
           __LINE__, adsp_cdr_ctrl->imc_param_1 );
#endif
   adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error       */
   return;                                  /* return to main-prog     */

   pdcco72:                                 /* we have more output area */
   iml_shift_v = adsl_dec_int->imc_shift_v;  /* shift-value            */
   iml_shift_c = adsl_dec_int->imc_shift_c;  /* shift-count            */
   achl_histbu_end = adsl_dec_int->achc_histbu_end;  /* end of history buffer */
   achl_histbu_cur = adsl_dec_int->achc_histbu_cur;  /* current position in history buffer */
   achl_histbu_max = adsl_dec_int->achc_histbu_max;  /* maximum position in history buffer */
   iml_copy_offset = adsl_dec_int->imc_save_1;  /* copy-offset         */
   adsl_dec_int->iec_dec_cont = ied_dc_dcbu20;  /* continue compressed packet */
   switch (adsp_cdr_ctrl->imc_param_1) {    /* type of decompression   */
     case 40:                               /* RDP4                    */
       goto p_dcco_r4_12;                   /* start calculating Length-of-Match RDP4 */
     case 50:                               /* RDP5                    */
       goto p_dcco_r5_12;                   /* start calculating Length-of-Match RDP5 */
     case 60:                               /* RDP6.0                  */
       goto p_dcco_r6_20;                   /* start calculating Length-of-Match RDP6.0 */
   }
#ifdef TRACEHL1
   printf( "DEC l%05d pdcbu20 imc_param_1=%d invalid value / allowed: 40 50 60.\n",
           __LINE__, adsp_cdr_ctrl->imc_param_1 );
#endif
   adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error       */
   return;                                  /* return to main-prog     */

   pdcco80:                                 /* continue bits for Length-of-Match */
   iml_shift_v = adsl_dec_int->imc_shift_v;  /* shift-value            */
   iml_shift_c = adsl_dec_int->imc_shift_c;  /* shift-count            */
   achl_histbu_end = adsl_dec_int->achc_histbu_end;  /* end of history buffer */
   achl_histbu_cur = adsl_dec_int->achc_histbu_cur;  /* current position in history buffer */
   achl_histbu_max = adsl_dec_int->achc_histbu_max;  /* maximum position in history buffer */
   iml_copy_offset = adsl_dec_int->imc_save_1;  /* copy-offset         */
   iml1 = adsl_dec_int->imc_save_2;         /* bits for Length-of-Match */
   adsl_dec_int->iec_dec_cont = ied_dc_dcbu20;  /* continue compressed packet */
   switch (adsp_cdr_ctrl->imc_param_1) {    /* type of decompression   */
     case 40:                               /* RDP4                    */
       goto p_dcco_r4_24;                   /* continue bits for Length-of-Match RDP4 */
     case 50:                               /* RDP5                    */
       goto p_dcco_r5_24;                   /* continue bits for Length-of-Match RDP5 */
#ifdef XYZ1
     case 60:                               /* RDP6.0                  */
       goto p_dcco_r6_20;                   /* start calculating Length-of-Match RDP6.0 */
#endif
   }
#ifdef TRACEHL1
   printf( "DEC l%05d pdcbu20 imc_param_1=%d invalid value / allowed: 40 50 60.\n",
           __LINE__, adsp_cdr_ctrl->imc_param_1 );
#endif
   adsp_cdr_ctrl->imc_return = DEF_IRET_ERRAU;  /* message error       */
   return;                                  /* return to main-prog     */

   pdc_trans_00:                            /* input data transparent  */
#ifdef TRACEHL1
   printf( "DEC l%05d pdc_trans_00\n",
           __LINE__ );
#endif
   adsl_dec_int->imc_shift_v = 0;           /* shift-value             */
   adsl_dec_int->imc_shift_c = 0;           /* shift-count             */
   iml1 = achl_out_end - achl_out_cur;

   pdc_trans_20:                            /* copy content of gather  */
   iml2 = adsl_gai1_in->achc_ginp_end - adsl_gai1_in->achc_ginp_cur;
   if (iml2 > iml1) iml2 = iml1;
   memcpy( achl_out_cur, adsl_gai1_in->achc_ginp_cur, iml2 );
   achl_out_cur += iml2;                    /* increment output        */
   adsl_gai1_in->achc_ginp_cur += iml2;     /* increment input         */
   iml1 -= iml2;                            /* subtract bytes processed */
   if (iml1 <= 0) {                         /* end of output area      */
     adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
     if (adsp_cdr_ctrl->boc_mp_flush == FALSE) return;  /* not flush set from main program */
     while (TRUE) {
       if (adsl_gai1_in == NULL) break;     /* we have no gather       */
       if (adsl_gai1_in->achc_ginp_cur < adsl_gai1_in->achc_ginp_end) {  /* data in this gather */
         adsp_cdr_ctrl->boc_sr_flush = FALSE;  /* did not reach end of input */
         break;
       }
       adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain   */
     }
     return;                                /* wait for more output space */
   }

   pdc_trans_40:                            /* get next input          */
   adsl_gai1_in = adsl_gai1_in->adsc_next;  /* get next in chain       */
   if (adsl_gai1_in == NULL) {              /* end of input            */
     adsp_cdr_ctrl->achc_out_cur = achl_out_cur;  /* current end of output data */
//   adsp_cdr_ctrl->boc_sr_flush = FALSE;   /* did not reach end of input */
     return;                                /* wait for input data     */
   }
   if (adsl_gai1_in->achc_ginp_cur < adsl_gai1_in->achc_ginp_end) {  /* data in this gather */
     goto pdc_trans_20;                     /* copy content of gather  */
   }
   goto pdc_trans_40;                       /* get next input          */
} /* end m_cdr_dec()                                                   */

#ifdef TRACEHL1
/* subroutine to dump storage-content to console                       */
static void m_console_out( char *achp_buff, int implength ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   iml1 = 0;
   while (iml1 < implength) {
     iml2 = iml1 + 16;
     if (iml2 > implength) iml2 = implength;
     for ( iml3 = 4; iml3 < 75; iml3++ ) {
       chrlwork1[iml3] = ' ';
     }
     chrlwork1[58] = '*';
     chrlwork1[75] = '*';
     iml3 = 4;
     do {
       iml3--;
       chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
     } while (iml3 > 0);
     iml4 = 6;                              /* start hexa digits here  */
     iml5 = 59;                             /* start ASCII here        */
     iml6 = 4;                              /* times normal            */
     do {
       byl1 = achp_buff[ iml1++ ];
       chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
       chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
       iml4++;
       if (byl1 > 0X20) {
         chrlwork1[ iml5 ] = byl1;
       }
       iml5++;
       iml6--;
       if (iml6 == 0) {
         iml4++;
         iml6 = 4;
       }
     } while (iml1 < iml2);
     printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_console_out()                                               */

/* subroutine to dump storage-content to console                       */
static void m_console_gather( struct dsd_gather_i_1 *adsp_gai1_in ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   char       *achl_w1;                     /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_in_w1;  /* working-variable        */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   adsl_gai1_in_w1 = adsp_gai1_in;          /* get input               */
   achl_w1 = adsl_gai1_in_w1->achc_ginp_cur;
   iml1 = 0;

   p_out_20:                                /* next line output        */
   for ( iml3 = 4; iml3 < 75; iml3++ ) {
     chrlwork1[iml3] = ' ';
   }
   chrlwork1[58] = '*';
   chrlwork1[75] = '*';
   iml3 = 4;
   do {
     iml3--;
     chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
   } while (iml3 > 0);
   iml4 = 6;                                /* start hexa digits here  */
   iml5 = 59;                               /* start ASCII here        */
   iml6 = 4;                                /* times normal            */
   iml2 = iml1;                             /* save start              */
   do {
     while (achl_w1 >= adsl_gai1_in_w1->achc_ginp_end) {  /* end of this gather */
       adsl_gai1_in_w1 = adsl_gai1_in_w1->adsc_next;  /* get next in chain */
       if (adsl_gai1_in_w1 == NULL) {       /* end of input            */
         if (iml1 == iml2) return;
         goto p_out_40;                     /* line has been prepared  */
       }
       achl_w1 = adsl_gai1_in_w1->achc_ginp_cur;
     }
     byl1 = *achl_w1++;
     iml1++;
     chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
     chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
     iml4++;
     if (byl1 > 0X20) {
       chrlwork1[ iml5 ] = byl1;
     }
     iml5++;
     iml6--;
     if (iml6 == 0) {
       iml4++;
       iml6 = 4;
     }
   } while (iml1 < (iml2 + 16));

   p_out_40:                                /* line has been prepared  */
   printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
   if (adsl_gai1_in_w1) {                   /* more of input           */
     goto p_out_20;                         /* next line output        */
   }
   return;
} /* end m_console_gather()                                            */
#endif
