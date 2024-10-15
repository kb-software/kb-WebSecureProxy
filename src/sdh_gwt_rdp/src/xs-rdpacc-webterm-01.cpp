//%SET TRY$170928$01=1;                       /* HOB-RDP-EXT1 disable */
#define _CRT_SECURE_NO_WARNINGS // To disable warnings due to the use of "insecure" functions like strncpy or similar


//*SET TRY$160324$01=1;                       /* Virus-Checking Clipboard */
//*SET TRY$150912$01=1;
//*SET DEBUG$150728$01=1;
//*SET TRY_120425_1=1;
//*SET CAP$LEVEL=0;
//*SET D_TRACE_HL1=1;
//*SET D_TRACE_HL1=1;

// 2017.03.06 DD: HELP_DEBUG has been renamed to HL_RDPACC_HELP_DEBUG.
//                If you want or need to use this define, please add the 
//                definition in the respective header. This way, all compilation
//                units that use the structures defined in the header will have 
//                the same structure's definition.
//*SET TRY_101213_01=1;
//*SET D_TRACE_HL1=1;
//*SET D_PROB_101209=1;
//*set BNEWACC1=1;
/* end special setting KB 12.09 */
//*set D_TRACE_090302=1;
//*set D_FILE_BITMAP=1;
//*set D_TRACE_HL1=1;
//*set D_TRACE_HL1=0;
//*set try$070518=1;
#define CERTMS01                            /* 20.01.05 KB - certificate Microsoft */
#define PROB_050608
#define PROB_050610
#define PROB_050611
#define PROB_050618
#define PROB_050619
#define PROB_060725
#define PROB_060827
//#define B050514
//#define TRACEHL1
//#define TEMPSCR1                            /* 06.01.05 KB - send screen */
#define CERTMS01                            /* 20.01.05 KB - certificate Microsoft */
//#define TRACE_LOOP_1                        /* 24.01.05 KB - loop after error */
#define D_FFLUSH                            /* 30.05.05 KB - flush stdout */
#define D_FOR_TRACE1                        /* 31.05.05 KB - help in tracing */
#define D_BUG_HLJWT_INP1                    /* 17.07.07 KB - input from HOBlink JWT not encrypted */
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xlrdpac1                                            |*/
/*| -------------                                                     |*/
/*|  DLL / Library for WebSecureProxy                                 |*/
/*|  RDP Accelerator                                                  |*/
/*|  KB 01.08.04                                                      |*/
/*|  Version 1.2 KB 15.02.12                                          |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|  Copyright (C) HOB Germany 2005                                   |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|  Copyright (C) HOB Germany 2017                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC all plattforms                                               |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|  generated source from .pre (PRECOMP)                             |*/
/*|  this is the source for little endian                             |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* #define TRACEHL1 */

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#define HCOMPR2
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#ifndef HL_UNIX
#include <conio.h>
#endif
#include <time.h>
#ifndef HL_UNIX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
//#include <unistd.h>
#include "hob-unix01.h"
#endif
#include "hob-cd-record-1.h"
#ifdef HL_APPLE_IOS
#include <TargetConditionals.h>
#endif
#include "hob-encry-1.h"
#include "hob-xsclib01.h"
#include "hob-rdptracer1.h"
#include <hob-xslunic1.h>
#include "hob-webterm-rdp-01.h"
#include "hob-stor-sdh.h"

#ifndef HL_UNIX
typedef int socklen_t;
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#endif

#ifndef HL_WCHAR
#ifndef HL_UNIX
#define HL_WCHAR WCHAR
#else
#define HL_WCHAR unsigned short int
#endif
#endif

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

#define D_STACK_WORKAREA_SIZE   65536

#define D_AUX_STOR_SIZE      (32 * 1024)    /* size storage element    */
#define DEF_LEN_VIRTCH_STA   12
#define D_MAX_CRYPT_LEN      0X100
#define D_MAX_OFFSCR_DELETE  64             /* maximum indices in OFFSCR_DELETE_LIST */
#define D_MAX_BMC_MSTSC      32000          /* maximum length for bitmap compression */
#define D_MAX_OUT_BMC_MSTSC  4000           /* maximum output of bitmap compression */
#define D_USERID_SE2CL       1              /* userid from server to client */
#define D_DISPLAY_CHANNEL    0X03EB         /* default display channel */
#define D_EXTRA_CHANNEL      0X03E9         /* begin extra channels    */
#define D_R5_ORD_NO          32             /* RDP 5 maximum order number */
#define MAX_PASSWORD         256            /* maximum length of password */
#define D_LEN_CLIENT_RAND    32             /* length client random    */
#define D_LEN_HMAC           64             /* length constants HMAC   */
#define CONST_DEV_BITMAP     13             /* ask Microsoft why shorten length is needed */
#define D_RSA_KEY_SIZE       256            /* compare size RSA key    */
#define D_RSA_KEY_PADDING    8              /* padding of RSA key      */
//#define DEF_NO_COPY          128
#define DEF_CONST_RDP_03     0X03
#define DEF_CONST_ASN1_OS_04 0X04
#define DEF_CONST_ORDSEC_CACHE_GLYPHS_XRDP 0X03
#define DEF_CONST_ORDSEC_BRUSH 0X07
#define DEF_CONST_ORDSEC_MAX   0X05
#define DEF_CONST_ORDSEC_BRUSH_LEN 6        /* length of brush data    */
#define DEF_CONST_O01_BRUSH_LEN 7           /* length of brush data    */
#define DEF_CONST_O0E_BRUSH_LEN 7           /* length of brush data    */
#define DEF_UPDATE_BITMAP_CO 9              /* number of short update bitmap */
#define D_TYPE_PUB_PAR_DIR   1              /* public parms direct     */
#define D_TYPE_PUB_PAR_CERT  2              /* public parms certificate */
#define D_PPDIR_PUB_VAL      6              /* public parms direct public value */
#define D_PPDIR_SIG          8              /* public parms direct signature */
#define D_GLYCOT1            10             /* glyph coordinates       */
#define D_GLYCOT2            256            /* glyph coordinates       */
#define D_GLYLEFT            0              /* glyph coordinate left   */
#define D_GLYTOP             1              /* glyph coordinate top    */
#define D_GLYWIDTH           2              /* glyph coordinate width  */
#define D_GLYHEIGHT          3              /* glyph coordinate height */
#define D_DEMAND_ACT_PDU     0X11           /* demand active PDU       */
#define TS_DEACTIVATE_ALL_PDU 0X16          /* Deactivate All PDU Data */
#define PDUTYPE_DATAPDU      0X07           /* Data PDU                */
#define D_XYZ_ERROR          0X17           /* ??? 04.06.11 KB         */
#define SYNCMSGTYPE_SYNC     1
// TS_UD_CS_CORE::supportedColorDepths:
#define RNS_UD_24BPP_SUPPORT              0X0001
#define RNS_UD_16BPP_SUPPORT              0X0002
#define RNS_UD_15BPP_SUPPORT              0X0004
#define RNS_UD_32BPP_SUPPORT              0X0008
// TS_UD_CS_CORE::earlyCapabilityFlags:
#define RNS_UD_CS_SUPPORT_ERRINFO_PDU         0X0001
#define RNS_UD_CS_WANT_32BPP_SESSION          0X0002
#define RNS_UD_CS_SUPPORT_STATUSINFO_PDU      0X0004
#define RNS_UD_CS_STRONG_ASYMMETRIC_KEYS      0X0008
#define RNS_UD_CS_UNUSED                      0x0010
#define RNS_UD_CS_VALID_CONNECTION_TYPE       0x0020
#define RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU  0x0040
#define RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT  0x0080
#define RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL  0x0100
#define RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE   0x0200
#define RNS_UD_CS_SUPPORT_HEARTBEAT_PDU       0x0400

#define INFO_FORCE_ENCRYPTED_CS_PDU      0X00004000

#define CAPSTYPE_GENERAL     1              /* General Capability Set (section 2.2.7.1.1) */
#define CAPSTYPE_BITMAP      2              /* Bitmap Capability Set (section 2.2.7.1.2) */
#define CAPSTYPE_ORDER       3              /* Order Capability Set (section 2.2.7.1.3) */
#define CAPSTYPE_BITMAPCACHE 4              /* Revision 1 Bitmap Cache Capability Set (section 2.2.7.1.4.1) */
#define CAPSTYPE_CONTROL     5              /* Control Capability Set (section 2.2.7.2.2) */
#define CAPSTYPE_ACTIVATION  7              /* Window Activation Capability Set (section 2.2.7.2.3) */
#define CAPSTYPE_POINTER     8              /* Pointer Capability Set (section 2.2.7.1.5) */
#define CAPSTYPE_SHARE       9              /* Share Capability Set (section 2.2.7.2.4) */
#define CAPSTYPE_COLORCACHE  10             /* Color Table Cache Capability Set (see [MS-RDPEGDI] section 2.2.1.1) */
#define CAPSTYPE_SOUND       12             /* Sound Capability Set (section 2.2.7.1.11) */
#define CAPSTYPE_INPUT       13             /* Input Capability Set (section 2.2.7.1.6) */
#define CAPSTYPE_FONT        14             /* Font Capability Set (section 2.2.7.2.5) */
#define CAPSTYPE_BRUSH       15             /* Brush Capability Set (section 2.2.7.1.7) */
#define CAPSTYPE_GLYPHCACHE  16             /* Glyph Cache Capability Set (section 2.2.7.1.8) */
#define CAPSTYPE_OFFSCREENCACHE 17          /* Offscreen Bitmap Cache Capability Set (section 2.2.7.1.9) */
#define CAPSTYPE_BITMAPCACHE_HOSTSUPPORT 18  /* Bitmap Cache Host Support Capability Set (section 2.2.7.2.1) */
#define CAPSTYPE_BITMAPCACHE_REV2 19        /* Revision 2 Bitmap Cache Capability Set (section 2.2.7.1.4.2) */
#define CAPSTYPE_VIRTUALCHANNEL 20          /* Virtual Channel Capability Set (section 2.2.7.1.10) */
#define CAPSTYPE_DRAWNINEGRIDCACHE 21       /* DrawNineGrid Cache Capability Set ([MS-RDPEGDI] section 2.2.1.2) */
#define CAPSTYPE_DRAWGDIPLUS 22             /* Draw GDI+ Cache Capability Set ([MS-RDPEGDI] section 2.2.1.3) */
#define CAPSTYPE_RAIL        23             /* Remote Programs Capability Set ([MS-RDPERP] section 2.2.1.1.1) */
#define CAPSTYPE_WINDOW      24             /* Window List Capability Set ([MS-RDPERP] section 2.2.1.1.2) */
#define CAPSETTYPE_COMPDESK  25             /* Desktop Composition Extension Capability Set (section 2.2.7.2.8) */
#define CAPSETTYPE_MULTIFRAGMENTUPDATE 26   /* Multifragment Update Capability Set (section 2.2.7.2.6) */
#define CAPSETTYPE_LARGE_POINTER 27         /* Large Pointer Capability Set (section 2.2.7.2.7) */
#define TS_CACHED_BRUSH      0X80
#define BS_SOLID             0X00
#define BS_NULL              0X01
#define BS_HATCHED           0X02
#define BS_PATTERN           0X03
#define HS_HORIZONTAL        0X00
#define HS_VERTICAL          0X01
#define HS_FDIAGONAL         0X02
#define HS_BDIAGONAL         0X03
#define HS_CROSS             0X04
#define HS_DIAGCROSS         0X05
#define SV_SAVEBITS          0X00           /* Save bitmap operation   */
#define SV_RESTOREBITS       0X01           /* Restore bitmap operation */
// JB: Calculating exact lengths for Mac Gate. Request by SM.
#define MAX_PDU_LEN          0X00003FFF
#define MAX_FP_HEADER_SIZE   (3 + 8)
#define MAX_TS_FP_HEADER_SIZE (MAX_FP_HEADER_SIZE + 3)
#define TS_CACHE_GLYPH                    0X03
#define TS_ALTSEC_STREAM_BITMAP_FIRST     0X02
#define TS_ALTSEC_STREAM_BITMAP_NEXT      0X03
#define TS_ALTSEC_CREATE_NINEGRID_BITMAP  0X04
#define TS_ALTSEC_FRAME_MARKER            0X0D
#define STREAM_BITMAP_REV2                0X04

#define TS_PROTOCOL_VERSION               0X10
#define PDUTYPE_CONFIRMACTIVEPDU          0X03

// Secondary drawing order types (orderType):
#define TS_CACHE_BITMAP_UNCOMPRESSED        0x00
#define TS_CACHE_BITMAP_COMPRESSED          0x02
#define TS_CACHE_BITMAP_UNCOMPRESSED_REV2   0x04
#define TS_CACHE_BITMAP_COMPRESSED_REV2     0x05
#define TS_CACHE_BITMAP_COMPRESSED_REV3     0x08

// Embedded extraflags for 2.2.2.2.1.2.2 Cache Bitmap - Revision 1 (CACHE_BITMAP_ORDER):
#define NO_BITMAP_COMPRESSION_HDR   0x0400
// Embedded extraFlags for 2.2.2.2.1.2.3 Cache Bitmap - Revision 2 (CACHE_BITMAP_REV2_ORDER):
//   + bitsPerPixelId (4 bits):
#define CBR2_8BPP   0x3
#define CBR2_16BPP  0x4
#define CBR2_24BPP  0x5
#define CBR2_32BPP  0x6
//   + flags (9 bits):
#define CBR2_HEIGHT_SAME_AS_WIDTH         0X01
#define CBR2_PERSISTENT_KEY_PRESENT       0X02
#define CBR2_NO_BITMAP_COMPRESSION_HDR    0X08
#define CBR2_DO_NOT_CACHE                 0X10
// Embedded extraFlags for 2.2.2.2.1.2.8 Cache Bitmap - Revision 3 (CACHE_BITMAP_REV3_ORDER):
//   + bitsPerPixelId (4 bits):
#define CBR23_8BPP  0x3
#define CBR23_16BPP 0x4
#define CBR23_24BPP 0x5
#define CBR23_32BPP 0x6
//   + flags (9 bits):
#define CBR3_IGNORABLE_FLAG 0x08
#define CBR3_DO_NOT_CACHE                 0X10

#define BITMAPCACHE_WAITING_LIST_INDEX  32767


#define LEN_MPOI_NEW_PAD                  1  /* pad from [MS-RDPBCGR] section 2.2.9.1.1.4.4 */
//#define PDUTYPE_DATAPDU                   0X07
#define PACKET_COMPR_TYPE_8K              0X00
/* RDP 4.0 bulk compression (see section 3.1.8.4.1).                   */
#define PACKET_COMPR_TYPE_64K             0X01
/* RDP 5.0 bulk compression (see section 3.1.8.4.2).                   */
#define PACKET_COMPR_TYPE_RDP6            0X02
/* RDP 6.0 bulk compression (see [MS-RDPEGDI] section 3.1.8.1).        */
#define PACKET_COMPR_TYPE_RDP61           0X03
/* RDP 6.1 bulk compression (see [MS-RDPEGDI] section 3.1.8.2)         */


#define M_ERROR_FRSE_ILLOGIC iml_line_no = __LINE__; goto pfrse96;



/* get a piece of storage                                              */
/* end of macro M_MALLOC()                                             */

/* copy field structure dsd_rdp_co from server to client               */
/* end of macro M_COPY_CO1_SE2CL()                                     */


/* some cryptographical data mixing steps used in key generation       */
/* end of macro M_SALTHASH()                                           */

/* Macro to assign the string stored in the unicode string to the given destination in UTF-16-LE */
/* end of macro M_UNICODE_STRING_TO_UTF16LE_BUFFER();
/* macro to apply order coordinates - absolute                         */
/* end of macro M_APPLY_ORD_ABS()                                      */

/* macro to apply order coordinates - absolute                         */
/* end of macro NEW_APPLY_ORD_ABS()                                    */

//*if def BNEWACC1;
/* macro to continue depending on flag bits                            */
/* end of macro M_CONT_O_COOR_ABS()                                    */

/* macro to apply order coordinates - delta                            */
/* end of macro M_APPLY_ORD_DELTA()                                    */

/* macro to continue depending on flag bits                            */
/* end of macro M_CONT_O_COOR_DELTA()                                  */
//*cend;

/* macro to continue depending on flag bits for bounds absolute or delta */
/* end of macro M_CO_BOUNDS_APPLY()                                    */

/* macro to apply value litle endian                                   */
/* end of macro M_APPLY_LE()                                           */

/* macro to apply a single byte                                        */
/* end of macro M_CL_APPLY_SINGLE()                                    */

/* macro to prepare for a field with a single byte                     */
/* end of macro M_CL_PREPARE_SINGLE()                                  */

/* macro to prepare for multi-byte field                               */
/* end of macro M_CL_PREPARE_MULTI()                                   */

/* macro to apply awcs mouse pointer field                             */
/* end of macro M_CL_APPLY_MPOI()                                      */

/* macro to continue depending on flag bits for order 00 / 0X00        */
/* end of macro M_CO_O00_FIELDS()                                      */

/* macro to continue depending on flag bits for order 01 / 0X01        */
/* end of macro M_CO_O01_FIELDS()                                      */

/* macro to continue depending on flag bits for order 02 / 0X02        */
/* end of macro M_CO_O02_FIELDS()                                      */

/* macro to continue depending on flag bits for order 7 / 0X07         */
/* end of macro M_CO_O07_FIELDS()                                      */

/* macro to continue depending on flag bits for order 8 / 0X08         */
/* end of macro M_CO_O08_FIELDS()                                      */

/* macro to continue depending on flag bits for order 09 / 0X09        */
/* end of macro M_CO_O09_FIELDS()                                      */

/* macro to continue depending on flag bits for order 10 / 0X0A        */
/* end of macro M_CO_O0A_FIELDS()                                      */

/* macro to continue depending on flag bits for order 11 / 0X0B        */
/* end of macro M_CO_O0B_FIELDS()                                      */

/* macro to continue depending on flag bits for order 13 / 0X0D        */
/* end of macro M_CO_O0D_FIELDS()                                      */

/* macro to continue depending on flag bits for order 14 / 0X0E        */
/* end of macro M_CO_O0E_FIELDS()                                      */

/* macro to continue depending on flag bits for order 15 / 0X0F        */
/* end of macro M_CO_O0F_FIELDS()                                      */

/* macro to continue depending on flag bits for order 16 / 0X10        */
/* end of macro M_CO_O10_FIELDS()                                      */

/* macro to continue depending on flag bits for order 17 / 0X11        */
/* end of macro M_CO_O11_FIELDS()                                      */

/* macro to continue depending on flag bits for order 18 / 0X12        */
/* end of macro M_CO_O12_FIELDS()                                      */

/* macro to continue depending on flag bits for order 19 / 0X13        */
/* end of macro M_CO_O13_FIELDS()                                      */

/* macro to continue depending on flag bits for order 20 / 0X14        */
/* end of macro M_CO_O14_FIELDS()                                      */

/* macro to continue depending on flag bits for order 21 / 0X15        */
/* end of macro M_CO_O15_FIELDS()                                      */

/* macro to continue depending on flag bits for order 22 / 0X16        */
/* end of macro M_CO_O16_FIELDS()                                      */

/* macro to continue depending on flag bits for order 24 / 0X18        */
/* end of macro M_CO_O18_FIELDS()                                      */

/* macro to continue depending on flag bits for order 25 / 0X19        */
/* end of macro M_CO_O19_FIELDS()                                      */

/* macro to continue depending on flag bits for order 26 / 0X1A        */
/* end of macro M_CO_O1A_FIELDS()                                      */

/* macro to continue depending on flag bits for order 27 / 0X1B        */
/* end of macro M_CO_O1B_FIELDS()                                      */

/* macro to check if temporary buffer is big enough                    */
/* end of macro M_TMPBUF_CL_1()                                        */

/* macro to check if temporary buffer is big enough                    */
/* end of macro M_TMPBUF_SE_1()                                        */

/* macro bitmap order 0 fill9                                          */
/* end of macro M_BITMAP_00_1()                                        */

/* macro bitmap order 1 Mix                                            */
/* end of macro M_BITMAP_01_1()                                        */

/* macro make frame buffer                                             */
/* end of macro M_FRAME_BUF_1()                                        */

/* macro make frame buffer                                             */
/* end of macro M_FRAME_BUF_2()                                        */

/* macro make frame buffer                                             */
/* end of macro M_FRAME_BUF_3()                                        */

/* macro make frame buffer                                             */
/* end of macro M_FRAME_BUF_4()                                        */

/* macro make frame buffer                                             */
/* end of macro M_FRAME_BUF_5()                                        */

/* macro check PDU overflow                                            */
/* end of macro M_CHECK_PDU_OV()                                       */

/* macro to send bounds to the client, first part                      */
/* end of macro M_SEND_BOUNDS_P1()                                     */

/* macro to send bounds to the client, second part                     */
/* end of macro M_SEND_BOUNDS_P2()                                     */

/* macro to generate prototype statement for ROP2/3                    */
/* end of macro to generate prototype statement for ROP2/3             */
/* macro to generate functions for ROP2/3                              */
/* macro to generate definitions for ROP2/3                            */
/* end of macro to generate definitions for ROP2/3                     */
/* macro to generate functions for ROP2/3                              */
/* end of macro to generate functions for ROP2/3                       */
/* macro to generate LineTo operations, also for Polyline              */
/* end of macro to generate LineTo operations, also for Polyline       */

typedef unsigned int ( * amd_rop2_x_x )( unsigned int, unsigned int );


/* receive block from server, field position                           */
enum ied_fsfp_bl {
   ied_fsfp_invalid,                        /* invalid data received   */
   ied_fsfp_constant,                       /* is in constant          */
   ied_fsfp_status,                         /* status from server      */
   ied_fsfp_x224_p01,                       /* is in x224 header       */
   ied_fsfp_ignore,                         /* ignore data             */
   ied_fsfp_copy,                           /* copy data               */
   ied_fsfp_cmp_zero,                       /* compare with zeroes     */
   ied_fsfp_rec_type,                       /* receive record type     */
   ied_fsfp_byte01,                         /* receive byte 01         */
   ied_fsfp_lencons_2,                      /* two bytes length remain */
   ied_fsfp_lencons_1,                      /* one byte length remains */
   ied_fsfp_mcs_c1,                         /* x224 MCS command 1      */
   ied_fsfp_mcs_c2,                         /* x224 MCS command 2      */
   ied_fsfp_userid_se2cl,                   /* userid server to client */
   ied_fsfp_userid_cl2se,                   /* userid client to server */
   ied_fsfp_chno,                           /* channel number          */
   ied_fsfp_prio_seg,                       /* Priority / Segmentation */
   ied_fsfp_rt02,                           /* record type 2           */
   ied_fsfp_rt03,                           /* record type 3           */
   ied_fsfp_padd_1,                         /* padding                 */
   ied_fsfp_rdp4_hash,                      /* hash RDP4 block         */
   ied_fsfp_sch_len,                        /* Share Control Header length */
   ied_fsfp_sch_pdu_type,                   /* Share Control Header PDU type */
   ied_fsfp_sch_pdu_source,                 /* Share Control Header PDU source */
   ied_fsfp_sdh_header_1,
   ied_fsfp_sdh_header_2,
   ied_fsfp_sdh_header_3,
   ied_fsfp_datapdu_monitor_layout,
   ied_fsfp_datapdu_synchronize,
   ied_fsfp_datapdu_save_session_info,
   ied_fsfp_r04_rdp_v,                      /* block 4 RDP version     */
   ied_fsfp_int_lit_e,                      /* int little endian       */
   ied_fsfp_int_big_e,                      /* int big endian          */
   ied_fsfp_asn1_tag,                       /* ASN.1 tag               */
   ied_fsfp_asn1_l1_fi,                     /* ASN.1 length field      */
   ied_fsfp_asn1_l1_p2,                     /* ASN.1 length part two   */
   ied_fsfp_mu_len_1,                       /* multi length 1          */
   ied_fsfp_mu_len_2,                       /* multi length 2          */
   ied_fsfp_actpdu_no_cap,                  /* Demand Active PDU caps block */
   ied_fsfp_r5_len_1,                       /* RDP 5 multi length 1    */
   ied_fsfp_r5_len_2,                       /* RDP 5 multi length 2    */
   ied_fsfp_r5_hash,                        /* RDP 5 hash              */
   ied_fsfp_r5_pdu_typ,                     /* RDP 5 PDU type          */
   ied_fsfp_r5_pdu_cofl,                    /* RDP 5 compression flags */
   ied_fsfp_r5_pdu_len,                     /* RDP 5 PDU length        */
   ied_fsfp_r5_pdu_content,                 /* RDP 5 PDU content       */
   ied_fsfp_r5_pdu_compr,                   /* RDP 5 PDU compressed    */
   ied_fsfp_send_from_server,               /* send data to client     */
   ied_fsfp_end_com,                        /* end of communication    */
   ied_fsfp_no_session,                     /* no more session         */
#ifdef XYZ1
                   ied_fcfp_int_lit_e,      /* int little endian       */
                    ied_frclnv_usxx,        /* userid invalid - not fo */
#endif
                    ied_frclnvx_pasxxord };  /* password invalid        */


/* receive block from server                                           */
enum ied_frse_bl {
   ied_frse_start,                          /* start of communication  */
   ied_frse_sta_02,                         /* start second field      */
   ied_frse_rec_04,                         /* receive block 4         */
   ied_frse_r04_asn1_1,                     /* block 4 ASN-1 field 1   */
   ied_frse_r04_asn1_2,                     /* block 4 ASN-1 field 2   */
   ied_frse_r04_asn1_3,                     /* block 4 ASN-1 field 3   */
   ied_frse_r04_asn1_4,                     /* block 4 ASN-1 field 4   */
   ied_frse_r04_sel_t,                      /* block 4 selection tag   */
   ied_frse_r04_sel_l,                      /* block 4 selection length */
   ied_frse_r04_rdp_v,                      /* block 4 RDP version     */
   ied_frse_r04_ch_disp,                    /* block 4 display channel */
   ied_frse_r04_vch_no,                     /* block 4 no virtual channels */
   ied_frse_r04_vch_var,                    /* block 4 variable channel */
   ied_frse_r04_vch_del,                    /* block 4 vch delemiter   */
   ied_frse_r04_sec_method,                 /* block 4 security method */
   ied_frse_r04_sec_level,                  /* block 4 security level  */
   ied_frse_r04_l_serv_rand,                /* block 4 length server random */
   ied_frse_r04_l_pub_par,                  /* block 4 length public parameters */
   ied_frse_r04_d_serv_rand,                /* block 4 data server random */
   ied_frse_r04_type_pub_par,               /* block 4 type public parameters */
   ied_frse_r04_ppdir_tag,                  /* block 4 public parms direct tag */
   ied_frse_r04_ppdir_len,                  /* block 4 public parms direct lenght */
   ied_frse_r04_d_pub_par,                  /* block 4 data public parameters */
   ied_frse_r04_mcs_msgchannel,             // block4 2.2.1.4.5 Server Message Channel Data
   ied_frse_rec_07,                         /* receive block 7         */
   ied_frse_cjresp_rec,                     /* receive block channel join response */
   ied_frse_lic_pr_1_rec,                   /* receive block licence protocol */
   ied_frse_lic_pr_type,                    /* licencing block to check */
   ied_frse_lic_pr_req_rand,                /* server license request random */
   ied_frse_lic_pr_req_cert,                /* server license request certificate */
   ied_frse_lic_pr_req_scopelist,           /* parse the scopelist of server license request packet */
   ied_frse_lic_pr_chll,                    /* platform challenge      */
   ied_frse_lic_pr_new_license,             /* new license or upgrade license */
   ied_frse_lic_pr_lic_error_mes1,          /* Licensing Error Message */
   ied_frse_lic_pr_lic_error_mes2,          /* Licensing Error Message */
   ied_frse_act_pdu_rec,                    /* receive block active PDU */
   ied_frse_actpdu_parse_shareid,           /* parse shareid           */
   ied_frse_actpdu_sdl,                     /* get source descriptor length */
   ied_frse_actpdu_len_cap,                 /* get length capabilities */
   ied_frse_actpdu_no_cap,                  /* get number capabilities */
   ied_frse_actpdu_cap_ind,                 /* get capabilities index  */
   ied_frse_actpdu_cap_len,                 /* get capabilities length */
   ied_frse_actpdu_trail,                   /* trailer of act PDU      */
   ied_frse_deaap_rec,                      /* Deactivate All PDU Data */
   ied_frse_deactivate_all,                 /* deactivate all PDU      */
   ied_frse_error_bl_01,                    /* receive error block 01  */
   ied_frse_error_bl_02,                    /* receive error block 02  */
   ied_frse_any_pdu_rec,                    /* receive any PDU type    */
   ied_frse_rdp4_vch_ulen,                  /* virtual channel uncompressed data length */
   ied_frse_rdp4_mcs_msgchannel,            // PDU on the MCS MSGChannel
   ied_frse_r5_pdu_primord,                 /* RDP 5 PDU primary order */
   ied_frse_r5_pdu_apply_order,             /* RDP 5 PDU apply order   */
   ied_frse_r5_ign_single_unic,             /* ignore one single Unicode character */
   ied_frse_r5_o01_brush_data,              /* RDP 5 order 1 brush data */
   ied_frse_r5_o0e_brush_data,              /* RDP 5 order 14 brush data */
   ied_frse_r5_o10_brush_data,              /* RDP 5 order 16 brush data */
   ied_frse_r5_o15_brush_data,              /* RDP 5 order 21/15H brush data */
   ied_frse_r5_o1a_brush_data,              /* RDP 5 order 26/0X1A brush data */
   ied_frse_r5_o1b_brush_data,              /* RDP 5 order 27/0X1B brush data */
   ied_frse_xyz_end_pdu,                    /* end of PDU              */
/* 18.06.05 KB UUUU */
   ied_frse_xyz_end_order,                  /* end of order            */
// ied_frse_r04_rdp_v,                      /* block 4 RDP version     */
                    ied_ad_inv_user_x,        /* userid invalid - not fo */
                    ied_ad_inv_password_x };  /* password invalid        */

struct dsd_progaddr_1 {                     /* program addresses       */
   BOOL (* amc_decomp_01_x) ( struct dsd_call_wt_rdp_client_1 *, struct dsd_cache_1 *, char *, int );
   amd_rop2_x_x amrc_rop2_x_x[ 16 ];        /* ROP2 functions          */
};

struct dsd_encry_work_1 {                   /* work area for encryption */
   int        imrl_sha1_work[ SHA_ARRAY_SIZE ];
   int        imrl_md5_work[ MD5_ARRAY_SIZE ];
};

struct dsd_encry_work_2 {                   /* work area for encryption */
   int        imrl_sha1_work[ SHA_ARRAY_SIZE ];
   char       byrl_sha1_digest[ SHA_DIGEST_LEN ];
   int        imrl_md5_work[ MD5_ARRAY_SIZE ];
   char       byrl_md5_digest[ MD5_DIGEST_LEN ];
   char       byrl_pre_hash[ 16 * 3 ];
   char       byrl_master_h1[ 16 ];
   char       byrl_master_h2[ 16 ];
   char       byrl_master_h3[ 16 ];
};



struct dsd_offscr_b_1 {                     /* offscreen buffer        */
   unsigned short int usc_dim_x;            /* dimension x pixels      */
   unsigned short int usc_dim_y;            /* dimension y pixels      */
   void *     ac_offscr_buffer;             /* offscreen buffer        */
};

struct dsd_bmp_cache_b_1 {                  /* Bitmap Cache Buffer     */
   unsigned short int usc_dim_x;            /* dimension x pixels      */
   unsigned short int usc_dim_y;            /* dimension y pixels      */
   int        imc_no_pixel;                 /* number of pixel in buffer */
   void *     ac_bmp_cache_buffer;          /* Bitmap Cache Buffer     */
};

struct dsd_raord_scr {                      /* RA order screen         */
   struct dsd_raord_scr *adsc_next;         /* next in chain           */
   int        imc_left;                     /* coordinate left         */
   int        imc_top;                      /* coordinate top          */
   int        imc_right;                    /* coordinate right        */
   int        imc_bottom;                   /* coordinate bottom       */
};


//#define D_LOINFO_COMPR_ENA   128            /* compression enabled     */
//#define D_LOINFO_COMPR_LDIC  512            /* use large dictionary    */
#define D_LOINFO_COMPR_ENA   0X0080         /* compression enabled     */
#define D_LOINFO_COMPR_LDIC  0X0200         /* use large dictionary    */
#define D_LOINFO_COMPR_BULK  0X0400         /* use bulk compression    */
#define D_LOINFO_COMPRESSION_TYPE_MASK  0X00001E00  /* CompressionTypeMask */
#define D_LOINFO_COMPRESSION_TYPE_SHIFT 9  /* shift CompressionTypeMask */

#define SEC_EXCHANGE_PKT          0X0001
#define SEC_TRANSPORT_REQ         0X0002
#define RDP_SEC_TRANSPORT_RSP     0X0004
#define SEC_ENCRYPT               0X0008
#define SEC_RESET_SEQNO           0X0010
#define SEC_IGNORE_SEQNO          0X0020
#define SEC_INFO_PKT              0X0040
#define SEC_LICENSE_PKT           0X0080
#define SEC_LICENSE_ENCRYPT_SC    0X0200
#define SEC_REDIRECTION_PKT       0X0400
#define SEC_SECURE_CHECKSUM       0X0800
#define SEC_AUTODETECT_REQ        0X1000
#define SEC_AUTODETECT_RSP        0X2000
#define SEC_HEARTBEAT             0X4000
#define SEC_FLAGSHI_VALID         0X8000


#define LB_TARGET_NET_ADDRESS               0x00000001
#define LB_LOAD_BALANCE_INFO                0x00000002
#define LB_USERNAME                         0x00000004
#define LB_DOMAIN                           0x00000008
#define LB_PASSWORD                         0x00000010
#define LB_DONTSTOREUSERNAME                0x00000020
#define LB_SMARTCARD_LOGON                  0x00000040
#define LB_NOREDIRECT                       0x00000080
#define LB_TARGET_FQDN                      0x00000100
#define LB_TARGET_NETBIOS_NAME              0x00000200
#define LB_TARGET_NET_ADDRESSES             0x00000800
#define LB_CLIENT_TSV_URL                   0x00001000
#define LB_SERVER_TSV_CAPABLE               0x00002000
#define LB_PASSWORD_IS_PK_ENCRYPTED         0x00004000
#define LB_REDIRECTION_GUID                 0x00008000
#define LB_TARGET_CERTIFICATE               0x00010000

// Constants for TS_SHAREDATAHEADER::streamId
#define STREAM_UNDEFINED 0x00
#define STREAM_LOW       0x01
#define STREAM_MED       0x02
#define STREAM_HI        0x04

// Constants for TS_SHAREDATAHEADER::streamId
#define PDUTYPE2_UPDATE                          0x02
#define PDUTYPE2_CONTROL                         0x14
#define PDUTYPE2_POINTER                         0x1B
#define PDUTYPE2_INPUT                           0x1C
#define PDUTYPE2_SYNCHRONIZE                     0x1F
#define PDUTYPE2_REFRESH_RECT                    0x21
#define PDUTYPE2_PLAY_SOUND                      0x22
#define PDUTYPE2_SUPPRESS_OUTPUT                 0x23
#define PDUTYPE2_SHUTDOWN_REQUEST                0x24
#define PDUTYPE2_SHUTDOWN_DENIED                 0x25
#define PDUTYPE2_SAVE_SESSION_INFO               0x26
#define PDUTYPE2_FONTLIST                        0x27
#define PDUTYPE2_FONTMAP                         0x28
#define PDUTYPE2_SET_KEYBOARD_INDICATORS         0x29
#define PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST     0x2B
#define PDUTYPE2_BITMAPCACHE_ERROR_PDU           0x2C
#define PDUTYPE2_SET_KEYBOARD_IME_STATUS         0x2D
#define PDUTYPE2_OFFSCRCACHE_ERROR_PDU           0x2E
#define PDUTYPE2_SET_ERROR_INFO_PDU              0x2F
#define PDUTYPE2_DRAWNINEGRID_ERROR_PDU          0x30
#define PDUTYPE2_DRAWGDIPLUS_ERROR_PDU           0x31
#define PDUTYPE2_ARC_STATUS_PDU                  0x32
#define PDUTYPE2_STATUS_INFO_PDU                 0x36
#define PDUTYPE2_MONITOR_LAYOUT_PDU              0x37

// 2.2.8.1.1.1.2 Share Data Header (TS_SHAREDATAHEADER):
   struct dsd_shared_data_header {
       unsigned int umc_share_id;                   // shareId: Share identifier for the packet.
       // There is 1 byte of padding here
       unsigned char uchc_stream_id;                // streamId: The stream identifier for the packet.
       unsigned short int usc_uncompressed_length;  // uncompressedLength: The uncompressed length of the packet in bytes.
       unsigned char uchc_pdu_type_2;               // pduType2: The type of Data PDU.
       unsigned char uchc_compressed_type;          // compressedType: The compression type and flags specifying the data following the Share Data Header
       unsigned short int usc_compressed_length;    // compressedLength: The compressed length of the packet in bytes.
   };





struct dsd_rdp_client_1 {                   /* RDP client part         */
   struct dsd_rdp_co_client dsc_rdp_co_1;  /* RDP communication      */
   enum ied_fsfp_bl iec_fsfp_bl;            /* field position          */
   enum ied_frse_bl iec_frse_bl;            /* receive block from server */
   enum ied_frse_bl iec_frse_bl2;
   char *     achc_cert_key;                /* RSA key                 */
   int        imc_len_cert_key;             /* length RSA key          */
// char       chrc_cert_exp[4];             /* RSA exponent            */
   char       chrc_cert_exp[3];             /* RSA exponent            */
   int        imc_pos_inp_frame;            /* position in input frame */
   int        imc_no_cmd_frame;             /* number of commands in frame */
   int        imc_order_flags;              /* order flags of command  */
   union {
     int      imc_prot_1;                   /* for protocol decoding   */
     int      imc_prot_akku;                /* akkumulator of protocol decoding */
   };
   union {
     int      imc_prot_2;                   /* for protocol decoding   */
     int      imc_prot_count_in;            /* count input of protocol decoding */
   };
   union {
     int      imc_prot_3;                   /* for protocol decoding   */
     int      imc_prot_aux1;                /* auxiliary one of protocol decoding */
   };
   union {
     int      imc_prot_4;                   /* for protocol decoding   */
     int      imc_prot_save1;               /* save one of protocol decoding */
// to-do 13.01.13 KB - is this needed? or in imc_pos_inp_frame ???
     int      imc_prot_pdu_rem;             /* remaining data in PDU   */
   };
   union {
     int      imc_prot_5;                   /* for protocol decoding   */
     int      imc_prot_pdu_type;            /* PDU type                */
     int      imc_prot_save2;               /* save two of protocol decoding */
   };
   struct dsd_shared_data_header dsc_sdh;
   int        imc_prot_6;                   /* for protocol decoding   */
   int        imc_prot_7;                   /* for protocol decoding   */
   int        imc_prot_8;                   /* for protocol decoding   */
   int        imc_prot_chno;                /* for protocol decoding   */
   int        imc_prot_prfl;                /* primary order flags     */
   int        imc_cmp_dim_x;                /* compare dimension x pixels */
   int        imc_cmp_dim_y;                /* compare dimension y pixels */
   void *     ac_paint_buffer;              /* buffer to paint to      */
   char       *axxc_pibu_line;              /* pixel buffer line start */
   char       *axxc_pibu_cur;               /* pixel buffer current    */
   char       *axxc_pibu_end;               /* pixel buffer end        */
   BOOL       boc_fill9;                    /* last command was Fill 9 */
   unsigned short int xxc_mix;              /* Mix Value               */
/* initialize parameters at demand active PDU */
   short int  isrc_bitmap_data[ DEF_UPDATE_BITMAP_CO ];  /* number of short update bitmap */
/* 10.08.09 KB - is really needed ??? */
   unsigned char ucc_order_flags_1;         /* send order flags        */
   char *     achc_prot_1;                  /* for protocol decoding   */
// char *     achc_prot_2;                  /* for protocol decoding   */
   char *     achc_prot_2;                  /* for protocol decoding   */
   char *     achc_prot_3;                  /* for protocol decoding   */
#ifdef B060821
   char       chrc_prot_1[ 128 ];           /* for protocol decoding   */
#endif
   char       chrc_prot_1[ 4096 ];          /* for protocol decoding   */
//*IF DEF D$RDP$HOOK;
//*CEND;
// to-do 19.10.13 KB - is this needed?
     char     chrc_prot_2[ 128 ];           /* for protocol decoding   */
   char       chc_prot_rt02;                /* for protocol decoding   */
   char       chc_prot_rt03;                /* for protocol decoding   */
   char       chc_prot_r5_first;            /* for protocol decoding   */
   char       chc_prot_r5_pdu_type;         /* for protocol decoding   */
   char       chc_prot_r5_pdu_cofl;         /* for protocol decoding   */
   char       chc_prot_r5_pdu_ord_fl;       /* for protocol decoding   */
   unsigned char ucc_prot_r5_pdu_ord_prim;  /* primary order number    */
   char       chc_prot_r5_pdu_ord_bofl;     /* bounds flags            */
   char       chc_prot_r5_pdu_ord_type;     /* RDP 5 PDU order type    */
   unsigned char ucc_prot_r5_pdu_ord_width;  /* RDP 5 PDU order width  */
   unsigned char ucc_prot_r5_pdu_ord_height;  /* RDP 5 PDU order height */
// char       chc_prot_r5_pdu_ord_cache_ind;  /* RDP 5 PDU cache index */
/* following field no more needed? UUUU 24.08.06 KB */
   struct dsd_cache_1 *adsc_prot_cache_1;   /* cache of order          */
   void *     ac_redirect;                  /* memory for Standard Security Server Redirection PDU */
   unsigned int umc_vch_ulen;               /* virtual channel length uncompressed */
   char       chrc_vch_flags[4];            /* virtual channel flags   */
#ifdef TEMPSCR2                             /* 15.06.05 KB - send screen */
   int        imc_count_order;              /* count orders            */
#endif
#ifdef TRACEHL_BMP_060827
   int        imc_count_mbp;                /* count bitmaps           */
#endif
   int        imc_len_temp;                 /* length temporary buffer */
   void *     ac_temp_buffer;               /* temporary buffer        */
};


struct dsd_cache_1 {                        /* cache for pixels        */
   struct dsd_cache_1 *adsc_next;           /* next in chain           */
   int        inc_id;                       /* cache id                */
   int        inc_ind;                      /* cache index             */
};

struct dsd_pix_buf_1 {                      /* pixel buffer            */
   struct dsd_pix_buf_1 *adsc_next;         /* next in chain           */
   unsigned short int usc_ind;              /* index of pixel buffer   */
   unsigned short int usc_width;            /* width of buffer         */
   unsigned short int usc_height;           /* height of buffer        */
};

struct dsd_rdpa_f {                         /* RDP accelerator frame   */
   struct dsd_rdp_client_1 dsc_rdp_cl_1;    /* rdp client part         */
   char       chrc_server_random[32];       /* specify server-random   */
   void *     ac_screen_buffer;             /* screen buffer           */
   struct dsd_cache_1 *adsc_cache_1;        /* chain of caches         */
   struct dsd_call_rdptrac_1 dsc_rdptr1;    /* for RDP-Tracer          */
   struct dsd_stor_sdh_1 dsc_stor_sdh_1;    /* storage management      */
#ifdef HL_RDPACC_HELP_DEBUG
   BOOL       boc_help_debug_1;             /* stop debugger           */
#endif
#ifdef TEMPSCR1
   BOOL       boc_temp_scr_1;               /* screen buffer send      */
#endif
#ifdef TRACEHL_CL2SE_COM1                   /* 21.09.06 KB - client to server commands */
   int        inc_count_frse;               /* count from server       */
#endif
};

struct dsd_info_packet_fields {             /* fields of TS_INFO_PACKET */
   unsigned int umc_loinf_options;          /* Logon Info Options      */
   int        imc_len_domain;
   int        imc_len_username;
   int        imc_len_password;
   char       *achc_domain;
   char       *achc_username;
   char       *achc_password;
};

struct dsd_output_area_1 {                  /* output of subroutine    */
   char       *achc_lower;                  /* lower addr output area  */
   char       *achc_upper;                  /* higher addr output area */
   struct dsd_raord_scr *adsc_raord_scr;    /* chain of ra orders      */
   struct dsd_gather_i_1 **aadsc_gai1_out_to_server;  /* output data to server */
   struct dsd_se_co1 **aadsc_se_co1_chain;  /* chain commands from server */
   struct dsd_wt_record_1 **aadsc_wtr1_chain;  /* chain of WebTerm records */
};

static const unsigned char ucrs_crypt_ini_01[] = {  /* initialize crypto */
   0X41
};

static const unsigned char ucrs_crypt_ini_02[] = {  /* initialize crypto */
   0X42, 0X42
};

static const unsigned char ucrs_crypt_ini_03[] = {  /* initialize crypto */
   0X43, 0X43, 0X43
};

static const unsigned char ucrs_crypt_ini_04[] = {  /* initialize crypto */
   0X58
};

static const unsigned char ucrs_crypt_ini_05[] = {  /* initialize crypto */
   0X59, 0X59
};

static const unsigned char ucrs_crypt_ini_06[] = {  /* initialize crypto */
   0X5A, 0X5A, 0X5A
};


static const unsigned char ucrs_secl_01[] = {  /* send to client - first block */
   0X03, 0X00, 0X00, 0X0B, 0X06, 0XD0, 0X00, 0X00, 0X12, 0X34, 0X00
};

static const unsigned char ucrs_secl_02[] = {  /* send to client - first block */
   0X03, 0X00, 0X00, 0X13,
   0X0E, 0XD0, 0X00, 0X00, 0X12, 0X34, 0X00,
   0X02, 0X01, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00
};

static const unsigned char ucrs_sese_01[] = {  /* send to server - first bl */
   0X03, 0X00, 0X00, 0X13,                          // tpktHeader
   0X0E, 0XE0, 0X00, 0X00, 0X00, 0X00, 0X00,        // x224Crq
   // RDP_NEG_REQ
   0X01,                                            // TYPE_RDP_NEG_REQ
   0X00,                                            // flags
   0X08, 0X00,                                      // length
   0X00, 0X00, 0X00, 0X00                           // PROTOCOL_RDP
};


static const unsigned char ucrs_rec_se_01_cmp1[] = {  /* compare received from server first block */
   0XD0, 0X00, 0X00, 0X12, 0X34, 0X00
};

static const unsigned char ucrs_x224_mcs[] = {  /* X224 Data plus MCS  */
   0X02, 0XF0, 0X80, 0X7F, 0X65
};

static const unsigned char ucrs_x224_r05_errect[] = {  /* X224 Data MCS Errect Domain Request */
   0X03, 0X00, 0X00, 0X0C, 0X02, 0XF0, 0X80, 0X04
};

static const unsigned char ucrs_x224_errect_domain_pdu[] = {  /* X224 Data MCS Errect Domain Request */
   0X03, 0X00, 0X00, 0X0C, 0X02, 0XF0, 0X80, 0X04,
   0X01, 0X00, 0X01, 0X00,
   0X03, 0X00, 0X00, 0X08, 0X02, 0XF0, 0X80, 0X28
};

static const unsigned char ucrs_x224_r06_attuser[] = {  /* X224 Data MCS Attach User Request */
   0X03, 0X00, 0X00, 0X08, 0X02, 0XF0, 0X80, 0X28
};

static const unsigned char ucrs_x224_r07_aurep[] = {  /* X224 Data MCS Attach User Reply */
   0X03, 0X00, 0X00, 0X0B, 0X02, 0XF0, 0X80, 0X2E
};

static const unsigned char ucrs_x224_cjreq_1[] = {  /* X224 Data MCS Channel Join Request */
   0X03, 0X00, 0X00, 0X0C, 0X02, 0XF0, 0X80, 0X38
};

static const unsigned char ucrs_x224_cjresp_1[] = {  /* X224 Data MCS Channel Join Response */
   0X03, 0X00, 0X00, 0X0F, 0X02, 0XF0, 0X80, 0X3E
};

static const unsigned char ucrs_lic_err_hash[] = {
  DEF_CONST_RDP_03, 0X00, 0X00, 0X24, 0X20, 0XF0, 0X80, 0X64,
  0XFF, 0XFF, 0XFF, 0XFF, 0X70, 0X14, 0X80, 0X00, 0X00, 0X00,
  0XFF, 0X03, 0X10, 0X00, 0X03, 0X00, 0X00, 0X00,
  0X01, 0X00, 0X00, 0X00, 0X04, 0X00, 0X00, 0X00
};

static const unsigned char ucrs_lic_bef_cert[] = {
  0X08, 0X00, 0X00, 0X00,  /* length of following string, within Product Info */
  0X41, 0X00, 0X30, 0X00, 0X32, 0X00, 0X00, 0X00,  /* "A02", MS-RDPELE 2.2.2.1.1 */
  0X0D, 0X00, 0X04, 0X00,  /* Key Exchange List: blobtype and length */
  0X01, 0X00, 0X00, 0X00,  /* called KEY_EXCHANGE_ALG_RSA in MS-RDPELE 2.2.2.1 */
  0X03, 0X00               /* Blobtype of Server Certificate */
};

static const unsigned char ucrs_ks_01[] = {
   0XD1, 0X26, 0X9E
};

static const unsigned char ucrs_x224_p01[] = {  /* X224 Data part 01   */
   0X02, 0XF0, 0X80
};

static const unsigned char ucrs_x224_p02[] = {  /* X224 record 2 part 02 */
   0X04, 0X01, 0X01, 0X04, 0X01,
   0X01, 0X01, 0X01, 0XFF, 0X30, 0X19, 0X02, 0X01,
   0X22, 0X02, 0X01, 0X02, 0X02, 0X01, 0X00, 0X02,
   0X01, 0X01, 0X02, 0X01, 0X00, 0X02, 0X01, 0X01,
   0X02, 0X02, 0XFF, 0XFF, 0X02, 0X01, 0X02, 0X30,
   0X19, 0X02, 0X01, 0X01, 0X02, 0X01, 0X01, 0X02,
   0X01, 0X01, 0X02, 0X01, 0X01, 0X02, 0X01, 0X00,
   0X02, 0X01, 0X01, 0X02, 0X02, 0X04, 0X20, 0X02,
   0X01, 0X02, 0X30, 0X1C, 0X02, 0X02, 0XFF, 0XFF,
   0X02, 0X02, 0XFC, 0X17, 0X02, 0X02, 0XFF, 0XFF,
   0X02, 0X01, 0X01, 0X02, 0X01, 0X00, 0X02, 0X01,
   0X01, 0X02, 0X02, 0XFF, 0XFF, 0X02, 0X01, 0X02
};

static const unsigned char ucrs_x224_p03[] = {  /* X224 record 2 part 03 */
   0X00, 0X05, 0X00, 0X14, 0X7C, 0X00, 0X01
};

static const unsigned char ucrs_x224_p04[] = {  /* X224 record 2 part 04 */
   0X00, 0X08, 0X00, 0X10, 0X00, 0X01, 0XC0, 0X00,
   0X44, 0X75, 0X63, 0X61
};

static const unsigned char ucrs_x224_p05[] = {  /* X224 record 2 part 05 */
   0X01, 0XC0, 0XD8, 0X00, 0X04, 0X00, 0X08, 0X00
};

/* Bitmap Size Tag Present + SAS Sequence                              */
static const unsigned char ucrs_x224_p06[] = {  /* X224 record 2 part 06 */
   0X01, 0XCA, 0X03, 0XAA,
};

static const unsigned char ucrs_x224_buildno[] = {  /* X224 record 2 build number */
   0XB1, 0X1D, 0X00, 0X00
};
static const unsigned char ucrs_logon_info_c1[] = {  /* Constant Logon Info */
   0X00, 0X00, 0X00, 0X00
};

static const unsigned char ucrs_capabilities_resp[] = {  /* X224 send capabilities */
   0X06, 0X00,
   0XF1, 0X01,                              /* length of combined capabilities */
   0X4D, 0X53, 0X54, 0X53, 0X43, 0X00,      /* MSTSC                   */
   0X15, 0X00,                              /* number of capabilities  */
   0X00, 0X00,                              /* padding                 */
   CAPSTYPE_GENERAL, 0X00,
   0X18, 0X00,                              /* length                  */
   0X01, 0X00, 0X03, 0X00, 0X00, 0X02, 0X00, 0X00,
   0X00, 0X00, 0X1D, 0X04, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00,
   CAPSTYPE_BITMAP, 0X00,
   0X1C, 0X00,                              /* length                  */
   0X10, 0X00, 0X01, 0X00, 0X01, 0X00, 0X01, 0X00, // preferredBitsPerPixel(2), receive1BitPerPixel(2), receive4BitsPerPixel(2), receive8BitsPerPixel(2) 
   0X80, 0X02, 0XE0, 0X01, 0X00, 0X00, 0X01, 0X00, // desktopWidth(2), desktopHeight(2), pad2octets(2), desktopResizeFlag(2),
   0X01, 0X00, 0X00, 0X08, 0X01, 0X00, 0X00, 0X00, // bitmapCompressionFlag(2), highColorFlags(1), drawingFlags(1), multipleRectangleSupport(2), pad2octetsB(2)
   CAPSTYPE_ORDER, 0X00,
   0X58, 0X00,                              /* length                  */
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, // terminalDescriptor (0-7)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, // terminalDescriptor (8-15)
   0X00, 0X00, 0X00, 0X00, 0X01, 0X00, 0X14, 0X00, // pad4octetsA(4), desktopSaveXGranularity(2), desktopSaveYGranularity(2)
   0X00, 0X00, 0X01, 0X00, 0X00, 0X00, 0XAA, 0X00, // pad2octetsA(2), maximumOrderLevel(2), numberFonts(2), orderFlags(2)
   0X01, 0X01, 0X01, 0X01, 0X01, 0X00, 0X00, 0X01, // Order support 0-7
   0X01, 0X01, 0X00, 0X01, 0X00, 0X00, 0X00, 0X01, // Order support 8-15
   0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X01, 0X00, // Order support 16-23
   0X01, 0X01, 0X01, 0X01, 0X00, 0X00, 0X00, 0X00, // Order support 24-31
   0XA1, 0X06, 0X04, 0X00, 0X00, 0X00, 0X00, 0X00, // textFlags(2), orderSupportExFlags(2), pad4octetsB(4)
   0X00, 0X84, 0X03, 0X00, 0X00, 0X00, 0X00, 0X00, // desktopSaveSize(4), pad2octetsC(2), pad2octetsD(2)
   0XE4, 0X04, 0X00, 0X00,                         // textANSICodePage, pad2octetsE
   CAPSTYPE_BITMAPCACHE_REV2, 0X00,
   0X28, 0X00,                              /* length                  */
   0X02, 0X00, 0X00, 0X03, 0X78, 0X00, 0X00, 0X00, // CacheFlags(2), pad2(1), NumCellCaches(1), BitmapCache0CellInfo(4)
   0X78, 0X00, 0X00, 0X00, 0X51, 0X01, 0X00, 0X00, // BitmapCache1CellInfo(4), BitmapCache2CellInfo(4)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, // BitmapCache3CellInfo(4), BitmapCache4CellInfo(4)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, // Pad3 (12)
   0X00, 0X00, 0X00, 0X00,
   CAPSTYPE_COLORCACHE, 0X00,               /* 10 = 0X0A               */
   0X08, 0X00,                              /* length                  */
   0X06, 0X00, 0X00, 0X00,
   CAPSTYPE_ACTIVATION, 0X00,               /* 7 = 0X07                */
   0X0C, 0X00,                              /* length                  */
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   CAPSTYPE_CONTROL, 0X00,                  /* 5 = 0X05                */
   0X0C, 0X00,                              /* length                  */
   0X00, 0X00, 0X00, 0X00, 0X02, 0X00, 0X02, 0X00,
   CAPSTYPE_POINTER, 0X00,                  /* 8 = 0X08                */
   0X0A, 0X00,                              /* length                  */
   0X01, 0X00, 0X14, 0X00, 0X15, 0X00,
   CAPSTYPE_SHARE, 0X00,                    /* 9 = 0X09                */
   0X08, 0X00,                              /* length                  */
   0X00, 0X00, 0X00, 0X00,
   CAPSTYPE_INPUT, 0X00,                    /* 13 = 0X0D               */
   0X58, 0X00,                              /* length                  */
   0X91, 0X00, 0X20, 0X00, 0X07, 0X04, 0X00, 0X00,
   0X04, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X0C, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00,
   CAPSTYPE_SOUND, 0X00,                    /* 12 = 0X0C               */
   0X08, 0X00,                              /* length                  */
   0X01, 0X00, 0X00, 0X00,
   CAPSTYPE_FONT, 0X00,                     /* 14 = 0X0E               */
   0X08, 0X00,                              /* length                  */
   0X01, 0X00, 0X00, 0X00,
   CAPSTYPE_GLYPHCACHE, 0X00,               /* 16 = 0X10               */
   0X34, 0X00,                              /* length                  */
   0XFE, 0X00, 0X04, 0X00, 0XFE, 0X00, 0X04, 0X00,
   0XFE, 0X00, 0X08, 0X00, 0XFE, 0X00, 0X08, 0X00,
   0XFE, 0X00, 0X10, 0X00, 0XFE, 0X00, 0X20, 0X00,
   0XFE, 0X00, 0X40, 0X00, 0XFE, 0X00, 0X80, 0X00,
   0XFE, 0X00, 0X00, 0X01, 0X40, 0X00, 0X00, 0X08,
   0X00, 0X01, 0X00, 0X01, 0X03, 0X00, 0X00, 0X00,
   CAPSTYPE_BRUSH, 0X00,                    /* 15 = 0X0F               */
   0X08, 0X00,                              /* length                  */
   0X01, 0X00, 0X00, 0X00,
   CAPSTYPE_OFFSCREENCACHE, 0X00,           /* 17 = 0X11               */
   0X0C, 0X00,                              /* length                  */
   0X01, 0X00, 0X00, 0X00, 0X00, 0X14, 0X64, 0X00,
   CAPSTYPE_VIRTUALCHANNEL, 0X00,           /* 20 = 0X14               */
   0X08, 0X00,                              /* length                  */
   0X01, 0X00, 0X00, 0X00,
   CAPSTYPE_DRAWNINEGRIDCACHE, 0X00,        /* 21 = 0X15               */
   0X0C, 0X00,                              /* length                  */
   0X02, 0X00, 0X00, 0X00, 0X00, 0X0A, 0X00, 0X01,
   CAPSTYPE_RAIL, 0X00,                     /* 23 = 0X17               */
   0X08, 0X00,                              /* length                  */
   0X1F, 0X00, 0X00, 0X00,
   CAPSTYPE_WINDOW, 0X00,                   /* 24 = 0X18               */
   0X0B, 0X00,                              /* length                  */
   0X02, 0X00, 0X00, 0X00, 0X03, 0X0C, 0X00,
   CAPSTYPE_DRAWGDIPLUS, 0X00,              /* 22 = 0X16               */
   0X28, 0X00,                              /* length                  */
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X00, 0X00,
   CAPSETTYPE_MULTIFRAGMENTUPDATE, 0X00,    /* 26 = 0X1A               */
   0X08, 0X00,                              /* length                  */
   0X00, 0X00, 0X00, 0X00,
};

static const unsigned char ucrs_share_id[] = {  /* shareId             */
   0XEA, 0X03, 0X01, 0X00
};

static const unsigned char ucrs_pdu_header_01[] = {
  DEF_CONST_RDP_03, 0, 0, 0XFF,
  0X02, 0XF0, 0X80, 0X64, 0XFF, 0XFF, 0XFF, 0XFF,
  0X70, 0XFF, 0X08, 0X00, 0X00, 0X00
};

static const unsigned char ucrs_ts_synchronize_pdu[] = {
   0X00, 0X01,
   /* PDUTYPE2_SYNCHRONIZE (31)                                        */
   0X08, 0X00, 0X1F, 0X00, 0X00, 0X00, 0X01, 0X00,
   0XEA, 0X03
};

static const unsigned char ucrs_ctrl_pdu_data_cooperate[] = {  /* controlPduData */
   /* CTRLACTION_COOPERATE 0x0004                                      */
   0X00, 0X01,
   /* PDUTYPE2_CONTROL (20).                                           */
   0X0C, 0X00, 0X14, 0X00, 0X00, 0X00, 0X04, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00
};

static const unsigned char ucrs_ctrl_pdu_data_request_control[] = {  /* controlPduData */
   /* CTRLACTION_REQUEST_CONTROL (0x0001)                              */
   0X00, 0X01,
   /* PDUTYPE2_CONTROL (20).                                           */
   0X0C, 0X00, 0X14, 0X00, 0X00, 0X00, 0X01, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00
};

static const unsigned char ucrs_font_list_pdu[] = {
   0X00, 0X01,
   /* PDUTYPE2_FONTLIST (39).                                          */
   0X00, 0X00, 0X27, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00, 0X00, 0X03, 0X00, 0X32, 0X00
};

static const unsigned char ucrs_x224_encry[] = {  /* X224 record 2 encryption */
   0X01, 0XCA, 0X01, 0X00, 0X00, 0X00, 0X00, 0X00,  // postBeta2ColorDepth(2), clientProductId(2), serialNumber(4)
   0X10, 0X00, 0X07, 0X00, 0X01, 0X01, 0X00, 0X00,  // highColorDepth(2), supportedColorDepths(2), earlyCapabilityFlags(2), clientDigProductId(2)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  // clientDigProductId(8)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  // clientDigProductId(8)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  // clientDigProductId(8)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  // clientDigProductId(8)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  // clientDigProductId(8)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  // clientDigProductId(8)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  // clientDigProductId(8)
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  // clientDigProductId(6), connectionType(1), pad1octet(1)
   0X00, 0X00, 0X00, 0X00,                          // serverSelectedProtocol(4) -> RDP7
   /* 0XC004 CS_CLUSTER                                                */
   0X04, 0XC0, 0X0C, 0X00,                          // CS_CLUSTER(2), length(2)
   0X0D, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,  // Flags(4), RedirectedSessionID(4)
   /* 0XC002 CS_SECURITY                                               */
   0X02, 0XC0, 0X0C, 0X00,                          // CS_SECURITY(2), length(2)
   0X1B, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00   // encryptionMethods(4), extEncryptionMethods(4)
};
#ifdef B060907
static const unsigned char ucrs_desktop_tag[] = {  /* Desktop Tag      */
   0X01, 0XC0
};
#endif

#ifndef B060907_XXX
static const unsigned char ucrs_r02c01[] = {  /* record 2 const 1      */
   0X00, 0X08, 0X00
};
#else
static const unsigned char ucrs_r02c01[] = {  /* record 2 const 1      */
   0X04, 0X00, 0X08, 0X00
};
#endif

static const unsigned char ucrs_bitmap_tag[] = {  /* Bitmap Size Tag   */
   0X01, 0XCA
};

static const unsigned char ucrs_r02c02[] = {  /* record 2 const 2      */
   0X01, 0XCA, 0X03, 0XAA
};

#ifdef B060907
static const unsigned char ucrs_virtch_tag[] = {  /* Virtual Channel Tag */
   0X03, 0XC0
};
#endif

static const unsigned char ucrs_source_desc[] = {  /* Source Descriptor */
   0X52, 0X44, 0X50, 0X00                   /* RDP zero-terminated */
};

static const unsigned char ucrs_asn1_prot_id[] = {  /* ASN-1 protocol Id */
   0X00, 0X05, 0X00, 0X14, 0X7C, 0X00, 0X01, 0X2A,
   0X14, 0X76, 0X0A, 0X01, 0X01, 0X00, 0X01, 0XC0,
   0X00, 0X4D, 0X63, 0X44, 0X6E
};

static const unsigned char ucrs_r04_asn1_1[] = {  /* ASN-1 variables   */
   0X0A, 0X01, 0X00,
   0X02, 0X01, 0X00,
   0X30, 0X1A, 0X02, 0X01, 0X22, 0X02, 0X01, 0X03,
   0X02, 0X01, 0X00, 0X02, 0X01, 0X01, 0X02, 0X01,
   0X00, 0X02, 0X01, 0X01, 0X02, 0X03, 0X00, 0XFF,
   0XF8, 0X02, 0X01, 0X02
};

static const unsigned char ucrs_r04_vers_f[] = {  /* version field     */
   0X01, 0X0C, 0X0C, 0X00, 0X04, 0X00, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00
};


static const unsigned char ucrs_rdp_pre_cert[] = {
   0X02, 0X00, 0X00, 0X80
};


static const char chrs_zeroes[] = { 0, 0, 0, 0 };  /* zeroes for padding */

#ifdef TRACEHL_COM1
static int ims_no_order = 0;                /* count orders            */
#endif

static BOOL m_check_input_complete( struct dsd_gather_i_1 *, char *, int );
static BOOL m_copy_input_gai1( char *, struct dsd_gather_i_1 *, char *, int );
static void m_gen_keys( struct dsd_call_wt_rdp_client_1 *, char *, struct dsd_rdp_co_client *, char * );
static BOOL m_prepare_keys( struct dsd_call_wt_rdp_client_1 *, struct dsd_rdp_co_client * );
static void m_update_keys( struct dsd_rdp_co_client *, struct dsd_rdp_encry *, char * );
static void m_gen_lic_keys( struct dsd_rdp_lic_d *, char * );
static BOOL m_make_screen( struct dsd_call_wt_rdp_client_1 *, char * );
static int m_decode_ineta( struct dsd_call_wt_rdp_client_1 *, char *, char *, int );
static BOOL m_decode_credentials( struct dsd_info_packet_fields *, void * );
static BOOL m_decomp_01_s( struct dsd_call_wt_rdp_client_1 *, struct dsd_cache_1 *, char *, int );
static BOOL m_send_cl2se_rdp5( struct dsd_call_wt_rdp_client_1 *,
                               struct dsd_output_area_1 *, char *, int, int );
static BOOL m_send_cl2se_conf_act_pdu( struct dsd_call_wt_rdp_client_1 *, struct dsd_output_area_1 * );
static BOOL m_send_cl2se_license( struct dsd_call_wt_rdp_client_1 *, struct dsd_output_area_1 *,
                                  struct dsd_cc_pass_license *,
                                  char *, int, char *, int );
static BOOL m_send_vch_tose( struct dsd_call_wt_rdp_client_1 *,
                             struct dsd_output_area_1 *,
                             struct dsd_rdp_vch_io *,
                             char * );
static BOOL m_send_mcs_msgchannel_tose( struct dsd_call_wt_rdp_client_1 *,
                             struct dsd_output_area_1 *,
                             struct dsd_rdp_mcs_msgchannel_io *,
                             char * );
static inline int m_pos_array_glyph( int *, int, int );
static inline short int m_get_le2( char * );
static inline int m_get_le4( char * );
static inline void m_put_le2( char *, int );
static inline void m_put_le4( char *, int );
static inline void m_put_be2( char *, int );
#ifdef TRACEHL_BMP_060827
#ifndef D_CONSOLE_OUT
#define D_CONSOLE_OUT
#endif
#endif
#ifdef TRACEHL1
#ifndef D_CONSOLE_OUT
#define D_CONSOLE_OUT
#endif
#endif
#ifdef D_CONSOLE_OUT
static void m_console_out( char *achp_buff, int implength );
#else
#endif
static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static int m_sdh_printf( struct dsd_call_wt_rdp_client_1 *, const char *, ... );
static void m_sdh_console_out( struct dsd_call_wt_rdp_client_1 *, char *achp_buff, int implength );
static const char * m_ret_t_ied_fsfp_bl( ied_fsfp_bl );
static const char * m_ret_t_ied_frse_bl( ied_frse_bl );

static BOOL m_parse_server_redirection_packet(char* achp_curpos, struct dsd_se_switch_server* adsp_se_switch_server, unsigned int ump_max_len);
static BOOL m_ensure_wa_size( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1, struct dsd_output_area_1 * ADSL_OA1, size_t szp_size) {
    if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) >= szp_size)   
        return TRUE;
    struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
    memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
    dsl_aux_get_workarea.imc_len_work_area = szp_size;
    BOOL bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
    if (bol1 == FALSE) {       /* aux returned error      */
        return FALSE;
    }
    if(dsl_aux_get_workarea.imc_len_work_area < szp_size)
        return FALSE;
    ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
    ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
    return TRUE;
}
//----- 10.07.09
/* Predefined hatch brush patterns. */
static const unsigned char ucrs_brush_01[ 6 * 8 ] = {
   /* LSB least significant bit is for leftmost pixel                  */
   /* HS_HORIZONTAL                                                    */
   0XFF, 0XFF, 0XFF, 0XFF, 0X00, 0XFF, 0XFF, 0XFF,
   /* HS_VERTICAL                                                      */
   0XEF, 0XEF, 0XEF, 0XEF, 0XEF, 0XEF, 0XEF, 0XEF,
   /* HS_FDIAGONAL                                                     */
   0X7F, 0XBF, 0XDF, 0XEF, 0XF7, 0XFB, 0XFD, 0XFE,
   /* HS_BDIAGONAL                                                     */
   0XFE, 0XFD, 0XFB, 0XF7, 0XEF, 0XDF, 0XBF, 0X7F,
   /* HS_CROSS                                                         */
   0XEF, 0XEF, 0XEF, 0XEF, 0X00, 0XEF, 0XEF, 0XEF,
   /* HS_DIAGCROSS                                                     */
   0X7E, 0XBD, 0XDB, 0XE7, 0XE7, 0XDB, 0XBD, 0X7E
};
//----- 10.07.09
static const unsigned char ucrs_invert_bits[ 256 ] = {
   0,   128, 64,  192, 32,  160, 96,  224,
   16,  144, 80,  208, 48,  176, 112, 240,
   8,   136, 72,  200, 40,  168, 104, 232,
   24,  152, 88,  216, 56,  184, 120, 248,
   4,   132, 68,  196, 36,  164, 100, 228,
   20,  148, 84,  212, 52,  180, 116, 244,
   12,  140, 76,  204, 44,  172, 108, 236,
   28,  156, 92,  220, 60,  188, 124, 252,
   2,   130, 66,  194, 34,  162, 98,  226,
   18,  146, 82,  210, 50,  178, 114, 242,
   10,  138, 74,  202, 42,  170, 106, 234,
   26,  154, 90,  218, 58,  186, 122, 250,
   6,   134, 70,  198, 38,  166, 102, 230,
   22,  150, 86,  214, 54,  182, 118, 246,
   14,  142, 78,  206, 46,  174, 110, 238,
   30,  158, 94,  222, 62,  190, 126, 254,
   1,   129, 65,  193, 33,  161, 97,  225,
   17,  145, 81,  209, 49,  177, 113, 241,
   9,   137, 73,  201, 41,  169, 105, 233,
   25,  153, 89,  217, 57,  185, 121, 249,
   5,   133, 69,  197, 37,  165, 101, 229,
   21,  149, 85,  213, 53,  181, 117, 245,
   13,  141, 77,  205, 45,  173, 109, 237,
   29,  157, 93,  221, 61,  189, 125, 253,
   3,   131, 67,  195, 35,  163, 99,  227,
   19,  147, 83,  211, 51,  179, 115, 243,
   11,  139, 75,  203, 43,  171, 107, 235,
   27,  155, 91,  219, 59,  187, 123, 251,
   7,   135, 71,  199, 39,  167, 103, 231,
   23,  151, 87,  215, 55,  183, 119, 247,
   15,  143, 79,  207, 47,  175, 111, 239,
   31,  159, 95,  223, 63,  191, 127, 255
};

/** subroutine to process the copy library function                    */
extern "C" void m_wt_rdp_client_1( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1 ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variables */
   int        iml_length;                   /* working variable length */
   int        iml_rec;                      /* data received remaining */
   int        iml_line_no;                  /* line number for errors  */
   int        iml_source_no;                /* source line no for errors */
   char       chl_w1;                       /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
   char       *achl3, *achl4;               /* working variables       */
   char       *achl5;                       /* working variable        */
   BOOL       bol_compressed;               /* save compressed         */
   BOOL       bol_encrypted;                /* packet is encrypted     */
   struct dsd_output_area_1 dsl_output_area_1;  /* output of subroutine */
   struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_inp_w2;  /* input data             */
// struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
   struct dsd_gather_i_1 dsl_gai1_comp_data;  /* compressed data       */
   struct dsd_gather_i_1 *adsl_gai1_inp_save_compr;  /* save current gather input */
   int        iml_compr_len;                /* length compressed       */
   int        iml_compr_inp;                /* input to compression    */
   struct dsd_gather_i_1 **aadsl_gai1_ch;   /* create chain gather data */
   char       *achl_out_1;                  /* output-area             */
   int        iml_out_len;                  /* length output           */
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
   struct dsd_gather_i_1 *adsl_gai1_out_save;  /* output data          */
   struct dsd_bmp_cache_b_1 *adsl_bmpc_b_1;  /* Bitmap Cache Buffer    */
   struct dsd_cc_co1 *adsl_cc_co1_w1;       /* client commands, working variable */
   struct dsd_se_co1 *adsl_se_co1_w1;       /* command from server     */
   struct dsd_se_co1 *adsl_se_co1_last;     /* command from server     */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* chain of data           */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* chain of data           */
/* to-do 17.02.15 KB - other solution needed */
// struct dsd_gather_i_1 dsl_gai1_start_rec;  /* start of record       */
   char       chrl_work_trace[ 256 ];       /* work area trace         */
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_rdp_server_1 *D_ADSL_RSE1;
   struct dsd_rdp_client_1 *D_ADSL_RCL1;
   struct dsd_rdp_co_client *D_ADSL_RCO1;  /* RDP communication client */
   struct dsd_output_area_1 *ADSL_OA1;
#endif
   char       *achl_inp_start;              /* start of input area     */
   char       chrl_work_1[ D_MAX_CRYPT_LEN ];  /* work area            */
   char       chrl_work_2[ D_STACK_WORKAREA_SIZE ];         /* work area               */

#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_info_packet_fields *ADSL_IPF_G;
#endif
   char* achl_rdp_neg_req;
#ifdef D_FOR_TRACE1                         /* 31.05.05 KB - help in tracing */
   iml1 = 0;
#endif                                      /* 31.05.05 KB - help in tracing */
   iml_line_no = 0;                         /* line number for errors  */
   achl_out_1 = NULL;
   adsl_gai1_out_save = NULL;               /* clear output data       */
#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#define ADSL_OA1 (&dsl_output_area_1)
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
   ADSL_OA1 = &dsl_output_area_1;
#endif
   memset( &dsl_output_area_1, 0, sizeof(dsl_output_area_1) );
#ifdef HL_RDPACC_HELP_DEBUG
   if (adsp_hl_clib_1->inc_func != DEF_IFUNC_START) {
     if (ADSL_RDPA_F) {                     /* memory defined          */
       if (ADSL_RDPA_F->boc_help_debug_1) {  /* stop debugger          */
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_hlclib01() called boc_help_debug_1 set",
                       __LINE__, 9745 );
         int inh1 = 0;
         inh1++;
       }
     }
   }
#endif
   iml_line_no = 0;                         /* line number for errors  */
   iml_source_no = 0;                       /* source line no for errors */
   switch (adsp_hl_clib_1->inc_func) {
     case DEF_IFUNC_START:
       goto pfsta00;                        /* start communication     */
     case DEF_IFUNC_REFLECT:
       goto pfrse00;                        /* from server             */
     case DEF_IFUNC_CLOSE:
       if (adsp_hl_clib_1->ac_ext == NULL) return;
       goto p_cleanup_00;                   /* do cleanup now          */
     default:
       m_sdh_printf( adsp_hl_clib_1, "xlrdpa1-l%05d-W m_hlclib01() called inc_func=%d - value invalid",
                     __LINE__, adsp_hl_clib_1->inc_func );
       return;
   }

   pfsta00:                                 /* start communication     */
#ifdef D_FFLUSH                             /* 30.05.05 KB - flush stdout */
   fflush( stdout );
#endif                                      /* 30.05.05 KB - flush stdout */
   bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                      DEF_AUX_MEMGET,
                                      &adsp_hl_clib_1->ac_ext,
                                      sizeof(struct dsd_rdpa_f) );
   if (bol1 == FALSE) {                     /* aux returned error      */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
     return;
   }
#ifdef HL_RDPACC_HELP_DEBUG
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
   memset( ADSL_RDPA_F, 0, sizeof(struct dsd_rdpa_f) );
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   ADSL_RDPA_F->dsc_stor_sdh_1.imc_stor_size = D_AUX_STOR_SIZE;  /* size of storage element */
   m_aux_stor_start( &ADSL_RDPA_F->dsc_stor_sdh_1 );
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_cont = D_DISPLAY_CHANNEL + 1;  /* channel number control */
   adsp_hl_clib_1->adsc_rdp_co = &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1;  /* RDP communication */
   ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl = ied_frse_start;  /* receive block from client */
   ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl = ied_fsfp_invalid;  /* invalid data received */
   /* see 2.2.2.2.1.1.2 Primary Drawing Order (PRIMARY_DRAWING_ORDER)  */
   ADSL_RDPA_F->dsc_rdp_cl_1.ucc_prot_r5_pdu_ord_prim = 0X01;
// ADSL_RDPA_F->dsc_rdp_cl_1.imc_pos_inp_frame = 0;  /* start of frame */
// ADSL_RDPA_F->iec_frcl_bl = ied_frcl_start;  /* receive block from client */
// ADSL_RDPA_F->inc_send_server_len = 0;    /* send nothing to client  */
   return;

   pfrse00:                                 /* from server - to client */
#ifndef HL_RDPACC_HELP_DEBUG
#define D_ADSL_RCL1 (&ADSL_RDPA_F->dsc_rdp_cl_1)
#define D_ADSL_RCO1 (&D_ADSL_RCL1->dsc_rdp_co_1)
#else
// ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
   D_ADSL_RCL1 = &ADSL_RDPA_F->dsc_rdp_cl_1;
   D_ADSL_RCO1 = &D_ADSL_RCL1->dsc_rdp_co_1;
#endif
   /* prepare Trace-Area                                               */
   ADSL_RDPA_F->dsc_rdptr1.adsc_hl_clib_1 = adsp_hl_clib_1;
   ADSL_RDPA_F->dsc_rdptr1.imc_trace_level = adsp_hl_clib_1->imc_trace_level;  /* WSP trace level */
   ADSL_RDPA_F->dsc_rdptr1.imc_sno = adsp_hl_clib_1->imc_sno;  /* session number */
// to-do 20.04.12 KB - afterwards again
   ADSL_OA1->aadsc_gai1_out_to_server = &adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   ADSL_OA1->aadsc_se_co1_chain = &adsp_hl_clib_1->adsc_se_co1_ch;  /* chain commands from server */
   ADSL_OA1->aadsc_wtr1_chain = &adsp_hl_clib_1->adsc_wtr1_out;  /* chain of WebTerm records */
   /* prepare area to send to server                                   */
   ADSL_OA1->achc_lower = adsp_hl_clib_1->achc_work_area;  /* addr work-area */
   ADSL_OA1->achc_upper = ADSL_OA1->achc_lower + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   if (adsp_hl_clib_1->adsc_gather_i_1_in == NULL) goto pfrse80;
   ADSL_OA1->aadsc_gai1_out_to_server = &adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   ADSL_OA1->aadsc_se_co1_chain = &adsp_hl_clib_1->adsc_se_co1_ch;  /* chain commands from server */
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;

   ADSL_OA1->adsc_raord_scr = NULL;         /* chain of ra orders      */

   memset( &dsl_gai1_comp_data, 0, sizeof(struct dsd_gather_i_1) );  /* compressed data */
   achl_inp_start = adsl_gai1_inp_1->achc_ginp_cur;  /* start of input area */

   /* loop to process the input data                                   */
   pfrse20:                                 /* process next byte input */
   if (adsl_gai1_inp_1) {                   /* more gather input       */
     iml_rec = adsl_gai1_inp_1->achc_ginp_end
                 - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml_rec > 0) {                     /* data to process         */
       goto pfrse24;                        /* data to process found   */
     }
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     if (adsl_gai1_inp_1) {                 /* more data to follow     */
       achl_inp_start = adsl_gai1_inp_1->achc_ginp_cur;  /* start of input area */
       goto pfrse20;                        /* check if more input     */
     }
   }
   if (dsl_gai1_comp_data.achc_ginp_cur) {  /* decompressed data       */
     adsl_gai1_inp_1 = adsl_gai1_inp_save_compr;  /* restore current gather input */
     dsl_gai1_comp_data.achc_ginp_cur = NULL;  /* no more in decompressed data */
     achl_inp_start = adsl_gai1_inp_1->achc_ginp_cur;  /* start of input area */
     goto pfrse20;                          /* check if more input     */
   }
#ifdef D_FFLUSH                             /* 30.05.05 KB - flush stdout */
   fflush( stdout );
#endif                                      /* 30.05.05 KB - flush stdout */
//   goto pfrse60;
//   return;
//#ifdef TRACEHL1
#ifdef TEMPSCR2                             /* 15.06.05 KB - send screen */
   ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imc_s_coldep = 16;
#ifdef OLD01
   if (D_ADSL_RCL1->imc_count_order >= 1244) {
#else
   if (D_ADSL_RCL1->imc_count_order >= 1243) {
#endif
     printf( "l%05d s%05d send screen now\n",
             __LINE__, 10285 );
     memset( &dsl_sc_draw_sc, 0, sizeof(struct dsd_sc_draw_sc) );  /* draw on screen */
     dsl_sc_draw_sc.imc_left = 0;
     dsl_sc_draw_sc.imc_top = 0;
     dsl_sc_draw_sc.imc_right = D_ADSL_RCO1->imc_dim_x;
     dsl_sc_draw_sc.imc_bottom = D_ADSL_RCO1->imc_dim_y;
     if ((ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.umc_loinf_options & D_LOINFO_COMPR_ENA) == 0) {  /* compression not enabled */
       m_send_draw_sc_s_normal( adsp_hl_clib_1, ADSL_OA1, &dsl_sc_draw_sc, chrl_work_2 );
     } else {                             /* compression enabled     */
       bol1 = m_send_draw_sc_s_compr( adsp_hl_clib_1, ADSL_OA1, &dsl_sc_draw_sc, chrl_work_2 );
       if (bol1 == FALSE) goto p_cleanup_00;  /* do cleanup now        */
     }
   }
#endif /* TEMPSCR2                          15.06.05 KB - send screen  */
//#endif
   goto pfrse80;                            /* search what to send     */

   pfrse24:                                 /* data to process found   */
   if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
     ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
       = ied_trc_se2cl_msg;                 /* server to client message */
     ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = NULL;
     ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = 0;  /* length of record */
     ADSL_RDPA_F->dsc_rdptr1.achc_trace_input = chrl_work_trace;  /* work area trace */
     sprintf( chrl_work_trace, "se2cl l%05d s%05d process input iec_frse_bl=%d %s + iec_fsfp_bl=%d %s addr=%p pos=%04X cont=%02X.",
              __LINE__, 10339,
              ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl,
              m_ret_t_ied_frse_bl( ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl ),
              ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl,
              m_ret_t_ied_fsfp_bl( ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl ),
              adsl_gai1_inp_1->achc_ginp_cur,
              adsl_gai1_inp_1->achc_ginp_cur - achl_inp_start,
              *((unsigned char *) adsl_gai1_inp_1->achc_ginp_cur) );
     m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
   }
   switch (D_ADSL_RCL1->iec_fsfp_bl) {      /* field position in rec   */
     case ied_fsfp_invalid:                 /* invalid data received   */
       M_ERROR_FRSE_ILLOGIC                 /* program illogic         */
     case ied_fsfp_constant:                /* compare with constant   */
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_start:
           achl1 = (char *) ucrs_rec_se_01_cmp1;  /* compare received from server first block */
           iml1 = sizeof(ucrs_rec_se_01_cmp1);
           break;
         case ied_frse_r04_asn1_4:          /* block 4 ASN-1 field 4   */
           achl1 = (char *) ucrs_asn1_prot_id;
           iml1 = sizeof(ucrs_asn1_prot_id);
           break;
#ifdef XYZ1
         case ied_frse_r04_rdp_v:           /* block 4 RDP version     */
           achl1 = (char *) ucrs_rdp_version;
           iml1 = sizeof(ucrs_rdp_version);
           break;
#endif
         case ied_frse_actpdu_len_cap:      /* get length capabilities */
           achl1 = (char *) ucrs_source_desc;
           iml1 = sizeof(ucrs_source_desc);
           break;
         default:
           goto pfrse96;                    /* program illogic         */
       }
       iml2 = iml1;                         /* save length             */
       if (iml1 > (D_ADSL_RCL1->imc_prot_1 + iml_rec)) {
         iml1 = D_ADSL_RCL1->imc_prot_1 + iml_rec;
       }
       iml1 -= D_ADSL_RCL1->imc_prot_1;
       if (memcmp( achl1 + D_ADSL_RCL1->imc_prot_1,
                   adsl_gai1_inp_1->achc_ginp_cur,
                   iml1 )) {
         iml_line_no = __LINE__;
         iml_source_no = 10384;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_1 += iml1;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RCL1->imc_prot_1 < iml2) {
         goto pfrse20;                      /* process next data       */
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_start:
           if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* nothing more in packet */
             goto pfrse_send_secbl;         /* send second block to server */
           }
           D_ADSL_RCL1->imc_prot_save1 = -1;  /* first retrieve type   */
           D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_akku = 0;  /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_asn1_4:          /* block 4 ASN-1 field 4   */
/* UUUU 16.12.04 KB */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_mu_len_1;  /* multi length 1 */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_len_cap:      /* get length capabilities */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 10423;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_no_cap;  /* get number capabilities */
           goto pfrse20;                    /* process next data       */
//       default:
//         goto pfrse96;                    /* program illogic         */
       }
           goto pfrse96;                    /* program illogic         */
     case ied_fsfp_ignore:                  /* ignore this data        */
       /* compute how many to ignore                                   */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame
                - D_ADSL_RCL1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RCL1->imc_pos_inp_frame > D_ADSL_RCL1->imc_prot_2) {
         goto pfrse20;                      /* needs more data         */
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_r04_asn1_1:          /* block 4 ASN-1 field 1   */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_asn1_2;  /* block 4 ASN-1 field 2 */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_tag;
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_asn1_2:          /* block 4 ASN-1 field 2   */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_asn1_3;  /* block 4 ASN-1 field 3 */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_tag;
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_asn1_3:          /* block 4 ASN-1 field 3   */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_asn1_4;  /* block 4 ASN-1 field 4 */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_tag;
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_rdp_v:           /* block 4 RDP version     */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {  /* at end of block */
             iml_line_no = __LINE__;
             iml_source_no = 10459;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 10467;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_ppdir_tag:       /* block 4 public parms direct tag */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 10476;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_no_cap:       /* get number capabilities */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 10485;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_cap_ind;  /* get capabilities index */
           goto pfrse20;                    /* process next data       */
/* 05.01.05 KB - invalid */
         case ied_frse_any_pdu_rec:         /* RDP 5 PDU length        */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_chll:         /* platform challenge      */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 10499;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_deaap_rec:           /* Deactivate All PDU Data */
           D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_count_in <= 0) {  /* at least one byte must follow */
             iml_line_no = __LINE__;
             iml_source_no = 10525;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_akku = 0;  /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_xyz_end_pdu:         /* end of PDU              */
           if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* at end of block      */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
             goto pfrse20;                          /* process next data       */
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
             iml_line_no = __LINE__;
             iml_source_no = 10538;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_typ;  /* RDP 5 PDU type */
           goto pfrse20;                    /* process next data       */
/* 18.06.05 KB UUUU */
       }
           goto pfrse96;                    /* program illogic         */
     case ied_fsfp_copy:                    /* copy data               */
       /* compute how many to copy                                     */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame
                - D_ADSL_RCL1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       memcpy( D_ADSL_RCL1->achc_prot_1,
               adsl_gai1_inp_1->achc_ginp_cur,
               iml1 );
       D_ADSL_RCL1->achc_prot_1 += iml1;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RCL1->imc_pos_inp_frame > D_ADSL_RCL1->imc_prot_2) {
         goto pfrse20;                      /* needs more data         */
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_r04_d_serv_rand:     /* block 4 data server random */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                     - D_ADSL_RCO1->imc_l_pub_par;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 10572;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 10576;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_type_pub_par;  /* block 4 type public parameters */
           D_ADSL_RCL1->iec_frse_bl2 = ied_frse_r04_d_serv_rand;
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_ppdir_len:       /* block 4 public parms direct lenght */
           if (D_ADSL_RCL1->imc_prot_5 == 0) {  /* was first parameter */
             if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {
               iml_line_no = __LINE__;
               iml_source_no = 10589;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCL1->imc_prot_5 = D_ADSL_RCL1->imc_prot_4;
             D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_ppdir_tag;  /* get public parms direct tag */
             D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
             if (D_ADSL_RCL1->imc_prot_2 < 0) {
               iml_line_no = __LINE__;
               iml_source_no = 10595;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RCL1->imc_prot_1 = 0;   /* clear value             */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
             goto pfrse20;                  /* process next data       */
           }
/* maybe other sequence of tags */
           {
             if (memcmp( D_ADSL_RCL1->chrc_prot_1, "RSA1", 4)) {
               iml_line_no = __LINE__;
               iml_source_no = 10613;    /* source line no for errors */
               goto pfrse92;
             }
             iml1 = m_get_le4( D_ADSL_RCL1->chrc_prot_1 + 4 );
             if (iml1 != (D_ADSL_RCL1->imc_prot_6 - 20)) {
               iml_line_no = __LINE__;
               iml_source_no = 10617;    /* source line no for errors */
               goto pfrse92;
             }
// to-do 29.01.10 KB where does length of exponent come from ???
             /* check power of two                                     */
             iml5 = iml1;
             iml6 = 32 - 1;
             while (iml5 > 0) {
               iml6--;                      /* subtract one position bit */
               iml5 <<= 1;                  /* remove this bit         */
             }
             iml5 = 1 << iml6;              /* compute power of two    */
             if (iml5 > D_RSA_KEY_SIZE) {
               iml_line_no = __LINE__;
               iml_source_no = 10641;    /* source line no for errors */
               goto pfrse92;
             }
             if (iml1 > (iml5 + D_RSA_KEY_PADDING)) {  /* too many leading bytes */
               iml_line_no = __LINE__;
               iml_source_no = 10644;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCL1->imc_len_cert_key = iml5;  /* length RSA key  */
             D_ADSL_RCL1->achc_cert_key     /* RSA key                 */
                 = (char *) m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, iml5 );
             achl1 = D_ADSL_RCL1->achc_cert_key;  /* RSA key           */
             achl2 = achl1 + iml5;          /* add length RSA key      */
             achl3 = D_ADSL_RCL1->chrc_prot_1 + 20;
             do {
               *(--achl2) = *achl3++;
             } while (achl2 > achl1);
             /* check if remaining bytes are all zero                  */
             while (iml5 < iml1) {
               if (*(D_ADSL_RCL1->chrc_prot_1 + 20 + iml5)) {  /* byte not zero */
                 iml_line_no = __LINE__;
                 iml_source_no = 10658;    /* source line no for errors */
                 goto pfrse92;
               }
               iml5++;                      /* check next              */
             }
             iml1 = 3;
             achl1 = D_ADSL_RCL1->chrc_cert_exp;
             if (iml1 < sizeof(D_ADSL_RCL1->chrc_cert_exp)) {
               memset( achl1, 0, sizeof(D_ADSL_RCL1->chrc_cert_exp) - iml1 );
               achl1 += sizeof(D_ADSL_RCL1->chrc_cert_exp) - iml1;
             }
             memcpy( achl1,
                     D_ADSL_RCL1->chrc_prot_1 + 16,
                     iml1 );
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame > 0) {  /* more data in block */
              D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;
              D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;                /* block 4 selection */
              D_ADSL_RCL1->imc_prot_1 = 0;                                  /* clear value             */
              D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2; /* number of bytes */
              if (D_ADSL_RCL1->imc_prot_2 < 0) {
                iml_line_no = __LINE__;
                iml_source_no = 10679;    /* source line no for errors */
                goto pfrse92;
              }
              D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;     /* here first byte */
              D_ADSL_RCL1->imc_prot_4 = 0;
              goto pfrse20;                                                 /* process next data       */
           }
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_rec_07;
           goto pfrse_send_erect_domain_request_pdu;
         case ied_frse_r04_d_pub_par:       /* block 4 data public parameters */
           /* get certificate values                                   */
           /* stored in temporary buffer at D_ADSL_RCL1->ac_temp_buffer */
           /* length is (D_ADSL_RCL1->achc_prot_1 - (char *) D_ADSL_RCL1->ac_temp_buffer) */
           iml1 = D_ADSL_RCL1->achc_prot_1 - (char *) D_ADSL_RCL1->ac_temp_buffer;
           iml2 = 4 + sizeof(int);          /* start here              */
           iml3 = iml1;                     /* set stopper             */
           while (TRUE) {                   /* loop to walk thru certificate */
             if (iml2 > iml1) {             /* after end of buffer     */
               iml_line_no = __LINE__;
               iml_source_no = 10831;    /* source line no for errors */
               goto pfrse92;
             }
             /* get int little endian                                  */
             iml4 = *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2 - 4)
                    | (*((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2 - 3) << 8)
                    | (*((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2 - 2) << 16)
                    | (*((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2 - 1) << 24);
             if (iml4 == 0) break;          /* reached last position   */
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
               iml_line_no = __LINE__;
               iml_source_no = 10840;    /* source line no for errors */
               goto pfrse92;
             }
             iml3 = iml2;                   /* save previous value     */
             iml2 += iml4;                  /* after this part         */
             if (iml2 == iml1) break;       /* end of certificate      */
             iml2 += sizeof(int);           /* after this part         */
           }
           /* skip length certificate                                  */
           iml3 += sizeof(int) + 2;         /* add length length + Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
             iml_line_no = __LINE__;
             iml_source_no = 10850;    /* source line no for errors */
             goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) < 0) {  /* MSB set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
           }
           /* skip length TBS certificate                              */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
             iml_line_no = __LINE__;
             iml_source_no = 10858;    /* source line no for errors */
             goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) < 0) {  /* MSB set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer digits */
           }
           /* skip Version                                             */
           /* macro to skip one ASN.1 field                            */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10864;    /* source line no for errors */
           goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10864;    /* source line no for errors */
           goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
           iml_line_no = __LINE__;
           iml_source_no = 10864;    /* source line no for errors */
           goto pfrse92;
             }
             iml3 += iml4;                  /* add length of this field */
           }
           /* end of macro to skip one ASN.1 field                     */
           /* skip Serial Number                                       */
           /* macro to skip one ASN.1 field                            */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10866;    /* source line no for errors */
           goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10866;    /* source line no for errors */
           goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
           iml_line_no = __LINE__;
           iml_source_no = 10866;    /* source line no for errors */
           goto pfrse92;
             }
             iml3 += iml4;                  /* add length of this field */
           }
           /* end of macro to skip one ASN.1 field                     */
           /* skip Signature Alg.                                      */
           /* macro to skip one ASN.1 field                            */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10868;    /* source line no for errors */
           goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10868;    /* source line no for errors */
           goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
           iml_line_no = __LINE__;
           iml_source_no = 10868;    /* source line no for errors */
           goto pfrse92;
             }
             iml3 += iml4;                  /* add length of this field */
           }
           /* end of macro to skip one ASN.1 field                     */
           /* skip Issuer                                              */
           /* macro to skip one ASN.1 field                            */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10870;    /* source line no for errors */
           goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10870;    /* source line no for errors */
           goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
           iml_line_no = __LINE__;
           iml_source_no = 10870;    /* source line no for errors */
           goto pfrse92;
             }
             iml3 += iml4;                  /* add length of this field */
           }
           /* end of macro to skip one ASN.1 field                     */
           /* skip validity                                            */
           /* macro to skip one ASN.1 field                            */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10872;    /* source line no for errors */
           goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10872;    /* source line no for errors */
           goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
           iml_line_no = __LINE__;
           iml_source_no = 10872;    /* source line no for errors */
           goto pfrse92;
             }
             iml3 += iml4;                  /* add length of this field */
           }
           /* end of macro to skip one ASN.1 field                     */
           /* skip subject                                             */
           /* macro to skip one ASN.1 field                            */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10874;    /* source line no for errors */
           goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10874;    /* source line no for errors */
           goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
           iml_line_no = __LINE__;
           iml_source_no = 10874;    /* source line no for errors */
           goto pfrse92;
             }
             iml3 += iml4;                  /* add length of this field */
           }
           /* end of macro to skip one ASN.1 field                     */
           /* skip length subjectPublicKeyInfo                         */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
             iml_line_no = __LINE__;
             iml_source_no = 10878;    /* source line no for errors */
             goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) < 0) {  /* MSB set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer digits */
           }
           /* skip algorithm ID                                        */
           /* macro to skip one ASN.1 field                            */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10884;    /* source line no for errors */
           goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
           iml_line_no = __LINE__;
           iml_source_no = 10884;    /* source line no for errors */
           goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
           iml_line_no = __LINE__;
           iml_source_no = 10884;    /* source line no for errors */
           goto pfrse92;
             }
             iml3 += iml4;                  /* add length of this field */
           }
           /* end of macro to skip one ASN.1 field                     */
           /* skip length subjectPublicKey                             */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
             iml_line_no = __LINE__;
             iml_source_no = 10888;    /* source line no for errors */
             goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) < 0) {  /* MSB set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer digits */
           }
           iml3++;
           /* skip Modulus & Exp                                       */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
             iml_line_no = __LINE__;
             iml_source_no = 10897;    /* source line no for errors */
             goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) < 0) {  /* MSB set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer digits */
           }
           /* now Exponent                                             */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
             iml_line_no = __LINE__;
             iml_source_no = 10905;    /* source line no for errors */
             goto pfrse92;
           }
           if (*((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 2) != 0X02) {
             iml_line_no = __LINE__;
             iml_source_no = 10908;    /* source line no for errors */
             goto pfrse92;
           }
           /* get length of field Modulus                              */
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml4 = *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* get integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
               iml_line_no = __LINE__;
               iml_source_no = 10917;    /* source line no for errors */
               goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
           }
           if ((iml3 + iml4) > iml1) {      /* after end of buffer     */
             iml_line_no = __LINE__;
             iml_source_no = 10926;    /* source line no for errors */
             goto pfrse92;
           }
           /* check power of two                                       */
           iml5 = iml4;
           iml6 = 32 - 1;
           while (iml5 > 0) {
             iml6--;                        /* subtract one position bit */
             iml5 <<= 1;                    /* remove this bit         */
           }
           iml5 = 1 << iml6;                /* compute power of two    */
           if (iml5 > D_RSA_KEY_SIZE) {
             iml_line_no = __LINE__;
             iml_source_no = 10937;    /* source line no for errors */
             goto pfrse92;
           }
           if (iml4 > (iml5 + 2)) {         /* too many leading bytes  */
             iml_line_no = __LINE__;
             iml_source_no = 10940;    /* source line no for errors */
             goto pfrse92;
           }
           /* check if leading bytes are zero                          */
           while (iml4 > iml5) {            /* remove leading zeroes */
             if (*((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3) != 0)  {  /* check zero */
               iml_line_no = __LINE__;
               iml_source_no = 10945;    /* source line no for errors */
               goto pfrse92;
             }
             iml3++;                        /* increment address       */
             iml4--;                        /* decrement length        */
           }
           D_ADSL_RCL1->imc_len_cert_key = iml4;  /* length RSA key    */
           D_ADSL_RCL1->achc_cert_key       /* RSA key                 */
               = (char *) m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, iml4 );
           memcpy( D_ADSL_RCL1->achc_cert_key,
                   (unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3,
                   iml4 );

           iml3 += iml4;                    /* after field Exponent    */
           /* now Modulus                                              */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
             iml_line_no = __LINE__;
             iml_source_no = 10961;    /* source line no for errors */
             goto pfrse92;
           }
           if (*((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 2) != 0X02) {
             iml_line_no = __LINE__;
             iml_source_no = 10964;    /* source line no for errors */
             goto pfrse92;
           }
           /* get length of field Exponent                             */
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml4 = *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* get integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
               iml_line_no = __LINE__;
               iml_source_no = 10973;    /* source line no for errors */
               goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
           }
           if ((iml4 < 2) || (iml4 > 4)) {  /* check ranges            */
             iml_line_no = __LINE__;
             iml_source_no = 10982;    /* source line no for errors */
             goto pfrse92;
           }
           if ((iml3 + iml4) > iml1) {      /* after end of buffer     */
             iml_line_no = __LINE__;
             iml_source_no = 10985;    /* source line no for errors */
             goto pfrse92;
           }
           achl1 = D_ADSL_RCL1->chrc_cert_exp;
           if (iml4 < sizeof(D_ADSL_RCL1->chrc_cert_exp)) {
             memset( achl1, 0, sizeof(D_ADSL_RCL1->chrc_cert_exp) - iml4 );
             achl1 += sizeof(D_ADSL_RCL1->chrc_cert_exp) - iml4;
           }
           memcpy( achl1,
                   (unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3,
                   iml4 );
           if(D_ADSL_RCL1->iec_frse_bl2 == ied_frse_lic_pr_req_cert) {
               D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_exp = ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp;
               D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_exp_len = sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp);
               D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_key = ADSL_RDPA_F->dsc_rdp_cl_1.achc_cert_key;  /* RSA key */
               D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len = ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key;  /* length RSA key */
           

               D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
               if(D_ADSL_RCL1->imc_prot_2 < 0) {
                  iml_line_no = __LINE__;
                  iml_source_no = 11005;    /* source line no for errors */
                  goto pfrse92;
               }
               D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_req_scopelist;  /* parse scopelist. Len of list first */
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
               goto pfrse20;
           }
           /* certificate now processed                                */
           if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* end of block */
             if (D_ADSL_RCL1->imc_prot_4 != 7) {  /* not all fields received */
               iml_line_no = __LINE__;
               iml_source_no = 11017;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* first record type */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_rec_07;
             goto pfrse_send_erect_domain_request_pdu;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 11073;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
           case ied_frse_actpdu_cap_len:      /* get capabilities length */
           switch (D_ADSL_RCL1->imc_prot_6) {
             case 2:                        /* bitmap capability       */
               if (D_ADSL_RCL1->imc_prot_7) {  /* double               */
                 iml_line_no = __LINE__;
                 iml_source_no = 11091;    /* source line no for errors */
                 goto pfrse92;
               }
               if (D_ADSL_RCL1->achc_prot_1 < (D_ADSL_RCL1->chrc_prot_1 + 16)) {
                 iml_line_no = __LINE__;
                 iml_source_no = 11094;    /* source line no for errors */
                 goto pfrse92;
               }
               memcpy( D_ADSL_RCL1->chrc_prot_2 + 0,
                       D_ADSL_RCL1->chrc_prot_1 + 8,
                       4 );
               memcpy( D_ADSL_RCL1->chrc_prot_2 + 4,
                       D_ADSL_RCL1->chrc_prot_1 + 0,
                       2 );
               D_ADSL_RCL1->imc_prot_7 = 1;  /* set value found        */
               break;
           }
           D_ADSL_RCL1->imc_prot_5--;       /* one capability less     */
           if (D_ADSL_RCL1->imc_prot_5) {   /* more to follow          */
             D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
             if (D_ADSL_RCL1->imc_prot_2 < 0) {
               iml_line_no = __LINE__;
               iml_source_no = 11109;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RCL1->imc_prot_1 = 0;   /* clear value             */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_cap_ind;  /* get capabilities index */
             goto pfrse20;                  /* process next data       */
           }
           if (D_ADSL_RCL1->imc_prot_7 == 0) {  /* screen parameters not found */
             iml_line_no = __LINE__;
             iml_source_no = 11118;    /* source line no for errors */
             goto pfrse92;
           }
           bol1 = m_make_screen( adsp_hl_clib_1, D_ADSL_RCL1->chrc_prot_2 );
           if (bol1 == FALSE) {             /* screen parameters invalid */
             iml_line_no = __LINE__;
             iml_source_no = 11123;    /* source line no for errors */
             goto pfrse92;
           }
           /* check if till end of capabilities                        */
           if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_4) {
             iml_line_no = __LINE__;
             iml_source_no = 11128;    /* source line no for errors */
             goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame != 4) {
             iml_line_no = __LINE__;
             iml_source_no = 11131;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = 0;     /* number of bytes         */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_big_e;  /* int big endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_trail;  /* trailer of act PDU */
           goto pfrse20;                    /* process next data       */
         case ied_frse_rdp4_vch_ulen:       /* virtual channel uncompressed data length */
           goto pfrse_vch_00;               /* virtual channel data received */
         case ied_frse_rdp4_mcs_msgchannel:
             goto pfrse_mcs_msgchannel;
         case ied_frse_lic_pr_req_rand:  /* server license request (after) random */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 11381;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                /* process next data       */
         case ied_frse_lic_pr_req_cert:  /* server license request (before) certificate */
           iml1 = 4 + 4 + m_get_le4( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 4 );
           iml2 = m_get_le2( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + iml1 + sizeof(ucrs_lic_bef_cert) );
           if ( memcmp( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + iml1,
                 ucrs_lic_bef_cert, sizeof(ucrs_lic_bef_cert) )) {
             if ( (! memcmp( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + iml1,
                     ucrs_lic_bef_cert, sizeof(ucrs_lic_bef_cert)-2 ))
                  && (D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1[iml1 + sizeof(ucrs_lic_bef_cert)-1] == (char)0xF5)
                  && (iml2 == 0) ) {
// to-do 22.07.11 KB - nothing to do and no printf ???
#ifdef TRACEHL1_LIC
             printf( "unknown format in Server License Request occurred again: "
                     "%02X F5 00 00 instead of Server Certificate blobheader\n",
                     D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1[sizeof(ucrs_lic_bef_cert)-2] );
#endif
             } else {
               iml_line_no = __LINE__;
               iml_source_no = 11403;    /* source line no for errors */
               goto pfrse92;
             }
           }
             D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_exp = ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp;
             D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_exp_len = sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp);
             D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_key = ADSL_RDPA_F->dsc_rdp_cl_1.achc_cert_key;  /* RSA key */
             D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len = ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key;  /* length RSA key */
           if (iml2 == 0) {                 /* no special licensing certificate given */
             D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
             D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_req_scopelist;  /* parse scopelist. Len of list first */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
             goto pfrse20;
           }
           D_ADSL_RCL1->imc_prot_6 = D_ADSL_RCL1->imc_pos_inp_frame - iml2;
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 11444;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_type_pub_par;  /* licensing certificate, parsed like block 4 type public parameters */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           D_ADSL_RCL1->iec_frse_bl2 = ied_frse_lic_pr_req_cert;
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_req_scopelist:
           D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_req_cert;
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
           goto pfrse40;                    /* send RDP4 to client     */
         case ied_frse_lic_pr_chll:         /* platform challenge      */
           iml1 = m_get_le2(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1); /* hwid length */
#define ACHL_WORK_RC4 ((char *) chrl_work_2)
#define ACHL_WORK_SHA1 ((int *) ((char *) ACHL_WORK_RC4 + RC4_STATE_SIZE))
#define ACHL_WORK_MD5 ((int *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int)))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
#define ACHL_WORK_CHLL ((char *) ACHL_WORK_UTIL_01 + 20)
           /* decrypt */
           /* In Licensing JWT initializes the state before every call of RC4. */
           memcpy(ACHL_WORK_RC4, D_ADSL_RCO1->adsc_lic_neg->chrc_rc4_state_se2cl, RC4_STATE_SIZE);
           RC4( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1, 2, iml1,
                ACHL_WORK_CHLL, 0,
                ACHL_WORK_RC4 );
           memcpy( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 2, ACHL_WORK_CHLL, iml1 );
#ifdef TRACEHL1_LIC
           printf( "l%05d s%05d decrypted challenge teststring.\n",
                   __LINE__, 11478 );
           m_console_out( ACHL_WORK_CHLL, iml1 );
#endif
           /* calculate the challenged hash                            */
           memcpy( ACHL_WORK_SHA1,
                   D_ADSL_RCO1->adsc_lic_neg->imrc_sha1_state,
                   sizeof(D_ADSL_RCO1->adsc_lic_neg->imrc_sha1_state) );
           memcpy( ACHL_WORK_MD5,
                   D_ADSL_RCO1->adsc_lic_neg->imrc_md5_state,
                   sizeof(D_ADSL_RCO1->adsc_lic_neg->imrc_md5_state) );
           m_put_le4( ACHL_WORK_UTIL_01, iml1 );
           SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
           SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_CHLL, 0, iml1 );
           SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
           MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
           MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
           /* compare hash                                             */
           if (memcmp( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 2 + iml1, ACHL_WORK_UTIL_01, 16 )) {
#ifdef TRACEHL1
             printf( "s%05d l%05d received from server licensing platform challenge hash fail\n",
                     11498,        /* source line no for errors */
                     __LINE__ );            /* line number for errors  */
#endif
             /* [MS-RDPELE] 3.1.5.1 says the client MUST send a LICENSE_ERROR_MESSAGE - see [MS-RDPBCGR] 2.2.1.12.1.3
             memcpy( chrl_work_2, ucrs_lic_err_hash, sizeof(ucrs_lic_err_hash) );
             m_put_be2( chrl_work_2 + 8, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
             m_put_be2( chrl_work_2 + 10, D_DISPLAY_CHANNEL );
             ... XXX how to send something and after that exit with an error? */
             iml_line_no = __LINE__;
             iml_source_no = 11506;    /* source line no for errors */
             goto pfrse92;
           }
#undef ACHL_RC4_STATE
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
#undef ACHL_WORK_CHLL
           /* send data to client                                      */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;
           goto pfrse40;                    /* send RDP4 to client     */
         case ied_frse_any_pdu_rec:         /* receive any PDU type    */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
           goto pfrse20;                    /* process next data       */
       }
       iml_line_no = __LINE__;
       iml_source_no = 11766;    /* source line no for errors */
       goto pfrse96;
     case ied_fsfp_cmp_zero:                /* compare with zeroes     */
       /* compute how many to compare                                  */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame
                - D_ADSL_RCL1->imc_prot_count_in;
       if (iml1 > iml_rec) iml1 = iml_rec;
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* length constant     */
       do {
         if (*adsl_gai1_inp_1->achc_ginp_cur) {
           iml_line_no = __LINE__;
           iml_source_no = 11783;    /* source line no for errors */
           goto pfrse92;
         }
         adsl_gai1_inp_1->achc_ginp_cur++;  /* next character input    */
         iml1--;                            /* decrement count         */
       } while (iml1 > 0);
       if (D_ADSL_RCL1->imc_pos_inp_frame > D_ADSL_RCL1->imc_prot_count_in) {
         goto pfrse20;                      /* needs more data         */
       }
//       case ied_frse_deaap_rec:           /* Deactivate All PDU Data */
           if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < sizeof(struct dsd_se_co1)) {  /* get new area */
             memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
             bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                                DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                                &dsl_aux_get_workarea,
                                                sizeof(struct dsd_aux_get_workarea) );
             if (bol1 == FALSE) {           /* aux returned error      */
               adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
               goto p_cleanup_20;           /* do cleanup now          */
             }
             ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
             ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
           }
           ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1);
#define ADSL_SE_CO1_G ((struct dsd_se_co1 *) ADSL_OA1->achc_upper)
           ADSL_SE_CO1_G->iec_se_command = ied_sec_d_deact_pdu;  /* received demand de-active PDU */
           ADSL_SE_CO1_G->adsc_next = NULL;  /* clear chain field      */
           *ADSL_OA1->aadsc_se_co1_chain = ADSL_SE_CO1_G;  /* append to chain */
           ADSL_OA1->aadsc_se_co1_chain = &ADSL_SE_CO1_G->adsc_next;  /* set new end of chain */
#undef ADSL_SE_CO1_G
           D_ADSL_RCL1->iec_frse_bl = ied_frse_act_pdu_rec;  /* receive block active PDU */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
           goto pfrse20;                    /* process next data       */
     case ied_fsfp_r04_rdp_v:               /* block 4 RDP version     */
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RCL1->imc_pos_inp_frame--;    /* length constant         */
       if (D_ADSL_RCL1->imc_prot_2 >= D_ADSL_RCL1->imc_pos_inp_frame) {
         iml_line_no = __LINE__;
         iml_source_no = 11822;    /* source line no for errors */
         goto pfrse92;
       }
#ifdef XYZ1
       D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
       D_ADSL_RCL1->imc_prot_1 = 0;         /* clear value             */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
#endif
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data     */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_rec_type:                /* get type of record      */
#ifdef OLD01
       if (D_ADSL_RCL1->iec_frse_bl == ied_frse_rec_02) {
         if (ADSL_RDPA_F->inc_send_server_len) {  /* still something to send */
           goto pfrse92;                    /* protocol error          */
         }
       }
#endif
       D_ADSL_RCO1->chrc_start_rec[0] = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record */
       D_ADSL_RCO1->imc_len_start_rec = 1;  /* length start of record  */
       switch ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur) {
         case 0X00:                         /* RDP 5 record            */
/* 28.07.08 KB receive also 0X80 */
         case 0X80:                         /* RDP 5 record encrypted  */
         case 0XC0:                         /* RDP 5 record encrypted  */
#ifdef D_FOR_TRACE1                         /* 31.05.05 KB - help in tracing */
           iml1++;
           iml1--;
#endif                                      /* 31.05.05 KB - help in tracing */
           if (D_ADSL_RCL1->iec_frse_bl == ied_frse_any_pdu_rec) {  /* ????ive block active PDU */
             D_ADSL_RCL1->chc_prot_r5_first = *adsl_gai1_inp_1->achc_ginp_cur;
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_len_1;  /* RDP 5 multi length 1 */
             break;
           }
           iml_line_no = __LINE__;
           iml_source_no = 11864;    /* source line no for errors */
           goto pfrse92;
         case 0X03:                         /* RDP 4 record            */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_byte01;  /* receive byte 01 */
           break;
         default:
           iml_line_no = __LINE__;
           iml_source_no = 11869;    /* source line no for errors */
           goto pfrse92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_byte01:                  /* receive byte 01         */
       if (*adsl_gai1_inp_1->achc_ginp_cur) {
         iml_line_no = __LINE__;
         iml_source_no = 11905;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec++ ]
         = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record        */
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_lencons_2;  /* receive len c */
       D_ADSL_RCL1->imc_prot_1 = 0;         /* clear length field      */
       D_ADSL_RCL1->imc_pos_inp_frame = 0;  /* no length frame yet     */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_lencons_2:               /* two bytes length remain */
/* nothing before - fill field 07.08.04 KB */
       if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* no len frame yet */
         D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec++ ]
           = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record      */
       }
       D_ADSL_RCL1->imc_prot_1 <<= 8;
       D_ADSL_RCL1->imc_prot_1
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_lencons_1;  /* receive len c */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_lencons_1:               /* one byte length remains */
       if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* no len frame yet */
         D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec++ ]
           = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record      */
       }
       D_ADSL_RCL1->imc_prot_1 <<= 8;
       D_ADSL_RCL1->imc_prot_1
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
       if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* no len frame yet  */
         D_ADSL_RCO1->imc_len_record = D_ADSL_RCL1->imc_prot_1;  /* length of record */
         D_ADSL_RCO1->imc_len_part = D_ADSL_RCL1->imc_prot_1;  /* length of part */
         ADSL_RDPA_F->dsc_rdptr1.chc_type_disp = 'R';  /* type of displacement */
         D_ADSL_RCL1->imc_pos_inp_frame = D_ADSL_RCL1->imc_prot_1 - 4;
         if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
           iml_line_no = __LINE__;
           iml_source_no = 11975;    /* source line no for errors */
           goto pfrse92;
         }
#ifdef HL_RDPACC_HELP_DEBUG
         D_ADSL_RCO1->imc_debug_reclen = D_ADSL_RCL1->imc_prot_1;
#endif
       } else {
         D_ADSL_RCL1->imc_pos_inp_frame -= 2;  /* adjust length remaining */
         if (D_ADSL_RCL1->imc_pos_inp_frame < 0) {
           iml_line_no = __LINE__;
           iml_source_no = 11987;    /* source line no for errors */
           goto pfrse92;
         }
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_start:               /* reply from server to first packet */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_l1_fi;  /* ASN.1 length field */
           goto pfrse20;                    /* process next data       */
         case ied_frse_rec_04:              /* block 4 received        */
         case ied_frse_rec_07:              /* block 7 received        */
         case ied_frse_cjresp_rec:          /* receive block channel join response */
         case ied_frse_lic_pr_1_rec:        /* receive block licence protocol */
         case ied_frse_act_pdu_rec:         /* receive block active PDU */
         case ied_frse_error_bl_01:         /* receive error block 01  */
         case ied_frse_any_pdu_rec:         /* ????ive block active PDU */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= sizeof(ucrs_x224_p01)) {
             iml_line_no = __LINE__;
             iml_source_no = 12002;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_x224_p01;  /* is in x224 header */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* position                */
           goto pfrse20;                    /* process next data       */
//       default:
//         goto pfrse96;                    /* program illogic         */
       }
       iml_line_no = __LINE__;
       iml_source_no = 12010;    /* source line no for errors */
       goto pfrse96;
     case ied_fsfp_x224_p01:                /* is in x224 header       */
       iml1 = sizeof(ucrs_x224_p01);        /* get length              */
       if (iml1 > (D_ADSL_RCL1->imc_prot_1 + iml_rec)) {
         iml1 = D_ADSL_RCL1->imc_prot_1 + iml_rec;
       }
       iml1 -= D_ADSL_RCL1->imc_prot_1;
       if (memcmp( ucrs_x224_p01 + D_ADSL_RCL1->imc_prot_1,
                   adsl_gai1_inp_1->achc_ginp_cur,
                   iml1 )) {
         iml_line_no = __LINE__;
         iml_source_no = 12100;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_1 += iml1;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RCL1->imc_prot_1 < sizeof(ucrs_x224_p01)) {
         goto pfrse20;                      /* get more input          */
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_mcs_c1;  /* MCS command 1   */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_mcs_c1:                  /* MCS command 1           */
       switch (*adsl_gai1_inp_1->achc_ginp_cur) {
         case 0X20:                         /* MCS end of comm - machine down ???? UUUU */
         case 0X21:                         /* MCS end of comm ???? UUUU */
           if (   (D_ADSL_RCL1->iec_frse_bl != ied_frse_act_pdu_rec)  /* receive block active PDU */
               && (D_ADSL_RCL1->iec_frse_bl != ied_frse_any_pdu_rec)) {  /* ????ive block active PDU */
             iml_line_no = __LINE__;
             iml_source_no = 12116;    /* source line no for errors */
             goto pfrse92;
           }
           if (*adsl_gai1_inp_1->achc_ginp_cur == 0X20) {
             D_ADSL_RCL1->ac_redirect = NULL;  /* memory for Standard Security Server Redirection PDU */
           }
           D_ADSL_RCL1->imc_prot_1 = (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur;
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
             iml_line_no = __LINE__;
             iml_source_no = 12127;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_end_com;  /* end of communication */
           goto pfrse20;                    /* process next data       */
         case 0X2E:                         /* MCS Attach User reply   */
           if (D_ADSL_RCL1->iec_frse_bl != ied_frse_rec_07) {
             iml_line_no = __LINE__;
             iml_source_no = 12133;    /* source line no for errors */
             goto pfrse92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
             iml_line_no = __LINE__;
             iml_source_no = 12138;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_status;  /* status from server */
           goto pfrse20;                    /* process next data       */
         case 0X3E:                         /* MCS channel join response */
           if (D_ADSL_RCL1->iec_frse_bl != ied_frse_cjresp_rec) {
             iml_line_no = __LINE__;
             iml_source_no = 12144;    /* source line no for errors */
             goto pfrse92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
             iml_line_no = __LINE__;
             iml_source_no = 12149;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_status;  /* status from server */
           goto pfrse20;                    /* process next data       */
         case 0X68:                         /* Send Data Indication    */
           switch (D_ADSL_RCL1->iec_frse_bl) {
             case ied_frse_lic_pr_1_rec:    /* receive block licence protocol */
             case ied_frse_act_pdu_rec:     /* receive block active PDU */
             case ied_frse_error_bl_01:     /* receive error block 01  */
             case ied_frse_any_pdu_rec:     /* ????ive block active PDU */
               break;
             default:
               iml_line_no = __LINE__;
               iml_source_no = 12161;    /* source line no for errors */
               goto pfrse92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
             iml_line_no = __LINE__;
             iml_source_no = 12166;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 12170;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_userid_se2cl;  /* userid communication follows */
           goto pfrse20;                    /* process next data       */
         case 0X7F:                         /* MCS connect reply       */
           if (D_ADSL_RCL1->iec_frse_bl != ied_frse_rec_04) {
             iml_line_no = __LINE__;
             iml_source_no = 12177;    /* source line no for errors */
             goto pfrse92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_mcs_c2;  /* MCS command 2 */
           goto pfrse20;                    /* process next data       */
       }
             iml_line_no = __LINE__;
             iml_source_no = 12184;    /* source line no for errors */
             goto pfrse92;
     case ied_fsfp_mcs_c2:                  /* MCS command 2           */
       switch (*adsl_gai1_inp_1->achc_ginp_cur) {
         case 0X66:                         /* MCS connect reply       */
           if (D_ADSL_RCL1->iec_frse_bl != ied_frse_rec_04) {
             iml_line_no = __LINE__;
             iml_source_no = 12189;    /* source line no for errors */
             goto pfrse92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             goto pfrse92;                  /* protocol error          */
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_l1_fi;  /* ASN.1 length field */
           goto pfrse20;                    /* process next data       */
       }
             iml_line_no = __LINE__;
             iml_source_no = 12200;    /* source line no for errors */
             goto pfrse92;
     case ied_fsfp_status:                  /* status from server      */
       if (*adsl_gai1_inp_1->achc_ginp_cur) {
         iml_line_no = __LINE__;
         iml_source_no = 12203;    /* source line no for errors */
         goto pfrse92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RCL1->imc_pos_inp_frame--;    /* length constant         */
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_rec_07:
           if (D_ADSL_RCL1->imc_pos_inp_frame != 2) {
             iml_line_no = __LINE__;
             iml_source_no = 12210;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = 0;     /* number of bytes         */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_big_e;  /* int big endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_cjresp_rec:          /* receive block channel join response */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 12219;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_userid_cl2se;  /* userid client to server follows */
           goto pfrse20;                    /* process next data       */
       }
           goto pfrse96;                    /* program illogic         */
     case ied_fsfp_userid_se2cl:            /* userid server to client follows */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_1 <<= 8;
         D_ADSL_RCL1->imc_prot_1
           |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
       if (D_ADSL_RCL1->imc_prot_1 != D_USERID_SE2CL) {
         iml_line_no = __LINE__;
         iml_source_no = 12245;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12249;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_chno = 0;      /* clear value             */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_chno;  /* channel no follows */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_userid_cl2se:            /* userid client to server follows */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_1 <<= 8;
         D_ADSL_RCL1->imc_prot_1
           |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
#ifdef TRACEHL1
       printf( "ied_fsfp_userid_cl2se found int=%d D_ADSL_RCL1->iec_frse_bl=%d\n",
               D_ADSL_RCL1->imc_prot_1,
               D_ADSL_RCL1->iec_frse_bl );
#endif
       if (D_ADSL_RCL1->imc_prot_1 != D_ADSL_RCO1->usc_userid_cl2se) {
         iml_line_no = __LINE__;
         iml_source_no = 12272;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12276;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_chno = 0;      /* clear value             */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_chno;  /* channel no follows */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_chno:                    /* channel number follows  */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_chno <<= 8;
         D_ADSL_RCL1->imc_prot_chno
           |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_cjresp_rec:          /* receive block channel join response */
           if (D_ADSL_RCL1->imc_pos_inp_frame != 2) {
             iml_line_no = __LINE__;
             iml_source_no = 12302;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = 0;     /* number of bytes         */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_big_e;  /* int big endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_1_rec:        /* receive block licence protocol */
         case ied_frse_act_pdu_rec:         /* receive block active PDU */
         case ied_frse_error_bl_01:         /* receive error block 01  */
         case ied_frse_any_pdu_rec:         /* ????ive block active PDU */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_prio_seg;  /* Priority / Segmentation */
           goto pfrse20;                    /* process next data       */
       }
       iml_line_no = __LINE__;
       iml_source_no = 12315;    /* source line no for errors */
       goto pfrse92;
     case ied_fsfp_prio_seg:                /* Priority / Segmentation */
//     if (*adsl_gai1_inp_1->achc_ginp_cur != 0X70) {
//       goto pfrse92;                      /* protocol error          */
//     }
/* 05.01.05 check channel - display channel always 0X70 */
       adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12324;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_mu_len_1;  /* multi length 1 */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_rt02:                    /* record type 2           */
       D_ADSL_RCL1->chc_prot_rt02 = *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12332;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rt03;  /* record type 3     */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_rt03:                    /* record type 3           */
       D_ADSL_RCL1->chc_prot_rt03 = *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12340;    /* source line no for errors */
         goto pfrse92;
       }
       /* two bytes padding follow - to be ignored                     */
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12345;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_padd_1;  /* padding         */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_padd_1:                  /* padding                 */
       /* compute how many to ignore                                   */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame
                - D_ADSL_RCL1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RCL1->imc_pos_inp_frame > D_ADSL_RCL1->imc_prot_2) {
         goto pfrse20;                      /* needs more data         */
       }
       if(D_ADSL_RCO1->imc_sec_level == 0) {
          if (D_ADSL_RCL1->chc_prot_rt03 & (SEC_AUTODETECT_REQ | SEC_HEARTBEAT) >> 8){
             if ((D_ADSL_RCL1->dsc_rdp_co_1.boc_enable_mcs_message_channel == FALSE)
                || (D_ADSL_RCL1->imc_prot_chno != D_ADSL_RCO1->usc_chno_mcs_msgchannel)){
                iml_line_no = __LINE__;
                iml_source_no = 12386;    /* source line no for errors */
                goto pfrse92;
             }
             // NOTE: we do not want to copy anything, but in case all data is not present
             //    in the present frame, we need to return to the correct point somehow, and 
             //    for the virtual channels, this is the way.
             D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame;     // This will result in 0 bytes to copy
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;
             D_ADSL_RCL1->iec_frse_bl = ied_frse_rdp4_mcs_msgchannel;
             goto pfrse_mcs_msgchannel;
          }
          goto LBL_fsfp_padd_1_01;  
       }
       if (   (D_ADSL_RCL1->chc_prot_rt02 & SEC_ENCRYPT)  /* block encrypted */
          || (D_ADSL_RCL1->chc_prot_rt03 & (SEC_REDIRECTION_PKT >> 8))) {  /* Standard Security Server Redirection PDU */
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - D_SIZE_HASH;
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
            iml_line_no = __LINE__;
            iml_source_no = 12411;    /* source line no for errors */
            goto pfrse92;
         }
         D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_prot_1;
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rdp4_hash;  /* hash RDP4 block */
         goto pfrse20;                        /* process next data       */
      }
LBL_fsfp_padd_1_01:
       if (D_ADSL_RCL1->chc_prot_rt02 & 0X80) {  /* SEC_LICENSE_PKT    */
         if (   (D_ADSL_RCL1->iec_frse_bl != ied_frse_lic_pr_1_rec)  /* receive block licence protocol */
             && (D_ADSL_RCL1->iec_frse_bl != ied_frse_any_pdu_rec)) {  /* ????ive block active PDU */
           iml_line_no = __LINE__;
           iml_source_no = 12424;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes (preamble header) */
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
           iml_line_no = __LINE__;
           iml_source_no = 12435;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
         D_ADSL_RCL1->imc_prot_1 = 0;       /* clear value             */
         D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_type;  /* licencing block to check */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e; /* int little endian (for length) */
         goto pfrse20;                      /* process next data       */
       }
LBL_fsfp_padd_1_02:
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_lic_pr_1_rec:        /* receive block licence protocol */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
           goto pfrse40;                    /* send RDP4 to client     */
         case ied_frse_any_pdu_rec:         /* ????ive block active PDU */
           if (D_ADSL_RCL1->imc_prot_chno == D_ADSL_RCO1->usc_chno_disp) {  /* channel number display  */
             D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
             if (D_ADSL_RCL1->imc_prot_count_in < 0) {
               iml_line_no = __LINE__;
               iml_source_no = 12454;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RCL1->imc_prot_akku = 0;  /* clear value           */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sch_len;  /* Share Control Header length */
             goto pfrse20;                  /* process next data       */
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 12463;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_rdp4_vch_ulen;  /* virtual channel uncompressed data length */
           goto pfrse20;                    /* process next data       */
         case ied_frse_act_pdu_rec:         /* receive block active PDU */
         case ied_frse_error_bl_01:         /* receive error block 01  */
           break;                           /* continue                */
         default:
           iml_line_no = __LINE__;
           iml_source_no = 12474;    /* source line no for errors */
           goto pfrse96;
       }
       if ((D_ADSL_RCL1->chc_prot_rt02 & 0XF7) == 0) {
         D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
         if (D_ADSL_RCL1->imc_prot_count_in < 0) {
           iml_line_no = __LINE__;
           iml_source_no = 12479;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
         D_ADSL_RCL1->imc_prot_akku = 0;    /* clear value             */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sch_len;  /* Share Control Header length */
         goto pfrse20;                      /* process next data       */
       }
       iml_line_no = __LINE__;
       iml_source_no = 12486;    /* source line no for errors */
       goto pfrse96;
     case ied_fsfp_rdp4_hash:               /* hash RDP4 block         */
       /* compute how many to copy                                     */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame
                - D_ADSL_RCL1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       memcpy( D_ADSL_RCL1->achc_prot_1,
               adsl_gai1_inp_1->achc_ginp_cur,
               iml1 );
       D_ADSL_RCL1->achc_prot_1 += iml1;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RCL1->imc_pos_inp_frame > D_ADSL_RCL1->imc_prot_2) {
         goto pfrse20;                      /* needs more data         */
       }
       /* check if all data of this frame have been received           */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data in frame */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
       while (TRUE) {                       /* loop over all gather structures input */
         iml1 -= adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
         if (iml1 <= 0) break;              /* enough data found       */
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
#ifdef TRACEHL1
         printf( "s%05d l%05d received from server need more data %d\n",
                 12511,            /* source line no for errors */
                 __LINE__,                  /* line number for errors  */
                 iml1 );                    /* length of data needed   */
#endif
           /* wait for more data                                       */
           goto pfrse80;
         }
       }
#ifdef TRACEHL1
       printf( "s%05d l%05d received from server encrypted 26.10.06 KB\n",
               12525,              /* source line no for errors */
               __LINE__ );                  /* line number for errors  */
#endif
       if ((D_ADSL_RCO1->dsc_encry_se2cl.imc_count_sent & (4096 - 1)) == 0){
         if (D_ADSL_RCO1->dsc_encry_se2cl.imc_count_sent) {
           m_update_keys( D_ADSL_RCO1, &D_ADSL_RCO1->dsc_encry_se2cl, NULL );
         }
       }
       /* decrypt the data where they are                              */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data in frame */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
       while (TRUE) {                       /* loop over all gather structures input */
         iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;      /* only data in this frame */
         RC4( adsl_gai1_inp_w2->achc_ginp_cur, 0, iml2,
              adsl_gai1_inp_w2->achc_ginp_cur, 0,
              D_ADSL_RCO1->dsc_encry_se2cl.chrc_rc4_state );
         iml1 -= iml2;                      /* subtract data decyrpted */
         if (iml1 <= 0) break;              /* all data decrypted      */
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
           iml_line_no = __LINE__;
           iml_source_no = 12546;    /* source line no for errors */
           goto pfrse96;
         }
       }
       /* check the hash now                                       */
#define ACHL_WORK_SHA1 ((int *) chrl_work_2)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
       memcpy( ACHL_WORK_SHA1,
               D_ADSL_RCO1->imrc_sha1_state,
               sizeof(D_ADSL_RCO1->imrc_sha1_state) );
       memcpy( ACHL_WORK_MD5,
               D_ADSL_RCO1->imrc_md5_state,
               sizeof(D_ADSL_RCO1->imrc_md5_state) );
       m_put_le4( ACHL_WORK_UTIL_01, D_ADSL_RCL1->imc_pos_inp_frame );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data in frame */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
       while (TRUE) {                       /* loop over all gather structures input */
         iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;      /* only data in this frame */
         SHA1_Update( ACHL_WORK_SHA1,
                      adsl_gai1_inp_w2->achc_ginp_cur, 0, iml2 );
         iml1 -= iml2;                      /* subtract data processed */
         if (iml1 <= 0) break;              /* all data processed      */
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
           goto pfrse96;                    /* program illogic         */
         }
       }
       if (D_ADSL_RCL1->chc_prot_rt03 & 0X08) {  /* flag for block count */
         m_put_le4( ACHL_WORK_UTIL_01, D_ADSL_RCO1->dsc_encry_se2cl.imc_count_sent );
         SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
       }
       SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
       MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
       MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
       if (memcmp( D_ADSL_RCL1->chrc_prot_1, ACHL_WORK_UTIL_01, D_SIZE_HASH )) {
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d received from server hash invalid",
                       __LINE__, 12584 );  /* line number for errors  */
         iml_line_no = __LINE__;
         iml_source_no = 12585;    /* source line no for errors */
         goto pfrse92;
       }
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
       D_ADSL_RCO1->dsc_encry_se2cl.imc_count_sent++;  /* count block received from server */
       /* data from server decrypted                                   */
       if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
         ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
           = ied_trc_se2cl_decry;           /* server to client, decrypted */
         ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_inp_1;
         ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data */
         ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_record - D_ADSL_RCL1->imc_pos_inp_frame;
         m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
         D_ADSL_RCO1->imc_len_part = D_ADSL_RCL1->imc_pos_inp_frame;  /* length of part */
         ADSL_RDPA_F->dsc_rdptr1.chc_type_disp = 'E';  /* type of displacement */
       }
       if (D_ADSL_RCL1->chc_prot_rt02 & 0X80) {  /* SEC_LICENSE_PKT    */
         if (   (D_ADSL_RCL1->iec_frse_bl != ied_frse_lic_pr_1_rec)  /* receive block licence protocol */
             && (D_ADSL_RCL1->iec_frse_bl != ied_frse_any_pdu_rec)) {  /* ????ive block active PDU */
           iml_line_no = __LINE__;
           iml_source_no = 12607;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes (preamble header) */
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
           iml_line_no = __LINE__;
           iml_source_no = 12618;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
         D_ADSL_RCL1->imc_prot_1 = 0;       /* clear value             */
         D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_type;  /* licencing block to check */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e; /* int little endian (for length) */
         goto pfrse20;                      /* process next data       */
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_lic_pr_1_rec:        /* receive block licence protocol */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
           goto pfrse40;                    /* send RDP4 to client     */
         case ied_frse_any_pdu_rec:         /* receive any PDU type    */
           if ((D_ADSL_RCL1->imc_prot_chno == D_ADSL_RCO1->usc_chno_disp)               /* channel number display  */
               || (D_ADSL_RCL1->imc_prot_chno == D_ADSL_RCO1->usc_chno_mcs_msgchannel)  // MCS MSGChannel's channel number
               ){
             break;                         /* parse Share Control Header */
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 12645;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_rdp4_vch_ulen;  /* virtual channel uncompressed data length */
           goto pfrse20;                    /* process next data       */
         case ied_frse_act_pdu_rec:         /* receive block active PDU */
           break;                           /* continue                */
         default:
           iml_line_no = __LINE__;
           iml_source_no = 12655;    /* source line no for errors */
           goto pfrse96;
       }
       if (D_ADSL_RCL1->chc_prot_rt03 & (SEC_REDIRECTION_PKT >> 8)) {  /* Standard Security Server Redirection PDU */
         if (D_ADSL_RCL1->ac_redirect) {    /* memory for Standard Security Server Redirection PDU */
           iml_line_no = __LINE__;
           iml_source_no = 12667;    /* source line no for errors */
           goto pfrse92;
         }
#ifdef TRACEHL1
         m_sdh_printf( adsp_hl_clib_1, "SEC_REDIRECTION_PKT l%05d s%05d length %d.",
                       __LINE__, 12672,
                       D_ADSL_RCL1->imc_pos_inp_frame );
         m_sdh_console_out( adsp_hl_clib_1, adsl_gai1_inp_1->achc_ginp_cur, D_ADSL_RCL1->imc_pos_inp_frame );
#endif // TRACEHL1
         D_ADSL_RCL1->ac_redirect           /* memory for Standard Security Server Redirection PDU */
           = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, sizeof(int) + D_ADSL_RCL1->imc_pos_inp_frame );
         *((int *) D_ADSL_RCL1->ac_redirect) = D_ADSL_RCL1->imc_pos_inp_frame;
         D_ADSL_RCL1->achc_prot_1 = (char *) D_ADSL_RCL1->ac_redirect + sizeof(int);
         D_ADSL_RCL1->imc_prot_2 = 0;       /* till end of block       */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data       */
         goto pfrse20;                      /* process next data       */
       }
       if (D_ADSL_RCL1->chc_prot_rt03 & (SEC_AUTODETECT_REQ | SEC_HEARTBEAT) >> 8){
          if ((D_ADSL_RCL1->dsc_rdp_co_1.boc_enable_mcs_message_channel == FALSE)
              || (D_ADSL_RCL1->imc_prot_chno != D_ADSL_RCO1->usc_chno_mcs_msgchannel)){
             iml_line_no = __LINE__;
             iml_source_no = 12695;    /* source line no for errors */
             goto pfrse92;
          }
          // NOTE: we do not want to copy anything, but in case all data is not present
          //    in the present frame, we need to return to the correct point somehow, and 
          //    for the virtual channels, this is the way.
          D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame;     // This will result in 0 bytes to copy
          D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;
          D_ADSL_RCL1->iec_frse_bl = ied_frse_rdp4_mcs_msgchannel;
          goto pfrse_mcs_msgchannel;
       }
       if ((D_ADSL_RCL1->chc_prot_rt02 & 0XF7) == 0) {
         D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
         if (D_ADSL_RCL1->imc_prot_count_in < 0) {
           iml_line_no = __LINE__;
           iml_source_no = 12709;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
         D_ADSL_RCL1->imc_prot_akku = 0;    /* clear value             */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sch_len;  /* Share Control Header length */
         goto pfrse20;                      /* process next data       */
       }
       iml_line_no = __LINE__;
       iml_source_no = 12716;    /* source line no for errors */
       goto pfrse96;
     case ied_fsfp_sch_len:                 /* Share Control Header length */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_akku
           |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                << ((D_ADSL_RCL1->imc_prot_aux1 - D_ADSL_RCL1->imc_pos_inp_frame)
                      << 3);
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_count_in) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
       /* length PDU including length bytes                            */
       if (D_ADSL_RCL1->imc_pos_inp_frame != (D_ADSL_RCL1->imc_prot_akku - 2)) {
         iml_line_no = __LINE__;
         iml_source_no = 12732;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_count_in < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12736;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
       D_ADSL_RCL1->imc_prot_pdu_type = 0;  /* clear value             */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sch_pdu_type;  /* Share Control Header PDU type */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_sch_pdu_type:            /* Share Control Header PDU type */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_pdu_type
           |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                << ((D_ADSL_RCL1->imc_prot_aux1 - D_ADSL_RCL1->imc_pos_inp_frame)
                      << 3);
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_count_in) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
       D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_count_in < 0) {
         if (   (D_ADSL_RCL1->imc_pos_inp_frame == 0)
             && (D_ADSL_RCL1->imc_prot_pdu_type == TS_DEACTIVATE_ALL_PDU)) {
           // Ends here: short form not seen in the MS-spec., but in the
           // HOB-internal one (at 14.1) and sent by XP. Doing what old case
           // ied_fsfp_parse_pdu_type (B120722) would have done  WS 05.04.13
           D_ADSL_RCL1->iec_frse_bl = ied_frse_deactivate_all;
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
           goto pfrse40;
         }
         iml_line_no = __LINE__;
         iml_source_no = 12768;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
       D_ADSL_RCL1->imc_prot_akku = 0;      /* clear value             */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sch_pdu_source;  /* Share Control Header PDU source */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_sch_pdu_source:          /* Share Control Header PDU source */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_akku
           |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                << ((D_ADSL_RCL1->imc_prot_aux1 - D_ADSL_RCL1->imc_pos_inp_frame)
                      << 3);
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_count_in) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
       /* end of Share Control Header / TS_SHARECONTROLHEADER          */
        // TODO: it would probably be better to have a switch case instead of multiple ifs...
        if ((D_ADSL_RCL1->imc_prot_pdu_type & 0X0F) == PDUTYPE_DATAPDU) {
            D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;
            if (D_ADSL_RCL1->imc_prot_2 < 0) {
                iml_line_no = __LINE__;
                iml_source_no = 12793;    /* source line no for errors */
                goto pfrse92;
            }
            D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
            D_ADSL_RCL1->imc_prot_1 = 0;       /* clear value             */
            D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sdh_header_1;
            goto pfrse20;
        }
       if (D_ADSL_RCL1->imc_prot_pdu_type == D_DEMAND_ACT_PDU) {  /* is demand active PDU */
         if (   (D_ADSL_RCL1->ac_redirect)  /* memory for Standard Security Server Redirection PDU */
             && (D_ADSL_RCL1->imc_prot_pdu_type == D_DEMAND_ACT_PDU)) {  /* is demand active PDU */
           m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCL1->ac_redirect );
           D_ADSL_RCL1->ac_redirect = NULL;  /* memory for Standard Security Server Redirection PDU */
         }
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
           iml_line_no = __LINE__;
           iml_source_no = 12830;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
         D_ADSL_RCL1->imc_prot_1 = 0;       /* clear value             */
         D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_parse_shareid;  /* get share id */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
         goto pfrse20;                      /* process next data       */
       }
       if (D_ADSL_RCL1->imc_prot_pdu_type == 0x000A) {  /* Standard Security Server Redirection PDU */
         if (D_ADSL_RCL1->ac_redirect) {    /* memory for Standard Security Server Redirection PDU */
           iml_line_no = __LINE__;
           iml_source_no = 12896;    /* source line no for errors */
           goto pfrse96;
         }
         D_ADSL_RCL1->imc_pos_inp_frame -= 2;
         adsl_gai1_inp_1->achc_ginp_cur += 2;
         D_ADSL_RCL1->ac_redirect           /* memory for Standard Security Server Redirection PDU */
           = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, sizeof(int) + D_ADSL_RCL1->imc_pos_inp_frame);
         *((int *) D_ADSL_RCL1->ac_redirect) = D_ADSL_RCL1->imc_pos_inp_frame;
         D_ADSL_RCL1->achc_prot_1 = (char *) D_ADSL_RCL1->ac_redirect + sizeof(int);
         D_ADSL_RCL1->imc_prot_2 = 0;       /* till end of block       */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data       */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->imc_prot_1 = D_ADSL_RCL1->imc_prot_pdu_type;
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
       goto pfrse40;                        /* send RDP4 data to client */
    case ied_fsfp_sdh_header_1:
        while (TRUE) {
            D_ADSL_RCL1->imc_prot_akku
                |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                    << ((D_ADSL_RCL1->imc_prot_aux1 - D_ADSL_RCL1->imc_pos_inp_frame)
                        << 3);
            D_ADSL_RCL1->imc_pos_inp_frame--;
            if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_count_in) break;
            if (adsl_gai1_inp_1->achc_ginp_cur
                >= adsl_gai1_inp_1->achc_ginp_end) {
                goto pfrse20;                    /* needs more data         */
            }
        }
        // Prepare share data header structure:
        memset(&D_ADSL_RCL1->dsc_sdh, 0, sizeof(struct dsd_shared_data_header));
        D_ADSL_RCL1->dsc_sdh.umc_share_id = D_ADSL_RCL1->imc_prot_akku;
        // Prepare for next field to be read:
        D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 4;
        if (D_ADSL_RCL1->imc_prot_count_in < 0) {
            iml_line_no = __LINE__;
            iml_source_no = 12939;    /* source line no for errors */
            goto pfrse92;
        }
        D_ADSL_RCL1->imc_prot_akku = 0;
        D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
        D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sdh_header_2;
        goto pfrse20;                        /* process next data       */
     case ied_fsfp_sdh_header_2:
        while (TRUE) {
            D_ADSL_RCL1->imc_prot_akku
                |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                    << ((D_ADSL_RCL1->imc_prot_aux1 - D_ADSL_RCL1->imc_pos_inp_frame)
                        << 3);
            D_ADSL_RCL1->imc_pos_inp_frame--;
            if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_count_in) break;
            if (adsl_gai1_inp_1->achc_ginp_cur
                >= adsl_gai1_inp_1->achc_ginp_end) {
                goto pfrse20;                    /* needs more data         */
            }
        }
        // Fill header structure:
        D_ADSL_RCL1->dsc_sdh.uchc_stream_id = ((D_ADSL_RCL1->imc_prot_akku & 0x0000FF00) >> 8);
        D_ADSL_RCL1->dsc_sdh.usc_uncompressed_length = ((D_ADSL_RCL1->imc_prot_akku & 0xFFFF0000) >> 16);
        // Prepare for next field to be read:
        D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 4;
        if (D_ADSL_RCL1->imc_prot_count_in < 0) {
            iml_line_no = __LINE__;
            iml_source_no = 12964;    /* source line no for errors */
            goto pfrse92;
        }
        D_ADSL_RCL1->imc_prot_akku = 0;
        D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
        D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sdh_header_3;
        goto pfrse20;                        /* process next data       */
     case ied_fsfp_sdh_header_3:
        while (TRUE) {
            D_ADSL_RCL1->imc_prot_akku
                |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                    << ((D_ADSL_RCL1->imc_prot_aux1 - D_ADSL_RCL1->imc_pos_inp_frame)
                        << 3);
            D_ADSL_RCL1->imc_pos_inp_frame--;
            if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_count_in) break;
            if (adsl_gai1_inp_1->achc_ginp_cur
                >= adsl_gai1_inp_1->achc_ginp_end) {
                goto pfrse20;                    /* needs more data         */
            }
        }
        // Prepare share data header structure:
        D_ADSL_RCL1->dsc_sdh.uchc_pdu_type_2 = (D_ADSL_RCL1->imc_prot_akku & 0xFF);
        D_ADSL_RCL1->dsc_sdh.uchc_compressed_type = ((D_ADSL_RCL1->imc_prot_akku & 0x0000FF00) >> 8);
        D_ADSL_RCL1->dsc_sdh.usc_compressed_length = ((D_ADSL_RCL1->imc_prot_akku & 0xFFFF0000) >> 16);

        // Check pdu type 2 to divert:
        switch(D_ADSL_RCL1->dsc_sdh.uchc_pdu_type_2){
           case PDUTYPE2_MONITOR_LAYOUT_PDU :
               D_ADSL_RCL1->imc_prot_save2 = D_ADSL_RCL1->imc_pos_inp_frame;
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_datapdu_monitor_layout;
               D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;
               goto pfrse20;
           case PDUTYPE2_SYNCHRONIZE:
               D_ADSL_RCL1->imc_prot_save2 = D_ADSL_RCL1->imc_pos_inp_frame;
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_datapdu_synchronize;
               D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;
               goto pfrse20;
           case PDUTYPE2_SAVE_SESSION_INFO:
               D_ADSL_RCL1->imc_prot_save2 = D_ADSL_RCL1->imc_pos_inp_frame;
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_datapdu_save_session_info;
               D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;
               goto pfrse20;
           default:
               // Ignore rest of PDU:
                D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
                D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
                goto pfrse40;                      /* send RDP4 data to client */
           }
        // Prepare for next field to be read:
        D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;
        if (D_ADSL_RCL1->imc_prot_count_in < 0) {
            iml_line_no = __LINE__;
            iml_source_no = 13014;    /* source line no for errors */
            goto pfrse92;
        }
        D_ADSL_RCL1->imc_prot_akku = 0;
        D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
        goto pfrse20;                        /* process next data       */
     case ied_fsfp_int_lit_e:               /* int little endian       */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_1
           |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                << ((D_ADSL_RCL1->imc_prot_3 - D_ADSL_RCL1->imc_pos_inp_frame)
                      << 3);
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_start:               /* first block from server */
           if (D_ADSL_RCL1->imc_prot_save1 < 0) {  /* first retrieve type */
             D_ADSL_RCL1->imc_prot_save1 = D_ADSL_RCL1->imc_prot_akku;  /* save type */
             D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
             D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RCL1->imc_prot_akku = 0;  /* clear value           */
             goto pfrse20;                  /* process next data       */
           }
           /** from Sebastian Sommer, 18.01.14
              Various flags seen here, e.g. Server 2003:100:1000:e40::4 W2K12R2 sends all four: 0x0F02.
              See [MS-RDPBCGR] v20121017 2.2.1.2.1 (RDP_NEG_RSP); LSB is type, MSB is flags
           */
           if (   ((D_ADSL_RCL1->imc_prot_save1 & 0XFF) != 0X0002)  /* check type */
               && ((D_ADSL_RCL1->imc_prot_save1 & 0XFF) != 0X0003)) {  /* check type error */
                iml_line_no = __LINE__;
                iml_source_no = 13060;    /* source line no for errors */
                goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_prot_akku != (2 + 2 + 4)) {  /* check length */
             iml_line_no = __LINE__;
             iml_source_no = 13064;    /* source line no for errors */
             goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame != 4) {  /* check till end of frame */
             iml_line_no = __LINE__;
             iml_source_no = 13067;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_akku = 0;  /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_sta_02;  /* start second field */
           goto pfrse20;                    /* process next data       */
         case ied_frse_sta_02:              /* start second field      */
            adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.usc_type = (D_ADSL_RCL1->imc_prot_save1 & 0XFF);
            adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.usc_flags = (D_ADSL_RCL1->imc_prot_save1 >> 8) & 0xff;

            if (!m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1, sizeof(struct dsd_se_co1) + sizeof(struct dsd_rdp_neg_resp))) {
               iml_line_no = __LINE__;
               iml_source_no = 13136;    /* source line no for errors */
               goto pfrse96;
            }
            ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1) + sizeof(struct dsd_rdp_neg_resp);
            memset(ADSL_OA1->achc_upper, 0, sizeof(struct dsd_se_co1) + sizeof(struct dsd_rdp_neg_resp));
            {
               struct dsd_se_co1* adsl_server_command = (struct dsd_se_co1*) ADSL_OA1->achc_upper;
               struct dsd_rdp_neg_resp* adsl_rdp_neg_resp = (struct dsd_rdp_neg_resp*)(adsl_server_command + 1);
               adsl_server_command->iec_se_command = ied_sec_rdp_neg_resp;  /* request parameters for dynamic connect */
               memcpy(adsl_rdp_neg_resp, &adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp, sizeof(struct dsd_rdp_neg_resp));
               *ADSL_OA1->aadsc_se_co1_chain = adsl_server_command;  /* append to chain */
               ADSL_OA1->aadsc_se_co1_chain = &adsl_server_command->adsc_next;  /* set new end of chain */
               //D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_no_session;  /* no more session */
               if (adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.usc_type == TYPE_RDP_NEG_RSP) {  /* check type */
                  adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.umc_selected_protocol = D_ADSL_RCL1->imc_prot_akku;
                  adsl_rdp_neg_resp->umc_selected_protocol = D_ADSL_RCL1->imc_prot_akku;
                  if(adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.umc_selected_protocol != PROTOCOL_RDP)
                     goto pfrse20;                    /* process next data       */
                  goto pfrse_send_secbl;         /* send second block to server */
               }
               if (adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.usc_type == TYPE_RDP_NEG_FAILURE) {
                  adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.umc_failure_code = D_ADSL_RCL1->imc_prot_akku;
                  adsl_rdp_neg_resp->umc_failure_code = D_ADSL_RCL1->imc_prot_akku;
                  // TODO: (suggested by Mr. Stefan Martin)instead of printing the error message, provide a callbackk or a 
                  //     another method where the RDPAcc caller could get the error code and print the error message (if wanted so).
                  switch (adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.umc_failure_code){
                  case SSL_REQUIRED_BY_SERVER:
                      achl1 = "SSL_REQUIRED_BY_SERVER";
                      break;
                  case SSL_NOT_ALLOWED_BY_SERVER:
                      achl1 = "SSL_NOT_ALLOWED_BY_SERVER";
                      break;
                  case SSL_CERT_NOT_ON_SERVER:
                      achl1 = "SSL_CERT_NOT_ON_SERVER";
                      break;
                  case INCONSISTENT_FLAGS:
                      achl1 = "INCONSISTENT_FLAGS";
                      break;
                  case HYBRID_REQUIRED_BY_SERVER:
                      achl1 = "HYBRID_REQUIRED_BY_SERVER";
                      break;
                  case SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER:
                      achl1 = "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER";
                      break;
                  default:
                      achl1 = "Unknown error code";
                  }
                  m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d error: TYPE_RDP_NEG_FAILURE received with failure code 0x%08X - %s",
                         __LINE__, 13215,  /* line number for errors */
                         D_ADSL_RCL1->imc_prot_akku, achl1 );
                  iml_line_no = __LINE__;
                  iml_source_no = 13217;    /* source line no for errors */
                  goto pfrse96;
               }
               achl1 = "Unknown value in X.224 Connection Confirm PDU";
               m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d error: RDP Negotiation failed 0x%08X - %s",
                         __LINE__, 13221,  /* line number for errors */
                         adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.usc_type, achl1 );
               iml_line_no = __LINE__;
               iml_source_no = 13223;    /* source line no for errors */
               goto pfrse96;
            }
           goto p_cleanup_00;               /* do cleanup now          */
         case ied_frse_rec_04:              /* record 4 received       */
           if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_1) {
             iml_line_no = __LINE__;
             iml_source_no = 13231;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_tag;
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_sel_t:           /* block 4 selection tag   */
           switch (D_ADSL_RCL1->imc_prot_1) {
             case 0X0C01:                   /* version tag             */
               D_ADSL_RCL1->imc_prot_5 = 1;  /* type of tag            */
               break;
             case 0X0C02:                   /* encryption tag          */
               D_ADSL_RCL1->imc_prot_5 = 2;  /* type of tag            */
               break;
             case 0X0C03:                   /* virtual channel tag     */
               D_ADSL_RCL1->imc_prot_5 = 4;  /* type of tag            */
               break;
             case SC_MCS_MSGCHANNEL:            // 0x0C04
               D_ADSL_RCL1->imc_prot_5 = 8;     /* type of tag            */
               break;
             default:
               iml_line_no = __LINE__;
               iml_source_no = 13252;    /* source line no for errors */
               goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_prot_5 & D_ADSL_RCL1->imc_prot_4) {
             iml_line_no = __LINE__;
             iml_source_no = 13255;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_4 |= D_ADSL_RCL1->imc_prot_5;
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_l;  /* block 4 selection length */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13261;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_sel_l:           /* block 4 selection length */
           D_ADSL_RCL1->imc_prot_1 -= 4;    /* minus tag and length    */
           if (D_ADSL_RCL1->imc_prot_1 <= 0) {  /* check length        */
             iml_line_no = __LINE__;
             iml_source_no = 13269;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                     - D_ADSL_RCL1->imc_prot_1;
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13274;    /* source line no for errors */
             goto pfrse92;
           }
           switch (D_ADSL_RCL1->imc_prot_5) {  /* type of field        */
             case 1:                        /* version tag             */
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r04_rdp_v;  /* block 4 RDP version */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_rdp_v;  /* block 4 RDP version */
               goto pfrse20;                /* needs more data         */
             case 2:                        /* encryption tag          */
               D_ADSL_RCL1->imc_prot_6 = D_ADSL_RCL1->imc_prot_2;  /* save end */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sec_method;  /* block 4 security method */
               D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
               if (D_ADSL_RCL1->imc_prot_2 < 0) {
                 iml_line_no = __LINE__;
                 iml_source_no = 13290;    /* source line no for errors */
                 goto pfrse92;
               }
               D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RCL1->imc_prot_1 = 0;  /* clear value            */
               goto pfrse20;                /* needs more data         */
             case 4:                        /* virtual channel tag     */
               D_ADSL_RCL1->imc_prot_6 = D_ADSL_RCL1->imc_prot_2;  /* save end */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_ch_disp;  /* block 4 display channel */
               D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
               if (D_ADSL_RCL1->imc_prot_2 < 0) {
                 iml_line_no = __LINE__;
                 iml_source_no = 13300;    /* source line no for errors */
                 goto pfrse92;
               }
               D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RCL1->imc_prot_1 = 0;  /* clear value            */
               goto pfrse20;                /* needs more data         */
             case 8:                            // MCS message channel
               D_ADSL_RCL1->imc_prot_6 = D_ADSL_RCL1->imc_prot_2;  /* save end */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_mcs_msgchannel;  /* block 4 display channel */
               D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
               if (D_ADSL_RCL1->imc_prot_2 < 0) {
                  iml_line_no = __LINE__;
                  iml_source_no = 13311;    /* source line no for errors */
                  goto pfrse92;
               }
               D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RCL1->imc_prot_1 = 0;  /* clear value            */
               goto pfrse20;                /* needs more data         */
           }
             iml_line_no = __LINE__;
             iml_source_no = 13318;    /* source line no for errors */
             goto pfrse92;
         case ied_frse_r04_ch_disp:         /* block 4 display channel */
/* 18.12.04 KB UUUU */
           D_ADSL_RCO1->usc_chno_disp = (unsigned short int) D_ADSL_RCL1->imc_prot_1;
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_vch_no;  /* block 4 no virtual channels */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13329;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_mcs_msgchannel:                         // MCS message channel
           D_ADSL_RCO1->usc_chno_mcs_msgchannel = (unsigned short int) D_ADSL_RCL1->imc_prot_1;
           if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* end of block */
              D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* first record type */
              D_ADSL_RCL1->iec_frse_bl = ied_frse_rec_07;
              goto pfrse_send_erect_domain_request_pdu;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
              iml_line_no = __LINE__;
              iml_source_no = 13346;    /* source line no for errors */
              goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_vch_no:          /* block 4 no virtual channels */
           if (D_ADSL_RCL1->imc_prot_1 != D_ADSL_RCO1->imc_no_virt_ch) {
             iml_line_no = __LINE__;
             iml_source_no = 13354;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_7 = D_ADSL_RCL1->imc_prot_1;  /* number of fields */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_vch_var;  /* block 4 variable channel */
           if (D_ADSL_RCL1->imc_prot_1 == 0) {
             D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_vch_del;  /* block 4 vch delemiter */
             /* check if already block end                             */
             if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_6) {
               /* 17.05.05 KB - end if block not implemented           */
               if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* end of block */
                 M_ERROR_FRSE_ILLOGIC       /* program illogic         */
               }
               D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
             }
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13371;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_vch_var:         /* block 4 variable channel */
           (D_ADSL_RCO1->adsrc_vc_1 + (D_ADSL_RCO1->imc_no_virt_ch - D_ADSL_RCL1->imc_prot_7))
               ->usc_vch_no
             = (unsigned short int) D_ADSL_RCL1->imc_prot_1;
           D_ADSL_RCL1->imc_prot_7--;       /* number of fields        */
           if (D_ADSL_RCL1->imc_prot_7 == 0) {  /* was last virtual channel */
             /* output all virtual channels                            */
             if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
               ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
                 = ied_trc_virt_ch;         /* virtual channels        */
               ADSL_RDPA_F->dsc_rdptr1.achc_trace_input = (char *) D_ADSL_RCO1->adsrc_vc_1;  /* addr trace-input */
               ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RCO1->imc_no_virt_ch;  /* number of channels */
               m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
             }
             D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_vch_del;  /* block 4 vch delemiter */
             /* check if already block end                             */
             if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_6) {
               /* 17.05.05 KB - end if block not implemented           */
               if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* end of block */
                 M_ERROR_FRSE_ILLOGIC       /* program illogic         */
               }
               D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
             }
           } else if (D_ADSL_RCL1->imc_pos_inp_frame <= D_ADSL_RCL1->imc_prot_6) {
             iml_line_no = __LINE__;
             iml_source_no = 13402;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13406;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_vch_del:         /* block 4 vch delemiter   */
           if (D_ADSL_RCL1->imc_prot_1) {   /* must be zero            */
             iml_line_no = __LINE__;
             iml_source_no = 13413;    /* source line no for errors */
             goto pfrse92;
           }
           /* check end of this sequence                               */
           if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_6) {
             iml_line_no = __LINE__;
             iml_source_no = 13417;    /* source line no for errors */
             goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* end of block */
             if (D_ADSL_RCL1->imc_prot_4 != 7) {
               iml_line_no = __LINE__;
               iml_source_no = 13421;    /* source line no for errors */
               goto pfrse92;
             }
/* 19.12.04 KB - at end of block - not implemented */
             iml_line_no = __LINE__;
             iml_source_no = 13424;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13429;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_sec_method:         /* block 4 security method */
            D_ADSL_RCO1->imc_sec_method = D_ADSL_RCL1->imc_prot_1; 
            switch (D_ADSL_RCO1->imc_sec_method){
               case ENCRYPTION_METHOD_NONE:                     // 0x00000000
                    achl1 = "ENCRYPTION_METHOD_NONE";
                    goto LBL_METHOD_SUPPORTED;
                case ENCRYPTION_METHOD_40BIT:                   // 0x00000001
                    achl1 = "ENCRYPTION_METHOD_40BIT";
                    goto LBL_METHOD_SUPPORTED;
                case ENCRYPTION_METHOD_128BIT:                  // 0x00000002
                    achl1 = "ENCRYPTION_METHOD_128BIT";
                    goto LBL_METHOD_SUPPORTED;
                case ENCRYPTION_METHOD_56BIT:                   // 0x00000008
                    achl1 = "ENCRYPTION_METHOD_56BIT";
                    goto LBL_METHOD_SUPPORTED;
                case ENCRYPTION_METHOD_FIPS:                     // 0x00000010
                    // 2017.03.30 DD: after talking to KB, he says that FIPS is not going to be supported.
                    achl1 = "ENCRYPTION_METHOD_FIPS";
                    goto LBL_METHOD_NOT_SUPPORTED;
                default:
                    achl1 = "Unknown method";
                    goto LBL_METHOD_NOT_SUPPORTED;
           }
LBL_METHOD_NOT_SUPPORTED:
           m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d error: Encryption method selected by server is not supported: 0x%08X - %s",
                     __LINE__, 13463,  /* line number for errors */
                     D_ADSL_RCO1->imc_sec_method, achl1 );
           iml_line_no = __LINE__;
           iml_source_no = 13465;    /* source line no for errors */
           goto pfrse92;

LBL_METHOD_SUPPORTED:
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sec_level;  /* block 4 security level  */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13472;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_sec_level:       /* block 4 security level  */
           D_ADSL_RCO1->imc_sec_level = D_ADSL_RCL1->imc_prot_1;
           switch (D_ADSL_RCO1->imc_sec_level){
           case ENCRYPTION_LEVEL_NONE:                  // 0x00
                if (D_ADSL_RCO1->imc_sec_method != ENCRYPTION_METHOD_NONE){
                    achl1 = "Inconsistent selection of encryption method and encryption level";
                }
                goto LBL_SEC_LEVEL_CONTINUE;
            case ENCRYPTION_LEVEL_LOW:                  // 0x01
                // TODO: ask KB and configure RDPAcc for this specific situation if needed.
                goto LBL_SEC_LEVEL_RDP_CHECK_CONSISTENCY;
            case ENCRYPTION_LEVEL_CLIENT_COMPATIBLE:    // 0x02
                // TODO: ask KB and configure RDPAcc for this specific situation if needed.
                goto LBL_SEC_LEVEL_RDP_CHECK_CONSISTENCY;
            case ENCRYPTION_LEVEL_HIGH:                 // 0x03
                // TODO: ask KB and configure RDPAcc for this specific situation if needed.
                goto LBL_SEC_LEVEL_RDP_CHECK_CONSISTENCY;
            case ENCRYPTION_LEVEL_FIPS:                 // 0x04
                // break;   // 2017.03.30 DD: FIPS is not supported, and therefore we should drop the connection. 
                achl1 = "Encryption level not supported - ENCRYPTION_LEVEL_FIPS";
                goto LBL_SEC_LEVEL_ERROR;
            default:
                achl1 = "Encryption level unknown";
                goto LBL_SEC_LEVEL_ERROR;
            }

LBL_SEC_LEVEL_RDP_CHECK_CONSISTENCY:
            if ((D_ADSL_RCO1->imc_sec_method == ENCRYPTION_LEVEL_LOW) ||
                (D_ADSL_RCO1->imc_sec_method == ENCRYPTION_LEVEL_CLIENT_COMPATIBLE) ||
                (D_ADSL_RCO1->imc_sec_method == ENCRYPTION_LEVEL_HIGH)){
                goto LBL_SEC_LEVEL_CONTINUE;
            }
            achl1 = "Inconsistent selection of encryption method and encryption level";

LBL_SEC_LEVEL_ERROR:
            m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d error: Encryption method selected by server is not supported: 0x%08X - %s",
                         __LINE__, 13514,  /* line number for errors */
                         D_ADSL_RCO1->imc_sec_method, achl1 );
            iml_line_no = __LINE__;
            iml_source_no = 13516;    /* source line no for errors */
            goto pfrse92;

LBL_SEC_LEVEL_CONTINUE:
            if(D_ADSL_RCO1->imc_sec_level == 0) {
               ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.umc_loinf_options &= ~INFO_FORCE_ENCRYPTED_CS_PDU;
               // TODO: Remove certificate
               if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* end of block */
                  if (D_ADSL_RCL1->imc_prot_4 != 7) {  /* not all fields received */
                     iml_line_no = __LINE__;
                     iml_source_no = 13526;    /* source line no for errors */
                     goto pfrse92;
                  }
                  D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* first record type */
                  D_ADSL_RCL1->iec_frse_bl = ied_frse_rec_07;
                  goto pfrse_send_erect_domain_request_pdu;
               }
               D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
               D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
               if (D_ADSL_RCL1->imc_prot_2 < 0) {
                  iml_line_no = __LINE__;
                  iml_source_no = 13535;    /* source line no for errors */
                  goto pfrse92;
               }
               D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
               goto pfrse20;                    /* process next data       */
            }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_l_serv_rand;  /* block 4 length server random */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13572;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_l_serv_rand:     /* block 4 length server random */
           if (D_ADSL_RCL1->imc_prot_1 != sizeof(ADSL_RDPA_F->chrc_server_random)) {
             iml_line_no = __LINE__;
             iml_source_no = 13579;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_7 = D_ADSL_RCL1->imc_prot_1;  /* save length */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_l_pub_par;  /* block 4 length public parameters */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13585;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_l_pub_par:       /* block 4 length public parameters */
           if ((D_ADSL_RCL1->imc_prot_7 + D_ADSL_RCL1->imc_prot_1 + D_ADSL_RCL1->imc_prot_6)
                 != D_ADSL_RCL1->imc_pos_inp_frame) {
             iml_line_no = __LINE__;
             iml_source_no = 13593;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCO1->imc_l_pub_par = D_ADSL_RCL1->imc_prot_1;
           /* get server-random                                        */
           D_ADSL_RCL1->achc_prot_1 = ADSL_RDPA_F->chrc_server_random;
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                     - sizeof(ADSL_RDPA_F->chrc_server_random);
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13601;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_d_serv_rand;  /* copy server random */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data     */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_type_pub_par:    /* block 4 type public parameters */
           if (D_ADSL_RCL1->imc_prot_1 == D_TYPE_PUB_PAR_DIR) {
             D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 8;  /* number of bytes */
             if (D_ADSL_RCL1->imc_prot_2 < 0) {
               iml_line_no = __LINE__;
               iml_source_no = 13619;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_ppdir_tag;  /* get public parms direct tag */
             D_ADSL_RCL1->imc_prot_5 = 0;   /* no value before         */
             goto pfrse20;                  /* process next data       */
           }
           if ((D_ADSL_RCL1->imc_prot_1 & 0X7FFFFFFF) != D_TYPE_PUB_PAR_CERT) {
             iml_line_no = __LINE__;
             iml_source_no = 13627;    /* source line no for errors */
             goto pfrse92;
           }
           /* data from server certificate                             */
           if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
             ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
              = ied_trc_server_cert;        /* server certificate      */
             ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_inp_1;
             ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input
               = D_ADSL_RCL1->imc_pos_inp_frame - D_ADSL_RCL1->imc_prot_6;  /* remaining data */
             ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_record - D_ADSL_RCL1->imc_pos_inp_frame;
             m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
           }
           iml1 = D_ADSL_RCL1->imc_pos_inp_frame - D_ADSL_RCL1->imc_prot_6;
       /* generated from macro M_TMPBUF_CL_1()                         */
       if (iml1 > D_ADSL_RCL1->imc_len_temp) {
         D_ADSL_RCL1->imc_len_temp = iml1;
         ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
         ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
         if (D_ADSL_RCL1->ac_temp_buffer) {  /* buffer already allocated */
           m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCL1->ac_temp_buffer );
         }
         D_ADSL_RCL1->ac_temp_buffer
           = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCL1->imc_len_temp );
       }
           D_ADSL_RCL1->achc_prot_1 = (char *) D_ADSL_RCL1->ac_temp_buffer;
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_d_pub_par;  /* block 4 data public parameters */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_prot_6;  /* till end of this part */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data     */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_ppdir_tag:       /* block 4 public parms direct tag */
           switch (D_ADSL_RCL1->imc_prot_1) {  /* check if tag valid   */
             case D_PPDIR_PUB_VAL:          /* public parms direct public value */
             case D_PPDIR_SIG:              /* public parms direct signature */
               break;
             default:
               iml_line_no = __LINE__;
               iml_source_no = 13655;    /* source line no for errors */
               goto pfrse92;
           }
           /* check if tag double                                      */
           if (D_ADSL_RCL1->imc_prot_1 == D_ADSL_RCL1->imc_prot_5) {
             iml_line_no = __LINE__;
             iml_source_no = 13659;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_4 = D_ADSL_RCL1->imc_prot_1;  /* save ppdir type */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13664;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_ppdir_len;  /* get public parms direct length */
//         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_ppdir_len:       /* block 4 public parms direct lenght */
           if (D_ADSL_RCL1->imc_prot_1 > D_ADSL_RCL1->imc_pos_inp_frame) {
             iml_line_no = __LINE__;
             iml_source_no = 13676;    /* source line no for errors */
             goto pfrse92;
           }
           switch (D_ADSL_RCL1->imc_prot_4) {  /* proceed depending on tag */
             case D_PPDIR_PUB_VAL:          /* public parms direct public value */
               D_ADSL_RCL1->imc_prot_6 = D_ADSL_RCL1->imc_prot_1;  /* save length */
               D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_prot_1;
               iml1 = sizeof(D_ADSL_RCL1->chrc_prot_1);
               break;
             case D_PPDIR_SIG:              /* public parms direct signature */
               D_ADSL_RCL1->imc_prot_7 = D_ADSL_RCL1->imc_prot_1;  /* save length */
               D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_prot_2;
               iml1 = sizeof(D_ADSL_RCL1->chrc_prot_2);
               break;
             default:
               M_ERROR_FRSE_ILLOGIC         /* program illogic         */
           }
           if (D_ADSL_RCL1->imc_prot_1 > iml1) {  /* longer than field */
             iml_line_no = __LINE__;
             iml_source_no = 13693;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                     - D_ADSL_RCL1->imc_prot_1;
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13698;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data     */
           goto pfrse20;                    /* process next data       */
         case ied_frse_error_bl_02:         /* receive error block 02  */
           if (D_ADSL_RCL1->imc_prot_1 == D_XYZ_ERROR) {  /* ??? 04.06.11 KB */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
             goto pfrse40;                  /* send RDP4 to client     */
           }
           iml_line_no = __LINE__;
           iml_source_no = 13721;    /* source line no for errors */
           goto pfrse92;
         case ied_frse_actpdu_parse_shareid: /* shareid */
           // Save shared ID
           D_ADSL_RCO1->imc_shareid = D_ADSL_RCL1->imc_prot_1;
           // Next is source descriptor
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13728;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_sdl;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_sdl:          /* get source descriptor length */
           if (D_ADSL_RCL1->imc_prot_1 != sizeof(ucrs_source_desc)) {
             iml_line_no = __LINE__;
             iml_source_no = 13737;    /* source line no for errors */
             goto pfrse92;
           }
           /* get 2 bytes little endian again                          */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13748;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_len_cap;  /* get length capabilities */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_len_cap:      /* get length capabilities */
           if (D_ADSL_RCL1->imc_pos_inp_frame < D_ADSL_RCL1->imc_prot_1) {
             iml_line_no = __LINE__;
             iml_source_no = 13776;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_save2 = D_ADSL_RCL1->imc_prot_akku - sizeof(ucrs_source_desc);  /* length of capabilities */
           D_ADSL_RCL1->imc_prot_4
             = D_ADSL_RCL1->imc_pos_inp_frame
               - D_ADSL_RCL1->imc_prot_1
               - sizeof(ucrs_source_desc);
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_constant;  /* compare with constant */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* position                */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_no_cap:       /* get number capabilities */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_actpdu_no_cap;
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_cap_ind:      /* get capabilities index  */
           D_ADSL_RCL1->imc_prot_6 = D_ADSL_RCL1->imc_prot_1;  /* save no cap */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13836;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
//         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_cap_len;  /* get capabilities length */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_cap_len:      /* get capabilities length */
           D_ADSL_RCL1->imc_prot_1 -= 4;    /* minus length index and length */
           if (D_ADSL_RCL1->imc_prot_1 < 0) {  /* less than minimum length */
             iml_line_no = __LINE__;
             iml_source_no = 13846;    /* source line no for errors */
             goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_prot_1) {   /* value follows    */
             D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - D_ADSL_RCL1->imc_prot_1;
             if (D_ADSL_RCL1->imc_prot_2 < D_ADSL_RCL1->imc_prot_4) {
               iml_line_no = __LINE__;
               iml_source_no = 13851;    /* source line no for errors */
               goto pfrse92;
             }
             if (D_ADSL_RCL1->imc_prot_1 > sizeof(D_ADSL_RCL1->chrc_prot_1)) {
               iml_line_no = __LINE__;
               iml_source_no = 13854;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_prot_1;
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data   */
             goto pfrse20;                  /* process next data       */
           }
           switch (D_ADSL_RCL1->imc_prot_6) {
/* UUUU code missing */
           }
           D_ADSL_RCL1->imc_prot_5--;       /* one capability less     */
           if (D_ADSL_RCL1->imc_prot_5) {   /* more to follow          */
             D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
             if (D_ADSL_RCL1->imc_prot_2 < 0) {
               iml_line_no = __LINE__;
               iml_source_no = 13867;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RCL1->imc_prot_1 = 0;   /* clear value             */
//           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_cap_ind;  /* get capabilities index */
             goto pfrse20;                    /* process next data       */
           }
           /* check if till end of capabilities                        */
           if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_4) {
             iml_line_no = __LINE__;
             iml_source_no = 13877;    /* source line no for errors */
             goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame != 4) {
             iml_line_no = __LINE__;
             iml_source_no = 13880;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = 0;     /* number of bytes         */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_big_e;  /* int big endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_trail;  /* trailer of act PDU */
           goto pfrse20;                    /* process next data       */
         case ied_frse_deaap_rec:           /* Deactivate All PDU Data */
           if (D_ADSL_RCL1->imc_prot_akku != D_ADSL_RCL1->imc_pos_inp_frame) {  /* not as many as remaining bytes */
             iml_line_no = __LINE__;
             iml_source_no = 13889;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_prot_akku;  /* number of bytes */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_cmp_zero;  /* compare with zeroes */
           goto pfrse20;                    /* process next data       */
         case ied_frse_rdp4_vch_ulen:       /* virtual channel uncompressed data length */
           D_ADSL_RCL1->umc_vch_ulen = D_ADSL_RCL1->imc_prot_1;  /* virtual channel length uncompressed */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - sizeof(D_ADSL_RCL1->chrc_vch_flags);
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 13898;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_vch_flags;
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data     */
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_type:         /* licencing block to check */
           if ((D_ADSL_RCL1->imc_prot_1 & 0x00007E00) != 0x0200) {
             iml_line_no = __LINE__;
             iml_source_no = 13905;    /* source line no for errors */
             goto pfrse92;
           }
           if ((((unsigned int) (D_ADSL_RCL1->imc_prot_1)) >> 16)
                 != (D_ADSL_RCL1->imc_pos_inp_frame + 4)) {
             iml_line_no = __LINE__;
             iml_source_no = 13909;    /* source line no for errors */
             goto pfrse92;
           }
           switch (D_ADSL_RCL1->imc_prot_1 & 0XFF) {
             case 0X01:                     /* LICENSE_REQUEST         */
               if (D_ADSL_RCO1->adsc_lic_neg) {
                 iml_line_no = __LINE__;
                 iml_source_no = 13914;    /* source line no for errors */
                 goto pfrse92;
               }
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->adsc_lic_neg) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, sizeof(struct dsd_rdp_lic_d) );
               D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 = NULL;  /* init  */
               D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len = 0;  /* init  */
               D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data = NULL;  /* init  */
               D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand);  /* number of bytes */
               if (D_ADSL_RCL1->imc_prot_2 < 0) {
                 iml_line_no = __LINE__;
                 iml_source_no = 13941;    /* source line no for errors */
                 goto pfrse92;
               }
               D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand;  /* licensing server random */
               D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers = (unsigned char) (D_ADSL_RCL1->imc_prot_1 >> 8);  /* licensing version and some poorly documented "ExtendedError supported" flag */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_req_rand;  /* server license request */
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data */
               goto pfrse20;                /* process next data       */
             case 0X02:                     /* PLATFORM_CHALLENGE      */
               D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 6;  /* number of bytes */
               if (D_ADSL_RCL1->imc_prot_2 < 0) {
                 iml_line_no = __LINE__;
                 iml_source_no = 13951;    /* source line no for errors */
                 goto pfrse92;
               }
               D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers = (unsigned char) (D_ADSL_RCL1->imc_prot_1 >> 8);  /* licensing version and some poorly documented "ExtendedError supported" flag */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_chll;  /* platform challenge */
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data */
               goto pfrse20;                /* process next data       */
             case 0XFF:                     /* ERROR_ALERT (may be success) */
               /* licensing data no more needed, free the memory  */
//if ndf HELP$CL$01;  22.07.11 KB
               if (D_ADSL_RCO1->adsc_lic_neg) {
                 ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
                 ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
                 if (D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data)
                   m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data );
                 if (D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1)
                   m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 );
                 m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg );
                 D_ADSL_RCO1->adsc_lic_neg = NULL;
               }
//iff;  22.07.11 KB
// to-do 16.06.10 KB - with Mr. Sommer
//cend;  22.07.11 KB
               D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
               if (D_ADSL_RCL1->imc_prot_2 < 0) {
                 iml_line_no = __LINE__;
                 iml_source_no = 13983;    /* source line no for errors */
                 goto pfrse92;
               }
               D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_lic_error_mes1;
               goto pfrse20;                /* process next data       */
             case 0X03:                     /* NEW_LICENSE             */
             case 0X04:                     /* UPGRAD_LICENSE          */
                D_ADSL_RCO1->boc_licensing_done = TRUE;
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
               goto pfrse40;                /* send RDP4 to client     */
             default:
               iml_line_no = __LINE__;
               iml_source_no = 14017;    /* source line no for errors */
               goto pfrse92;
           }
         case ied_frse_lic_pr_req_rand:     /* server license request (after) random */
           D_ADSL_RCL1->imc_prot_5 = D_ADSL_RCL1->imc_prot_1;  /* save RDP version temporarily here */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 14023;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           //D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_req_cert;  /* server license request certificate */
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_req_cert:     /* server license request (before) certificate */
           D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len = 4 + 4 + D_ADSL_RCL1->imc_prot_1 + sizeof(ucrs_lic_bef_cert) + 2;
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len );
           m_put_le4( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1, D_ADSL_RCL1->imc_prot_5 );  /* RDP version */
           m_put_le4( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 4, D_ADSL_RCL1->imc_prot_1 );  /* cbCompanyName (Length of pbCompanyName) */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - (D_ADSL_RCL1->imc_prot_1 + sizeof(ucrs_lic_bef_cert) + 2);  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 14037;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 4 + 4;  /* start of pbCompanyName */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data     */
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_chll:         /* platform challenge      */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                 - (D_ADSL_RCL1->imc_prot_1 + 16);  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 14046;    /* source line no for errors */
             goto pfrse92;
           }
           if (D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len < (2 + D_ADSL_RCL1->imc_prot_1 + 16)) {  /* not big enough */
             ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
             ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
             if (D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len) {
               /* chrc_lic_1 already used (for licensing certificate with special server public-key). free (no realloc), because no need to copy old content */
               m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 );
             }
             D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len = 2 + D_ADSL_RCL1->imc_prot_1 + 16;
             D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1
               = (char *) m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len );
           }
           m_put_le2( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1, D_ADSL_RCL1->imc_prot_1 );  /* length of encrypted data */
           D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 2;  /* start of encrypted data */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data     */
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_req_scopelist:
           /* License requested. Tell client to send a license.        */
           iml2 = m_get_le4( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 4 ); /* len Company name */
           iml3 = m_get_le4( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 8 + iml2 ); /* len product ID */
           iml4 = D_ADSL_RCL1->imc_prot_1;  /* number of scopelist-entries */
           iml1 = sizeof(struct dsd_sc_request_license)
                    + iml2                  /* len Company name        */
                    + iml3                  /* len Product ID          */
                    + iml4 * sizeof(void *)  /* pointers to scopelist-entries */
                    + D_ADSL_RCL1->imc_pos_inp_frame;
           if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < (sizeof(struct dsd_se_co1) + iml1)) {  /* get new area */
             memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
             bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                                DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                                &dsl_aux_get_workarea,
                                                sizeof(struct dsd_aux_get_workarea) );
             if (bol1 == FALSE) {           /* aux returned error      */
               adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
               goto p_cleanup_20;           /* do cleanup now          */
             }
             ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
             ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
           }
           ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1);
#define ADSL_SE_CO1_G ((struct dsd_se_co1 *) ADSL_OA1->achc_upper)
#define ADSL_SC_REQ_L_G ((struct dsd_sc_request_license *) ADSL_OA1->achc_lower)
// to-do 18.04.12 KB what is memset good for ???
           memset( ADSL_SC_REQ_L_G, 0X42, iml1 );
// ????      D_ADSL_RCL1->achc_prot_2 = (char*) adsl_se_co1_w1; /* Save command for client */
           ADSL_SC_REQ_L_G->imc_version = D_ADSL_RCL1->imc_prot_5;
           /* Company name */
           achl1 = (char*) (ADSL_SC_REQ_L_G + 1);
           memcpy( achl1, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 8, iml2 );
           ADSL_SC_REQ_L_G->awsc_companyname = (HL_WCHAR *) achl1;
           achl1 += iml2;
           /* Product ID */
           memcpy( achl1, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 8 + iml2 + 4, iml3 );
           ADSL_SC_REQ_L_G->awsc_productid = (HL_WCHAR *) achl1;
           achl1 += iml3;
           /* Number of send scopes */
           ADSL_SC_REQ_L_G->im_num_scopes = iml4;
           /* Copy scope list */
           ADSL_SC_REQ_L_G->ach_scope = (char **) achl1;
#undef ADSL_SC_REQ_L_G
           ADSL_OA1->achc_lower += iml1;       /* memory is in use        */
           achl1 += iml4 * sizeof(void *);
           D_ADSL_RCL1->imc_prot_2 = 0; /* number of bytes to copy  */
           D_ADSL_RCL1->achc_prot_1 = achl1; /* Start of Data */
           D_ADSL_RCL1->achc_prot_3 = achl1; /* Start of Data */
           ADSL_SE_CO1_G->iec_se_command = ied_sec_request_license;  /* request a license */
           ADSL_SE_CO1_G->adsc_next = NULL;  /* clear chain field      */
           *ADSL_OA1->aadsc_se_co1_chain = ADSL_SE_CO1_G;  /* append to chain */
           ADSL_OA1->aadsc_se_co1_chain = &ADSL_SE_CO1_G->adsc_next;  /* set new end of chain */
#undef ADSL_SE_CO1_G
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data     */
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_new_license:
           /* Receive a new license. Create Order dsd_sc_save_license */
           iml1 = sizeof(struct dsd_sc_save_license) /* struct of order */
                   + D_ADSL_RCL1->imc_prot_1     /* copy the data here */
                   + 0X10;                  /* copy MAC                */
           if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < (sizeof(struct dsd_se_co1) + iml1)) {  /* get new area */
             memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
             bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                                DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                                &dsl_aux_get_workarea,
                                                sizeof(struct dsd_aux_get_workarea) );
             if (bol1 == FALSE) {           /* aux returned error      */
               adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
               goto p_cleanup_20;           /* do cleanup now          */
             }
             ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
             ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
           }
           ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1);
#define ADSL_SE_CO1_G ((struct dsd_se_co1 *) ADSL_OA1->achc_upper)
// to-do 18.04.12 KB what is memset good for ???
           memset( ADSL_SE_CO1_G + 1, 0X42, iml1 );
           ADSL_SE_CO1_G->iec_se_command = ied_sec_save_license;  /* save the license */
           ADSL_SE_CO1_G->adsc_next = NULL;  /* clear chain field      */
           *ADSL_OA1->aadsc_se_co1_chain = ADSL_SE_CO1_G;  /* append to chain */
           ADSL_OA1->aadsc_se_co1_chain = &ADSL_SE_CO1_G->adsc_next;  /* set new end of chain */
           /* copy data                                                */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - D_ADSL_RCL1->imc_prot_1 - 0X10; /* number of bytes to copy = D_ADSL_RCL1->imc_prot_1 + 0X10 */
           D_ADSL_RCL1->achc_prot_2 = (char *) ADSL_SE_CO1_G; /* remember start of order */
           D_ADSL_RCL1->achc_prot_1 = ADSL_OA1->achc_lower + sizeof(struct dsd_sc_save_license); /* Start of Data */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data     */
           ADSL_OA1->achc_lower += iml1;       /* memory is in use        */
           goto pfrse20;                    /* process next data       */
#undef ADSL_SE_CO1_G
         case ied_frse_lic_pr_lic_error_mes1:
           D_ADSL_RCL1->imc_prot_5 = D_ADSL_RCL1->imc_prot_1; /* Save error code */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 14159;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_lic_error_mes2;
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_lic_error_mes2:
           D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_type;
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
           if(D_ADSL_RCL1->imc_prot_5 == 0x7){
              /* Success -> no message */
              D_ADSL_RCO1->boc_licensing_done = TRUE;
             goto pfrse40;                /* send RDP4 to client     */
           }
           /* Print out a meaningfull error-message */
           achl1 = ""; /* Error Code */
           switch(D_ADSL_RCL1->imc_prot_5){
             case 0X3: achl1 = "ERR_INVALID_MAC"; break;
             case 0X4: achl1 = "ERR_INVALID_SCOPE"; break;
             case 0X6: achl1 = "ERR_NO_LICENSE_SERVER"; break;
             case 0X7: achl1 = "STATUS_VALID_CLIENT"; break;
             case 0X8: achl1 = "ERR_INVALID_CLIENT"; break;
             case 0XB: achl1 = "ERR_INVALID_PRODUCTID"; break;
             case 0XC: achl1 = "ERR_INVALID_MESSAGE_LEN"; break;
             default: achl1 = "Unknown Licensing Error"; break;
           }
           achl2 = ""; /* StateTransition */
           switch(D_ADSL_RCL1->imc_prot_1){
             case 0X1: achl2 = "ST_TOTAL_ABORT"; break;
             case 0X2: achl2 = "ST_NO_TRANSITION"; break;
             case 0X3: achl2 = "ST_RESET_PHASE_TO_START";
             case 0X4: achl2 = "ST_RESEND_LAST_MESSAGE";
             default: achl2 = "Unknown State Transition";
           }
           m_sdh_printf( adsp_hl_clib_1, "License error message received from server l%05d s%05d %s %s",
                             __LINE__,               /* line number for errors  */
                             14197,             /* source line no for errors */
                             achl1,
                             achl2 );
           goto pfrse40;                /* send RDP4 to client     */
       }
           goto pfrse96;                    /* program illogic         */
     case ied_fsfp_int_big_e:               /* int big endian          */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_1 <<= 8;
         D_ADSL_RCL1->imc_prot_1
           |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
#ifdef TRACEHL1
       printf( "ied_fsfp_int_big_e found int=%d D_ADSL_RCL1->iec_frse_bl=%d\n",
               D_ADSL_RCL1->imc_prot_1,
               D_ADSL_RCL1->iec_frse_bl );
#endif
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_rec_07:              /* block 7 received        */
           D_ADSL_RCO1->usc_userid_cl2se = (unsigned short int) D_ADSL_RCL1->imc_prot_1;
           D_ADSL_RCL1->imc_prot_5 = 0;     /* clear channel index     */
           goto p_cjr_frse_00;              /* send channel join request */
         case ied_frse_cjresp_rec:          /* receive block channel join response */
           do {
             if (D_ADSL_RCL1->imc_prot_1 == D_ADSL_RCO1->usc_chno_disp) {  /* channel number display */
               D_ADSL_RCO1->usc_chno_disp = (unsigned short int) D_ADSL_RCL1->imc_prot_chno;
               break;
             }
             if ((ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_enable_mcs_message_channel != FALSE) 
                 && (D_ADSL_RCL1->imc_prot_1 == D_ADSL_RCO1->usc_chno_mcs_msgchannel)) {  /* channel number display */
               D_ADSL_RCO1->usc_chno_mcs_msgchannel = (unsigned short int) D_ADSL_RCL1->imc_prot_chno;
               break;
             }
             iml1 = D_ADSL_RCO1->imc_no_virt_ch;  /* number of virtual channels */
             while (iml1) {
#define D_ADSL_VCH (D_ADSL_RCO1->adsrc_vc_1 + (D_ADSL_RCO1->imc_no_virt_ch - iml1))
               /* compare virtual channel no                           */
               if (D_ADSL_RCL1->imc_prot_1 == D_ADSL_VCH->usc_vch_no) {
                 D_ADSL_VCH->usc_vch_no = (unsigned short int) D_ADSL_RCL1->imc_prot_chno;
                 break;
               }
#undef D_ADSL_VCH
               iml1--;                      /* number before           */
             }
             if (iml1 > 0) break;           /* channel found           */
             /* channel number control                                 */
             if (D_ADSL_RCL1->imc_prot_1 != (D_EXTRA_CHANNEL + D_ADSL_RCO1->usc_userid_cl2se)) {  /* check number virtual channel */
               iml_line_no = __LINE__;
               iml_source_no = 14309;    /* source line no for errors */
               goto pfrse92;
             }
             D_ADSL_RCO1->usc_chno_cont = (unsigned short int) D_ADSL_RCL1->imc_prot_chno;
           } while (FALSE);
           goto p_cjr_frse_00;              /* send channel join request */
         case ied_frse_actpdu_trail:        /* trailer of act PDU      */
           if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < sizeof(struct dsd_se_co1)) {  /* get new area */
             memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
             bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                                DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                                &dsl_aux_get_workarea,
                                                sizeof(struct dsd_aux_get_workarea) );
             if (bol1 == FALSE) {           /* aux returned error      */
               adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
               goto p_cleanup_20;           /* do cleanup now          */
             }
             ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
             ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
           }
           ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1);
#define ADSL_SE_CO1_G ((struct dsd_se_co1 *) ADSL_OA1->achc_upper)
           ADSL_SE_CO1_G->iec_se_command = ied_sec_recv_demand_active_pdu;  /* received Demand Active PDU */
           ADSL_SE_CO1_G->adsc_next = NULL;  /* clear chain field      */
           *ADSL_OA1->aadsc_se_co1_chain = ADSL_SE_CO1_G;  /* append to chain */
           ADSL_OA1->aadsc_se_co1_chain = &ADSL_SE_CO1_G->adsc_next;  /* set new end of chain */
#undef ADSL_SE_CO1_G
// to-do 13.02.09 KB check if more data received
           D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* receive any PDU type */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
           goto pfrse20;                    /* process next data       */
       }
           goto pfrse96;                    /* program illogic         */
     case ied_fsfp_asn1_tag:                /* ASN.1 tag follows       */
       adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->imc_pos_inp_frame < D_ADSL_RCL1->imc_prot_3) {
         iml_line_no = __LINE__;
         iml_source_no = 14467;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_l1_fi;  /* ASN.1 length field */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_asn1_l1_fi:              /* ASN.1 length field 1    */
       D_ADSL_RCL1->imc_prot_1
         = *adsl_gai1_inp_1->achc_ginp_cur & 0X7F;
       if (D_ADSL_RCL1->imc_prot_1 == 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14475;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_pos_inp_frame--;
       /* compute how many remain after this length                    */
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                  - D_ADSL_RCL1->imc_prot_1;
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14482;    /* source line no for errors */
         goto pfrse92;
       }
       /* check ASN-1 length in more than one byte                     */
       if (*adsl_gai1_inp_1->achc_ginp_cur & 0X80) {
         if (D_ADSL_RCL1->imc_prot_1 > 4) {
           iml_line_no = __LINE__;
           iml_source_no = 14487;    /* source line no for errors */
           goto pfrse92;
         }
         adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RCL1->imc_prot_1 = 0;        /* length comes to this    */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_l1_p2;  /* ASN.1 length part two */
         goto pfrse20;                      /* process next data       */
       }
#ifdef TRACEHL1
       printf( "ied_fsfp_asn1_l1_fi found len=%d till=%d D_ADSL_RCL1->iec_frse_bl=%d\n",
               D_ADSL_RCL1->imc_prot_1,
               D_ADSL_RCL1->imc_prot_2,
               D_ADSL_RCL1->iec_frse_bl );
#endif
       adsl_gai1_inp_1->achc_ginp_cur++;
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_start:               /* reply from server to first packet */
           if (D_ADSL_RCL1->imc_prot_2) {
             m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d ied_frse_start found end invalid %d / %d.",
                           __LINE__, 14518,  /* line number for errors */
                           D_ADSL_RCL1->imc_prot_2, D_ADSL_RCL1->imc_pos_inp_frame );
             iml_line_no = __LINE__;
             iml_source_no = 14520;    /* source line no for errors */
             goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame < sizeof(ucrs_rec_se_01_cmp1)) {  /* compare received from server first block */
             iml_line_no = __LINE__;
             iml_source_no = 14523;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_constant;  /* compare with constant */
           D_ADSL_RCL1->imc_prot_akku = 0;  /* position                */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_asn1_1:          /* block 4 ASN-1 field 1   */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_asn1_2:          /* block 4 ASN-1 field 2   */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_asn1_3:          /* block 4 ASN-1 field 3   */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_asn1_4:          /* block 4 ASN-1 field 4   */
           if (D_ADSL_RCL1->imc_prot_2) {   /* is not till end of block */
             iml_line_no = __LINE__;
             iml_source_no = 14550;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_constant;  /* compare with constant */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* position                */
           goto pfrse20;                    /* process next data       */
         case ied_frse_rec_04:              /* record 4 received       */
           if (D_ADSL_RCL1->imc_prot_2) {   /* is not till end of block */
             iml_line_no = __LINE__;
             iml_source_no = 14557;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_asn1_1;  /* block 4 ASN-1 field 1 */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_tag;
           goto pfrse20;                    /* process next data       */
// TODO: check if block within #else and #endif should be removed completely or if it
// should be enclosed as alternate path in a condition 
         default:
           iml_line_no = __LINE__;
           iml_source_no = 14573;    /* source line no for errors */
           goto pfrse96;
       }
     case ied_fsfp_asn1_l1_p2:              /* ASN.1 length part two   */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_1 <<= 8;
         D_ADSL_RCL1->imc_prot_1
           |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
       /* compute how many remain after this length                    */
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                  - D_ADSL_RCL1->imc_prot_1;
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14592;    /* source line no for errors */
         goto pfrse92;
       }
#ifdef TRACEHL1
       printf( "ied_fsfp_asn1_l1_p2 found len=%d till=%d D_ADSL_RCL1->iec_frse_bl=%d\n",
               D_ADSL_RCL1->imc_prot_1,
               D_ADSL_RCL1->imc_prot_2,
               D_ADSL_RCL1->iec_frse_bl );
#endif
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_rec_04:              /* record 4 received       */
           if (D_ADSL_RCL1->imc_prot_2) {   /* is not till end of block */
             iml_line_no = __LINE__;
             iml_source_no = 14603;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_asn1_1;  /* block 4 ASN-1 field 1 */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_tag;
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_asn1_4:          /* block 4 ASN-1 field 4   */
           if (D_ADSL_RCL1->imc_prot_2) {   /* is not till end of block */
             iml_line_no = __LINE__;
             iml_source_no = 14610;    /* source line no for errors */
             goto pfrse92;
           }
#ifdef XYZ1
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_tag;
#endif
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_constant;  /* compare with constant */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* position                */
           goto pfrse20;                    /* process next data       */
         default:
           goto pfrse96;                    /* program illogic         */
       }
         iml_line_no = __LINE__;
         iml_source_no = 14621;    /* source line no for errors */
         goto pfrse92;
     case ied_fsfp_mu_len_1:                /* multi length 1          */
       D_ADSL_RCL1->imc_prot_1
         = *adsl_gai1_inp_1->achc_ginp_cur & 0X7F;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (*adsl_gai1_inp_1->achc_ginp_cur & 0X80) {  /* second byte follows */
         adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_mu_len_2;  /* multi length 2 follows */
         goto pfrse20;                      /* process next data       */
       }
       adsl_gai1_inp_1->achc_ginp_cur++;
       if (D_ADSL_RCL1->imc_prot_1 == 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14633;    /* source line no for errors */
         goto pfrse92;
       }
       if (D_ADSL_RCL1->imc_pos_inp_frame < D_ADSL_RCL1->imc_prot_1) {
         iml_line_no = __LINE__;
         iml_source_no = 14636;    /* source line no for errors */
         goto pfrse92;
       }
       // TODO: instead of the following goto, it is better idea to make a "precomp macro"
       // with the switch where the goto jumps, so in both cases, exactly the same code is
       // executed
       goto LBL_ACTION_RDP;
     case ied_fsfp_mu_len_2:                /* multi length 2          */
       D_ADSL_RCL1->imc_prot_1 <<= 8;       /* shift old value         */
       D_ADSL_RCL1->imc_prot_1
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->imc_prot_1 == 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14660;    /* source line no for errors */
         goto pfrse92;
       }
       if (D_ADSL_RCL1->imc_pos_inp_frame < D_ADSL_RCL1->imc_prot_1) {
         iml_line_no = __LINE__;
         iml_source_no = 14663;    /* source line no for errors */
         goto pfrse92;
       }
LBL_ACTION_RDP:
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_r04_asn1_4:          /* block 4 ASN-1 field 4   */
           if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_1) {
             iml_line_no = __LINE__;
             iml_source_no = 14671;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
           D_ADSL_RCL1->imc_prot_4 = 0;     /* no fields yet           */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 14677;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_act_pdu_rec:         /* receive block active PDU */
         case ied_frse_lic_pr_1_rec:        /* receive block licence protocol */
         case ied_frse_error_bl_01:         /* receive error block 01  */
         case ied_frse_any_pdu_rec:
         if(D_ADSL_RCO1->imc_sec_level != 0 || !D_ADSL_RCO1->boc_licensing_done) {
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rt02;  /* record type 2 */
               goto pfrse20;                    /* process next data       */
           }
           goto LBL_fsfp_padd_1_02;
       }
       iml_line_no = __LINE__;
       iml_source_no = 14775;    /* source line no for errors */
       goto pfrse96;
    case ied_fsfp_datapdu_synchronize:         // 2.2.1.14.1 Synchronize PDU Data (TS_SYNCHRONIZE_PDU)
        bol1 = m_check_input_complete(adsl_gai1_inp_1, adsl_gai1_inp_1->achc_ginp_cur, D_ADSL_RCL1->imc_prot_save2);
        if (bol1 == FALSE) {             /* not yet all data received */
            /* wait for more data                                     */
            goto p_ret_00;                 /* check how to return     */
        }
        {
            unsigned int iml_bytes = 0;
            // Get the messageType and the targetUser:
            for (int iml_iter = 0; iml_iter < 4; iml_iter++){
                iml_bytes |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                        << ((iml_iter) << 3);
                D_ADSL_RCL1->imc_pos_inp_frame--;
                if (D_ADSL_RCL1->imc_pos_inp_frame <=0) break;
                if (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end){
                    adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
                    if (adsl_gai1_inp_1 == NULL){
                        iml_line_no = __LINE__;
                        iml_source_no = 14826;    /* source line no for errors */
                        goto pfrse92;
                    }
                }
            }
            // Check if the messageType is OK:
            if (SYNCMSGTYPE_SYNC != (iml_bytes & 0x0000FFFF)){
                iml_line_no = __LINE__;
                iml_source_no = 14832;    /* source line no for errors */
                goto pfrse92;
            }
            // Check if enough memory available for the command:
            if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)
                < (sizeof(struct dsd_se_co1) + sizeof(struct dsd_sc_synchronize_pdu))) {
                memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
                bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                            DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                            &dsl_aux_get_workarea,
                                            sizeof(struct dsd_aux_get_workarea) );
                if (bol1 == FALSE) {               /* aux returned error      */
                    adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
                    goto p_cleanup_20;               /* do cleanup now          */
                }
                ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
                ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
            }
            
            ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1) + sizeof(struct dsd_sc_synchronize_pdu);
            achl1 = ADSL_OA1->achc_upper;        /* set start of order      */
        
            struct dsd_se_co1* adsl_server_command = (struct dsd_se_co1*)achl1;
            struct dsd_sc_synchronize_pdu* adsl_synchronize_pdu 
                = (struct dsd_sc_synchronize_pdu*)(adsl_server_command + 1);

            adsl_server_command->iec_se_command = ied_sec_synchronize_pdu;
            adsl_synchronize_pdu->usc_target_user = (iml_bytes >> 16);
                    
            // End server command:
            adsl_server_command->adsc_next = NULL;     /* clear chain field       */
            *ADSL_OA1->aadsc_se_co1_chain = adsl_server_command;  /* append to chain */
            ADSL_OA1->aadsc_se_co1_chain = &adsl_server_command->adsc_next;  /* set new end of chain */
        }
        D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;
        D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;
        goto pfrse20;
    case ied_fsfp_datapdu_monitor_layout:          // 2.2.12.1 Monitor Layout PDU
        bol1 = m_check_input_complete(adsl_gai1_inp_1, adsl_gai1_inp_1->achc_ginp_cur, D_ADSL_RCL1->imc_prot_save2);
        if (bol1 == FALSE) {             /* not yet all data received */
            /* wait for more data                                     */
            goto p_ret_00;                 /* check how to return     */
        }
        {
            int iml_monitor_count = 0;
            // Get the monitor count:
            for (int iml_iter = 0; iml_iter < 4; iml_iter++){
                iml_monitor_count |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                        << ((iml_iter) << 3);
                D_ADSL_RCL1->imc_pos_inp_frame--;
                if (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end){
                    adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
                    if (adsl_gai1_inp_1 == NULL){
                        iml_line_no = __LINE__;
                        iml_source_no = 14884;    /* source line no for errors */
                        goto pfrse92;
                    }
                }
            }
            // Check coherency:
            if ((iml_monitor_count <= 0) 
                || (D_ADSL_RCL1->imc_pos_inp_frame != (iml_monitor_count * sizeof(struct dsd_ts_monitor_def)))){
                iml_line_no = __LINE__;
                iml_source_no = 14891;    /* source line no for errors */
                goto pfrse92;
            }
            // Check if enough memory available for creating the monitor layout command:
            iml3 = sizeof(struct dsd_sc_monitor_layout_pdu) + D_ADSL_RCL1->imc_pos_inp_frame;
            if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)
                < (sizeof(struct dsd_se_co1) + iml3)) {
                memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
                bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                            DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                            &dsl_aux_get_workarea,
                                            sizeof(struct dsd_aux_get_workarea) );
                if (bol1 == FALSE) {               /* aux returned error      */
                    adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
                    goto p_cleanup_20;               /* do cleanup now          */
                }
                ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
                ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
            }
            ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1) + iml3;
            achl1 = ADSL_OA1->achc_upper;        /* set start of order      */

            // Prepare the command:
            struct dsd_se_co1* adsl_server_command = (struct dsd_se_co1*)achl1;
            adsl_server_command->iec_se_command = ied_sec_monitor_layout_pdu;

            struct dsd_sc_monitor_layout_pdu* adsl_monitor_layout_pdu 
                = (struct dsd_sc_monitor_layout_pdu*)(adsl_server_command + 1);
            memset(adsl_monitor_layout_pdu, 0, sizeof(struct dsd_sc_monitor_layout_pdu));
            adsl_monitor_layout_pdu->adsrc_ts_monitor = (struct dsd_ts_monitor_def*)(adsl_monitor_layout_pdu + 1);
            adsl_monitor_layout_pdu->imc_monitor_count = iml_monitor_count;
            // Prepare to copy the monitorDefArray
            struct dsd_ts_monitor_def* adsl_monitor_dest 
                = adsl_monitor_layout_pdu->adsrc_ts_monitor; 
            int iml_size = 0;
            // Copy the array:
            while (iml_monitor_count > 0){
                iml_size = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
                if (iml_size > D_ADSL_RCL1->imc_pos_inp_frame) iml_size = D_ADSL_RCL1->imc_pos_inp_frame;
                memcpy(adsl_monitor_dest, adsl_gai1_inp_1->achc_ginp_cur, iml_size);
                adsl_gai1_inp_1->achc_ginp_cur += iml_size;
                D_ADSL_RCL1->imc_pos_inp_frame -= iml_size;
                if (adsl_gai1_inp_1 == NULL){
                    iml_line_no = __LINE__;
                    iml_source_no = 14933;    /* source line no for errors */
                    goto pfrse92;
                }
                adsl_monitor_dest += 1;
                iml_monitor_count--;
            }
            // End server command:
            adsl_server_command->adsc_next = NULL;     /* clear chain field       */
            *ADSL_OA1->aadsc_se_co1_chain = adsl_server_command;  /* append to chain */
            ADSL_OA1->aadsc_se_co1_chain = &adsl_server_command->adsc_next;  /* set new end of chain */
        }
        D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;
        D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;
        goto pfrse20;
    case ied_fsfp_datapdu_save_session_info:
        bol1 = m_check_input_complete(adsl_gai1_inp_1, adsl_gai1_inp_1->achc_ginp_cur, D_ADSL_RCL1->imc_prot_save2);
        if (bol1 == FALSE) {             /* not yet all data received */
            /* wait for more data                                     */
            goto p_ret_00;                 /* check how to return     */
        }
        {
            unsigned int iml_version = 0;
            // Get the messageType and the targetUser:
            for (int iml_iter = 0; iml_iter < 4; iml_iter++){
                iml_version |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                        << ((iml_iter) << 3);
                D_ADSL_RCL1->imc_pos_inp_frame--;
                if (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end){
                    adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
                    if (adsl_gai1_inp_1 == NULL){
                        iml_line_no = __LINE__;
                        iml_source_no = 14962;    /* source line no for errors */
                        goto pfrse92;
                    }
                }
            }
            switch (iml_version){
            case INFOTYPE_LOGON_EXTENDED_INFO:
            case INFOTYPE_LOGON_PLAINNOTIFY:
            default:
                D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
                D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
                goto pfrse40;                      /* send RDP4 data to client */
            }
        }
        D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
        D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
        goto pfrse40;                      /* send RDP4 data to client */
     case ied_fsfp_actpdu_no_cap:
           /* copy capabilities without padding of number              */
           bol1 = m_check_input_complete( adsl_gai1_inp_1, adsl_gai1_inp_1->achc_ginp_cur, D_ADSL_RCL1->imc_prot_save2 );
           if (bol1 == FALSE) {             /* not yet all data received */
             /* wait for more data                                     */
             goto p_ret_00;                 /* check how to return     */
           }
           if (D_ADSL_RCO1->achc_server_capabilities) {  /* storage from ACTPDU before */
             m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->achc_server_capabilities );
           }
           D_ADSL_RCO1->imc_len_server_capabilities = D_ADSL_RCL1->imc_prot_save2;  /* length server capabilities */
           ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
           ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
           *((void **) &D_ADSL_RCO1->achc_server_capabilities) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCL1->imc_prot_save2 );
           /* overread padding                                         */
           iml1 = 2;
           adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather          */
           achl1 = adsl_gai1_inp_1->achc_ginp_cur;  /* current position */
           while (TRUE) {                   /* loop over all gather structures input */
             iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
             if (iml2 > iml1) iml2 = iml1;
             achl1 += iml2;
             iml1 -= iml2;
             if (iml1 <= 0) break;          /* enough data found       */
             adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
             if (adsl_gai1_inp_w2 == NULL) {  /* already end of chain  */
                iml_line_no = __LINE__;
                iml_source_no = 15012;    /* source line no for errors */
                goto pfrse96;
             }
             achl1 = adsl_gai1_inp_w2->achc_ginp_cur;  /* current position */
           }

           bol1 = m_copy_input_gai1( D_ADSL_RCO1->achc_server_capabilities,
                                     adsl_gai1_inp_w2, achl1, D_ADSL_RCL1->imc_prot_save2 );
           if (bol1 == FALSE) {             /* something went wrong - illogic */
             iml_line_no = __LINE__;
             iml_source_no = 14691;    /* source line no for errors */
             goto pfrse96;
           }
           D_ADSL_RCL1->imc_prot_5 = D_ADSL_RCL1->imc_prot_1;  /* save no cap */
           D_ADSL_RCL1->imc_prot_7 = 0;     /* clear indicator         */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 14698;    /* source line no for errors */
             goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data */
           goto pfrse20;                    /* process next data       */

     case ied_fsfp_r5_len_1:                /* RDP 5 multi length 1    */
       D_ADSL_RCL1->imc_pos_inp_frame
         = *adsl_gai1_inp_1->achc_ginp_cur & 0X7F;
       D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec++ ]
         = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record        */
       if (*adsl_gai1_inp_1->achc_ginp_cur & 0X80) {  /* second byte follows */
         adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_len_2;  /* RDP 5 multi length 2 follows */
         goto pfrse20;                      /* process next data       */
       }
       adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCO1->imc_len_record = D_ADSL_RCL1->imc_pos_inp_frame;  /* length of record */
       D_ADSL_RCO1->imc_len_part = D_ADSL_RCL1->imc_prot_1;  /* length of part */
       ADSL_RDPA_F->dsc_rdptr1.chc_type_disp = 'R';  /* type of displacement */
       D_ADSL_RCL1->imc_pos_inp_frame -= 2;  /* minus length header    */
       if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15080;    /* source line no for errors */
         goto pfrse92;
       }
       if (D_ADSL_RCL1->chc_prot_r5_first & 0X80) {  /* received encrypted */
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - D_SIZE_HASH;
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
           iml_line_no = __LINE__;
           iml_source_no = 15086;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_prot_1;
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_hash;  /* RDP 5 hash   */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_typ;  /* RDP 5 PDU type */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_r5_len_2:                /* RDP 5 multi length 2    */
       D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec++ ]
         = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record        */
       D_ADSL_RCL1->imc_pos_inp_frame <<= 8;  /* shift old value       */
       D_ADSL_RCL1->imc_pos_inp_frame
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCO1->imc_len_record = D_ADSL_RCL1->imc_pos_inp_frame;  /* length of record */
       D_ADSL_RCO1->imc_len_part = D_ADSL_RCL1->imc_prot_1;  /* length of part */
       ADSL_RDPA_F->dsc_rdptr1.chc_type_disp = 'R';  /* type of displacement */
       D_ADSL_RCL1->imc_pos_inp_frame -= 3;  /* minus length header    */
       if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15136;    /* source line no for errors */
         goto pfrse92;
       }
#ifdef TEMPSCR1
       if (ADSL_RDPA_F->boc_temp_scr_1) {   /* screen buffer send      */
         D_ADSL_RCL1->imc_prot_2 = 0;       /* till end of block       */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data   */
         goto pfrse20;                      /* process next data       */
       }
#endif
       if (D_ADSL_RCL1->chc_prot_r5_first & 0X80) {  /* received encrypted */
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - D_SIZE_HASH;
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
           iml_line_no = __LINE__;
           iml_source_no = 15186;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_prot_1;
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_hash;  /* RDP 5 hash   */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_typ;  /* RDP 5 PDU type */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_r5_hash:                 /* RDP 5 hash              */
       /* compute how many to copy                                     */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame
                - D_ADSL_RCL1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       memcpy( D_ADSL_RCL1->achc_prot_1,
               adsl_gai1_inp_1->achc_ginp_cur,
               iml1 );
       D_ADSL_RCL1->achc_prot_1 += iml1;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RCL1->imc_pos_inp_frame > D_ADSL_RCL1->imc_prot_2) {
         goto pfrse20;                      /* needs more data         */
       }
       /* check if all data of this frame have been received           */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data in frame */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
       while (TRUE) {                       /* loop over all gather structures input */
         iml1 -= adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
         if (iml1 <= 0) break;              /* enough data found       */
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
           /* wait for more data                                       */
           goto pfrse80;
         }
       }
       if ((D_ADSL_RCO1->dsc_encry_se2cl.imc_count_sent & (4096 - 1)) == 0){
         if (D_ADSL_RCO1->dsc_encry_se2cl.imc_count_sent) {
           m_update_keys( D_ADSL_RCO1, &D_ADSL_RCO1->dsc_encry_se2cl, NULL );
         }
       }
       /* decrypt the data where they are                              */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data in frame */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
       while (TRUE) {                       /* loop over all gather structures input */
         iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;      /* only data in this frame */
         RC4( adsl_gai1_inp_w2->achc_ginp_cur, 0, iml2,
              adsl_gai1_inp_w2->achc_ginp_cur, 0,
              D_ADSL_RCO1->dsc_encry_se2cl.chrc_rc4_state );
         iml1 -= iml2;                      /* subtract data decyrpted */
         if (iml1 <= 0) break;              /* all data decrypted      */
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
           iml_line_no = __LINE__;
           iml_source_no = 15255;    /* source line no for errors */
           goto pfrse96;
         }
       }
       /* check the hash now                                       */
#define ACHL_WORK_SHA1 ((int *) chrl_work_2)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
       memcpy( ACHL_WORK_SHA1,
               D_ADSL_RCO1->imrc_sha1_state,
               sizeof(D_ADSL_RCO1->imrc_sha1_state) );
       memcpy( ACHL_WORK_MD5,
               D_ADSL_RCO1->imrc_md5_state,
               sizeof(D_ADSL_RCO1->imrc_md5_state) );
       m_put_le4( ACHL_WORK_UTIL_01, D_ADSL_RCL1->imc_pos_inp_frame );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data in frame */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
       while (TRUE) {                       /* loop over all gather structures input */
         iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;      /* only data in this frame */
         SHA1_Update( ACHL_WORK_SHA1,
                      adsl_gai1_inp_w2->achc_ginp_cur, 0, iml2 );
         iml1 -= iml2;                      /* subtract data processed */
         if (iml1 <= 0) break;              /* all data processed      */
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
           goto pfrse96;                    /* program illogic         */
         }
       }
       if (D_ADSL_RCL1->chc_prot_r5_first & 0X40) {  /* flag for block count */
         m_put_le4( ACHL_WORK_UTIL_01, D_ADSL_RCO1->dsc_encry_se2cl.imc_count_sent );
         SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
       }
       SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
       MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
       MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
       if (memcmp( D_ADSL_RCL1->chrc_prot_1, ACHL_WORK_UTIL_01, D_SIZE_HASH )) {
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d received from server hash invalid",
                       __LINE__, 15293 );  /* line number for errors  */
         iml_line_no = __LINE__;
         iml_source_no = 15294;    /* source line no for errors */
         goto pfrse92;
       }
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
       D_ADSL_RCO1->dsc_encry_se2cl.imc_count_sent++;  /* count block received from server */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_typ;  /* RDP 5 PDU type */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_r5_pdu_typ:              /* RDP 5 PDU type          */
       D_ADSL_RCL1->chc_prot_r5_pdu_type = *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->chc_prot_r5_pdu_type & 0X80) {  /* input compressed */
         if ((D_ADSL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) == 0) {  /* compression not enabled */
           iml_line_no = __LINE__;
           iml_source_no = 15307;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_cofl;  /* RDP 5 compression flags */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15314;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_1 = 0;         /* clear value             */
#ifndef B170221_DD_TICKET_48103
       // Ticket 48103: if the compression flag is not present in the fast path pdu header,
       //   we need to clear the compression flag; otherwise, (after reading the size field) if
       //   the previous PDU was compressed, it will try to decompress the PDU content when this is
       //   not compressed.
       D_ADSL_RCL1->chc_prot_r5_pdu_cofl = 0;
#endif // B170221_DD_TICKET_48103
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_len;  /* RDP 5 PDU length */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_r5_pdu_cofl:             /* RDP 5 compression flags */
       D_ADSL_RCL1->chc_prot_r5_pdu_cofl = *adsl_gai1_inp_1->achc_ginp_cur++;  /* for protocol decoding */
       D_ADSL_RCL1->imc_pos_inp_frame--;
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15333;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_1 = 0;         /* clear value             */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_len;  /* RDP 5 PDU length */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_r5_pdu_len:              /* RDP 5 PDU length        */
       while (TRUE) {
         D_ADSL_RCL1->imc_prot_1
           |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                << ((D_ADSL_RCL1->imc_prot_2 + 2 - D_ADSL_RCL1->imc_pos_inp_frame)
                      << 3);
         D_ADSL_RCL1->imc_pos_inp_frame--;
         if (D_ADSL_RCL1->imc_pos_inp_frame == D_ADSL_RCL1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto pfrse20;                    /* needs more data         */
         }
       }
   D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
       if (D_ADSL_RCL1->chc_prot_r5_pdu_cofl & 0X20) {  /* input compressed */
         if (D_ADSL_RCL1->imc_prot_1 == 0) {
// to-do 21.10.13 KB - maybe switch in this case should be executed
// so    if (   (D_ADSL_RCL1->chc_prot_r5_pdu_cofl & 0X20)
//           && (D_ADSL_RCL1->imc_prot_1 > 0) { ...
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_typ;  /* RDP 5 PDU type */
           goto pfrse20;                    /* process next data       */
         }
         if (D_ADSL_RCO1->dsc_cdrf_dec.imc_func == 0) {  /* compression not started */
           iml_line_no = __LINE__;
           iml_source_no = 15377;    /* source line no for errors */
           goto pfrse92;
         }
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_compr;  /* RDP 5 PDU compressed */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->imc_prot_4
         = D_ADSL_RCL1->imc_pos_inp_frame - D_ADSL_RCL1->imc_prot_1;
       if (D_ADSL_RCL1->imc_prot_4 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15385;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_content;  /* RDP 5 PDU content */
     case ied_fsfp_r5_pdu_content:          /* RDP 5 PDU content       */
       /* check if all data of this frame have been received           */
       iml1 = D_ADSL_RCL1->imc_prot_akku;   /* remaining data in PDU   */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
       while (TRUE) {                       /* loop over all gather structures input */
         iml1 -= adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
         if (iml1 <= 0) break;              /* enough data found       */
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
           /* wait for more data                                       */
           goto p_ret_00;                   /* check how to return     */
         }
       }
       if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < sizeof(struct dsd_wt_record_1)) {
         memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
         bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                            DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                            &dsl_aux_get_workarea,
                                            sizeof(struct dsd_aux_get_workarea) );
         if (bol1 == FALSE) {               /* aux returned error      */
           adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
           goto p_cleanup_20;               /* do cleanup now          */
         }
         ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
         ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
       }
       ADSL_OA1->achc_upper -= sizeof(struct dsd_wt_record_1);
#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) ADSL_OA1->achc_upper)
// to-do 20.10.13 KB - can be optimized
       ADSL_WTR1_G->adsc_next = NULL;   /* clear chain             */
       ADSL_WTR1_G->ucc_record_type = (unsigned char) (D_ADSL_RCL1->chc_prot_r5_pdu_type & 0X0F) | 0X20;  /* record type */
       *ADSL_OA1->aadsc_wtr1_chain = ADSL_WTR1_G;  /* chain of WebTerm records */
       ADSL_OA1->aadsc_wtr1_chain = &ADSL_WTR1_G->adsc_next;  /* chain of WebTerm records */
       aadsl_gai1_ch = &ADSL_WTR1_G->adsc_gai1_data;   /* output data be be sent to client */
#undef ADSL_WTR1_G
       iml1 = D_ADSL_RCL1->imc_prot_akku;   /* remaining data in PDU   */
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* content processed   */
       while (iml1 > 0) {                   /* needs to copy data / gather */
         while (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
           adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
           if (adsl_gai1_inp_1 == NULL) {   /* end of input data       */
             iml_line_no = __LINE__;
             iml_source_no = 15569;    /* source line no for errors */
             goto pfrse96;
           }
         }
         if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < sizeof(struct dsd_gather_i_1)) {
           memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
           bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                              DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                              &dsl_aux_get_workarea,
                                              sizeof(struct dsd_aux_get_workarea) );
           if (bol1 == FALSE) {             /* aux returned error      */
             adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
             goto p_cleanup_20;             /* do cleanup now          */
           }
           ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
           ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
         }
         ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
         if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
           iml_line_no = __LINE__;
           iml_source_no = 15587;    /* source line no for errors */
           goto pfrse96;
         }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
         iml2 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;
         ADSL_GAI1_OUT_G->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_cur;
         ADSL_GAI1_OUT_G->achc_ginp_end = adsl_gai1_inp_1->achc_ginp_cur + iml2;
         *aadsl_gai1_ch = ADSL_GAI1_OUT_G;  /* create chain gather data */
         aadsl_gai1_ch = &ADSL_GAI1_OUT_G->adsc_next;  /* next entry create chain gather data */
         adsl_gai1_inp_1->achc_ginp_cur += iml2;
         iml1 -= iml2;                      /* data processed          */
#undef ADSL_GAI1_OUT_G
       }
       *aadsl_gai1_ch = NULL;               /* end create chain gather data */
       if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* at end of block  */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
         D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_typ;  /* RDP 5 PDU type */
       goto pfrse20;                        /* needs more data         */
     case ied_fsfp_r5_pdu_compr:            /* RDP 5 PDU compressed    */
       /* check if all data of this frame have been received           */
       iml1 = D_ADSL_RCL1->imc_prot_1;      /* length of compressed data */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
#define ADSL_GAI1_S ((struct dsd_gather_i_1 *) chrl_work_2)
       adsl_gai1_w1 = ADSL_GAI1_S;          /* first gather here       */
       while (TRUE) {                       /* loop over input bytes   */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
           /* wait for more data                                       */
           goto p_ret_00;                   /* check how to return     */
         }
         iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
         if (iml2 > iml1) iml2 = iml1;
         adsl_gai1_w1->achc_ginp_cur = adsl_gai1_inp_w2->achc_ginp_cur;
         adsl_gai1_w1->achc_ginp_end = adsl_gai1_inp_w2->achc_ginp_cur + iml2;
         iml1 -= iml2;                      /* remaining data to decompress */
         if (iml1 <= 0) break;              /* end of data to decompress */
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next in chain */
         adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain gather */
         adsl_gai1_w1++;                    /* use next gather         */
       }
       ADSL_RDPA_F->dsc_rdptr1.imc_disp_field
         = D_ADSL_RCO1->imc_len_record - D_ADSL_RCL1->imc_pos_inp_frame;
       while (adsl_gai1_inp_1 != adsl_gai1_inp_w2) {  /* loop to set processed input */
         D_ADSL_RCL1->imc_pos_inp_frame     /* remaining data in frame */
           -= adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
         adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_end;
         adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
       }
       D_ADSL_RCL1->imc_pos_inp_frame       /* remaining data in frame */
         -= adsl_gai1_w1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_w1->achc_ginp_end;
       adsl_gai1_w1->adsc_next = NULL;      /* end of data             */
       D_ADSL_RCO1->dsc_cdrf_dec.adsc_gai1_in = ADSL_GAI1_S;  /* input data */
#undef ADSL_GAI1_S
       D_ADSL_RCO1->dsc_cdrf_dec.chrc_header[ 0 ]  /* copy compression header */
         = D_ADSL_RCL1->chc_prot_r5_pdu_cofl;  /* address act input-data */
       D_ADSL_RCO1->dsc_cdrf_dec.boc_mp_flush = TRUE;  /* end-of-record input */
       if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < sizeof(struct dsd_wt_record_1)) {
         memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
         bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                            DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                            &dsl_aux_get_workarea,
                                            sizeof(struct dsd_aux_get_workarea) );
         if (bol1 == FALSE) {               /* aux returned error      */
           adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
           goto p_cleanup_20;               /* do cleanup now          */
         }
         ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
         ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
       }
       ADSL_OA1->achc_upper -= sizeof(struct dsd_wt_record_1);
#define ADSL_WTR1_G ((struct dsd_wt_record_1 *) ADSL_OA1->achc_upper)
// to-do 20.10.13 KB - can be optimized
       ADSL_WTR1_G->adsc_next = NULL;   /* clear chain             */
       ADSL_WTR1_G->ucc_record_type = (unsigned char) (D_ADSL_RCL1->chc_prot_r5_pdu_type & 0X0F) | 0X20;  /* record type */
       *ADSL_OA1->aadsc_wtr1_chain = ADSL_WTR1_G;  /* chain of WebTerm records */
       ADSL_OA1->aadsc_wtr1_chain = &ADSL_WTR1_G->adsc_next;  /* chain of WebTerm records */
       aadsl_gai1_ch = &ADSL_WTR1_G->adsc_gai1_data;   /* output data be be sent to client */
       /* decompress data in a loop                                    */
       do {
         if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) <= sizeof(struct dsd_gather_i_1)) {  /* get new area */
           memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
           bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                              DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                              &dsl_aux_get_workarea,
                                              sizeof(struct dsd_aux_get_workarea) );
           if (bol1 == FALSE) {             /* aux returned error      */
             adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
             goto p_cleanup_20;             /* do cleanup now          */
           }
           ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
           ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
         }
         ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_L1 ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
         ADSL_GAI1_L1->achc_ginp_cur
           = D_ADSL_RCO1->dsc_cdrf_dec.achc_out_cur  /* current end of output data */
             = ADSL_OA1->achc_lower;
         D_ADSL_RCO1->dsc_cdrf_dec.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
         D_ADSL_RCO1->amc_cdr_dec( &D_ADSL_RCO1->dsc_cdrf_dec );
         if (D_ADSL_RCO1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {
           m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d de-compression error %d.",
                         __LINE__, 15817,  /* line number for errors */
                         D_ADSL_RCO1->dsc_cdrf_dec.imc_return );
           goto p_cleanup_00;               /* do cleanup now          */
         }
         ADSL_GAI1_L1->achc_ginp_end
           = ADSL_OA1->achc_lower
             = D_ADSL_RCO1->dsc_cdrf_dec.achc_out_cur;
         *aadsl_gai1_ch = ADSL_GAI1_L1;     /* create chain gather data */
         aadsl_gai1_ch = &ADSL_GAI1_L1->adsc_next;  /* next entry create chain gather data */
#undef ADSL_GAI1_L1
       } while (D_ADSL_RCO1->dsc_cdrf_dec.boc_sr_flush == FALSE);  /* end-of-record output */
       *aadsl_gai1_ch = NULL;               /* end create chain gather data */
       if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* at end of block  */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
         D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_typ;  /* RDP 5 PDU type */
       goto pfrse20;                        /* needs more data         */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_send_from_server:        /* send data to client     */
       goto pfrse40;                        /* send RDP4 to client     */
     case ied_fsfp_end_com:                 /* end of communication    */
       if ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur != (unsigned char) 0X80) {
         iml_line_no = __LINE__;
         iml_source_no = 22709;    /* source line no for errors */
         goto pfrse92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RCL1->imc_pos_inp_frame--;    /* length constant         */
       if (D_ADSL_RCL1->imc_pos_inp_frame != 0) {
         iml_line_no = __LINE__;
         iml_source_no = 22714;    /* source line no for errors */
         goto pfrse92;
       }
       if (D_ADSL_RCL1->ac_redirect == NULL) {  /* memory for Standard Security Server Redirection PDU */
         if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < (sizeof(struct dsd_se_co1))) {  /* get new area */
           memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
           bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                              DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                              &dsl_aux_get_workarea,
                                              sizeof(struct dsd_aux_get_workarea) );
           if (bol1 == FALSE) {                   /* aux returned error      */
             adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
             goto p_cleanup_20;                   /* do cleanup now          */
           }
           ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
           ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
         }
         ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1);
#define ADSL_SE_CO1_G ((struct dsd_se_co1 *) ADSL_OA1->achc_upper)
         ADSL_SE_CO1_G->iec_se_command = ied_sec_end_session;  /* end of session server side */
         if (D_ADSL_RCL1->imc_prot_1 == 0X20) {
           ADSL_SE_CO1_G->iec_se_command = ied_sec_end_shutdown;  /* shutdown of server */
         }
         ADSL_SE_CO1_G->adsc_next = NULL;   /* clear chain field       */
         *ADSL_OA1->aadsc_se_co1_chain = ADSL_SE_CO1_G;  /* append to chain  */
         ADSL_OA1->aadsc_se_co1_chain = &ADSL_SE_CO1_G->adsc_next;  /* set new end of chain */
         goto p_cleanup_00;                 /* do cleanup now          */
#undef ADSL_SE_CO1_G
       }
        if (D_ADSL_RCL1->ac_redirect != NULL){
            char* achl_curpos = (char*)D_ADSL_RCL1->ac_redirect;
            unsigned int uml_mem_length = m_get_le4(achl_curpos);
            achl_curpos += 4;

            if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)
                < (sizeof(struct dsd_se_co1)
                    + sizeof(struct dsd_se_switch_server))) {
                memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
                bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                                DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                                &dsl_aux_get_workarea,
                                                sizeof(struct dsd_aux_get_workarea) );
                if (bol1 == FALSE) {               /* aux returned error      */
                    adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
                    goto p_cleanup_20;               /* do cleanup now          */
                }
                ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
                ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
            }
            ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1) + sizeof(struct dsd_se_switch_server);

#define ADSL_SE_CO1_G ((struct dsd_se_co1 *) ADSL_OA1->achc_upper)
#define ADSL_SE_SWITCH_SERVER ((struct dsd_se_switch_server *) (ADSL_SE_CO1_G + 1))
            memset( ADSL_SE_CO1_G, 0, sizeof(struct dsd_se_co1) + sizeof(struct dsd_se_switch_server) );
            ADSL_SE_CO1_G->iec_se_command = ied_sec_switch_server;  /* received connect to other RDP server */
       
            bol_rc = 
                m_parse_server_redirection_packet(achl_curpos, ADSL_SE_SWITCH_SERVER, uml_mem_length);
            if (bol_rc == FALSE){
                 iml_line_no = __LINE__;
                 iml_source_no = 22840;    /* source line no for errors */
                 goto pfrse96;
            }

            iml3 = m_decode_ineta( adsp_hl_clib_1, chrl_work_2, ADSL_SE_SWITCH_SERVER->achc_target_net_address, ADSL_SE_SWITCH_SERVER->umc_target_net_address_length );
            if (iml3 < 0) {                    /* returned error          */
              iml_line_no = __LINE__;
              iml_source_no = 22845;    /* source line no for errors */
              goto pfrse92;
            } else {
                ADSL_SE_SWITCH_SERVER->imc_len_ineta = iml3;                    /* length of INETA   */
                memcpy(ADSL_SE_SWITCH_SERVER->chrc_ineta, chrl_work_2, iml3);   /* INETA IPV4 / IPV6 to connect to */
            }
       
            *ADSL_OA1->aadsc_se_co1_chain = ADSL_SE_CO1_G;   /* append to chain */
            ADSL_OA1->aadsc_se_co1_chain = &ADSL_SE_CO1_G->adsc_next;  /* set new end of chain */
#undef ADSL_SE_CO1_G
#undef ADSL_SE_SWITCH_SERVER
        }
        D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_no_session;  /* no more session */
        goto pfrse20;                        /* process next data       */
     case ied_fsfp_no_session:              /* no more session         */
       iml_line_no = __LINE__;
       iml_source_no = 22861;    /* source line no for errors */
       goto pfrse92;
   }
   iml_line_no = __LINE__;
   iml_source_no = 22863;    /* source line no for errors */
   goto pfrse96;



   pfrse_end_pdu:                           /* end of pdu              */
   if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_4) {  /* not end of PDU data */
     iml_line_no = __LINE__;
     iml_source_no = 23314;    /* source line no for errors */
     goto pfrse92;
   }
// goto pfrse96;                            /* program illogic         */
#ifdef TRACEHL1
   if (D_ADSL_RCL1->imc_pos_inp_frame != 0) {  /* not end of block     */
     printf( "l%05d remainder of record len=%d/%04X buf=%p\n",
             __LINE__,
             D_ADSL_RCL1->imc_pos_inp_frame,
             D_ADSL_RCL1->imc_pos_inp_frame,
             adsl_gai1_inp_1->achc_ginp_cur );
   }
#endif
#ifdef D_FOR_TRACE1                         /* 31.05.05 KB - help in tracing */
   if (D_ADSL_RCL1->imc_pos_inp_frame != 0) {  /* not end of block     */
     iml1++;
     iml1--;
   }
#endif                                      /* 31.05.05 KB - help in tracing */
   if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* at end of block      */
     D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
     D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
     goto pfrse20;                          /* process next data       */
   }
   D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 1;  /* number of bytes */
   if (D_ADSL_RCL1->imc_prot_2 < 0) {
     iml_line_no = __LINE__;
     iml_source_no = 23339;    /* source line no for errors */
     goto pfrse92;
   }
   D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_typ;  /* RDP 5 PDU type  */
   goto pfrse20;                            /* process next data       */

   pfrse40:                                 /* send RDP4 data to client */
// to-do 20.11.13 KB - record may not be completely in input buffer - RDP client
// should use ied_fsfp_ignore               /* ignore this data        */
   /* ignore remaining part of this frame                              */
   while (TRUE) {                         /* loop over all gather structures input */
     iml1 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml1 > D_ADSL_RCL1->imc_pos_inp_frame) {
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* only data in this frame */
     }
     adsl_gai1_inp_1->achc_ginp_cur += iml1;  /* add length data processed */
     D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* subtract data processed */
     if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) break;  /* all data processed */
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next gather */
     if (adsl_gai1_inp_1 == NULL) {         /* already end of chain    */
       /* wait for more data                                           */
       goto p_ret_00;                       /* check how to return     */
     }
   }
   switch (D_ADSL_RCL1->iec_frse_bl) {
     case ied_frse_lic_pr_req_cert:         /* server license request  */
       if (m_get_le2( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 4 + 4 + m_get_le4( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 4 ) + sizeof(ucrs_lic_bef_cert))) {
         /* got a special server key for licensing, save it            */
         if (bol1 = (D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len < 0))  /* revert key before use */
           D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len = - D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len;
         if ( D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len <= D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len + D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_exp_len ) {
           /* chrc_lic_1 not big enough. free (no realloc), because no need to copy old content */
           ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
           ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
           m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 );
           D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len = D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len + D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_exp_len;
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len );
         }
         if (bol1) {                        /* copy invers             */
           achl1 = D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1;
           achl2 = D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_key;
           achl3 = achl1 + D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len;
           do {
             *(--achl3) = *(achl2++);
           } while (achl3 > achl1);
         } else {
           memcpy( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1,
                   D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_key,
                   D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len );
         }
         memcpy( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len,
                 D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_exp,
                 D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_exp_len );
         D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_key =
                 D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1;
         D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_exp =
                 D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len;
       }
       /* put command in queue */

       D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
       goto pfrse20;                    /* process next data       */

     case ied_frse_lic_pr_chll:             /* platform challenge      */
       // +-----------------------------------------+
       // | Send Client Platform Challenge Response |
       // +-----------------------------------------+

       iml5 = m_get_le2(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1); /* hwid length */
       iml1 = 4                             /* Licencing Preamble      */
              + 4 + 8 + iml5   /* EncryptedPlatformChallengeResponse */
              + 4 + 4 + 0X10   /* Blob EncryptedHWID */
              + 0X10;          /* Hash */
// to-do 20.04.12 KB work-area big enough ???
       ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
       achl3 = achl1 = ADSL_OA1->achc_lower; // save position of start

       *achl1++ = DEF_CONST_RDP_03;
       *achl1++ = 0;                        /* second byte zero        */
       achl1 += 2;    // save space for length
       memcpy(achl1, ucrs_x224_p01, sizeof(ucrs_x224_p01));
       achl1 += sizeof(ucrs_x224_p01);
       *achl1++ = 0X64;  /* send data request */
       m_put_be2(achl1, D_ADSL_RCL1->dsc_rdp_co_1.usc_userid_cl2se);
       achl1 += 2;
       m_put_be2(achl1, D_ADSL_RCL1->imc_prot_chno);
       achl1 += 2;
       *achl1++ = 0X70;                     /* priority / segmentation */
       if (iml1 <= (127 - 4)) {             /* length in one byte      */
         *achl1++ = (unsigned char) (iml1 + 4);
       } else {
         m_put_be2( achl1, iml1 + 4 );
         *achl1 |= 0X80;                    /* length in two bytes     */
         achl1 += 2;
       }
       m_put_le2(achl1, 0X80);              /* encyption flags: licensing encryption */
       achl1 += 2;
//     m_put_le2(achl1, 0X00); /* padding */
//     achl1 += 2;
       *achl1++ = 0;                        /* padding                 */
       *achl1++ = 0;                        /* padding                 */

       *achl1++ = 0x15;                     /* type: Client Platform Challenge Response */
       *achl1++ = D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers;      /* version 2 or 3, and maybe flag 0x80 */
       m_put_le2( achl1, iml1 );            /* len */
       achl1 += 2;
       // EncryptedPlatformChallengeResponse
       m_put_le2( achl1, 0x0009 ); /* BB_ENCRYPTED_DATA_BLOB */
       achl1 += 2;
       m_put_le2( achl1, iml5 + 8 ); /* len of Platform challenge response data */
       achl1 += 2;

#define ACHL_WORK_SHA1 ((int *) chrl_work_2)
#define ACHL_WORK_MD5 ((int *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int)))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
#define ACHL_WORK_CHLL ((char *) ACHL_WORK_UTIL_01 + 20)
#define ACHL_WORK_RC4 ACHL_WORK_CHLL + iml5 + 8 + 20

       achl2 = ACHL_WORK_CHLL; /* Start to write Data on workarea. */
       m_put_le2( achl2, 0x0100 ); /* wVersion */
       achl2 += 2;
       m_put_le2( achl2, 0x0100 ); /* wClientType. JWT sends first two bytes of hardware-id? */
       achl2 += 2;
       m_put_le2( achl2, 0x0003 ); /* wLicenseDetailLevel */
       achl2 += 2;
       m_put_le2( achl2, iml5 ); /* bytes in pbChallenge field (test-data) */
       achl2 += 2;
       memcpy( achl2, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 2, iml5 ); /* pbChallenge field (test-data) */
       achl2 += iml5;
       /* encrypt data -> In Licensing JWT initializes the state before every call of RC4. */
       memcpy( ACHL_WORK_RC4, D_ADSL_RCO1->adsc_lic_neg->chrc_rc4_state_cl2se, RC4_STATE_SIZE);
       RC4( ACHL_WORK_CHLL, 0, iml5 + 8,
            achl1, 0, ACHL_WORK_RC4);
       achl1 += iml5 + 8;
       // EncryptedHWID
       m_put_le2( achl1, 0x0009 );
       achl1 += 2;
       m_put_le2( achl1, 0x14);
       achl1 += 0x2;

       m_put_le4( achl2, D_ADSL_RCO1->imc_platform_id);
       achl2 += 4;
       memcpy( achl2, D_ADSL_RCO1->chrc_client_hardware_data, 0x10 ); /* Data-fields of client hardware identification */
       achl2 += 0x10;
       /* encrypt data -> JWT initializes the state before every call of RC4. */
       memcpy( ACHL_WORK_RC4, D_ADSL_RCO1->adsc_lic_neg->chrc_rc4_state_cl2se, RC4_STATE_SIZE );
       RC4( ACHL_WORK_CHLL + iml5 + 8, 0, 4 + 0x10,
            achl1, 0, ACHL_WORK_RC4);
       achl1 += 4 + 0X10;
       /* calculate the hash                            */
       /* JWT initializes the state of SHA1 and MD5 before every call! */
       iml1 = iml5 + 8 + 4 + 0X10;
       memcpy( ACHL_WORK_SHA1,
               D_ADSL_RCO1->adsc_lic_neg->imrc_sha1_state,
               sizeof(D_ADSL_RCO1->adsc_lic_neg->imrc_sha1_state) );
       memcpy( ACHL_WORK_MD5,
               D_ADSL_RCO1->adsc_lic_neg->imrc_md5_state,
               sizeof(D_ADSL_RCO1->adsc_lic_neg->imrc_md5_state) );
       m_put_le4( ACHL_WORK_UTIL_01, iml1 );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_CHLL, 0, iml1 );
       SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );

       MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
       MD5_Final( ACHL_WORK_MD5, achl1, 0 );
       achl1 += 0X10;

#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
#undef ACHL_WORK_CHLL
#undef ACHL_WORK_RC4

       iml1 = achl1 - achl3;
       m_put_be2(achl3 + 2, iml1);
       ADSL_GAI1_OUT_G->adsc_next = NULL;
       ADSL_GAI1_OUT_G->achc_ginp_cur = achl3;
       ADSL_GAI1_OUT_G->achc_ginp_end = achl1;
       *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;
       ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;
       ADSL_OA1->achc_lower = achl1;           /* set end of storage used */
#undef ADSL_GAI1_OUT_G
//#undef ACHL_OUT1
       D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* receive block active PDU XXX maybe introduce extra states for awaiting licensing packets? */
       break;
     case ied_frse_lic_pr_1_rec:            /* receive block licence protocol */
     case ied_frse_lic_pr_type:             /* licencing block to check */
     case ied_frse_deactivate_all:          /* Connect to existing session */
     case ied_frse_error_bl_02:             /* receive error block 02  */
     case ied_frse_actpdu_trail:            /* trailer of act PDU      */
     case ied_frse_any_pdu_rec:             /* Share Control Header PDU source */
     case ied_frse_xyz_end_pdu:             /* end of PDU              */
       D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
       break;
   }
   D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
   goto pfrse20;                            /* process next data       */


   pfrse_send_secbl:                        /* send second block to server */
    if (adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.umc_selected_protocol != PROTOCOL_RDP){
       adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
       dsl_gai1_comp_data.achc_ginp_cur = NULL;
    }
#define D_ADSL_VCH (D_ADSL_RCO1->adsrc_vc_1 + (D_ADSL_RCO1->imc_no_virt_ch - iml1))
   if (!m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1,
     (376 
      + D_ADSL_RCO1->imc_no_virt_ch * (sizeof(D_ADSL_VCH->byrc_name) + 4) 
      + 4 + 4 + 4 + D_ADSL_RCO1->imc_monitor_count * sizeof(struct dsd_ts_monitor_def) 
      + 4 + 4 + 4 + 4 + D_ADSL_RCO1->imc_monitor_attributes_count * sizeof(struct dsd_ts_monitor_attributes) 
      + sizeof(struct dsd_gather_i_1))))
    {
      iml_line_no = __LINE__;
      iml_source_no = 24452;    /* source line no for errors */
      goto pfrse96;
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
#define ACHL_OUT1 ADSL_OA1->achc_lower
   achl1 = ACHL_OUT1;                       /* start output here       */
   *achl1 = DEF_CONST_RDP_03;
   memcpy( achl1 + 4,
           ucrs_x224_mcs,
           sizeof(ucrs_x224_mcs) );
   /* length in three bytes                                            */
   memcpy( achl1 + 12,
           ucrs_x224_p02,
           sizeof(ucrs_x224_p02) );
   *(achl1 + 105) = DEF_CONST_ASN1_OS_04;
   memcpy( achl1 + 109,
           ucrs_x224_p03,
           sizeof(ucrs_x224_p03) );
   /* length in two bytes                                              */
   memcpy( achl1 + 118,
           ucrs_x224_p04,
           sizeof(ucrs_x224_p04) );
   /* length in two bytes                                              */
   memcpy( achl1 + 132,
           ucrs_x224_p05,
           sizeof(ucrs_x224_p05) );
   m_put_le2( achl1 + 140,
              D_ADSL_RCO1->imc_dim_x );
   m_put_le2( achl1 + 142,
              D_ADSL_RCO1->imc_dim_y );
   memcpy( achl1 + 144,
           ucrs_x224_p06,
           sizeof(ucrs_x224_p06) );
   m_put_le4( achl1 + 148,
              D_ADSL_RCO1->imc_keyboard_layout );
   memcpy( achl1 + 152,
           ucrs_x224_buildno,
           sizeof(ucrs_x224_buildno) );
   memcpy( achl1 + 156,
           D_ADSL_RCO1->wcrc_computer_name,
           sizeof(D_ADSL_RCO1->wcrc_computer_name) );
   /* Type of Keyboard / 102                                           */
   m_put_le4( achl1 + 188,
              D_ADSL_RCO1->imc_keyboard_type );
   /* Subtype of Keyboard                                              */
   m_put_le4( achl1 + 192,
              D_ADSL_RCO1->imc_keyboard_subtype );
   /* Number of Function Keys                                          */
   m_put_le4( achl1 + 196,
              D_ADSL_RCO1->imc_no_func_keys );
   /* IME Mapping Table                                                */
   memset( achl1 + 200, 0, 64 );
   memcpy( achl1 + 264,
           ucrs_x224_encry,
           sizeof(ucrs_x224_encry) );
   // Copy the TS_UD_CS_CORE::earlyCapabilityFlags:
   *(achl1 + 264 + 12) |= ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_cl_early_capability_flag;
   /* field highColorDepth                                             */
   switch( D_ADSL_RCO1->imc_s_coldep ) {
     case 8:
     case 15:
     case 16:
     case 24:
       m_put_le2( achl1 + 264 + 8, D_ADSL_RCO1->imc_s_coldep );
       break;
     case 32:
       m_put_le2( achl1 + 264 + 8, 24 );    /* highColorDepth, maximum */
       *(achl1 + 264 + 10) |= RNS_UD_32BPP_SUPPORT;  /* supportedColorDepths */
       *(achl1 + 264 + 12) |= RNS_UD_CS_WANT_32BPP_SESSION;  /* earlyCapailityFlags */
       break;
     default:
       iml_line_no = __LINE__;
       iml_source_no = 24546;    /* source line no for errors */
       goto pfrse96;
   }
   m_put_le4( achl1 + 264 + 80, D_ADSL_RCO1->dsc_rdp_neg_resp.umc_selected_protocol );
   /* output CS_NET                                                    */
#define D_POS_VCH (264 + sizeof(ucrs_x224_encry))
   *(achl1 + D_POS_VCH + 0) = 0X03;
   *(achl1 + D_POS_VCH + 1) = (unsigned char) 0XC0;
   iml1 = D_ADSL_RCO1->imc_no_virt_ch;
   m_put_le2( achl1 + D_POS_VCH + 2,
              8 + iml1 * DEF_LEN_VIRTCH_STA );
   m_put_le4( achl1 + D_POS_VCH + 4,
              iml1 );
   achl1 += D_POS_VCH + 8;
#undef D_POS_VCH
   while (iml1) {                           /* loop over all channels  */
     memcpy( achl1,
             D_ADSL_VCH->byrc_name,
             sizeof(D_ADSL_VCH->byrc_name) );
     achl1 += sizeof(D_ADSL_VCH->byrc_name);
     m_put_le4( achl1, D_ADSL_VCH->imc_flags );
     achl1 += 4;                            /* after flags             */
     iml1--;                                /* decrement index         */
   }
   if (D_ADSL_RCO1->dsc_rdp_neg_resp.usc_flags & EXTENDED_CLIENT_DATA_SUPPORTED) {
      // The following fields can only be present if the EXTENDED_CLIENT_DATA_SUPPORTED is present:
      if (D_ADSL_RCO1->boc_multimonitor_support){
         // 2.2.1.3.6 Client Monitor Data (TS_UD_CS_MONITOR):
         if (D_ADSL_RCO1->imc_monitor_count > 0){
            // TD_UD_CS_MONITOR::header:
            // TD_UD_CS_MONITOR::header::type:
            m_put_le2(achl1, 0xC005);    // CS_MONITOR
            achl1 += 2;
            // TD_UD_CS_MONITOR::header::length:
            m_put_le2(achl1, 4 + 4 + 4 
              + D_ADSL_RCO1->imc_monitor_count * sizeof(struct dsd_ts_monitor_def));
            achl1 += 2;
            // TD_UD_CS_MONITOR::flags:
            m_put_le4(achl1, 0x00);
            achl1 += 4;
            // TD_UD_CS_MONITOR::monitorCount:
            m_put_le4(achl1, D_ADSL_RCO1->imc_monitor_count);
            achl1 += 4;
            // TD_UD_CS_MONITOR::monitorAttributesArray:
            iml1 = D_ADSL_RCO1->imc_monitor_count;
            struct dsd_ts_monitor_def* achl_monitor 
               = D_ADSL_RCO1->adsrc_ts_monitor;
            while (iml1) {
               //memcpy(achl1, achl_monitor, sizeof(struct dsd_ts_monitor_def));
					//achl1 += sizeof(struct dsd_ts_monitor_def);
               m_put_le4(achl1, achl_monitor->imc_left);
					achl1 += 4;
					m_put_le4(achl1, achl_monitor->imc_top);
					achl1 += 4;
					m_put_le4(achl1, achl_monitor->imc_right);
					achl1 += 4;
					m_put_le4(achl1, achl_monitor->imc_bottom);
					achl1 += 4;
					m_put_le4(achl1, achl_monitor->umc_flags);
					achl1 += 4;
               achl_monitor += 1;
               iml1--;
            }
         }
      }
   }
   if (D_ADSL_RCO1->dsc_rdp_neg_resp.usc_flags & EXTENDED_CLIENT_DATA_SUPPORTED) {
      // The following fields can only be present if the EXTENDED_CLIENT_DATA_SUPPORTED is present:
      if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_enable_mcs_message_channel != FALSE){
         // clientMessageChannelData (8 bytes): Optional Client Message Channel Data structure (section 2.2.1.3.7):
         // header (4 bytes):
         m_put_le2(achl1, CS_MCS_MSGCHANNEL);
         achl1 += 2;
         m_put_le2(achl1, 8);
         achl1 += 2;
         // flags (4 bytes):
         m_put_le4(achl1, 0);
         achl1 += 4;
      }
   } else {
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_enable_mcs_message_channel = FALSE;
   }
   if (D_ADSL_RCO1->dsc_rdp_neg_resp.usc_flags & EXTENDED_CLIENT_DATA_SUPPORTED) {
      // The following fields can only be present if the EXTENDED_CLIENT_DATA_SUPPORTED is present:
      if (D_ADSL_RCO1->boc_multimonitor_support){
         // 2.2.1.3.9 Client Monitor Extended Data (TS_UD_CS_MONITOR_EX):
         if (D_ADSL_RCO1->imc_monitor_attributes_count == D_ADSL_RCO1->imc_monitor_count){
            // TS_UD_CS_MONITOR_EX::header:
            // TS_UD_CS_MONITOR_EX::header::type:
            m_put_le2(achl1, 0xC008);    // CS_MONITOR_EX 
            achl1 += 2;
            // TS_UD_CS_MONITOR_EX::header::length:
            m_put_le2(achl1, 4 + 4 + 4 + 4
               + D_ADSL_RCO1->imc_monitor_attributes_count 
               * sizeof(struct dsd_ts_monitor_attributes));
            achl1 += 2;
            // TS_UD_CS_MONITOR_EX::flags:
            m_put_le4(achl1, 0x00);
            achl1 += 4;
            // TS_UD_CS_MONITOR_EX::monitorAttributeSize :
            m_put_le4(achl1, 20);
            achl1 += 4;
            // TS_UD_CS_MONITOR_EX::monitorCount:
            m_put_le4(achl1, D_ADSL_RCO1->imc_monitor_attributes_count);
            achl1 += 4;
            // TS_UD_CS_MONITOR_EX::monitorAttributesArray:
            iml1 = D_ADSL_RCO1->imc_monitor_attributes_count;
            struct dsd_ts_monitor_attributes* achl_monitor_attributes
               = D_ADSL_RCO1->adsrc_ts_monitor_attributes;
            while (iml1) {
               memcpy(achl1, achl_monitor_attributes, sizeof(struct dsd_ts_monitor_attributes));
               achl1 += sizeof(struct dsd_ts_monitor_attributes);
               achl_monitor_attributes += 1;
               iml1--;
            }
         }
      }
   }
   m_put_be2( ACHL_OUT1 + 10,
              achl1 - (ACHL_OUT1 + 10 + 2) );
   *(ACHL_OUT1 + 9) = (unsigned char) 0X82;
   m_put_be2( ACHL_OUT1 + 107,
              achl1 - (ACHL_OUT1 + 107 + 2) );
   *(ACHL_OUT1 + 106) = (unsigned char) 0X82;
   /* output length of block                                           */
   /* set length fields                                                */
   m_put_be2( ACHL_OUT1 + 116,
              achl1 - (ACHL_OUT1 + 116 + 2) );
   *(ACHL_OUT1 + 116) |= 0X80;
   m_put_be2( ACHL_OUT1 + 130,
              achl1 - (ACHL_OUT1 + 130 + 2) );
   *(ACHL_OUT1 + 130) |= 0X80;
   *(ACHL_OUT1 + 1) = 0;
   m_put_be2( ACHL_OUT1 + 2,
              achl1 - ACHL_OUT1 );
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
//         D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_02;
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   ADSL_GAI1_OUT_G->achc_ginp_cur = ACHL_OUT1;
   ADSL_GAI1_OUT_G->achc_ginp_end = achl1;
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;
   ACHL_OUT1 = achl1;
   ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl = ied_fsfp_rec_type;  /* first record type */
   D_ADSL_RCL1->iec_frse_bl = ied_frse_rec_04;
   goto pfrse20;                            /* process next data       */
#undef D_ADSL_VCH
#undef ADSL_GAI1_OUT_G
#undef ACHL_OUT1

   pfrse_send_erect_domain_request_pdu:
   if(!m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1, sizeof(struct dsd_gather_i_1))) {
     iml_line_no = __LINE__;
     iml_source_no = 24800;    /* source line no for errors */
     goto pfrse96;
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   #define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   ADSL_GAI1_OUT_G->achc_ginp_cur = (char *) ucrs_x224_errect_domain_pdu;
   ADSL_GAI1_OUT_G->achc_ginp_end = (char *) ucrs_x224_errect_domain_pdu + sizeof(ucrs_x224_errect_domain_pdu);
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
   goto pfrse20;                            /* process next data       */
pfrse_mcs_msgchannel:
   while (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
      adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
      if (adsl_gai1_inp_1 == NULL) return;   /* wait for more data      */
   }
   /* check if all data of this frame have been received               */
   iml1 = D_ADSL_RCL1->imc_pos_inp_frame;   /* remaining data in frame */
   adsl_gai1_inp_w2 = adsl_gai1_inp_1;      /* get gather              */
   while (TRUE) {                           /* loop over all gather structures input */
      iml1 -= adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
      if (iml1 <= 0) break;                  /* enough data found       */
      adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
      if (adsl_gai1_inp_w2 == NULL) {        /* already end of chain    */
         /* wait for more data                                           */
         goto p_ret_00;                       /* check how to return     */
      }
   }
   // In the MSC MSGChannel there aren't any PDUs with 0 length payloads:
   if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
      iml_line_no = __LINE__;
      iml_source_no = 24833;    /* source line no for errors */
      goto pfrse92;
   }
   adsl_gai1_inp_w2 = adsl_gai1_inp_1;      /* save input data         */
   iml1 = D_ADSL_RCL1->imc_pos_inp_frame;   /* length of data          */
   // TODO: TRACING (starts here)
   ADSL_RDPA_F->dsc_rdptr1.iec_tr_command   /* tracer component command */
      = ied_trc_se2cl_vch;                   /* server to client virtual channel */
   ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_part - D_ADSL_RCL1->imc_pos_inp_frame;
   /* virtual channel flags                                            */
   memcpy( ADSL_RDPA_F->dsc_rdptr1.chrc_vch_flags, D_ADSL_RCL1->chrc_vch_flags, sizeof(ADSL_RDPA_F->dsc_rdptr1.chrc_vch_flags) );
   ADSL_RDPA_F->dsc_rdptr1.usc_vch_no = D_ADSL_RCL1->imc_prot_chno;  /* virtual channel no com */
   ADSL_RDPA_F->dsc_rdptr1.imc_prot1 = D_ADSL_RCL1->umc_vch_ulen;  /* variable field */
   /* trace server to client virtual channel                           */
   if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
      ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_inp_w2;
      ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = iml1;  /* remaining data */
      m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
   }
   // TODO: TRACING (end)
   {
      if (m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1, 
         sizeof(struct dsd_se_co1) + sizeof(struct dsd_rdp_mcs_msgchannel_io) +  sizeof(struct dsd_gather_i_1)) == FALSE){
         iml_line_no = __LINE__;
         iml_source_no = 24855;    /* source line no for errors */
         goto pfrse92;
      }
      ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1) + sizeof(struct dsd_rdp_mcs_msgchannel_io) + sizeof(struct dsd_gather_i_1);
      
      struct dsd_se_co1* adsl_sc = (struct dsd_se_co1*)ADSL_OA1->achc_upper;
      adsl_sc->iec_se_command = ied_sec_msc_msgchannel_in;
      adsl_sc->adsc_next = NULL;
      *ADSL_OA1->aadsc_se_co1_chain = adsl_sc;  /* append to chain  */
      ADSL_OA1->aadsc_se_co1_chain = &adsl_sc->adsc_next;  /* set new end of chain */

      struct dsd_rdp_mcs_msgchannel_io* adsl_sc_payload = (struct dsd_rdp_mcs_msgchannel_io*) (adsl_sc + 1);
      struct dsd_gather_i_1* adsl_sc_payload_data = (struct dsd_gather_i_1*)(adsl_sc_payload + 1);
      
      adsl_sc_payload->umc_data_ulen = D_ADSL_RCL1->imc_pos_inp_frame;
      adsl_sc_payload->adsc_gai1_data = adsl_sc_payload_data;

      switch (D_ADSL_RCL1->chc_prot_rt03 & ((SEC_AUTODETECT_REQ | SEC_HEARTBEAT) >> 8)){
      case (SEC_AUTODETECT_REQ >> 8):
         adsl_sc_payload->iec_rmms = ied_rmms_network_characteristics_detection;
         break;
      case (SEC_HEARTBEAT >> 8):
         adsl_sc_payload->iec_rmms = ied_rmms_connection_health_monitoring;
         break;
      default:
         iml_line_no = __LINE__;
         iml_source_no = 24879;    /* source line no for errors */
         goto pfrse92;
      }
      adsl_gai1_w1 = adsl_sc_payload->adsc_gai1_data;
   }
   /* create gather structures with the data received over this virtual channel */
   while (TRUE) {                           /* loop over input bytes   */
      iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
      if (iml2 > iml1) iml2 = iml1;
      adsl_gai1_w1->achc_ginp_cur = adsl_gai1_inp_w2->achc_ginp_cur;
      adsl_gai1_w1->achc_ginp_end = adsl_gai1_inp_w2->achc_ginp_cur + iml2;
      adsl_gai1_inp_w2->achc_ginp_cur += iml2;
      if (adsl_gai1_inp_w2->achc_ginp_cur >= adsl_gai1_inp_w2->achc_ginp_end) {
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
      }
      iml1 -= iml2;                          /* remaining data to pass  */
      if (iml1 <= 0) break;                  /* end of data to pass     */
      if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < sizeof(struct dsd_gather_i_1)) {  /* get new area */
         memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
         bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                          DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                          &dsl_aux_get_workarea,
                                          sizeof(struct dsd_aux_get_workarea) );
         if (bol1 == FALSE) {                 /* aux returned error      */
            adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
            goto p_cleanup_20;                 /* do cleanup now          */
         }
         ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
         ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
      }
      ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
      adsl_gai1_w1->adsc_next = (struct dsd_gather_i_1 *) ADSL_OA1->achc_upper;  /* set chain gather */
      adsl_gai1_w1 = (struct dsd_gather_i_1 *) ADSL_OA1->achc_upper;  /* use next gather */
   }
   adsl_gai1_w1->adsc_next = NULL;          /* set end chain gather    */
   dsl_gai1_comp_data.achc_ginp_cur = NULL;  /* no decompressed data   */
   D_ADSL_RCL1->imc_pos_inp_frame = 0;      /* the frame has been processed */
   D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
   D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
   goto pfrse20;                            /* process next data       */
   pfrse_vch_00:                            /* virtual channel data received */
   while (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) return;   /* wait for more data      */
   }
   /* check if all data of this frame have been received               */
   iml1 = D_ADSL_RCL1->imc_pos_inp_frame;   /* remaining data in frame */
   adsl_gai1_inp_w2 = adsl_gai1_inp_1;      /* get gather              */
   while (TRUE) {                           /* loop over all gather structures input */
     iml1 -= adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
     if (iml1 <= 0) break;                  /* enough data found       */
     adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
     if (adsl_gai1_inp_w2 == NULL) {        /* already end of chain    */
       /* wait for more data                                           */
       goto p_ret_00;                       /* check how to return     */
     }
   }
   // TODO: check what happens with a VCH PDU with no payload (payload length = 0) and with maximum length
   if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
     iml_line_no = __LINE__;
     iml_source_no = 24929;    /* source line no for errors */
     goto pfrse92;
   }
   /* trace server to client virtual channel                           */
   ADSL_RDPA_F->dsc_rdptr1.iec_tr_command   /* tracer component command */
     = ied_trc_se2cl_vch;                   /* server to client virtual channel */
   ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_part - D_ADSL_RCL1->imc_pos_inp_frame;
   /* virtual channel flags                                            */
   memcpy( ADSL_RDPA_F->dsc_rdptr1.chrc_vch_flags, D_ADSL_RCL1->chrc_vch_flags, sizeof(ADSL_RDPA_F->dsc_rdptr1.chrc_vch_flags) );
   ADSL_RDPA_F->dsc_rdptr1.usc_vch_no = D_ADSL_RCL1->imc_prot_chno;  /* virtual channel no com */
   ADSL_RDPA_F->dsc_rdptr1.imc_prot1 = D_ADSL_RCL1->umc_vch_ulen;  /* variable field */
   if (D_ADSL_RCL1->chrc_vch_flags[2] & 0X20) {  /* data compressed    */
     goto pfrse_vch_20;                     /* virtual channel data compressed */
   }
   bol_compressed = FALSE;                  /* save not compressed     */
   adsl_gai1_inp_w2 = adsl_gai1_inp_1;      /* save input data         */
   iml1 = D_ADSL_RCL1->imc_pos_inp_frame;   /* length of data          */
   goto pfrse_vch_40;                       /* send virtual channel to client */

   pfrse_vch_20:                            /* virtual channel data compressed */
   if ((D_ADSL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) == 0) {  /* compression not enabled */
     iml_line_no = __LINE__;
     iml_source_no = 24951;    /* source line no for errors */
     goto pfrse92;
   }
   bol_compressed = TRUE;                   /* save compressed         */
// to-do 21.02.12 KB decompression
   /* decompress data                                                  */
   D_ADSL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
   D_ADSL_RCO1->dsc_cdrf_dec.chrc_header[ 0 ]  /* copy compression header */
     = D_ADSL_RCL1->chrc_vch_flags[2];      /* flags for compression   */
   /* prepare gather of all input data                                 */
#define ADSL_GAI1_S ((struct dsd_gather_i_1 *) chrl_work_2)
   adsl_gai1_w1 = ADSL_GAI1_S;              /* first gather here       */
   while (TRUE) {                           /* loop over input bytes   */
     if (adsl_gai1_inp_1 == NULL) {         /* already end of chain    */
       M_ERROR_FRSE_ILLOGIC
     }
     iml1 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml1 > D_ADSL_RCL1->imc_pos_inp_frame) iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data in frame */
     D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* compute remaining length compressed data */
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_cur;
     adsl_gai1_w1->achc_ginp_end = adsl_gai1_inp_1->achc_ginp_cur + iml1;
     adsl_gai1_inp_1->achc_ginp_cur += iml1;
     if (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
     if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) break;  /* now last part */
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain gather  */
     adsl_gai1_w1++;                        /* use next gather         */
   }
   adsl_gai1_w1->adsc_next = NULL;          /* end of data             */
   D_ADSL_RCO1->dsc_cdrf_dec.adsc_gai1_in = ADSL_GAI1_S;  /* input data */
#undef ADSL_GAI1_S
   D_ADSL_RCO1->dsc_cdrf_dec.boc_mp_flush = TRUE;  /* end-of-record input */
   adsl_gai1_w2 = &dsl_gai1_comp_data;
   /* decompress data in a loop                                    */
   iml1 = 0;                                /* clear count decompressed data */
   while (TRUE) {
     adsl_gai1_w2->achc_ginp_cur
       = D_ADSL_RCO1->dsc_cdrf_dec.achc_out_cur  /* current end of output data */
         = ADSL_OA1->achc_lower;
     D_ADSL_RCO1->dsc_cdrf_dec.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
     D_ADSL_RCO1->amc_cdr_dec( &D_ADSL_RCO1->dsc_cdrf_dec );
     if (D_ADSL_RCO1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {
       m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d de-compression error %d.",
                     __LINE__, 25003,  /* line number for errors */
                     D_ADSL_RCO1->dsc_cdrf_dec.imc_return );
       goto p_cleanup_00;                   /* do cleanup now          */
     }
     adsl_gai1_w2->achc_ginp_end
       = ADSL_OA1->achc_lower
         = D_ADSL_RCO1->dsc_cdrf_dec.achc_out_cur;
     iml1 += adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur;  /* length of data */
     adsl_gai1_w2->adsc_next = NULL;        /* end of chain gather     */
     if (D_ADSL_RCO1->dsc_cdrf_dec.boc_sr_flush) break;  /* end-of-record output */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error      */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       goto p_cleanup_20;                   /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
     adsl_gai1_w1++;                        /* next gather             */
     adsl_gai1_w2->adsc_next = adsl_gai1_w1;  /* set chain gather      */
     adsl_gai1_w2 = adsl_gai1_w1;           /* put into this gather    */
   }
   adsl_gai1_inp_w2 = &dsl_gai1_comp_data;  /* process decompressed data */

   pfrse_vch_40:                            /* send virtual channel to client */
   /* trace server to client virtual channel                           */
   if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
     ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_inp_w2;
     ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = iml1;  /* remaining data */
     m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
   }
   if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)
         < (sizeof(struct dsd_se_co1) + sizeof(struct dsd_rdp_vch_io) + sizeof(struct dsd_gather_i_1))) {  /* get new area */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error      */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       goto p_cleanup_20;                   /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_se_co1) + sizeof(struct dsd_rdp_vch_io) + sizeof(struct dsd_gather_i_1);
#define ADSL_SE_CO1_G ((struct dsd_se_co1 *) ADSL_OA1->achc_upper)
   ADSL_SE_CO1_G->iec_se_command = ied_sec_vch_in;  /* input from virtual channel */
   ADSL_SE_CO1_G->adsc_next = NULL;         /* clear chain field       */
   *ADSL_OA1->aadsc_se_co1_chain = ADSL_SE_CO1_G;  /* append to chain  */
   ADSL_OA1->aadsc_se_co1_chain = &ADSL_SE_CO1_G->adsc_next;  /* set new end of chain */
#define ADSL_SC_VCH_OUT_G ((struct dsd_rdp_vch_io *) (ADSL_SE_CO1_G + 1))
   iml2 = D_ADSL_RCO1->imc_no_virt_ch;      /* number of virtual channels */
   while (TRUE) {                           /* loop over all virtual channels */
     if (iml2 <= 0) {                       /* virtual channel not found */
       iml_line_no = __LINE__;
       iml_source_no = 25411;    /* source line no for errors */
       goto pfrse92;
     }
     iml2--;                                /* decrement index         */
     if (D_ADSL_RCO1->adsrc_vc_1[ iml2 ].usc_vch_no == D_ADSL_RCL1->imc_prot_chno) {  /* virtual channel no com */
       ADSL_SC_VCH_OUT_G->adsc_rdp_vc_1 = &D_ADSL_RCO1->adsrc_vc_1[ iml2 ];  /* RDP virtual channel */
       break;
     }
   }
#define ADSL_GAI1_OUT1 ((struct dsd_gather_i_1 *) (ADSL_SC_VCH_OUT_G + 1))
   ADSL_SC_VCH_OUT_G->adsc_gai1_data = ADSL_GAI1_OUT1;  /* output data */
   // to-do 24.03.13 KB - which field is needed, compatible with other components
   ADSL_SC_VCH_OUT_G->umc_vch_ulen = iml1;  /* virtual channel length uncompressed */
// ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_part - (D_ADSL_RCL1->imc_pos_inp_frame - 2);
   /* virtual channel flags                                            */
   memcpy( ADSL_SC_VCH_OUT_G->chrc_vch_flags, D_ADSL_RCL1->chrc_vch_flags, sizeof(ADSL_SC_VCH_OUT_G->chrc_vch_flags) );
// ADSL_RDPA_F->dsc_rdptr1.usc_vch_no = D_ADSL_RCL1->imc_prot_chno;  /* virtual channel no com */
// ADSL_RDPA_F->dsc_rdptr1.imc_prot1 = D_ADSL_RCL1->umc_vch_ulen;  /* variable field */
   adsl_gai1_w1 = ADSL_GAI1_OUT1;           /* first gather here       */
#undef ADSL_SE_CO1_G
#undef ADSL_SC_VCH_OUT_G
#undef ADSL_GAI1_OUT1
   /* create gather structures with the data received over this virtual channel */
   while (TRUE) {                           /* loop over input bytes   */
     iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
     if (iml2 > iml1) iml2 = iml1;
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_inp_w2->achc_ginp_cur;
     adsl_gai1_w1->achc_ginp_end = adsl_gai1_inp_w2->achc_ginp_cur + iml2;
     adsl_gai1_inp_w2->achc_ginp_cur += iml2;
     if (adsl_gai1_inp_w2->achc_ginp_cur >= adsl_gai1_inp_w2->achc_ginp_end) {
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
     }
     iml1 -= iml2;                          /* remaining data to pass  */
     if (iml1 <= 0) break;                  /* end of data to pass     */
     if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < sizeof(struct dsd_gather_i_1)) {  /* get new area */
       memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
       bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                          DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                          &dsl_aux_get_workarea,
                                          sizeof(struct dsd_aux_get_workarea) );
       if (bol1 == FALSE) {                 /* aux returned error      */
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
         goto p_cleanup_20;                 /* do cleanup now          */
       }
       ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
       ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
     }
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     adsl_gai1_w1->adsc_next = (struct dsd_gather_i_1 *) ADSL_OA1->achc_upper;  /* set chain gather */
     adsl_gai1_w1 = (struct dsd_gather_i_1 *) ADSL_OA1->achc_upper;  /* use next gather */
   }
   adsl_gai1_w1->adsc_next = NULL;          /* set end chain gather    */
   dsl_gai1_comp_data.achc_ginp_cur = NULL;  /* no decompressed data   */
   D_ADSL_RCL1->imc_pos_inp_frame = 0;      /* the frame has been processed */
   D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
   D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
   goto pfrse20;                            /* process next data       */

   p_cjr_frse_00:                           /* send channel join request */
   if (D_ADSL_RCL1->imc_prot_5 > D_ADSL_RCO1->imc_no_virt_ch + 1) {
      if ((ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_enable_mcs_message_channel != FALSE) 
      && (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_mcs_message_channel_active == FALSE)){
         iml1 = D_ADSL_RCO1->usc_chno_mcs_msgchannel;
         D_ADSL_RCL1->imc_prot_5 = HL_EXTRA_MCS_CHANNELS;
      } else {
         goto p_cjr_frse_20;                    /* send client private key */
      }
   }
   if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)
         < (sizeof(ucrs_x224_cjreq_1)
              + 2 + 2
              + sizeof(struct dsd_gather_i_1))) {
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error      */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       goto p_cleanup_20;                   /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
   }
   achl1 = ADSL_OA1->achc_lower;            /* start of output area    */
   memcpy( achl1, ucrs_x224_cjreq_1, sizeof(ucrs_x224_cjreq_1) );
   achl1 += sizeof(ucrs_x224_cjreq_1);
   m_put_be2( achl1, D_ADSL_RCO1->usc_userid_cl2se );
   achl1 += 2;
   switch (D_ADSL_RCL1->imc_prot_5) {       /* depend on channel index */
     case 0:
       iml1 = D_EXTRA_CHANNEL + D_ADSL_RCO1->usc_userid_cl2se;  /* set number virtual channel */
       D_ADSL_RCO1->dtc_rdpfl_1.ibc_contchno = 1;
       break;
     case 1:
       iml1 = D_ADSL_RCO1->usc_chno_disp;
       break;
     case HL_EXTRA_MCS_CHANNELS: // Extra channels
       if ((ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_enable_mcs_message_channel != FALSE) 
      && (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_mcs_message_channel_active == FALSE)){
          ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_mcs_message_channel_active = TRUE;
          iml1 = D_ADSL_RCO1->usc_chno_mcs_msgchannel;
          break;
       } 
     default:
       iml1 = (D_ADSL_RCO1->adsrc_vc_1 + D_ADSL_RCL1->imc_prot_5 - 2)->usc_vch_no;   /* channel number virtual channel  */
       break;
   }
   m_put_be2( achl1, iml1 );
   achl1 += 2;
   D_ADSL_RCL1->imc_prot_5++;               /* increment channel index */
   D_ADSL_RCL1->iec_frse_bl = ied_frse_cjresp_rec;  /* receive block channel join response */
   goto p_cjr_frse_80;                      /* fields have been set    */

   p_cjr_frse_20:                           /* send client private key */
#define LEN_TS_SECURITY_PACKET 0X005E
#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_IPF_G ((struct dsd_info_packet_fields *) (chrl_work_2 + 1024))
#else
   ADSL_IPF_G = ((struct dsd_info_packet_fields *) (chrl_work_2 + 1024));
#endif
   ADSL_IPF_G->umc_loinf_options = D_ADSL_RCO1->umc_loinf_options;  /* Logon Info Options */
   if (D_ADSL_RCL1->ac_redirect == NULL) {  /* memory for Standard Security Server Redirection PDU */
     ADSL_IPF_G->imc_len_domain = D_ADSL_RCO1->usc_loinf_domna_len;  /* Domain Name Length */
     ADSL_IPF_G->imc_len_username = D_ADSL_RCO1->usc_loinf_userna_len;  /* User Name Length */
     ADSL_IPF_G->imc_len_password = D_ADSL_RCO1->usc_loinf_pwd_len;  /* Password Length */
     ADSL_IPF_G->achc_domain = (char *) D_ADSL_RCO1->awcc_loinf_domna_a;
     ADSL_IPF_G->achc_username = (char *) D_ADSL_RCO1->awcc_loinf_userna_a;
     ADSL_IPF_G->achc_password = (char *) D_ADSL_RCO1->awcc_loinf_pwd_a;
   } else {                                 /* memory for Standard Security Server Redirection PDU */
     bol1 = m_decode_credentials( ADSL_IPF_G, D_ADSL_RCL1->ac_redirect );
     if (bol1 == FALSE) {                   /* returned error          */
       iml_line_no = __LINE__;
       iml_source_no = 25565;    /* source line no for errors */
       goto pfrse92;
     }
   }
   if ((adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_resp.umc_selected_protocol & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX)) != 0) {
      // If the security protocol is not RDP, we should not send the credentials again, as they already have been checked
      //     during the external security protocol (SSL, CredSSP) negotiation phase.
      ADSL_IPF_G->umc_loinf_options &= ~INFO_AUTOLOGON;
      ADSL_IPF_G->imc_len_domain = 0;
      ADSL_IPF_G->imc_len_username = 0;
      ADSL_IPF_G->imc_len_password = 0;
   }
   iml_length = sizeof(ucrs_logon_info_c1)
                  + sizeof(D_ADSL_RCO1->umc_loinf_options)  /* Logon Info Options */
                  + 5 * sizeof(unsigned short int)
                  + ADSL_IPF_G->imc_len_domain  /* Domain Name Length  */
                  + sizeof(unsigned short int)
                  + ADSL_IPF_G->imc_len_username  /* User Name Length  */
                  + sizeof(unsigned short int)
                  + ADSL_IPF_G->imc_len_password  /* Password Length   */
                  + sizeof(unsigned short int)
                  + D_ADSL_RCO1->usc_loinf_altsh_len  /* Alt Shell Length */
                  + sizeof(unsigned short int)
                  + D_ADSL_RCO1->usc_loinf_wodir_len  /* Working Directory Length */
                  + sizeof(unsigned short int)
                  + sizeof(unsigned short int)
                  + D_ADSL_RCO1->usc_loinf_ineta_len  /* INETA Length  */
                  + sizeof(unsigned short int)
                  + sizeof(unsigned short int)
                  + D_ADSL_RCO1->usc_loinf_path_len   /* Client Path Length      */
                  + D_ADSL_RCO1->usc_loinf_extra_len;  /* Extra Parameters Length */
   if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)
         < (LEN_TS_SECURITY_PACKET + iml_length + sizeof(struct dsd_gather_i_1))) {
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error      */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       goto p_cleanup_20;                   /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
   }
   achl1 = ADSL_OA1->achc_lower;               /* start of output area    */
   if(D_ADSL_RCO1->imc_sec_level == 0)
      goto LBL_LOGON_INFO;
#define ACHL_CLIENT_RANDOM_CL (chrl_work_2)
#define ACHL_CLIENT_RANDOM_RE (ACHL_CLIENT_RANDOM_CL + 32)
#define ACHL_CL_RAND_ENCRY (ACHL_CLIENT_RANDOM_RE + 32)
#define ACHL_WORK_SHA1 (ACHL_CL_RAND_ENCRY + 72)
#define ACHL_WORK_MD5 (ACHL_WORK_SHA1 + 40)
#define ACHL_WORK_AREA (ACHL_WORK_MD5 + 48)
   /* 32 bytes of client random as server                              */
   bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                      DEF_AUX_RANDOM_RAW,  /* calcalute random */
                                      ACHL_CLIENT_RANDOM_CL,
                                      D_LEN_CLIENT_RAND );
   if (bol1 == FALSE) {                     /* aux returned error      */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
     goto p_cleanup_20;                     /* do cleanup now          */
   }
   m_gen_keys( adsp_hl_clib_1, ACHL_CLIENT_RANDOM_CL, D_ADSL_RCO1, ACHL_WORK_AREA );
   /* reverse input bytes for RSA encryption                           */
   achl2 = ACHL_CLIENT_RANDOM_RE;
   achl3 = ACHL_CLIENT_RANDOM_CL;
   achl4 = ACHL_CLIENT_RANDOM_CL + D_LEN_CLIENT_RAND;
   do {
     *achl2++ = *(--achl4);
   } while (achl4 > achl3);
   iml3 = D_RSA_KEY_SIZE;                   /* compare size RSA key    */
#ifdef __INSURE__
   // rsa_crypt_raw uses lnum, which causes an Insure-error.
   _Insure_checking_enable(0);
#endif
#ifdef XH_INTERFACE
   {
   ds__hmem dsl_new_struct;
   memset(&dsl_new_struct, 0, sizeof(ds__hmem));
   dsl_new_struct.in__aux_up_version = 1;
   dsl_new_struct.am__aux2 = adsp_hl_clib_1->amc_aux;
   dsl_new_struct.in__flags = 0;
   dsl_new_struct.vp__context = adsp_hl_clib_1->vpc_userfld;

   iml2 = m_rsa_crypt_raw_big( &dsl_new_struct, (unsigned char *) ACHL_CLIENT_RANDOM_RE,
#else // XH_INTERFACE
   iml2 = m_rsa_crypt_raw_big( (unsigned char *) ACHL_CLIENT_RANDOM_RE,
#endif // XH_INTERFACE
                               D_LEN_CLIENT_RAND,
                               (unsigned char *) ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp,
                               sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp),
                               (unsigned char *) ADSL_RDPA_F->dsc_rdp_cl_1.achc_cert_key,
                               ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key,
                               (unsigned char *) ACHL_WORK_AREA,
                               &iml3 );
#ifdef XH_INTERFACE
   HMemMgrFree(&dsl_new_struct);
   }
#endif
#ifdef __INSURE__
   _Insure_checking_enable(1);
#endif
   if (iml2) {
     iml_line_no = __LINE__;
     iml_source_no = 25706;    /* source line no for errors */
     goto pfrse92;
   }
   if (iml3 == 0) {
     iml_line_no = __LINE__;
     iml_source_no = 25709;    /* source line no for errors */
     goto pfrse92;
   }
   /* shorten the keys                                                 */
   bol1 = m_prepare_keys( adsp_hl_clib_1, &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1 );
   if (bol1 == FALSE) {                     /* subroutine reported error */
     iml_line_no = __LINE__;
     iml_source_no = 25714;    /* source line no for errors */
     goto pfrse92;
   }
   RC4_SetKey( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_rc4_state,
               ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_cl_pkd,
               0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_sec_used_keylen);
   RC4_SetKey( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state,
               ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_cl_pkd,
               0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_sec_used_keylen );
   memset( ACHL_WORK_SHA1, 0X36, 40 );
   memset( ACHL_WORK_MD5, 0X5C, 48 );
   SHA1_Init( D_ADSL_RCO1->imrc_sha1_state );
   SHA1_Update( D_ADSL_RCO1->imrc_sha1_state, D_ADSL_RCO1->chrc_sig,
                0, D_ADSL_RCO1->imc_sec_used_keylen );
   SHA1_Update( D_ADSL_RCO1->imrc_sha1_state, ACHL_WORK_SHA1, 0, 40 );
   MD5_Init( D_ADSL_RCO1->imrc_md5_state );
   MD5_Update( D_ADSL_RCO1->imrc_md5_state, D_ADSL_RCO1->chrc_sig,
               0, D_ADSL_RCO1->imc_sec_used_keylen );
   MD5_Update( D_ADSL_RCO1->imrc_md5_state, ACHL_WORK_MD5, 0, 48 );
   /* send the block to the server                                     */
   iml1 = 8 + iml3 + D_RSA_KEY_PADDING;     /* length second part      */
   achl1 += 4 + sizeof(ucrs_x224_p01) + 6 + 2 + iml1;
   if (iml1 <= 127) achl1--;                /* length in one byte      */
   achl2 = achl1;                           /* end of this block       */
   achl2 -= D_RSA_KEY_PADDING;
   memset( achl2, 0, D_RSA_KEY_PADDING );
   /* send reverse encrypted client random from this client to server  */
   achl3 = ACHL_WORK_AREA;
   achl4 = ACHL_WORK_AREA + iml3;
   do {
     *(--achl2) = *achl3++;
   } while (achl3 < achl4);
   iml2 = achl1 - achl2;                    /* length this part        */
   *(--achl2) = 0;
   *(--achl2) = 0;
   achl2 -= 2;
   m_put_le2( achl2, iml2 );                /* output length           */
   *(--achl2) = 0;
   *(--achl2) = 0;
   *(--achl2) = (unsigned char) 0X02;
   *(--achl2) = (unsigned char) 0X01;
   if (iml1 <= 127) {                       /* length in one byte      */
     *(--achl2) = (unsigned char) iml1;
   } else {
     achl2 -= 2;
     m_put_be2( achl2, iml1 );
     *achl2 |= 0X80;                        /* length in two bytes     */
   }
   achl2 -= 13;                             /* here is start of block  */
   *achl2 = DEF_CONST_RDP_03;
   *(achl2 + 1) = 0;                        /* second byte zero        */
   m_put_be2( achl2 + 2, achl1 - achl2 );
   memcpy( achl2 + 4,
           ucrs_x224_p01,
           sizeof(ucrs_x224_p01) );
   *(achl2 + 4 + sizeof(ucrs_x224_p01)) = 0X64;  /* send data request  */
   m_put_be2( achl2 + 8,
              ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
   m_put_be2( achl2 + 10, D_DISPLAY_CHANNEL );
   *(achl2 + 12) = 0X70;                    /* priority / segmentation */
#undef ACHL_CLIENT_RANDOM_CL
#undef ACHL_CLIENT_RANDOM_RE
#undef ACHL_CL_RAND_ENCRY
#undef ACHL_WORK_AREA
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
LBL_LOGON_INFO:
   /* send log on information                                          */
   achl3 = achl1;                           /* save start of output    */
   *achl1 = DEF_CONST_RDP_03;
   *(achl1 + 1) = 0;                        /* second byte zero        */
   memcpy( achl1 + 4,
           ucrs_x224_p01,
           sizeof(ucrs_x224_p01) );
   *(achl1 + 4 + sizeof(ucrs_x224_p01)) = 0X64;  /* send data request  */
   achl1 += 4 + sizeof(ucrs_x224_p01) + 1;
   m_put_be2( achl1, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
   achl1 += 2;
   m_put_be2( achl1, D_ADSL_RCO1->usc_chno_disp);
   achl1 += 2;
   *achl1++ = 0X70;                         /* priority / segmentation */
   iml4 = iml_length;
   if(D_ADSL_RCO1->imc_sec_level != 0 || !D_ADSL_RCO1->boc_licensing_done)
       iml4 += 4;
   if(D_ADSL_RCO1->imc_sec_level != 0) {
      iml4 += D_SIZE_HASH;
   }
   if (iml4 <= 127) {   /* length in one byte */
     *achl1++ = (unsigned char) iml4;
   } else {
     m_put_be2( achl1, iml4 );
     *achl1 |= 0X80;                        /* length in two bytes     */
     achl1 += 2;
   }
   if(D_ADSL_RCO1->imc_sec_level != 0) {
       *achl1++ = (unsigned char) 0X48;  /* rt02 - logon information + data is encrypted */
       *achl1++ = 0;                            /* rt03                    */
       /* two bytes padding zero                                           */
       *achl1++ = 0;
       *achl1++ = 0;
   } else {
       *achl1++ = (unsigned char) 0X40;  /* rt02 - logon information + data is encrypted */
       *achl1++ = 0;                            /* rt03                    */
       /* two bytes padding zero                                           */
       *achl1++ = 0;
       *achl1++ = 0;
   }
   achl2 = achl1;
   if(D_ADSL_RCO1->imc_sec_level != 0) {
       /* leave eight bytes for hash                                       */
       achl2 += D_SIZE_HASH;             /* start output here      */
   }
   memcpy( achl2,
           ucrs_logon_info_c1,
           sizeof(ucrs_logon_info_c1) );
   achl2 += sizeof(ucrs_logon_info_c1);
   m_put_le4( achl2, ADSL_IPF_G->umc_loinf_options );  /* Logon Info Options */
   achl2 += sizeof(ADSL_IPF_G->umc_loinf_options);
   m_put_le2( achl2, ADSL_IPF_G->imc_len_domain );  /* Domain Name Length */
   achl2 += sizeof(unsigned short int);
   m_put_le2( achl2, ADSL_IPF_G->imc_len_username );  /* User Name Length */
   achl2 += sizeof(unsigned short int);
   m_put_le2( achl2, ADSL_IPF_G->imc_len_password );  /* Password Length */
   achl2 += sizeof(unsigned short int);
   m_put_le2( achl2, D_ADSL_RCO1->usc_loinf_altsh_len );  /* Alt Shell Length    */
   achl2 += sizeof(unsigned short int);
   m_put_le2( achl2, D_ADSL_RCO1->usc_loinf_wodir_len );  /* Working Directory Length */
   achl2 += sizeof(unsigned short int);
   if (ADSL_IPF_G->imc_len_domain) {        /* Domain Name Length      */
     memcpy( achl2,
             ADSL_IPF_G->achc_domain,
             ADSL_IPF_G->imc_len_domain );
     achl2 += ADSL_IPF_G->imc_len_domain;
   }
   m_put_le2( achl2, 0 );
   achl2 += sizeof(unsigned short int);
   if (ADSL_IPF_G->imc_len_username) {      /* User Name Length        */
     memcpy( achl2,
             ADSL_IPF_G->achc_username,
             ADSL_IPF_G->imc_len_username );
     achl2 += ADSL_IPF_G->imc_len_username;
   }
   m_put_le2( achl2, 0 );
   achl2 += sizeof(unsigned short int);
   if (ADSL_IPF_G->imc_len_password) {      /* Password Length         */
     memcpy( achl2,
             ADSL_IPF_G->achc_password,
             ADSL_IPF_G->imc_len_password );
     achl2 += ADSL_IPF_G->imc_len_password;
   }
   m_put_le2( achl2, 0 );
   achl2 += sizeof(unsigned short int);
   if (D_ADSL_RCO1->usc_loinf_altsh_len) {  /* Alt Shell Length        */
     memcpy( achl2,
             D_ADSL_RCO1->awcc_loinf_altsh_a,
             D_ADSL_RCO1->usc_loinf_altsh_len );
     achl2 += D_ADSL_RCO1->usc_loinf_altsh_len;
   }
   m_put_le2( achl2, 0 );
   achl2 += sizeof(unsigned short int);
   if (D_ADSL_RCO1->usc_loinf_wodir_len) {  /* Working Directory Length */
     memcpy( achl2,
             D_ADSL_RCO1->awcc_loinf_wodir_a,
             D_ADSL_RCO1->usc_loinf_wodir_len );
     achl2 += D_ADSL_RCO1->usc_loinf_wodir_len;
   }
   m_put_le2( achl2, 0 );
   achl2 += sizeof(unsigned short int);
   m_put_le2( achl2, D_ADSL_RCO1->usc_loinf_no_a_par );  /* number of additional parameters */
   achl2 += sizeof(unsigned short int);
   m_put_le2( achl2, D_ADSL_RCO1->usc_loinf_ineta_len );  /* INETA Length */
   achl2 += sizeof(unsigned short int);
   memcpy( achl2,
           D_ADSL_RCO1->awcc_loinf_ineta_a,
           D_ADSL_RCO1->usc_loinf_ineta_len - 2 );
   achl2 += D_ADSL_RCO1->usc_loinf_ineta_len;
   m_put_le2( achl2 - 2, 0 );
   m_put_le2( achl2, D_ADSL_RCO1->usc_loinf_path_len );  /* Client Path Length      */
   achl2 += sizeof(unsigned short int);
   memcpy( achl2,
           D_ADSL_RCO1->awcc_loinf_path_a,
           D_ADSL_RCO1->usc_loinf_path_len-2 );
   achl2 += D_ADSL_RCO1->usc_loinf_path_len;
   m_put_le2( achl2 - 2, 0 );
   memcpy( achl2,
           D_ADSL_RCO1->awcc_loinf_extra_a,
           D_ADSL_RCO1->usc_loinf_extra_len );
// achl1 += D_ADSL_RCO1->usc_loinf_extra_len;
#undef ADSL_IPF_G
    if(D_ADSL_RCO1->imc_sec_level == 0){
        goto LBL_NO_ENCRYPT_1;
    }
#ifdef TRACEHL1_LOGON_INFO
   m_sdh_printf( adsp_hl_clib_1, "p_cjr_frse_20 l%05d s%05d logon info length %d.",
                 __LINE__, 26086,
                 iml_length );
   m_sdh_console_out( adsp_hl_clib_1, achl1 + D_SIZE_HASH, iml_length );
#endif // TRACEHL1_LOGON_INFO
   if ((ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent & (4096 - 1)) == 0){
     if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent) {
       m_update_keys( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se, NULL );
     }
   }
   /* generate random                                                  */
#define ACHL_WORK_SHA1 ((int *) chrl_work_2)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
   memcpy( ACHL_WORK_SHA1,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
   memcpy( ACHL_WORK_MD5,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
   m_put_le4( ACHL_WORK_UTIL_01, iml_length );
   SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
   SHA1_Update( ACHL_WORK_SHA1,
                achl1 + D_SIZE_HASH, 0, iml_length );
   RC4( achl1 + D_SIZE_HASH, 0, iml_length, achl1 + D_SIZE_HASH, 0,
        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
   SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
   MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
   MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
   memcpy( achl1, ACHL_WORK_UTIL_01, D_SIZE_HASH );
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
   achl1 += D_SIZE_HASH;
LBL_NO_ENCRYPT_1:
   achl1 += iml_length;
   m_put_be2( achl3 + 2, achl1 - achl3 );
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
   D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_1_rec;  /* receive block licence protocol */

   p_cjr_frse_80:                           /* fields have been set    */
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
   ADSL_GAI1_OUT_G->achc_ginp_end = achl1;
   ADSL_OA1->achc_lower = achl1;            /* this area occupied      */
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
   D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* first record type */
   goto pfrse20;                            /* process next data       */

   pfrse80:                                 /* send to client          */
// to-do 13.03.12 KB
   goto p_rcsub1_tose_00;                   /* process commands to server */

   pfrse92:                                 /* protocol error          */
   m_sdh_printf( adsp_hl_clib_1, "pfrse92 - protocoll error received from server iec_frse_bl=%d iec_fsfp_bl=%d l%05d s%05d inp_cur=%p pos=%d/0X%08X",
                 ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl,
                 ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl,
                 iml_line_no,               /* line number for errors  */
                 iml_source_no,             /* source line no for errors */
                 adsl_gai1_inp_1->achc_ginp_cur,
                 iml_rec, iml_rec );
#ifdef TRACEHL1
   if (adsl_gai1_inp_1) {
     m_sdh_printf( adsp_hl_clib_1, "pfrse92 l%05d achl_inp_start=%p achc_ginp_cur=%p achc_ginp_end=%p pos=%04X.",
                   __LINE__,
                   achl_inp_start,
                   adsl_gai1_inp_1->achc_ginp_cur,
                   adsl_gai1_inp_1->achc_ginp_end,
                   adsl_gai1_inp_1->achc_ginp_cur - achl_inp_start );
     iml1 = adsl_gai1_inp_1->achc_ginp_end - achl_inp_start;
     if ((iml1 > 0) && (iml1 <= 0X4000)) {
       m_sdh_console_out( adsp_hl_clib_1, achl_inp_start, iml1 );
     }
   }
#endif
#ifdef D_FFLUSH                             /* 30.05.05 KB - flush stdout */
   fflush( stdout );
#endif                                      /* 30.05.05 KB - flush stdout */
#ifdef D_FOR_TRACE1                         /* 31.05.05 KB - help in tracing */
   iml1++;
   iml1--;
#endif                                      /* 31.05.05 KB - help in tracing */
#ifdef TRACE_LOOP_1
   while (ADSL_RDPA_F) {
     Sleep( 2000 );
   }
#endif
   adsl_gai1_inp_1->achc_ginp_cur
     = adsl_gai1_inp_1->achc_ginp_end;
   goto p_cleanup_00;                       /* do cleanup now          */

   pfrse96:                                 /* program illogic         */
   achl1 = NULL;
   if (adsl_gai1_inp_1) {
     achl1 = adsl_gai1_inp_1->achc_ginp_cur;
   }
   m_sdh_printf( adsp_hl_clib_1, "pfrse96 - program illogic received from server iec_frse_bl=%d iec_fsfp_bl=%d l%05d s%05d inp_cur=%p pos=%d/0X%08X",
                 ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl,
                 ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl,
                 iml_line_no,               /* line number for errors  */
                 iml_source_no,             /* source line no for errors */
                 achl1,
                 iml_rec, iml_rec );
#ifdef D_FFLUSH                             /* 30.05.05 KB - flush stdout */
   fflush( stdout );
#endif                                      /* 30.05.05 KB - flush stdout */
#ifdef TRACE_LOOP_1
   while (ADSL_RDPA_F) {
     Sleep( 2000 );
   }
#endif
   if (adsl_gai1_inp_1) {
     adsl_gai1_inp_1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_end;
   }
   goto p_cleanup_00;                       /* do cleanup now          */
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RCL1
#undef D_ADSL_RCO1
#endif

   p_rcsub1_tose_00:                        /* process commands to server */

   p_rcsub1_tose_04:                        /* work-area prepared      */
   bol1 = FALSE;                            /* no command processed    */

   p_rcsub1_tose_20:                        /* process next command to server */
   adsl_cc_co1_w1 = adsp_hl_clib_1->adsc_cc_co1_ch;  /* get first command in chain */
   if (adsl_cc_co1_w1 == NULL) {            /* end of command chain    */
     if (bol1 == FALSE) {                   /* no command processed    */
       goto p_ret_00;                       /* check how to return     */
     }
     goto p_rcsub1_tose_04;                 /* process commands to server */
   }
   switch (adsl_cc_co1_w1->iec_cc_command) {  /* client component command */
     case ied_ccc_start_rdp_client:         /* start the RDP client    */
       adsp_hl_clib_1->boc_input_pdu_allowed = FALSE;
       goto p_rcsub1_start_rdp_client;      /* start the RDP client    */
     case ied_ccc_continue_after_ext:         /* start the RDP client    */
       adsp_hl_clib_1->adsc_cc_co1_ch = adsl_cc_co1_w1->adsc_next;  /* remove command from chain */
       goto pfrse_send_secbl;               /* send second block to server */
     case ied_ccc_events_mouse_keyb:        /* events from mouse or keyboard */
       if (adsp_hl_clib_1->boc_input_pdu_allowed == FALSE){
          break;
       };
//     goto p_rcsub1_events_mouse_keyb;     /* events from mouse or keyboard */
#define ADSL_CC_EMK_G ((struct dsd_cc_events_mouse_keyb *) (adsl_cc_co1_w1 + 1))
       m_send_cl2se_rdp5( adsp_hl_clib_1, &dsl_output_area_1,
                          ADSL_CC_EMK_G->achc_event_buf,  /* buffer with events */
                          ADSL_CC_EMK_G->imc_events_len,  /* length of events */
                          ADSL_CC_EMK_G->imc_no_order );  /* number of events */
#undef ADSL_CC_EMK_G
       adsp_hl_clib_1->adsc_cc_co1_ch = adsl_cc_co1_w1->adsc_next;  /* remove command from chain */
       goto p_rcsub1_tose_04;               /* work-area prepared      */
      case ied_ccc_msc_msgchannel_out:                  /* output to virtual channel */
#define ADSL_RDP_MCS_MSGCHANNEL_IO_G ((struct dsd_rdp_mcs_msgchannel_io *) (adsl_cc_co1_w1 + 1))
         bol1 = m_send_mcs_msgchannel_tose( adsp_hl_clib_1,
                               ADSL_OA1,
                               ADSL_RDP_MCS_MSGCHANNEL_IO_G ,
                               chrl_work_2 );
         if (bol1 == FALSE) goto p_cleanup_00;  /* do cleanup now        */
#undef ADSL_RDP_MCS_MSGCHANNEL_IO_G 
         adsp_hl_clib_1->adsc_cc_co1_ch = adsl_cc_co1_w1->adsc_next;  /* remove command from chain */
         goto p_rcsub1_tose_04;               /* work-area prepared      */
     case ied_ccc_vch_out:                  /* output to virtual channel */
#define ADSL_RDP_VCH_IO_G ((struct dsd_rdp_vch_io *) (adsl_cc_co1_w1 + 1))
       bol1 = m_send_vch_tose( adsp_hl_clib_1,
                               ADSL_OA1,
                               ADSL_RDP_VCH_IO_G,
                               chrl_work_2 );
       if (bol1 == FALSE) goto p_cleanup_00;  /* do cleanup now        */
#undef ADSL_RDP_VCH_IO_G
       adsp_hl_clib_1->adsc_cc_co1_ch = adsl_cc_co1_w1->adsc_next;  /* remove command from chain */
       goto p_rcsub1_tose_04;               /* work-area prepared      */
     case ied_ccc_send_confirm_active_pdu:  /* send Confirm Active PDU */
       adsp_hl_clib_1->boc_input_pdu_allowed = TRUE;
       ADSL_RDPA_F->ac_screen_buffer = ADSL_RDPA_F->dsc_rdp_cl_1.ac_paint_buffer
         = adsp_hl_clib_1->ac_screen_buffer;  /* buffer to paint to    */
       bol1 = m_send_cl2se_conf_act_pdu( adsp_hl_clib_1, &dsl_output_area_1 );
       if (bol1 == FALSE) goto p_cleanup_00;  /* do cleanup now        */
       break;                               /* all done                */
     case ied_ccc_pass_license:             /* Send a Client license info or Client New License Request */
       bol1 = m_send_cl2se_license( adsp_hl_clib_1, &dsl_output_area_1,
                                    (struct dsd_cc_pass_license *) (adsl_cc_co1_w1 + 1),
                                    chrl_work_1, sizeof(chrl_work_1),
                                    chrl_work_2, sizeof(chrl_work_2) );
       if (bol1 == FALSE) goto p_cleanup_00;  /* do cleanup now        */
       break;
     case ied_ccc_reconnect:                /* reconnect the RDP client */
       adsp_hl_clib_1->boc_input_pdu_allowed = FALSE;
       adsp_hl_clib_1->adsc_cc_co1_ch = adsl_cc_co1_w1->adsc_next;  /* remove command from chain */
       goto p_rcsub1_reconnect_00;          /* do reconnect - new session */
   }

   p_rcsub1_tose_40:                        /* command to server processed */
   adsp_hl_clib_1->adsc_cc_co1_ch = adsl_cc_co1_w1->adsc_next;  /* remove from chain */
   bol1 = TRUE;                             /* command processed       */
   goto p_rcsub1_tose_20;                   /* process next command to server */


   p_rcsub1_reconnect_00:                   /* do reconnect - new session */
   ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl = ied_frse_start;  /* receive block from client */
#define D_ADSL_CL_RCO1 (&ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1)
   D_ADSL_CL_RCO1->boc_licensing_done = FALSE;
   /* reset block counters for encryption                              */
   D_ADSL_CL_RCO1->dsc_encry_se2cl.imc_count_sent = 0;
   D_ADSL_CL_RCO1->dsc_encry_cl2se.imc_count_sent = 0;
   if ((D_ADSL_CL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) == 0) {  /* compression not enabled */
     goto p_rcsub1_start_rdp_cl_02;         /* continue start the RDP client */
   }
   D_ADSL_CL_RCO1->dsc_cdrf_dec.imc_func = DEF_IFUNC_END;
   D_ADSL_CL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_CL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
   D_ADSL_CL_RCO1->amc_cdr_dec( &D_ADSL_CL_RCO1->dsc_cdrf_dec );
   if (D_ADSL_CL_RCO1->dsc_cdrf_dec.imc_return != DEF_IRET_END) {  /* connection should be ended */
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d end de-compression error %d.",
                   __LINE__, 33992,  /* line number for errors */
                   D_ADSL_CL_RCO1->dsc_cdrf_dec.imc_return );
     goto p_cleanup_00;                     /* do cleanup now          */
   }
   D_ADSL_CL_RCO1->dsc_cdrf_dec.imc_func = DEF_IFUNC_START;  /* start of processing, initialize */
   D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_func = DEF_IFUNC_END;
   D_ADSL_CL_RCO1->dsc_cdrf_enc.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_CL_RCO1->dsc_cdrf_enc.amc_aux = adsp_hl_clib_1->amc_aux;
   D_ADSL_CL_RCO1->amc_cdr_enc( &D_ADSL_CL_RCO1->dsc_cdrf_enc );
   if (D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_return != DEF_IRET_END) {  /* connection should be ended */
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d end compression error %d.",
                   __LINE__, 34003,  /* line number for errors */
                   D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_return );
     goto p_cleanup_00;                     /* do cleanup now          */
   }
   D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_func = DEF_IFUNC_START;  /* start of processing, initialize */
   goto p_rcsub1_start_rdp_cl_02;           /* continue start the RDP client */
#undef D_ADSL_CL_RCO1

   p_rcsub1_start_rdp_client:               /* start the RDP client    */
#define ADSL_CC_SRC_G ((struct dsd_cc_start_rdp_client *) (adsl_cc_co1_w1 + 1))
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_dim_x = ADSL_CC_SRC_G->imc_dim_x;  /* dimension x pixels */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_dim_y = ADSL_CC_SRC_G->imc_dim_y;  /* dimension y pixels */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_s_coldep = ADSL_CC_SRC_G->imc_coldep;  /* colour depth */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_keyboard_layout = ADSL_CC_SRC_G->imc_keyboard_layout;  /* Keyboard Layout */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_keyboard_type = ADSL_CC_SRC_G->imc_keyboard_type;  /* Type of Keyboard / 102 */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_keyboard_subtype = ADSL_CC_SRC_G->imc_keyboard_subtype;  /* Subtype of Keyboard */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_no_func_keys = ADSL_CC_SRC_G->imc_no_func_keys;  /* Number of Function Keys */
   // Common/basic TS_UD_CS_CORE::earlyCapabilityFlags:
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_cl_early_capability_flag 
       = RNS_UD_CS_SUPPORT_ERRINFO_PDU;
   // 2.2.1.3 Client MCS Connect Initial PDU with GCC Conference Create Request:
   //   2.2.1.3.2 Client Core Data: TS_UD_CS_CORE.earlyCapabilityFlags:
   if (ADSL_CC_SRC_G->boc_enable_support_netchar_autodetect != FALSE){
       ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_cl_early_capability_flag  
            |= RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT;
       ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_enable_mcs_message_channel = TRUE;
   }
   if (ADSL_CC_SRC_G->boc_enable_support_heartbeat_pdu != FALSE){
       ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_cl_early_capability_flag  
            |= RNS_UD_CS_SUPPORT_HEARTBEAT_PDU;
       ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_enable_mcs_message_channel = TRUE;
   }
// ADSL_CC_SRC_G->imc_coldep = 16;          /* colour depth            */
// to-do 10.04.12 KB - should RDP-client generate umc_loinf_options from other values - like compression ???
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.umc_loinf_options  /* Logon Info Options */
     = ADSL_CC_SRC_G->umc_loinf_options
         & (INFO_MOUSE | INFO_DISABLECTRLALTDEL | INFO_AUTOLOGON
              | INFO_MAXIMIZESHELL | INFO_LOGONNOTIFY | INFO_ENABLEWINDOWSKEY
              | INFO_REMOTECONSOLEAUDIO | INFO_RAIL | INFO_LOGONERRORS
              | INFO_MOUSE_HAS_WHEEL | INFO_PASSWORD_IS_SC_PIN | INFO_NOAUDIOPLAYBACK
              | INFO_USING_SAVED_CREDS | RNS_INFO_AUDIOCAPTURE | RNS_INFO_VIDEO_DISABLE);
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.umc_loinf_options  /* Logon Info Options */
     |= INFO_UNICODE | INFO_FORCE_ENCRYPTED_CS_PDU;
   if (ADSL_CC_SRC_G->boc_compression) {    /* with compression        */
     ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.umc_loinf_options  /* Logon Info Options */
       |= INFO_COMPRESSION | (PACKET_COMPR_TYPE_RDP6 << 9);
   }
   // Common/basic TS_UD_CS_CORE::earlyCapabilityFlags:
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_cc_early_capability_flags 
       = RNS_UD_CS_SUPPORT_ERRINFO_PDU;
   // Optional TS_UD_CS_CORE::earlyCapabilityFlags:
   if (ADSL_CC_SRC_G->boc_multimonitor_support) {
       ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_cl_early_capability_flag 
           |= RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU;
       ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.boc_multimonitor_support = TRUE;
       // Copy the monitor structures:
       if (ADSL_CC_SRC_G->imc_monitor_count > 0) {
          ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsrc_ts_monitor
             = (struct dsd_ts_monitor_def*) m_aux_stor_alloc(&ADSL_RDPA_F->dsc_stor_sdh_1,
                ADSL_CC_SRC_G->imc_monitor_count * sizeof(struct dsd_ts_monitor_def));
          memcpy(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsrc_ts_monitor,
                ADSL_CC_SRC_G->adsrc_ts_monitor,
                ADSL_CC_SRC_G->imc_monitor_count * sizeof(struct dsd_ts_monitor_def));
          ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_monitor_count
             = ADSL_CC_SRC_G->imc_monitor_count;
            
          if (ADSL_CC_SRC_G->imc_monitor_attributes_count > 0) {
             ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsrc_ts_monitor_attributes
                = (struct dsd_ts_monitor_attributes*) m_aux_stor_alloc(&ADSL_RDPA_F->dsc_stor_sdh_1,
                  ADSL_CC_SRC_G->imc_monitor_attributes_count * sizeof(struct dsd_ts_monitor_attributes));
               memcpy(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsrc_ts_monitor_attributes,
                  ADSL_CC_SRC_G->adsrc_ts_monitor_attributes,
                  ADSL_CC_SRC_G->imc_monitor_attributes_count * sizeof(struct dsd_ts_monitor_attributes));
               ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_monitor_attributes_count
                  = ADSL_CC_SRC_G->imc_monitor_attributes_count;
       }
       }
   }
#ifdef HL_USE_UNICODE_STRINGS
	{
   int iml_ucs_len = 0;
   iml_ucs_len = m_len_vx_ucs(ied_chs_le_utf_16, &ADSL_CC_SRC_G->dsc_ucs_domain);
   if (iml_ucs_len > 0){
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_domna_len = sizeof(HL_WCHAR) * iml_ucs_len;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_domna_a = 
         (HL_WCHAR*)m_aux_stor_alloc(&ADSL_RDPA_F->dsc_stor_sdh_1, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_domna_len + sizeof(HL_WCHAR));
      memset(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_domna_a, 0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_domna_len + sizeof(HL_WCHAR));
      iml_ucs_len = m_cpy_vx_vx(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_domna_a,
                        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_domna_len,
                        ied_chs_le_utf_16, 
                        ADSL_CC_SRC_G->dsc_ucs_domain.ac_str,
                        ADSL_CC_SRC_G->dsc_ucs_domain.imc_len_str,
                        ADSL_CC_SRC_G->dsc_ucs_domain.iec_chs_str);
      if (iml_ucs_len < 0){
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d - Error copying Logon Info data.",
                      __LINE__, 34086);       /* line number for errors */
         goto p_cleanup_00;                            /* do cleanup now          */
      }
   } else {
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_domna_len = 0;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_domna_a = NULL;
   }

   iml_ucs_len = m_len_vx_ucs(ied_chs_le_utf_16, &ADSL_CC_SRC_G->dsc_ucs_username);
   if (iml_ucs_len > 0){
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_userna_len = sizeof(HL_WCHAR) * iml_ucs_len;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_userna_a = 
         (HL_WCHAR*)m_aux_stor_alloc(&ADSL_RDPA_F->dsc_stor_sdh_1, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_userna_len + sizeof(HL_WCHAR));
      memset(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_userna_a, 0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_userna_len + sizeof(HL_WCHAR));
      iml_ucs_len = m_cpy_vx_vx(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_userna_a,
                        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_userna_len,
                        ied_chs_le_utf_16, 
                        ADSL_CC_SRC_G->dsc_ucs_username.ac_str,
                        ADSL_CC_SRC_G->dsc_ucs_username.imc_len_str,
                        ADSL_CC_SRC_G->dsc_ucs_username.iec_chs_str);
      if (iml_ucs_len < 0){
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d - Error copying Logon Info data.",
                      __LINE__, 34089);       /* line number for errors */
         goto p_cleanup_00;                            /* do cleanup now          */
      }
   } else {
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_userna_len = 0;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_userna_a = NULL;
   }

   iml_ucs_len = m_len_vx_ucs(ied_chs_le_utf_16, &ADSL_CC_SRC_G->dsc_ucs_password);
   if (iml_ucs_len > 0){
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_pwd_len = sizeof(HL_WCHAR) * iml_ucs_len;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_pwd_a = 
         (HL_WCHAR*)m_aux_stor_alloc(&ADSL_RDPA_F->dsc_stor_sdh_1, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_pwd_len + sizeof(HL_WCHAR));
      memset(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_pwd_a, 0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_pwd_len + sizeof(HL_WCHAR));
      iml_ucs_len = m_cpy_vx_vx(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_pwd_a,
                        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_pwd_len,
                        ied_chs_le_utf_16, 
                        ADSL_CC_SRC_G->dsc_ucs_password.ac_str,
                        ADSL_CC_SRC_G->dsc_ucs_password.imc_len_str,
                        ADSL_CC_SRC_G->dsc_ucs_password.iec_chs_str);
      if (iml_ucs_len < 0){
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d - Error copying Logon Info data.",
                      __LINE__, 34092);       /* line number for errors */
         goto p_cleanup_00;                            /* do cleanup now          */
      }
   } else {
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_pwd_len = 0;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_pwd_a = NULL;
   }

   iml_ucs_len = m_len_vx_ucs(ied_chs_le_utf_16, &ADSL_CC_SRC_G->dsc_ucs_loinf_altsh);
   if (iml_ucs_len > 0){
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_altsh_len = sizeof(HL_WCHAR) * iml_ucs_len;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_altsh_a = 
         (HL_WCHAR*)m_aux_stor_alloc(&ADSL_RDPA_F->dsc_stor_sdh_1, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_altsh_len + sizeof(HL_WCHAR));
      memset(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_altsh_a, 0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_altsh_len + sizeof(HL_WCHAR));
      iml_ucs_len = m_cpy_vx_vx(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_altsh_a,
                        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_altsh_len,
                        ied_chs_le_utf_16, 
                        ADSL_CC_SRC_G->dsc_ucs_loinf_altsh.ac_str,
                        ADSL_CC_SRC_G->dsc_ucs_loinf_altsh.imc_len_str,
                        ADSL_CC_SRC_G->dsc_ucs_loinf_altsh.iec_chs_str);
      if (iml_ucs_len < 0){
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d - Error copying Logon Info data.",
                      __LINE__, 34095);       /* line number for errors */
         goto p_cleanup_00;                            /* do cleanup now          */
      }
   } else {
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_altsh_len = 0;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_altsh_a = NULL;
   }

   iml_ucs_len = m_len_vx_ucs(ied_chs_le_utf_16, &ADSL_CC_SRC_G->dsc_ucs_loinf_wodir);
   if (iml_ucs_len > 0){
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_wodir_len = sizeof(HL_WCHAR) * iml_ucs_len;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_wodir_a = 
         (HL_WCHAR*)m_aux_stor_alloc(&ADSL_RDPA_F->dsc_stor_sdh_1, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_wodir_len + sizeof(HL_WCHAR));
      memset(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_wodir_a, 0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_wodir_len + sizeof(HL_WCHAR));
      iml_ucs_len = m_cpy_vx_vx(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_wodir_a,
                        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_wodir_len,
                        ied_chs_le_utf_16, 
                        ADSL_CC_SRC_G->dsc_ucs_loinf_wodir.ac_str,
                        ADSL_CC_SRC_G->dsc_ucs_loinf_wodir.imc_len_str,
                        ADSL_CC_SRC_G->dsc_ucs_loinf_wodir.iec_chs_str);
      if (iml_ucs_len < 0){
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d - Error copying Logon Info data.",
                      __LINE__, 34098);       /* line number for errors */
         goto p_cleanup_00;                            /* do cleanup now          */
      }
   } else {
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_wodir_len = 0;
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_wodir_a = NULL;
   }
	}
#else // HL_USE_UNICODE_STRINGS
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_domna_a = ADSL_CC_SRC_G->awcc_loinf_domna_a;  /* Domain Name */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_domna_len = ADSL_CC_SRC_G->usc_loinf_domna_len;  /* Domain Name Length */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_userna_a = ADSL_CC_SRC_G->awcc_loinf_userna_a;  /* User Name */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_userna_len = ADSL_CC_SRC_G->usc_loinf_userna_len;  /* User Name Length */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_pwd_a = ADSL_CC_SRC_G->awcc_loinf_pwd_a;  /* Password */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_pwd_len = ADSL_CC_SRC_G->usc_loinf_pwd_len;  /* Password Length */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_altsh_a = ADSL_CC_SRC_G->awcc_loinf_altsh_a;  /* Alt Shell */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_altsh_len = ADSL_CC_SRC_G->usc_loinf_altsh_len;  /* Alt Shell Length */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_wodir_a = ADSL_CC_SRC_G->awcc_loinf_wodir_a;  /* Working Directory */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_wodir_len = ADSL_CC_SRC_G->usc_loinf_wodir_len;  /* Working Directory Length */
#endif // HL_USE_UNICODE_STRINGS
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_no_a_par = ADSL_CC_SRC_G->usc_loinf_no_a_par;  /* number of additional parameters */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_ineta_a = ADSL_CC_SRC_G->awcc_loinf_ineta_a;  /* INETA */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_ineta_len = ADSL_CC_SRC_G->usc_loinf_ineta_len;  /* INETA Length */
   if(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_ineta_len <= 0)
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_ineta_len = 2;
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_path_a = ADSL_CC_SRC_G->awcc_loinf_path_a;  /* Client Path */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_path_len = ADSL_CC_SRC_G->usc_loinf_path_len;  /* Client Path Length */
   if(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_path_len <= 0)
      ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_path_len = 2;
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.awcc_loinf_extra_a = ADSL_CC_SRC_G->awcc_loinf_extra_a;  /* Extra Parameters */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_loinf_extra_len = ADSL_CC_SRC_G->usc_loinf_extra_len;  /* Extra Parameters Length */
   
   m_cpy_vx_ucs( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.wcrc_computer_name,
                 sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.wcrc_computer_name),
                 ied_chs_le_utf_16,         /* Unicode UTF-16 little endian */
                 &ADSL_CC_SRC_G->dsc_ucs_computer_name );
   if (ADSL_CC_SRC_G->imc_no_virt_ch > 0) {  /* number of virtual channels */
     ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsrc_vc_1  /* array of virtual channels */
       = (struct dsd_rdp_vc_1 *) m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1,
                                                     ADSL_CC_SRC_G->imc_no_virt_ch * sizeof(struct dsd_rdp_vc_1) );  /* number of virtual channels */
     memcpy( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsrc_vc_1,  /* array of virtual channels */
             ADSL_CC_SRC_G->adsrc_vc_1,     /* array of virtual channels */
             ADSL_CC_SRC_G->imc_no_virt_ch * sizeof(struct dsd_rdp_vc_1) );  /* number of virtual channels */
     ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_no_virt_ch  /* number of virtual channels */
       = ADSL_CC_SRC_G->imc_no_virt_ch;     /* number of virtual channels */
   }
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.achc_machine_name = ADSL_CC_SRC_G->achc_machine_name;  /* Name of machine */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_rdp_neg_req = ADSL_CC_SRC_G->dsc_rdp_neg_req;
   adsp_hl_clib_1->adsc_cc_co1_ch = adsl_cc_co1_w1->adsc_next;  /* remove command from chain */
#undef ADSL_CC_SRC_G

   p_rcsub1_start_rdp_cl_02:                /* continue start the RDP client */
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) adsp_hl_clib_1->achc_work_area)
   memset( ADSL_GAI1_OUT_G, 0, sizeof(struct dsd_gather_i_1) );
   achl_rdp_neg_req = (char*)(ADSL_GAI1_OUT_G + 1);
   memcpy(achl_rdp_neg_req, ucrs_sese_01, sizeof(ucrs_sese_01));
   ADSL_GAI1_OUT_G->achc_ginp_cur = achl_rdp_neg_req;
   ADSL_GAI1_OUT_G->achc_ginp_end = achl_rdp_neg_req + sizeof(ucrs_sese_01);
   *(achl_rdp_neg_req + 12) = adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_req.usc_flags;
   m_put_le4(achl_rdp_neg_req + 15, adsp_hl_clib_1->adsc_rdp_co->dsc_rdp_neg_req.umc_requested_protocols);
   while (ADSL_RDPA_F->dsc_rdp_cl_1.ac_redirect) {  /* memory for Standard Security Server Redirection PDU */
// to-do 12.12.13 KB - cookie needed at end of first packet
     achl1 = (char *) ADSL_RDPA_F->dsc_rdp_cl_1.ac_redirect;  /* memory for Standard Security Server Redirection PDU */
     iml1 = *((int *) achl1);               /* get length memory       */
     if (iml1 < (sizeof(int) + 8 + sizeof(int))) {
       iml_line_no = __LINE__;
       iml_source_no = 34201;    /* source line no for errors */
       goto pfrse92;
     }
     iml2 = *((unsigned char *) achl1 + sizeof(int) + 8 + 0)
              | (*((unsigned char *) achl1 + sizeof(int) + 8 + 1) << 8)
              | (*((unsigned char *) achl1 + sizeof(int) + 8 + 2) << 16)
              | (*((unsigned char *) achl1 + sizeof(int) + 8 + 3) << 24);
     if ((iml2 & LB_LOAD_BALANCE_INFO) == 0) break;  /* no load-balancing info */
     iml3 = 0;                              /* length INETA + length information */
     if (iml2 & LB_TARGET_NET_ADDRESS) {    /* with target ineta       */
       iml3 = *((unsigned char *) achl1 + sizeof(int) + 12 + 0)
                | (*((unsigned char *) achl1 + sizeof(int) + 12 + 1) << 8)
                | (*((unsigned char *) achl1 + sizeof(int) + 12 + 2) << 16)
                | (*((unsigned char *) achl1 + sizeof(int) + 12 + 3) << 24);
       if (iml3 <= 2) {                     /* length too short        */
         iml_line_no = __LINE__;
         iml_source_no = 34215;    /* source line no for errors */
         goto pfrse92;
       }
       iml3 += sizeof(int);                 /* add length length information */
     }
     if (iml1 < (sizeof(int) + 12 + iml3 + sizeof(int))) {
       iml_line_no = __LINE__;
       iml_source_no = 34220;    /* source line no for errors */
       goto pfrse92;
     }
     iml2 = *((unsigned char *) achl1 + sizeof(int) + 12 + iml3 + 0)
              | (*((unsigned char *) achl1 + sizeof(int) + 12 + iml3 + 1) << 8)
              | (*((unsigned char *) achl1 + sizeof(int) + 12 + iml3 + 2) << 16)
              | (*((unsigned char *) achl1 + sizeof(int) + 12 + iml3 + 3) << 24);
     if (iml2 == 0) {
       iml_line_no = __LINE__;
       iml_source_no = 34227;    /* source line no for errors */
       goto pfrse92;
     }
     if (iml2 > 256) {
       iml_line_no = __LINE__;
       iml_source_no = 34230;    /* source line no for errors */
       goto pfrse92;
     }
     if (iml1 < (sizeof(int) + 12 + iml3 + sizeof(int) + iml2)) {
       iml_line_no = __LINE__;
       iml_source_no = 34233;    /* source line no for errors */
       goto pfrse92;
     }
#define ACHL_OUT_G ((char *) (ADSL_GAI1_OUT_G + 1))
     memcpy( ACHL_OUT_G, ucrs_sese_01, 5 + 6 );
     memcpy( ACHL_OUT_G + 5 + 6,
             achl1 + sizeof(int) + 12 + iml3 + sizeof(int),
             iml2 );
     memcpy( ACHL_OUT_G + 5 + 6 + iml2,
             ucrs_sese_01 + 5 + 6,
             sizeof(ucrs_sese_01) - 5 - 6 );
     *(ACHL_OUT_G + 4) = (unsigned char) (6 + iml2 + (sizeof(ucrs_sese_01) - 5 - 6));
     iml1 = 4 + 1 + 6 + iml2 + (sizeof(ucrs_sese_01) - 5 - 6);
     *(ACHL_OUT_G + 2 + 0) = (unsigned char) (iml1 >> 8);
     *(ACHL_OUT_G + 2 + 1) = (unsigned char) iml1;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ACHL_OUT_G;
     ADSL_GAI1_OUT_G->achc_ginp_end = ACHL_OUT_G + sizeof(ucrs_sese_01) + iml2;
#undef ACHL_OUT_G
     break;
   }
#ifndef NEW_WSP_1102
   adsp_hl_clib_1->adsc_gather_i_1_out = ADSL_GAI1_OUT_G;
#else
   adsp_hl_clib_1->adsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
#endif
#undef ADSL_GAI1_OUT_G
   ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl = ied_fsfp_rec_type;  /* first record type */
   /* check start compression                                          */
#define D_ADSL_CL_RCO1 (&ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1)
   if ((D_ADSL_CL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) == 0) {  /* compression not enabled */
     goto p_ret_00;                         /* check how to return     */
   }
   D_ADSL_CL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_CL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
   D_ADSL_CL_RCO1->amc_cdr_dec = &m_cdr_mppc_5_dec;  /* decoding routine */
   D_ADSL_CL_RCO1->amc_cdr_dec( &D_ADSL_CL_RCO1->dsc_cdrf_dec );
   if (D_ADSL_CL_RCO1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d de-compression error %d.",
                   __LINE__, 34276,  /* line number for errors */
                   D_ADSL_CL_RCO1->dsc_cdrf_dec.imc_return );
     goto p_cleanup_00;                     /* do cleanup now          */
   }
// D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_func = DEF_IFUNC_START;
   D_ADSL_CL_RCO1->dsc_cdrf_enc.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_CL_RCO1->dsc_cdrf_enc.amc_aux = adsp_hl_clib_1->amc_aux;
   D_ADSL_CL_RCO1->amc_cdr_enc = &m_cdr_mppc_4_enc;  /* encryption routine */
   D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_param_1 = 40;  /* RDP4             */
   D_ADSL_CL_RCO1->amc_cdr_enc( &D_ADSL_CL_RCO1->dsc_cdrf_enc );
   if (D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d compression error %d.",
                   __LINE__, 34294,  /* line number for errors */
                   D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_return );
     goto p_cleanup_00;                     /* do cleanup now          */
   }
   goto p_ret_00;                           /* check how to return     */
#undef D_ADSL_CL_RCO1


   p_ret_00:                                /* check how to return     */
   if (adsp_hl_clib_1->boc_eof_server == FALSE) {  /* check End-of-File Server */
     return;
   }

   p_cleanup_00:                            /* do cleanup now          */
   adsp_hl_clib_1->inc_return = DEF_IRET_END;  /* set normal end       */

   p_cleanup_20:                            /* do cleanup now - part two */
   if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
     ADSL_RDPA_F->dsc_rdptr1.imc_func = DEF_IFUNC_CLOSE;  /* set normal end */
     ADSL_RDPA_F->dsc_rdptr1.adsc_hl_clib_1 = adsp_hl_clib_1;
     m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
   }
#define D_ADSL_CL_RCO1 (&ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1)
   if (D_ADSL_CL_RCO1->amc_cdr_dec) {
     D_ADSL_CL_RCO1->dsc_cdrf_dec.imc_func = DEF_IFUNC_END;
     D_ADSL_CL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
     D_ADSL_CL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
     D_ADSL_CL_RCO1->amc_cdr_dec( &D_ADSL_CL_RCO1->dsc_cdrf_dec );
   }
   if (D_ADSL_CL_RCO1->amc_cdr_enc) {
     D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_func = DEF_IFUNC_END;
     D_ADSL_CL_RCO1->dsc_cdrf_enc.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
     D_ADSL_CL_RCO1->dsc_cdrf_enc.amc_aux = adsp_hl_clib_1->amc_aux;
     D_ADSL_CL_RCO1->amc_cdr_enc( &D_ADSL_CL_RCO1->dsc_cdrf_enc );
   }
#undef D_ADSL_CL_RCO1
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   m_aux_stor_end( &ADSL_RDPA_F->dsc_stor_sdh_1 );
   bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                      DEF_AUX_MEMFREE,
                                      &adsp_hl_clib_1->ac_ext,
                                      sizeof(struct dsd_rdpa_f) );
   if (bol1 == FALSE) {                     /* aux returned error      */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
   }
   adsp_hl_clib_1->ac_ext = NULL;           /* no more memory          */
   return;
#ifndef HL_RDPACC_HELP_DEBUG
#undef ADSL_RDPA_F
#undef ADSL_OA1
#endif
} /* end m_hlclib01()                                                  */

/** check if all input bytes have been received                        */
static BOOL m_check_input_complete( struct dsd_gather_i_1 *adsp_gai1_in, char *achp_rp, int imp_len ) {
   int        iml_count;                    /* count remaining bytes   */
   struct dsd_gather_i_1 *adsl_gai1_inp_rp;  /* gather input read pointer */
   char       *achl_rp;                     /* read pointer            */

/**
   imp_len not be zero
*/
   if (adsp_gai1_in == NULL) return FALSE;
   iml_count = imp_len;                     /* count remaining bytes   */
   adsl_gai1_inp_rp = adsp_gai1_in;         /* gather input read pointer */
   achl_rp = achp_rp;                       /* read pointer            */
   while (TRUE) {                           /* loop over gather input  */
     iml_count -= adsl_gai1_inp_rp->achc_ginp_end - achl_rp;  /* bytes in this gather */
     if (iml_count <= 0) return TRUE;       /* all content found       */
     adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_rp == NULL) {        /* was last gather         */
       return FALSE;
     }
     achl_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* start scanning here  */
   }
} /* end m_check_input_complete()                                      */

/** copy input in multiple gather                                      */
static BOOL m_copy_input_gai1( char *achp_dest, struct dsd_gather_i_1 *adsp_gai1_in, char *achp_rp, int imp_len ) {
   int        iml1;                         /* working variable        */
   int        iml_count;                    /* count remaining bytes   */
   struct dsd_gather_i_1 *adsl_gai1_inp_rp;  /* gather input read pointer */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_dest;                   /* destination             */

/**
   imp_len not be zero
*/
   if (adsp_gai1_in == NULL) return FALSE;
   iml_count = imp_len;                     /* count remaining bytes   */
   adsl_gai1_inp_rp = adsp_gai1_in;         /* gather input read pointer */
   achl_rp = achp_rp;                       /* read pointer            */
   achl_dest = achp_dest;                   /* destination             */
   while (TRUE) {                           /* loop over gather input  */
     iml1 = adsl_gai1_inp_rp->achc_ginp_end - achl_rp;  /* bytes in this gather */
     if (iml1 > 0) {                        /* found data in gather    */
       if (iml1 > iml_count) iml1 = iml_count;
       memcpy( achl_dest, achl_rp, iml1);   /* copy chunk              */
       iml_count -= iml1;                   /* bytes in this gather    */
       if (iml_count <= 0) return TRUE;     /* all content found       */
       achl_dest += iml1;                   /* increment destination   */
     }
     adsl_gai1_inp_rp = adsl_gai1_inp_rp->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_rp == NULL) {        /* was last gather         */
       return FALSE;
     }
     achl_rp = adsl_gai1_inp_rp->achc_ginp_cur;  /* start scanning here  */
   }
} /* end m_copy_input_gai1()                                           */


/* generate keys for RDP encryption                                    */
static void m_gen_keys( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
     char *achp_client_random,
     struct dsd_rdp_co_client *adsp_rdp_co,  /* output in RDP communication */
     char *achp_work_area ) {               /* work area               */
   char       *achl1, *achl2, *achl3;       /* working variables       */
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
#endif

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
#define ACHL_SHA_ARRAY ((int *) (achp_work_area + 0))
#define ACHL_SHA_DIG ((char *) ACHL_SHA_ARRAY + 24 * sizeof(int))
#define ACHL_MD5_ARRAY ((int *) (ACHL_SHA_DIG + 20))
#define ACHL_PRE_HASH ((char *) ACHL_MD5_ARRAY + 24 * sizeof(int))
#define ACHL_MASTER_H_1 (ACHL_PRE_HASH + 16 * 3)
#define ACHL_MASTER_H_2 (ACHL_MASTER_H_1 + 16)
#define ACHL_MASTER_H_3 (ACHL_MASTER_H_2 + 16)
   /* make first pre master hash                                       */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_01, 0, sizeof(ucrs_crypt_ini_01) );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 32 );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, achp_client_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_PRE_HASH + 0, 0 );
   /* make second pre master hash                                      */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_02, 0, sizeof(ucrs_crypt_ini_02) );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 32 );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, achp_client_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_PRE_HASH + 16, 0 );
   /* make third pre master hash                                       */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_03, 0, sizeof(ucrs_crypt_ini_03) );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 32 );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, achp_client_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_PRE_HASH + 32, 0 );
   /* make first master hash                                           */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_04, 0, sizeof(ucrs_crypt_ini_04) );
   SHA1_Update( ACHL_SHA_ARRAY, ACHL_PRE_HASH, 0, 48 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 32 );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_PRE_HASH, 0, 48 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_MASTER_H_1, 0 );
   /* make second master hash                                          */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_05, 0, sizeof(ucrs_crypt_ini_05) );
   SHA1_Update( ACHL_SHA_ARRAY, ACHL_PRE_HASH, 0, 48 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 32 );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_PRE_HASH, 0, 48 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_MASTER_H_2, 0 );
   /* make third master hash                                           */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_06, 0, sizeof(ucrs_crypt_ini_06) );
   SHA1_Update( ACHL_SHA_ARRAY, ACHL_PRE_HASH, 0, 48 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 32 );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_PRE_HASH, 0, 48 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_MASTER_H_3, 0 );
   /* signature                                                        */
   memcpy( adsp_rdp_co->chrc_sig, ACHL_MASTER_H_1, sizeof(adsp_rdp_co->chrc_sig) );
   /* client receive pre key data                                      */
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_MASTER_H_2, 0, 16 );
   MD5_Update( ACHL_MD5_ARRAY, achp_client_random, 0, 32 );
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 32 );
   MD5_Final( ACHL_MD5_ARRAY, adsp_rdp_co->dsc_encry_se2cl.chrc_cl_pkd, 0 );
   /* save original key data for future key update calculations        */
   memcpy( adsp_rdp_co->dsc_encry_se2cl.chrc_orig_pkd,
           adsp_rdp_co->dsc_encry_se2cl.chrc_cl_pkd,
           sizeof(adsp_rdp_co->dsc_encry_se2cl.chrc_orig_pkd) );
#ifdef TRACEHL1
   printf( "receive pre key data :" );
   achl1 = adsp_rdp_co->dsc_encry_se2cl.chrc_cl_pkd;
   achl2 = achl1 + 16;
   achl3 = achl1 + 4;
   do {
     if (achl1 == achl3) {
       printf( " " );
       achl3 = achl1 + 4;
     }
     printf( " %02X", (unsigned char) *achl1++ );
   } while (achl1 < achl2);
   printf( "\n" );
#endif
   /* client transmit pre key data                                     */
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_MASTER_H_3, 0, 16 );
   MD5_Update( ACHL_MD5_ARRAY, achp_client_random, 0, 32 );
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrc_server_random, 0, 32 );
   MD5_Final( ACHL_MD5_ARRAY, adsp_rdp_co->dsc_encry_cl2se.chrc_cl_pkd, 0 );
   /* save original key data for future key update calculations        */
   memcpy( adsp_rdp_co->dsc_encry_cl2se.chrc_orig_pkd,
           adsp_rdp_co->dsc_encry_cl2se.chrc_cl_pkd,
           sizeof(adsp_rdp_co->dsc_encry_cl2se.chrc_orig_pkd) );
#ifdef TRACEHL1
   printf( "transmit pre key data:" );
   achl1 = adsp_rdp_co->dsc_encry_cl2se.chrc_cl_pkd;
   achl2 = achl1 + 16;
   achl3 = achl1 + 4;
   do {
     if (achl1 == achl3) {
       printf( " " );
       achl3 = achl1 + 4;
     }
     printf( " %02X", (unsigned char) *achl1++ );
   } while (achl1 < achl2);
   printf( "\n" );
#endif
   return;
#ifndef HL_RDPACC_HELP_DEBUG
#undef ADSL_RDPA_F
#endif
#undef ACHL_SHA_ARRAY
#undef ACHL_SHA_DIG
#undef ACHL_MD5_ARRAY
#undef ACHL_PRE_HASH
#undef ACHL_MASTER_H_1
#undef ACHL_MASTER_H_2
#undef ACHL_MASTER_H_3
} /* end m_gen_keys()                                                  */

/* prepare keys for RDP encryption                                     */
static BOOL m_prepare_keys( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
     struct dsd_rdp_co_client *adsp_rdp_co ) {  /* output in RDP communication */
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
#endif

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
   /* shorten the keys                                                 */
   switch ( adsp_rdp_co->imc_sec_method) {
     case ENCRYPTION_METHOD_40BIT:
       memcpy( adsp_rdp_co->dsc_encry_se2cl.chrc_orig_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
       memcpy( adsp_rdp_co->dsc_encry_cl2se.chrc_orig_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
       memcpy( adsp_rdp_co->dsc_encry_se2cl.chrc_cl_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
       memcpy( adsp_rdp_co->dsc_encry_cl2se.chrc_cl_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
       memcpy( adsp_rdp_co->chrc_sig, ucrs_ks_01, sizeof(ucrs_ks_01) );
       adsp_rdp_co->imc_sec_used_keylen = 8;
       break;
     case ENCRYPTION_METHOD_128BIT:
       adsp_rdp_co->imc_sec_used_keylen = 16;
       break;
     // case 4: // According to what it is stated in "5.3.5.1 Non-FIPS", there is no encryption method for case "4"
     case ENCRYPTION_METHOD_56BIT:
       adsp_rdp_co->dsc_encry_se2cl.chrc_orig_pkd[0] = (char) 0XD1;
       adsp_rdp_co->dsc_encry_cl2se.chrc_orig_pkd[0] = (char) 0XD1;
       adsp_rdp_co->dsc_encry_se2cl.chrc_cl_pkd[0] = (char) 0XD1;
       adsp_rdp_co->dsc_encry_cl2se.chrc_cl_pkd[0] = (char) 0XD1;
       adsp_rdp_co->chrc_sig[0] = (char) 0XD1;
       adsp_rdp_co->imc_sec_used_keylen = 8;
       break;
     default:
       return FALSE;                        /* protocol error          */
   }
   return TRUE;                             /* all valid               */
#ifndef HL_RDPACC_HELP_DEBUG
#undef ADSL_RDPA_F
#endif
} /* end m_prepare_keys()                                              */

static void m_update_keys( struct dsd_rdp_co_client *adsp_rdp_co,
                           struct dsd_rdp_encry *adsp_encry,
                           char *achp_work_area ) {
// char       chrl_work_1[ SHA_ARRAY_SIZE * sizeof(int)
//                         + MD5_ARRAY_SIZE * sizeof(int) ];
   char       chrl_work_1[ 2048 ];

#define ACHL_CONST_SHA1 ((char *) chrl_work_1)
#define ACHL_CONST_MD5 ((char *) chrl_work_1 + 40)
#define ACHL_WORK_SHA1 ((int *) ((char *) chrl_work_1 + 40 + 48))
#define ACHL_WORK_MD5 ((int *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int)))
//#define ACHL_SAVE_SHA1 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
//#define ACHL_SAVE_MD5 ((char *) ACHL_SAVE_SHA1 + MD5_ARRAY_SIZE * sizeof(int) + sizeof(adsp_encry->imrc_sha1_state))
//#define ACHL_WORK_UTIL_01 ((char *) ACHL_SAVE_MD5 + sizeof(adsp_encry->imrc_md5_state))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
#define ACHL_WORK_UTIL_02 ((char *) ACHL_WORK_UTIL_01 + 128)
// memcpy( ACHL_SAVE_SHA1, adsp_encry->imrc_sha1_state, sizeof(adsp_encry->imrc_sha1_state) );  /* save old key */
// memcpy( ACHL_SAVE_MD5, adsp_encry->imrc_md5_state, sizeof(adsp_encry->imrc_md5_state) );  /* save old key */
   memset( ACHL_CONST_SHA1, 0X36, 40 );
   memset( ACHL_CONST_MD5, 0X5C, 48 );
   SHA1_Init( ACHL_WORK_SHA1 );
   SHA1_Update( ACHL_WORK_SHA1, adsp_encry->chrc_orig_pkd,
                0, adsp_rdp_co->imc_sec_used_keylen );
   SHA1_Update( ACHL_WORK_SHA1, ACHL_CONST_SHA1, 0, 40 );
   SHA1_Update( ACHL_WORK_SHA1, adsp_encry->chrc_cl_pkd,
                0, adsp_rdp_co->imc_sec_used_keylen );
   SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
   MD5_Init( ACHL_WORK_MD5 );
   MD5_Update( ACHL_WORK_MD5, adsp_encry->chrc_orig_pkd,
               0, adsp_rdp_co->imc_sec_used_keylen );
   MD5_Update( ACHL_WORK_MD5, ACHL_CONST_MD5, 0, 48 );
   MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
   MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
   switch ( adsp_rdp_co->imc_sec_method) {
     case ENCRYPTION_METHOD_40BIT:
       memcpy( adsp_encry->chrc_cl_pkd, ACHL_WORK_UTIL_01, 8 );
       RC4_SetKey( ACHL_WORK_UTIL_02,
                   adsp_encry->chrc_cl_pkd, 0,
                   8 );
       RC4( adsp_encry->chrc_cl_pkd, 0, 8, adsp_encry->chrc_cl_pkd, 0, ACHL_WORK_UTIL_02 );
       memcpy( adsp_encry->chrc_cl_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
       break;
     case ENCRYPTION_METHOD_128BIT:
       memcpy( adsp_encry->chrc_cl_pkd, ACHL_WORK_UTIL_01, 16 );
       RC4_SetKey( ACHL_WORK_UTIL_02,
                   adsp_encry->chrc_cl_pkd, 0,
                   16 );
       RC4( adsp_encry->chrc_cl_pkd, 0, 16, adsp_encry->chrc_cl_pkd, 0, ACHL_WORK_UTIL_02 );
       break;
     // case 4: // According to what it is stated in "5.3.5.1 Non-FIPS", there is no encryption method for case "4"
     case ENCRYPTION_METHOD_56BIT:
       memcpy( adsp_encry->chrc_cl_pkd, ACHL_WORK_UTIL_01, 8 );
       RC4_SetKey( ACHL_WORK_UTIL_02,
                   adsp_encry->chrc_cl_pkd, 0,
                   8 );
       RC4( adsp_encry->chrc_cl_pkd, 0, 8, adsp_encry->chrc_cl_pkd, 0, ACHL_WORK_UTIL_02 );
       adsp_encry->chrc_cl_pkd[0] = (char) 0XD1;
       break;
   }
   RC4_SetKey( adsp_encry->chrc_rc4_state,
               adsp_encry->chrc_cl_pkd, 0,
               adsp_rdp_co->imc_sec_used_keylen );
   return;
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
#undef ACHL_WORK_UTIL_02
} /* end m_update_keys()                                               */

/* generate keys for licensing encryption, [MS-RDPELE] 5.1.3 .. 5.1.6  */
static void m_gen_lic_keys( struct dsd_rdp_lic_d* adsp_lic_neg,
     char *achp_work_area ) {               /* work area               */
#define ACHL_SHA_ARRAY ((int *) (achp_work_area + 0))
#define ACHL_SHA_DIG ((char *) ACHL_SHA_ARRAY + 24 * sizeof(int))
#define ACHL_MD5_ARRAY ((int *) (ACHL_SHA_DIG + 20))
#define ACHL_PRE_HASH ((char *) ACHL_MD5_ARRAY + 24 * sizeof(int))
#define ACHL_MASTER_H_1 (ACHL_PRE_HASH + 16 * 3)
#define ACHL_MASTER_H_2 (ACHL_MASTER_H_1 + 16)
#define ACHL_WORK_UTIL_01 (ACHL_MASTER_H_2 + 16)
   /* invert the client premaster to little endian                     */
   char       *achl1, *achl2;               /* working variables       */
   achl1 = ACHL_WORK_UTIL_01 + adsp_lic_neg->dsc_lic_pms.usc_bb_len;
   achl2 = adsp_lic_neg->dsc_lic_pms.achc_bb_data;
   do {
     *(--achl1) = *achl2++;
   } while (achl1 > ACHL_WORK_UTIL_01);
#define CLRAND adsp_lic_neg->chrc_lic_clrand
#define SERAND adsp_lic_neg->chrc_lic_serand
   /* make first pre master hash                                       */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_01, 0, sizeof(ucrs_crypt_ini_01) );
   SHA1_Update( ACHL_SHA_ARRAY, ACHL_WORK_UTIL_01, 0, adsp_lic_neg->dsc_lic_pms.usc_bb_len );
   SHA1_Update( ACHL_SHA_ARRAY, CLRAND, 0, sizeof(CLRAND) );
   SHA1_Update( ACHL_SHA_ARRAY, SERAND, 0, sizeof(SERAND) );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_WORK_UTIL_01, 0, adsp_lic_neg->dsc_lic_pms.usc_bb_len );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_PRE_HASH + 0, 0 );
   /* make second pre master hash                                      */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_02, 0, sizeof(ucrs_crypt_ini_02) );
   SHA1_Update( ACHL_SHA_ARRAY, ACHL_WORK_UTIL_01, 0, adsp_lic_neg->dsc_lic_pms.usc_bb_len );
   SHA1_Update( ACHL_SHA_ARRAY, CLRAND, 0, sizeof(CLRAND) );
   SHA1_Update( ACHL_SHA_ARRAY, SERAND, 0, sizeof(SERAND) );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_WORK_UTIL_01, 0, adsp_lic_neg->dsc_lic_pms.usc_bb_len );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_PRE_HASH + 16, 0 );
   /* make third pre master hash                                       */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_03, 0, sizeof(ucrs_crypt_ini_03) );
   SHA1_Update( ACHL_SHA_ARRAY, ACHL_WORK_UTIL_01, 0, adsp_lic_neg->dsc_lic_pms.usc_bb_len );
   SHA1_Update( ACHL_SHA_ARRAY, CLRAND, 0, sizeof(CLRAND) );
   SHA1_Update( ACHL_SHA_ARRAY, SERAND, 0, sizeof(SERAND) );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_WORK_UTIL_01, 0, adsp_lic_neg->dsc_lic_pms.usc_bb_len );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_PRE_HASH + 32, 0 );
   /* make first master hash                                           */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_01, 0, sizeof(ucrs_crypt_ini_01) );
   SHA1_Update( ACHL_SHA_ARRAY, ACHL_PRE_HASH, 0, 48 );
   SHA1_Update( ACHL_SHA_ARRAY, SERAND, 0, sizeof(SERAND) );
   SHA1_Update( ACHL_SHA_ARRAY, CLRAND, 0, sizeof(CLRAND) );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_PRE_HASH, 0, 48 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_MASTER_H_1, 0 );
   /* make second master hash                                          */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_02, 0, sizeof(ucrs_crypt_ini_02) );
   SHA1_Update( ACHL_SHA_ARRAY, ACHL_PRE_HASH, 0, 48 );
   SHA1_Update( ACHL_SHA_ARRAY, SERAND, 0, sizeof(SERAND) );
   SHA1_Update( ACHL_SHA_ARRAY, CLRAND, 0, sizeof(CLRAND) );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_PRE_HASH, 0, 48 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_MASTER_H_2, 0 );
   /* make third master hash, as part of the spec ...
   *M_SALTHASH( ACHL_PRE_HASH, '48', -, 0, 3, SERAND, 'sizeof(SERAND)', CLRAND, 'sizeof(CLRAND)', 'ACHL_MASTER_H_3' );
      which however seems irrelevant; the last 128 bits are not used   */
#define ACHL_RC4_KEY ACHL_WORK_UTIL_01
#define ACHL_CONST_SIX (ACHL_RC4_KEY + 16)
#define ACHL_CONST_BS (ACHL_CONST_SIX + 40)
   /* encryption key                                                   */
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_MASTER_H_2, 0, 16 );
   MD5_Update( ACHL_MD5_ARRAY, CLRAND, 0, sizeof(CLRAND) );
   MD5_Update( ACHL_MD5_ARRAY, SERAND, 0, sizeof(SERAND) );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_RC4_KEY , 0 );
#undef CLRAND
#undef SERAND
   /* initialise server and client RC4 with the same key               */
   RC4_SetKey( adsp_lic_neg->chrc_rc4_state_se2cl,
               ACHL_RC4_KEY,
               0, 16 );
   memcpy( adsp_lic_neg->chrc_rc4_state_cl2se,
           adsp_lic_neg->chrc_rc4_state_se2cl,
           RC4_STATE_SIZE );
   /* prepare state arrays for hash generation                         */
   memset( ACHL_CONST_SIX, 0X36, 40 );
   memset( ACHL_CONST_BS, 0X5C, 48 );
   SHA1_Init( adsp_lic_neg->imrc_sha1_state );
   SHA1_Update( adsp_lic_neg->imrc_sha1_state, ACHL_MASTER_H_1, 0, 16 );
   SHA1_Update( adsp_lic_neg->imrc_sha1_state, ACHL_CONST_SIX, 0, 40 );
   MD5_Init( adsp_lic_neg->imrc_md5_state );
   MD5_Update( adsp_lic_neg->imrc_md5_state, ACHL_MASTER_H_1, 0, 16 );
   MD5_Update( adsp_lic_neg->imrc_md5_state, ACHL_CONST_BS, 0, 48 );
#undef ACHL_RC4_KEY
#undef ACHL_CONST_SIX
#undef ACHL_CONST_BS
#undef ACHL_WORK_UTIL_01
#undef ACHL_SHA_ARRAY
#undef ACHL_SHA_DIG
#undef ACHL_MD5_ARRAY
#undef ACHL_PRE_HASH
#undef ACHL_MASTER_H_1
#undef ACHL_MASTER_H_2
} /* end m_gen_lic_keys()                                              */

/* prepare a screen buffer                                             */
static BOOL m_make_screen( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
     char *achp_param ) {                   /* parameters are here     */
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   int        iml_width, iml_height, iml_coldep, iml_bpp;
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
#endif

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
   iml_width = (unsigned char) *(achp_param + 0)
                  | ((unsigned char) *(achp_param + 1) << 8);
   if (iml_width == 0) return FALSE;
   iml_height  = (unsigned char) *(achp_param + 2)
                  | ((unsigned char) *(achp_param + 3) << 8);
   if (iml_height == 0) return FALSE;
   iml_coldep = (unsigned char) *(achp_param + 4)
                  | ((unsigned char) *(achp_param + 5) << 8);
   switch (iml_coldep) {
     case 8:
       iml_bpp = 1;
       break;
     case 15:
     case 16:
       iml_bpp = 2;
       break;
     case 24:
       iml_bpp = 4;
       break;
     case 32:
       iml_bpp = 4;
       break;
     default:
       return FALSE;
   }
   /* release Bitmap Caches                                            */
/* UUUU 19.08.06 KB - missing */
   /* release all caches                                               */
/* 05.01.05 KB UUUU */
   iml1 = iml_width * iml_height * iml_bpp;
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_dim_x = iml_width;
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_dim_y = iml_height;
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_s_coldep = iml_coldep;
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_bpp = iml_bpp;
   ADSL_RDPA_F->dsc_rdp_cl_1.imc_cmp_dim_x = iml_width;
   ADSL_RDPA_F->dsc_rdp_cl_1.imc_cmp_dim_y = iml_height;
#ifdef TEMPSCR2                            /* 15.06.05 KB - send screen */
   if (iml_bpp == 2)
       {
         unsigned short int *aush1 = (unsigned short int *) ADSL_RDPA_F->ac_screen_buffer;
         unsigned short int *aush2 = (unsigned short int *) ADSL_RDPA_F->ac_screen_buffer
                                       + iml_width * iml_height;
         do {
           *aush1++ = (unsigned short int) 0XF0F0;
         } while (aush1 < aush2);
       }
#endif /* TEMPSCR2                            15.06.05 KB - send screen */
   return TRUE;
#ifndef HL_RDPACC_HELP_DEBUG
#undef ADSL_RDPA_F
#endif
} /* end m_make_screen()                                               */


static int m_decode_ineta( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
                           char *achp_out,
                           char *achp_inp, int imp_len_inp ) {
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_cur;                      /* current character       */
   int        iml_digit;                    /* IPV6 digit found        */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of input            */
   char       *achl_double_dot;             /* IPV6 position double-dot */

   if (imp_len_inp & 1) {                   /* length not even         */
     return -1;                             /* return error            */
   }
   achl_end = achp_inp + imp_len_inp;       /* end of input            */
   if (   (*(achl_end - 1) == 0)
       && (*(achl_end - 2) == 0)) {
     achl_end -= 2;                         /* remove terminating zero */
   }
   achl_rp = achp_inp;                      /* read pointer            */
   iml1 = iml2 = iml3 = 0;                  /* clear indices           */

   p_ipv4_00:                               /* start IPV4              */
   if (achl_rp >= achl_end) goto p_ipv4_40;  /* end IPV4               */
   iml_cur = *((unsigned char *) achl_rp + 0)
               | (*((unsigned char *) achl_rp + 1) << 8);
   achl_rp += 2;                            /* increment read pointer  */
   if ((iml_cur >= '0') && (iml_cur <= '9')) {
     if (iml1 >= 3) {                       /* too many digits         */
       goto p_ipv6_00;                      /* try IPV6                */
     }
     if (   (iml2 == 0)                     /* no value yet            */
         && (iml1 != 0)) {                  /* found leading zero      */
       goto p_ipv6_00;                      /* try IPV6                */
     }
     iml2 *= 10;                            /* multiply old value      */
     iml2 += iml_cur - '0';                 /* add new digit           */
     if (iml2 >= 256) {                     /* value too high          */
       goto p_ipv6_00;                      /* try IPV6                */
     }
     iml1++;                                /* one digit found         */
     goto p_ipv4_00;                        /* start IPV4              */
   }
   if (iml_cur != '.') {                    /* not terminating dot     */
     goto p_ipv6_00;                        /* try IPV6                */
   }

   p_ipv4_40:                               /* end IPV4                */
   if (iml1 == 0) return -1;                /* no digit                */
   if ((iml1 > 1) && (iml2 == 0)) return -1;  /* twice zero            */
   *(achp_out + iml3) = (unsigned char) iml2;  /* output of digit      */
   iml3++;                                  /* next digit              */
   if (achl_rp < achl_end) {                /* not end IPV4            */
     if (iml3 >= 4) return -1;              /* too many digits         */
     iml1 = iml2 = 0;                       /* clear indices           */
     goto p_ipv4_00;                        /* start IPV4              */
   }
   if (iml3 != 4) return -1;                /* not full IPV4 address   */
   return 4;                                /* return success IPV4     */

   p_ipv6_00:                               /* start IPV6              */
   achl_rp = achp_inp;                      /* read pointer            */
   iml1 = iml2 = iml3 = iml4 = 0;           /* clear indices           */
   achl_double_dot = NULL;                  /* IPV6 position double-dot */

   p_ipv6_20:                               /* next digit IPV6         */
   if (achl_rp >= achl_end) goto p_ipv6_40;  /* end IPV6               */
   iml_cur = *((unsigned char *) achl_rp + 0)
               | (*((unsigned char *) achl_rp + 1) << 8);
   achl_rp += 2;                            /* increment read pointer  */
   iml_digit = -1;                          /* IPV6 digit found        */
   if ((iml_cur >= '0') && (iml_cur <= '9')) {
     iml_digit = iml_cur - '0';             /* IPV6 digit found        */
   } else if ((iml_cur >= 'A') && (iml_cur <= 'F')) {
     iml_digit = iml_cur - 'A' + 10;        /* IPV6 digit found        */
   } else if ((iml_cur >= 'a') && (iml_cur <= 'f')) {
     iml_digit = iml_cur - 'a' + 10;        /* IPV6 digit found        */
   }
   if (iml_digit >= 0) {                    /* IPV6 digit found        */
     if (iml1 >= 4) return -1;              /* too many digits         */
     if (   (iml2 == 0)                     /* no value yet            */
         && (iml1 != 0)) {                  /* found leading zero      */
       return -1;                           /* invalid                 */
     }
     if (iml4 != 0) {                       /* count only :            */
       return -1;                           /* invalid                 */
     }
     iml2 <<= 4;                            /* shift old value         */
     iml2 |= iml_digit;                     /* apply new digit         */
     iml1++;                                /* one digit found         */
     goto p_ipv6_20;                        /* next digit IPV6         */
   }
   if (iml_cur != ':') return -1;           /* invalid character       */
   if (iml1 == 0) {                         /* only : - no digit       */
     if (achl_double_dot) {                 /* IPV6 position double-dot */
       return -1;                           /* invalid                 */
     }
     if (iml3 == 0) {                       /* at start of INETA       */
       iml4 = 1;                            /* count only :            */
       goto p_ipv6_20;                      /* next digit IPV6         */
     }
     achl_double_dot = achp_out + iml3;     /* save position of double-dot */
     goto p_ipv6_20;                        /* next digit IPV6         */
   }
   if (iml3 >= 16) {                        /* too many digits         */
     return -1;                             /* invalid                 */
   }
   *(achp_out + iml3 + 0) = (unsigned char) (iml2 >> 8);  /* output of digit */
   *(achp_out + iml3 + 1) = (unsigned char) iml2;  /* output of digit  */
   iml3 += 2;                               /* increment output        */
   iml1 = iml2 = iml4 = 0;                  /* clear indices           */
   goto p_ipv6_20;                          /* next digit IPV6         */

   p_ipv6_40:                               /* end IPV6                */
   if (iml1 != 0) {                         /* with digit              */
     *(achp_out + iml3 + 0) = (unsigned char) (iml2 >> 8);  /* output of digit */
     *(achp_out + iml3 + 1) = (unsigned char) iml2;  /* output of digit  */
     iml3 += 2;                             /* increment output        */
   }
   if (iml4 != 0) {                         /* only one :              */
     return -1;                             /* invalid                 */
   }
   if (   (iml3 == 16)
       && (achl_double_dot == NULL)) {      /* IPV6 position double-dot */
     return 16;
   }
   if (achl_double_dot == NULL) {           /* IPV6 position double-dot */
     return -1;                             /* invalid                 */
   }
   iml1 = 16 - iml3;                        /* number of zeroes missing */
   iml2 = (achp_out + iml3) - achl_double_dot;  /* bytes after ::      */
   if (iml2 > 0) {
     memmove( achp_out + 16 - iml2, achl_double_dot, iml2 );
   }
   memset( achl_double_dot, 0, iml1 );      /* clear bytes             */
   return 16;                               /* all done                */
} /* m_decode_ineta()                                                  */

static BOOL m_decode_credentials( struct dsd_info_packet_fields *adsp_ipf, void * ap_redirect ) {
   int        iml1, iml2, iml3;             /* working variables       */
   char       *achl1;                       /* working variable        */

#define ACHL_REDIRECT ((char *) ap_redirect)
   iml1 = *((int *) ACHL_REDIRECT);         /* get length memory       */
   if (iml1 < (sizeof(int) + 8 + sizeof(int))) {
     return FALSE;                          /* protocol error          */
   }
   iml2 = *((unsigned char *) ACHL_REDIRECT + sizeof(int) + 8 + 0)
            | (*((unsigned char *) ACHL_REDIRECT + sizeof(int) + 8 + 1) << 8)
            | (*((unsigned char *) ACHL_REDIRECT + sizeof(int) + 8 + 2) << 16)
            | (*((unsigned char *) ACHL_REDIRECT + sizeof(int) + 8 + 3) << 24);
   achl1 = ACHL_REDIRECT + sizeof(int) + 12;
   if (iml2 & LB_TARGET_NET_ADDRESS) {      /* with target ineta       */
     if (iml1 < ((achl1 + sizeof(int)) - (ACHL_REDIRECT + sizeof(int)))) {
       return FALSE;                        /* protocol error          */
     }
     iml3 = *((unsigned char *) achl1 + 0)
              | (*((unsigned char *) achl1 + 1) << 8)
              | (*((unsigned char *) achl1 + 2) << 16)
              | (*((unsigned char *) achl1 + 3) << 24);
     if (iml3 <= 2) {                       /* length too short        */
       return FALSE;                        /* protocol error          */
     }
     achl1 += sizeof(int) + iml3;           /* add length length information */
   }
   if (iml2 & LB_LOAD_BALANCE_INFO) {       /* with load-balancing info */
     if (iml1 < ((achl1 + sizeof(int)) - (ACHL_REDIRECT + sizeof(int)))) {
       return FALSE;                        /* protocol error          */
     }
     iml3 = *((unsigned char *) achl1 + 0)
              | (*((unsigned char *) achl1 + 1) << 8)
              | (*((unsigned char *) achl1 + 2) << 16)
              | (*((unsigned char *) achl1 + 3) << 24);
     if (iml3 <= 2) {                       /* length too short        */
       return FALSE;                        /* protocol error          */
     }
     achl1 += sizeof(int) + iml3;           /* add length length information */
   }
   /* get length username including terminating zero                   */
   if (iml1 < ((achl1 + sizeof(int)) - (ACHL_REDIRECT + sizeof(int)))) {
     return FALSE;                          /* protocol error          */
   }
   iml3 = *((unsigned char *) achl1 + 0)
            | (*((unsigned char *) achl1 + 1) << 8)
            | (*((unsigned char *) achl1 + 2) << 16)
            | (*((unsigned char *) achl1 + 3) << 24);
   if (iml3 <= 2) {                         /* length too short        */
     return FALSE;                          /* protocol error          */
   }
   if (iml1 < ((achl1 + sizeof(int) + iml3) - (ACHL_REDIRECT + sizeof(int)))) {
     return FALSE;                          /* protocol error          */
   }
   adsp_ipf->imc_len_username = iml3 - 2;   /* User Name Length        */
   adsp_ipf->achc_username = achl1 + sizeof(int);
   if (*(adsp_ipf->achc_username + adsp_ipf->imc_len_username + 0) != 0) {
     return FALSE;                          /* not zero-terminated     */
   }
   if (*(adsp_ipf->achc_username + adsp_ipf->imc_len_username + 1) != 0) {
     return FALSE;                          /* not zero-terminated     */
   }
   achl1 += sizeof(int) + iml3;             /* add length username     */
   if (iml1 < ((achl1 + sizeof(int)) - (ACHL_REDIRECT + sizeof(int)))) {
     return FALSE;                          /* protocol error          */
   }
   iml2 = *((unsigned char *) achl1 + 0)
            | (*((unsigned char *) achl1 + 1) << 8)
            | (*((unsigned char *) achl1 + 2) << 16)
            | (*((unsigned char *) achl1 + 3) << 24);
   if (iml2 <= 2) {                         /* length too short        */
     return FALSE;                          /* protocol error          */
   }
   if (iml1 < ((achl1 + sizeof(int) + iml2) - (ACHL_REDIRECT + sizeof(int)))) {
     return FALSE;                          /* protocol error          */
   }
   adsp_ipf->imc_len_domain = iml2 - 2;     /* Domain Name Length      */
   adsp_ipf->achc_domain = achl1 + sizeof(int);
   if (*(adsp_ipf->achc_domain + adsp_ipf->imc_len_domain + 0) != 0) {
     return FALSE;                          /* not zero-terminated     */
   }
   if (*(adsp_ipf->achc_domain + adsp_ipf->imc_len_domain + 1) != 0) {
     return FALSE;                          /* not zero-terminated     */
   }
   achl1 += sizeof(int) + iml2;             /* after domain            */
   if (iml1 < ((achl1 + sizeof(int)) - (ACHL_REDIRECT + sizeof(int)))) {
     return FALSE;                          /* protocol error          */
   }
   iml2 = *((unsigned char *) achl1 + 0)
            | (*((unsigned char *) achl1 + 1) << 8)
            | (*((unsigned char *) achl1 + 2) << 16)
            | (*((unsigned char *) achl1 + 3) << 24);
   if (iml2 <= 2) {                         /* length too short        */
     return FALSE;                          /* protocol error          */
   }
   if (iml1 < ((achl1 + sizeof(int) + iml2) - (ACHL_REDIRECT + sizeof(int)))) {
     return FALSE;                          /* protocol error          */
   }
   adsp_ipf->imc_len_password = iml2 - 2;   /* Password Length         */
   adsp_ipf->achc_password = achl1 + sizeof(int);
   if (*(adsp_ipf->achc_password + adsp_ipf->imc_len_password + 0) != 0) {
     return FALSE;                          /* not zero-terminated     */
   }
   if (*(adsp_ipf->achc_password + adsp_ipf->imc_len_password + 1) != 0) {
     return FALSE;                          /* not zero-terminated     */
   }
   adsp_ipf->umc_loinf_options |= INFO_AUTOLOGON;  /* Logon Info Options */
   return TRUE;
} /* end m_decode_credentials()                                        */


static BOOL m_decomp_01_s( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
     struct dsd_cache_1 *adsp_cache_1,
     char *achp_inp_buf, int imp_inp_len ) {
   int        iml1, iml2, iml3;             /* working variables       */
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_fill9;                    /* last command was Fill 9 */
#ifdef OLD01
   int        iml_width;                    /* width of cache in pixels */
#endif
   unsigned short int xxl_mix;              /* Mix Value               */
   unsigned short int xxl_col_1;            /* Value Colour 1          */
   unsigned short int xxl_col_2;            /* Value Colour 2          */
   char       *achl_cobu_next;              /* address next command    */
   char       *achl_cobu_cur;               /* current buffer address  */
   char       *achl_cobu_end;               /* end of buffer           */
   unsigned short int *axxl_pibu_next;      /* pixel buffer next command */
   unsigned short int *axxl_pibu_cur;       /* current pixel buffer    */
   unsigned short int *axxl_pibu_end;       /* end pixel buffer        */
#ifdef OLD01
   unsigned short int *axxl_pibu_line;      /* current line pixel buffer */
#endif
   unsigned short int *axxl_pibu_temp1;     /* temporary pointer pixel buffer */
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_rdp_client_1 *D_ADSL_RCL1;
   struct dsd_rdp_co_client *D_ADSL_RCO1;  /* RDP communication client */
   struct dsd_output_area_1 *ADSL_OA1;
#endif

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
#ifndef HL_RDPACC_HELP_DEBUG
#define D_ADSL_RCL1 (&ADSL_RDPA_F->dsc_rdp_cl_1)
#define D_ADSL_RCO1 (&D_ADSL_RCL1->dsc_rdp_co_1)
#else
   D_ADSL_RCL1 = &ADSL_RDPA_F->dsc_rdp_cl_1;
   D_ADSL_RCO1 = &D_ADSL_RCL1->dsc_rdp_co_1;
#endif
   achl_cobu_next = achp_inp_buf;           /* address next command    */
   achl_cobu_end = achp_inp_buf + imp_inp_len;  /* end of buffer       */
#ifdef OLD01
   axxl_pibu_next = (unsigned short int *) (adsp_cache_1 + 1);
   axxl_pibu_line = (unsigned short int *) (adsp_cache_1 + 1);
   switch (adsp_cache_1->inc_id) {
     case 0:
       iml_width = 0X10;
       break;
     case 1:
       iml_width = 0X20;
       break;
     case 2:
       iml_width = 0X40;
       break;
     default:
       return FALSE;
   }
   if (D_ADSL_RCL1->ucc_prot_r5_pdu_ord_width == 0) return FALSE;
   if (D_ADSL_RCL1->ucc_prot_r5_pdu_ord_width > iml_width) return FALSE;
   if (D_ADSL_RCL1->ucc_prot_r5_pdu_ord_height == 0) return FALSE;
   if (D_ADSL_RCL1->ucc_prot_r5_pdu_ord_height > iml_width) return FALSE;
#endif
   iml1 = D_ADSL_RCL1->ucc_prot_r5_pdu_ord_width
            * D_ADSL_RCL1->ucc_prot_r5_pdu_ord_height;
   D_ADSL_RCL1->achc_prot_1 = (char *) m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1,
                                                         iml1 * sizeof(unsigned short int) );
#define AXXL_PIBU_START ((unsigned short int *) D_ADSL_RCL1->achc_prot_1)
#define UCL_WIDTH (D_ADSL_RCL1->ucc_prot_r5_pdu_ord_width)
   axxl_pibu_next = AXXL_PIBU_START;
   axxl_pibu_end = axxl_pibu_next + iml1;
   bol_fill9 = FALSE;                       /* this command is not Fill 9 */
   xxl_mix = 0XFFFF;                        /* Mix Value               */

   pdeco20:                                 /* decode command          */
   /* pay attention that command is not behind last byte in buffer     */
   achl_cobu_cur = achl_cobu_next;          /* address next command    */
   achl_cobu_next++;                        /* after this input        */
   axxl_pibu_cur = axxl_pibu_next;          /* address next pixel buffer */
   /* shift only 4 bits, so shift 3 bits occurs double                 */
   switch (((unsigned char) *achl_cobu_cur) >> 4) {
     case (0 * 2):                          /* Fill 9                  */
     case (0 * 2 + 1):                      /* Fill 9                  */
       iml1 = *achl_cobu_cur & 0X1F;        /* get length in 5 bits    */
       if (iml1 == 0) {                     /* length follows next byte */
         achl_cobu_next++;                  /* add length of length byte */
         if (achl_cobu_next > achl_cobu_end) return FALSE;
         iml1 = 32 + (unsigned char) *(achl_cobu_cur + 1);
       }
       axxl_pibu_next += iml1;
       if (axxl_pibu_next > axxl_pibu_end) return FALSE;
       if (bol_fill9) {                     /* last command was Fill 9 */
         /* one single pixel mix                                       */
         iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
         if (iml2 > 0) {                    /* part is in first line   */
           *axxl_pibu_next++ = xxl_mix;     /* one pixel mix           */
         } else {
           *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH) ^ xxl_mix;
         }
         iml1--;                            /* one pixel done          */
         if (iml1 == 0) break;              /* all done                */
         axxl_pibu_cur++;                   /* continue from this position */
       }
       bol_fill9 = TRUE;                    /* last command was Fill 9 */
       iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
       if (iml2 > 0) {                      /* part is in first line   */
         if (iml2 > iml1) iml2 = iml1;      /* only as long as length  */
         iml1 -= iml2;                      /* this part has been done */
         memset( axxl_pibu_cur, 0, iml2 * sizeof(unsigned short int) );
         if (iml1 == 0) break;              /* all done                */
         axxl_pibu_cur += iml2;             /* continue from this position */
       }
#ifdef OLD01
       memmove( axxl_pibu_cur,
                axxl_pibu_cur - UCL_WIDTH,
                iml1 * sizeof(unsigned short int) );
#endif
       do {
         *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH);
         axxl_pibu_cur++;
       } while (axxl_pibu_cur < axxl_pibu_next);
       break;
     case (1 * 2):                          /* Mix                     */
     case (1 * 2 + 1):                      /* Mix                     */
#ifdef OLD01
       iml1 = *achl_cobu_next & 0X1F;       /* get length in 5 bits    */
       if (iml1 == 0) {                     /* length follows next byte */
         achl_cobu_next++;                  /* add length command      */
         if (achl_cobu_next > achl_cobu_end) return FALSE;
         iml1 = 32 + (unsigned char) *achl_cobu_next;
       }
       achl_cobu_next++;                    /* add length command      */
       if (achl_cobu_next > achl_cobu_end) return FALSE;
       iml1 = *achl_cobu_cur & 0X1F;
       axxl_pibu_next += iml1;
       if (axxl_pibu_next > axxl_pibu_end) return FALSE;
       memset( axxl_pibu_cur, 0, iml1 * sizeof(unsigned short int) );
       axxl_pibu_cur += iml1;
       break;
#endif
       iml1 = *achl_cobu_cur & 0X1F;        /* get length in 5 bits    */
       if (iml1 == 0) {                     /* length follows next byte */
         achl_cobu_next++;                  /* add length of length byte */
         if (achl_cobu_next > achl_cobu_end) return FALSE;
         iml1 = 32 + (unsigned char) *(achl_cobu_cur + 1);
       }
       axxl_pibu_next += iml1;
       if (axxl_pibu_next > axxl_pibu_end) return FALSE;
       bol_fill9 = FALSE;                   /* this command is not Fill 9 */
       iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
       if (iml2 > 0) {                      /* part is in first line   */
         if (iml2 > iml1) iml2 = iml1;      /* only as long as length  */
         iml1 -= iml2;                      /* this part has been done */
         axxl_pibu_temp1 = axxl_pibu_cur + iml2;  /* compute end loop  */
         do {                               /* fill with mix           */
           *axxl_pibu_cur++ = xxl_mix;
         } while (axxl_pibu_cur < axxl_pibu_temp1);
         if (iml1 == 0) break;              /* all done                */
       }
       do {                                 /* loop to XOR remaining part */
         *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH) ^ xxl_mix;
         axxl_pibu_cur++;                   /* increment position pixel */
       } while (axxl_pibu_cur < axxl_pibu_next);
       break;
     case (2 * 2):                          /* FillOrMix               */
     case (2 * 2 + 1):                      /* FillOrMix               */
       iml1 = (*achl_cobu_cur & 0X1F) << 3;  /* get length in 5 bits, shifted */
       if (iml1 == 0) {                     /* length follows next byte */
         achl_cobu_next++;                  /* add length command      */
         if (achl_cobu_next > achl_cobu_end) return FALSE;
         iml1 = 1 + (unsigned char) *(achl_cobu_cur + 1);
       }
       iml3 = (iml1 + 7) >> 3;              /* number of bytes Mask    */
       achl_cobu_cur = achl_cobu_next;      /* save start mask minus one */
       achl_cobu_next += iml3;              /* add length mask         */
       if (achl_cobu_next > achl_cobu_end) return FALSE;
       bol_fill9 = FALSE;                   /* this command is not Fill 9 */
       iml3 = 1;                            /* mask byte filled        */
       iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
       if (iml2 > 0) {                      /* part is in first line   */
         if (iml2 > iml1) iml2 = iml1;      /* only as long as length  */
         iml1 -= iml2;                      /* this part has been done */
         axxl_pibu_temp1 = axxl_pibu_next + iml2;  /* compute end loop */
         do {                               /* fill with mix           */
           if (iml3 == 256) {               /* mask byte exhausted     */
             achl_cobu_cur++;               /* get next byte mask      */
             iml3 = 1;                      /* start with LSB          */
           }
           *axxl_pibu_next = 0;
           if (*((unsigned char *) achl_cobu_cur) & iml3) {  /* mask-bit set */
             *axxl_pibu_next = xxl_mix;
           }
           axxl_pibu_next++;
           iml3 <<= 1;                      /* take next bit in mask   */
         } while (axxl_pibu_next < axxl_pibu_temp1);
         if (iml1 == 0) break;              /* all done                */
         axxl_pibu_cur = axxl_pibu_next;    /* continue from this position */
       }
       axxl_pibu_next += iml1;
       if (axxl_pibu_next > axxl_pibu_end) return FALSE;
       do {                                 /* loop to XOR remaining part */
         if (iml3 == 256) {                 /* mask byte exhausted     */
           achl_cobu_cur++;                 /* get next byte mask      */
           iml3 = 1;                        /* start with LSB          */
         }
         *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH);
         if (*((unsigned char *) achl_cobu_cur) & iml3) {  /* mask-bit set */
           *axxl_pibu_cur ^= xxl_mix;
         }
         axxl_pibu_cur++;                   /* increment position pixel */
         iml3 <<= 1;                        /* take next bit in mask   */
       } while (axxl_pibu_cur < axxl_pibu_next);
       break;                               /* all done                */
     case (3 * 2):                          /* Color                   */
     case (3 * 2 + 1):                      /* Color                   */
       iml1 = *achl_cobu_cur & 0X1F;        /* get length in 5 bits    */
       if (iml1 == 0) {                     /* length follows next byte */
         achl_cobu_next++;                  /* add length of length byte */
         if (achl_cobu_next > achl_cobu_end) return FALSE;
         iml1 = 32 + (unsigned char) *(achl_cobu_cur + 1);
       }
       achl_cobu_next += sizeof(unsigned short int);  /* add length colour */
       if (achl_cobu_next > achl_cobu_end) return FALSE;
       /* attention little endian / big endian / alignment UUUU 25.08.06 KB */
       xxl_col_1 = *((unsigned char *) achl_cobu_next - 2)
                      | (*((unsigned char *) achl_cobu_next - 1) << 8);
       axxl_pibu_next += iml1;
       if (axxl_pibu_next > axxl_pibu_end) return FALSE;
       do {                                 /* loop to fill in colour  */
         *axxl_pibu_cur++ = xxl_col_1;
       } while (axxl_pibu_cur < axxl_pibu_next);
       bol_fill9 = FALSE;                   /* this command is not Fill 9 */
       break;                               /* all done                */
     case (4 * 2):                          /* Copy                    */
     case (4 * 2 + 1):                      /* Copy                    */
       iml1 = *achl_cobu_cur & 0X1F;        /* get length in 5 bits    */
       if (iml1 == 0) {                     /* length follows next byte */
         achl_cobu_next++;                  /* add length of length byte */
         if (achl_cobu_next > achl_cobu_end) return FALSE;
         iml1 = 32 + (unsigned char) *(achl_cobu_cur + 1);
       }
       achl_cobu_cur = achl_cobu_next;      /* save position for copy  */
       achl_cobu_next += iml1 * sizeof(unsigned short int);  /* add length command */
       if (achl_cobu_next > achl_cobu_end) return FALSE;
       axxl_pibu_next += iml1;
       if (axxl_pibu_next > axxl_pibu_end) return FALSE;
/* UUUU ERROR ??? little / big endian 31.12.06 KB */
       memcpy( axxl_pibu_cur, achl_cobu_cur, iml1 * sizeof(unsigned short int) );
       bol_fill9 = FALSE;                   /* this command is not Fill 9 */
       break;
     case 0X0C:                             /* SetMix_Mix              */
       iml1 = *achl_cobu_cur & 0X0F;        /* get length in 4 bits    */
       if (iml1 == 0) {                     /* length follows next byte */
         achl_cobu_next++;                  /* add length of length byte */
         if (achl_cobu_next > achl_cobu_end) return FALSE;
         iml1 = 16 + (unsigned char) *(achl_cobu_cur + 1);
       }
       achl_cobu_next += sizeof(unsigned short int);  /* add length colour */
       if (achl_cobu_next > achl_cobu_end) return FALSE;
       /* attention little endian / big endian / alignment UUUU 25.08.06 KB */
       xxl_mix = *((unsigned char *) achl_cobu_next - 2)
                    | (*((unsigned char *) achl_cobu_next - 1) << 8);
       bol_fill9 = FALSE;                   /* this command is not Fill 9 */
       iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
       if (iml2 > 0) {                      /* part is in first line   */
         if (iml2 > iml1) iml2 = iml1;      /* only as long as length  */
         iml1 -= iml2;                      /* this part has been done */
         axxl_pibu_temp1 = axxl_pibu_next + iml2;  /* compute end loop */
         do {                               /* fill with mix           */
           *axxl_pibu_next++ = xxl_mix;
         } while (axxl_pibu_next < axxl_pibu_temp1);
         if (iml1 == 0) break;              /* all done                */
         axxl_pibu_cur = axxl_pibu_next;    /* continue from this position */
       }
       axxl_pibu_next += iml1;
       if (axxl_pibu_next > axxl_pibu_end) return FALSE;
       do {                                 /* loop to XOR remaining part */
         *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH) ^ xxl_mix;
         axxl_pibu_cur++;                   /* increment position pixel */
       } while (axxl_pibu_cur < axxl_pibu_next);
       break;                               /* all done                */
     case 0X0D:                             /* SetMix_FillOrMix        */
       iml1 = (*achl_cobu_cur & 0X0F) << 3;  /* get length in 4 bits, shifted */
       if (iml1 == 0) {                     /* length follows next byte */
         achl_cobu_next++;                  /* add length command      */
         if (achl_cobu_next > achl_cobu_end) return FALSE;
         iml1 = 1 + (unsigned char) *(achl_cobu_cur + 1);
       }
       iml3 = (iml1 + 7) >> 3;              /* number of bytes Mask    */
       achl_cobu_next += sizeof(unsigned short int);  /* add length colour */
       achl_cobu_cur = achl_cobu_next;      /* save start mask         */
       achl_cobu_next += iml3;              /* add length mask         */
       if (achl_cobu_next > achl_cobu_end) return FALSE;
       /* attention little endian / big endian / alignment UUUU 25.08.06 KB */
       xxl_mix = *((unsigned char *) achl_cobu_cur - 2)
                    | (*((unsigned char *) achl_cobu_cur - 1) << 8);
       bol_fill9 = FALSE;                   /* this command is not Fill 9 */
       iml3 = 1;                            /* mask byte filled        */
       iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
       if (iml2 > 0) {                      /* part is in first line   */
         if (iml2 > iml1) iml2 = iml1;      /* only as long as length  */
         iml1 -= iml2;                      /* this part has been done */
         axxl_pibu_temp1 = axxl_pibu_next + iml2;  /* compute end loop */
         do {                               /* fill with mix           */
           if (iml3 == 256) {               /* mask byte exhausted     */
             achl_cobu_cur++;               /* get next byte mask      */
             iml3 = 1;                      /* start with LSB          */
           }
           *axxl_pibu_next = 0;
           if (*((unsigned char *) achl_cobu_cur) & iml3) {  /* mask-bit set */
             *axxl_pibu_next = xxl_mix;
           }
           axxl_pibu_next++;
           iml3 <<= 1;                      /* take next bit in mask   */
         } while (axxl_pibu_next < axxl_pibu_temp1);
         if (iml1 == 0) break;              /* all done                */
         axxl_pibu_cur = axxl_pibu_next;    /* continue from this position */
       }
       axxl_pibu_next += iml1;
       if (axxl_pibu_next > axxl_pibu_end) return FALSE;
       do {                                 /* loop to XOR remaining part */
         if (iml3 == 256) {                 /* mask byte exhausted     */
           achl_cobu_cur++;                 /* get next byte mask      */
           iml3 = 1;                        /* start with LSB          */
         }
         *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH);
         if (*((unsigned char *) achl_cobu_cur) & iml3) {  /* mask-bit set */
           *axxl_pibu_cur ^= xxl_mix;
         }
         axxl_pibu_cur++;                   /* increment position pixel */
         iml3 <<= 1;                        /* take next bit in mask   */
       } while (axxl_pibu_cur < axxl_pibu_next);
       break;                               /* all done                */
     case 0X0E:                             /* Bicolor                 */
       iml1 = *achl_cobu_cur & 0X0F;        /* get length in 4 bits    */
       if (iml1 == 0) {                     /* length follows next byte */
         achl_cobu_next++;                  /* add length of length byte */
         if (achl_cobu_next > achl_cobu_end) return FALSE;
         iml1 = 16 + (unsigned char) *(achl_cobu_cur + 1);
       }
       achl_cobu_next += 2 * sizeof(unsigned short int);  /* add length colours */
       if (achl_cobu_next > achl_cobu_end) return FALSE;
       /* attention little endian / big endian / alignment UUUU 25.08.06 KB */
       xxl_col_1 = *((unsigned char *) achl_cobu_next - 4)
                      | (*((unsigned char *) achl_cobu_next - 3) << 8);
       xxl_col_2 = *((unsigned char *) achl_cobu_next - 2)
                      | (*((unsigned char *) achl_cobu_next - 1) << 8);
       axxl_pibu_next += iml1 * 2;
       if (axxl_pibu_next > axxl_pibu_end) return FALSE;
       do {                                 /* loop to fill in colours */
         *axxl_pibu_cur++ = xxl_col_1;
         *axxl_pibu_cur++ = xxl_col_2;
       } while (axxl_pibu_cur < axxl_pibu_next);
       bol_fill9 = FALSE;                   /* this command is not Fill 9 */
       break;                               /* all done                */
     case 0X0F:                             /* extended Opcodes        */
       switch ((unsigned char) *achl_cobu_cur) {
         case 0XF0:                         /* Fill 9                  */
           achl_cobu_next += sizeof(unsigned short int);  /* add length length */
           if (achl_cobu_next > achl_cobu_end) return FALSE;
           iml1 = *((unsigned char *) achl_cobu_next - 2)
                     | (*((unsigned char *) achl_cobu_next - 1) << 8);
           if (iml1 == 0) return FALSE;
           axxl_pibu_next += iml1;
           if (axxl_pibu_next > axxl_pibu_end) return FALSE;
           if (bol_fill9) {                 /* last command was Fill 9 */
             /* one single pixel mix                                   */
             iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
             if (iml2 > 0) {                /* part is in first line   */
               *axxl_pibu_next++ = xxl_mix;  /* one pixel mix          */
             } else {
               *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH) ^ xxl_mix;
             }
             iml1--;                        /* one pixel done          */
             if (iml1 == 0) break;          /* all done                */
             axxl_pibu_cur++;               /* continue from this position */
           }
           bol_fill9 = TRUE;                /* last command was Fill 9 */
           iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
           if (iml2 > 0) {                  /* part is in first line   */
             if (iml2 > iml1) iml2 = iml1;  /* only as long as length  */
             iml1 -= iml2;                  /* this part has been done */
             memset( axxl_pibu_cur, 0, iml2 * sizeof(unsigned short int) );
             if (iml1 == 0) break;          /* all done                */
             axxl_pibu_cur += iml2;         /* continue from this position */
           }
#ifdef OLD01
           memmove( axxl_pibu_cur,
                    axxl_pibu_cur - UCL_WIDTH,
                    iml1 * sizeof(unsigned short int) );
#endif
           do {
             *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH);
             axxl_pibu_cur++;
           } while (axxl_pibu_cur < axxl_pibu_next);
           break;
         case 0XF2:                         /* FillOrMix               */
           achl_cobu_next += sizeof(unsigned short int);  /* add length length */
           if (achl_cobu_next > achl_cobu_end) return FALSE;
           iml1 = *((unsigned char *) achl_cobu_next - 2)
                     | (*((unsigned char *) achl_cobu_next - 1) << 8);
           if (iml1 == 0) return FALSE;
           iml3 = (iml1 + 7) >> 3;          /* number of bytes Mask    */
           achl_cobu_cur = achl_cobu_next;  /* save start mask minus one */
           achl_cobu_next += iml3;          /* add length mask         */
           if (achl_cobu_next > achl_cobu_end) return FALSE;
           bol_fill9 = FALSE;               /* this command is not Fill 9 */
           iml3 = 1;                        /* mask byte filled        */
           iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
           if (iml2 > 0) {                  /* part is in first line   */
             if (iml2 > iml1) iml2 = iml1;  /* only as long as length  */
             iml1 -= iml2;                  /* this part has been done */
             axxl_pibu_temp1 = axxl_pibu_next + iml2;  /* compute end loop */
             do {                           /* fill with mix           */
               if (iml3 == 256) {           /* mask byte exhausted     */
                 achl_cobu_cur++;           /* get next byte mask      */
                 iml3 = 1;                  /* start with LSB          */
               }
               *axxl_pibu_next = 0;
               if (*((unsigned char *) achl_cobu_cur) & iml3) {  /* mask-bit set */
                 *axxl_pibu_next = xxl_mix;
               }
               axxl_pibu_next++;
               iml3 <<= 1;                  /* take next bit in mask   */
             } while (axxl_pibu_next < axxl_pibu_temp1);
             if (iml1 == 0) break;          /* all done                */
             axxl_pibu_cur = axxl_pibu_next;  /* continue from this position */
           }
           axxl_pibu_next += iml1;
           if (axxl_pibu_next > axxl_pibu_end) return FALSE;
           do {                             /* loop to XOR remaining part */
             if (iml3 == 256) {             /* mask byte exhausted     */
               achl_cobu_cur++;             /* get next byte mask      */
               iml3 = 1;                    /* start with LSB          */
             }
             *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH);
             if (*((unsigned char *) achl_cobu_cur) & iml3) {  /* mask-bit set */
               *axxl_pibu_cur ^= xxl_mix;
             }
             axxl_pibu_cur++;               /* increment position pixel */
             iml3 <<= 1;                    /* take next bit in mask   */
           } while (axxl_pibu_cur < axxl_pibu_next);
           break;                           /* all done                */
         case 0XF3:                         /* Color                   */
           achl_cobu_next += 2 * sizeof(unsigned short int);  /* add length length and colour */
           if (achl_cobu_next > achl_cobu_end) return FALSE;
           iml1 = *((unsigned char *) achl_cobu_next - 4)
                     | (*((unsigned char *) achl_cobu_next - 3) << 8);
           if (iml1 == 0) return FALSE;
           xxl_col_1 = *((unsigned char *) achl_cobu_next - 2)
       /* attention little endian / big endian / alignment UUUU 25.08.06 KB */
                          | (*((unsigned char *) achl_cobu_next - 1) << 8);
           axxl_pibu_next += iml1;
           if (axxl_pibu_next > axxl_pibu_end) return FALSE;
           do {                             /* loop to fill in colour  */
             *axxl_pibu_cur++ = xxl_col_1;
           } while (axxl_pibu_cur < axxl_pibu_next);
           bol_fill9 = FALSE;               /* this command is not Fill 9 */
           break;                           /* all done                */
         case 0XF4:                         /* Copy                    */
           achl_cobu_next += sizeof(unsigned short int);  /* add length length */
           if (achl_cobu_next > achl_cobu_end) return FALSE;
           iml1 = *((unsigned char *) achl_cobu_next - 2)
                     | (*((unsigned char *) achl_cobu_next - 1) << 8);
           if (iml1 == 0) return FALSE;
           achl_cobu_cur = achl_cobu_next;  /* save position for copy  */
           achl_cobu_next += iml1 * sizeof(unsigned short int);  /* add length command */
           if (achl_cobu_next > achl_cobu_end) return FALSE;
           axxl_pibu_next += iml1;
           if (axxl_pibu_next > axxl_pibu_end) return FALSE;
           memcpy( axxl_pibu_cur, achl_cobu_cur, iml1 * sizeof(unsigned short int) );
           bol_fill9 = FALSE;               /* this command is not Fill 9 */
           break;
         case 0XF7:                         /* SetMix_FillOrMix        */
           achl_cobu_next += 2 * sizeof(unsigned short int);  /* add length length and colour */
           if (achl_cobu_next > achl_cobu_end) return FALSE;
           iml1 = *((unsigned char *) achl_cobu_next - 4)
                     | (*((unsigned char *) achl_cobu_next - 3) << 8);
           if (iml1 == 0) return FALSE;
           iml3 = (iml1 + 7) >> 3;          /* number of bytes Mask    */
           achl_cobu_cur = achl_cobu_next;  /* save start mask         */
           achl_cobu_next += iml3;          /* add length mask         */
           if (achl_cobu_next > achl_cobu_end) return FALSE;
       /* attention little endian / big endian / alignment UUUU 25.08.06 KB */
           xxl_mix = *((unsigned char *) achl_cobu_cur - 2)
                        | (*((unsigned char *) achl_cobu_cur - 1) << 8);
           bol_fill9 = FALSE;               /* this command is not Fill 9 */
           iml3 = 1;                        /* mask byte filled        */
           iml2 = UCL_WIDTH - (axxl_pibu_cur - AXXL_PIBU_START);
           if (iml2 > 0) {                  /* part is in first line   */
             if (iml2 > iml1) iml2 = iml1;  /* only as long as length  */
             iml1 -= iml2;                  /* this part has been done */
             axxl_pibu_temp1 = axxl_pibu_next + iml2;  /* compute end loop */
             do {                           /* fill with mix           */
               if (iml3 == 256) {           /* mask byte exhausted     */
                 achl_cobu_cur++;           /* get next byte mask      */
                 iml3 = 1;                  /* start with LSB          */
               }
               *axxl_pibu_next = 0;
               if (*((unsigned char *) achl_cobu_cur) & iml3) {  /* mask-bit set */
                 *axxl_pibu_next = xxl_mix;
               }
               axxl_pibu_next++;
               iml3 <<= 1;                  /* take next bit in mask   */
             } while (axxl_pibu_next < axxl_pibu_temp1);
             if (iml1 == 0) break;          /* all done                */
             axxl_pibu_cur = axxl_pibu_next;  /* continue from this position */
           }
           axxl_pibu_next += iml1;
           if (axxl_pibu_next > axxl_pibu_end) return FALSE;
           do {                             /* loop to XOR remaining part */
             if (iml3 == 256) {             /* mask byte exhausted     */
               achl_cobu_cur++;             /* get next byte mask      */
               iml3 = 1;                    /* start with LSB          */
             }
             *axxl_pibu_cur = *(axxl_pibu_cur - UCL_WIDTH);
             if (*((unsigned char *) achl_cobu_cur) & iml3) {  /* mask-bit set */
               *axxl_pibu_cur ^= xxl_mix;
             }
             axxl_pibu_cur++;               /* increment position pixel */
             iml3 <<= 1;                    /* take next bit in mask   */
           } while (axxl_pibu_cur < axxl_pibu_next);
           break;                           /* all done                */
         case 0XFD:                         /* White                   */
           axxl_pibu_next++;                /* only one pixel          */
           if (axxl_pibu_next > axxl_pibu_end) return FALSE;
           *axxl_pibu_cur = (unsigned short int) 0XFFFF;
           bol_fill9 = FALSE;               /* this command is not Fill 9 */
           break;                           /* all done                */
         case 0XFE:                         /* Black                   */
           axxl_pibu_next++;                /* only one pixel          */
           if (axxl_pibu_next > axxl_pibu_end) return FALSE;
           *axxl_pibu_cur = 0;
           bol_fill9 = FALSE;               /* this command is not Fill 9 */
           break;                           /* all done                */
         default:
           return FALSE;                    /* command unknown         */
       }
       break;
     default:
       return FALSE;                        /* command unknown         */
   }
   if (achl_cobu_next < achl_cobu_end) {
#ifdef OLD01
     if (axxl_pibu_next == axxl_pibu_end) {
       axxl_pibu_line += iml_width;
       if (((unsigned short int *) (adsp_cache_1 + 1)
             + D_ADSL_RCL1->ucc_prot_r5_pdu_ord_height * iml_width)
             >= axxl_pibu_line) {
         return FALSE;                      /* more than height        */
       }
       axxl_pibu_next = axxl_pibu_line;     /* start in new line       */
       axxl_pibu_end = axxl_pibu_next + D_ADSL_RCL1->ucc_prot_r5_pdu_ord_width;
     }
#endif
     goto pdeco20;                          /* decode command          */
   }
#undef AXXL_PIBU_START
#undef UCL_WIDTH
#ifdef OLD01
   iml1 = (D_ADSL_RCL1->ucc_prot_r5_pdu_ord_height - 1) * iml_width
          + D_ADSL_RCL1->ucc_prot_r5_pdu_ord_width;
   if (axxl_pibu_next != ((unsigned short int *) (adsp_cache_1 + 1) + iml1)) {
     return FALSE;
   }
#endif
   if (axxl_pibu_next != axxl_pibu_end) {
     return FALSE;
   }
   return TRUE;
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RCL1
#undef D_ADSL_RCO1
#undef ADSL_OA1
#undef ADSL_RDPA_F
#endif
} /* end m_decomp_01_s()                                               */



/** send RDP5-style input from client to server                        */
static BOOL m_send_cl2se_rdp5( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
                               struct dsd_output_area_1 *adsp_output_area_1,
                               char *achp_data, int imp_len_data,
                               int imp_no_order ) {
   int        iml1, iml2;                   /* working-variables       */
   char       chl_no_order;                 /* optional number of orders */
   char       *achl_out;                    /* output pointer          */
#ifdef OLD01
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
#endif
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_output_area_1 *ADSL_OA1;
#endif
   char       chrl_work_1[ 256 ];           /* work area               */

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#define ADSL_OA1 adsp_output_area_1
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
#ifdef HL_RDPACC_HELP_DEBUG
   ADSL_OA1 = adsp_output_area_1;
#endif
   if (imp_no_order >= 256) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_cl2se_rdp5() number of orders (%d) too high",
                   __LINE__, 37881,  /* line number for errors */
                   imp_no_order );
     return FALSE;
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_cl2se_rdp5() output-area too small",
                   __LINE__, 37888 );  /* line number for errors */
     return FALSE;
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   // TODO: check how to generate correctly for all cases the security header on 2.2.8.1.2 Client Fast-Path Input Event PDU (TS_FP_INPUT_PDU)
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
        iml1 = 1 + 1 + D_SIZE_HASH + imp_len_data;
   } else {
        iml1 = 1 + 1 + imp_len_data;
   }
   if (imp_no_order > 15) {
     iml1++;
     chl_no_order = (unsigned char) imp_no_order;
   }
   if (iml1 >= 128) {                       /* length in two bytes     */
     iml1++;                                /* additional length byte  */
   }
#ifdef OLD01
   adsl_gai1_out_1->achc_ginp_cur = achl_out = ADSL_OA1->achc_lower;
   adsl_gai1_out_1->achc_ginp_end = ADSL_OA1->achc_lower + iml1;
#endif
   ADSL_GAI1_OUT_G->achc_ginp_cur = achl_out = ADSL_OA1->achc_lower;
   ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower + iml1;
   ADSL_OA1->achc_lower += iml1;               /* space in output area    */
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d output-area too small",
                   __LINE__, 37930 );  /* line number for errors */
     return FALSE;
   }
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
   iml2 = 0;
   if (imp_no_order <= 15) {
     iml2 = imp_no_order << 2;
   }
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
      *achl_out++ = (char) (0XC0 | iml2);
   } else {
      *achl_out++ = (char) (0X00 | iml2);
   }
   if (iml1 < 128) {                        /* length in one byte      */
     *achl_out++ = (char) iml1;             /* length follows          */
   } else {                                 /* length in two bytes     */
     *achl_out++ = (unsigned char) (0X80 | (iml1 >> 8));  /* length byte one follows */
     *achl_out++ = (unsigned char) iml1;    /* length byte two follows */
   }
    iml1 = imp_len_data;
    if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level == 0){
        goto LBL_FASTPATH_EVENT_NOT_ENCRYPTED;
    }
   if ((ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent & (4096 - 1)) == 0){
     if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent) {
       m_update_keys( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se, NULL );
     }
   }
   /* generate random                                                  */
#define ACHL_WORK_SHA1 ((int *) chrl_work_1)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
   memcpy( ACHL_WORK_SHA1,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
   memcpy( ACHL_WORK_MD5,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
   iml1 = imp_len_data;
   if (imp_no_order > 15) {
     iml1++;
   }
   m_put_le4( ACHL_WORK_UTIL_01, iml1 );
   SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
   if (imp_no_order > 15) {
     SHA1_Update( ACHL_WORK_SHA1, &chl_no_order, 0, 1 );
   }
   SHA1_Update( ACHL_WORK_SHA1, achp_data, 0, imp_len_data );
     m_put_le4( ACHL_WORK_UTIL_01, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent );
     SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
   SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
   MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
   MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
   memcpy( achl_out, ACHL_WORK_UTIL_01, D_SIZE_HASH );
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
LBL_FASTPATH_EVENT_NOT_ENCRYPTED:
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
       achl_out += D_SIZE_HASH;                 /* add length hash         */
       if (imp_no_order > 15) {
         RC4( &chl_no_order, 0, 1,
         achl_out, 0,
         ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
         achl_out++;
       }
       RC4( achp_data, 0, imp_len_data,
            achl_out, 0,
            ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
       ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
   } else {
       if (imp_no_order > 15) {
          *achl_out= imp_no_order;
          achl_out++;
       }
       memcpy(achl_out, achp_data, imp_len_data);
   }
// adsl_gai1_out_2 = adsl_gai1_out_1;       /* save this field         */
   return TRUE;                             /* all done                */
#ifndef HL_RDPACC_HELP_DEBUG
#undef ADSL_OA1
#undef ADSL_RDPA_F
#endif
} /* end m_send_cl2se_rdp5()                                           */

/* send Confirm Active PDU from client to server                       */
static BOOL m_send_cl2se_conf_act_pdu( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
                                       struct dsd_output_area_1 *adsp_output_area_1 ) {
   int        iml1;                         /* working-variable        */
   char       *achl_out;                    /* output pointer          */
#ifdef OLD01
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
#endif
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_output_area_1 *ADSL_OA1;
#endif
   char       chrl_work_1[ 256 ];           /* work area               */

    struct dsd_gather_i_1 *adsl_gai1_out_1;
    int iml_security_header_len;
    int iml_size_hash;
    switch (adsp_hl_clib_1->adsc_rdp_co->imc_sec_method){
    case 0x00: // ENCRYPTION_METHOD_NONE
        iml_security_header_len = 0;
        iml_size_hash = 0;
        break;
    case 0x01: // ENCRYPTION_METHOD_40BIT
    case 0x02: // ENCRYPTION_METHOD_128BIT
    case 0x08: // ENCRYPTION_METHOD_56BIT
        iml_security_header_len = 4;
        iml_size_hash = D_SIZE_HASH;
        break;
    case 0x10: // ENCRYPTION_METHOD_FIPS // Not supported
    default:
        m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_vch_tose() illogic - Encryption method not supported - %d/0x%X",
                     __LINE__, 38137, 
                     adsp_hl_clib_1->adsc_rdp_co->imc_sec_method, adsp_hl_clib_1->adsc_rdp_co->imc_sec_method);  /* line number for errors */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
        return FALSE; 
   }
#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#define ADSL_OA1 adsp_output_area_1
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
#ifdef HL_RDPACC_HELP_DEBUG
   ADSL_OA1 = adsp_output_area_1;
#endif
#ifdef TRACEHL1
   printf( "l%05d s%05d m_send_cl2se_conf_act_pdu() ADSL_OA1->achc_lower=%p ADSL_OA1->achc_upper=%p\n",
           __LINE__, 38155, ADSL_OA1->achc_lower, ADSL_OA1->achc_upper );
#endif
   iml1 = 1 + 1 + 2 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1 + 2 + iml_security_header_len + iml_size_hash;
   if(!m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1, iml1 + 12 + sizeof(ucrs_capabilities_resp) + sizeof(struct dsd_gather_i_1))) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
     return FALSE;                     /* do cleanup now          */
   }
   achl_out = ADSL_OA1->achc_lower + iml1;
   *(achl_out + 2) = (unsigned char) 0X13;  /* Confirm Active PDU      */
   *(achl_out + 3) = 0;                     /* padding                 */
// to-do 13.02.09 share-id from server
// temporary F0 03 EA 03  01 00 EA 03
// *(achl_out + 4) = (unsigned char) 0XF0;
// *(achl_out + 5) = (unsigned char) 0X03;
   m_put_le2( achl_out + 4, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_cont );
// JB 04.02.11: shareID is only 0x000103EA, if this ist a new connection.
// In case of a reconnect to an existing session, it is different.
   m_put_le4( achl_out + 6, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_shareid );
   *(achl_out + 10) = (unsigned char) 0XEA;
   *(achl_out + 11) = (unsigned char) 0X03;
   memcpy( achl_out + 12, ucrs_capabilities_resp, sizeof(ucrs_capabilities_resp) );
   m_put_le2( achl_out, 12 + sizeof(ucrs_capabilities_resp) );
    if(adsp_hl_clib_1->adsc_rdp_co->imc_sec_level == 0)
       goto LBL_NO_ENCRYPT_CAPS_RESP;
   /* encrypt the data                                                 */
#define ACHL_WORK_SHA1 ((int *) chrl_work_1)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
   memcpy( ACHL_WORK_SHA1,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
   memcpy( ACHL_WORK_MD5,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
   m_put_le4( ACHL_WORK_UTIL_01, 12 + sizeof(ucrs_capabilities_resp) );
   SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
   SHA1_Update( ACHL_WORK_SHA1, achl_out, 0, 12 + sizeof(ucrs_capabilities_resp) );
   SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
   MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
   MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
   memcpy( achl_out - D_SIZE_HASH, ACHL_WORK_UTIL_01, D_SIZE_HASH );
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
   RC4( achl_out, 0, 12 + sizeof(ucrs_capabilities_resp),
        achl_out, 0,
        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
LBL_NO_ENCRYPT_CAPS_RESP:
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   ADSL_GAI1_OUT_G->achc_ginp_end = achl_out + 12 + sizeof(ucrs_capabilities_resp);
   ADSL_OA1->achc_lower = ADSL_GAI1_OUT_G->achc_ginp_end;  /* space in output area */
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
   adsl_gai1_out_1 = ADSL_GAI1_OUT_G;
   /* prepare the header                                               */
    if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
        // TODO: this is only valid for non-FIPS headers; FIPS headers will give trouble...
        *(achl_out - iml_security_header_len - iml_size_hash) = (unsigned char) 0x38; // 0x08 = SEC_ENCRYPT
        memset( achl_out - 3 - iml_size_hash, 0, 3 );
    }
    iml1 = iml_security_header_len + iml_size_hash + 12 + sizeof(ucrs_capabilities_resp);
    if (iml1 <= 127) {
        achl_out -= 1 + iml_security_header_len + iml_size_hash;
        *achl_out = (unsigned char) iml1;
    } else {
        achl_out -= 2 + iml_security_header_len + iml_size_hash;
        m_put_be2( achl_out, iml1 );
        *achl_out |= 0X80;                     /* length in two bytes     */
    }
    achl_out -= 1 + 1 + 2 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1;
   *achl_out = DEF_CONST_RDP_03;
   *(achl_out + 1) = 0;                     /* second byte zero        */
   m_put_be2( achl_out + 2, ADSL_GAI1_OUT_G->achc_ginp_end - achl_out );
   memcpy( achl_out + 4,
           ucrs_x224_p01,
           sizeof(ucrs_x224_p01) );
   *(achl_out + 4 + sizeof(ucrs_x224_p01)) = (unsigned char) 0X64;  /* send data request */
   m_put_be2( achl_out + 4 + sizeof(ucrs_x224_p01) + 1, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
   m_put_be2( achl_out + 4 + sizeof(ucrs_x224_p01) + 1 + 2, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_disp );
   *(achl_out + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2) = (unsigned char) 0X70;  /* priority / segmentation */
   ADSL_GAI1_OUT_G->achc_ginp_cur = achl_out;  /* set start of output  */
   if(!m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1, sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ts_synchronize_pdu) + sizeof(struct dsd_gather_i_1))) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
     return FALSE;                     /* do cleanup now          */
   }
   /* send 2.2.1.14 Client Synchronize PDU                             */
   achl_out = ADSL_OA1->achc_lower;
   memcpy( achl_out, ucrs_pdu_header_01, sizeof(ucrs_pdu_header_01) );
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
     *(achl_out + 3) = (unsigned char) (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ts_synchronize_pdu));
   } else {
       // Remove length of securityHeader non-FIPS // TODO: search a solution that works also for FIPS headers!
      *(achl_out + 3) = (unsigned char) (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ts_synchronize_pdu) - 4);
   }
   m_put_be2( achl_out + 8, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
   m_put_be2( achl_out + 10, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_disp );
   *(achl_out + 13) = (unsigned char) (iml_security_header_len + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ts_synchronize_pdu));
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
    *(achl_out + 14) = (unsigned char) 0x28;
   } else {
       achl_out -= 4; // Remove securityHeader non-FIPS // TODO: search a solution that works also for FIPS headers!
   }
   *(achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash) = (unsigned char) (6 + sizeof(ucrs_share_id) + sizeof(ucrs_ts_synchronize_pdu));
   memset( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 1, 0, 3 );
   *(achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 2) = (unsigned char) 0X17;
   m_put_le2( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 4, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_cont );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 6, ucrs_share_id, sizeof(ucrs_share_id) );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id),
           ucrs_ts_synchronize_pdu, sizeof(ucrs_ts_synchronize_pdu) );
    if(adsp_hl_clib_1->adsc_rdp_co->imc_sec_level == 0)
       goto LBL_NO_ENCRYPT_TS_SYNCHRONIZE_PDU;
   /* encrypt the data                                                 */
#define ACHL_WORK_SHA1 ((int *) chrl_work_1)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
   memcpy( ACHL_WORK_SHA1,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
   memcpy( ACHL_WORK_MD5,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
   m_put_le4( ACHL_WORK_UTIL_01, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ts_synchronize_pdu) );
   SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
   SHA1_Update( ACHL_WORK_SHA1, achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ts_synchronize_pdu) );
   SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
   MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
   MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01), ACHL_WORK_UTIL_01, D_SIZE_HASH );
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
   RC4( achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ts_synchronize_pdu),
        achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0,
        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
LBL_NO_ENCRYPT_TS_SYNCHRONIZE_PDU:
   achl_out += sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ts_synchronize_pdu);
   /* Need a new gather? */
   if(ADSL_OA1->achc_lower != adsl_gai1_out_1->achc_ginp_end) {
      ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
      ADSL_GAI1_OUT_G->adsc_next = NULL;
      ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
      ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
      *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
      ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
      adsl_gai1_out_1 = ADSL_GAI1_OUT_G;
      ADSL_OA1->achc_upper = (char*)ADSL_GAI1_OUT_G;
   }
   ADSL_GAI1_OUT_G->achc_ginp_end = achl_out;
   ADSL_OA1->achc_lower = achl_out;
   if(!m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1, (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_cooperate) + sizeof(struct dsd_gather_i_1)))) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
     return FALSE;                     /* do cleanup now          */
   }
   /* send 2.2.1.15 Client Control PDU - Cooperate                     */
   memcpy( achl_out, ucrs_pdu_header_01, sizeof(ucrs_pdu_header_01) );
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
        *(achl_out + 3) = (unsigned char) (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_cooperate));
   } else {
       // Remove length of securityHeader non-FIPS // TODO: search a solution that works also for FIPS headers!
       *(achl_out + 3) = (unsigned char) (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_cooperate) - 4);
   }
   m_put_be2( achl_out + 8, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
   m_put_be2( achl_out + 10, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_disp );
   *(achl_out + 13) = (unsigned char) (iml_security_header_len + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_cooperate));
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
    *(achl_out + 14) = (unsigned char) 0x08; // 0x08 = SEC_ENCRYPT
   } else {
       achl_out -= 4; // Remove securityHeader non-FIPS // TODO: search a solution that works also for FIPS headers!
   }
   *(achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash) = (unsigned char) (6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_cooperate));
   memset( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 1, 0, 3 );
   *(achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 2) = (unsigned char) 0X17;
   m_put_le2( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 4, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_cont );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 6, ucrs_share_id, sizeof(ucrs_share_id) );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id),
           ucrs_ctrl_pdu_data_cooperate, sizeof(ucrs_ctrl_pdu_data_cooperate) );

    if(adsp_hl_clib_1->adsc_rdp_co->imc_sec_level == 0)
       goto LBL_NO_ENCRYPT_PDU_DATA_COOPERATE;
   /* encrypt the data                                                 */
#define ACHL_WORK_SHA1 ((int *) chrl_work_1)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
   memcpy( ACHL_WORK_SHA1,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
   memcpy( ACHL_WORK_MD5,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
   m_put_le4( ACHL_WORK_UTIL_01, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_cooperate) );
   SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
   SHA1_Update( ACHL_WORK_SHA1, achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_cooperate) );
   SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
   MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
   MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01), ACHL_WORK_UTIL_01, D_SIZE_HASH );
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
   RC4( achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_cooperate),
        achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0,
        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
LBL_NO_ENCRYPT_PDU_DATA_COOPERATE:
   achl_out += sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_cooperate);
   /* Need a new gather? */
   if(ADSL_OA1->achc_lower != adsl_gai1_out_1->achc_ginp_end) {
      ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
      ADSL_GAI1_OUT_G->adsc_next = NULL;
      ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
      ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
      *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
      ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
      adsl_gai1_out_1 = ADSL_GAI1_OUT_G;
      ADSL_OA1->achc_upper = (char*)ADSL_GAI1_OUT_G;
   }
   ADSL_GAI1_OUT_G->achc_ginp_end = achl_out;
   ADSL_OA1->achc_lower = achl_out;
   if(!m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1, sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_request_control) + sizeof(struct dsd_gather_i_1))) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
     return FALSE;                     /* do cleanup now          */
   }
   /* send 2.2.1.16 Client Control PDU - Request Control               */
   memcpy( achl_out, ucrs_pdu_header_01, sizeof(ucrs_pdu_header_01) );
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
       *(achl_out + 3) = (unsigned char) (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_request_control));
   } else {
       // Remove length of securityHeader non-FIPS // TODO: search a solution that works also for FIPS headers!
       *(achl_out + 3) = (unsigned char) (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_request_control) - 4);
   }
   m_put_be2( achl_out + 8, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
   m_put_be2( achl_out + 10, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_disp );
   *(achl_out + 13) = (unsigned char) (iml_security_header_len + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_request_control));
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
       *(achl_out + 14) = (unsigned char) 0x08; // 0x08 = SEC_ENCRYPT
   } else {
       achl_out -= 4; // Remove securityHeader non-FIPS // TODO: search a solution that works also for FIPS headers!
   }
   *(achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash) = (unsigned char) (6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_request_control));
   memset( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 1, 0, 3 );
   *(achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 2) = (unsigned char) 0X17;
   m_put_le2( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 4, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_cont );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 6, ucrs_share_id, sizeof(ucrs_share_id) );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id),
           ucrs_ctrl_pdu_data_request_control, sizeof(ucrs_ctrl_pdu_data_request_control) );
    
    if(adsp_hl_clib_1->adsc_rdp_co->imc_sec_level == 0)
       goto LBL_NO_ENCRYPT_PDU_DATA_REQUEST_CONTROL;
   /* encrypt the data                                                 */
#define ACHL_WORK_SHA1 ((int *) chrl_work_1)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
   memcpy( ACHL_WORK_SHA1,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
   memcpy( ACHL_WORK_MD5,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
   m_put_le4( ACHL_WORK_UTIL_01, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_request_control) );
   SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
   SHA1_Update( ACHL_WORK_SHA1, achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_request_control) );
   SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
   MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
   MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01), ACHL_WORK_UTIL_01, D_SIZE_HASH );
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
   RC4( achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_request_control),
        achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0,
        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
LBL_NO_ENCRYPT_PDU_DATA_REQUEST_CONTROL:
   achl_out += sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_ctrl_pdu_data_request_control);
   /* Need a new gather? */
   if(ADSL_OA1->achc_lower != adsl_gai1_out_1->achc_ginp_end) {
      ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
      ADSL_GAI1_OUT_G->adsc_next = NULL;
      ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
      ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
      *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
      ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
      adsl_gai1_out_1 = ADSL_GAI1_OUT_G;
      ADSL_OA1->achc_upper = (char*)ADSL_GAI1_OUT_G;
   }
   ADSL_GAI1_OUT_G->achc_ginp_end = achl_out;
   ADSL_OA1->achc_lower = achl_out;
   if(!m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1, (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_font_list_pdu) + sizeof(struct dsd_gather_i_1)))) {
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
     return FALSE;                     /* do cleanup now          */
   }
   /* send 2.2.1.17 Client Persistant Key List PDU                     */
   /* is not sent                                                      */
   /* send 2.2.1.18 Client Font List PDU                               */
   memcpy( achl_out, ucrs_pdu_header_01, sizeof(ucrs_pdu_header_01) );
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
        *(achl_out + 3) = (unsigned char) (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_font_list_pdu));
   } else {
       // Remove length of securityHeader non-FIPS // TODO: search a solution that works also for FIPS headers!
       *(achl_out + 3) = (unsigned char) (sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_font_list_pdu) - 4);
   }
   m_put_be2( achl_out + 8, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
   m_put_be2( achl_out + 10, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_disp );
   *(achl_out + 13) = (unsigned char) (iml_security_header_len + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_font_list_pdu));
   if (adsp_hl_clib_1->adsc_rdp_co->imc_sec_level != 0){
       *(achl_out + 14) = (unsigned char) 0x08; // 0x08 = SEC_ENCRYPT
   } else {
       achl_out -= 4; // Remove securityHeader non-FIPS // TODO: search a solution that works also for FIPS headers!
   }
   *(achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash) = (unsigned char) (6 + sizeof(ucrs_share_id) + sizeof(ucrs_font_list_pdu));
   memset( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 1, 0, 3 );
   *(achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 2) = (unsigned char) 0X17;
   m_put_le2( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 4, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_cont );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 6, ucrs_share_id, sizeof(ucrs_share_id) );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id),
           ucrs_font_list_pdu, sizeof(ucrs_font_list_pdu) );

    if(adsp_hl_clib_1->adsc_rdp_co->imc_sec_level == 0)
       goto LBL_NO_ENCRYPT_FONT_LIST_PDU;
   /* encrypt the data                                                 */
#define ACHL_WORK_SHA1 ((int *) chrl_work_1)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
   memcpy( ACHL_WORK_SHA1,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
   memcpy( ACHL_WORK_MD5,
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
           sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
   m_put_le4( ACHL_WORK_UTIL_01, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_font_list_pdu) );
   SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
   SHA1_Update( ACHL_WORK_SHA1, achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_font_list_pdu) );
   SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
   MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
   MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
   memcpy( achl_out + sizeof(ucrs_pdu_header_01), ACHL_WORK_UTIL_01, D_SIZE_HASH );
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
   RC4( achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0, 6 + sizeof(ucrs_share_id) + sizeof(ucrs_font_list_pdu),
        achl_out + sizeof(ucrs_pdu_header_01) + D_SIZE_HASH, 0,
        ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
LBL_NO_ENCRYPT_FONT_LIST_PDU:
   achl_out += sizeof(ucrs_pdu_header_01) + iml_size_hash + 6 + sizeof(ucrs_share_id) + sizeof(ucrs_font_list_pdu);
   /* Need a new gather? */
   if(ADSL_OA1->achc_lower != adsl_gai1_out_1->achc_ginp_end) {
      ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
      ADSL_GAI1_OUT_G->adsc_next = NULL;
      ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
      ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
      *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
      ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
      adsl_gai1_out_1 = ADSL_GAI1_OUT_G;
      ADSL_OA1->achc_upper = (char*)ADSL_GAI1_OUT_G;
   }
   ADSL_GAI1_OUT_G->achc_ginp_end = achl_out;
   ADSL_OA1->achc_lower = achl_out;
#undef ADSL_GAI1_OUT_G
#undef ADSL_RDPA_F
   return TRUE;
} /* end m_send_cl2se_conf_act_pdu()                                   */

/* send license to server or a client new license request                      */
static BOOL m_send_cl2se_license( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
                                  struct dsd_output_area_1 *adsp_output_area_1,
                                  struct dsd_cc_pass_license *dsc_cc_pass_license,
                                  char *chr_work_1, int im_len_work_1,
                                  char *chr_work_2, int im_len_work_2 ) {

  BOOL       bol1;                         /* working variable        */
  int        iml1, iml2, iml3, iml4, iml5, iml6; /* working-variables       */
  char       *achl1, *achl2;               /* working variables       */
  char       *achl3, *achl4;               /* working variables       */
  struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */

  struct dsd_rdpa_f *ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
  struct dsd_rdp_client_1 *D_ADSL_RCL1 = &ADSL_RDPA_F->dsc_rdp_cl_1;
  struct dsd_rdp_co_client *D_ADSL_RCO1 = &D_ADSL_RCL1->dsc_rdp_co_1;  /* RDP communication client */

  BOOL bo_new_license = (dsc_cc_pass_license->imc_len_content == 0);

  /* fill dsd_lic_neg-structure */
  // if in hook-mode, the dsd_lic_net-structure filled by the new license request, send from the client.
  if(D_ADSL_RCO1->adsc_lic_neg == NULL) {
    adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
    return FALSE;
  }
  D_ADSL_RCO1->adsc_lic_neg->imc_lic_pkea = 0x1;
  D_ADSL_RCO1->adsc_lic_neg->imc_lic_platform = D_ADSL_RCO1->imc_platform_id;

  /* Get new client randoms for licensing */
  bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                     DEF_AUX_RANDOM_RAW,  /* calcalute random */
                                     D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand,
                                     sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand) );
  if (bol1 == FALSE) {                     /* aux returned error      */
    adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
    return FALSE;                     /* do cleanup now          */
  }

  /* Get client premaster */
  iml1 = 48; // len premaster
  D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_type = 0x0000;
  D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_len  = iml1;
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, iml1 );
  bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                     DEF_AUX_RANDOM_RAW,  /* calcalute random */
                                     D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data,
                                     iml1 );
  if (bol1 == FALSE) {                     /* aux returned error      */
    adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
    return FALSE;                     /* do cleanup now          */
  }

  /* Create the keys                 */
  m_gen_lic_keys( D_ADSL_RCO1->adsc_lic_neg, chr_work_2 );

  /* first encrypt the client random with the server-side keys     */
  iml1 = D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_len;
  iml3 = im_len_work_1;
#ifdef __INSURE__
  // rsa_crypt_raw uses lnum, which causes an Insure-error.
  _Insure_checking_enable(0);
#endif
#ifdef XH_INTERFACE
   ds__hmem dsl_new_struct;
   memset(&dsl_new_struct, 0, sizeof(ds__hmem));
   dsl_new_struct.in__aux_up_version = 1;
   dsl_new_struct.am__aux2 = adsp_hl_clib_1->amc_aux;
   dsl_new_struct.in__flags = 0;
   dsl_new_struct.vp__context = adsp_hl_clib_1->vpc_userfld;

  iml2 = m_rsa_crypt_raw_big( &dsl_new_struct, (unsigned char *) D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data,
#else // XH_INTERFACE
  iml2 = m_rsa_crypt_raw_big( (unsigned char *) D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data,
#endif // XH_INTERFACE
                              iml1,
                              (unsigned char *) D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_exp,
                              D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_exp_len,
                              (unsigned char *) D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_key,
                              D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len,
                              (unsigned char *) chr_work_1,
                              &iml3 );
#ifdef XH_INTERFACE
   HMemMgrFree(&dsl_new_struct);
#endif
#ifdef __INSURE__
  _Insure_checking_enable(1);
#endif
  if (iml2) return FALSE;              /* protocol error          */
  if (iml3 == 0) return FALSE;         /* protocol error          */

// to-do 20.04.12 KB - == TRUE should not be used, unsafe and slow
  if(bo_new_license == TRUE){
    /* Client New License Request */
    /* Username and computername */
// to-do 10.03.12 KB use new function
    iml2 = m_cpy_vx_vx( chr_work_2, im_len_work_2, ied_chs_ascii_850,
                        D_ADSL_RCO1->awcc_loinf_userna_a, D_ADSL_RCO1->usc_loinf_userna_len / sizeof(HL_WCHAR), ied_chs_le_utf_16 );  /* Unicode UTF-16 little endian */
    if (iml2 < 0) return FALSE;
    *(chr_work_2 + iml2) = 0;

    iml1 = 4                             /* Licencing Preamble      */
         + 4                             /* PreferredKeyExchangeAlg */
         + 4                             /* PlatformId              */
         + 32                            /* ClientRandom            */
         + 2                             /* Binary BLOB, type       */
         + 2                             /* Binary BLOB, length     */
         + ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key + 8 /* length of the re-encrypted licensing premaster with padding */
         + 2 + 2 + strlen(chr_work_2) + 1  /* Blob for username */
         + 2 + 2 + strlen(D_ADSL_RCO1->achc_machine_name) + 1; /* Blob for machinename */
// to-do 20.04.12 KB - == WSP may crash D_ADSL_RCO1->achc_machine_name does not contain terminating zero
// severe security flaw !!!
  } else {
    /* Client License Info */
    iml1 = 4                             /* Licencing Preamble      */
         + 4                             /* PreferredKeyExchangeAlg */
         + 4                             /* PlatformId              */
         + 32                            /* ClientRandom            */
         + 2                             /* Binary BLOB, type       */
         + 2                             /* Binary BLOB, length     */
         + ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key + 8 /* length of the re-encrypted licensing premaster with padding */
         + 2 + 2 + dsc_cc_pass_license->imc_len_content  /* Blob license info */
         + 2 + 2 + 4 + 0x10                              /* Blob EncryptedHWID */
         + 0X10;                                         /* Hash */
  }

  achl1 = adsp_output_area_1->achc_lower; /* Start of input */

  /* make the gather */
  adsp_output_area_1->achc_upper -= sizeof(dsd_gather_i_1);
  dsd_gather_i_1* ads_gather = (dsd_gather_i_1*) adsp_output_area_1->achc_upper;
  ads_gather->adsc_next = NULL;
  ads_gather->achc_ginp_cur = achl1;

   *adsp_output_area_1->aadsc_gai1_out_to_server = ads_gather;  /* output data to server */
   adsp_output_area_1->aadsc_gai1_out_to_server = &ads_gather->adsc_next;  /* new chain output data to server */

  /* create message */
  achl3 = achl1; /* save start */
  achl4 = achl3; /* save start in this workarea */
  iml6 = 0;      /* count bytes in workareas which are full */
  memset(achl1, 0X42, adsp_output_area_1->achc_upper - achl1); // UUU remove later

  *achl1++ = DEF_CONST_RDP_03;
  *achl1++ = 0;                        /* second byte zero        */
  achl1 += 2;    // save space for length
  memcpy(achl1, ucrs_x224_p01, sizeof(ucrs_x224_p01));
  achl1 += sizeof(ucrs_x224_p01);
  *achl1++ = 0X64;  /* send data request */
  m_put_be2(achl1, D_ADSL_RCL1->dsc_rdp_co_1.usc_userid_cl2se);
  achl1 += 2;
  m_put_be2(achl1, D_ADSL_RCL1->imc_prot_chno);
  achl1 += 2;
  *achl1++ = 0X70;                    /* priority / segmentation */
  if (iml1 <= (127 - 4)) {          /* length in one byte      */
    *achl1++ = (unsigned char) (iml1 + 4);
  } else {
    m_put_be2( achl1, iml1 + 4 );
    *achl1 |= 0X80;            /* length in two bytes     */
    achl1 += 2;
  }
  m_put_le2(achl1, 0X80); /* encyption flags: licensing encryption */
  achl1 += 2;
  m_put_le2(achl1, 0X00); /* padding */
  achl1 += 2;

// to-do 20.04.12 KB - == TRUE should not be used, unsafe and slow
  if(bo_new_license == TRUE){
    /* Client New License Request */
    *achl1++ = 0x13; /* type */
  } else {
    /* Client License Info */
    *achl1++ = 0x12; /* type */
  }

  *achl1++ = D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers;      /* version 2 or 3, and maybe flag 0x80 */
  m_put_le2( achl1, iml1 ); /* len */
  achl1 += 2;
  m_put_le4( achl1, D_ADSL_RCO1->adsc_lic_neg->imc_lic_pkea );
  achl1 += 4;
  m_put_le4( achl1, D_ADSL_RCO1->adsc_lic_neg->imc_lic_platform );
  achl1 += 4;
  memcpy( achl1, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand, sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand) );
  achl1 += sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand);
  m_put_le2( achl1, D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_type);
  achl1 += 2;
  m_put_le2( achl1, ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key + 8 );
  achl1 += 2;
  achl2 = achl1 + ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key + 8;
  while (iml3) {   /* copy re-encrypted lic. premaster BE -> LE */
    *achl1++ = chr_work_1[--iml3];
  }
  memset( achl1, 0, achl2 - achl1 );
  achl1 = achl2;
    
  if (bo_new_license != FALSE) {
    /* Client New License Request */
    /* user name */
    m_put_le2( achl1, 0x000F); /* BB_CLIENT_USER_NAME_BLOB */
    achl1 += 2;
    iml2 = strlen(chr_work_2);
    m_put_le2( achl1, iml2 + 1);   /* write len of username */
    achl1 += 2;
    memcpy(achl1, chr_work_2, iml2); /* copy username */
    achl1 += iml2;
    *achl1++ = 0; /* mark end of string */
    
    /* computer name */
    m_put_le2( achl1, 0x0010); /* B_CLIENT_MACHINE_NAME_BLOB */
    achl1 += 2;
    iml2 = strlen(D_ADSL_RCO1->achc_machine_name);
    m_put_le2( achl1, iml2 + 1);   /* write len of username */
    achl1 += 2;
    memcpy(achl1, D_ADSL_RCO1->achc_machine_name, iml2); /* copy username */
    achl1 += iml2;
    *achl1++ = 0; /* mark end of string */

  } else {
     /* Client License Info */
     /* License Info */
     m_put_le2( achl1, 0x0001 );
     achl1 += 2;
     m_put_le2( achl1, dsc_cc_pass_license->imc_len_content );
     achl1 += 2;
     iml4 = dsc_cc_pass_license->imc_len_content;
     while(true){
       iml5 = adsp_output_area_1->achc_upper - achl1;
       if(iml5 > iml4) iml5 = iml4;
       memcpy( achl1, dsc_cc_pass_license->achc_content, iml5 );
       achl1 += iml5;
       iml4 -= iml5;
       if(iml4 == 0)
         break;

       // new Workarea needed.
       ads_gather->achc_ginp_end = achl1; // End of old gather
       iml6 += achl1 - achl4;
       memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
       bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                          DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                          &dsl_aux_get_workarea,
                                          sizeof(struct dsd_aux_get_workarea) );
       if (bol1 == FALSE) {           /* aux returned error      */
         adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
         exit(1);           /* UUU right error handling missing          */
       }
       adsp_output_area_1->achc_lower = dsl_aux_get_workarea.achc_work_area;
       adsp_output_area_1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
       adsp_output_area_1->achc_upper -= sizeof(dsd_gather_i_1);
       ads_gather = (dsd_gather_i_1*) adsp_output_area_1->achc_upper;
       ads_gather->adsc_next = NULL;
       achl1 = adsp_output_area_1->achc_lower;
       achl4 = achl1;
       ads_gather->achc_ginp_cur = achl1;

       *adsp_output_area_1->aadsc_gai1_out_to_server = ads_gather;  /* output data to server */
       adsp_output_area_1->aadsc_gai1_out_to_server = &ads_gather->adsc_next;  /* new chain output data to server */

     }
     /* EncryptedHWID + Hash */
#define ACHL_WORK_SHA1 ((int *) chr_work_2)
#define ACHL_WORK_MD5 ((int *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int)))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
#define ACHL_WORK_CHLL ((char *) ACHL_WORK_UTIL_01 + 20)
#define ACHL_WORK_RC4 ACHL_WORK_CHLL + 20

    // EncryptedHWID
    m_put_le2( achl1, 0x0009 );
    achl1 += 2;
    m_put_le2( achl1, 0x14);
    achl1 += 0x2;

    achl2 = ACHL_WORK_CHLL; /* Start to write Data on workarea. */
    m_put_le4( achl2, D_ADSL_RCO1->imc_platform_id);
    achl2 += 4;
//  memcpy( achl2, D_ADSL_RCO1->chrc_client_hardware_data, 0x10); /* Data-fields of client hardware identification */
//  achl2 += 0x10;
    memcpy( achl2, D_ADSL_RCO1->chrc_client_hardware_data, sizeof(D_ADSL_RCO1->chrc_client_hardware_data) ); /* Data-fields of client hardware identification */
    achl2 += sizeof(D_ADSL_RCO1->chrc_client_hardware_data);
    /* encrypt data -> JWT initializes the state before every call of RC4. */
    memcpy( ACHL_WORK_RC4, D_ADSL_RCO1->adsc_lic_neg->chrc_rc4_state_cl2se, RC4_STATE_SIZE );
    RC4( ACHL_WORK_CHLL, 0, 4 + 0x10,
         achl1, 0, ACHL_WORK_RC4);
    achl1 += 4 + 0X10;
    /* calculate the hash                            */
    /* JWT initializes the state of SHA1 and MD5 before every call! */
    iml1 = 4 + 0X10;
    memcpy( ACHL_WORK_SHA1,
            D_ADSL_RCO1->adsc_lic_neg->imrc_sha1_state,
            sizeof(D_ADSL_RCO1->adsc_lic_neg->imrc_sha1_state) );
    memcpy( ACHL_WORK_MD5,
            D_ADSL_RCO1->adsc_lic_neg->imrc_md5_state,
            sizeof(D_ADSL_RCO1->adsc_lic_neg->imrc_md5_state) );
    m_put_le4( ACHL_WORK_UTIL_01, iml1 );
    SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
    SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_CHLL, 0, iml1 );
    SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );

    MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
    MD5_Final( ACHL_WORK_MD5, achl1, 0 );
    achl1 += 0X10;

#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
#undef ACHL_WORK_CHLL
#undef ACHL_WORK_RC4
  }

  m_put_be2(achl3 + 2, (achl1 - achl4) + iml6);
  ads_gather->achc_ginp_end = achl1;
  D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */

  return TRUE;
} /* end m_send_cl2se_license()                                   */


/* draw bitmap, send to server                                         */

static BOOL m_send_vch_tose( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
                             struct dsd_output_area_1 *adsp_output_area_1,
                             struct dsd_rdp_vch_io *adsp_sc_vch_out,
                             char *achp_work ) {
   int        iml1, iml2;                   /* working-variables       */
   BOOL       bol1;                         /* working variable        */
// char       *achl1;                       /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   BOOL       bol_compressed;               /* compress output         */
   char       *achl_out_1;                  /* output-area             */
   char       *achl_out_start;              /* start of output-area    */
   int        iml_out_len;                  /* length output           */
   struct dsd_gather_i_1 *adsl_gai1_out_save;  /* output data          */
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_rdp_client_1 *D_ADSL_RCL1;
   struct dsd_rdp_co_client *D_ADSL_RCO1;  /* RDP communication server */
   struct dsd_output_area_1 *ADSL_OA1;
#endif
    int iml_security_header_len;
    int iml_size_hash;
    switch (adsp_hl_clib_1->adsc_rdp_co->imc_sec_method){
    case 0x00: // ENCRYPTION_METHOD_NONE
        iml_security_header_len = 0;
        iml_size_hash = 0;
        break;
    case 0x01: // ENCRYPTION_METHOD_40BIT
    case 0x02: // ENCRYPTION_METHOD_128BIT
    case 0x08: // ENCRYPTION_METHOD_56BIT
        iml_security_header_len = 4;
        iml_size_hash = D_SIZE_HASH;
        break;
    case 0x10: // ENCRYPTION_METHOD_FIPS // Not supported
    default:
        m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_vch_tose() illogic - Encryption method not supported - %d/0x%X",
                     __LINE__, 52354, 
                     adsp_hl_clib_1->adsc_rdp_co->imc_sec_method, adsp_hl_clib_1->adsc_rdp_co->imc_sec_method);  /* line number for errors */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
        return FALSE; 
   }
#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#define D_ADSL_RCL1 (&ADSL_RDPA_F->dsc_rdp_cl_1)
#define D_ADSL_RCO1 (&D_ADSL_RCL1->dsc_rdp_co_1)
#define ADSL_OA1 adsp_output_area_1
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
   D_ADSL_RCL1 = &ADSL_RDPA_F->dsc_rdp_cl_1;
   D_ADSL_RCO1 = &D_ADSL_RCL1->dsc_rdp_co_1;
   ADSL_OA1 = adsp_output_area_1;
#endif
   bol_compressed = FALSE;                  /* compress output         */
   if ((adsp_sc_vch_out->adsc_rdp_vc_1->imc_flags & CHANNEL_OPTION_COMPRESS) 
       || ((adsp_sc_vch_out->adsc_rdp_vc_1->imc_flags & CHANNEL_OPTION_COMPRESS_RDP) && (D_ADSL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA))
       ){
           bol_compressed = TRUE;
   }
   if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < 128) {  /* get new area */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error      */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       return FALSE;                        /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_vch_tose() illogic",
                   __LINE__, 52409);  /* line number for errors */
     return FALSE;                          /* program illogic         */
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
   adsl_gai1_out_save = ADSL_GAI1_OUT_G;    /* save start output data  */
   /* compute where to start output                                    */
   achl_out_1 = ADSL_OA1->achc_lower 
                + 4                         // TPKT Header
                + sizeof(ucrs_x224_p01)     // X.224 Data TDPDU
                + 1 + 2 + 2 + 1 + 2 
                + iml_security_header_len   // TS_SECURITY_HEADER::flags + TS_SECURITY_HEADER::flagsHi
                + iml_size_hash             // TS_SECURITY_HEADER::dataSignature
                + 4                         // CHANNEL_PDU_HEADER::length
                + 2 + 2;                    // CHANNEL_PDU_HEADER::flags
#undef ADSL_GAI1_OUT_G
   achl_out_start = achl_out_1;             /* save position start output */
   adsl_gai1_w1 = adsp_sc_vch_out->adsc_gai1_data;  /* output data     */
   iml_out_len = 0;                         /* clear length output     */
   memset( achl_out_1 - 2, 0, 2 );          /* clear compression flags */
   if (adsl_gai1_w1 == NULL) {              /* no data to send         */
     goto psend_vch_20;                     /* output finished         */
   }
   if (bol_compressed) goto psend_vch_08;   /* send virtual channel data compressed */
   while (TRUE) {
     iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     if (iml1 > (ADSL_OA1->achc_upper - achl_out_1)) iml1 = ADSL_OA1->achc_upper - achl_out_1;
     memcpy( achl_out_1, adsl_gai1_w1->achc_ginp_cur, iml1 );
     adsl_gai1_w1->achc_ginp_cur += iml1;
     achl_out_1 += iml1;
     iml_out_len += iml1;                   /* increment length output */
     if (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       if (adsl_gai1_w1 == NULL) {          /* already end of chain    */
         break;                             /* all data copied         */
       }
     }
     if (achl_out_1 < ADSL_OA1->achc_upper) continue;  /* still space in output-area */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set current end */
     /* get new block for more output                                  */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error        */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       return FALSE;                        /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
       m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_vch_tose() illogic",
                     __LINE__, 52469);  /* line number for errors */
       return FALSE;                        /* program illogic         */
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
     ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
   }
   goto psend_vch_20;                       /* output finished         */

   psend_vch_08:                            /* send virtual channel data compressed */
// to-do 21.02.12 KB - only copied - is correct ??? UUUU
   /* prepare gather input to be compressed                            */
   D_ADSL_RCO1->dsc_cdrf_enc.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_RCO1->dsc_cdrf_enc.amc_aux = adsp_hl_clib_1->amc_aux;
   D_ADSL_RCO1->dsc_cdrf_enc.adsc_gai1_in = adsl_gai1_w1;  /* input data */
   D_ADSL_RCO1->dsc_cdrf_enc.boc_mp_flush = TRUE;  /* end-of-record input */
   D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur = achl_out_1;  /* current end of output data */
   D_ADSL_RCO1->dsc_cdrf_enc.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
   while (TRUE) {                           /* loop over gather input  */
     D_ADSL_RCO1->amc_cdr_enc( &D_ADSL_RCO1->dsc_cdrf_enc );
     if (D_ADSL_RCO1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {
       m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d compression error %d.",
                     __LINE__, 52511,  /* line number for errors */
                     D_ADSL_RCO1->dsc_cdrf_enc.imc_return );
       return FALSE;                        /* do cleanup now          */
     }
     iml_out_len += D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur - achl_out_1;
     achl_out_1 = D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur;  /* set end of output */
     if (D_ADSL_RCO1->dsc_cdrf_enc.boc_sr_flush) break;  /* end-of-record output */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set current end */

     /* get new block for more output                                  */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error      */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       return FALSE;                        /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
       return FALSE;                        /* program illogic         */
     }
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
    #define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = achl_out_1;
     *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
     ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
    #undef ADSL_GAI1_OUT_G
     D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur = achl_out_1;  /* current end of output data */
     D_ADSL_RCO1->dsc_cdrf_enc.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
   }
   *(achl_out_start - 2) = D_ADSL_RCO1->dsc_cdrf_enc.chrc_header[ 0 ];  /* copy compression header */
   *(achl_out_start - 1) = 0;               /* second byte compression header */

   psend_vch_20:                            /* output finished         */
   ADSL_OA1->achc_lower = ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set end of block */
   /* make header of output                                            */
   // Write CHANNEL_PDU_HEADER:
   achl_out_start -= 4 + 2 + 2;             /* length uncompressed, segmentation flags and compression flags */
   m_put_le4( achl_out_start, adsp_sc_vch_out->umc_vch_ulen );
   memcpy( achl_out_start + 4, adsp_sc_vch_out->chrc_vch_flags, 2 );
   iml_out_len += 4 + 4;                    /* add length output       */
   if(D_ADSL_RCO1->imc_sec_level == 0){
      goto LBL_SEND_VCH_DATA_UNENCRYPTED;
   }
   if ((ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent & (4096 - 1)) == 0){
     if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent) {
       m_update_keys( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se, NULL );
     }
   }
// 25.04.12 KB - send virtual channel always encrypted to server
   {
     /* generate random                                                */
#define ACHL_WORK_SHA1 ((int *) achp_work)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
     memcpy( ACHL_WORK_SHA1,
             ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
     memcpy( ACHL_WORK_MD5,
             ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
     m_put_le4( ACHL_WORK_UTIL_01, iml_out_len );
     SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     adsl_gai1_out_save->achc_ginp_cur = achl_out_start;
     adsl_gai1_w1 = adsl_gai1_out_save;
     iml2 = iml_out_len;                    /* get length output       */
     while (TRUE) {                         /* loop over all gather structures input */
       iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       if (iml1 > iml2) {
         iml1 = iml2;                       /* only data in this frame */
       }
       SHA1_Update( ACHL_WORK_SHA1,
                    adsl_gai1_w1->achc_ginp_cur,
                    0, iml1 );
       RC4( adsl_gai1_w1->achc_ginp_cur, 0, iml1,
            adsl_gai1_w1->achc_ginp_cur, 0,
            ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
       iml2 -= iml1;                        /* subtract data processed */
       if (iml2 <= 0) break;                /* all data processed      */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather     */
       if (adsl_gai1_w1 == NULL) {          /* already end of chain    */
         return FALSE;                      /* program illogic         */
       }
     }
//   if (D_ADSL_RCL1->chc_prot_rt03 & 0X08) {  /* flag for block count */
       m_put_le4( ACHL_WORK_UTIL_01, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
//   }
     SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
     MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
     MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
     achl_out_start -= D_SIZE_HASH;         /* subtract length hash    */
     memcpy( achl_out_start, ACHL_WORK_UTIL_01, D_SIZE_HASH );
     iml_out_len += D_SIZE_HASH;            /* add length hash         */
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
     ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
   }
LBL_SEND_VCH_DATA_UNENCRYPTED:
   achl_out_start -= 1;
   if(D_ADSL_RCO1->imc_sec_level != 0){
       achl_out_start -= 2 + 2;             /* length length, fl2, fl3, padding */
       // 25.04.12 KB - send virtual channel always encrypted to server
       {
          *(achl_out_start + 1 + 0) = 0X08;
          *(achl_out_start + 1 + 1) = 0X08;
       }
       /* two bytes padding zero                                           */
       *(achl_out_start + 1 + 2 + 0) = 0;
       *(achl_out_start + 1 + 2 + 1) = 0;
       iml_out_len += 4;                        /* add length header       */
   }
   *achl_out_start = (unsigned char) iml_out_len;  /* one byte length  */
   if (iml_out_len >= 0X0080) {             /* length in two bytes     */
     achl_out_start--;                      /* space for second byte   */
     m_put_be2( achl_out_start, iml_out_len );
     *achl_out_start |= 0X80;               /* flag length two bytes   */
     iml_out_len += 1;                      /* increment length        */
   }
   achl_out_start -= 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1;
   iml_out_len += 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1 + 1;
   adsl_gai1_out_save->achc_ginp_cur = achl_out_start;
   *achl_out_start = DEF_CONST_RDP_03;
   *(achl_out_start + 1) = 0;               /* second byte zero        */
   m_put_be2( achl_out_start + 2, iml_out_len );
   memcpy( achl_out_start + 4,
           ucrs_x224_p01,
           sizeof(ucrs_x224_p01) );
// *(achl_out_start + 4 + sizeof(ucrs_x224_p01)) = 0X68;  /* Send Data Indication */
   *(achl_out_start + 4 + sizeof(ucrs_x224_p01)) = 0X64;  /* Send Data Indication */
   m_put_be2( achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1, D_ADSL_RCO1->usc_userid_cl2se );
   m_put_be2( achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1 + 2, adsp_sc_vch_out->adsc_rdp_vc_1->usc_vch_no );
// *(achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2) = 0XF0;  /* priority / segmentation */
   *(achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2) = (unsigned char) 0X70;  /* priority / segmentation */
   return TRUE;                             /* all done                */
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RCL1
#undef D_ADSL_RCO1
#undef ADSL_OA1
#undef ADSL_RDPA_F
#endif
} /* end m_send_vch_tose()                                             */
static BOOL m_send_mcs_msgchannel_tose( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
                             struct dsd_output_area_1 *adsp_output_area_1,
                             struct dsd_rdp_mcs_msgchannel_io *adsp_mcs_msgchannel_out,
                             char *achp_work ) {
   int        iml1, iml2;                   /* working-variables       */
   BOOL       bol1;                         /* working variable        */
// char       *achl1;                       /* working variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   BOOL       bol_compressed;               /* compress output         */
   char       *achl_out_1;                  /* output-area             */
   char       *achl_out_start;              /* start of output-area    */
   int        iml_out_len;                  /* length output           */
   struct dsd_gather_i_1 *adsl_gai1_out_save;  /* output data          */
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_rdp_client_1 *D_ADSL_RCL1;
   struct dsd_rdp_co_client *D_ADSL_RCO1;  /* RDP communication server */
   struct dsd_output_area_1 *ADSL_OA1;
#endif
    int iml_security_header_len;
    int iml_size_hash;
    // This type of PDU has a Basic Security Header when ENCRYPTION_LEVEL_NONE (and ENCRYPTION_METHOD_NONE); 
    //      a FIPS Security Header when ENCRYPTION_METHOD_FIPS; and a Non-FIPS Security Header otherwhise.
    switch (adsp_hl_clib_1->adsc_rdp_co->imc_sec_method){
    case 0x00: // ENCRYPTION_METHOD_NONE
        iml_security_header_len = 4;
        iml_size_hash = 0;
        break;
    case 0x01: // ENCRYPTION_METHOD_40BIT
    case 0x02: // ENCRYPTION_METHOD_128BIT
    case 0x08: // ENCRYPTION_METHOD_56BIT
        iml_security_header_len = 4;
        iml_size_hash = D_SIZE_HASH;
        break;
    case 0x10: // ENCRYPTION_METHOD_FIPS // Not supported
    default:
        m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_mcs_msgchannel_tose() illogic - Encryption method not supported - %d/0x%X",
                     __LINE__, 50728, 
                     adsp_hl_clib_1->adsc_rdp_co->imc_sec_method, adsp_hl_clib_1->adsc_rdp_co->imc_sec_method);  /* line number for errors */
        adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
        return FALSE; 
   }
#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#define D_ADSL_RCL1 (&ADSL_RDPA_F->dsc_rdp_cl_1)
#define D_ADSL_RCO1 (&D_ADSL_RCL1->dsc_rdp_co_1)
#define ADSL_OA1 adsp_output_area_1
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
   D_ADSL_RCL1 = &ADSL_RDPA_F->dsc_rdp_cl_1;
   D_ADSL_RCO1 = &D_ADSL_RCL1->dsc_rdp_co_1;
   ADSL_OA1 = adsp_output_area_1;
#endif
   if (adsp_mcs_msgchannel_out->adsc_gai1_data == NULL) {
      // Over the MCS MSGCHannel there are no PDUs without payload!
      return FALSE;
   }
   bol1 = m_ensure_wa_size(adsp_hl_clib_1, ADSL_OA1, 128);
   if (bol1 == FALSE){
       return FALSE;
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_mcs_msgchannel_tose() illogic",
                   __LINE__, 50783);  /* line number for errors */
     return FALSE;                          /* program illogic         */
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
     ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
     adsl_gai1_out_save = ADSL_GAI1_OUT_G;
#undef ADSL_GAI1_OUT_G

   /* compute where to start output                                    */
   achl_out_1 = ADSL_OA1->achc_lower 
                + 4                         // TPKT Header
                + sizeof(ucrs_x224_p01)     // X.224 Data TDPDU
                + 1 + 2 + 2 + 1 + 2 
                + iml_security_header_len   // TS_SECURITY_HEADER::flags + TS_SECURITY_HEADER::flagsHi
                + iml_size_hash;            // TS_SECURITY_HEADER::dataSignature
   achl_out_start = achl_out_1;             /* save position start output */
   adsl_gai1_w1 = adsp_mcs_msgchannel_out->adsc_gai1_data;  /* output data     */
   iml_out_len = 0;                         /* clear length output     */

   while (TRUE) {
     iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
     if (iml1 > (ADSL_OA1->achc_upper - achl_out_1)) iml1 = ADSL_OA1->achc_upper - achl_out_1;
     memcpy( achl_out_1, adsl_gai1_w1->achc_ginp_cur, iml1 );
     adsl_gai1_w1->achc_ginp_cur += iml1;
     achl_out_1 += iml1;
     iml_out_len += iml1;                   /* increment length output */
     if (adsl_gai1_w1->achc_ginp_cur >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       if (adsl_gai1_w1 == NULL) {          /* already end of chain    */
         break;                             /* all data copied         */
       }
     }
     if (achl_out_1 < ADSL_OA1->achc_upper) continue;  /* still space in output-area */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set current end */
     /* get new block for more output                                  */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error        */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       return FALSE;                        /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
       m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_mcs_msgchannel_tose() illogic",
                     __LINE__, 50843);  /* line number for errors */
       return FALSE;                        /* program illogic         */
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
     ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
   }
   ADSL_OA1->achc_lower = ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set end of block */

   if(D_ADSL_RCO1->imc_sec_level == 0){
      goto LBL_SEND_DATA_UNENCRYPTED;
   }
   if ((ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent & (4096 - 1)) == 0){
     if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent) {
       m_update_keys( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se, NULL );
     }
   }
   {
     /* generate random                                                */
#define ACHL_WORK_SHA1 ((int *) achp_work)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
     memcpy( ACHL_WORK_SHA1,
             ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
     memcpy( ACHL_WORK_MD5,
             ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
     m_put_le4( ACHL_WORK_UTIL_01, iml_out_len );
     SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     adsl_gai1_out_save->achc_ginp_cur = achl_out_start;
     adsl_gai1_w1 = adsl_gai1_out_save;
     iml2 = iml_out_len;                    /* get length output       */
     while (TRUE) {                         /* loop over all gather structures input */
       iml1 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       if (iml1 > iml2) {
         iml1 = iml2;                       /* only data in this frame */
       }
       SHA1_Update( ACHL_WORK_SHA1,
                    adsl_gai1_w1->achc_ginp_cur,
                    0, iml1 );
       RC4( adsl_gai1_w1->achc_ginp_cur, 0, iml1,
            adsl_gai1_w1->achc_ginp_cur, 0,
            ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
       iml2 -= iml1;                        /* subtract data processed */
       if (iml2 <= 0) break;                /* all data processed      */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather     */
       if (adsl_gai1_w1 == NULL) {          /* already end of chain    */
         return FALSE;                      /* program illogic         */
       }
     }
//   if (D_ADSL_RCL1->chc_prot_rt03 & 0X08) {  /* flag for block count */
       m_put_le4( ACHL_WORK_UTIL_01, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
//   }
     SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
     MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
     MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
     achl_out_start -= D_SIZE_HASH;         /* subtract length hash    */
     memcpy( achl_out_start, ACHL_WORK_UTIL_01, D_SIZE_HASH );
     iml_out_len += D_SIZE_HASH;            /* add length hash         */
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
     ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
   }

LBL_SEND_DATA_UNENCRYPTED:
   achl_out_start -= (1 + iml_security_header_len);
   
   if(D_ADSL_RCO1->imc_sec_level != 0){
       *(achl_out_start + 1 + 0) = SEC_ENCRYPT;
       *(achl_out_start + 1 + 1) = (SEC_SECURE_CHECKSUM >> 8);
       /* two bytes padding zero                                           */
   }
   switch(adsp_mcs_msgchannel_out->iec_rmms){
   case ied_rmms_network_characteristics_detection:
       *(achl_out_start + 1 + 1) = (SEC_AUTODETECT_RSP >> 8);
       break;
   case ied_rmms_connection_health_monitoring:
       // No client to server messages possible in this case!
   default:
       return FALSE;
   }
   *(achl_out_start + 1 + 2 + 0) = 0;
   *(achl_out_start + 1 + 2 + 1) = 0;
   iml_out_len += 4;                        /* add length header       */

   *achl_out_start = (unsigned char) iml_out_len;  /* one byte length  */
   if (iml_out_len >= 0X0080) {             /* length in two bytes     */
     achl_out_start--;                      /* space for second byte   */
     m_put_be2( achl_out_start, iml_out_len );
     *achl_out_start |= 0X80;               /* flag length two bytes   */
     iml_out_len += 1;                      /* increment length        */
   }
   achl_out_start -= 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1;
   iml_out_len += 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1 + 1;

   adsl_gai1_out_save->achc_ginp_cur = achl_out_start;
   *achl_out_start = DEF_CONST_RDP_03;
   *(achl_out_start + 1) = 0;               /* second byte zero        */
   m_put_be2( achl_out_start + 2, iml_out_len );
   memcpy( achl_out_start + 4,
           ucrs_x224_p01,
           sizeof(ucrs_x224_p01) );
   *(achl_out_start + 4 + sizeof(ucrs_x224_p01)) = 0X64;  /* Send Data Indication */
   m_put_be2(achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1, D_ADSL_RCO1->usc_userid_cl2se);
   m_put_be2(achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1 + 2, D_ADSL_RCO1->usc_chno_mcs_msgchannel);
   *(achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2) = (unsigned char) 0X70;  /* priority / segmentation */
   return TRUE;                             /* all done                */
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RCL1
#undef D_ADSL_RCO1
#undef ADSL_OA1
#undef ADSL_RDPA_F
#endif
} /* end m_send_mcs_msgchannel_tose()                                             */

/* compute position in array chrc_glyph_cache                          */
static inline int m_pos_array_glyph( int *aimp_len, int imp_id, int imp_index ) {
   if (imp_index > 254) return -1;
   switch (imp_id) {
     case 0:
       *aimp_len = 4;
       return (imp_index << 2);
     case 1:
       *aimp_len = 4;
       return (254 * 4 + (imp_index << 2));
     case 2:
       *aimp_len = 8;
       return (2 * 254 * 4 + (imp_index << 3));
     case 3:
       *aimp_len = 8;
       return (2 * 254 * 4 + 254 * 8 + (imp_index << 3));
     case 4:
       *aimp_len = 16;
       return (2 * 254 * 4 + 2 * 254 * 8 + (imp_index << 4));
     case 5:
       *aimp_len = 32;
       return (2 * 254 * 4 + 2 * 254 * 8 + 254 * 16 + (imp_index << 5));
     case 6:
       *aimp_len = 64;
       return (2 * 254 * 4 + 2 * 254 * 8 + 254 * 16 + 254 * 32
                 + (imp_index << 6));
     case 7:
       *aimp_len = 128;
       return (2 * 254 * 4 + 2 * 254 * 8 + 254 * 16
                 + 254 * 32 + 254 * 64
                 + (imp_index << 7));
     case 8:
       *aimp_len = 256;
       return (2 * 254 * 4 + 2 * 254 * 8 + 254 * 16
                 + 254 * 32 + 254 * 64 + 254 * 128
                 + (imp_index << 8));
     case 9:
       *aimp_len = 2048;
       return (2 * 254 * 4 + 2 * 254 * 8 + 254 * 16
                 + 254 * 32 + 254 * 64 + 254 * 128 + 254 * 256
                 + (imp_index << 11));
   }
   return -1;                               /* return error            */
} /* end m_pos_array_glyph()                                           */

/* input two bytes little endian                                       */
static inline short int m_get_le2( char *achp_source ) {
   return *((short int *) achp_source);
}

/* input four bytes little endian                                      */
static inline int m_get_le4( char *achp_source ) {
   return *((int *) achp_source);
}

/* output two bytes little endian                                      */
static inline void m_put_le2( char *achp_target, int inp1 ) {
   *((unsigned short int *) achp_target) = (unsigned short int) inp1;
}

/* output four bytes little endian                                     */
static inline void m_put_le4( char *achp_target, int inp1 ) {
   *((unsigned int *) achp_target) = (unsigned int) inp1;
}

/* output two bytes big endian                                         */
#define GHHW(str) ((unsigned short int) ((str & 0X00FF) << 8) \
        | ((str >> 8) & 0X00FF))
static inline void m_put_be2( char *achp_target, int inp1 ) {
   *((unsigned short int *) achp_target) = GHHW( inp1 );
}

#ifdef D_CONSOLE_OUT
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
   fflush( stdout );
} /* end m_console_out()                                            */
#endif


/* subroutine for output to console                                    */
static int m_sdh_printf( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1, const char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = vsnprintf( chrl_out1, sizeof(chrl_out1), achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                      DEF_AUX_CONSOLE_OUT,  /* output to console */
                                      chrl_out1, iml1 );
   return iml1;
} /* end m_sdh_printf()                                                */

/* subroutine to dump storage-content to console                       */
static void m_sdh_console_out( struct dsd_call_wt_rdp_client_1 *adsp_hl_clib_1,
                               char *achp_buff, int implength ) {
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
     m_sdh_printf( adsp_hl_clib_1, "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_sdh_console_out()                                           */


static const char * m_ret_t_ied_fsfp_bl( ied_fsfp_bl iel_fsfp_bl ) {
   switch (iel_fsfp_bl) {
     case ied_fsfp_invalid:                 /* invalid data received   */
       return "ied_fsfp_invalid";
     case ied_fsfp_constant:                /* is in constant          */
       return "ied_fsfp_constant";
     case ied_fsfp_status:                  /* status from server      */
       return "ied_fsfp_status";
     case ied_fsfp_x224_p01:                /* is in x224 header       */
       return "ied_fsfp_x224_p01";
     case ied_fsfp_ignore:                  /* ignore data             */
       return "ied_fsfp_ignore";
     case ied_fsfp_copy:                    /* copy data               */
       return "ied_fsfp_copy";
     case ied_fsfp_rec_type:                /* receive record type     */
       return "ied_fsfp_rec_type";
     case ied_fsfp_byte01:                  /* receive byte 01         */
       return "ied_fsfp_byte01";
     case ied_fsfp_lencons_2:               /* two bytes length remain */
       return "ied_fsfp_lencons_2";
     case ied_fsfp_lencons_1:               /* one byte length remains */
       return "ied_fsfp_lencons_1";
     case ied_fsfp_mcs_c1:                  /* x224 MCS command 1      */
       return "ied_fsfp_mcs_c1";
     case ied_fsfp_mcs_c2:                  /* x224 MCS command 2      */
       return "ied_fsfp_mcs_c2";
     case ied_fsfp_userid_se2cl:            /* userid server to client */
       return "ied_fsfp_userid_se2cl";
     case ied_fsfp_userid_cl2se:            /* userid client to server */
       return "ied_fsfp_userid_cl2se";
     case ied_fsfp_chno:                    /* channel number          */
       return "ied_fsfp_chno";
     case ied_fsfp_prio_seg:                /* Priority / Segmentation */
       return "ied_fsfp_prio_seg";
     case ied_fsfp_rt02:                    /* record type 2           */
       return "ied_fsfp_rt02";
     case ied_fsfp_rt03:                    /* record type 3           */
       return "ied_fsfp_rt03";
     case ied_fsfp_padd_1:                  /* padding                 */
       return "ied_fsfp_padd_1";
     case ied_fsfp_rdp4_hash:               /* hash RDP4 block         */
       return "ied_fsfp_rdp4_hash";
     case ied_fsfp_sch_len:                 /* Share Control Header length */
       return "ied_fsfp_sch_len";
     case ied_fsfp_sch_pdu_type:            /* Share Control Header PDU type */
       return "ied_fsfp_sch_pdu_type";
     case ied_fsfp_sch_pdu_source:          /* Share Control Header PDU source */
       return "ied_fsfp_sch_pdu_source";
     case ied_fsfp_r04_rdp_v:               /* block 4 RDP version     */
       return "ied_fsfp_r04_rdp_v";
     case ied_fsfp_int_lit_e:               /* int little endian       */
       return "ied_fsfp_int_lit_e";
     case ied_fsfp_int_big_e:               /* int big endian          */
       return "ied_fsfp_int_big_e";
     case ied_fsfp_asn1_tag:                /* ASN.1 tag               */
       return "ied_fsfp_asn1_tag:";
     case ied_fsfp_asn1_l1_fi:              /* ASN.1 length field      */
       return "ied_fsfp_asn1_l1_fi";
     case ied_fsfp_asn1_l1_p2:              /* ASN.1 length part two   */
       return "ied_fsfp_asn1_l1_p2";
     case ied_fsfp_mu_len_1:                /* multi length 1          */
       return "ied_fsfp_mu_len_1";
     case ied_fsfp_mu_len_2:                /* multi length 2          */
       return "ied_fsfp_mu_len_2";
     case ied_fsfp_r5_len_1:                /* RDP 5 multi length 1    */
       return "ied_fsfp_r5_len_1";
     case ied_fsfp_r5_len_2:                /* RDP 5 multi length 2    */
       return "ied_fsfp_r5_len_2";
     case ied_fsfp_r5_hash:                 /* RDP 5 hash              */
       return "ied_fsfp_r5_hash";
     case ied_fsfp_r5_pdu_typ:              /* RDP 5 PDU type          */
       return "ied_fsfp_r5_pdu_typ";
     case ied_fsfp_r5_pdu_cofl:             /* RDP 5 compression flags */
       return "ied_fsfp_r5_pdu_cofl";
     case ied_fsfp_r5_pdu_len:              /* RDP 5 PDU length        */
       return "ied_fsfp_r5_pdu_len";
     case ied_fsfp_r5_pdu_compr:            /* RDP 5 PDU compressed    */
       return "ied_fsfp_r5_pdu_compr";
     case ied_fsfp_send_from_server:        /* send data to client     */
       return "ied_fsfp_send_from_server";
     case ied_fsfp_end_com:                 /* end of communication    */
       return "ied_fsfp_end_com";
     case ied_fsfp_no_session:              /* no more session         */
       return "ied_fsfp_no_session";
   }
   return "-undef-";
}  /* end m_ret_t_ied_fsfp_bl()                                        */


static const char * m_ret_t_ied_frse_bl( ied_frse_bl iel_frse_bl ) {
   switch (iel_frse_bl) {
     case ied_frse_start:                   /* start of communication  */
       return "ied_frse_start";
     case ied_frse_sta_02:                  /* start second field      */
       return "ied_frse_sta_02";
     case ied_frse_rec_04:                  /* receive block 4         */
       return "ied_frse_rec_04";
     case ied_frse_r04_asn1_1:              /* block 4 ASN-1 field 1   */
       return "ied_frse_r04_asn1_1";
     case ied_frse_r04_asn1_2:              /* block 4 ASN-1 field 2   */
       return "ied_frse_r04_asn1_2";
     case ied_frse_r04_asn1_3:              /* block 4 ASN-1 field 3   */
       return "ied_frse_r04_asn1_3";
     case ied_frse_r04_asn1_4:              /* block 4 ASN-1 field 4   */
       return "ied_frse_r04_asn1_4";
     case ied_frse_r04_sel_t:               /* block 4 selection tag   */
       return "ied_frse_r04_sel_t";
     case ied_frse_r04_sel_l:               /* block 4 selection length */
       return "ied_frse_r04_sel_l";
     case ied_frse_r04_rdp_v:               /* block 4 RDP version     */
       return "ied_frse_r04_rdp_v";
     case ied_frse_r04_ch_disp:             /* block 4 display channel */
       return "ied_frse_r04_ch_disp";
     case ied_frse_r04_vch_no:              /* block 4 no virtual channels */
       return "ied_frse_r04_vch_no";
     case ied_frse_r04_vch_var:             /* block 4 variable channel */
       return "ied_frse_r04_vch_var";
     case ied_frse_r04_vch_del:             /* block 4 vch delemiter   */
       return "ied_frse_r04_vch_del";
     case ied_frse_r04_sec_method:             /* block 4 security method */
       return "ied_frse_r04_sec_method";
     case ied_frse_r04_sec_level:           /* block 4 security level  */
       return "ied_frse_r04_sec_level";
     case ied_frse_r04_l_serv_rand:         /* block 4 length server random */
       return "ied_frse_r04_l_serv_rand";
     case ied_frse_r04_l_pub_par:           /* block 4 length public parameters */
       return "ied_frse_r04_l_pub_par";
     case ied_frse_r04_d_serv_rand:         /* block 4 data server random */
       return "ied_frse_r04_d_serv_rand";
     case ied_frse_r04_type_pub_par:        /* block 4 type public parameters */
       return "ied_frse_r04_type_pub_par";
     case ied_frse_r04_ppdir_tag:           /* block 4 public parms direct tag */
       return "ied_frse_r04_ppdir_tag";
     case ied_frse_r04_ppdir_len:           /* block 4 public parms direct lenght */
       return "ied_frse_r04_ppdir_len";
     case ied_frse_r04_d_pub_par:           /* block 4 data public parameters */
       return "ied_frse_r04_d_pub_par";
     case ied_frse_rec_07:                  /* receive block 7         */
       return "ied_frse_rec_07";
     case ied_frse_cjresp_rec:              /* receive block channel join response */
       return "ied_frse_cjresp_rec";
     case ied_frse_lic_pr_1_rec:            /* receive block licence protocol */
       return "ied_frse_lic_pr_1_rec";
     case ied_frse_lic_pr_type:             /* licencing block to check */
       return "ied_frse_lic_pr_type";
     case ied_frse_lic_pr_req_rand:         /* server license request random */
       return "ied_frse_lic_pr_req_rand";
     case ied_frse_lic_pr_req_cert:         /* server license request certificate */
       return "ied_frse_lic_pr_req_cert";
     case ied_frse_lic_pr_req_scopelist:    /* parse scopelist of server license request */
       return "ied_frse_lic_pr_req_scopelist";
     case ied_frse_lic_pr_chll:             /* platform challenge      */
       return "ied_frse_lic_pr_chll";
     case ied_frse_lic_pr_new_license:      /* new license or update license */
       return "ied_frse_lic_pr_new_license";
     case ied_frse_lic_pr_lic_error_mes1:   /* License Error Message */
       return "ied_frse_lic_pr_lic_error_mes1";
     case ied_frse_lic_pr_lic_error_mes2:   /* License Error Message */
       return "ied_frse_lic_pr_lic_error_mes2";
     case ied_frse_act_pdu_rec:             /* receive block active PDU */
       return "ied_frse_act_pdu_rec";
     case ied_frse_actpdu_parse_shareid:    /* parse shareid           */
       return "ied_frse_actpdu_parse_shareid";
     case ied_frse_actpdu_sdl:              /* get source descriptor length */
       return "ied_frse_actpdu_sdl";
     case ied_frse_actpdu_len_cap:          /* get length capabilities */
       return "ied_frse_actpdu_len_cap";
     case ied_frse_actpdu_no_cap:           /* get number capabilities */
       return "ied_frse_actpdu_no_cap";
     case ied_frse_actpdu_cap_ind:          /* get capabilities index  */
       return "ied_frse_actpdu_cap_ind";
     case ied_frse_actpdu_cap_len:          /* get capabilities length */
       return "ied_frse_actpdu_cap_len";
     case ied_frse_actpdu_trail:            /* trailer of act PDU      */
       return "ied_frse_actpdu_trail";
     case ied_frse_error_bl_01:             /* receive error block 01  */
       return"ied_frse_error_bl_01";
     case ied_frse_error_bl_02:             /* receive error block 02  */
       return"ied_frse_error_bl_02";
     case ied_frse_any_pdu_rec:             /* ????ive block active PDU */
       return "ied_frse_any_pdu_rec";
     case ied_frse_rdp4_vch_ulen:           /* virtual channel uncompressed data length */
       return "ied_frse_rdp4_vch_ulen";
     case ied_frse_r5_pdu_primord:          /* RDP 5 PDU primary order */
       return "ied_frse_r5_pdu_primord";
     case ied_frse_r5_pdu_apply_order:      /* RDP 5 PDU apply order   */
       return "ied_frse_r5_pdu_apply_order";
     case ied_frse_r5_ign_single_unic:      /* ignore one single Unicode character */
       return "ied_frse_r5_ign_single_unic";
     case ied_frse_r5_o01_brush_data:       /* RDP 5 order 1 brush data */
       return "ied_frse_r5_o01_brush_data";
     case ied_frse_r5_o0e_brush_data:       /* RDP 5 order 14 brush data */
       return "ied_frse_r5_o0e_brush_data";
     case ied_frse_xyz_end_pdu:             /* end of PDU              */
       return "ied_frse_xyz_end_pdu";
     case ied_frse_xyz_end_order:           /* end of order            */
       return "ied_frse_xyz_end_order";
     case ied_ad_inv_user_x:                /* userid invalid - not fo */
       return "ied_ad_inv_user_x";
     case ied_ad_inv_password_x:            /* password invalid        */
       return "ied_ad_inv_password_x";
   }
   return "-undef-";
}  /* end m_ret_t_ied_frse_bl()                                        */

static BOOL m_parse_server_redirection_packet(char* achp_curpos, struct dsd_se_switch_server* adsp_se_switch_server, unsigned int ump_max_len){
    unsigned int uml_pdu_flags;
    int iml_pdu_rem_len;
    char* achl_end_pos = achp_curpos + ump_max_len;

    if ((ump_max_len < 12) || (achp_curpos == NULL) || (adsp_se_switch_server == NULL)){
        // The server redirection packet is ate least 12bytes long
        return FALSE;
    }

    uml_pdu_flags = m_get_le2(achp_curpos);     // Flags field
    if (uml_pdu_flags != SEC_REDIRECTION_PKT){  // It can only be 0x04000, otherwise it is not the server redirection packet
        return FALSE;
    }
    achp_curpos += 2;

    iml_pdu_rem_len = m_get_le2(achp_curpos);   // Length field
    if (ump_max_len < iml_pdu_rem_len){         // It has to be less than the memory buffer we have been passed!
        return FALSE;
    }
    achp_curpos += 2;
    
    adsp_se_switch_server->umc_session_id = (unsigned int)m_get_le4(achp_curpos);
    achp_curpos += 4;
    adsp_se_switch_server->umc_redir_flags = (unsigned int)m_get_le4(achp_curpos);
    achp_curpos += 4;

    adsp_se_switch_server->boc_lb_dont_store_username = 
        ((adsp_se_switch_server->umc_redir_flags & LB_DONTSTOREUSERNAME) != 0) ? TRUE:FALSE;
    adsp_se_switch_server->boc_lb_smartcard_logon = 
        ((adsp_se_switch_server->umc_redir_flags & LB_SMARTCARD_LOGON) != 0) ? TRUE:FALSE;
    adsp_se_switch_server->boc_lb_no_redirect = 
        ((adsp_se_switch_server->umc_redir_flags & LB_NOREDIRECT) != 0) ? TRUE:FALSE;
    adsp_se_switch_server->boc_lb_server_tsv_capable = 
        ((adsp_se_switch_server->umc_redir_flags & LB_SERVER_TSV_CAPABLE) != 0) ? TRUE:FALSE;
    adsp_se_switch_server->boc_lb_password_is_pk_encrypted = 
        ((adsp_se_switch_server->umc_redir_flags & LB_PASSWORD_IS_PK_ENCRYPTED) != 0) ? TRUE:FALSE;
            
    // LB_TARGET_NET_ADDRESS:
    if (adsp_se_switch_server->umc_redir_flags & LB_TARGET_NET_ADDRESS){
        adsp_se_switch_server->umc_target_net_address_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_target_net_address = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_target_net_address_length;
    }
    // LB_LOAD_BALANCE_INFO:
    if (adsp_se_switch_server->umc_redir_flags & LB_LOAD_BALANCE_INFO){
        adsp_se_switch_server->umc_load_balance_info_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_load_balance_info = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_load_balance_info_length;
    }
    // LB_USERNAME:
    if (adsp_se_switch_server->umc_redir_flags & LB_USERNAME){
        adsp_se_switch_server->umc_username_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_username = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_username_length;
    }
    // LB_DOMAIN:
    if (adsp_se_switch_server->umc_redir_flags & LB_DOMAIN){
        adsp_se_switch_server->umc_domain_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_domain = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_domain_length;
    }
    // LB_PASSWORD:
    if (adsp_se_switch_server->umc_redir_flags & LB_PASSWORD){
        adsp_se_switch_server->umc_password_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_password = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_password_length;
    }
    // LB_TARGET_FQDN:
    if (adsp_se_switch_server->umc_redir_flags & LB_TARGET_FQDN){
        adsp_se_switch_server->umc_target_fqdn_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_target_fqdn = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_target_fqdn_length;
    }
    // LB_TARGET_NETBIOS_NAME:
    if (adsp_se_switch_server->umc_redir_flags & LB_TARGET_NETBIOS_NAME){
        adsp_se_switch_server->umc_target_netbios_name_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_target_netbios_name = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_target_netbios_name_length;
    }
    // LB_CLIENT_TSV_URL:
    if (adsp_se_switch_server->umc_redir_flags & LB_CLIENT_TSV_URL){
        adsp_se_switch_server->umc_tsv_url_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_tsv_url = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_tsv_url_length;
    }
    // LB_REDIRECTION_GUID:
    if (adsp_se_switch_server->umc_redir_flags & LB_REDIRECTION_GUID){
        adsp_se_switch_server->umc_redirection_guid_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_redirection_guid = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_redirection_guid_length;
    }
    // LB_TARGET_CERTIFICATE:
    if (adsp_se_switch_server->umc_redir_flags & LB_TARGET_CERTIFICATE){
        adsp_se_switch_server->umc_target_certificate_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_target_certificate = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_target_certificate_length;
    }
    // LB_TARGET_NET_ADDRESSES:
    if (adsp_se_switch_server->umc_redir_flags & LB_TARGET_NET_ADDRESSES){
        adsp_se_switch_server->umc_target_net_addresses_length = (unsigned int)m_get_le4(achp_curpos);
        achp_curpos += 4;
        adsp_se_switch_server->achc_target_net_addresses = achp_curpos;
        achp_curpos += adsp_se_switch_server->umc_target_net_addresses_length;
    }

    //imc_len_ineta = 
    //chrc_ineta

    if (achl_end_pos < achp_curpos) return FALSE; // We read beyond the end of the packet
    
    return TRUE;

} // End of m_parse_server_redirection_packet
