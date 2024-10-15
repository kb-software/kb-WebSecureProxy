// 2017.03.14 DD:
//  If you need to use the old HELP_DEBUG facilities, please uncomment the
//      HL_RDPACC_HELP_DEBUG definition.
// #define HL_RDPACC_HELP_DEBUG

//*SET TRY_120425_1=1;

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
#define TEMPSCR2                            /* 15.06.05 KB - send screen */
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
#include <string.h>
#ifndef HL_UNIX
#include <conio.h>
#endif
#include <time.h>
#ifndef HL_UNIX
#include <winsock2.h>
//#include <ws2tcpip.h>
#include <windows.h>
#else
//#include <unistd.h>
#include "hob-unix01.h"
#include <sys/socket.h>
#endif
#include "hob-cd-record-1.h"
#include <stdint.h>
#include "hob-encry-1.h"
/* pseudo-entry, cannot be used in Server-Data-Hook                    */
extern "C" int m_hl1_printf( char *aptext, ... ) {
   return 0;
} /* end m_hl1_printf()                                                */
#define DEF_HL_INCL_INET
#include "hob-xsclib01.h"
#include "hob-rdptracer1.h"
#include "hob-stor-sdh.h"
#include "hob-xsrdpvch1.h"

#ifndef HL_WCHAR
#ifndef HL_UNIX
#define HL_WCHAR WCHAR
#else
#define HL_WCHAR unsigned short int
#endif
#endif

#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */

#define D_AUX_STOR_SIZE      (32 * 1024)    /* size storage element    */
#define DEF_LEN_VIRTCH_STA   12
#define D_MAX_CRYPT_LEN      0X100
#define D_MAX_OFFSCR_DELETE  64             /* maximum indices in OFFSCR_DELETE_LIST */
#define D_MAX_BMC_MSTSC      32000          /* maximum length for bitmap compression */
#define D_MAX_OUT_BMC_MSTSC  4000           /* maximum output of bitmap compression */
#define D_USERID_SE2CL       1              /* userid from server to client */
#define D_USERID_CL2SE       8              /* userid from client to server */
#define D_DISPLAY_CHANNEL    0X03EB         /* default display channel */
#define D_EXTRA_CHANNEL      0X03E9         /* begin extra channels    */
#define D_R5_ORD_NO          32             /* RDP 5 maximum order number */
#define D_LEN_CLIENT_RAND    32             /* length client random    */
#define D_LEN_HMAC           64             /* length constants HMAC   */
#define CONST_DEV_BITMAP     13             /* ask Microsoft why shorten length is needed */
#define D_OFFSCR_B_NO        64             /* number of offscreen buffers */
#define D_CACHE_BMP_NO       3              /* number of Bitmap Cache Stages */
#define D_C_BMP_NO_0         0X78           /* Bitmap Cache Stages 0 entries */
#define D_C_BMP_NO_1         0X78           /* Bitmap Cache Stages 1 entries */
#define D_C_BMP_NO_2         0X1CE          /* Bitmap Cache Stages 2 entries */
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
#define D_SIZE_HASH          8              /* size of hash            */
#define D_DEMAND_ACT_PDU     0X11           /* demand active PDU       */
#define TS_DEACTIVATE_ALL_PDU 0X16          /* Deactivate All PDU Data */
#define PDUTYPE_DATAPDU      0X07           /* Data PDU                */
#define D_XYZ_ERROR          0X17           /* ??? 04.06.11 KB         */
#define PDUTYPE2_SYNCHRONIZE       0X1F     /* 31                      */
#define PDUTYPE2_REFRESH_RECT      0X21     /* 33                      */
#define PDUTYPE2_SUPPRESS_OUTPUT   0X23     /* 35                      */
#define PDUTYPE2_SHUTDOWN_REQUEST  0X24     /* 36                      */
#define PDUTYPE2_SAVE_SESSION_INFO 0X26     /* 38 - Save Session Info PDU (section 2.2.10.1.1) */
#define SYNCMSGTYPE_SYNC     1
#define RNS_UD_24BPP_SUPPORT              0X0001
#define RNS_UD_16BPP_SUPPORT              0X0002
#define RNS_UD_15BPP_SUPPORT              0X0004
#define RNS_UD_32BPP_SUPPORT              0X0008
#define RNS_UD_CS_SUPPORT_ERRINFO_PDU     0X0001
#define RNS_UD_CS_WANT_32BPP_SESSION      0X0002
#define RNS_UD_CS_STRONG_ASYMMETRIC_KEYS  0X0008
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
#define MAX_PDU_LEN          0X00004000
#define TS_CACHE_BITMAP_UNCOMPRESSED_REV2 0X04
#define TS_CACHE_BITMAP_COMPRESSED_REV2   0X05
#define TS_CACHE_GLYPH                    0X03
#define TS_ALTSEC_STREAM_BITMAP_FIRST     0X02
#define TS_ALTSEC_STREAM_BITMAP_NEXT      0X03
#define TS_ALTSEC_CREATE_NINEGRID_BITMAP  0X04
#define TS_ALTSEC_FRAME_MARKER            0X0D
#define STREAM_BITMAP_REV2                0X04
#define CBR2_HEIGHT_SAME_AS_WIDTH         0X01
#define CBR2_PERSISTENT_KEY_PRESENT       0X02
#define CBR2_NO_BITMAP_COMPRESSION_HDR    0X08
#define CBR2_DO_NOT_CACHE                 0X10
#define CBR3_DO_NOT_CACHE                 0X10
#define TS_PROTOCOL_VERSION               0X10
#define PDUTYPE_CONFIRMACTIVEPDU          0X03
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
#define M_ERROR_TOSE_ILLOGIC iml_line_no = __LINE__; goto ptose96;



/* get a piece of storage                                              */
/* end of macro M_MALLOC()                                             */

/* copy field structure dsd_rdp_co from server to client               */
/* end of macro M_COPY_CO1_SE2CL()                                     */


/* some cryptographical data mixing steps used in key generation       */
/* end of macro M_SALTHASH()                                           */

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

/* receive block from client, field position                           */
enum ied_fcfp_bl {
   ied_fcfp_invalid,                        /* invalid data received   */
   ied_fcfp_constant,                       /* is in constant          */
   ied_fcfp_x224_p01,                       /* is in x224 header       */
   ied_fcfp_ignore,                         /* ignore data             */
   ied_fcfp_copy_normal,                    /* copy data normal        */
   ied_fcfp_copy_invers,                    /* copy data invers        */
   ied_fcfp_copy_crlf,                      /* copy till <CR><LF> found */
   ied_fcfp_zero_cmp,                       /* compare zeroes          */
   ied_fcfp_rdp5_rc4,                       /* input RC4 encrypted     */
                   ied_fcfp_rec_type,       /* receive record type     */
                   ied_fcfp_byte01,         /* receive byte 01         */
                   ied_fcfp_lencons_2,      /* two bytes length remain */
                   ied_fcfp_lencons_1,      /* one byte length remains */
   ied_fcfp_r4_collect,                     /* RDP 4 collect data      */
   ied_fcfp_rdp5_len1,                      /* RDP5 input length 1     */
   ied_fcfp_rdp5_len2,                      /* RDP5 input length 2     */
   ied_fcfp_mcs_c1,                         /* x224 MCS command 1      */
   ied_fcfp_userid,                         /* userid communication    */
   ied_fcfp_chno,                           /* receive channel no      */
   ied_fcfp_prio_seg,                       /* Priority / Segmentation */
   ied_fcfp_rt02,                           /* record type 2           */
   ied_fcfp_rt03,                           /* record type 3           */
#ifdef NOT_VALID_060924
   ied_fcfp_rt04,                           /* record type 4           */
#endif
   ied_fcfp_padd_1,                         /* padding                 */
                   ied_fcfp_asn1_tag,       /* ASN.1 tag follows       */
                   ied_fcfp_asn1_l1_fi,     /* ASN.1 length field      */
                   ied_fcfp_asn1_l1_p2,     /* ASN.1 length part two   */
                   ied_fcfp_mu_len_1,       /* multi length 1          */
                   ied_fcfp_mu_len_2,       /* multi length 2          */
   ied_fcfp_int_lit_e,                      /* int little endian       */
   ied_fcfp_int_big_e,                      /* int big endian          */
   ied_fcfp_send_from_client,               /* send data to server     */
   ied_fcfp_end_com,                        /* end of communication    */
   ied_fcfp_no_session,                     /* no more session         */
   ied_fcfp_hext_b2,                        /* HOB-RDP-EXT1 byte 2     */
   ied_fcfp_hext_ctrl,                      /* HOB-RDP-EXT1 control character */
   ied_fcfp_hext_l_nhasn,                   /* HOB-RDP-EXT1 length NHASN */
                    ied_frclnv_usxx,        /* userid invalid - not fo */
                    ied_frclnv_pasxxord };  /* password invalid        */

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
   ied_fsfp_lenext_2,                       /* two bytes length remaining HOB-RDP-EXT1 */
   ied_fsfp_lenext_1,                       /* one byte length remaining HOB-RDP-EXT1 */
   ied_fsfp_r4_collect,                     /* RDP 4 collect data      */
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
   ied_fsfp_r04_rdp_v,                      /* block 4 RDP version     */
   ied_fsfp_int_lit_e,                      /* int little endian       */
   ied_fsfp_int_big_e,                      /* int big endian          */
   ied_fsfp_asn1_tag,                       /* ASN.1 tag               */
   ied_fsfp_asn1_l1_fi,                     /* ASN.1 length field      */
   ied_fsfp_asn1_l1_p2,                     /* ASN.1 length part two   */
   ied_fsfp_mu_len_1,                       /* multi length 1          */
   ied_fsfp_mu_len_2,                       /* multi length 2          */
   ied_fsfp_r5_len_1,                       /* RDP 5 multi length 1    */
   ied_fsfp_r5_len_2,                       /* RDP 5 multi length 2    */
   ied_fsfp_r5_collect,                     /* RDP 5 collect data      */
   ied_fsfp_r5_hash,                        /* RDP 5 hash              */
   ied_fsfp_r5_pdu_typ,                     /* RDP 5 PDU type          */
   ied_fsfp_r5_pdu_cofl,                    /* RDP 5 compression flags */
   ied_fsfp_r5_pdu_len,                     /* RDP 5 PDU length        */
   ied_fsfp_r5_pdu_compr,                   /* RDP 5 PDU compressed    */
   ied_fsfp_send_from_server,               /* send data to client     */
   ied_fsfp_end_com,                        /* end of communication    */
   ied_fsfp_no_session,                     /* no more session         */
#ifdef XYZ1
                   ied_fcfp_int_lit_e,      /* int little endian       */
                    ied_frclnv_usxx,        /* userid invalid - not fo */
#endif
                    ied_frclnvx_pasxxord };  /* password invalid        */

/* receive block from client, in block of type                         */
enum ied_frcl_bl { ied_frcl_start,          /* start of communication  */
   ied_frcl_sta_02,                         /* start second field      */
                   ied_frcl_rec_02,         /* receive block 2         */
                   ied_frcl_r02_x224mcs,    /* proc bl 2 X.224 MCS     */
                   ied_frcl_r02_mcscoen,    /* b2 MCS connect encoding */
                   ied_frcl_r02_mc_cids,    /* b2 MC Calling Domain Selector */
                   ied_frcl_r02_mc_ceds,    /* b2 MC Called Domain Selector */
                   ied_frcl_r02_mc_upwf,    /* b2 MC Upward Flag       */
                   ied_frcl_r02_mc_tdop,    /* b2 MC Target Domain Parameters */
                   ied_frcl_r02_mc_midp,    /* b2 MC Minimum Domain Parameters */
                   ied_frcl_r02_mc_madp,    /* b2 MC Maximum Domain Parameters */
                   ied_frcl_r02_mc_usd1,    /* b2 MC User Data Start   */
                   ied_frcl_r02_mcud_l1,    /* b2 MC Us-Da length 1    */
//                 ied_frcl_r02_mcud_l2,    /* b2 MC Us-Da length 2    */
#ifdef B060907
                   ied_frcl_r02_mcud_dtt,   /* b2 MC Us-Da Desktop Tag */
#endif
#ifdef B060907
   ied_frcl_r02_fie_dtt,                    /* b2 MC Us-Da Desktop Tag */
#endif
//                 ied_frcl_r02_mcud_prv,   /* b2 MC Us-Da Protocol Ve */
   ied_frcl_r02_fietype,                    /* b2 MC Field Type        */
   ied_frcl_r02_fielen,                     /* b2 MC Field Length      */
                   ied_frcl_r02_mcud_c01,   /* b2 MC Us-Da const 01    */
                   ied_frcl_r02_mcud_scw,   /* b2 MC Us-Da scr width   */
                   ied_frcl_r02_mcud_sch,   /* b2 MC Us-Da scr height  */
                   ied_frcl_r02_mcud_c02,   /* b2 MC Us-Da const 02    */
                   ied_frcl_r02_mcud_kbl,   /* b2 MC Us-Da Keyboard La */
                   ied_frcl_r02_mcud_bun,   /* b2 MC Us-Da Build Numb  */
                   ied_frcl_r02_mcud_con,   /* b2 MC Us-Da Computer Na */
                   ied_frcl_r02_mcud_kbt,   /* b2 MC Us-Da Keyboard Ty */
                   ied_frcl_r02_mcud_kbs,   /* b2 MC Us-Da Keyboard ST */
                   ied_frcl_r02_mcud_nfk,   /* b2 MC Us-Da No Func Key */
                   ied_frcl_r02_mcud_ime,   /* b2 MC Us-Da IME Keyb ma */
                   ied_frcl_r02_mcud_c03,   /* b2 MC Us-Da const 03    */
                   ied_frcl_r02_mcud_pv1,   /* b2 MC Us-Da protocol ve */
                   ied_frcl_r02_mcud_cod,   /* b2 MC Us-Da Color Depth */
   ied_frcl_r02_mcud_sup_cod,               /* b2 MC Us-Da supported Color Depth */
   ied_frcl_r02_mcud_early_cf,              /* b2 MC Us-Da early capability flag */
#ifdef B060907
                   ied_frcl_r02_mcud_vc1,   /* b2 MC Us-Da virtual ch  */
#endif
                   ied_frcl_r02_mcud_nvc,   /* b2 MC Us-Da no virt ch  */
                   ied_frcl_r02_mcud_vcn,   /* b2 MC Us-Da virt ch nam */
                   ied_frcl_r02_mcud_vcf,   /* b2 MC Us-Da virt ch fla */
   ied_frcl_rdp5_inp,                       /* RDP5-style input data   */
#ifdef OLD01
                   ied_frcl_rec_03,         /* receive block 3         */
#endif
   ied_frcl_rec_05,                         /* receive block 5         */
   ied_frcl_rec_06,                         /* receive block 6         */
   ied_frcl_cjreq_rec,                      /* receive block channel join request */
   ied_frcl_clrand_rec,   /* ??? */         /* receive client random   */
   ied_frcl_client_rand,                    /* receive client random   */
   ied_frcl_c_logon_info_1,                 /* logon information 1     */
   ied_frcl_c_loinf_options,                /* Options                 */
   ied_frcl_c_loinf_domna_len,              /* Domain Name Length      */
   ied_frcl_c_loinf_userna_len,             /* User Name Length        */
   ied_frcl_c_loinf_pwd_len,                /* Password Length         */
   ied_frcl_c_loinf_altsh_len,              /* Alt Shell Length        */
   ied_frcl_c_loinf_wodir_len,              /* Working Directory Length */
   ied_frcl_c_loinf_domna_val,              /* Domain Name String      */
   ied_frcl_c_loinf_userna_val,             /* User Name String        */
   ied_frcl_c_loinf_pwd_val,                /* Password String         */
   ied_frcl_c_loinf_altsh_val,              /* Alt Shell String        */
   ied_frcl_c_loinf_wodir_val,              /* Working Directory String */
   ied_frcl_c_loinf_no_a_par,               /* number of additional parameters */
   ied_frcl_c_loinf_ineta,                  /* INETA                   */
   ied_frcl_c_loinf_path,                   /* Client Path             */
   ied_frcl_c_loinf_extra,                  /* Extra Parameters        */
   ied_frcl_lic_01,                         /* licencing block to check */
   ied_frcl_lic_clrand,                     /* New Licence Request / Client License Info */
   ied_frcl_lic_pkea,                       /* dito, parse PreferredKeyExchangeAlg */
   ied_frcl_lic_platform,                   /* dito, parse PlatformId  */
   ied_frcl_bb_type,                        /* dito, parse BinaryBlob Type */
   ied_frcl_bb_len,                         /* dito, parse BinaryBlob len */
   ied_frcl_resp_act_pdu_rec,               /* response block active PDU */
   ied_frcl_rdp4_vch_ulen,                  /* virtual channel uncompressed data length */
   ied_frcl_rec_xyz_01,                     /* ?????nse block active PDU */
   ied_frcl_hext_send,                      /* HOB-RDP-EXT1 send to server / SDH */
                    ied_frclnv_user,        /* userid invalid - not fo */
                    ied_frclnv_password };  /* password invalid        */

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
   ied_frse_r04_keytype,                    /* block 4 security keytype */
   ied_frse_r04_sec_level,                  /* block 4 security level  */
   ied_frse_r04_l_serv_rand,                /* block 4 length server random */
   ied_frse_r04_l_pub_par,                  /* block 4 length public parameters */
   ied_frse_r04_d_serv_rand,                /* block 4 data server random */
   ied_frse_r04_type_pub_par,               /* block 4 type public parameters */
   ied_frse_r04_ppdir_tag,                  /* block 4 public parms direct tag */
   ied_frse_r04_ppdir_len,                  /* block 4 public parms direct lenght */
   ied_frse_r04_d_pub_par,                  /* block 4 data public parameters */
   ied_frse_hrdpext1_01,                    /* HOB-RDP-EXT1 data       */
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
   ied_frse_r5_pdu_ord_buf,                 /* RDP 5 PDU order buffer  */
   ied_frse_r5_pdu_primord,                 /* RDP 5 PDU primary order */
   ied_frse_r5_pdu_apply_order,             /* RDP 5 PDU apply order   */
   ied_frse_r5_ign_single_unic,             /* ignore one single Unicode character */
   ied_frse_ordsec_brush_header,            /* secondary order brush header */
   ied_frse_ordsec_brush_data,              /* secondary order brush data */
   ied_frse_ordsec_cache_glyph,             /* secondary order cache glyph */
   ied_frse_xyz_end_pdu,                    /* end of PDU              */
/* 18.06.05 KB UUUU */
   ied_frse_xyz_end_order,                  /* end of order            */
// ied_frse_r04_rdp_v,                      /* block 4 RDP version     */
                    ied_ad_inv_user_x,        /* userid invalid - not fo */
                    ied_ad_inv_password_x };  /* password invalid        */

struct dsd_progaddr_1 {                     /* program addresses       */
   BOOL (* amrc_r5_ord_x[ D_R5_ORD_NO ]) ( struct dsd_hl_clib_1 *, char * );
   BOOL (* amc_decomp_01_x) ( struct dsd_hl_clib_1 *, struct dsd_cache_1 *, char *, int );
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


/* structure of an rectangle, defined by width and height              */
struct dsd_rectwh {
   signed short int isc_left;
   signed short int isc_top;
   signed short int isc_width;
   signed short int isc_height;
};

/* struct of an rectangle, defined by right and bottom                 */
struct dsd_rectrb {
   signed short int isc_left;
   signed short int isc_top;
   signed short int isc_right;
   signed short int isc_bottom;
};

struct dsd_brush {
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
/* 10.08.09 KB rename to scc_ because signed */
   signed char scc_brushorgx;               /* top leftmost pixel of brushpattern, x-coordinate */
   signed char scc_brushorgy;               /* top leftmost pixel of brushpattern, y-coordinate */
   unsigned char ucc_brushstyle;            /* style of brush          */
   unsigned char ucc_brushhatch;            /* hatched_brush info or last row of brush-pattern */
   char       chrc_brushextra[7];           /* pixel pattern (only needed, if ucc_brushstyle = ied_bs_pattern) */
};

struct dsd_short_point {
   signed short isc_x;  // x-coordinate of point
   signed short isc_y;  // y-coordinate of point
};

enum ied_sc_lineto_backmode {
   ied_scc_transparent = 0x0001,
   ied_scc_opaque      = 0x0002
};

enum ied_sc_savebitmap_operation {
   ied_scc_sv_savebits = 0x00,                  // save bitmap operation
   ied_scc_sv_restorebits = 0x01                // restore bitmap operation
};




/* [MS-RDPEGDI] 2.2.2.2.1.1.2.1 DstBlt (DSTBLT_ORDER)                  */
struct dsd_ord_co_o00 {                     /* order O00 coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.3 PatBlt (PATBLT_ORDER)                  */
struct dsd_ord_co_o01 {                     /* order O01 coordinates   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   struct dsd_brush dsc_brush;              /* brush                   */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.7 ScrBlt (SCRBLT_ORDER)                  */
struct dsd_ord_co_o02 {                     /* order O02 coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   short isc_x_src;                         /* x coordinate of source  */
   short isc_y_src;                         /* y coordinate of source  */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.21 DrawNineGrid (DRAWNINEGRID_ORDER)     */
struct dsd_ord_co_o07 {                     /* order O07 coordinates   */
   struct dsd_rectrb dsc_rect;              /* rectangle source src    */
   unsigned short int usc_bitmap_id;        /* offscreen BitmapId      */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.22 MultiDrawNineGrid (MULTI_DRAWNINEGRID_ORDER) */
struct dsd_ord_co_o08 {                     /* order O08 coordinates   */
   struct dsd_rectrb dsc_rect;              /* rectangle source src    */
   unsigned short int usc_bitmap_id;        /* offscreen BitmapId      */
   unsigned char ucc_no_delta_entries;      /* number of points CodedDeltaList */
   unsigned short int usc_len_delta_entries;  /* length of points CodedDeltaList */
   char       *achc_coded_delta_list;       /* contains the points CodedDeltaList */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.11 LineTo (LINETO_ORDER)                 */
struct dsd_ord_co_o09 {                     /* order O09 coordinates   */
   unsigned short int usc_backmode;         /* mode of background: transparent or opaque */
   signed short int isc_nxstart;                // starting point of the line, x-coordinate
   signed short int isc_nystart;                // starting point of the line, y-coordinate
   signed short int isc_nxend;                  // end point of the line, x-coordinate
   signed short int isc_nyend;                  // end point of the line, y-coordinate
   unsigned int umc_back_color;             /* BackColor               */
   unsigned char ucc_brop2;                 // binary raster operation
   unsigned char ucc_penstyle;              // PenStyle must be PS_SOLID(0x00)
   unsigned char ucc_penwidth;              // PenWidth must be 0x01.
   unsigned int umc_pencolor;               // color of the drawn line
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.5 OpaqueRect (OPAQUERECT_ORDER)          */
struct dsd_ord_co_o0a {                     /* order O0A coordinates   */
   struct dsd_rectwh dsc_rect;              /* virtual desktop rectangle to fill */
   unsigned char ucc_color_red;             /* RedOrPaletteIndex       */
   unsigned char ucc_color_green;           /* Green                   */
   unsigned char ucc_color_blue;            /* Blue                    */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.12 SaveBitmap (SAVEBITMAP_ORDER)         */
struct dsd_ord_co_o0b {                     /* order O0B coordinates   */
   unsigned int umc_savedbitmappos;         /* encoded start position of the rectangle in the saved bitmap */
   struct dsd_rectrb dsc_rect;              /* virtual desktop rectangle to save or to restore from */
// ied_sc_savebitmap_operation ucc_operation;  /* operation: either ied_sv_savebits or ied_sv_restorebits */
   unsigned char ucc_operation;             /* operation: either ied_sv_savebits or ied_sv_restorebits */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.9 MemBlt (MEMBLT_ORDER)                  */
struct dsd_ord_co_o0d {                     /* order O0D coordinates   */
   unsigned short int usc_cache_id;         /* cacheId                 */
// struct dsd_rectwh dsc_destination_rec;   /* destination rectangle   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   signed short int isc_x_src;              /* x-coordinate of source bitmap in cache of client */
   signed short int isc_y_src;              /* inverted y-coordinate of source bitmap in cache of client */
   unsigned short int usc_cacheindex;       /* index of bitmap within the bitmap cache of client */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.10 Mem3Blt (MEM3BLT_ORDER)               */
struct dsd_ord_co_o0e {                     /* order O0E coordinates   */
   unsigned short int usc_cache_id;         /* cacheId                 */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   signed short int isc_x_src;              /* x-coordinate of source bitmap in cache of client */
   signed short int isc_y_src;              /* inverted y-coordinate of source bitmap in cache of client */
   unsigned short int usc_cacheindex;       /* index of bitmap within the bitmap cache of client */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
// struct dsd_rectwh dsc_destination_rec;   /* destination rectangle   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   struct dsd_brush dsc_brush;              /* brush                   */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.2 MultiDstBlt (MULTI_DSTBLT_ORDER)       */
struct dsd_ord_co_o0f {                     /* order O0F coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   unsigned char ucc_no_delta_entries;      /* nDeltaEntries - number of delta entries */
   unsigned short int usc_len_delta;        /* length CodedDeltaList   */
   char *     achc_delta;                   /* CodedDeltaList          */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.4 MultiPatBlt (MULTI_PATBLT_ORDER)       */
struct dsd_ord_co_o10 {                     /* order O10 coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_brush dsc_brush;              /* brush                   */
   unsigned char ucc_no_delta_entries;      /* nDeltaEntries - number of delta entries */
   unsigned short int usc_len_delta;        /* length CodedDeltaList   */
   char *     achc_delta;                   /* CodedDeltaList          */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.8 MultiScrBlt (MULTI_SCRBLT_ORDER)       */
struct dsd_ord_co_o11 {                     /* order O11 coordinates   */
   struct dsd_rectwh dsc_rect;              /* destination rectangle   */
   unsigned char ucc_brop3;                 /* index of the ternary raster operation */
   short isc_x_src;                         /* x coordinate of source  */
   short isc_y_src;                         /* y coordinate of source  */
   unsigned char ucc_no_delta_entries;      /* nDeltaEntries - number of delta entries */
   unsigned short int usc_len_delta;        /* length CodedDeltaList   */
   char *     achc_delta;                   /* CodedDeltaList          */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.6 MultiOpaqueRect (MULTI_OPAQUERECT_ORDER) */
struct dsd_ord_co_o12 {                     /* order O12 coordinates   */
   struct dsd_rectwh dsc_rect;              /* virtual desktop rectangle to fill */
   unsigned char ucc_color_red;             /* RedOrPaletteIndex       */
   unsigned char ucc_color_green;           /* Green                   */
   unsigned char ucc_color_blue;            /* Blue                    */
   unsigned char ucc_no_delta_entries;      /* nDeltaEntries - number of delta entries */
   unsigned short int usc_len_delta;        /* length CodedDeltaList   */
   char *     achc_delta;                   /* CodedDeltaList          */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.14 FastIndex (FASTINDEX_ORDER)           */
struct dsd_ord_co_o13 {                     /* order O13 coordinates   */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned short int usc_fdrawing;         /* fDrawing                */
   unsigned int umc_forecolor;              /* foreground color        */
   unsigned int umc_backcolor;              /* background color        */
   struct dsd_rectrb dsc_backrect;          /* text background rectangle, like a clip */
   struct dsd_rectrb dsc_opaqrect;          /* opaque rectangle        */
   signed short int isc_start_x;            /* starting point of first glyph, x-coordinate */
   signed short int isc_start_y;            /* starting point of first glyph, y-coordinate */
   unsigned char ucc_len_glyph;             /* length glyph data      */
   char *     achc_glyph;                   /* glyph data             */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.16 PolygonSC (POLYGON_SC_ORDER)          */
struct dsd_ord_co_o14 {                     /* order O14 coordinates   */
   signed short int isc_start_x;            /* starting point of the line, x-coordinate */
   signed short int isc_start_y;            /* starting point of the line, y-coordinate */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned char ucc_fillmode;              /* FillMode                */
   unsigned int umc_brushcolor;             /* BrushColor              */
   unsigned char ucc_no_delta_entries;      /* number of points along the polygon path */
   unsigned char ucc_len_delta_entries;     /* length of points along the polygon path */
   char       *achc_coded_delta_list;       /* contains the points along the polygon path */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.17 PolygonCB (POLYGON_CB_ORDER)          */
struct dsd_ord_co_o15 {                     /* order O15 coordinates   */
   signed short int isc_start_x;            /* starting point of the line, x-coordinate */
   signed short int isc_start_y;            /* starting point of the line, y-coordinate */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned char ucc_fillmode;              /* FillMode                */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_brush dsc_brush;              /* brush                   */
   unsigned char ucc_no_delta_entries;      /* number of points along the polygon path */
   unsigned char ucc_len_delta_entries;     /* length of points along the polygon path */
   char       *achc_coded_delta_list;       /* contains the points along the polygon path */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.18 Polyline (POLYLINE_ORDER)             */
struct dsd_ord_co_o16 {                     /* order O16 coordinates   */
   signed short int isc_start_x;            /* starting point of the line, x-coordinate */
   signed short int isc_start_y;            /* starting point of the line, y-coordinate */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned short int usc_brush_cache_entry;  /* brush cache entry     */
   unsigned int umc_pencolor;               /* color of the drawn line */
   unsigned char ucc_no_delta_entries;      /* number of points along the polyline path */
   unsigned char ucc_len_delta_entries;     /* length of points along the polyline path */
   char       *achc_coded_delta_list;       /* contains the points along the polyline path */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.15 FastGlyph (FASTGLYPH_ORDER)           */
struct dsd_ord_co_o18 {                     /* order O18 coordinates   */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned short int usc_fdrawing;         /* fDrawing                */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_rectrb dsc_backrect;          /* text background rectangle, like a clip */
   struct dsd_rectrb dsc_opaqrect;          /* opaque rectangle        */
   signed short int isc_start_x;            /* starting point of first glyph, x-coordinate */
   signed short int isc_start_y;            /* starting point of first glyph, y-coordinate */
//#ifdef XYZ1
//*if def D_TRACE_100110A;
   int        imc_save_prot_7;
//*cend;
//#endif
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.19 EllipseSC (ELLIPSE_SC_ORDER)          */
struct dsd_ord_co_o19 {                     /* order O19 coordinates   */
   struct dsd_rectrb dsc_rect;              /* rectangle for the ellipse */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned char ucc_fillmode;              /* FillMode                */
   unsigned int umc_color;                  /* foreground color        */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.20 EllipseCB (ELLIPSE_CB_ORDER)          */
struct dsd_ord_co_o1a {                     /* order O1A coordinates   */
   struct dsd_rectrb dsc_rect;              /* rectangle for the ellipse */
   unsigned char ucc_brop2;                 /* binary raster operation */
   unsigned char ucc_fillmode;              /* FillMode                */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_brush dsc_brush;              /* brush for the ellipse   */
};

/* [MS-RDPEGDI] 2.2.2.2.1.1.2.13 GlyphIndex (GLYPHINDEX_ORDER)         */
struct dsd_ord_co_o1b {                     /* order O1B coordinates   */
   unsigned char ucc_cache_id;              /* cacheId                 */
   unsigned char ucc_flaccel;               /* flAccel                 */
   unsigned char ucc_ulcharinc;             /* ulCharInc               */
   unsigned char ucc_fopredundant;          /* fOpRedundant            */
   unsigned int umc_backcolor;              /* background color        */
   unsigned int umc_forecolor;              /* foreground color        */
   struct dsd_rectrb dsc_backrect;          /* text background rectangle, like a clip */
   struct dsd_rectrb dsc_opaqrect;          /* opaque rectangle        */
   struct dsd_brush dsc_brush;              /* brush for the glyph     */
   signed short int isc_start_x;            /* starting point of first glyph, x-coordinate */
   signed short int isc_start_y;            /* starting point of first glyph, y-coordinate */
   unsigned char ucc_len_glyph;             /* length glyph data      */
   char *     achc_glyph;                   /* glyph data             */
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


#define LB_TARGET_NET_ADDRESS     0X00000001
#define LB_LOAD_BALANCE_INFO      0X00000002  /* load-balancing info   */
#define LB_USERNAME               0X00000004
#define LB_DOMAIN                 0X00000008
#define LB_PASSWORD               0X00000010
#define LB_DONTSTOREUSERNAME      0X00000020
#define LB_SMARTCARD_LOGON        0X00000040
#define LB_NOREDIRECT             0X00000080
#define LB_TARGET_FQDN            0X00000100
#define LB_TARGET_NETBIOS_NAME    0X00000200
#define LB_TARGET_NET_ADDRESSES   0X00000800
#define LB_CLIENT_TSV_URL         0X00001000
#define LB_SERVER_TSV_CAPABLE     0X00002000


struct dsd_rdp_encry {                      /* rdp encryption          */
   char       chrc_cl_pkd[16];              /* pre key data            */
   char       chrc_orig_pkd[16];            /* first key before update */
   char       chrc_rc4_state[ RC4_STATE_SIZE ];  /* RC4 state array    */
   int        imc_count_sent;               /* count blocks sent       */
};

struct dsd_rdp_lic_bb {                     /* licencing binary blob   */
   unsigned short int usc_bb_type;          /* blob type, 2.2.1.12.1.2 */
   unsigned short int usc_bb_len;           /* length of data in byte  */
   char *     achc_bb_data;                 /* content                 */
};

struct dsd_rdp_lic_d {                      /* licensing protocol data */
   char       chc_lic_clcertway;            /* type of first client lic.packet */
   char       chc_lic_vers;                 /* licensing version and some flag */
   int        imc_lic_pkea;                 /* preferred key algorithm */
   int        imc_lic_platform;             /* platform ID             */
   char       chrc_lic_clrand[32];          /* licensing client random */
   struct dsd_rdp_lic_bb dsc_lic_pms;       /* lic. premaster secret   */
   char       chrc_lic_serand[32];          /* licensing server random */
// 08.08.09 KB rename to achc
   char *     chrc_lic_1;                   /* data temporarily needed */
   int        imc_lic_1_len;                /* length of temporary data */
   int        imc_lic_cert_key_len;         /* length of certificate modulus */
// 08.08.09 KB rename to achc
   char *     chrc_lic_cert_key;            /* certificate modulus     */
   int        imc_lic_cert_exp_len;         /* length of certificate exponent */
// 08.08.09 KB rename to achc
   char *     chrc_lic_cert_exp;            /* certificate exponent    */
   char       chrc_rc4_state_se2cl[RC4_STATE_SIZE]; /* RC4 state array */
   char       chrc_rc4_state_cl2se[RC4_STATE_SIZE]; /* RC4 state array */
   int        imrc_sha1_state[ SHA_ARRAY_SIZE ];  /* SHA1 state array  */
   int        imrc_md5_state[ MD5_ARRAY_SIZE ];  /* MD5 state array    */
};

typedef struct {
   unsigned short int ibc_contchno : 1;     /* control channel defined */
   unsigned short int filler : 15;          /* filler                  */
} dtd_rdpfl_1;

struct dsd_rdp_co {                         /* RDP communication       */
   unsigned char ucc_prot_vers;             /* protocol version        */
   int        imc_cl_coldep;                /* client capabilities colour depth */
   unsigned short int usc_cl_supported_color_depth;  /* client capabilities */
   unsigned short int usc_cl_early_capability_flag;  /* client capabilities */
   int        imc_dim_x;                    /* dimension x pixels      */
   int        imc_dim_y;                    /* dimension y pixels      */
   int        imc_keyboard_layout;          /* Keyboard Layout         */
   int        imc_build_number;             /* MS Build Number         */
   int        imc_shareid;                  /* share id, parsed from Demand active PDU */
   HL_WCHAR   wcrc_computer_name[16];       /* computer name           */
   int        imc_keyboard_type;            /* Type of Keyboard / 102  */
   int        imc_keyboard_subtype;         /* Subtype of Keyboard     */
   int        imc_no_func_keys;             /* Number of Function Keys */
   int        imc_keytype;                  /* keytype                 */
   int        imc_used_keylen;              /* used keylen 03.01.05    */
   int        imc_sec_level;                /* security level          */
   int        imc_l_pub_par;                /* length public parameters */
   int        imc_no_virt_ch;               /* number of virtual channels */
   BOOL       boc_always_compr_vc;          /* TRUE, if there is a virtual channel, which is always compressed */
   unsigned short int usc_chno_disp;        /* channel number display  */
   unsigned short int usc_chno_cont;        /* channel number control  */
   unsigned short int usc_userid_cl2se;     /* userid client to server */
   dtd_rdpfl_1 dtc_rdpfl_1;                 /* RDP flags               */
   struct dsd_rdp_vc_1 *adsrc_vc_1;         /* array of virtual chann  */
   struct dsd_progaddr_1 *adsc_progaddr_1;  /* program addresses       */
   struct dsd_cdr_ctrl dsc_cdrf_dec;        /* compression decoding    */
   struct dsd_cdr_ctrl dsc_cdrf_enc;        /* compression encoding    */
   amd_cdr_dec amc_cdr_dec;                 /* routine compression decoding */
   amd_cdr_enc amc_cdr_enc;                 /* routine compression encoding */
   char       chrc_sig[16];                 /* signature               */
   struct dsd_rdp_encry dsc_encry_se2cl;    /* rdp encryption server to client */
   struct dsd_rdp_encry dsc_encry_cl2se;    /* rdp encryption client to server */
   int        imrc_sha1_state[ SHA_ARRAY_SIZE ];  /* SHA1 state array  */
   int        imrc_md5_state[ MD5_ARRAY_SIZE ];  /* MD5 state array    */
#ifdef HL_RDPACC_HELP_DEBUG
   int        imc_debug_reclen;
   int        imc_debug_count_event;
#endif
/* new 25.03.07 KB */
   unsigned int umc_loinf_options;          /* Logon Info Options      */
   unsigned short int usc_loinf_domna_len;  /* Domain Name Length      */
   unsigned short int usc_loinf_userna_len;  /* User Name Length       */
   unsigned short int usc_loinf_pwd_len;    /* Password Length         */
   unsigned short int usc_loinf_altsh_len;  /* Alt Shell Length        */
   unsigned short int usc_loinf_wodir_len;  /* Working Directory Length */
   unsigned short int usc_loinf_no_a_par;   /* number of additional parameters */
   unsigned short int usc_loinf_ineta_len;  /* INETA Length            */
   unsigned short int usc_loinf_path_len;   /* Client Path Length      */
   unsigned short int usc_loinf_extra_len;  /* Extra Parameters Length */
   HL_WCHAR   *awcc_loinf_domna_a;          /* Domain Name             */
   HL_WCHAR   *awcc_loinf_userna_a;         /* User Name               */
   HL_WCHAR   *awcc_loinf_pwd_a;            /* Password                */
   HL_WCHAR   *awcc_loinf_altsh_a;          /* Alt Shell               */
   HL_WCHAR   *awcc_loinf_wodir_a;          /* Working Directory       */
   HL_WCHAR   *awcc_loinf_ineta_a;          /* INETA                   */
   HL_WCHAR   *awcc_loinf_path_a;           /* Client Path             */
   void       *awcc_loinf_extra_a;          /* Extra Parameters        */
   struct dsd_rdp_lic_d * adsc_lic_neg;     /* for license negotiation */
   char       chrc_start_rec[ 4 + D_SIZE_HASH ];  /* start of record   */
   int        imc_len_start_rec;            /* length start of record  */
   int        imc_len_record;               /* length of record        */
   int        imc_len_part;                 /* length of part          */
};

struct dsd_rdp_server_1 {                   /* RDP server part         */
   struct dsd_rdp_co dsc_rdp_co_1;  /* RDP communication      */
   ied_fcfp_bl iec_fcfp_bl;                 /* field position          */
   ied_frcl_bl iec_frcl_bl;                 /* receive block from client */
   int        imc_pos_inp_frame;            /* position in input frame */
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
   };
   int        imc_prot_count_01;            /* count 01 of protocol decoding */
   int        imc_prot_chno;                /* for protocol decoding   */
   char *     achc_prot_1;                  /* for protocol decoding   */
   char       chrc_prot_1[ D_MAX_CRYPT_LEN ];  /* for protocol decoding */
   char       chc_prot_rt02;                /* for protocol decoding   */
   char       chc_prot_rt03;                /* for protocol decoding   */
   unsigned char ucc_order_flags_1;         /* send order flags        */
   unsigned int umc_vch_ulen;               /* virtual channel length uncompressed */
   char       chrc_vch_segfl[2];            /* virtual channel segmentation flags */
   char       chrc_inp_hash[ D_SIZE_HASH ];  /* input hash             */
   int        imc_len_temp;                 /* length temporary buffer */
   void *     ac_temp_buffer;               /* temporary buffer        */
};

struct dsd_rdp_client_1 {                   /* RDP client part         */
   struct dsd_rdp_co dsc_rdp_co_1;  /* RDP communication      */
   enum ied_fsfp_bl iec_fsfp_bl;            /* field position          */
   enum ied_frse_bl iec_frse_bl;            /* receive block from server */
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
   };
   int        imc_prot_6;                   /* for protocol decoding   */
   int        imc_prot_7;                   /* for protocol decoding   */
   int        imc_prot_8;                   /* for protocol decoding   */
   int        imc_prot_chno;                /* for protocol decoding   */
   char *     achc_prot_1;                  /* for protocol decoding   */
// char *     achc_prot_2;                  /* for protocol decoding   */
#ifdef B060821
   char       chrc_prot_1[ 128 ];           /* for protocol decoding   */
#endif
   char       chrc_prot_1[ 4096 ];          /* for protocol decoding   */
   char       chrc_prot_2[ 128 ];           /* for protocol decoding   */
//*IF DEF D$RDP$HOOK;
//*CEND;
   char       chc_prot_rt02;                /* for protocol decoding   */
   char       chc_prot_rt03;                /* for protocol decoding   */
   char       chc_prot_r5_first;            /* for protocol decoding   */
   char       chc_prot_r5_pdu_type;         /* for protocol decoding   */
   char       chc_prot_r5_pdu_cofl;         /* for protocol decoding   */
   unsigned int umc_vch_ulen;               /* virtual channel length uncompressed */
   char       chrc_vch_segfl[2];            /* virtual channel segmentation flags */
#ifdef TEMPSCR2                             /* 15.06.05 KB - send screen */
   int        imc_count_order;              /* count orders            */
#endif
#ifdef TRACEHL_BMP_060827
   int        imc_count_mbp;                /* count bitmaps           */
#endif
   int        imc_len_temp;                 /* length temporary buffer */
   void *     ac_temp_buffer;               /* temporary buffer        */
};

struct dsd_sc_draw_sc {                     /* draw on screen          */
   int        imc_left;                     /* coordinate left         */
   int        imc_top;                      /* coordinate top          */
   int        imc_right;                    /* coordinate right        */
   int        imc_bottom;                   /* coordinate bottom       */
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
   BOOL       boc_scp_hrdpe1;               /* protocol HOB MS RDP Ext 1 */
   struct dsd_rdp_server_1 dsc_rdp_se_1;    /* rdp server part         */
   struct dsd_rdp_client_1 dsc_rdp_cl_1;    /* rdp client part         */
   char       chrl_server_random[32];       /* specify server-random   */
   void *     ac_cs_block_ch;               /* chain GCC client data   */
//   struct dsd_cliprdr_ctrl *adsc_cb_c;      /* cliprdr flags           */
   struct dsd_rdp_save_vch_1 dsc_s1;        /* RDP parameters saved virus checking */
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
   0X03, 0X00, 0X00, 0X13,
   0X0E, 0XE0, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X01, 0X00, 0X08, 0X00, 0X00, 0X00, 0X00, 0X00
};

static const unsigned char ucrs_rec_cl_01_cmp1[] = {  /* compare received from client first block */
   0XE0, 0X00, 0X00, 0X00, 0X00, 0X00
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
#ifdef OLD01
   0XCE, 0X0E, 0X00, 0X00
#else
   0X93, 0X08, 0X00, 0X00
#endif
};

static const unsigned char ucrs_logon_info_c1[] = {  /* Constant Logon Info */
   0X07, 0X04, 0X07, 0X04
};


static const unsigned char ucrs_x224_encry[] = {  /* X224 record 2 encryption */
   0X01, 0XCA, 0X01, 0X00, 0X00, 0X00, 0X00, 0X00,  // postBeta2ColorDepth(2), clientProductId(2), serialNumber(4)
   0X10, 0X00, 0X07, 0X00, 0X01, 0X00, 0X00, 0X00,  // highColorDepth(2), supportedColorDepths(2), earlyCapabilityFlags(2), clientDigProductId(2)
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

#ifndef CERTMS01
//#define D_LEN_CERT_PUBLIC_KEY 64
#define D_POS_CERT_PUBLIC_KEY 1214
#define D_LEN_CERT_PUBLIC_KEY 64
//#define D_POS_CERT_EXP        1280
//#define D_LEN_CERT_EXP        3

static const unsigned char ucrs_rdp_cert[] = {
   0X02, 0X00, 0X00, 0X00, 0XCB, 0X02, 0X00, 0X00, 0X30, 0X82, 0X02, 0XC7, 0X30, 0X82, 0X02, 0X71,
   0XA0, 0X03, 0X02, 0X01, 0X02, 0X02, 0X06, 0X00, 0X94, 0X1B, 0X84, 0XA8, 0XD7, 0X30, 0X0D, 0X06,
   0X09, 0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X05, 0X05, 0X00, 0X30, 0X81, 0XD6, 0X31,
   0X0B, 0X30, 0X09, 0X06, 0X03, 0X55, 0X04, 0X06, 0X13, 0X02, 0X44, 0X45, 0X31, 0X13, 0X30, 0X11,
   0X06, 0X03, 0X55, 0X04, 0X07, 0X13, 0X0A, 0X43, 0X61, 0X64, 0X6F, 0X6C, 0X7A, 0X62, 0X75, 0X72,
   0X67, 0X31, 0X0F, 0X30, 0X0D, 0X06, 0X03, 0X55, 0X04, 0X08, 0X13, 0X06, 0X42, 0X61, 0X79, 0X65,
   0X72, 0X6E, 0X31, 0X1F, 0X30, 0X1D, 0X06, 0X03, 0X55, 0X04, 0X09, 0X13, 0X16, 0X53, 0X63, 0X68,
   0X77, 0X61, 0X64, 0X65, 0X72, 0X6D, 0X75, 0X65, 0X68, 0X6C, 0X73, 0X74, 0X72, 0X61, 0X73, 0X73,
   0X65, 0X20, 0X33, 0X31, 0X0C, 0X30, 0X0A, 0X06, 0X03, 0X55, 0X04, 0X0A, 0X13, 0X03, 0X48, 0X4F,
   0X42, 0X31, 0X1B, 0X30, 0X19, 0X06, 0X03, 0X55, 0X04, 0X0B, 0X13, 0X12, 0X52, 0X44, 0X50, 0X20,
   0X43, 0X65, 0X72, 0X74, 0X69, 0X66, 0X69, 0X63, 0X61, 0X74, 0X65, 0X20, 0X43, 0X41, 0X31, 0X0E,
   0X30, 0X0C, 0X06, 0X03, 0X55, 0X04, 0X11, 0X13, 0X05, 0X39, 0X30, 0X35, 0X35, 0X36, 0X31, 0X24,
   0X30, 0X22, 0X06, 0X03, 0X55, 0X04, 0X03, 0X13, 0X1B, 0X52, 0X44, 0X50, 0X20, 0X53, 0X65, 0X72,
   0X76, 0X65, 0X72, 0X20, 0X52, 0X6F, 0X6F, 0X74, 0X20, 0X43, 0X65, 0X72, 0X74, 0X69, 0X66, 0X69,
   0X63, 0X61, 0X74, 0X65, 0X31, 0X1F, 0X30, 0X1D, 0X06, 0X09, 0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D,
   0X01, 0X09, 0X01, 0X16, 0X10, 0X6D, 0X61, 0X72, 0X6B, 0X65, 0X74, 0X69, 0X6E, 0X67, 0X40, 0X68,
   0X6F, 0X62, 0X2E, 0X64, 0X65, 0X30, 0X1E, 0X17, 0X0D, 0X30, 0X34, 0X31, 0X32, 0X30, 0X39, 0X30,
   0X37, 0X30, 0X30, 0X30, 0X30, 0X5A, 0X17, 0X0D, 0X34, 0X34, 0X31, 0X32, 0X30, 0X39, 0X30, 0X37,
   0X30, 0X30, 0X30, 0X30, 0X5A, 0X30, 0X81, 0XD6, 0X31, 0X0B, 0X30, 0X09, 0X06, 0X03, 0X55, 0X04,
   0X06, 0X13, 0X02, 0X44, 0X45, 0X31, 0X13, 0X30, 0X11, 0X06, 0X03, 0X55, 0X04, 0X07, 0X13, 0X0A,
   0X43, 0X61, 0X64, 0X6F, 0X6C, 0X7A, 0X62, 0X75, 0X72, 0X67, 0X31, 0X0F, 0X30, 0X0D, 0X06, 0X03,
   0X55, 0X04, 0X08, 0X13, 0X06, 0X42, 0X61, 0X79, 0X65, 0X72, 0X6E, 0X31, 0X1F, 0X30, 0X1D, 0X06,
   0X03, 0X55, 0X04, 0X09, 0X13, 0X16, 0X53, 0X63, 0X68, 0X77, 0X61, 0X64, 0X65, 0X72, 0X6D, 0X75,
   0X65, 0X68, 0X6C, 0X73, 0X74, 0X72, 0X61, 0X73, 0X73, 0X65, 0X20, 0X33, 0X31, 0X0C, 0X30, 0X0A,
   0X06, 0X03, 0X55, 0X04, 0X0A, 0X13, 0X03, 0X48, 0X4F, 0X42, 0X31, 0X1B, 0X30, 0X19, 0X06, 0X03,
   0X55, 0X04, 0X0B, 0X13, 0X12, 0X52, 0X44, 0X50, 0X20, 0X43, 0X65, 0X72, 0X74, 0X69, 0X66, 0X69,
   0X63, 0X61, 0X74, 0X65, 0X20, 0X43, 0X41, 0X31, 0X0E, 0X30, 0X0C, 0X06, 0X03, 0X55, 0X04, 0X11,
   0X13, 0X05, 0X39, 0X30, 0X35, 0X35, 0X36, 0X31, 0X24, 0X30, 0X22, 0X06, 0X03, 0X55, 0X04, 0X03,
   0X13, 0X1B, 0X52, 0X44, 0X50, 0X20, 0X53, 0X65, 0X72, 0X76, 0X65, 0X72, 0X20, 0X52, 0X6F, 0X6F,
   0X74, 0X20, 0X43, 0X65, 0X72, 0X74, 0X69, 0X66, 0X69, 0X63, 0X61, 0X74, 0X65, 0X31, 0X1F, 0X30,
   0X1D, 0X06, 0X09, 0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X09, 0X01, 0X16, 0X10, 0X6D, 0X61,
   0X72, 0X6B, 0X65, 0X74, 0X69, 0X6E, 0X67, 0X40, 0X68, 0X6F, 0X62, 0X2E, 0X64, 0X65, 0X30, 0X5C,
   0X30, 0X0D, 0X06, 0X09, 0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X01, 0X05, 0X00, 0X03,
   0X4B, 0X00, 0X30, 0X48, 0X02, 0X41, 0X00, 0XCB, 0XB5, 0X09, 0X46, 0X90, 0XAA, 0X0E, 0X9E, 0X79,
   0X7D, 0X4B, 0XD1, 0X52, 0XCD, 0X21, 0X88, 0X6C, 0XAA, 0XE8, 0X45, 0X9E, 0XAD, 0XC9, 0XBE, 0X9D,
   0XBC, 0X9F, 0XCA, 0XF2, 0X55, 0XB7, 0XAA, 0X1F, 0X0F, 0X0B, 0X08, 0XA0, 0XA0, 0X0A, 0XE3, 0X50,
   0XCB, 0X2A, 0X99, 0X0D, 0X3B, 0X12, 0X6E, 0X9A, 0XC2, 0X0B, 0X8C, 0X63, 0XB8, 0X9B, 0X2C, 0X19,
   0XAF, 0XF9, 0X86, 0XAD, 0XD8, 0XD1, 0X8F, 0X02, 0X03, 0X01, 0X00, 0X01, 0XA3, 0X23, 0X30, 0X21,
   0X30, 0X0E, 0X06, 0X03, 0X55, 0X1D, 0X0F, 0X01, 0X01, 0XFF, 0X04, 0X04, 0X03, 0X02, 0X02, 0XBC,
   0X30, 0X0F, 0X06, 0X03, 0X55, 0X1D, 0X13, 0X01, 0X01, 0XFF, 0X04, 0X05, 0X30, 0X03, 0X01, 0X01,
   0XFF, 0X30, 0X0D, 0X06, 0X09, 0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X05, 0X05, 0X00,
   0X03, 0X41, 0X00, 0X5E, 0X38, 0XF8, 0X46, 0X79, 0XC0, 0X21, 0XFA, 0X4D, 0X7D, 0XB0, 0X8F, 0X0A,
   0X55, 0X8F, 0X11, 0XE8, 0X9F, 0X36, 0XCE, 0XD7, 0X91, 0X29, 0X0E, 0XC7, 0X53, 0X9A, 0X80, 0XB7,
   0X78, 0XCE, 0XF7, 0XE0, 0XCA, 0X04, 0X4F, 0XC5, 0X42, 0X25, 0XB7, 0XCD, 0X10, 0XE2, 0XFA, 0X71,
   0X15, 0X39, 0X3F, 0X29, 0X92, 0X31, 0XC0, 0XC2, 0X94, 0X08, 0X11, 0X04, 0X3A, 0X4F, 0XB6, 0X85,
   0X3B, 0X55, 0X9D, 0XA3, 0X02, 0X00, 0X00, 0X30, 0X82, 0X02, 0X9F, 0X30, 0X82, 0X02, 0X49, 0XA0,
   0X03, 0X02, 0X01, 0X02, 0X02, 0X06, 0X00, 0XB4, 0X1B, 0X84, 0XB1, 0XA3, 0X30, 0X0D, 0X06, 0X09,
   0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X05, 0X05, 0X00, 0X30, 0X81, 0XD6, 0X31, 0X0B,
   0X30, 0X09, 0X06, 0X03, 0X55, 0X04, 0X06, 0X13, 0X02, 0X44, 0X45, 0X31, 0X13, 0X30, 0X11, 0X06,
   0X03, 0X55, 0X04, 0X07, 0X13, 0X0A, 0X43, 0X61, 0X64, 0X6F, 0X6C, 0X7A, 0X62, 0X75, 0X72, 0X67,
   0X31, 0X0F, 0X30, 0X0D, 0X06, 0X03, 0X55, 0X04, 0X08, 0X13, 0X06, 0X42, 0X61, 0X79, 0X65, 0X72,
   0X6E, 0X31, 0X1F, 0X30, 0X1D, 0X06, 0X03, 0X55, 0X04, 0X09, 0X13, 0X16, 0X53, 0X63, 0X68, 0X77,
   0X61, 0X64, 0X65, 0X72, 0X6D, 0X75, 0X65, 0X68, 0X6C, 0X73, 0X74, 0X72, 0X61, 0X73, 0X73, 0X65,
   0X20, 0X33, 0X31, 0X0C, 0X30, 0X0A, 0X06, 0X03, 0X55, 0X04, 0X0A, 0X13, 0X03, 0X48, 0X4F, 0X42,
   0X31, 0X1B, 0X30, 0X19, 0X06, 0X03, 0X55, 0X04, 0X0B, 0X13, 0X12, 0X52, 0X44, 0X50, 0X20, 0X43,
   0X65, 0X72, 0X74, 0X69, 0X66, 0X69, 0X63, 0X61, 0X74, 0X65, 0X20, 0X43, 0X41, 0X31, 0X0E, 0X30,
   0X0C, 0X06, 0X03, 0X55, 0X04, 0X11, 0X13, 0X05, 0X39, 0X30, 0X35, 0X35, 0X36, 0X31, 0X24, 0X30,
   0X22, 0X06, 0X03, 0X55, 0X04, 0X03, 0X13, 0X1B, 0X52, 0X44, 0X50, 0X20, 0X53, 0X65, 0X72, 0X76,
   0X65, 0X72, 0X20, 0X52, 0X6F, 0X6F, 0X74, 0X20, 0X43, 0X65, 0X72, 0X74, 0X69, 0X66, 0X69, 0X63,
   0X61, 0X74, 0X65, 0X31, 0X1F, 0X30, 0X1D, 0X06, 0X09, 0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01,
   0X09, 0X01, 0X16, 0X10, 0X6D, 0X61, 0X72, 0X6B, 0X65, 0X74, 0X69, 0X6E, 0X67, 0X40, 0X68, 0X6F,
   0X62, 0X2E, 0X64, 0X65, 0X30, 0X1E, 0X17, 0X0D, 0X30, 0X34, 0X31, 0X32, 0X30, 0X39, 0X30, 0X37,
   0X30, 0X30, 0X30, 0X30, 0X5A, 0X17, 0X0D, 0X34, 0X34, 0X31, 0X32, 0X30, 0X39, 0X30, 0X37, 0X30,
   0X30, 0X30, 0X30, 0X5A, 0X30, 0X81, 0XAE, 0X31, 0X0B, 0X30, 0X09, 0X06, 0X03, 0X55, 0X04, 0X06,
   0X13, 0X02, 0X44, 0X45, 0X31, 0X13, 0X30, 0X11, 0X06, 0X03, 0X55, 0X04, 0X07, 0X13, 0X0A, 0X43,
   0X61, 0X64, 0X6F, 0X6C, 0X7A, 0X62, 0X75, 0X72, 0X67, 0X31, 0X0F, 0X30, 0X0D, 0X06, 0X03, 0X55,
   0X04, 0X08, 0X13, 0X06, 0X42, 0X61, 0X79, 0X65, 0X72, 0X6E, 0X31, 0X1F, 0X30, 0X1D, 0X06, 0X03,
   0X55, 0X04, 0X09, 0X13, 0X16, 0X53, 0X63, 0X68, 0X77, 0X61, 0X64, 0X65, 0X72, 0X6D, 0X75, 0X65,
   0X68, 0X6C, 0X73, 0X74, 0X72, 0X61, 0X73, 0X73, 0X65, 0X20, 0X33, 0X31, 0X0C, 0X30, 0X0A, 0X06,
   0X03, 0X55, 0X04, 0X0A, 0X13, 0X03, 0X48, 0X4F, 0X42, 0X31, 0X14, 0X30, 0X12, 0X06, 0X03, 0X55,
   0X04, 0X0B, 0X13, 0X0B, 0X45, 0X6E, 0X74, 0X77, 0X69, 0X63, 0X6B, 0X6C, 0X75, 0X6E, 0X67, 0X31,
   0X0E, 0X30, 0X0C, 0X06, 0X03, 0X55, 0X04, 0X11, 0X13, 0X05, 0X39, 0X30, 0X35, 0X35, 0X36, 0X31,
   0X24, 0X30, 0X22, 0X06, 0X03, 0X55, 0X04, 0X03, 0X13, 0X1B, 0X52, 0X44, 0X50, 0X20, 0X53, 0X65,
   0X72, 0X76, 0X65, 0X72, 0X20, 0X54, 0X65, 0X73, 0X74, 0X20, 0X43, 0X65, 0X72, 0X74, 0X69, 0X66,
   0X69, 0X63, 0X61, 0X74, 0X65, 0X30, 0X5C, 0X30, 0X0D, 0X06, 0X09, 0X2A, 0X86, 0X48, 0X86, 0XF7,
   0X0D, 0X01, 0X01, 0X01, 0X05, 0X00, 0X03, 0X4B, 0X00, 0X30, 0X48, 0X02, 0X41, 0X00, 0XA8, 0X24,
   0X5D, 0X65, 0X3B, 0X7C, 0XD1, 0X62, 0X30, 0XC1, 0X75, 0X83, 0X27, 0X74, 0X8D, 0XD9, 0X88, 0X30,
   0X12, 0XD1, 0XD4, 0X15, 0XD5, 0XB4, 0X4F, 0X3F, 0X28, 0XF8, 0X21, 0XCF, 0X8B, 0X83, 0XB0, 0XB4,
   0X62, 0X93, 0XBF, 0X6B, 0XBF, 0XB1, 0XC8, 0XD6, 0X76, 0X5F, 0X13, 0X4D, 0X54, 0X5C, 0XE8, 0X45,
   0XA1, 0X3E, 0XB3, 0X53, 0X6E, 0XDA, 0X91, 0X0F, 0X5F, 0X27, 0XBC, 0X89, 0X26, 0X93, 0X02, 0X03,
   0X01, 0X00, 0X01, 0XA3, 0X23, 0X30, 0X21, 0X30, 0X0E, 0X06, 0X03, 0X55, 0X1D, 0X0F, 0X01, 0X01,
   0XFF, 0X04, 0X04, 0X03, 0X02, 0X02, 0XBC, 0X30, 0X0F, 0X06, 0X03, 0X55, 0X1D, 0X13, 0X01, 0X01,
   0XFF, 0X04, 0X05, 0X30, 0X03, 0X01, 0X01, 0XFF, 0X30, 0X0D, 0X06, 0X09, 0X2A, 0X86, 0X48, 0X86,
   0XF7, 0X0D, 0X01, 0X01, 0X05, 0X05, 0X00, 0X03, 0X41, 0X00, 0XB7, 0X9C, 0X12, 0X51, 0X31, 0X9A,
   0X93, 0XE4, 0X87, 0X34, 0X9A, 0X18, 0X19, 0X9A, 0XB0, 0X2D, 0X80, 0XA5, 0X90, 0XB4, 0XCB, 0X0B,
   0XBF, 0XAE, 0XF7, 0X9C, 0XD9, 0XA9, 0X01, 0XDB, 0XCF, 0XBC, 0X66, 0X30, 0X95, 0X3D, 0X13, 0X96,
   0XE7, 0XBC, 0X27, 0X2F, 0X58, 0X61, 0X36, 0X77, 0X91, 0X19, 0X75, 0X53, 0X3B, 0X44, 0X2C, 0XB5,
   0XAA, 0X96, 0XF7, 0X23, 0X33, 0X96, 0X23, 0X98, 0X22, 0XD7,
/* 16 bytes more says Mr. Heinrich, 22.12.04 KB */
   0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00
};

//static const int ins_pos_public_key = 1214;
//static const int ins_pos_public_key = 1230;
/* displacement 0X0500 = e (public exponent) 3 bytes long, 01 00 01 */
/* 0X02, 0X41, 0X00, at position 1227: 02 = int, 41 = length 64 + 1 leading zero */

static const unsigned char ucrs_rdp_private_key[] = {
   0X56, 0X6C, 0XCA, 0XAC, 0XBC, 0X14, 0XFE, 0X32, 0XF0, 0X48, 0XA0, 0X34, 0X57, 0XD5, 0X6B, 0X0C,
   0X03, 0X1A, 0X62, 0XB2, 0X03, 0XC7, 0X6D, 0X5F, 0X0E, 0XD4, 0XB2, 0X24, 0X48, 0X8C, 0XBB, 0X72,
   0X91, 0X55, 0X76, 0XC5, 0XC0, 0XD7, 0X11, 0X34, 0X7E, 0XFF, 0XC8, 0X22, 0XCB, 0X27, 0X4C, 0XEF,
   0XC0, 0X5C, 0X76, 0XFA, 0XC4, 0XA3, 0X72, 0X27, 0X1E, 0X45, 0XD7, 0XB7, 0X27, 0XB1, 0X42, 0X01
};
#else
//#define D_LEN_CERT_PUBLIC_KEY 64
#define D_POS_CERT_PUBLIC_KEY 638
#define D_LEN_CERT_PUBLIC_KEY 64
//#define D_POS_CERT_EXP        704
//#define D_LEN_CERT_EXP        3

static const unsigned char ucrs_rdp_cert[] = {
   0X02, 0X00, 0X00, 0X00, 0X57, 0X01, 0X00, 0X00, 0X30, 0X82, 0X01,
   0X53, 0X30, 0X82, 0X01, 0X01, 0XA0, 0X03, 0X02, 0X01, 0X02, 0X02, 0X08, 0X01, 0X9D, 0XE9, 0XB1,
   0XD3, 0X32, 0X67, 0X80, 0X30, 0X09, 0X06, 0X05, 0X2B, 0X0E, 0X03, 0X02, 0X1D, 0X05, 0X00, 0X30,
   0X28, 0X31, 0X26, 0X30, 0X0D, 0X06, 0X03, 0X55, 0X04, 0X07, 0X1E, 0X06, 0X00, 0X57, 0X00, 0X54,
   0X00, 0X53, 0X30, 0X15, 0X06, 0X03, 0X55, 0X04, 0X03, 0X1E, 0X0E, 0X00, 0X48, 0X00, 0X4F, 0X00,
   0X42, 0X00, 0X5A, 0X00, 0X30, 0X00, 0X31, 0X00, 0X4B, 0X30, 0X1E, 0X17, 0X0D, 0X37, 0X30, 0X30,
   0X33, 0X31, 0X33, 0X30, 0X30, 0X35, 0X38, 0X35, 0X34, 0X5A, 0X17, 0X0D, 0X34, 0X39, 0X30, 0X33,
   0X31, 0X33, 0X30, 0X30, 0X35, 0X38, 0X35, 0X34, 0X5A, 0X30, 0X28, 0X31, 0X26, 0X30, 0X0D, 0X06,
   0X03, 0X55, 0X04, 0X07, 0X1E, 0X06, 0X00, 0X57, 0X00, 0X54, 0X00, 0X53, 0X30, 0X15, 0X06, 0X03,
   0X55, 0X04, 0X03, 0X1E, 0X0E, 0X00, 0X48, 0X00, 0X4F, 0X00, 0X42, 0X00, 0X5A, 0X00, 0X30, 0X00,
   0X31, 0X00, 0X4B, 0X30, 0X5C, 0X30, 0X0D, 0X06, 0X09, 0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01,
   0X01, 0X01, 0X05, 0X00, 0X03, 0X4B, 0X00, 0X30, 0X48, 0X02, 0X41, 0X00, 0XED, 0XFC, 0X0D, 0XCC,
   0XCD, 0X4D, 0X1E, 0X4C, 0X6B, 0XFC, 0X78, 0X8D, 0XED, 0XB3, 0X8F, 0X33, 0XBE, 0X7A, 0XB8, 0X9E,
   0X71, 0XAC, 0X47, 0XEE, 0X9A, 0XF1, 0X87, 0XC4, 0X85, 0X12, 0X40, 0X59, 0X25, 0X50, 0X56, 0X28,
   0XF2, 0X71, 0X49, 0XC6, 0XE2, 0XD5, 0X40, 0X4B, 0X31, 0X6E, 0X93, 0XA2, 0X13, 0X0D, 0X23, 0XE6,
   0XB7, 0X2F, 0XB2, 0X52, 0X41, 0XD6, 0X6D, 0XA3, 0X62, 0XAF, 0X8B, 0X77, 0X02, 0X03, 0X01, 0X00,
   0X01, 0XA3, 0X13, 0X30, 0X11, 0X30, 0X0F, 0X06, 0X03, 0X55, 0X1D, 0X13, 0X04, 0X08, 0X30, 0X06,
   0X01, 0X01, 0XFF, 0X02, 0X01, 0X00, 0X30, 0X09, 0X06, 0X05, 0X2B, 0X0E, 0X03, 0X02, 0X1D, 0X05,
   0X00, 0X03, 0X41, 0X00, 0X27, 0XD1, 0X1E, 0X18, 0X0F, 0X1A, 0XFB, 0X7D, 0XF8, 0XCB, 0X81, 0XA4,
   0XBF, 0XAE, 0X18, 0X3B, 0X3E, 0XAC, 0XE5, 0XD4, 0X00, 0XB6, 0X90, 0XA2, 0XA6, 0XD9, 0XF1, 0X5F,
   0X6B, 0XD7, 0X0B, 0X68, 0XF6, 0X85, 0XD8, 0XD6, 0XC0, 0X68, 0XB9, 0XAA, 0X90, 0X4F, 0X27, 0XE7,
   0X34, 0X8C, 0X06, 0XC0, 0X14, 0X6F, 0X1A, 0XDC, 0XE0, 0X26, 0X30, 0X51, 0X10, 0X54, 0X66, 0X25,
   0XEB, 0X98, 0XB2, 0X07, 0X69, 0X03, 0X00, 0X00, 0X30, 0X82, 0X03, 0X65, 0X30, 0X82, 0X03, 0X13,
   0XA0, 0X03, 0X02, 0X01, 0X02, 0X02, 0X05, 0X01, 0X00, 0X00, 0X00, 0X01, 0X30, 0X09, 0X06, 0X05,
   0X2B, 0X0E, 0X03, 0X02, 0X1D, 0X05, 0X00, 0X30, 0X28, 0X31, 0X26, 0X30, 0X0D, 0X06, 0X03, 0X55,
   0X04, 0X07, 0X1E, 0X06, 0X00, 0X57, 0X00, 0X54, 0X00, 0X53, 0X30, 0X15, 0X06, 0X03, 0X55, 0X04,
   0X03, 0X1E, 0X0E, 0X00, 0X48, 0X00, 0X4F, 0X00, 0X42, 0X00, 0X5A, 0X00, 0X30, 0X00, 0X31, 0X00,
   0X4B, 0X30, 0X1E, 0X17, 0X0D, 0X38, 0X30, 0X30, 0X31, 0X30, 0X31, 0X30, 0X38, 0X30, 0X30, 0X30,
   0X30, 0X5A, 0X17, 0X0D, 0X33, 0X38, 0X30, 0X31, 0X31, 0X39, 0X30, 0X33, 0X31, 0X34, 0X30, 0X37,
   0X5A, 0X30, 0X81, 0X96, 0X31, 0X81, 0X93, 0X30, 0X25, 0X06, 0X03, 0X55, 0X04, 0X03, 0X1E, 0X1E,
   0X00, 0X6E, 0X00, 0X63, 0X00, 0X61, 0X00, 0X6C, 0X00, 0X72, 0X00, 0X70, 0X00, 0X63, 0X00, 0X3A,
   0X00, 0X48, 0X00, 0X4F, 0X00, 0X42, 0X00, 0X5A, 0X00, 0X30, 0X00, 0X31, 0X00, 0X4B, 0X30, 0X25,
   0X06, 0X03, 0X55, 0X04, 0X07, 0X1E, 0X1E, 0X00, 0X6E, 0X00, 0X63, 0X00, 0X61, 0X00, 0X6C, 0X00,
   0X72, 0X00, 0X70, 0X00, 0X63, 0X00, 0X3A, 0X00, 0X48, 0X00, 0X4F, 0X00, 0X42, 0X00, 0X5A, 0X00,
   0X30, 0X00, 0X31, 0X00, 0X4B, 0X30, 0X43, 0X06, 0X03, 0X55, 0X04, 0X05, 0X1E, 0X3C, 0X00, 0X31,
   0X00, 0X42, 0X00, 0X63, 0X00, 0X4B, 0X00, 0X65, 0X00, 0X58, 0X00, 0X61, 0X00, 0X4A, 0X00, 0X66,
   0X00, 0X61, 0X00, 0X57, 0X00, 0X7A, 0X00, 0X39, 0X00, 0X69, 0X00, 0X50, 0X00, 0X50, 0X00, 0X79,
   0X00, 0X37, 0X00, 0X49, 0X00, 0X4C, 0X00, 0X6C, 0X00, 0X6F, 0X00, 0X51, 0X00, 0X64, 0X00, 0X2F,
   0X00, 0X46, 0X00, 0X59, 0X00, 0X3D, 0X00, 0X0D, 0X00, 0X0A, 0X30, 0X5C, 0X30, 0X0D, 0X06, 0X09,
   0X2A, 0X86, 0X48, 0X86, 0XF7, 0X0D, 0X01, 0X01, 0X04, 0X05, 0X00, 0X03, 0X4B, 0X00, 0X30, 0X48,
   0X02, 0X41, 0X00, 0XD1, 0X3A, 0X18, 0X04, 0X6C, 0X54, 0X6F, 0XD2, 0X86, 0XA6, 0XA3, 0XE8, 0X68,
   0XEB, 0XA5, 0X14, 0XF1, 0XB6, 0X20, 0X32, 0X23, 0X9E, 0XFF, 0X72, 0X2F, 0X0C, 0X59, 0XE8, 0X2C,
   0X1D, 0X50, 0XD5, 0X1D, 0X11, 0XEC, 0X39, 0XEB, 0XFA, 0X81, 0X92, 0X28, 0XB2, 0XAA, 0XB4, 0XA0,
   0X30, 0X90, 0XE1, 0X4E, 0X76, 0XD3, 0XD2, 0X5B, 0XE7, 0X3D, 0X1C, 0XBA, 0X69, 0X74, 0XB4, 0X0A,
   0X3B, 0X48, 0X49, 0X02, 0X03, 0X01, 0X00, 0X01, 0XA3, 0X82, 0X01, 0XB7, 0X30, 0X82, 0X01, 0XB3,
   0X30, 0X14, 0X06, 0X09, 0X2B, 0X06, 0X01, 0X04, 0X01, 0X82, 0X37, 0X12, 0X04, 0X01, 0X01, 0XFF,
   0X04, 0X04, 0X01, 0X00, 0X05, 0X00, 0X30, 0X3C, 0X06, 0X09, 0X2B, 0X06, 0X01, 0X04, 0X01, 0X82,
   0X37, 0X12, 0X02, 0X01, 0X01, 0XFF, 0X04, 0X2C, 0X4D, 0X00, 0X69, 0X00, 0X63, 0X00, 0X72, 0X00,
   0X6F, 0X00, 0X73, 0X00, 0X6F, 0X00, 0X66, 0X00, 0X74, 0X00, 0X20, 0X00, 0X43, 0X00, 0X6F, 0X00,
   0X72, 0X00, 0X70, 0X00, 0X6F, 0X00, 0X72, 0X00, 0X61, 0X00, 0X74, 0X00, 0X69, 0X00, 0X6F, 0X00,
   0X6E, 0X00, 0X00, 0X00, 0X30, 0X81, 0XCD, 0X06, 0X09, 0X2B, 0X06, 0X01, 0X04, 0X01, 0X82, 0X37,
   0X12, 0X05, 0X01, 0X01, 0XFF, 0X04, 0X81, 0XBC, 0X00, 0X30, 0X00, 0X00, 0X01, 0X00, 0X00, 0X00,
   0X02, 0X00, 0X00, 0X00, 0X09, 0X04, 0X00, 0X00, 0X1C, 0X00, 0X4A, 0X00, 0X66, 0X00, 0X4A, 0X00,
   0XB0, 0X00, 0X01, 0X00, 0X33, 0X00, 0X64, 0X00, 0X32, 0X00, 0X36, 0X00, 0X37, 0X00, 0X39, 0X00,
   0X35, 0X00, 0X34, 0X00, 0X2D, 0X00, 0X65, 0X00, 0X65, 0X00, 0X62, 0X00, 0X37, 0X00, 0X2D, 0X00,
   0X31, 0X00, 0X31, 0X00, 0X64, 0X00, 0X31, 0X00, 0X2D, 0X00, 0X62, 0X00, 0X39, 0X00, 0X34, 0X00,
   0X65, 0X00, 0X2D, 0X00, 0X30, 0X00, 0X30, 0X00, 0X63, 0X00, 0X30, 0X00, 0X34, 0X00, 0X66, 0X00,
   0X61, 0X00, 0X33, 0X00, 0X30, 0X00, 0X38, 0X00, 0X30, 0X00, 0X64, 0X00, 0X00, 0X00, 0X33, 0X00,
   0X64, 0X00, 0X32, 0X00, 0X36, 0X00, 0X37, 0X00, 0X39, 0X00, 0X35, 0X00, 0X34, 0X00, 0X2D, 0X00,
   0X65, 0X00, 0X65, 0X00, 0X62, 0X00, 0X37, 0X00, 0X2D, 0X00, 0X31, 0X00, 0X31, 0X00, 0X64, 0X00,
   0X31, 0X00, 0X2D, 0X00, 0X62, 0X00, 0X39, 0X00, 0X34, 0X00, 0X65, 0X00, 0X2D, 0X00, 0X30, 0X00,
   0X30, 0X00, 0X63, 0X00, 0X30, 0X00, 0X34, 0X00, 0X66, 0X00, 0X61, 0X00, 0X33, 0X00, 0X30, 0X00,
   0X38, 0X00, 0X30, 0X00, 0X64, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X10, 0X00, 0X80, 0XD4, 0X00,
   0X00, 0X00, 0X00, 0X00, 0X30, 0X64, 0X06, 0X09, 0X2B, 0X06, 0X01, 0X04, 0X01, 0X82, 0X37, 0X12,
   0X06, 0X01, 0X01, 0XFF, 0X04, 0X54, 0X00, 0X30, 0X00, 0X00, 0X00, 0X00, 0X10, 0X00, 0X40, 0X00,
   0X48, 0X00, 0X4F, 0X00, 0X42, 0X00, 0X5A, 0X00, 0X30, 0X00, 0X31, 0X00, 0X4B, 0X00, 0X00, 0X00,
   0X35, 0X00, 0X31, 0X00, 0X38, 0X00, 0X37, 0X00, 0X36, 0X00, 0X2D, 0X00, 0X32, 0X00, 0X37, 0X00,
   0X30, 0X00, 0X2D, 0X00, 0X39, 0X00, 0X30, 0X00, 0X32, 0X00, 0X39, 0X00, 0X31, 0X00, 0X34, 0X00,
   0X33, 0X00, 0X2D, 0X00, 0X35, 0X00, 0X31, 0X00, 0X34, 0X00, 0X37, 0X00, 0X31, 0X00, 0X00, 0X00,
   0X57, 0X00, 0X54, 0X00, 0X53, 0X00, 0X00, 0X00, 0X00, 0X00, 0X30, 0X27, 0X06, 0X03, 0X55, 0X1D,
   0X23, 0X01, 0X01, 0XFF, 0X04, 0X1D, 0X30, 0X1B, 0XA1, 0X12, 0XA4, 0X10, 0X48, 0X00, 0X4F, 0X00,
   0X42, 0X00, 0X5A, 0X00, 0X30, 0X00, 0X31, 0X00, 0X4B, 0X00, 0X00, 0X00, 0X82, 0X05, 0X01, 0X00,
   0X00, 0X00, 0X01, 0X30, 0X09, 0X06, 0X05, 0X2B, 0X0E, 0X03, 0X02, 0X1D, 0X05, 0X00, 0X03, 0X41,
   0X00, 0X2C, 0XB7, 0X0A, 0X4E, 0XF8, 0XAA, 0X43, 0X34, 0X74, 0XA5, 0XA5, 0X63, 0X3F, 0X4E, 0XFE,
   0X2D, 0X40, 0X36, 0X69, 0XA1, 0X11, 0X58, 0XC9, 0X0C, 0X2D, 0XDE, 0XE3, 0XA6, 0XE8, 0XDD, 0XCE,
   0XB6, 0X93, 0XC2, 0XF4, 0X27, 0XAF, 0XA5, 0XF1, 0XD8, 0XCB, 0XC2, 0X41, 0X8E, 0X7B, 0XC9, 0XD2,
   0X68, 0XD8, 0X8C, 0XFD, 0X0F, 0XEF, 0XF0, 0X5B, 0X7B, 0XA9, 0X2E, 0X83, 0XB1, 0XBB, 0X80, 0X6A,
   0X10, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00,
   0X00
};

static const unsigned char ucrs_rdp_private_key[] = {
   0XB8, 0X4B, 0X22, 0XA2, 0XAA, 0XC5, 0X49, 0X66, 0X38, 0X63, 0X0A, 0X57, 0X8A, 0X2B, 0X9E, 0XD2,
   0XAF, 0X02, 0X4C, 0XA3, 0XBD, 0X8A, 0XAC, 0XD9, 0X68, 0X25, 0XC9, 0XFF, 0XDE, 0XF3, 0XC7, 0XA1,
   0X07, 0X12, 0XE8, 0X9F, 0XCA, 0X41, 0X52, 0XA5, 0XCD, 0X51, 0X95, 0XD2, 0X3C, 0XF5, 0XA0, 0X5C,
   0X6D, 0X7A, 0XCE, 0X08, 0X9E, 0XB9, 0X58, 0XC3, 0X19, 0X4B, 0X42, 0X4B, 0X62, 0X23, 0X94, 0X6D
};
#endif

static const char chrs_zeroes[] = { 0, 0, 0, 0 };  /* zeroes for padding */

#ifdef TRACEHL_COM1
static int ims_no_order = 0;                /* count orders            */
#endif

static BOOL m_send_cl_r04( struct dsd_hl_clib_1 *, struct dsd_output_area_1 * );
static void m_gen_keys( struct dsd_hl_clib_1 *, char *, struct dsd_rdp_co *, char * );
static BOOL m_prepare_keys( struct dsd_hl_clib_1 *, struct dsd_rdp_co * );
static void m_update_keys( struct dsd_rdp_co *, struct dsd_rdp_encry *, char * );
static void m_gen_lic_keys( struct dsd_rdp_lic_d *, char * );
static BOOL m_check_hash_inp_rdp5( struct dsd_hl_clib_1 *adsp_hl_clib_1, char *achp_data, int imp_len_data );
static BOOL m_send_cl2se_rdp5( struct dsd_hl_clib_1 *,
                               struct dsd_output_area_1 *, char *, int, int );
static BOOL m_send_se2cl_const( struct dsd_hl_clib_1 *, struct dsd_output_area_1 *, char *, int );
static BOOL m_send_vch_out( struct dsd_hl_clib_1 *,
                            struct dsd_output_area_1 *,
                            struct dsd_rdp_vch_io *,
                            char * );
static BOOL m_send_vch_tose( struct dsd_hl_clib_1 *,
                             struct dsd_output_area_1 *,
                             struct dsd_rdp_vch_io *,
                             char * );
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
static int m_sdh_printf( struct dsd_hl_clib_1 *, char *, ... );
static void m_sdh_console_out( struct dsd_hl_clib_1 *, char *achp_buff, int implength );
static char * m_ret_t_ied_fcfp_bl( ied_fcfp_bl );
static char * m_ret_t_ied_fsfp_bl( ied_fsfp_bl );
static char * m_ret_t_ied_frcl_bl( ied_frcl_bl );
static char * m_ret_t_ied_frse_bl( ied_frse_bl );

static unsigned char ucrs_send_session_end[] = {
   0X03, 0X00, 0X00, 0X09, 0X02, 0XF0, 0X80, 0X20, 0X80
};


/** subroutine to process the copy library function                    */
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variables */
   int        iml_rec;                      /* data received remaining */
   int        iml_line_no;                  /* line number for errors  */
   int        iml_source_no;                /* source line no for errors */
   char       chl_w1;                       /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
   char       *achl3, *achl4;               /* working variables       */
   BOOL       bol_compressed;               /* save compressed         */
   BOOL       bol_encrypted;                /* packet is encrypted     */
   struct dsd_output_area_1 dsl_output_area_1;  /* output of subroutine */
   struct dsd_gather_i_1 *adsl_gai1_inp_1;  /* input data              */
   struct dsd_gather_i_1 *adsl_gai1_inp_w2;  /* input data             */
// struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
   struct dsd_sc_draw_sc dsl_sc_draw_sc;    /* draw on screen          */
   struct dsd_gather_i_1 dsl_gai1_comp_data;  /* compressed data       */
   struct dsd_gather_i_1 *adsl_gai1_inp_save_compr;  /* save current gather input */
   int        iml_compr_len;                /* length compressed       */
   int        iml_compr_inp;                /* input to compression    */
   struct dsd_gather_i_1 **aadsl_gai1_ch;   /* create chain gather data */
   char       *achl_out_1;                  /* output-area             */
   int        iml_out_len;                  /* length output           */
   struct dsd_aux_get_workarea dsl_aux_get_workarea;  /* acquire additional work area */
   struct dsd_gather_i_1 *adsl_gai1_out_save;  /* output data          */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* chain of data           */
   struct dsd_gather_i_1 *adsl_gai1_w2;     /* chain of data           */
   struct dsd_gather_i_1 dsl_gai1_start_rec;  /* start of record       */
   char       chrl_work_trace[ 256 ];       /* work area trace         */
   void *     al_chain_send_tose;           /* chain of buffers to be sent to the server */
   void *     al_chain_send_frse;           /* chain of buffers to be sent to the client */
   struct dsd_rdp_param_vch_1 dsl_rdp_param_vch_1;  /* RDP parameters virus checking */
   enum ied_sdh_ret1 iel_sdh_ret1;          /* return code Server-Data-Hook */
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_rdp_server_1 *D_ADSL_RSE1;
   struct dsd_rdp_client_1 *D_ADSL_RCL1;
   struct dsd_rdp_co *D_ADSL_RCO1;  /* RDP communication client */
   struct dsd_output_area_1 *ADSL_OA1;
#endif
   char       *achl_inp_start;              /* start of input area     */
   char       chrl_work_1[ D_MAX_CRYPT_LEN ];  /* work area            */
   char       chrl_work_2[ 65536 ];         /* work area               */

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
                       __LINE__, 9849 );
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
     case DEF_IFUNC_FROMSERVER:
       goto pfrse00;                        /* from server             */
     case DEF_IFUNC_TOSERVER:
       goto ptose00;                        /* to server               */
     case DEF_IFUNC_CLOSE:
       if (adsp_hl_clib_1->ac_ext == NULL) return;
       /* get pointer to virtual channel structure                     */
       memset( &dsl_rdp_param_vch_1, 0, sizeof(struct dsd_rdp_param_vch_1) );  /* clear RDP parameters virus checking */
       dsl_rdp_param_vch_1.adsc_conf = (struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf;  /* configuration data */
       memcpy( &dsl_rdp_param_vch_1.dsc_s1, &ADSL_RDPA_F->dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
       dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */
       goto p_cleanup_00;                   /* do cleanup now          */
     default:
       m_sdh_printf( adsp_hl_clib_1, "xlrdpa1-l%05d-W m_hlclib01() called inc_func=%d - value invalid",
                     __LINE__, adsp_hl_clib_1->inc_func );
       return;
   }

   pfsta00:                                 /* start communication     */
#ifdef D_FFLUSH                             /* 30.05.05 KB - flush stdout */
   setbuf( stdout, 0 );
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
   memset( &dsl_rdp_param_vch_1, 0, sizeof(struct dsd_rdp_param_vch_1) );  /* clear RDP parameters virus checking */
   dsl_rdp_param_vch_1.adsc_conf = (struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf;  /* configuration data */
   dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */
   bol1 = m_rdp_vch1_init( &dsl_rdp_param_vch_1 );
   if (bol1 == FALSE) {                     /* init failed             */
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d init processing virtual channels failed",
                   __LINE__, 9966 );  /* line number for errors */
     goto p_cleanup_00;                     /* do cleanup now          */
   }
   memcpy( &ADSL_RDPA_F->dsc_s1, &dsl_rdp_param_vch_1.dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
   ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl = ied_fcfp_rec_type;  /* first record type */
   ADSL_RDPA_F->dsc_rdp_se_1.iec_frcl_bl = ied_frcl_start;  /* receive block from client */
// ADSL_RDPA_F->dsc_rdp_se_1.imc_pos_inp_frame = 0;  /* start of frame */
// ADSL_RDPA_F->iec_frse_bl = ied_frse_start;  /* receive block from server */
// ADSL_RDPA_F->inc_send_client_len = 0;    /* send nothing to client  */
   ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl = ied_frse_start;  /* receive block from client */
   ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl = ied_fsfp_invalid;  /* invalid data received */
#define ADSL_AGSI_G ((struct dsd_aux_get_session_info *) chrl_work_2)
   bol1 = adsp_hl_clib_1->amc_aux( adsp_hl_clib_1->vpc_userfld,
                                   DEF_AUX_GET_SESSION_INFO,  /* get information about the session */
                                   ADSL_AGSI_G,  /* get information about the session */
                                   sizeof(struct dsd_aux_get_session_info) );
   if (bol1 == FALSE) {                     /* aux returned error      */
     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
     return;
   }
   if (ADSL_AGSI_G->iec_scp_def == ied_scp_hrdpe1) {  /* protocol HOB MS RDP Extension 1 */
     ADSL_RDPA_F->boc_scp_hrdpe1 = TRUE;      /* protocol HOB MS RDP Ext 1 */
     ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl = ied_fsfp_rec_type;  /* get type of record */
   }
#undef ADSL_AGSI_G
// ADSL_RDPA_F->dsc_rdp_cl_1.imc_pos_inp_frame = 0;  /* start of frame */
// ADSL_RDPA_F->iec_frcl_bl = ied_frcl_start;  /* receive block from client */
// ADSL_RDPA_F->inc_send_server_len = 0;    /* send nothing to client  */
   return;

   pfrse00:                                 /* from server - to client */
   /* prepare area to send to client                                   */
   ADSL_OA1->achc_lower = adsp_hl_clib_1->achc_work_area;  /* addr work-area */
   ADSL_OA1->achc_upper = ADSL_OA1->achc_lower + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   al_chain_send_frse = NULL;               /* chain of buffers to be sent to the client */
   /* prepare Trace-Area                                               */
   ADSL_RDPA_F->dsc_rdptr1.adsc_hl_clib_1 = adsp_hl_clib_1;
   ADSL_RDPA_F->dsc_rdptr1.imc_trace_level = adsp_hl_clib_1->imc_trace_level;  /* WSP trace level */
   ADSL_RDPA_F->dsc_rdptr1.imc_sno = adsp_hl_clib_1->imc_sno;  /* session number */
// to-do 20.04.12 KB - afterwards again
   ADSL_OA1->aadsc_gai1_out_to_server = &adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_client = &adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */
   ADSL_OA1->aadsc_gai1_out_to_server = &adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   if (adsp_hl_clib_1->adsc_gather_i_1_in == NULL) goto pfrse80;
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
#ifndef HL_RDPACC_HELP_DEBUG
#define D_ADSL_RCL1 (&ADSL_RDPA_F->dsc_rdp_cl_1)
#define D_ADSL_RCO1 (&D_ADSL_RCL1->dsc_rdp_co_1)
#else
// ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
   D_ADSL_RCL1 = &ADSL_RDPA_F->dsc_rdp_cl_1;
   D_ADSL_RCO1 = &D_ADSL_RCL1->dsc_rdp_co_1;
#endif


   memset( &dsl_gai1_comp_data, 0, sizeof(struct dsd_gather_i_1) );  /* compressed data */
   /* get pointer to virtual channel structure                         */
   memset( &dsl_rdp_param_vch_1, 0, sizeof(struct dsd_rdp_param_vch_1) );  /* clear RDP parameters virus checking */
   dsl_rdp_param_vch_1.adsc_conf = (struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf;  /* configuration data */
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   memcpy( &dsl_rdp_param_vch_1.dsc_s1, &ADSL_RDPA_F->dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
   //dsl_rdp_param_vch_1.adsc_cb_c = ADSL_RDPA_F->adsc_cb_c;  /* cliprdr flags */
   dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */
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
   goto pfrse80;                            /* search what to send     */

   pfrse24:                                 /* data to process found   */
   if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
     ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
       = ied_trc_se2cl_msg;                 /* server to client message */
     ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = NULL;
     ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = 0;  /* length of record */
     ADSL_RDPA_F->dsc_rdptr1.achc_trace_input = chrl_work_trace;  /* work area trace */
     sprintf( chrl_work_trace, "se2cl l%05d s%05d process input iec_frse_bl=%d %s + iec_fsfp_bl=%d %s addr=%p pos=%04X cont=%02X.",
              __LINE__, 10486,
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
         iml_source_no = 10542;    /* source line no for errors */
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
         iml_source_no = 10691;    /* source line no for errors */
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
         iml_source_no = 10727;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 10735;    /* source line no for errors */
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
         iml_source_no = 10745;    /* source line no for errors */
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
         iml_source_no = 10869;    /* source line no for errors */
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
         iml_source_no = 10883;    /* source line no for errors */
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
         iml_source_no = 10908;    /* source line no for errors */
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
         iml_source_no = 10928;    /* source line no for errors */
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
         iml_source_no = 10963;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 10968;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_type_pub_par;  /* block 4 type public parameters */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_ppdir_len:       /* block 4 public parms direct lenght */
           if (D_ADSL_RCL1->imc_prot_5 == 0) {  /* was first parameter */
             if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {
         iml_line_no = __LINE__;
         iml_source_no = 11034;    /* source line no for errors */
         goto pfrse92;
             }
             D_ADSL_RCL1->imc_prot_5 = D_ADSL_RCL1->imc_prot_4;
             D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_ppdir_tag;  /* get public parms direct tag */
             D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
             if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 11040;    /* source line no for errors */
         goto pfrse92;
             }
             D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RCL1->imc_prot_1 = 0;   /* clear value             */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
             goto pfrse20;                  /* process next data       */
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame > 0) {  /* more data in block */
         iml_line_no = __LINE__;
         iml_source_no = 11048;    /* source line no for errors */
         goto pfrse92;
           }
/* maybe other sequence of tags */
           {
             if (memcmp( D_ADSL_RCL1->chrc_prot_1, "RSA1", 4)) {
         iml_line_no = __LINE__;
         iml_source_no = 11056;    /* source line no for errors */
         goto pfrse92;
             }
             iml1 = m_get_le4( D_ADSL_RCL1->chrc_prot_1 + 4 );
             if (iml1 != (D_ADSL_RCL1->imc_prot_6 - 20)) {
         iml_line_no = __LINE__;
         iml_source_no = 11060;    /* source line no for errors */
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
         iml_source_no = 11098;    /* source line no for errors */
         goto pfrse92;
             }
             if (iml1 > (iml5 + D_RSA_KEY_PADDING)) {  /* too many leading bytes */
         iml_line_no = __LINE__;
         iml_source_no = 11101;    /* source line no for errors */
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
         iml_source_no = 11115;    /* source line no for errors */
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
             /* set constants                                          */
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imc_keytype = ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_keytype;
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imc_sec_level = ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_sec_level;
#define ADSL_RDPVCH1_CONFIG ((struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf)
             if (ADSL_RDPVCH1_CONFIG->imc_enc2cl > 0) {  /* encryption-to-client configured */
               ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imc_sec_level
                 = ADSL_RDPVCH1_CONFIG->imc_enc2cl;
             }
#undef ADSL_RDPVCH1_CONFIG
             m_send_cl_r04( adsp_hl_clib_1, ADSL_OA1 );  /* send block 04 to client */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_rec_07;
#ifdef TRACEHL1
             if (ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl != ied_fcfp_invalid) {  /* receive record type */
               printf( "after block 4 from server not correct state client\n" );
               goto pfrse96;                /* program illogic         */
             }
#endif
             ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
           goto pfrse20;                    /* process next data       */
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
         iml_source_no = 11360;    /* source line no for errors */
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
         iml_source_no = 11369;    /* source line no for errors */
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
         iml_source_no = 11379;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) < 0) {  /* MSB set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
           }
           /* skip length TBS certificate                              */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11387;    /* source line no for errors */
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
         iml_source_no = 11393;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11393;    /* source line no for errors */
         goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
         iml_line_no = __LINE__;
         iml_source_no = 11393;    /* source line no for errors */
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
         iml_source_no = 11395;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11395;    /* source line no for errors */
         goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
         iml_line_no = __LINE__;
         iml_source_no = 11395;    /* source line no for errors */
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
         iml_source_no = 11397;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11397;    /* source line no for errors */
         goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
         iml_line_no = __LINE__;
         iml_source_no = 11397;    /* source line no for errors */
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
         iml_source_no = 11399;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11399;    /* source line no for errors */
         goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
         iml_line_no = __LINE__;
         iml_source_no = 11399;    /* source line no for errors */
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
         iml_source_no = 11401;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11401;    /* source line no for errors */
         goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
         iml_line_no = __LINE__;
         iml_source_no = 11401;    /* source line no for errors */
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
         iml_source_no = 11403;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11403;    /* source line no for errors */
         goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
         iml_line_no = __LINE__;
         iml_source_no = 11403;    /* source line no for errors */
         goto pfrse92;
             }
             iml3 += iml4;                  /* add length of this field */
           }
           /* end of macro to skip one ASN.1 field                     */
           /* skip length subjectPublicKeyInfo                         */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11407;    /* source line no for errors */
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
         iml_source_no = 11413;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) >= 0) {  /* MSB not set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1);  /* add integer value */
           } else {                         /* MSB set, multiple integer digits */
             iml2 = iml3;                   /* save current position   */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer bytes */
             if (iml3 > iml1) {             /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11413;    /* source line no for errors */
         goto pfrse92;
             }
             iml4 = 0;                      /* clear result            */
             while (iml2 < iml3) {          /* loop over integer digits */
               iml4 <<= 8;                  /* shift old value         */
               iml4 |= *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml2++);
             }
             if (((unsigned int) iml4 > iml1)) {  /* greater length of this buffer */
         iml_line_no = __LINE__;
         iml_source_no = 11413;    /* source line no for errors */
         goto pfrse92;
             }
             iml3 += iml4;                  /* add length of this field */
           }
           /* end of macro to skip one ASN.1 field                     */
           /* skip length subjectPublicKey                             */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11417;    /* source line no for errors */
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
         iml_source_no = 11426;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((signed char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) < 0) {  /* MSB set */
             iml3 += *((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 1) & 0X7F;  /* add integer digits */
           }
           /* now Exponent                                             */
           iml3 += 2;                       /* add Tag Length one Byte */
           if (iml3 > iml1) {               /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11434;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 2) != 0X02) {
         iml_line_no = __LINE__;
         iml_source_no = 11437;    /* source line no for errors */
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
         iml_source_no = 11450;    /* source line no for errors */
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
         iml_source_no = 11479;    /* source line no for errors */
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
         iml_source_no = 11490;    /* source line no for errors */
         goto pfrse92;
           }
           if (iml4 > (iml5 + 2)) {         /* too many leading bytes  */
         iml_line_no = __LINE__;
         iml_source_no = 11493;    /* source line no for errors */
         goto pfrse92;
           }
           /* check if leading bytes are zero                          */
           while (iml4 > iml5) {            /* remove leading zeroes */
             if (*((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3) != 0)  {  /* check zero */
         iml_line_no = __LINE__;
         iml_source_no = 11498;    /* source line no for errors */
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
         iml_source_no = 11515;    /* source line no for errors */
         goto pfrse92;
           }
           if (*((unsigned char *) D_ADSL_RCL1->ac_temp_buffer + iml3 - 2) != 0X02) {
         iml_line_no = __LINE__;
         iml_source_no = 11518;    /* source line no for errors */
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
         iml_source_no = 11531;    /* source line no for errors */
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
         iml_source_no = 11540;    /* source line no for errors */
         goto pfrse92;
           }
           if ((iml3 + iml4) > iml1) {      /* after end of buffer     */
         iml_line_no = __LINE__;
         iml_source_no = 11543;    /* source line no for errors */
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
           /* certificate now processed                                */
           if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* end of block */
             if (D_ADSL_RCL1->imc_prot_4 != 7) {  /* not all fields received */
         iml_line_no = __LINE__;
         iml_source_no = 11556;    /* source line no for errors */
         goto pfrse92;
             }
             /* set constants                                          */
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imc_keytype = ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_keytype;
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imc_sec_level = ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_sec_level;
#define ADSL_RDPVCH1_CONFIG ((struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf)
             if (ADSL_RDPVCH1_CONFIG->imc_enc2cl > 0) {  /* encryption-to-client configured */
               ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imc_sec_level
                 = ADSL_RDPVCH1_CONFIG->imc_enc2cl;
             }
#undef ADSL_RDPVCH1_CONFIG
             m_send_cl_r04( adsp_hl_clib_1, ADSL_OA1 );  /* send block 04 to client */
//           D_ADSL_RCL1->iec_frse_bl = ied_frse_rec_type;  /* start of record follows */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_invalid;  /* invalid data received */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_rec_07;
             ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
             goto pfrse20;                  /* process next data       */
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 11641;    /* source line no for errors */
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
         iml_source_no = 11651;    /* source line no for errors */
         goto pfrse92;
               }
               if (D_ADSL_RCL1->achc_prot_1 < (D_ADSL_RCL1->chrc_prot_1 + 16)) {
         iml_line_no = __LINE__;
         iml_source_no = 11654;    /* source line no for errors */
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
         iml_source_no = 11669;    /* source line no for errors */
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
         iml_source_no = 11678;    /* source line no for errors */
         goto pfrse92;
           }
           /* check if till end of capabilities                        */
           if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_4) {
         iml_line_no = __LINE__;
         iml_source_no = 11688;    /* source line no for errors */
         goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame != 4) {
         iml_line_no = __LINE__;
         iml_source_no = 11691;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = 0;     /* number of bytes         */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_big_e;  /* int big endian */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_trail;  /* trailer of act PDU */
           goto pfrse20;                    /* process next data       */
         case ied_frse_rdp4_vch_ulen:       /* virtual channel uncompressed data length */
           goto pfrse_vch_00;               /* virtual channel data received */
         case ied_frse_lic_pr_req_rand:  /* server license request (after) random */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 11998;    /* source line no for errors */
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
         iml_source_no = 12034;    /* source line no for errors */
         goto pfrse92;
             }
           }
           if (iml2 == 0) {                 /* no special licensing certificate given */
             D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_exp = ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp;
             D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_exp_len = sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp);
             D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_key = ADSL_RDPA_F->dsc_rdp_cl_1.achc_cert_key;  /* RSA key */
             D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len = ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key;  /* length RSA key */
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
             goto pfrse40;                  /* send RDP4 to client     */
           }
           D_ADSL_RCL1->imc_prot_6 = D_ADSL_RCL1->imc_pos_inp_frame - iml2;
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12061;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_type_pub_par;  /* licensing certificate, parsed like block 4 type public parameters */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                    /* process next data       */
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
#ifdef TRACEHL1_LIC
           printf( "l%05d s%05d decrypted challenge teststring.\n",
                   __LINE__, 12102 );
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
                     12120,        /* source line no for errors */
                     __LINE__ );            /* line number for errors  */
#endif
             /* [MS-RDPELE] 3.1.5.1 says the client MUST send a LICENSE_ERROR_MESSAGE - see [MS-RDPBCGR] 2.2.1.12.1.3
             memcpy( chrl_work_2, ucrs_lic_err_hash, sizeof(ucrs_lic_err_hash) );
             m_put_be2( chrl_work_2 + 8, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
             m_put_be2( chrl_work_2 + 10, D_DISPLAY_CHANNEL );
             ... XXX how to send something and after that exit with an error? */
         iml_line_no = __LINE__;
         iml_source_no = 12130;    /* source line no for errors */
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
         case ied_frse_hrdpext1_01:         /* HOB-RDP-EXT1 data       */
           goto p_frse_send_hrdpext1;       /* send data to client     */
       }
         iml_line_no = __LINE__;
         iml_source_no = 12374;    /* source line no for errors */
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
         iml_source_no = 12394;    /* source line no for errors */
         goto pfrse92;
         }
         adsl_gai1_inp_1->achc_ginp_cur++;  /* next character input    */
         iml1--;                            /* decrement count         */
       } while (iml1 > 0);
       if (D_ADSL_RCL1->imc_pos_inp_frame > D_ADSL_RCL1->imc_prot_count_in) {
         goto pfrse20;                      /* needs more data         */
       }
//       case ied_frse_deaap_rec:           /* Deactivate All PDU Data */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_act_pdu_rec;  /* receive block active PDU */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
           goto pfrse20;                    /* process next data       */
     case ied_fsfp_r04_rdp_v:               /* block 4 RDP version     */
       if (*adsl_gai1_inp_1->achc_ginp_cur != 0X04) {
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d invalid RDP version %02X.",
                       __LINE__, 12436,  /* line number for errors */
                       (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur );
         iml_line_no = __LINE__;
         iml_source_no = 12439;    /* source line no for errors */
         goto pfrse92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RCL1->imc_pos_inp_frame--;    /* length constant         */
       if (D_ADSL_RCL1->imc_prot_2 >= D_ADSL_RCL1->imc_pos_inp_frame) {
         iml_line_no = __LINE__;
         iml_source_no = 12444;    /* source line no for errors */
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
         iml_source_no = 12486;    /* source line no for errors */
         goto pfrse92;
         case 0X03:                         /* RDP 4 record            */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_byte01;  /* receive byte 01 */
           break;
         default:
         iml_line_no = __LINE__;
         iml_source_no = 12491;    /* source line no for errors */
         goto pfrse92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_byte01:                  /* receive byte 01         */
       if (*adsl_gai1_inp_1->achc_ginp_cur) {
         while (ADSL_RDPA_F->boc_scp_hrdpe1) {  /* protocol HOB MS RDP Ext 1 */
           if (((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur) != 0XFF) break;
           if (D_ADSL_RCL1->imc_pos_inp_frame) break;  /* already len frame */
           if (D_ADSL_RCL1->iec_frse_bl != ied_frse_start) break;  /* start of communication */
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_lenext_2;  /* receive len c */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear length field      */
           D_ADSL_RCL1->imc_pos_inp_frame = 0;  /* no length frame yet */
           goto pfrse20;                    /* process next data       */
         }
         iml_line_no = __LINE__;
         iml_source_no = 12527;    /* source line no for errors */
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
         iml_source_no = 12604;    /* source line no for errors */
         goto pfrse92;
         }
#ifdef HL_RDPACC_HELP_DEBUG
         D_ADSL_RCO1->imc_debug_reclen = D_ADSL_RCL1->imc_prot_1;
#endif
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r4_collect;  /* RDP 4 collect data */
         goto pfrse20;                      /* process next data       */
       } else {
         D_ADSL_RCL1->imc_pos_inp_frame -= 2;  /* adjust length remaining */
         if (D_ADSL_RCL1->imc_pos_inp_frame < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12616;    /* source line no for errors */
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
         iml_source_no = 12640;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_x224_p01;  /* is in x224 header */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* position                */
           goto pfrse20;                    /* process next data       */
//       default:
//         goto pfrse96;                    /* program illogic         */
       }
         iml_line_no = __LINE__;
         iml_source_no = 12648;    /* source line no for errors */
         goto pfrse96;
     case ied_fsfp_lenext_2:                /* two bytes length remaining HOB-RDP-EXT1 */
       D_ADSL_RCL1->imc_prot_1 <<= 8;
       D_ADSL_RCL1->imc_prot_1
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_lenext_1;  /* receive len c */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_lenext_1:                /* one byte length remaining HOB-RDP-EXT1 */
       D_ADSL_RCL1->imc_prot_1 <<= 8;
       D_ADSL_RCL1->imc_prot_1
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame = D_ADSL_RCL1->imc_prot_1 - 4;
       if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12662;    /* source line no for errors */
         goto pfrse92;
       }
       if (D_ADSL_RCL1->imc_pos_inp_frame > sizeof(D_ADSL_RCL1->chrc_prot_1)) {
         iml_line_no = __LINE__;
         iml_source_no = 12665;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_prot_1;
       D_ADSL_RCL1->imc_prot_2 = 0;         /* till end of block       */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data         */
       D_ADSL_RCL1->iec_frse_bl = ied_frse_hrdpext1_01;  /* HOB-RDP-EXT1 data */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_r4_collect:              /* RDP 4 collect data      */
       /* check if all data of this frame have been received           */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data in frame */
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
       /* start of record                                              */
       if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
         memset( &dsl_gai1_start_rec, 0, sizeof(struct dsd_gather_i_1) );
         dsl_gai1_start_rec.achc_ginp_cur = D_ADSL_RCO1->chrc_start_rec;
         dsl_gai1_start_rec.achc_ginp_end = D_ADSL_RCO1->chrc_start_rec + D_ADSL_RCO1->imc_len_start_rec;
         dsl_gai1_start_rec.adsc_next = adsl_gai1_inp_1;
         ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
           = ied_trc_recv_server;           /* received from server    */
         ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = &dsl_gai1_start_rec;
         ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RCO1->imc_len_record;  /* length of record */
         m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_start:
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
         iml_source_no = 12740;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_x224_p01;  /* is in x224 header */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* position                */
           goto pfrse20;                    /* process next data       */
//       default:
//         goto pfrse96;                    /* program illogic         */
       }
         iml_line_no = __LINE__;
         iml_source_no = 12748;    /* source line no for errors */
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
         iml_source_no = 12759;    /* source line no for errors */
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
         iml_source_no = 12804;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_1 = (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur;
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12816;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_end_com;  /* end of communication */
           goto pfrse20;                    /* process next data       */
         case 0X2E:                         /* MCS Attach User reply   */
           if (D_ADSL_RCL1->iec_frse_bl != ied_frse_rec_07) {
         iml_line_no = __LINE__;
         iml_source_no = 12822;    /* source line no for errors */
         goto pfrse92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12827;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_status;  /* status from server */
           goto pfrse20;                    /* process next data       */
         case 0X3E:                         /* MCS channel join response */
           if (D_ADSL_RCL1->iec_frse_bl != ied_frse_cjresp_rec) {
         iml_line_no = __LINE__;
         iml_source_no = 12833;    /* source line no for errors */
         goto pfrse92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12838;    /* source line no for errors */
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
         iml_source_no = 12850;    /* source line no for errors */
         goto pfrse92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12855;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12859;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_userid_se2cl;  /* userid communication follows */
           goto pfrse20;                    /* process next data       */
         case 0X7F:                         /* MCS connect reply       */
           if (D_ADSL_RCL1->iec_frse_bl != ied_frse_rec_04) {
         iml_line_no = __LINE__;
         iml_source_no = 12866;    /* source line no for errors */
         goto pfrse92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RCL1->imc_pos_inp_frame--;  /* length constant       */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_mcs_c2;  /* MCS command 2 */
           goto pfrse20;                    /* process next data       */
       }
         iml_line_no = __LINE__;
         iml_source_no = 12873;    /* source line no for errors */
         goto pfrse92;
     case ied_fsfp_mcs_c2:                  /* MCS command 2           */
       switch (*adsl_gai1_inp_1->achc_ginp_cur) {
         case 0X66:                         /* MCS connect reply       */
           if (D_ADSL_RCL1->iec_frse_bl != ied_frse_rec_04) {
         iml_line_no = __LINE__;
         iml_source_no = 12885;    /* source line no for errors */
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
         iml_source_no = 12903;    /* source line no for errors */
         goto pfrse92;
     case ied_fsfp_status:                  /* status from server      */
       if (*adsl_gai1_inp_1->achc_ginp_cur) {
         iml_line_no = __LINE__;
         iml_source_no = 12913;    /* source line no for errors */
         goto pfrse92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RCL1->imc_pos_inp_frame--;    /* length constant         */
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_rec_07:
           if (D_ADSL_RCL1->imc_pos_inp_frame != 2) {
         iml_line_no = __LINE__;
         iml_source_no = 12920;    /* source line no for errors */
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
         iml_source_no = 12929;    /* source line no for errors */
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
         iml_source_no = 12963;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12967;    /* source line no for errors */
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
         iml_source_no = 12990;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 12994;    /* source line no for errors */
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
         iml_source_no = 13028;    /* source line no for errors */
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
         iml_source_no = 13041;    /* source line no for errors */
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
         iml_source_no = 13050;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_mu_len_1;  /* multi length 1 */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_rt02:                    /* record type 2           */
       D_ADSL_RCL1->chc_prot_rt02 = *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13058;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rt03;  /* record type 3     */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_rt03:                    /* record type 3           */
       D_ADSL_RCL1->chc_prot_rt03 = *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13184;    /* source line no for errors */
         goto pfrse92;
       }
       /* two bytes padding follow - to be ignored                     */
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13189;    /* source line no for errors */
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
       if (   (D_ADSL_RCL1->chc_prot_rt02 & SEC_ENCRYPT)  /* block encrypted */
           || (D_ADSL_RCL1->chc_prot_rt03 & (SEC_REDIRECTION_PKT >> 8))) {  /* Standard Security Server Redirection PDU */
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - D_SIZE_HASH;
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13214;    /* source line no for errors */
         goto pfrse92;
         }
         D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_prot_1;
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rdp4_hash;  /* hash RDP4 block */
         goto pfrse20;                        /* process next data       */
       }
       if (D_ADSL_RCL1->chc_prot_rt02 & 0X80) {  /* SEC_LICENSE_PKT    */
         if (   (D_ADSL_RCL1->iec_frse_bl != ied_frse_lic_pr_1_rec)  /* receive block licence protocol */
             && (D_ADSL_RCL1->iec_frse_bl != ied_frse_any_pdu_rec)) {  /* ????ive block active PDU */
         iml_line_no = __LINE__;
         iml_source_no = 13229;    /* source line no for errors */
         goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes (preamble header) */
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13241;    /* source line no for errors */
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
         case ied_frse_any_pdu_rec:         /* ????ive block active PDU */
           if (D_ADSL_RCL1->imc_prot_chno == D_ADSL_RCO1->usc_chno_disp) {  /* channel number display  */
             D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
             if (D_ADSL_RCL1->imc_prot_count_in < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13271;    /* source line no for errors */
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
         iml_source_no = 13281;    /* source line no for errors */
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
         iml_source_no = 13298;    /* source line no for errors */
         goto pfrse96;
       }
       if ((D_ADSL_RCL1->chc_prot_rt02 & 0XF7) == 0) {
         D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
         if (D_ADSL_RCL1->imc_prot_count_in < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13348;    /* source line no for errors */
         goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
         D_ADSL_RCL1->imc_prot_akku = 0;    /* clear value             */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sch_len;  /* Share Control Header length */
         goto pfrse20;                      /* process next data       */
       }
         iml_line_no = __LINE__;
         iml_source_no = 13359;    /* source line no for errors */
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
                 13391,            /* source line no for errors */
                 __LINE__,                  /* line number for errors  */
                 iml1 );                    /* length of data needed   */
#endif
           /* wait for more data                                       */
           goto p_ret_00;                   /* check how to return     */
         }
       }
#ifdef TRACEHL1
       printf( "s%05d l%05d received from server encrypted 26.10.06 KB\n",
               13401,              /* source line no for errors */
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
         iml_source_no = 13423;    /* source line no for errors */
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
                       __LINE__, 13485 );  /* line number for errors  */
         iml_line_no = __LINE__;
         iml_source_no = 13487;    /* source line no for errors */
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
         iml_source_no = 13530;    /* source line no for errors */
         goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes (preamble header) */
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13542;    /* source line no for errors */
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
           if (D_ADSL_RCL1->imc_prot_chno == D_ADSL_RCO1->usc_chno_disp) {  /* channel number display  */
             break;                         /* parse Share Control Header */
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13574;    /* source line no for errors */
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
         iml_source_no = 13590;    /* source line no for errors */
         goto pfrse96;
       }
       if (D_ADSL_RCL1->chc_prot_rt03 & (SEC_REDIRECTION_PKT >> 8)) {  /* Standard Security Server Redirection PDU */
         D_ADSL_RCL1->iec_frse_bl = ied_frse_xyz_end_pdu;  /* end of PDU */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
         goto pfrse40;                      /* send RDP4 to client     */
       }
       if ((D_ADSL_RCL1->chc_prot_rt02 & 0XF7) == 0) {
         D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
         if (D_ADSL_RCL1->imc_prot_count_in < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13668;    /* source line no for errors */
         goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
         D_ADSL_RCL1->imc_prot_akku = 0;    /* clear value             */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_sch_len;  /* Share Control Header length */
         goto pfrse20;                      /* process next data       */
       }
         iml_line_no = __LINE__;
         iml_source_no = 13679;    /* source line no for errors */
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
         iml_source_no = 13697;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_count_in < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13701;    /* source line no for errors */
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
           goto pfrse40;
         }
         iml_line_no = __LINE__;
         iml_source_no = 13732;    /* source line no for errors */
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
       D_ADSL_RCL1->imc_prot_8 = D_ADSL_RCL1->imc_prot_akku;  /* save Share Control Header PDU source */
       if (D_ADSL_RCL1->imc_prot_pdu_type == D_DEMAND_ACT_PDU) {  /* is demand active PDU */
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13783;    /* source line no for errors */
         goto pfrse92;
         }
         D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
         D_ADSL_RCL1->imc_prot_1 = 0;       /* clear value             */
         D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_parse_shareid;  /* get share id */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
         /* prepare area in gather to be sent to the client            */
         iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* number of bytes    */
         aadsl_gai1_ch = &adsl_gai1_out_save;  /* create chain gather data */
         adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather            */
         while (TRUE) {                     /* loop over all gather structures input */
           while (adsl_gai1_inp_w2->achc_ginp_cur >= adsl_gai1_inp_w2->achc_ginp_end) {
             adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
             if (adsl_gai1_inp_w2 == NULL) {  /* end of input data     */
         iml_line_no = __LINE__;
         iml_source_no = 13800;    /* source line no for errors */
         goto pfrse96;
             }
           }
           if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < sizeof(struct dsd_gather_i_1)) {
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
           ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
           if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
         iml_line_no = __LINE__;
         iml_source_no = 13818;    /* source line no for errors */
         goto pfrse96;
           }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
           iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
           if (iml2 > iml1) iml2 = iml1;
           ADSL_GAI1_OUT_G->achc_ginp_cur = adsl_gai1_inp_w2->achc_ginp_cur;
           ADSL_GAI1_OUT_G->achc_ginp_end = adsl_gai1_inp_w2->achc_ginp_cur + iml2;
           *aadsl_gai1_ch = ADSL_GAI1_OUT_G;  /* create chain gather data */
           aadsl_gai1_ch = &ADSL_GAI1_OUT_G->adsc_next;  /* next entry create chain gather data */
           iml1 -= iml2;                    /* data processed          */
           if (iml1 <= 0) break;            /* end of block            */
           adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
           if (adsl_gai1_inp_w2 == NULL) {  /* end of input data       */
         iml_line_no = __LINE__;
         iml_source_no = 13831;    /* source line no for errors */
         goto pfrse96;
           }
#undef ADSL_GAI1_OUT_G
         }
         *aadsl_gai1_ch = NULL;             /* end create chain gather data */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->imc_prot_1 = D_ADSL_RCL1->imc_prot_pdu_type;
       goto pfrse40;                        /* send RDP4 data to client */
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
           if (   ((D_ADSL_RCL1->imc_prot_save1 & 0XFFFFF0FF) != 0X0002)  /* check type */
               && ((D_ADSL_RCL1->imc_prot_save1 & 0XFFFFF0FF) != 0X0003)) {  /* check type error */
         iml_line_no = __LINE__;
         iml_source_no = 13916;    /* source line no for errors */
         goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_prot_akku != (2 + 2 + 4)) {  /* check length */
         iml_line_no = __LINE__;
         iml_source_no = 13920;    /* source line no for errors */
         goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame != 4) {  /* check till end of frame */
         iml_line_no = __LINE__;
         iml_source_no = 13923;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           D_ADSL_RCL1->imc_prot_aux1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_akku = 0;  /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_sta_02;  /* start second field */
           goto pfrse20;                    /* process next data       */
         case ied_frse_sta_02:              /* start second field      */
           if ((D_ADSL_RCL1->imc_prot_save1 & 0XFFFFF0FF) == 0X0002) {  /* check type */
             goto pfrse_send_secbl;         /* send second block to server */
           }
           achl1 = "error";
           if (D_ADSL_RCL1->imc_prot_akku == 5) {  /* check type of encryption */
             achl1 = "server requested CredSSP - not supported";
           }
           m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d received first packet encryption type 0X%08X %s",
                         __LINE__, 13947,  /* line number for errors */
                         D_ADSL_RCL1->imc_prot_akku, achl1 );
           goto p_cleanup_00;               /* do cleanup now          */
         case ied_frse_rec_04:              /* record 4 received       */
           if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_1) {
         iml_line_no = __LINE__;
         iml_source_no = 13952;    /* source line no for errors */
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
             default:
         iml_line_no = __LINE__;
         iml_source_no = 13968;    /* source line no for errors */
         goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_prot_5 & D_ADSL_RCL1->imc_prot_4) {
         iml_line_no = __LINE__;
         iml_source_no = 13971;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_4 |= D_ADSL_RCL1->imc_prot_5;
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_l;  /* block 4 selection length */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13977;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_sel_l:           /* block 4 selection length */
           D_ADSL_RCL1->imc_prot_1 -= 4;    /* minus tag and length    */
           if (D_ADSL_RCL1->imc_prot_1 <= 0) {  /* check length        */
         iml_line_no = __LINE__;
         iml_source_no = 13985;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                     - D_ADSL_RCL1->imc_prot_1;
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 13990;    /* source line no for errors */
         goto pfrse92;
           }
           switch (D_ADSL_RCL1->imc_prot_5) {  /* type of field        */
             case 1:                        /* version tag             */
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r04_rdp_v;  /* block 4 RDP version */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_rdp_v;  /* block 4 RDP version */
               goto pfrse20;                /* needs more data         */
             case 2:                        /* encryption tag          */
               D_ADSL_RCL1->imc_prot_6 = D_ADSL_RCL1->imc_prot_2;  /* save end */
               D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_keytype;  /* block 4 security keytype */
               D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
               if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14002;    /* source line no for errors */
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
         iml_source_no = 14012;    /* source line no for errors */
         goto pfrse92;
               }
               D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RCL1->imc_prot_1 = 0;  /* clear value            */
               goto pfrse20;                /* needs more data         */
           }
         iml_line_no = __LINE__;
         iml_source_no = 14018;    /* source line no for errors */
         goto pfrse92;
         case ied_frse_r04_ch_disp:         /* block 4 display channel */
/* 18.12.04 KB UUUU */
           D_ADSL_RCO1->usc_chno_disp = (unsigned short int) D_ADSL_RCL1->imc_prot_1;
           ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.usc_chno_disp
             = (unsigned short int) D_ADSL_RCL1->imc_prot_1;
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_vch_no;  /* block 4 no virtual channels */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14029;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_vch_no:          /* block 4 no virtual channels */
           if (D_ADSL_RCL1->imc_prot_1 != D_ADSL_RCO1->imc_no_virt_ch) {
         iml_line_no = __LINE__;
         iml_source_no = 14036;    /* source line no for errors */
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
         iml_source_no = 14055;    /* source line no for errors */
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
         iml_source_no = 14094;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14098;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* needs more data         */
         case ied_frse_r04_vch_del:         /* block 4 vch delemiter   */
           if (D_ADSL_RCL1->imc_prot_1) {   /* must be zero            */
         iml_line_no = __LINE__;
         iml_source_no = 14105;    /* source line no for errors */
         goto pfrse92;
           }
           /* check end of this sequence                               */
           if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_6) {
         iml_line_no = __LINE__;
         iml_source_no = 14109;    /* source line no for errors */
         goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame == 0) {  /* end of block */
             if (D_ADSL_RCL1->imc_prot_4 != 7) {
         iml_line_no = __LINE__;
         iml_source_no = 14113;    /* source line no for errors */
         goto pfrse92;
             }
/* 19.12.04 KB - at end of block - not implemented */
         iml_line_no = __LINE__;
         iml_source_no = 14116;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14121;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_keytype:         /* block 4 security keytype */
           D_ADSL_RCO1->imc_keytype = D_ADSL_RCL1->imc_prot_1;
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sec_level;  /* block 4 security level  */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14131;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_sec_level:       /* block 4 security level  */
           D_ADSL_RCO1->imc_sec_level = D_ADSL_RCL1->imc_prot_1;
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_l_serv_rand;  /* block 4 length server random */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14141;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_l_serv_rand:     /* block 4 length server random */
           if (D_ADSL_RCL1->imc_prot_1 != sizeof(ADSL_RDPA_F->chrl_server_random)) {
         iml_line_no = __LINE__;
         iml_source_no = 14148;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_7 = D_ADSL_RCL1->imc_prot_1;  /* save length */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_l_pub_par;  /* block 4 length public parameters */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14154;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_l_pub_par:       /* block 4 length public parameters */
           if ((D_ADSL_RCL1->imc_prot_7 + D_ADSL_RCL1->imc_prot_1 + D_ADSL_RCL1->imc_prot_6)
                 != D_ADSL_RCL1->imc_pos_inp_frame) {
         iml_line_no = __LINE__;
         iml_source_no = 14162;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCO1->imc_l_pub_par = D_ADSL_RCL1->imc_prot_1;
           /* get server-random                                        */
           D_ADSL_RCL1->achc_prot_1 = ADSL_RDPA_F->chrl_server_random;
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                     - sizeof(ADSL_RDPA_F->chrl_server_random);
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14170;    /* source line no for errors */
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
         iml_source_no = 14189;    /* source line no for errors */
         goto pfrse92;
             }
             D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data */
             D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_ppdir_tag;  /* get public parms direct tag */
             D_ADSL_RCL1->imc_prot_5 = 0;   /* no value before         */
             goto pfrse20;                  /* process next data       */
           }
           if ((D_ADSL_RCL1->imc_prot_1 & 0X7FFFFFFF) != D_TYPE_PUB_PAR_CERT) {
         iml_line_no = __LINE__;
         iml_source_no = 14202;    /* source line no for errors */
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
         iml_source_no = 14255;    /* source line no for errors */
         goto pfrse92;
           }
           /* check if tag double                                      */
           if (D_ADSL_RCL1->imc_prot_1 == D_ADSL_RCL1->imc_prot_5) {
         iml_line_no = __LINE__;
         iml_source_no = 14259;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_4 = D_ADSL_RCL1->imc_prot_1;  /* save ppdir type */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14264;    /* source line no for errors */
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
         iml_source_no = 14276;    /* source line no for errors */
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
         iml_source_no = 14293;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                     - D_ADSL_RCL1->imc_prot_1;
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14298;    /* source line no for errors */
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
         iml_source_no = 14361;    /* source line no for errors */
         goto pfrse92;
         case ied_frse_actpdu_parse_shareid: /* shareid */
           // Save shared ID
           D_ADSL_RCO1->imc_shareid = D_ADSL_RCL1->imc_prot_1;
           // Next is source descriptor
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14455;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_sdl;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_sdl:          /* get source descriptor length */
           if (D_ADSL_RCL1->imc_prot_1 != sizeof(ucrs_source_desc)) {
         iml_line_no = __LINE__;
         iml_source_no = 14464;    /* source line no for errors */
         goto pfrse92;
           }
           /* get 2 bytes little endian again                          */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14475;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_actpdu_len_cap;  /* get length capabilities */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_len_cap:      /* get length capabilities */
           if (D_ADSL_RCL1->imc_pos_inp_frame < D_ADSL_RCL1->imc_prot_1) {
         iml_line_no = __LINE__;
         iml_source_no = 14501;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_4
             = D_ADSL_RCL1->imc_pos_inp_frame
               - D_ADSL_RCL1->imc_prot_1
               - sizeof(ucrs_source_desc);
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_constant;  /* compare with constant */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* position                */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_no_cap:       /* get number capabilities */
           D_ADSL_RCL1->imc_prot_5 = D_ADSL_RCL1->imc_prot_1;  /* save no cap */
           D_ADSL_RCL1->imc_prot_7 = 0;     /* clear indicator         */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14515;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data */
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_cap_ind:      /* get capabilities index  */
           D_ADSL_RCL1->imc_prot_6 = D_ADSL_RCL1->imc_prot_1;  /* save no cap */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14523;    /* source line no for errors */
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
         iml_source_no = 14533;    /* source line no for errors */
         goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_prot_1) {   /* value follows    */
             D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - D_ADSL_RCL1->imc_prot_1;
             if (D_ADSL_RCL1->imc_prot_2 < D_ADSL_RCL1->imc_prot_4) {
         iml_line_no = __LINE__;
         iml_source_no = 14538;    /* source line no for errors */
         goto pfrse92;
             }
             if (D_ADSL_RCL1->imc_prot_1 > sizeof(D_ADSL_RCL1->chrc_prot_1)) {
         iml_line_no = __LINE__;
         iml_source_no = 14541;    /* source line no for errors */
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
         iml_source_no = 14554;    /* source line no for errors */
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
         iml_source_no = 14564;    /* source line no for errors */
         goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame != 4) {
         iml_line_no = __LINE__;
         iml_source_no = 14567;    /* source line no for errors */
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
         iml_source_no = 14577;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_count_in = D_ADSL_RCL1->imc_prot_akku;  /* number of bytes */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_cmp_zero;  /* compare with zeroes */
           goto pfrse20;                    /* process next data       */
         case ied_frse_rdp4_vch_ulen:       /* virtual channel uncompressed data length */
           D_ADSL_RCL1->umc_vch_ulen = D_ADSL_RCL1->imc_prot_1;  /* virtual channel length uncompressed */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - sizeof(D_ADSL_RCL1->chrc_vch_segfl);
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14587;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->achc_prot_1 = D_ADSL_RCL1->chrc_vch_segfl;
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_copy;  /* copy data     */
           goto pfrse20;                    /* process next data       */
         case ied_frse_lic_pr_type:         /* licencing block to check */
           if ((D_ADSL_RCL1->imc_prot_1 & 0x00007E00) != 0x0200) {
         iml_line_no = __LINE__;
         iml_source_no = 14594;    /* source line no for errors */
         goto pfrse92;
           }
           if ((((unsigned int) (D_ADSL_RCL1->imc_prot_1)) >> 16)
                 != (D_ADSL_RCL1->imc_pos_inp_frame + 4)) {
         iml_line_no = __LINE__;
         iml_source_no = 14598;    /* source line no for errors */
         goto pfrse92;
           }
           switch (D_ADSL_RCL1->imc_prot_1 & 0XFF) {
             case 0X01:                     /* LICENSE_REQUEST         */
               if (D_ADSL_RCO1->adsc_lic_neg) {
         iml_line_no = __LINE__;
         iml_source_no = 14603;    /* source line no for errors */
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
         iml_source_no = 14611;    /* source line no for errors */
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
         iml_source_no = 14621;    /* source line no for errors */
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
                 if (ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.adsc_lic_neg)
                   if (ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.adsc_lic_neg != D_ADSL_RCO1->adsc_lic_neg)
                     goto pfrse96;          /* program illogic         */
                   else
                     ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.adsc_lic_neg = NULL;
                 m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg );
                 D_ADSL_RCO1->adsc_lic_neg = NULL;
               }
//iff;  22.07.11 KB
// to-do 16.06.10 KB - with Mr. Sommer
//cend;  22.07.11 KB
             case 0X03:                     /* NEW_LICENSE             */
             case 0X04:                     /* UPGRAD_LICENSE          */
               D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_send_from_server;  /* send data to client */
               goto pfrse40;                /* send RDP4 to client     */
             default:
         iml_line_no = __LINE__;
         iml_source_no = 14665;    /* source line no for errors */
         goto pfrse92;
           }
         case ied_frse_lic_pr_req_rand:     /* server license request (after) random */
           D_ADSL_RCL1->imc_prot_5 = D_ADSL_RCL1->imc_prot_1;  /* save RDP version temporarily here */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14671;    /* source line no for errors */
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
         iml_source_no = 14685;    /* source line no for errors */
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
         iml_source_no = 14694;    /* source line no for errors */
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
         case ied_frse_lic_pr_lic_error_mes1:
           D_ADSL_RCL1->imc_prot_5 = D_ADSL_RCL1->imc_prot_1; /* Save error code */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 14871;    /* source line no for errors */
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
			                 17784,             /* source line no for errors */
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
           ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.usc_userid_cl2se
             = (unsigned short int) D_ADSL_RCL1->imc_prot_1;
           /* send this block unchanged to client                      */
           ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
           if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
             goto pfrse96;                  /* program illogic         */
           }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
           ADSL_GAI1_OUT_G->adsc_next = NULL;
           ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
           memcpy( ADSL_OA1->achc_lower, ucrs_x224_r07_aurep, sizeof(ucrs_x224_r07_aurep) );
           ADSL_OA1->achc_lower += sizeof(ucrs_x224_r07_aurep);
           *ADSL_OA1->achc_lower++ = 0;              /* status success          */
           m_put_be2( ADSL_OA1->achc_lower, ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.usc_userid_cl2se );
           ADSL_OA1->achc_lower += 2;
           ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
           *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
           ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
//         D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_06;  /* receive block 6 */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_invalid;  /* invalid data received */
           D_ADSL_RCL1->iec_frse_bl = ied_frse_cjresp_rec;  /* receive block channel join response */
#ifdef TRACEHL1
           if (ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl != ied_fcfp_invalid) {  /* receive record type */
             printf( "after block 7 from server not correct state client\n" );
             goto pfrse96;                  /* program illogic         */
           }
#endif
           if (ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl == ied_fcfp_invalid) {  /* receive record type */
             ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
           }
           goto pfrse20;                    /* process next data       */
         case ied_frse_cjresp_rec:          /* receive block channel join response */
           do {
             if (D_ADSL_RCL1->imc_prot_1 == D_ADSL_RCO1->usc_chno_disp) {  /* channel number display */
               D_ADSL_RCO1->usc_chno_disp = (unsigned short int) D_ADSL_RCL1->imc_prot_chno;
               /* set also for server                                  */
               ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.usc_chno_disp
                 = (unsigned short int) D_ADSL_RCL1->imc_prot_chno;
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
         iml_source_no = 15049;    /* source line no for errors */
         goto pfrse92;
             }
             D_ADSL_RCO1->usc_chno_cont = (unsigned short int) D_ADSL_RCL1->imc_prot_chno;
             /* set also for server                                    */
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.usc_chno_cont
               = (unsigned short int) D_ADSL_RCL1->imc_prot_chno;
           } while (FALSE);
           /* send this block unchanged to client                      */
           ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
           if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
             goto pfrse96;                  /* program illogic         */
           }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
           ADSL_GAI1_OUT_G->adsc_next = NULL;
           ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
           memcpy( ADSL_OA1->achc_lower, ucrs_x224_cjresp_1, sizeof(ucrs_x224_cjresp_1) );
           ADSL_OA1->achc_lower += sizeof(ucrs_x224_cjresp_1);
           *ADSL_OA1->achc_lower++ = 0;        /* status success          */
           m_put_be2( ADSL_OA1->achc_lower, ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.usc_userid_cl2se );
           ADSL_OA1->achc_lower += 2;
           m_put_be2( ADSL_OA1->achc_lower, D_ADSL_RCL1->imc_prot_chno );
           ADSL_OA1->achc_lower += 2;
           m_put_be2( ADSL_OA1->achc_lower, D_ADSL_RCL1->imc_prot_1 );
           ADSL_OA1->achc_lower += 2;
           ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
           *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
           ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
//         D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_06;  /* receive block 6 */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
           /* either the same block follows or the licence protocol    */
//         D_ADSL_RCL1->iec_frse_bl = ied_frse_lic_pr_1_rec;  /* receive block licence protocol */
#ifdef TRACEHL1
           if (ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl != ied_fcfp_invalid) {  /* receive record type */
             printf( "after block cjresp from server not correct state client\n" );
             goto pfrse96;                /* program illogic         */
           }
#endif
           goto pfrse20;                    /* process next data       */
         case ied_frse_actpdu_trail:        /* trailer of act PDU      */
           D_ADSL_RCL1->imc_prot_1 = D_DEMAND_ACT_PDU;
           goto pfrse40;                    /* send RDP4 data to client */
       }
           goto pfrse96;                    /* program illogic         */
     case ied_fsfp_asn1_tag:                /* ASN.1 tag follows       */
       adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->imc_pos_inp_frame < D_ADSL_RCL1->imc_prot_3) {
         iml_line_no = __LINE__;
         iml_source_no = 15273;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_l1_fi;  /* ASN.1 length field */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_asn1_l1_fi:              /* ASN.1 length field 1    */
       D_ADSL_RCL1->imc_prot_1
         = *adsl_gai1_inp_1->achc_ginp_cur & 0X7F;
       if (D_ADSL_RCL1->imc_prot_1 == 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15281;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_pos_inp_frame--;
       /* compute how many remain after this length                    */
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame
                                  - D_ADSL_RCL1->imc_prot_1;
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15288;    /* source line no for errors */
         goto pfrse92;
       }
       /* check ASN-1 length in more than one byte                     */
       if (*adsl_gai1_inp_1->achc_ginp_cur & 0X80) {
         if (D_ADSL_RCL1->imc_prot_1 > 4) {
         iml_line_no = __LINE__;
         iml_source_no = 15293;    /* source line no for errors */
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
                           __LINE__, 15324,  /* line number for errors */
                           D_ADSL_RCL1->imc_prot_2, D_ADSL_RCL1->imc_pos_inp_frame );
         iml_line_no = __LINE__;
         iml_source_no = 15326;    /* source line no for errors */
         goto pfrse92;
           }
           if (D_ADSL_RCL1->imc_pos_inp_frame < sizeof(ucrs_rec_se_01_cmp1)) {  /* compare received from server first block */
         iml_line_no = __LINE__;
         iml_source_no = 15329;    /* source line no for errors */
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
           D_ADSL_RCL1->imc_prot_4 = D_ADSL_RCL1->imc_prot_2;
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15347;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->imc_prot_3 = D_ADSL_RCL1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RCL1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_int_lit_e;  /* int little endian */
           goto pfrse20;                    /* process next data       */
         default:
           goto pfrse96;                    /* program illogic         */
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
         iml_source_no = 15377;    /* source line no for errors */
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
         iml_source_no = 15389;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_asn1_1;  /* block 4 ASN-1 field 1 */
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_asn1_tag;
           goto pfrse20;                    /* process next data       */
         case ied_frse_r04_asn1_4:          /* block 4 ASN-1 field 4   */
           if (D_ADSL_RCL1->imc_prot_2) {   /* is not till end of block */
         iml_line_no = __LINE__;
         iml_source_no = 15396;    /* source line no for errors */
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
         iml_source_no = 15407;    /* source line no for errors */
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
         iml_source_no = 15419;    /* source line no for errors */
         goto pfrse92;
       }
       if (D_ADSL_RCL1->imc_pos_inp_frame < D_ADSL_RCL1->imc_prot_1) {
         iml_line_no = __LINE__;
         iml_source_no = 15422;    /* source line no for errors */
         goto pfrse92;
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_act_pdu_rec:         /* receive block active PDU */
         case ied_frse_lic_pr_1_rec:        /* receive block licence protocol */
         case ied_frse_any_pdu_rec:
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rt02;  /* record type 2 */
           goto pfrse20;                    /* process next data       */
       }
           goto pfrse96;                    /* program illogic         */
     case ied_fsfp_mu_len_2:                /* multi length 2          */
       D_ADSL_RCL1->imc_prot_1 <<= 8;       /* shift old value         */
       D_ADSL_RCL1->imc_prot_1
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RCL1->imc_pos_inp_frame--;
       if (D_ADSL_RCL1->imc_prot_1 == 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15438;    /* source line no for errors */
         goto pfrse92;
       }
       if (D_ADSL_RCL1->imc_pos_inp_frame < D_ADSL_RCL1->imc_prot_1) {
         iml_line_no = __LINE__;
         iml_source_no = 15441;    /* source line no for errors */
         goto pfrse92;
       }
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_r04_asn1_4:          /* block 4 ASN-1 field 4   */
           if (D_ADSL_RCL1->imc_pos_inp_frame != D_ADSL_RCL1->imc_prot_1) {
         iml_line_no = __LINE__;
         iml_source_no = 15446;    /* source line no for errors */
         goto pfrse92;
           }
           D_ADSL_RCL1->iec_frse_bl = ied_frse_r04_sel_t;  /* block 4 selection */
           D_ADSL_RCL1->imc_prot_4 = 0;     /* no fields yet           */
           D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15462;    /* source line no for errors */
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
           D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rt02;  /* record type 2 */
           goto pfrse20;                    /* process next data       */
       }
         iml_line_no = __LINE__;
         iml_source_no = 15479;    /* source line no for errors */
         goto pfrse96;
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
         iml_source_no = 15591;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_collect;  /* RDP 5 collect data */
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
         iml_source_no = 15656;    /* source line no for errors */
         goto pfrse92;
       }
#ifdef TEMPSCR1
       if (ADSL_RDPA_F->boc_temp_scr_1) {   /* screen buffer send      */
         D_ADSL_RCL1->imc_prot_2 = 0;       /* till end of block       */
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_ignore;  /* ignore data   */
         goto pfrse20;                      /* process next data       */
       }
#endif
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_collect;  /* RDP 5 collect data */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_r5_collect:              /* RDP 5 collect data      */
       /* check if all data of this frame have been received           */
       iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* remaining data in frame */
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
       /* start of record                                              */
       if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
         memset( &dsl_gai1_start_rec, 0, sizeof(struct dsd_gather_i_1) );
         dsl_gai1_start_rec.achc_ginp_cur = D_ADSL_RCO1->chrc_start_rec;
         dsl_gai1_start_rec.achc_ginp_end = D_ADSL_RCO1->chrc_start_rec + D_ADSL_RCO1->imc_len_start_rec;
         dsl_gai1_start_rec.adsc_next = adsl_gai1_inp_1;
         ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
           = ied_trc_recv_server;           /* received from server    */
         ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = &dsl_gai1_start_rec;
         ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RCO1->imc_len_record;  /* length of record */
         m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
       }
       achl_out_1 = NULL;                   /* no output-area yet      */
       if (D_ADSL_RCL1->chc_prot_r5_first & 0X80) {  /* received encrypted */
         D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - D_SIZE_HASH;
         if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15718;    /* source line no for errors */
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
         iml_source_no = 15796;    /* source line no for errors */
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
                       __LINE__, 15858 );  /* line number for errors  */
         iml_line_no = __LINE__;
         iml_source_no = 15860;    /* source line no for errors */
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
         iml_source_no = 15877;    /* source line no for errors */
         goto pfrse92;
         }
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_cofl;  /* RDP 5 compression flags */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15884;    /* source line no for errors */
         goto pfrse92;
       }
       D_ADSL_RCL1->imc_prot_1 = 0;         /* clear value             */
       D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_len;  /* RDP 5 PDU length */
       goto pfrse20;                        /* process next data       */
     case ied_fsfp_r5_pdu_cofl:             /* RDP 5 compression flags */
       D_ADSL_RCL1->chc_prot_r5_pdu_cofl = *adsl_gai1_inp_1->achc_ginp_cur++;  /* for protocol decoding */
       D_ADSL_RCL1->imc_pos_inp_frame--;
       D_ADSL_RCL1->imc_prot_2 = D_ADSL_RCL1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RCL1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15894;    /* source line no for errors */
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
           goto pfrse_send_r5_00;           /* send RDP 5 data to client */
         }
         if (D_ADSL_RCO1->dsc_cdrf_dec.imc_func == 0) {  /* compression not started */
         iml_line_no = __LINE__;
         iml_source_no = 15966;    /* source line no for errors */
         goto pfrse92;
         }
         D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_compr;  /* RDP 5 PDU compressed */
         goto pfrse20;                      /* process next data       */
       }
       D_ADSL_RCL1->imc_prot_4
         = D_ADSL_RCL1->imc_pos_inp_frame - D_ADSL_RCL1->imc_prot_1;
       if (D_ADSL_RCL1->imc_prot_4 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 15990;    /* source line no for errors */
         goto pfrse92;
       }
       /* data from server RDP 5 PDU                                   */
       if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
         ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
           = ied_trc_se2cl_r5_pdu;          /* server to client, RDP 5 PDU */
         ADSL_RDPA_F->dsc_rdptr1.chc_prot_r5_pdu_type  /* RDP 5 PDU type */
           = D_ADSL_RCL1->chc_prot_r5_pdu_type;
         ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_inp_1;
         ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RCL1->imc_prot_1;  /* length of record */
         ADSL_RDPA_F->dsc_rdptr1.imc_disp_field
           = D_ADSL_RCO1->imc_len_record - D_ADSL_RCL1->imc_pos_inp_frame;
         m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
       }
       goto pfrse_send_r5_00;               /* send RDP 5 data to client */
     case ied_fsfp_r5_pdu_compr:            /* RDP 5 PDU compressed    */
       /* check if all data of this frame have been received           */
       iml1 = D_ADSL_RCL1->imc_prot_1;      /* length of compressed data */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
#define ADSL_GAI1_S ((struct dsd_gather_i_1 *) chrl_work_2)
       adsl_gai1_w1 = ADSL_GAI1_S;          /* first gather here       */
       while (TRUE) {                       /* loop over input bytes   */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
           //m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 wait for more data D_ADSL_RCL1->imc_prot_1=%d achl_out_1=%p.",
           //              __LINE__, 16323,  /* line number for errors */
           //              D_ADSL_RCL1->imc_prot_1, achl_out_1 );
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
       adsl_gai1_w2 = &dsl_gai1_comp_data;
       adsl_gai1_w1 += 16;                  /* space needed for later compression */
       /* decompress data in a loop                                    */
       D_ADSL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
       D_ADSL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
       D_ADSL_RCL1->imc_prot_1 = 0;         /* clear count decompressed data */
       while (TRUE) {
         adsl_gai1_w2->achc_ginp_cur
           = D_ADSL_RCO1->dsc_cdrf_dec.achc_out_cur  /* current end of output data */
             = ADSL_OA1->achc_lower;
         D_ADSL_RCO1->dsc_cdrf_dec.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
         D_ADSL_RCO1->amc_cdr_dec( &D_ADSL_RCO1->dsc_cdrf_dec );
         if (D_ADSL_RCO1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {
           m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d de-compression error %d.",
                         __LINE__, 16388,  /* line number for errors */
                         D_ADSL_RCO1->dsc_cdrf_dec.imc_return );
           goto p_cleanup_00;               /* do cleanup now          */
         }
         adsl_gai1_w2->achc_ginp_end
           = ADSL_OA1->achc_lower
             = D_ADSL_RCO1->dsc_cdrf_dec.achc_out_cur;
         D_ADSL_RCL1->imc_prot_1 += adsl_gai1_w2->achc_ginp_end - adsl_gai1_w2->achc_ginp_cur;  /* length of data */
         adsl_gai1_w2->adsc_next = NULL;    /* end of chain gather     */
         if (D_ADSL_RCO1->dsc_cdrf_dec.boc_sr_flush) break;  /* end-of-record output */
         //m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 continue de-compression D_ADSL_RCL1->imc_prot_1=%d achl_out_1=%p.",
         //              __LINE__, 16434,  /* line number for errors */
         //              D_ADSL_RCL1->imc_prot_1, achl_out_1 );
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
         adsl_gai1_w1++;                    /* next gather             */
         adsl_gai1_w2->adsc_next = adsl_gai1_w1;  /* set chain gather  */
         adsl_gai1_w2 = adsl_gai1_w1;       /* put into this gather    */
       }
       if (achl_out_1 != NULL) {            /* needs gap in output area */
         if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < (64 + sizeof(struct dsd_gather_i_1))) {  /* get new area */
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
         achl_out_1 = ADSL_OA1->achc_lower;  /* continue output here   */
         ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
         ADSL_GAI1_OUT_G->adsc_next = NULL;
         ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_GAI1_OUT_G->achc_ginp_end = achl_out_1;
         *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
         ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
       }
       D_ADSL_RCL1->imc_prot_4 = D_ADSL_RCL1->imc_pos_inp_frame;  /* position end of this PDU */
       adsl_gai1_inp_save_compr = adsl_gai1_inp_1;  /* save current gather input */
       adsl_gai1_inp_1 = &dsl_gai1_comp_data;  /* process decompressed data */
//     D_ADSL_RCL1->imc_pos_inp_frame = D_ADSL_RCL1->imc_prot_1;
       /* process first decompressed data, later remainder of frame    */
       D_ADSL_RCL1->imc_pos_inp_frame += D_ADSL_RCL1->imc_prot_1;
       /* data from server decompressed, RDP 5 PDU                     */
       if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
         ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
           = ied_trc_se2cl_r5_pdu;          /* server to client, RDP 5 PDU */
         ADSL_RDPA_F->dsc_rdptr1.chc_prot_r5_pdu_type  /* RDP 5 PDU type */
           = D_ADSL_RCL1->chc_prot_r5_pdu_type;
         ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = &dsl_gai1_comp_data;
         ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input  /* length of record */
           = dsl_gai1_comp_data.achc_ginp_end - dsl_gai1_comp_data.achc_ginp_cur;
         m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
       }
       goto pfrse_send_r5_00;               /* send RDP 5 data to client */
     case ied_fsfp_send_from_server:        /* send data to client     */
       goto pfrse40;                        /* send RDP4 to client     */
     case ied_fsfp_end_com:                 /* end of communication    */
       if ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur != (unsigned char) 0X80) {
         iml_line_no = __LINE__;
         iml_source_no = 25807;    /* source line no for errors */
         goto pfrse92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RCL1->imc_pos_inp_frame--;    /* length constant         */
       if (D_ADSL_RCL1->imc_pos_inp_frame != 0) {
         iml_line_no = __LINE__;
         iml_source_no = 25812;    /* source line no for errors */
         goto pfrse92;
       }
       goto p_se2cl_send_end_00;            /* send end of communication */
     case ied_fsfp_no_session:              /* no more session         */
         iml_line_no = __LINE__;
         iml_source_no = 25937;    /* source line no for errors */
         goto pfrse92;
   }
         iml_line_no = __LINE__;
         iml_source_no = 25943;    /* source line no for errors */
         goto pfrse96;


   pfrse_send_r5_00:                        /* send RDP 5 data to client */
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RCO1
#define D_ADSL_RSE1 (&ADSL_RDPA_F->dsc_rdp_se_1)
#define D_ADSL_RCO1 (&D_ADSL_RSE1->dsc_rdp_co_1)
#else
   D_ADSL_RSE1 = &ADSL_RDPA_F->dsc_rdp_se_1;
   D_ADSL_RCO1 = &D_ADSL_RSE1->dsc_rdp_co_1;
#endif
   if (achl_out_1 == NULL) {                /* no output-area yet      */
     if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < 256) {  /* get new area */
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
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
       goto pfrse96;                        /* program illogic         */
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
     ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
     adsl_gai1_out_save = ADSL_GAI1_OUT_G;  /* save start output data  */
     *(ADSL_OA1->achc_lower + 0) = 0;          /* clear type of block     */
     achl_out_1 = ADSL_OA1->achc_lower + 3;    /* here starts output      */
     if (D_ADSL_RCO1->imc_sec_level > 1) {  /* with encryption         */
       *(ADSL_OA1->achc_lower + 0) = 0X80 | (D_ADSL_RCL1->chc_prot_r5_first & 0X40);
       achl_out_1 += D_SIZE_HASH;           /* add length hash         */
     }
     ADSL_GAI1_OUT_G->achc_ginp_cur = achl_out_1;
#undef ADSL_GAI1_OUT_G
     iml_out_len = 0;                       /* clear length output     */
   }
   if ((ADSL_OA1->achc_upper - achl_out_1) < 32) {  /* get new area       */
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
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
       goto pfrse96;                        /* program illogic         */
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
     ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
     achl_out_1 = ADSL_OA1->achc_lower;        /* here starts output      */
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
#undef ADSL_GAI1_OUT_G
   }
   if (D_ADSL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) {  /* compression enabled */
     goto pfrse_send_r5_20;                 /* send RDP 5 compressed   */
   }
   iml_out_len += 3 + D_ADSL_RCL1->imc_prot_1;  /* add length output   */
   *achl_out_1++ = D_ADSL_RCL1->chc_prot_r5_pdu_type & 0X7F;
   m_put_le2( achl_out_1, D_ADSL_RCL1->imc_prot_1 );
   achl_out_1 += 2;
   if (D_ADSL_RCL1->imc_prot_1 == 0) {      /* PDU without content     */
     goto pfrse_send_r5_40;                 /* output finished         */
   }
   while (TRUE) {                           /* loop over gather input  */
     iml1 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml1 > D_ADSL_RCL1->imc_prot_1) iml1 = D_ADSL_RCL1->imc_prot_1;
     if (iml1 > (ADSL_OA1->achc_upper - achl_out_1)) iml1 = ADSL_OA1->achc_upper - achl_out_1;
     memcpy( achl_out_1, adsl_gai1_inp_1->achc_ginp_cur, iml1 );
     adsl_gai1_inp_1->achc_ginp_cur += iml1;
     if (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     }
     D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* remaining data in frame */
     achl_out_1 += iml1;
     D_ADSL_RCL1->imc_prot_1 -= iml1;
     if (D_ADSL_RCL1->imc_prot_1 == 0) break;
     if (adsl_gai1_inp_1 == NULL) {
       M_ERROR_FRSE_ILLOGIC
     }
     if (achl_out_1 < ADSL_OA1->achc_upper) continue;  /* still space in output-area */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;
     /* get new block for more output                                  */
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
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
       goto pfrse96;                        /* program illogic         */
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
     ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
   }
   goto pfrse_send_r5_40;                   /* output finished         */

   pfrse_send_r5_20:                        /* send RDP 5 compressed   */
   iml1 = iml2 = 0;
   if (D_ADSL_RCL1->imc_prot_1 != 0) {      /* PDU without content     */
     adsl_gai1_w1 = adsl_gai1_inp_1;        /* first gather here       */
     while (adsl_gai1_w1) {
       iml1++;
       iml3 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       //m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 pfrse_send_r5_20: %d. gather %p length %d/0X%X.",
       //              __LINE__, 26850,  /* line number for errors */
       //              iml1, adsl_gai1_w1, iml3, iml3 );
       iml2 += iml3;
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     }
   }
   //m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 pfrse_send_r5_20: send compressed D_ADSL_RCL1->imc_prot_1=%d achl_out_1=%p gather-in=%d data=%d/0X%X D_ADSL_RCL1->imc_pos_inp_frame=%d.",
   //              __LINE__, 26857,  /* line number for errors */
   //              D_ADSL_RCL1->imc_prot_1, achl_out_1, iml1, iml2, iml2, D_ADSL_RCL1->imc_pos_inp_frame );
   //m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 pfrse_send_r5_20: send compressed adsl_gai1_inp_1=%p chrl_work_2=%p.",
   //              __LINE__, 26860,  /* line number for errors */
   //              adsl_gai1_inp_1, chrl_work_2 );
   //if (iml2 != D_ADSL_RCL1->imc_prot_1) {
   //  m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 pfrse_send_r5_20: send compressed attention - length not equal +++",
   //                __LINE__, 26864 );  /* line number for errors */
   //}
   //if (((char *) adsl_gai1_inp_1) == chrl_work_2) {
   //  m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d pfrse_send_r5_20: send compressed attention - length not equal +++",
   //                __LINE__, 26868 );  /* line number for errors */
   //}
   *achl_out_1++ = D_ADSL_RCL1->chc_prot_r5_pdu_type | 0X80;
   if (D_ADSL_RCL1->imc_prot_1 == 0) {      /* PDU without content     */
     memset( achl_out_1, 0, 3 );            /* clear compression-flag and length */
     achl_out_1 += 3;                       /* increment position output */
     iml_out_len += 4;                      /* add length output       */
     goto pfrse_send_r5_40;                 /* output finished         */
   }
   achl1 = achl_out_1;                      /* save position start output */
   achl_out_1 += 3;                         /* here starts output      */
#define ADSL_GAI1_S ((struct dsd_gather_i_1 *) chrl_work_2)
   adsl_gai1_w1 = ADSL_GAI1_S;              /* first gather here       */
   while (TRUE) {                           /* loop over input bytes   */
     if (adsl_gai1_inp_1 == NULL) {         /* input exhausted         */
       M_ERROR_FRSE_ILLOGIC
     }
     //m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 copy gather from %p to %p.",
     //              __LINE__, 26888,  /* line number for errors */
     //              adsl_gai1_inp_1, adsl_gai1_w1 );
     //if (adsl_gai1_inp_1 == adsl_gai1_w1) {
     //  m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 attention - address gather equal",
     //                __LINE__, 26892 );  /* line number for errors */
     //}
     iml1 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml1 > D_ADSL_RCL1->imc_prot_1) iml1 = D_ADSL_RCL1->imc_prot_1;
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_cur;
     adsl_gai1_w1->achc_ginp_end = adsl_gai1_inp_1->achc_ginp_cur + iml1;
     adsl_gai1_inp_1->achc_ginp_cur += iml1;
     if (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     }
     D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* remaining data in frame */
     D_ADSL_RCL1->imc_prot_1 -= iml1;       /* remaining data to compress */
     if (D_ADSL_RCL1->imc_prot_1 <= 0) break;  /* end of data to compress */
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain gather  */
     adsl_gai1_w1++;                        /* use next gather         */
   }
   adsl_gai1_w1->adsc_next = NULL;          /* end of data             */
   D_ADSL_RCO1->dsc_cdrf_enc.adsc_gai1_in = ADSL_GAI1_S;  /* input data */
#undef ADSL_GAI1_S
   D_ADSL_RCO1->dsc_cdrf_enc.boc_mp_flush = TRUE;  /* end-of-record input */
   D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur = achl_out_1;  /* current end of output data */
   D_ADSL_RCO1->dsc_cdrf_enc.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
   iml_compr_len = 0;                       /* clear length compressed */
   while (TRUE) {                           /* loop over gather input  */
     D_ADSL_RCO1->amc_cdr_enc( &D_ADSL_RCO1->dsc_cdrf_enc );
     if (D_ADSL_RCO1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {
       m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d compression error %d.",
                     __LINE__, 26815,  /* line number for errors */
                     D_ADSL_RCO1->dsc_cdrf_enc.imc_return );
       goto p_cleanup_00;                   /* do cleanup now          */
     }
     iml_compr_len += D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur - achl_out_1;
     achl_out_1 = D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur;  /* set end of output */
     if (D_ADSL_RCO1->dsc_cdrf_enc.boc_sr_flush) break;  /* end-of-record output */
     //m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 pfrse_send_r5_20: continue compression iml_compr_len=%d achl_out_1=%p.",
     //              __LINE__, 26940,  /* line number for errors */
     //              iml_compr_len, achl_out_1 );
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;
     /* get new block for more output                                  */
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
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
         iml_line_no = __LINE__;
         iml_source_no = 26844;    /* source line no for errors */
         goto pfrse96;
     }
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = achl_out_1;
     *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
     ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
     D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur = achl_out_1;  /* current end of output data */
     D_ADSL_RCO1->dsc_cdrf_enc.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
   }
   *achl1 = D_ADSL_RCO1->dsc_cdrf_enc.chrc_header[ 0 ];  /* copy compression header */
   m_put_le2( achl1 + 1, iml_compr_len );
   iml_out_len += 4 + iml_compr_len;        /* add length output       */

   pfrse_send_r5_40:                        /* output finished         */
   //m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d DEBUG$150728$01 pfrse_send_r5_40: iml_out_len=%d/0X%X adsl_gai1_out_save->achc_ginp_cur=%p achl_out_1=%p D_ADSL_RCL1->imc_pos_inp_frame=%d/0X%X.",
   //              __LINE__, 26990,  /* line number for errors */
   //              iml_out_len, iml_out_len, adsl_gai1_out_save->achc_ginp_cur, achl_out_1, D_ADSL_RCL1->imc_pos_inp_frame, D_ADSL_RCL1->imc_pos_inp_frame );
   ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set end of block */
   ADSL_OA1->achc_lower = achl_out_1;       /* filled till here        */
   if (D_ADSL_RCL1->imc_pos_inp_frame > 0) {  /* more data in this frame */
     D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_r5_pdu_typ;  /* RDP 5 PDU type */
#ifdef HL_RDPACC_HELP_DEBUG
     D_ADSL_RCO1 = &D_ADSL_RCL1->dsc_rdp_co_1;
#endif
     goto pfrse20;                          /* process next data       */
   }
   if ((ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent & (4096 - 1)) == 0){
     if (ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent) {
       m_update_keys( &ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl, NULL );
     }
   }
   achl_out_1 = adsl_gai1_out_save->achc_ginp_cur;  /* here is start output */
   if (   (D_ADSL_RCL1->chc_prot_rt02 & 0X08)  /* output encrypted     */
       && (D_ADSL_RCO1->imc_sec_level > 1)) {  /* with encryption      */
     /* generate random                                                */
#define ACHL_WORK_SHA1 ((int *) (chrl_work_2 + 4096))
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
     memcpy( ACHL_WORK_SHA1,
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_sha1_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_sha1_state) );
     memcpy( ACHL_WORK_MD5,
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_md5_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_md5_state) );
     m_put_le4( ACHL_WORK_UTIL_01, iml_out_len );
     SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     adsl_gai1_inp_w2 = adsl_gai1_out_save;  /* get pointer output saved */
     do {                                   /* loop over all gather structures output */
       iml1 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
       SHA1_Update( ACHL_WORK_SHA1,
                    adsl_gai1_inp_w2->achc_ginp_cur,
                    0, iml1 );
       RC4( adsl_gai1_inp_w2->achc_ginp_cur, 0, iml1,
            adsl_gai1_inp_w2->achc_ginp_cur, 0,
            ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_rc4_state );
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
     } while (adsl_gai1_inp_w2);
     if (D_ADSL_RCL1->chc_prot_rt03 & 0X08) {  /* flag for block count */
       m_put_le4( ACHL_WORK_UTIL_01, ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     }
     SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
     MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
     MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
     achl_out_1 -= D_SIZE_HASH;
     memcpy( achl_out_1, ACHL_WORK_UTIL_01, D_SIZE_HASH );
     ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent++;
     iml_out_len += D_SIZE_HASH;
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
   }
   if ((iml_out_len + 2) < 0X80) {          /* length in one byte      */
     *(--achl_out_1) = (unsigned char) (iml_out_len + 2);
     achl_out_1--;
     *achl_out_1 = *(achl_out_1 - 1);
   } else {                                 /* length in two bytes     */
     achl_out_1 -= 3;
     m_put_be2( achl_out_1 + 1, iml_out_len + 3 );
     *(achl_out_1 + 1) |= 0X80;             /* length in two bytes     */
   }
   adsl_gai1_out_save->achc_ginp_cur = achl_out_1;  /* output starts here */
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RCO1
#undef D_ADSL_RSE1
#define D_ADSL_RCO1 (&D_ADSL_RCL1->dsc_rdp_co_1)
#else
   D_ADSL_RCO1 = &D_ADSL_RCL1->dsc_rdp_co_1;
#endif
   D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
   goto pfrse20;                            /* process next data       */

   pfrse40:                                 /* send RDP4 data to client */
// to-do 20.11.13 KB - record may not be completely in input buffer - RDP client
// should use ied_fsfp_ignore               /* ignore this data        */
/* 26.09.06 KB - check if output work area too small                   */
   iml4 = 0;                                /* clear extra length      */
   iml5 = 0;                                /* clear length gather     */
   switch (D_ADSL_RCL1->iec_frse_bl) {
     case ied_frse_error_bl_02:             /* receive error block 02  */
     case ied_frse_lic_pr_type:             /* licencing block         */
       iml4 = 4;
       break;
     case ied_frse_lic_pr_req_cert:         /* server license request  */
       iml4 = 4 + sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand)  /* lic. preamble, server random, */
            + 4 + 4 + m_get_le4( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 + 4 )  /* ..., pbCompanyName, */
            + sizeof(ucrs_lic_bef_cert) + 2;  /* etc. up to and including server certificate length */
       break;
     case ied_frse_lic_pr_chll:             /* platform challenge      */
       iml4 = 4 + 6 + 2 + m_get_le2( D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 ) + 16;
       break;
     case ied_frse_actpdu_trail:            /* trailer of act PDU      */
       adsl_gai1_w1 = adsl_gai1_out_save;   /* chain gather data to be sent */
       do {
         iml5 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
       /* fall thru                                                    */
     case ied_frse_any_pdu_rec:             /* Share Control Header PDU source */
       iml4 = 6; // JB: len, in prot1, 2-byte le.
       break;
     case ied_frse_deactivate_all:
       iml4 = 2; // JB: len, in prot1, 2-byte le.
       break;
   }
   bol_encrypted = FALSE;                   /* packet is not encrypted */
   if (D_ADSL_RCL1->chc_prot_rt02 & SEC_ENCRYPT) {  /* output encrypted */
     bol_encrypted = TRUE;                  /* packet is encrypted     */
   }
   if (D_ADSL_RCL1->chc_prot_rt03 & (SEC_REDIRECTION_PKT >> 8)) {  /* Standard Security Server Redirection PDU */
     bol_encrypted = TRUE;                  /* packet is encrypted     */
   }
   iml1 = D_ADSL_RCL1->imc_pos_inp_frame + 4 + iml4;
   iml2 = iml1;                             /* size frame to send      */
   if (bol_encrypted) {                     /* packet is encrypted     */
     iml2 += D_SIZE_HASH;
   }
   iml3 = 4 + sizeof(ucrs_x224_p01) + 8 + iml2 + sizeof(struct dsd_gather_i_1);
   if (iml3 > (ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)) {
     if (iml3 >= adsp_hl_clib_1->inc_len_work_area) {
         iml_line_no = __LINE__;
         iml_source_no = 27088;    /* source line no for errors */
         goto pfrse96;
     }
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
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
         iml_line_no = __LINE__;
         iml_source_no = 27108;    /* source line no for errors */
         goto pfrse96;
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
   *ADSL_OA1->achc_lower = DEF_CONST_RDP_03;
   *(ADSL_OA1->achc_lower + 1) = 0;            /* second byte zero        */
   memcpy( ADSL_OA1->achc_lower + 4,
           ucrs_x224_p01,
           sizeof(ucrs_x224_p01) );
   *(ADSL_OA1->achc_lower + 4 + sizeof(ucrs_x224_p01)) = 0X68;  /* Send Data Indication */
   ADSL_OA1->achc_lower += 4 + sizeof(ucrs_x224_p01) + 1;
   m_put_be2( ADSL_OA1->achc_lower, D_USERID_SE2CL );
   ADSL_OA1->achc_lower += 2;
   m_put_be2( ADSL_OA1->achc_lower, D_ADSL_RCL1->imc_prot_chno );
   ADSL_OA1->achc_lower += 2;
   *ADSL_OA1->achc_lower++ = 0X70;          /* priority / segmentation */
   iml2 += iml5;                            /* length of record including gather */
   if (iml2 <= 127) {                       /* length in one byte      */
     *ADSL_OA1->achc_lower++ = (unsigned char) iml2;
   } else {                                 /* length in two bytes     */
     m_put_be2( ADSL_OA1->achc_lower, iml2 );
     *ADSL_OA1->achc_lower |= 0X80;         /* flag length two bytes   */
     ADSL_OA1->achc_lower += 2;
   }
   *ADSL_OA1->achc_lower++ = D_ADSL_RCL1->chc_prot_rt02;
   *ADSL_OA1->achc_lower++ = D_ADSL_RCL1->chc_prot_rt03;
   /* two bytes padding zero                                           */
   *ADSL_OA1->achc_lower++ = 0;
   *ADSL_OA1->achc_lower++ = 0;
   if (bol_encrypted) {                     /* packet is encrypted     */
     /* generate random                                                */
#define ACHL_WORK_SHA1 ((int *) chrl_work_2)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
     memcpy( ACHL_WORK_SHA1,
             ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
     memcpy( ACHL_WORK_MD5,
             ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
     m_put_le4( ACHL_WORK_UTIL_01, iml1 + iml5 - 4 );
     SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     if (iml4) {
       switch (D_ADSL_RCL1->iec_frse_bl) {
         case ied_frse_error_bl_02:         /* receive error block 02  */
           m_put_le2( ADSL_OA1->achc_lower + D_SIZE_HASH + 0, iml1 - 4 );
           m_put_le2( ADSL_OA1->achc_lower + D_SIZE_HASH + 2, D_ADSL_RCL1->imc_prot_1 );
           break;
         case ied_frse_lic_pr_type:         /* licencing block         */
           m_put_le4( ADSL_OA1->achc_lower + D_SIZE_HASH, D_ADSL_RCL1->imc_prot_1 );
           break;
         case ied_frse_lic_pr_req_cert:     /* server license request  */
           *(ADSL_OA1->achc_lower + D_SIZE_HASH + 0) = 0x01;  /* LICENSE_REQUEST */
           *(ADSL_OA1->achc_lower + D_SIZE_HASH + 1) = D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers;
           m_put_le2( ADSL_OA1->achc_lower + D_SIZE_HASH + 2,
                      D_ADSL_RCL1->imc_pos_inp_frame + iml4 );
           memcpy( ADSL_OA1->achc_lower + D_SIZE_HASH + 4,
                   D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand,  /* licensing server random */
                   sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand) );
           memcpy( ADSL_OA1->achc_lower + D_SIZE_HASH + 4 + sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand),
                   D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1,
                   iml4 - (4 + sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand) + 2) );
           /* send 0x0000 as certificate length and no special certificate for licensing, even if */
           /* we received one. As we do not have the private key for it, we use the general key */
           *(ADSL_OA1->achc_lower + D_SIZE_HASH + iml4 - 2) = 0;
           *(ADSL_OA1->achc_lower + D_SIZE_HASH + iml4 - 1) = 0;
           break;
         case ied_frse_lic_pr_chll:         /* platform challenge      */
           *(ADSL_OA1->achc_lower + D_SIZE_HASH + 0) = 0x02;  /* PLATFORM_CHALLENGE */
           *(ADSL_OA1->achc_lower + D_SIZE_HASH + 1) = D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers;
           m_put_le2( ADSL_OA1->achc_lower + D_SIZE_HASH + 2,
                      D_ADSL_RCL1->imc_pos_inp_frame + iml4 );
           memset( ADSL_OA1->achc_lower + D_SIZE_HASH + 4, 0, 6 );  /* unused connect flags and unspecified blob type */
           memcpy( ADSL_OA1->achc_lower + D_SIZE_HASH + 10,
                   D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1,
                   iml4 - 10 );           /* bloblength, hwid and hash */
           /* free temporary data buffer                               */
           ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
           ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
           m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 );
           D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 = NULL;
           D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len = 0;
           break;
         case ied_frse_deactivate_all:
           m_put_le2( ADSL_OA1->achc_lower + D_SIZE_HASH + 0, D_ADSL_RCL1->imc_prot_1 );
           break;
         case ied_frse_actpdu_trail:        /* trailer of act PDU      */
         case ied_frse_any_pdu_rec:         /* Share Control Header PDU source */
           m_put_le2( ADSL_OA1->achc_lower + D_SIZE_HASH + 0, iml1 + iml5 - 4 );
           m_put_le2( ADSL_OA1->achc_lower + D_SIZE_HASH + 2, D_ADSL_RCL1->imc_prot_1 );
           m_put_le2( ADSL_OA1->achc_lower + D_SIZE_HASH + 4, D_ADSL_RCL1->imc_prot_8 );  /* Share Control Header PDU source */
           break;
         case ied_frse_xyz_end_pdu:         /* end of PDU              */
         default:
         iml_line_no = __LINE__;
         iml_source_no = 27258;    /* source line no for errors */
         goto pfrse96;
       }
       SHA1_Update( ACHL_WORK_SHA1,
                    ADSL_OA1->achc_lower + D_SIZE_HASH,
                    0, iml4 );
     }
     adsl_gai1_inp_w2 = adsl_gai1_inp_1;
     iml2 = D_ADSL_RCL1->imc_pos_inp_frame;
     if (D_ADSL_RCL1->iec_frse_bl == ied_frse_actpdu_trail) {  /* trailer of act PDU */
       adsl_gai1_inp_w2 = adsl_gai1_out_save;   /* chain gather data to be sent */
       iml2 = iml5;                         /* length gather           */
     }
     while (TRUE) {                         /* loop over all gather structures input */
       iml1 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
       if (iml1 > iml2) {
         iml1 = iml2;                       /* only data in this frame */
       }
       SHA1_Update( ACHL_WORK_SHA1,
                    adsl_gai1_inp_w2->achc_ginp_cur,
                    0, iml1 );
       iml2 -= iml1;                        /* subtract data processed */
       if (iml2 <= 0) break;                /* all data processed      */
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
       if (adsl_gai1_inp_w2 == NULL) {      /* already end of chain    */
         goto pfrse96;                      /* program illogic         */
       }
     }
     if (D_ADSL_RCL1->chc_prot_rt03 & (SEC_SECURE_CHECKSUM >> 8)) {  /* flag for block count */
       m_put_le4( ACHL_WORK_UTIL_01, ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     }
     SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
     MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
     MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
     memcpy( ADSL_OA1->achc_lower, ACHL_WORK_UTIL_01, D_SIZE_HASH );
     ADSL_OA1->achc_lower += D_SIZE_HASH;
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
     achl1 = ADSL_OA1->achc_lower;          /* save position start encrypted */
     ADSL_OA1->achc_lower += iml4;
   } else {                                 /* output not encrypted    */
     switch (D_ADSL_RCL1->iec_frse_bl) {
       case ied_frse_error_bl_02:           /* receive error block 02  */
         m_put_le2( ADSL_OA1->achc_lower, iml1 - 4 );
         ADSL_OA1->achc_lower += 2;
         m_put_le2( ADSL_OA1->achc_lower, D_ADSL_RCL1->imc_prot_1 );
         ADSL_OA1->achc_lower += 2;
         break;
       case ied_frse_lic_pr_type:           /* licencing block         */
         /* copy licencing preamble fetched in ied_fsfp_int_lit_e part */
         m_put_le4( ADSL_OA1->achc_lower, D_ADSL_RCL1->imc_prot_1 );
         ADSL_OA1->achc_lower += 4;
         break;
       case ied_frse_lic_pr_req_cert:       /* server license request  */
         *ADSL_OA1->achc_lower++ = 0X01;    /* LICENSE_REQUEST         */
         *ADSL_OA1->achc_lower++ = D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers;
         m_put_le2( ADSL_OA1->achc_lower,
                    D_ADSL_RCL1->imc_pos_inp_frame + iml4);
         ADSL_OA1->achc_lower += 2;
         memcpy( ADSL_OA1->achc_lower,
                 D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand,  /* licensing server random */
                 sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand) );
         ADSL_OA1->achc_lower += sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand);
         memcpy( ADSL_OA1->achc_lower,
                 D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1,
                 iml4 - (4 + sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand) + 2) );
         ADSL_OA1->achc_lower += iml4 - (4 + sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_serand) + 2);
         /* send 0x0000 as certificate length and no special certificate for licensing, even if */
         /* we received one. As we do not have the private key for it, we use the general key */
         *ADSL_OA1->achc_lower++ = 0;
         *ADSL_OA1->achc_lower++ = 0;
         break;
       case ied_frse_lic_pr_chll:           /* platform challenge      */
         *ADSL_OA1->achc_lower++ = 0X02;    /* PLATFORM_CHALLENGE      */
         *ADSL_OA1->achc_lower++ = D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers;
         m_put_le2( ADSL_OA1->achc_lower,
                    D_ADSL_RCL1->imc_pos_inp_frame + iml4 );
         ADSL_OA1->achc_lower += 2;
         memset( ADSL_OA1->achc_lower, 0, 6 );  /* unused connect flags and unspecified blob type */
         ADSL_OA1->achc_lower += 6;
         memcpy( ADSL_OA1->achc_lower,
                 D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1,
                 iml4 - 10 );             /* bloblength, hwid and hash */
         ADSL_OA1->achc_lower += iml4 - 10;
         /* free temporary data buffer                                 */
         ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
         ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
         m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 );
         D_ADSL_RCO1->adsc_lic_neg->chrc_lic_1 = NULL;
         D_ADSL_RCO1->adsc_lic_neg->imc_lic_1_len = 0;
         break;
       case ied_frse_deactivate_all:
         m_put_le2( ADSL_OA1->achc_lower, D_ADSL_RCL1->imc_prot_1 );
         ADSL_OA1->achc_lower += 2;
         break;
       case ied_frse_actpdu_trail:          /* trailer of act PDU      */
       case ied_frse_any_pdu_rec:           /* Share Control Header PDU source */
         m_put_le2( ADSL_OA1->achc_lower + 0, iml1 + iml5 - 4 );
         m_put_le2( ADSL_OA1->achc_lower + 2, D_ADSL_RCL1->imc_prot_1 );
         m_put_le2( ADSL_OA1->achc_lower + 4, D_ADSL_RCL1->imc_prot_8 );  /* Share Control Header PDU source */
         ADSL_OA1->achc_lower += 6;
         break;
     }
   }
     while (TRUE) {                         /* loop over all gather structures input */
       iml1 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       if (iml1 > D_ADSL_RCL1->imc_pos_inp_frame) {
         iml1 = D_ADSL_RCL1->imc_pos_inp_frame;  /* only data in this frame */
       }
       memcpy( ADSL_OA1->achc_lower,
               adsl_gai1_inp_1->achc_ginp_cur, iml1 );
       adsl_gai1_inp_1->achc_ginp_cur += iml1;  /* add length to input */
       ADSL_OA1->achc_lower += iml1;           /* add length copied       */
       D_ADSL_RCL1->imc_pos_inp_frame -= iml1;  /* subtract data copied */
       if (D_ADSL_RCL1->imc_pos_inp_frame <= 0) break;  /* all data copied */
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next gather */
       if (adsl_gai1_inp_1 == NULL) {       /* already end of chain    */
         goto pfrse96;                      /* program illogic         */
       }
     }
   m_put_be2( ADSL_GAI1_OUT_G->achc_ginp_cur + 2,
              (ADSL_OA1->achc_lower - ADSL_GAI1_OUT_G->achc_ginp_cur) + iml5 );
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
         iml_line_no = __LINE__;
         iml_source_no = 27478;    /* source line no for errors */
         goto pfrse96;
   }
   if ((ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent & (4096 - 1)) == 0){
     if (ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent) {
       m_update_keys( &ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl, NULL );
     }
   }
   if (bol_encrypted) {                     /* packet is encrypted     */
     RC4( achl1, 0, ADSL_OA1->achc_lower - achl1,
          achl1, 0,
          ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_rc4_state );
     if (D_ADSL_RCL1->iec_frse_bl == ied_frse_actpdu_trail) {  /* trailer of act PDU */
       adsl_gai1_w1 = adsl_gai1_out_save;   /* chain gather data to be sent */
       do {                                 /* loop to encrypt data    */
         RC4( adsl_gai1_w1->achc_ginp_cur, 0, adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
              adsl_gai1_w1->achc_ginp_cur, 0,
              ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_rc4_state );
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       } while (adsl_gai1_w1);
     }
     ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent++;
   }
   ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
   if (D_ADSL_RCL1->iec_frse_bl == ied_frse_actpdu_trail) {  /* trailer of act PDU */
     ADSL_GAI1_OUT_G->adsc_next = adsl_gai1_out_save;   /* chain gather data to be sent */
   }
   *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
   ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
   if (D_ADSL_RCL1->iec_frse_bl == ied_frse_actpdu_trail) {  /* trailer of act PDU */
     adsl_gai1_w1 = adsl_gai1_out_save;     /* chain gather data to be sent */
     while (adsl_gai1_w1->adsc_next) adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
     ADSL_OA1->aadsc_gai1_out_to_client = &adsl_gai1_w1->adsc_next;  /* new chain output data to client */
   }
#undef ADSL_GAI1_OUT_G
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
     case ied_frse_lic_pr_chll:             /* platform challenge      */
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

   p_se2cl_send_end_00:                     /* send end of communication */
   if ((sizeof(ucrs_send_session_end) + sizeof(struct dsd_gather_i_1)) > (ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)) {
     if (iml3 >= adsp_hl_clib_1->inc_len_work_area) {
         iml_line_no = __LINE__;
         iml_source_no = 27856;    /* source line no for errors */
         goto pfrse96;
     }
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
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
         iml_line_no = __LINE__;
         iml_source_no = 27872;    /* source line no for errors */
         goto pfrse96;
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
   memcpy( ADSL_OA1->achc_lower, ucrs_send_session_end, sizeof(ucrs_send_session_end) );
   *(ADSL_OA1->achc_lower + 7) = (unsigned char) D_ADSL_RCL1->imc_prot_1;  /* Send Data Indication */
   ADSL_OA1->achc_lower += sizeof(ucrs_send_session_end);
   ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
   *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
   ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
   D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_no_session;  /* no more session */
   goto pfrse20;                            /* process next data       */

   p_frse_send_hrdpext1:                    /* send HOB-RDP-EXT1 data to client */
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < (ADSL_OA1->achc_lower + D_ADSL_RCL1->imc_prot_1)) {
     M_ERROR_FRSE_ILLOGIC                  /* program illogic         */
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
   *ADSL_OA1->achc_lower = DEF_CONST_RDP_03;
   *(ADSL_OA1->achc_lower + 1) = (unsigned char) 0XFF;  /* second byte constant */
   *(ADSL_OA1->achc_lower + 2) = (unsigned char) (D_ADSL_RCL1->imc_prot_1 << 8);  /* first byte length */
   *(ADSL_OA1->achc_lower + 3) = (unsigned char) D_ADSL_RCL1->imc_prot_1;  /* second byte length */
   memcpy( ADSL_OA1->achc_lower + 4,
           D_ADSL_RCL1->chrc_prot_1,
           D_ADSL_RCL1->imc_prot_1 - 4 );
   ADSL_OA1->achc_lower += D_ADSL_RCL1->imc_prot_1;
   ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
   *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
   ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
   D_ADSL_RCL1->iec_frse_bl = ied_frse_start;  /* start of communication */
   D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
   goto pfrse20;                            /* process next data       */


   pfrse_send_secbl:                        /* send second block to server */
#define D_ADSL_VCH (D_ADSL_RCO1->adsrc_vc_1 + (D_ADSL_RCO1->imc_no_virt_ch - iml1))
   /* fields CS data in GCC user data                                  */
   achl1 = (char *) ADSL_RDPA_F->ac_cs_block_ch;  /* chain GCC client data */
   iml1 = 0;                                /* clear count             */
   while (achl1) {
     iml1 += m_get_le2( achl1 + sizeof(void *) + sizeof(short int) );
     achl1 = *((char **) achl1);            /* get next in chain       */
   }
   if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)
         < (376 + iml1 + D_ADSL_RCO1->imc_no_virt_ch * (sizeof(D_ADSL_VCH->byrc_name) + 4) + sizeof(struct dsd_gather_i_1))) {
         iml_line_no = __LINE__;
         iml_source_no = 27948;    /* source line no for errors */
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
   /* field highColorDepth                                             */
   m_put_le2( achl1 + 264 + 8, D_ADSL_RCO1->imc_cl_coldep );
   m_put_le2( achl1 + 264 + 10, D_ADSL_RCO1->usc_cl_supported_color_depth );  /* client capabilities */
   m_put_le2( achl1 + 264 + 12, D_ADSL_RCO1->usc_cl_early_capability_flag );  /* client capabilities */
   /* output CS_NET                                                    */
#define D_POS_VCH (264 + sizeof(ucrs_x224_encry))
   achl1 += D_POS_VCH;                      /* current output position */
#undef D_POS_VCH
   *achl1++ = 0X03;
   *achl1++ = (unsigned char) 0XC0;
   iml1 = D_ADSL_RCO1->imc_no_virt_ch;
   m_put_le2( achl1,
              8 + iml1 * DEF_LEN_VIRTCH_STA );
   achl1 += sizeof(short int);
   m_put_le4( achl1,
              iml1 );
   achl1 += sizeof(int);
   while (iml1) {                           /* loop over all channels  */
     memcpy( achl1,
             D_ADSL_VCH->byrc_name,
             sizeof(D_ADSL_VCH->byrc_name) );
     achl1 += sizeof(D_ADSL_VCH->byrc_name);
     m_put_le4( achl1, D_ADSL_VCH->imc_flags );
     achl1 += 4;                            /* after flags             */
     iml1--;                                /* decrement index         */
   }
   iml1 = 0X03 + 1;                         /* first with type after CS_NET */
   while (TRUE) {                           /* loop to copy CS data before Client Network Data (TS_UD_CS_NET) */
     achl2 = (char *) ADSL_RDPA_F->ac_cs_block_ch;  /* chain GCC client data */
     achl3 = NULL;                          /* no entry found          */
     while (achl2) {                        /* loop over CS data       */
       if (   (*((unsigned char *) achl2 + sizeof(void *)) >= iml1)
           && (*((unsigned char *) achl2 + sizeof(void *)) != 0X04)  /* 0XC004 CS_CLUSTER */
           && (*((unsigned char *) achl2 + sizeof(void *)) != 0X06)  /* 0XC006 CS_MCS_MSGCHANNEL */
           && (*((unsigned char *) achl2 + sizeof(void *)) != 0X0A)) {  /* 0XC00A CS_MULTITRANSPORT */
         if (   (achl3 == NULL)
             || (*((unsigned char *) achl2 + sizeof(void *)) < *((unsigned char *) achl3 + sizeof(void *)))) {
           achl3 = achl2;                   /* save this entry         */
         }
       }
       achl2 = *((char **) achl2);          /* get next in chain       */
     }
     if (achl3 == NULL) break;              /* no entry found          */
     iml2 = m_get_le2( achl3 + sizeof(void *) + sizeof(short int) );  /* get length */
     memcpy( achl1, achl3 + sizeof(void *), iml2 );
     achl1 += iml2;
     iml1 = *((unsigned char *) achl3 + sizeof(void *)) + 1;  /* next entry */
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


   pfrse_vch_00:                            /* virtual channel data received */
   while (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) return;   /* wait for more data      */
   }
   if (D_ADSL_RCL1->imc_pos_inp_frame < (2 + 1)) {
         iml_line_no = __LINE__;
         iml_source_no = 28120;    /* source line no for errors */
         goto pfrse92;
   }
   /* trace server to client virtual channel                           */
   ADSL_RDPA_F->dsc_rdptr1.iec_tr_command   /* tracer component command */
     = ied_trc_se2cl_vch;                   /* server to client virtual channel */
   ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_part - (D_ADSL_RCL1->imc_pos_inp_frame - 2);
   /* virtual channel segmentation flags                               */
   memcpy( ADSL_RDPA_F->dsc_rdptr1.chrc_vch_segfl, D_ADSL_RCL1->chrc_vch_segfl, sizeof(ADSL_RDPA_F->dsc_rdptr1.chrc_vch_segfl) );
   ADSL_RDPA_F->dsc_rdptr1.usc_vch_no = D_ADSL_RCL1->imc_prot_chno;  /* virtual channel no com */
   ADSL_RDPA_F->dsc_rdptr1.imc_prot1 = D_ADSL_RCL1->umc_vch_ulen;  /* variable field */
   if (*adsl_gai1_inp_1->achc_ginp_cur & 0X20) {  /* data compressed   */
     goto pfrse_vch_20;                     /* virtual channel data compressed */
   }
   bol_compressed = FALSE;                  /* save not compressed     */
   /* remove two bytes of compression flags                            */
   iml1 = 2;                                /* bytes to remove         */
   D_ADSL_RCL1->imc_pos_inp_frame -= iml1;
   while (TRUE) {
     iml_rec = adsl_gai1_inp_1->achc_ginp_end
                 - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml_rec > iml1) iml_rec = iml1;
     adsl_gai1_inp_1->achc_ginp_cur += iml_rec;
     iml1 -= iml_rec;
     if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) break;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     if (iml1 == 0) break;
   }
   adsl_gai1_inp_w2 = adsl_gai1_inp_1;      /* save input data         */
   iml1 = D_ADSL_RCL1->imc_pos_inp_frame ;  /* length of data          */
   goto pfrse_vch_40;                       /* send virtual channel to client */

   pfrse_vch_20:                            /* virtual channel data compressed */
   if ((D_ADSL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) == 0) {  /* compression not enabled */
         iml_line_no = __LINE__;
         iml_source_no = 28160;    /* source line no for errors */
         goto pfrse92;
   }
       bol_compressed = TRUE;                   /* save compressed         */
// to-do 21.02.12 KB decompression
   /* decompress data                                                  */
   D_ADSL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
   D_ADSL_RCO1->dsc_cdrf_dec.chrc_header[ 0 ]  /* copy compression header */
     = *(adsl_gai1_inp_1->achc_ginp_cur);   /* address act input-data  */
   /* remove two bytes of compression flags                            */
   iml1 = 2;                                /* bytes to remove         */
   D_ADSL_RCL1->imc_pos_inp_frame -= iml1;
   while (TRUE) {
     iml_rec = adsl_gai1_inp_1->achc_ginp_end
                 - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml_rec > iml1) iml_rec = iml1;
     adsl_gai1_inp_1->achc_ginp_cur += iml_rec;
     iml1 -= iml_rec;
     if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) break;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     if (adsl_gai1_inp_1 == NULL) {         /* already end of chain    */
       M_ERROR_FRSE_ILLOGIC
     }
     if (iml1 == 0) break;
   }
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
                     __LINE__, 28252,  /* line number for errors */
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
   /* get pointer to virtual channel structure                         */
   memset( &dsl_rdp_param_vch_1, 0, sizeof(struct dsd_rdp_param_vch_1) );  /* clear RDP parameters virus checking */
   dsl_rdp_param_vch_1.adsc_conf = (struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf;  /* configuration data */
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   memcpy( &dsl_rdp_param_vch_1.dsc_s1, &ADSL_RDPA_F->dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
//   dsl_rdp_param_vch_1.adsc_cb_c = ADSL_RDPA_F->adsc_cb_c;  /* cliprdr flags */
   dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */
   /* virtual channel segmentation flags                               */
   memcpy( dsl_rdp_param_vch_1.chrc_vch_segfl, D_ADSL_RCL1->chrc_vch_segfl, sizeof(dsl_rdp_param_vch_1.chrc_vch_segfl) );
   iml2 = D_ADSL_RCO1->imc_no_virt_ch;      /* number of virtual channels */
   while (iml2) {                           /* loop over all virtual channels */
     iml2--;                                /* decrement index         */
     if (D_ADSL_RCO1->adsrc_vc_1[ iml2 ].usc_vch_no == D_ADSL_RCL1->imc_prot_chno) {  /* virtual channel no com */
       dsl_rdp_param_vch_1.adsc_rdp_vc_1 = &D_ADSL_RCO1->adsrc_vc_1[ iml2 ];  /* RDP virtual channel */
       break;
     }
   }
   if (dsl_rdp_param_vch_1.adsc_rdp_vc_1 == NULL) {
         iml_line_no = __LINE__;
         iml_source_no = 28317;    /* source line no for errors */
         goto pfrse92;
   }
   if (dsl_rdp_param_vch_1.adsc_rdp_vc_1->chc_hob_vch) {
     ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
     ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
     memcpy( &dsl_rdp_param_vch_1.dsc_s1, &ADSL_RDPA_F->dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
     dsl_rdp_param_vch_1.ac_chain_send_frse = al_chain_send_frse;  /* chain of buffers to be sent to the client */
     dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */
     dsl_rdp_param_vch_1.adsc_output_area_1 = ADSL_OA1;  /* output of subroutine */
     dsl_rdp_param_vch_1.adsc_gather_i_1_in = adsl_gai1_inp_w2;
     dsl_rdp_param_vch_1.imc_len_vch_input = iml1;  /* remaining data  */
     iel_sdh_ret1 = m_rdp_vch1_rec_frse( &dsl_rdp_param_vch_1 );
     if (iel_sdh_ret1 == ied_sdhr1_fatal_error) {  /* fatal error occured, abend */
       goto p_cleanup_00;                   /* do cleanup now          */
     }
     memcpy( &ADSL_RDPA_F->dsc_s1, &dsl_rdp_param_vch_1.dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
     al_chain_send_frse = dsl_rdp_param_vch_1.ac_chain_send_frse;  /* chain of buffers to be sent to the client */
     if (dsl_rdp_param_vch_1.boc_callrevdir) {  /* call on reverse direction */
       adsp_hl_clib_1->boc_callrevdir = TRUE;  /* set call on reverse direction */
     }
     if (iel_sdh_ret1 == ied_sdhr1_failed) {  /* do not send virtual channel command */
       goto pfrse_vch_60;                   /* end of send virtual channel */
     }
   }
   if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < 128) {  /* get new area */
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
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     goto pfrse96;                          /* program illogic         */
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
   ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
   adsl_gai1_out_save = ADSL_GAI1_OUT_G;    /* save start output data  */
   /* compute where to start output                                    */
   achl_out_1 = ADSL_OA1->achc_lower + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1 + 2 + 4 + D_SIZE_HASH + 4 + 2 + 2;
#undef ADSL_GAI1_OUT_G
   achl1 = achl_out_1;                      /* save position start output */
#define D_ADSL_SE_RCO1 (&ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1)
   if (D_ADSL_SE_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) goto pfrse_vch_44;   /* send virtual channel data compressed */
#undef D_ADSL_SE_RCO1
   memset( achl_out_1 - 2, 0, 2 );          /* clear compression flags */
   iml_out_len = iml1;                      /* set length output       */
   /* do not eat input                                                 */
   achl2 = adsl_gai1_inp_w2->achc_ginp_cur;
   while (TRUE) {
     iml_rec = adsl_gai1_inp_w2->achc_ginp_end - achl2;
     if (iml_rec > iml1) iml_rec = iml1;
     if (iml_rec > (ADSL_OA1->achc_upper - achl_out_1)) iml_rec = ADSL_OA1->achc_upper - achl_out_1;
     memcpy( achl_out_1, achl2, iml_rec );
     achl2 += iml_rec;
     iml1 -= iml_rec;
     achl_out_1 += iml_rec;
     if (iml1 == 0) break;
     if (achl2 >= adsl_gai1_inp_w2->achc_ginp_end) {
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
       if (adsl_gai1_inp_w2 == NULL) {      /* already end of chain    */
         goto pfrse96;                      /* program illogic         */
       }
       achl2 = adsl_gai1_inp_w2->achc_ginp_cur;
     }
     if (achl_out_1 < ADSL_OA1->achc_upper) continue;  /* still space in output-area */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;
     /* get new block for more output                                  */
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
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
       M_ERROR_FRSE_ILLOGIC                 /* program illogic         */
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
     ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
   }
   goto pfrse_vch_48;                       /* output finished         */

   pfrse_vch_44:                            /* send virtual channel data compressed */
   iml_compr_inp = iml1;                    /* input to compression    */
   D_ADSL_RCL1->imc_pos_inp_frame = 0;      /* all data consumed       */
   iml_out_len = 0;                         /* clear length output     */
#define D_ADSL_SE_RCO1 (&ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1)
   D_ADSL_SE_RCO1->dsc_cdrf_enc.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_SE_RCO1->dsc_cdrf_enc.amc_aux = adsp_hl_clib_1->amc_aux;
#define ADSL_GAI1_S ((struct dsd_gather_i_1 *) chrl_work_2)
   adsl_gai1_w1 = ADSL_GAI1_S;              /* first gather here       */
   while (TRUE) {                           /* loop over input bytes   */
     iml1 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
     if (iml1 > iml_compr_inp) iml1 = iml_compr_inp;
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_inp_w2->achc_ginp_cur;
     adsl_gai1_w1->achc_ginp_end = adsl_gai1_inp_w2->achc_ginp_cur + iml1;
     adsl_gai1_inp_w2->achc_ginp_cur += iml1;
     if (adsl_gai1_inp_w2->achc_ginp_cur >= adsl_gai1_inp_w2->achc_ginp_end) {
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
     }
     iml_compr_inp -= iml1;                 /* remaining data to compress */
     if (iml_compr_inp <= 0) break;         /* end of data to compress */
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain gather  */
     adsl_gai1_w1++;                        /* use next gather         */
   }
   adsl_gai1_w1->adsc_next = NULL;          /* end of data             */
   D_ADSL_SE_RCO1->dsc_cdrf_enc.adsc_gai1_in = ADSL_GAI1_S;  /* input data */
#undef ADSL_GAI1_S
   D_ADSL_SE_RCO1->dsc_cdrf_enc.boc_mp_flush = TRUE;  /* end-of-record input */
   D_ADSL_SE_RCO1->dsc_cdrf_enc.achc_out_cur = achl_out_1;  /* current end of output data */
   D_ADSL_SE_RCO1->dsc_cdrf_enc.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
   while (TRUE) {                           /* loop over gather input  */
     D_ADSL_SE_RCO1->amc_cdr_enc( &D_ADSL_SE_RCO1->dsc_cdrf_enc );
     if (D_ADSL_SE_RCO1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {
       m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d compression error %d.",
                     __LINE__, 28497,  /* line number for errors */
                     D_ADSL_SE_RCO1->dsc_cdrf_enc.imc_return );
       goto p_cleanup_00;                   /* do cleanup now          */
     }
     iml_out_len += D_ADSL_SE_RCO1->dsc_cdrf_enc.achc_out_cur - achl_out_1;
     achl_out_1 = D_ADSL_SE_RCO1->dsc_cdrf_enc.achc_out_cur;  /* set end of output */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;
     if (D_ADSL_SE_RCO1->dsc_cdrf_enc.boc_sr_flush) break;  /* end-of-record output */
     /* get new block for more output                                  */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error        */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       goto p_cleanup_20;                   /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
         iml_line_no = __LINE__;
         iml_source_no = 28526;    /* source line no for errors */
         goto pfrse96;
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
     ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
     D_ADSL_SE_RCO1->dsc_cdrf_enc.achc_out_cur = achl_out_1;  /* current end of output data */
     D_ADSL_SE_RCO1->dsc_cdrf_enc.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
   }
   *(achl1 - 2) = D_ADSL_SE_RCO1->dsc_cdrf_enc.chrc_header[ 0 ];  /* copy compression header */
   *(achl1 - 1) = 0;                        /* second byte compression header */
#undef D_ADSL_SE_RCO1

   pfrse_vch_48:                            /* output finished         */
   ADSL_OA1->achc_lower = ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set end of block */
   /* make header of output                                            */
   achl1 -= 4 + 2 + 2;                      /* length uncompressed, segmentation flags and compression flags */
   m_put_le4( achl1, D_ADSL_RCL1->umc_vch_ulen );
   memcpy( achl1 + 4, D_ADSL_RCL1->chrc_vch_segfl, sizeof(D_ADSL_RCL1->chrc_vch_segfl) );
   iml_out_len += 4 + 2 + 2;                /* add length output       */
   if ((ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent & (4096 - 1)) == 0){
     if (ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent) {
       m_update_keys( &ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl, NULL );
     }
   }
   if (D_ADSL_RCL1->chc_prot_rt02 & 0X08) {  /* output encrypted       */
     /* generate random                                                */
#define ACHL_WORK_SHA1 ((int *) chrl_work_2)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
     memcpy( ACHL_WORK_SHA1,
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_sha1_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_sha1_state) );
     memcpy( ACHL_WORK_MD5,
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_md5_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_md5_state) );
     m_put_le4( ACHL_WORK_UTIL_01, iml_out_len );
     SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     adsl_gai1_out_save->achc_ginp_cur = achl1;
     adsl_gai1_inp_w2 = adsl_gai1_out_save;
     iml2 = iml_out_len;                    /* get length output       */
     while (TRUE) {                         /* loop over all gather structures input */
       iml1 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
       if (iml1 > iml2) {
         iml1 = iml2;                       /* only data in this frame */
       }
       SHA1_Update( ACHL_WORK_SHA1,
                    adsl_gai1_inp_w2->achc_ginp_cur,
                    0, iml1 );
       RC4( adsl_gai1_inp_w2->achc_ginp_cur, 0, iml1,
            adsl_gai1_inp_w2->achc_ginp_cur, 0,
            ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_rc4_state );
       iml2 -= iml1;                        /* subtract data processed */
       if (iml2 <= 0) break;                /* all data processed      */
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
       if (adsl_gai1_inp_w2 == NULL) {      /* already end of chain    */
         goto pfrse96;                      /* program illogic         */
       }
     }
     if (D_ADSL_RCL1->chc_prot_rt03 & 0X08) {  /* flag for block count */
       m_put_le4( ACHL_WORK_UTIL_01, ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     }
     SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
     MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
     MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
     achl1 -= D_SIZE_HASH;                  /* subtract length hash    */
     memcpy( achl1, ACHL_WORK_UTIL_01, D_SIZE_HASH );
     iml_out_len += D_SIZE_HASH;            /* add length hash         */
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
   }
   achl1 -= 1 + 2 + 2;                      /* length length, fl2, fl3, padding */
   *(achl1 + 1 + 0) = D_ADSL_RCL1->chc_prot_rt02;
   *(achl1 + 1 + 1) = D_ADSL_RCL1->chc_prot_rt03;
   /* two bytes padding zero                                           */
   *(achl1 + 1 + 2 + 0) = 0;
   *(achl1 + 1 + 2 + 1) = 0;
   iml_out_len += 4;                        /* add length header       */
   *achl1 = (unsigned char) iml_out_len;    /* one byte length         */
   if (iml_out_len >= 0X0080) {             /* length in two bytes     */
     achl1--;                               /* space for second byte   */
     m_put_be2( achl1, iml_out_len );
     *achl1 |= 0X80;                        /* flag length two bytes   */
     iml_out_len += 1;                      /* increment length        */
   }
   achl1 -= 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1;
   iml_out_len += 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1 + 1;
   adsl_gai1_out_save->achc_ginp_cur = achl1;
   *achl1 = DEF_CONST_RDP_03;
   *(achl1 + 1) = 0;                        /* second byte zero        */
   m_put_be2( achl1 + 2, iml_out_len );
   memcpy( achl1 + 4,
           ucrs_x224_p01,
           sizeof(ucrs_x224_p01) );
   *(achl1 + 4 + sizeof(ucrs_x224_p01)) = 0X68;  /* Send Data Indication */
   m_put_be2( achl1 + 4 + sizeof(ucrs_x224_p01) + 1, D_USERID_SE2CL );
   m_put_be2( achl1 + 4 + sizeof(ucrs_x224_p01) + 1 + 2, D_ADSL_RCL1->imc_prot_chno );
   *(achl1 + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2) = 0XF0;  /* priority / segmentation */
   ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent++;  /* count block sent */

   pfrse_vch_60:                            /* end of send virtual channel */
   D_ADSL_RCL1->iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
   D_ADSL_RCL1->iec_frse_bl = ied_frse_any_pdu_rec;  /* ????ive block active PDU */
   dsl_gai1_comp_data.achc_ginp_cur = NULL;  /* no decompressed data   */
   if (D_ADSL_RCL1->imc_pos_inp_frame == 0) goto pfrse20;  /* process next data */
   /* remove all input data                                            */
   while (TRUE) {
     if (adsl_gai1_inp_1 == NULL) {         /* already end of chain    */
       iml_line_no = __LINE__;
       iml_source_no = 28938;    /* source line no for errors */
       goto pfrse96;
     }
     iml_rec = adsl_gai1_inp_1->achc_ginp_end
                 - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml_rec > D_ADSL_RCL1->imc_pos_inp_frame) iml_rec = D_ADSL_RCL1->imc_pos_inp_frame;
     adsl_gai1_inp_1->achc_ginp_cur += iml_rec;
     D_ADSL_RCL1->imc_pos_inp_frame -= iml_rec;
     if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) break;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     if (D_ADSL_RCL1->imc_pos_inp_frame == 0) break;
   }
   goto pfrse20;                            /* process next data       */

   pfrse80:                                 /* send to client          */
   /* get pointer to virtual channel structure                         */
   memset( &dsl_rdp_param_vch_1, 0, sizeof(struct dsd_rdp_param_vch_1) );  /* clear RDP parameters virus checking */
   dsl_rdp_param_vch_1.adsc_conf = (struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf;  /* configuration data */
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   memcpy( &dsl_rdp_param_vch_1.dsc_s1, &ADSL_RDPA_F->dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
//   dsl_rdp_param_vch_1.adsc_cb_c = ADSL_RDPA_F->adsc_cb_c;  /* cliprdr flags */
   dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */
   dsl_rdp_param_vch_1.ac_chain_send_frse = al_chain_send_frse;  /* chain of buffers to be sent to the client */
   dsl_rdp_param_vch_1.adsc_output_area_1 = ADSL_OA1;  /* output of subroutine */
   iel_sdh_ret1 = m_rdp_vch1_get_frse( &dsl_rdp_param_vch_1 );
   if (iel_sdh_ret1 == ied_sdhr1_fatal_error) {  /* fatal error occured, abend */
     goto p_cleanup_00;                     /* do cleanup now          */
   }
   memcpy( &ADSL_RDPA_F->dsc_s1, &dsl_rdp_param_vch_1.dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
   al_chain_send_frse = dsl_rdp_param_vch_1.ac_chain_send_frse;  /* chain of buffers to be sent to the client */
   if (dsl_rdp_param_vch_1.boc_callrevdir) {  /* call on reverse direction */
     adsp_hl_clib_1->boc_callrevdir = TRUE;  /* set call on reverse direction */
   }
   if (dsl_rdp_param_vch_1.adsc_sc_vch_out) {  /* send output to virtual channel */
     if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
       /* trace server to client generated virtual channel             */
       ADSL_RDPA_F->dsc_rdptr1.iec_tr_command   /* tracer component command */
         = ied_trc_se2cl_gen_vch;           /* server to client virtual channel generated */
       ADSL_RDPA_F->dsc_rdptr1.usc_vch_no
         = dsl_rdp_param_vch_1.adsc_sc_vch_out->adsc_rdp_vc_1->usc_vch_no;  /* virtual channel no com */
       adsl_gai1_w1 = dsl_rdp_param_vch_1.adsc_sc_vch_out->adsc_gai1_data;  /* output data */
       ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_w1;
       iml1 = 0;                            /* clear count             */
       while (adsl_gai1_w1) {               /* loop over input         */
         iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
       ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = iml1;  /* remaining data */
       /* virtual channel segmentation flags                           */
       memcpy( ADSL_RDPA_F->dsc_rdptr1.chrc_vch_segfl, dsl_rdp_param_vch_1.adsc_sc_vch_out->chrc_vch_segfl, sizeof(ADSL_RDPA_F->dsc_rdptr1.chrc_vch_segfl) );
       m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
     }
     bol1 = m_send_vch_out( adsp_hl_clib_1,
                            ADSL_OA1,
                            dsl_rdp_param_vch_1.adsc_sc_vch_out,
                            chrl_work_2 );
     if (bol1 == FALSE) goto p_cleanup_00;  /* do cleanup now          */
     goto pfrse80;                          /* check if more to send   */
   }
   goto p_ret_00;                           /* check how to return     */

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

   ptose00:                                 /* to server - from client */
   /* prepare Trace-Area                                               */
   ADSL_RDPA_F->dsc_rdptr1.adsc_hl_clib_1 = adsp_hl_clib_1;
#ifndef HL_RDPACC_HELP_DEBUG
#define D_ADSL_RSE1 (&ADSL_RDPA_F->dsc_rdp_se_1)
#define D_ADSL_RCO1 (&D_ADSL_RSE1->dsc_rdp_co_1)
#else
   D_ADSL_RSE1 = &ADSL_RDPA_F->dsc_rdp_se_1;
   D_ADSL_RCO1 = &D_ADSL_RSE1->dsc_rdp_co_1;
#endif

   achl_inp_start = NULL;                   /* start of input area     */
   /* prepare area to send to server                                   */
   ADSL_OA1->achc_lower = adsp_hl_clib_1->achc_work_area;  /* addr work-area */
   ADSL_OA1->achc_upper = ADSL_OA1->achc_lower + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   ADSL_OA1->aadsc_gai1_out_to_client = &adsp_hl_clib_1->adsc_gai1_out_to_client;  /* output data to client */
   ADSL_OA1->aadsc_gai1_out_to_server = &adsp_hl_clib_1->adsc_gai1_out_to_server;  /* output data to server */
   al_chain_send_tose = NULL;               /* chain of buffers to be sent to the server */
   if (adsp_hl_clib_1->adsc_gather_i_1_in == NULL) goto ptose80;
   adsl_gai1_inp_1 = adsp_hl_clib_1->adsc_gather_i_1_in;
   achl_inp_start = adsl_gai1_inp_1->achc_ginp_cur;  /* start of input area */
   /* get pointer to virtual channel structure                         */
   memset( &dsl_rdp_param_vch_1, 0, sizeof(struct dsd_rdp_param_vch_1) );  /* clear RDP parameters virus checking */
   dsl_rdp_param_vch_1.adsc_conf = (struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf;  /* configuration data */
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   memcpy( &dsl_rdp_param_vch_1.dsc_s1, &ADSL_RDPA_F->dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
//   dsl_rdp_param_vch_1.adsc_cb_c = ADSL_RDPA_F->adsc_cb_c;  /* cliprdr flags */
   dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */

   /* loop to process the input data                                   */
   ptose20:                                 /* process next byte input */
   if (adsl_gai1_inp_1) {                   /* more gather input       */
     iml_rec = adsl_gai1_inp_1->achc_ginp_end
                 - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml_rec > 0) {                     /* data to process         */
       goto ptose24;                        /* data to process found   */
     }
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
#ifndef TRACEHL1
     if (adsl_gai1_inp_1) goto ptose20;
#else
     if (adsl_gai1_inp_1) {
       achl_inp_start = adsl_gai1_inp_1->achc_ginp_cur;  /* start of input area */
       goto ptose20;
     }
#endif
   }
// goto ptose60;
   goto ptose80;                            /* send to server          */

   ptose24:                                 /* data to process found   */
#ifdef HL_RDPACC_HELP_DEBUG
   if (ADSL_RDPA_F->boc_help_debug_1) {     /* stop debugger          */
     printf( "xlrdpa1 m_hlclib01() ptose24 boc_help_debug_1 set\n" );
     int inh1 = 0;
     inh1++;
   }
#endif
#ifdef TRACEHL_CL2SE_COM1                   /* 21.09.06 KB - client to server commands */
   printf( "ptose24 - iec_frcl_bl=%d iec_fcfp_bl=%d pos=%04X cont=%02X\n",
            ADSL_RDPA_F->dsc_rdp_se_1.iec_frcl_bl,
            ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl,
            adsl_gai1_inp_1->achc_ginp_cur - achl_help_sta,
            *((unsigned char *) adsl_gai1_inp_1->achc_ginp_cur) );
#endif /* TRACEHL_CL2SE_COM1                21.09.06 KB - client to server commands */
   if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
     ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
       = ied_trc_cl2se_msg;                 /* client to server message */
     ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = NULL;
     ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = 0;  /* length of record */
     ADSL_RDPA_F->dsc_rdptr1.achc_trace_input = chrl_work_trace;  /* work area trace */
     sprintf( chrl_work_trace, "cl2se l%05d s%05d process input iec_frcl_bl=%d %s + iec_fcfp_bl=%d %s pos=%04X cont=%02X.",
              __LINE__, 30878,
              ADSL_RDPA_F->dsc_rdp_se_1.iec_frcl_bl,
              m_ret_t_ied_frcl_bl( ADSL_RDPA_F->dsc_rdp_se_1.iec_frcl_bl ),
              ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl,
              m_ret_t_ied_fcfp_bl( ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl ),
              adsl_gai1_inp_1->achc_ginp_cur - achl_inp_start,
              *((unsigned char *) adsl_gai1_inp_1->achc_ginp_cur) );
     m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
   }
   switch (D_ADSL_RSE1->iec_fcfp_bl) {      /* field position in rec   */
     case ied_fcfp_invalid:                 /* invalid data received   */
//     goto ptose92;                        /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 30892;    /* source line no for errors */
         goto ptose92;
     case ied_fcfp_constant:                /* compare with constant   */
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_start:
           achl1 = (char *) ucrs_rec_cl_01_cmp1;  /* compare received from client first block */
           iml1 = sizeof(ucrs_rec_cl_01_cmp1);  /* length to compare   */
           break;
         case ied_frcl_r02_x224mcs:         /* proc bl 2 X.224 MCS     */
           achl1 = (char *) ucrs_x224_mcs;
           iml1 = sizeof(ucrs_x224_mcs);
           break;
#ifdef B060907
         case ied_frcl_r02_mcud_dtt:        /* b2 MC Us-Da Desktop Tag */
           achl1 = (char *) ucrs_desktop_tag;
           iml1 = sizeof(ucrs_desktop_tag);
           break;
#endif
         case ied_frcl_r02_mcud_c01:        /* b2 MC Us-Da const 01    */
           achl1 = (char *) ucrs_r02c01;
           iml1 = sizeof(ucrs_r02c01);
           break;
         case ied_frcl_r02_mcud_c02:        /* b2 MC Us-Da const 02    */
           achl1 = (char *) ucrs_r02c02;
           iml1 = sizeof(ucrs_r02c02);
           break;
         case ied_frcl_r02_mcud_c03:        /* b2 MC Us-Da const 03    */
           achl1 = (char *) ucrs_bitmap_tag;  /* Bitmap Size Tag       */
           iml1 = sizeof(ucrs_bitmap_tag);
           break;
#ifdef B060907
         case ied_frcl_r02_mcud_vc1:        /* b2 MC Us-Da virtual ch  */
           achl1 = (char *) ucrs_virtch_tag;  /* Virtual Channel Tag   */
           iml1 = sizeof(ucrs_virtch_tag);
           break;
#endif
         default:
           goto ptose96;                    /* program illogic         */
       }
       iml2 = iml1;                         /* save length             */
       if (iml1 > (D_ADSL_RSE1->imc_prot_1 + iml_rec)) {
         iml1 = D_ADSL_RSE1->imc_prot_1 + iml_rec;
       }
       iml1 -= D_ADSL_RSE1->imc_prot_1;
       if (memcmp( achl1 + D_ADSL_RSE1->imc_prot_1,
                   adsl_gai1_inp_1->achc_ginp_cur,
                   iml1 )) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 30949;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->imc_prot_1 += iml1;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RSE1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RSE1->imc_prot_1 < iml2) {
         goto ptose20;                      /* process next data       */
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_start:               /* first block from client */
           if (D_ADSL_RSE1->imc_pos_inp_frame == 0) {  /* end of this frame - old client */
             bol1 = m_send_se2cl_const( adsp_hl_clib_1, &dsl_output_area_1, (char *) ucrs_secl_01, sizeof(ucrs_secl_01) );
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
             D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_02;
             goto ptose20;                  /* process next data       */
           }
           /* cookie or field with security checking may follow        */
           if (D_ADSL_RSE1->imc_pos_inp_frame > sizeof(D_ADSL_RSE1->chrc_prot_1)) {  /* to long for memory area */
         iml_line_no = __LINE__;
         iml_source_no = 30991;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RSE1->chrc_prot_1;
           D_ADSL_RSE1->imc_prot_count_in = D_ADSL_RSE1->imc_pos_inp_frame;  /* maximum length to copy */
           D_ADSL_RSE1->imc_prot_akku = 0;  /* set state CR LF         */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_crlf;  /* copy till <CR><LF> found */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_x224mcs:         /* proc bl 2 X.224 MCS     */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_l1_fi;  /* ASN.1 length field */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcscoen;  /* MCS connect encoding */
           D_ADSL_RSE1->imc_prot_3 = 0;     /* maybe till end of block */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_c01:        /* b2 MC Us-Da const 01    */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31019;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_scw;  /* b2 MC Us-Da scr width */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_c02:        /* b2 MC Us-Da const 02    */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31030;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_kbl;  /* b2 MC Us-Da Keyboard La */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_c03:        /* b2 MC Us-Da const 03    */
           /* protocol version                                         */
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RSE1->chrc_prot_1;
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 1;
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31043;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_pv1;  /* b2 MC Us-Da protocol ve */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           goto ptose20;                    /* process next data       */
         default:
           goto ptose96;                    /* program illogic         */
       }
     case ied_fcfp_ignore:                  /* ignore this data        */
       /* compute how many to ignore                                   */
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame
                - D_ADSL_RSE1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RSE1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RSE1->imc_pos_inp_frame > D_ADSL_RSE1->imc_prot_2) {
         goto ptose20;                      /* needs more data         */
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_r02_mc_cids:         /* b2 MC Calling Domain Selector */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_tag;  /* ASN.1 tag follows */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mc_ceds;  /* b2 MC Called Domain Selector */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_ceds:         /* b2 MC Called Domain Selector */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_tag;  /* ASN.1 tag follows */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mc_upwf;  /* b2 MC Upward Flag       */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_upwf:         /* b2 MC Upward Flag       */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_tag;  /* ASN.1 tag follows */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mc_tdop;  /* b2 MC Target Domain Parameters */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_tdop:         /* b2 MC Target Domain Parameters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_tag;  /* ASN.1 tag follows */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mc_midp;  /* b2 MC Minimum Domain Parameters */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_midp:         /* b2 MC Minimum Domain Parameters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_tag;  /* ASN.1 tag follows */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mc_madp;  /* b2 MC Maximum Domain Parameters */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_madp:         /* b2 MC Maximum Domain Parameters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_tag;  /* ASN.1 tag follows */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mc_usd1;  /* b2 MC User Data Start   */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_usd1:         /* b2 MC User Data Start   */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_mu_len_1;  /* multi length 1 */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_l1;  /* b2 MC Us-Da length 1 */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_l1:         /* b2 MC Us-Da length 1    */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_mu_len_1;  /* multi length 1 */
#ifdef B060907
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_dtt;  /* b2 MC Us-Da Desktop Tag */
#endif
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_fietype;  /* b2 MC Field Type */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_fietype:         /* b2 MC Field Type        */
           if (D_ADSL_RSE1->imc_pos_inp_frame == 0) {  /* end of block */
             goto ptose_send_start;         /* send start to server    */
           }
           if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) {  /* end of block */
         iml_line_no = __LINE__;
         iml_source_no = 31156;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 31160;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;      /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_ime:        /* b2 MC Us-Da IME Keyb ma */
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_bitmap_tag)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31169;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_c03;  /* b2 MC Us-Da const 03 */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_pv1:        /* b2 MC Us-Da protocol ve */
           /* if chrc_prot_1[0] == 0: is already at end? 08.08.04 KB */
           if (D_ADSL_RSE1->chrc_prot_1[0] != 0X01) {
             printf( "b2 MC Us-Da protocol v found invalid protocol version %d\n",
                     D_ADSL_RSE1->chrc_prot_1[0] );
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31181;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31186;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;      /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_cod;  /* b2 MC Us-Da Color Depth */
           goto ptose20;                    /* process next data       */
#ifdef B060907
         case ied_frcl_r02_mcud_cod:        /* b2 MC Us-Da Color Depth */
#ifdef B060907
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_virtch_tag)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31198;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_vc1;  /* b2 MC Us-Da virtual ch */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
#endif
           if (D_ADSL_RSE1->imc_pos_inp_frame == 0) {  /* end of block */
         iml_line_no = __LINE__;
         iml_source_no = 31206;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 31210;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;      /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_fietype;  /* b2 MC Field Type */
           goto ptose20;                    /* process next data       */
#endif
         case ied_frcl_c_loinf_options:     /* Options                 */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 31221;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
       }
           goto ptose96;                    /* program illogic         */
     case ied_fcfp_copy_normal:             /* copy data normal        */
       /* compute how many to copy                                     */
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame
                - D_ADSL_RSE1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       if (iml1 > 0) {                      /* data to copy            */
         memcpy( D_ADSL_RSE1->achc_prot_1,
                 adsl_gai1_inp_1->achc_ginp_cur,
                 iml1 );
         D_ADSL_RSE1->achc_prot_1 += iml1;
         if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
           if (D_ADSL_RSE1->iec_frcl_bl == ied_frcl_rdp5_inp) {  /* RDP5-style input data */
             memcpy( &D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec ],
                     adsl_gai1_inp_1->achc_ginp_cur,
                     iml1 );
             D_ADSL_RCO1->imc_len_start_rec += iml1;
           }
         }
         adsl_gai1_inp_1->achc_ginp_cur += iml1;
         D_ADSL_RSE1->imc_pos_inp_frame -= iml1;  /* length constant   */
         if (D_ADSL_RSE1->imc_pos_inp_frame > D_ADSL_RSE1->imc_prot_2) {
           goto ptose20;                    /* needs more data         */
         }
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_r02_mcud_c01:        /* b2 MC Us-Da const 01    */
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_r02c01)) {
         iml_line_no = __LINE__;
         iml_source_no = 31398;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
//         D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_c01;  /* b2 MC Us-Da const 01 */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_con:        /* b2 MC Us-Da Computer Na */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31408;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_kbt;  /* b2 MC Us-Da Keyboard Ty */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_pv1:        /* b2 MC Us-Da protocol ve */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 5;
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31419;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_fietype:         /* b2 MC Field Type        */
           if (D_ADSL_RSE1->imc_pos_inp_frame == 0) {  /* end of block */
             goto ptose_send_start;         /* send start to server    */
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
             iml_line_no = __LINE__;
             iml_source_no = 31680;    /* source line no for errors */
             goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;      /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_vcn:        /* b2 MC Us-Da virt ch nam */
           if (   (!memcmp( D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].byrc_name, "HOB1", 5 ))
               || (!memcmp( D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].byrc_name, "HOB2", 5 ))) {
             D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].chc_hob_vch = *(D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].byrc_name + 3);
           } else if (!memcmp( D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].byrc_name, "rdpdr", 6 )) {
             if (((struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf)->boc_disa_ms_ldm) {  /* disable MS local-drive-mapping */
               D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].chc_hob_vch = 'd';  /* channel devices */
             }
           } else if (!memcmp( D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].byrc_name, "cliprdr", 8 )) {
             if (((struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf)->boc_disa_ms_clipb) {  /* disable MS clipboard */
               D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].chc_hob_vch = 'i';  /* ignore data on channel */
             } else {                       /* watch the clipboard     */
               if (((struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf)->imc_len_ldm_vch_serv > 0) {  /* length ldm virus-checking service name */
                 //D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].chc_hob_vch = 'c';  /* mark as clipboard */
                 //if (ADSL_RDPA_F->adsc_cb_c == NULL) {  /* cliprdr flags */
                 //  ADSL_RDPA_F->adsc_cb_c   /* cliprdr flags           */
                 //    = (struct dsd_cliprdr_ctrl *) m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, sizeof(struct dsd_cliprdr_ctrl) );
                 //}
                 //memset( ADSL_RDPA_F->adsc_cb_c, 0, sizeof(struct dsd_cliprdr_ctrl) );
                 //ADSL_RDPA_F->adsc_cb_c->adsc_cb_rdp_vc_1  /* RDP virtual channel clipboard */
                 //  = &D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ];
               }
             }
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_vcf;  /* b2 MC Us-Da virt ch fla */
           goto ptose20;                    /* process next data       */
         case ied_frcl_rec_05:              /* received block 5        */
           /* send this block unchanged to server                      */
           ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
           if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
             goto ptose96;                  /* program illogic         */
           }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
           ADSL_GAI1_OUT_G->adsc_next = NULL;
           ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
           memcpy( ADSL_OA1->achc_lower, ucrs_x224_r05_errect, sizeof(ucrs_x224_r05_errect) );
           ADSL_OA1->achc_lower += sizeof(ucrs_x224_r05_errect);
           memcpy( ADSL_OA1->achc_lower, D_ADSL_RSE1->chrc_prot_1, 4 );
           ADSL_OA1->achc_lower += 4;
           ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
           *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
           ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_06;  /* receive block 6 */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
           goto ptose20;                    /* process next data       */
         case ied_frcl_rdp5_inp:            /* RDP5-style input data   */
           /* start of record                                          */
           if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
             memset( &dsl_gai1_start_rec, 0, sizeof(struct dsd_gather_i_1) );
             dsl_gai1_start_rec.achc_ginp_cur = D_ADSL_RCO1->chrc_start_rec;
             dsl_gai1_start_rec.achc_ginp_end = D_ADSL_RCO1->chrc_start_rec + D_ADSL_RCO1->imc_len_start_rec;
             dsl_gai1_start_rec.adsc_next = adsl_gai1_inp_1;
             ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
               = ied_trc_recv_client;       /* received from client    */
             ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = &dsl_gai1_start_rec;
             ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RCO1->imc_len_record;  /* length of record */
             m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
           }
/* 04.09.06 KB UUUU */
//           *M_ERROR_TOSE_PROT;            /* protocol error          */
       /* generated from macro M_TMPBUF_SE_1()                         */
       if (D_ADSL_RSE1->imc_pos_inp_frame > D_ADSL_RSE1->imc_len_temp) {
         D_ADSL_RSE1->imc_len_temp = D_ADSL_RSE1->imc_pos_inp_frame;
         ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
         ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
         if (D_ADSL_RSE1->ac_temp_buffer) {  /* buffer already allocated */
           m_aux_stor_free( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RSE1->ac_temp_buffer );
         }
         D_ADSL_RSE1->ac_temp_buffer
           = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RSE1->imc_len_temp );
       }
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RSE1->ac_temp_buffer;  /* temporary buffer */
           D_ADSL_RSE1->imc_prot_2 = 0;     /* till end of frame       */
           if (D_ADSL_RSE1->imc_prot_3) {   /* input encrypted         */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rdp5_rc4;  /* input RC4 encrypted */
           }
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_logon_info_1:      /* logon information 1     */
         case ied_frcl_resp_act_pdu_rec:    /* response block active PDU */
         case ied_frcl_rec_xyz_01:
           /* check if all data of this frame have been received       */
           iml1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* remaining data in frame */
           adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather          */
           while (TRUE) {                   /* loop over all gather structures input */
             iml1 -= adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
             if (iml1 <= 0) break;          /* enough data found       */
             adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
             if (adsl_gai1_inp_w2 == NULL) {  /* already end of chain  */
               /* wait for more data                                   */
               goto p_ret_00;               /* check how to return     */
             }
           }
           if ((D_ADSL_RCO1->dsc_encry_cl2se.imc_count_sent & (4096 - 1)) == 0){
             if (D_ADSL_RCO1->dsc_encry_cl2se.imc_count_sent) {
               m_update_keys( D_ADSL_RCO1, &D_ADSL_RCO1->dsc_encry_cl2se, NULL );
             }
           }
           /* decrypt the data where they are                          */
           iml1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* remaining data in frame */
           adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather          */
           while (TRUE) {                   /* loop over all gather structures input */
             iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
             if (iml2 > iml1) iml2 = iml1;  /* only data in this frame */
             RC4( adsl_gai1_inp_w2->achc_ginp_cur, 0, iml2,
                  adsl_gai1_inp_w2->achc_ginp_cur, 0,
                  D_ADSL_RCO1->dsc_encry_cl2se.chrc_rc4_state );
             iml1 -= iml2;                  /* subtract data decyrpted */
             if (iml1 <= 0) break;          /* all data decrypted      */
             adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
             if (adsl_gai1_inp_w2 == NULL) {  /* already end of chain  */
               goto ptose96;                /* program illogic         */
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
           m_put_le4( ACHL_WORK_UTIL_01, D_ADSL_RSE1->imc_pos_inp_frame );
           SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
           iml1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* remaining data in frame */
           adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather          */
           while (TRUE) {                   /* loop over all gather structures input */
             iml2 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
             if (iml2 > iml1) iml2 = iml1;  /* only data in this frame */
             SHA1_Update( ACHL_WORK_SHA1,
                          adsl_gai1_inp_w2->achc_ginp_cur, 0, iml2 );
             iml1 -= iml2;                  /* subtract data processed */
             if (iml1 <= 0) break;          /* all data processed      */
             adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
             if (adsl_gai1_inp_w2 == NULL) {  /* already end of chain  */
               goto ptose96;                /* program illogic         */
             }
           }
           if (D_ADSL_RSE1->chc_prot_rt03 & 0X08) {  /* flag for block count */
             m_put_le4( ACHL_WORK_UTIL_01, D_ADSL_RCO1->dsc_encry_cl2se.imc_count_sent );
             SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
           }
           SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
           MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
           MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
           if (memcmp( D_ADSL_RSE1->chrc_prot_1, ACHL_WORK_UTIL_01, D_SIZE_HASH )) {
             m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d received from client hash invalid",
                           __LINE__, 31749 );  /* line number for errors */
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 31752;    /* source line no for errors */
         goto ptose92;
           }
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
           D_ADSL_RCO1->dsc_encry_cl2se.imc_count_sent++;  /* count blocks client has sent */
           /* data from client decrypted                               */
           if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
             ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
               = ied_trc_cl2se_decry;       /* client to server, decrypted */
             ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_inp_1;
             ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RSE1->imc_pos_inp_frame;  /* remaining data */
             ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_record - D_ADSL_RSE1->imc_pos_inp_frame;
             ADSL_RDPA_F->dsc_rdptr1.usc_vch_no = D_ADSL_RSE1->imc_prot_chno;  /* virtual channel no com */
             m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
             D_ADSL_RCO1->imc_len_part = D_ADSL_RSE1->imc_pos_inp_frame;  /* length of part */
             ADSL_RDPA_F->dsc_rdptr1.chc_type_disp = 'E';  /* type of displacement */
           }
           if (D_ADSL_RSE1->iec_frcl_bl == ied_frcl_c_logon_info_1) {  /* logon information 1 */
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
             if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame    */
         iml_line_no = __LINE__;
         iml_source_no = 31814;    /* source line no for errors */
         goto ptose92;
             }
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore next bytes */
             D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_options;  /* Options */
             goto ptose20;                  /* process next data       */
           }
           if (D_ADSL_RSE1->imc_prot_chno == D_ADSL_RCO1->usc_chno_disp) {  /* channel number display  */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_send_from_client;  /* send data to server */
             if ((((unsigned char) D_ADSL_RSE1->chc_prot_rt02) & 0X80) == 0) {
               goto ptose40;                /* process the data        */
             }
             /* encrypted licencing packet received from client (and already decrypted) */
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes (preamble header) */
             D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RSE1->imc_prot_1 = 0;   /* clear value             */
             D_ADSL_RSE1->iec_frcl_bl = ied_frcl_lic_01;  /* licencing block to check */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e; /* int little endian (for length) */
             goto ptose20;                  /* process next data       */
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 31856;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rdp4_vch_ulen;  /* virtual channel uncompressed data length */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_domna_val:   /* Domain Name String      */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 31879;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_zero_cmp;  /* compare zeroes */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_userna_val:  /* User Name String        */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 31886;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_zero_cmp;  /* compare zeroes */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_pwd_val:     /* Password String         */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 31893;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_zero_cmp;  /* compare zeroes */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_altsh_val:   /* Alt Shell String        */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 31900;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_zero_cmp;  /* compare zeroes */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_wodir_val:   /* Working Directory String */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 31907;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_zero_cmp;  /* compare zeroes */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_ineta:       /* INETA                   */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 31914;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_path;  /* Client Path */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_path:        /* Client Path             */
           if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) {  /* nothing left */
         iml_line_no = __LINE__;
         iml_source_no = 31923;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RCO1->usc_loinf_extra_len = D_ADSL_RSE1->imc_pos_inp_frame;  /* Extra Parameters Length */
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->awcc_loinf_extra_a) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RSE1->imc_pos_inp_frame );
           D_ADSL_RSE1->imc_prot_2 = 0;     /* copy till end of frame  */
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->awcc_loinf_extra_a;  /* Extra Parameters */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_extra;  /* Extra Parameters */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_extra:       /* Extra Parameters        */
#define D_ADSL_CL_RCO1 (&ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1)
            // RDP-Acc is not able to do RDP 6 bulk-compression so far.
            if (D_ADSL_RCO1->umc_loinf_options & D_LOINFO_COMPR_BULK) {
              D_ADSL_RCO1->umc_loinf_options &= - 1 - D_LOINFO_COMPR_BULK;
              D_ADSL_RCO1->umc_loinf_options |= D_LOINFO_COMPR_LDIC;
            };
           D_ADSL_CL_RCO1->umc_loinf_options = D_ADSL_RCO1->umc_loinf_options;
#define ADSL_RDPVCH1_CONFIG ((struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf)
           switch (ADSL_RDPVCH1_CONFIG->imc_comp2se) {  /* compression-to-server configured */
             case 1:                        /* NO                      */
               D_ADSL_CL_RCO1->umc_loinf_options
                 &= -1 - D_LOINFO_COMPR_ENA  /* compression enabled    */
                       - D_LOINFO_COMPR_LDIC;  /* use large dictionary */
               break;
             case 2:                        /* YES                     */
               D_ADSL_CL_RCO1->umc_loinf_options
                 |= D_LOINFO_COMPR_ENA      /* compression enabled     */
                      + D_LOINFO_COMPR_LDIC;  /* use large dictionary  */
               break;
           }
#undef ADSL_RDPVCH1_CONFIG
           D_ADSL_CL_RCO1->usc_loinf_domna_len = D_ADSL_RCO1->usc_loinf_domna_len;
           D_ADSL_CL_RCO1->usc_loinf_userna_len = D_ADSL_RCO1->usc_loinf_userna_len;
           D_ADSL_CL_RCO1->usc_loinf_pwd_len = D_ADSL_RCO1->usc_loinf_pwd_len;
           D_ADSL_CL_RCO1->usc_loinf_altsh_len = D_ADSL_RCO1->usc_loinf_altsh_len;
           D_ADSL_CL_RCO1->usc_loinf_wodir_len = D_ADSL_RCO1->usc_loinf_wodir_len;
           D_ADSL_CL_RCO1->usc_loinf_no_a_par = D_ADSL_RCO1->usc_loinf_no_a_par;
           D_ADSL_CL_RCO1->usc_loinf_ineta_len = D_ADSL_RCO1->usc_loinf_ineta_len;
           D_ADSL_CL_RCO1->usc_loinf_path_len = D_ADSL_RCO1->usc_loinf_path_len;
           D_ADSL_CL_RCO1->usc_loinf_extra_len = D_ADSL_RCO1->usc_loinf_extra_len;
           D_ADSL_CL_RCO1->awcc_loinf_domna_a = D_ADSL_RCO1->awcc_loinf_domna_a;
           D_ADSL_CL_RCO1->awcc_loinf_userna_a = D_ADSL_RCO1->awcc_loinf_userna_a;
           D_ADSL_CL_RCO1->awcc_loinf_pwd_a = D_ADSL_RCO1->awcc_loinf_pwd_a;
           D_ADSL_CL_RCO1->awcc_loinf_altsh_a = D_ADSL_RCO1->awcc_loinf_altsh_a;
           D_ADSL_CL_RCO1->awcc_loinf_wodir_a = D_ADSL_RCO1->awcc_loinf_wodir_a;
           D_ADSL_CL_RCO1->awcc_loinf_ineta_a = D_ADSL_RCO1->awcc_loinf_ineta_a;
           D_ADSL_CL_RCO1->awcc_loinf_path_a = D_ADSL_RCO1->awcc_loinf_path_a;
           D_ADSL_CL_RCO1->awcc_loinf_extra_a = D_ADSL_RCO1->awcc_loinf_extra_a;
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_send_from_client;  /* send data to server */
           /* start compression, if required                           */
           /* first part when RDP-Accelerator is the Client            */
           if (D_ADSL_CL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) {  /* compression enabled */
             D_ADSL_CL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
             D_ADSL_CL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
             D_ADSL_CL_RCO1->amc_cdr_dec = &m_cdr_mppc_5_dec;  /* decoding routine */
             D_ADSL_CL_RCO1->amc_cdr_dec( &D_ADSL_CL_RCO1->dsc_cdrf_dec );
             if (D_ADSL_CL_RCO1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
               m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d de-compression error %d.",
                             __LINE__, 32019,  /* line number for errors */
                             D_ADSL_CL_RCO1->dsc_cdrf_dec.imc_return );
               goto p_cleanup_00;           /* do cleanup now          */
             }
//           D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_func = DEF_IFUNC_START;
             D_ADSL_CL_RCO1->dsc_cdrf_enc.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
             D_ADSL_CL_RCO1->dsc_cdrf_enc.amc_aux = adsp_hl_clib_1->amc_aux;
             D_ADSL_CL_RCO1->amc_cdr_enc = &m_cdr_mppc_4_enc;  /* encryption routine */
             D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_param_1 = 40;  /* RDP4      */
             D_ADSL_CL_RCO1->amc_cdr_enc( &D_ADSL_CL_RCO1->dsc_cdrf_enc );
             if (D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {
               m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d compression error %d.",
                             __LINE__, 32037,  /* line number for errors */
                             D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_return );
               goto p_cleanup_00;           /* do cleanup now          */
             }
           }
#undef D_ADSL_CL_RCO1
           if ((D_ADSL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) == 0) {  /* compression not enabled */
             goto ptose40;                  /* process the data        */
           }
//         D_ADSL_RCO1->dsc_cdrf_dec.imc_func = DEF_IFUNC_START;
           D_ADSL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
           D_ADSL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
           D_ADSL_RCO1->amc_cdr_dec = &m_cdr_mppc_5_dec;  /* decoding routine */
           D_ADSL_RCO1->amc_cdr_dec( &D_ADSL_RCO1->dsc_cdrf_dec );
           if (D_ADSL_RCO1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {  /* continue processing */
             m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d de-compression error %d.",
                           __LINE__, 32100,  /* line number for errors */
                           D_ADSL_RCO1->dsc_cdrf_dec.imc_return );
             goto p_cleanup_00;             /* do cleanup now          */
           }
//         D_ADSL_RCO1->dsc_cdrf_enc.imc_func = DEF_IFUNC_START;
           D_ADSL_RCO1->dsc_cdrf_enc.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
           D_ADSL_RCO1->dsc_cdrf_enc.amc_aux = adsp_hl_clib_1->amc_aux;
           D_ADSL_RCO1->amc_cdr_enc = &m_cdr_mppc_4_enc;  /* encryption routine */
           switch ((D_ADSL_RCO1->umc_loinf_options & D_LOINFO_COMPRESSION_TYPE_MASK) >> D_LOINFO_COMPRESSION_TYPE_SHIFT) {
             case 0:                        /* PACKET_COMPR_TYPE_8K RDP 4.0 bulk compression (see section 3.1.8.4.1) */
               D_ADSL_RCO1->dsc_cdrf_enc.imc_param_1 = 40;  /* RDP4    */
               break;
             case 1:                        /* PACKET_COMPR_TYPE_64K RDP 5.0 bulk compression (see section 3.1.8.4.2). */
               D_ADSL_RCO1->dsc_cdrf_enc.imc_param_1 = 50;  /* RDP5    */
               break;
             default:
               /* PACKET_COMPR_TYPE_RDP6 0X2 RDP 6.0 bulk compression (see [MS-RDPEGDI] section 3.1.8.1). */
               /* PACKET_COMPR_TYPE_RDP61 0X3 RDP 6.1 bulk compression (see [MS-RDPEGDI] section 3.1.8.2). */
               D_ADSL_RCO1->dsc_cdrf_enc.imc_param_1 = 60;  /* RDP6.0  */
               break;
           }
           D_ADSL_RCO1->amc_cdr_enc( &D_ADSL_RCO1->dsc_cdrf_enc );
           if (D_ADSL_RCO1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {
             m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d compression error %d.",
                           __LINE__, 32136,  /* line number for errors */
                           D_ADSL_RCO1->dsc_cdrf_enc.imc_return );
             goto p_cleanup_00;             /* do cleanup now          */
           }
           goto ptose40;                    /* process the data        */
         case ied_frcl_lic_clrand:          /* New Licence Request / Client License Info */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 32295;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_bb_type;   /* parse BinaryBlob Type next */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e; /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_rdp4_vch_ulen:       /* virtual channel uncompressed data length */
           goto ptose_vch_00;               /* virtual channel data received */
         case ied_frcl_hext_send:           /* HOB-RDP-EXT1 send to server / SDH */
           iml1 = D_ADSL_RSE1->achc_prot_1 - D_ADSL_RSE1->chrc_prot_1;  /* length data to send */
           if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < (sizeof(struct dsd_gather_i_1) + iml1)) {  /* get new area */
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
           ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
           ADSL_GAI1_OUT_G->adsc_next = NULL;
           ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
           memcpy( ADSL_OA1->achc_lower, D_ADSL_RSE1->chrc_prot_1, iml1 );  /* copy the data */
           ADSL_OA1->achc_lower += iml1;       /* add length of the data  */
           ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
           *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
           ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
           ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl = ied_fcfp_rec_type;  /* first record type */
           ADSL_RDPA_F->dsc_rdp_se_1.iec_frcl_bl = ied_frcl_start;  /* receive block from client */
           if (ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl == ied_frse_any_pdu_rec) {
             ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl = ied_frse_start;  /* receive block from client */
           }
           goto ptose20;                    /* process next data       */
#undef ADSL_GAI1_OUT_G
       }
       goto ptose96;                        /* program illogic         */
/* to-do 17.12.14 KB - use m_rsa_crypt_raw_little() */
     case ied_fcfp_copy_invers:             /* copy data invers        */
       /* compute how many to copy                                     */
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame
                - D_ADSL_RSE1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       /* compute end of source area                                   */
       achl1 = adsl_gai1_inp_1->achc_ginp_cur + iml1;
       /* compute target address                                       */
       achl2 = D_ADSL_RSE1->achc_prot_1
               + (D_ADSL_RSE1->imc_prot_3 - D_ADSL_RSE1->imc_prot_2)
               - D_ADSL_RSE1->imc_prot_1;
       do {
         *(--achl2) = *adsl_gai1_inp_1->achc_ginp_cur++;
       } while (adsl_gai1_inp_1->achc_ginp_cur < achl1);
       D_ADSL_RSE1->imc_pos_inp_frame -= iml1;  /* length constant     */
       D_ADSL_RSE1->imc_prot_1 += iml1;     /* add displacement output */
       if (D_ADSL_RSE1->imc_pos_inp_frame > D_ADSL_RSE1->imc_prot_2) {
         goto ptose20;                      /* needs more data         */
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_client_rand:         /* receive client random   */
           if (D_ADSL_RSE1->imc_pos_inp_frame) {  /* more in block     */
         iml_line_no = __LINE__;
         iml_source_no = 32459;    /* source line no for errors */
         goto ptose92;
           }
           iml1 = sizeof(chrl_work_1);
           {
             unsigned char *auch1, *auch2;
             auch1 = (unsigned char *) D_ADSL_RSE1->chrc_prot_1;
             auch2 = auch1 + D_ADSL_RSE1->imc_prot_3 - D_ADSL_RSE1->imc_prot_2;
             while ((auch1 < auch2) && (*auch1 == 0X00)) auch1++;
#ifdef XH_INTERFACE
			   ds__hmem dsl_new_struct;
			   memset(&dsl_new_struct, 0, sizeof(ds__hmem));
			   dsl_new_struct.in__aux_up_version = 1;
			   dsl_new_struct.am__aux2 = adsp_hl_clib_1->amc_aux;
			   dsl_new_struct.in__flags = 0;
			   dsl_new_struct.vp__context = adsp_hl_clib_1->vpc_userfld;
#endif
#ifdef __INSURE__
             // rsa_crypt_raw uses lnum, which causes an Insure-error.
             _Insure_checking_enable(0);
#endif
/* to-do 17.12.14 KB - use m_rsa_crypt_raw_little() */
             iml2 = m_rsa_crypt_raw_big(
#ifdef XH_INTERFACE
                                         &dsl_new_struct,
#endif
				                         auch1, auch2 - auch1,
                                         (unsigned char *) ucrs_rdp_private_key,
                                         sizeof(ucrs_rdp_private_key),
                                         (unsigned char *) ucrs_rdp_cert + D_POS_CERT_PUBLIC_KEY,
                                         D_LEN_CERT_PUBLIC_KEY,
                                         (unsigned char *) chrl_work_1,
                                         &iml1 );
#ifdef __INSURE__
             _Insure_checking_enable(1);
#endif
#ifdef XH_INTERFACE
              HMemMgrFree(&dsl_new_struct);
#endif
           }
#ifdef TRACEHL1
           printf( "l%05d s%05d rsa_crypt_raw() server returned %d length %d.\n",
                   __LINE__, 32506,
                   iml2, iml1 );
#ifdef D_FFLUSH                             /* 30.05.05 KB - flush stdout */
           fflush( stdout );
#endif                                      /* 30.05.05 KB - flush stdout */
#endif
           iml_line_no = __LINE__;
           iml_source_no = 35353;
           if (iml2) goto ptose92;          /* protocol error          */
           if (iml1 == 0) goto ptose92;     /* protocol error          */
#define ACHL_CLIENT_RANDOM_SE (chrl_work_2)
#define ACHL_CLIENT_RANDOM_CL (chrl_work_2)
#define ACHL_CL_RAND_ENCRY (ACHL_CLIENT_RANDOM_CL + 32)
#define ACHL_WORK_AREA (ACHL_CL_RAND_ENCRY + 72)
#define ACHL_WORK_SHA1 (ACHL_CL_RAND_ENCRY + 72)
#define ACHL_WORK_MD5 (ACHL_WORK_SHA1 + 40)
           /* 32 bytes of client random as server                      */
           achl1 = chrl_work_1;             /* start input             */
           achl2 = chrl_work_1 + iml1;      /* end input               */
           achl3 = ACHL_CLIENT_RANDOM_SE + 32;  /* target to here      */
           achl4 = ACHL_CLIENT_RANDOM_SE;   /* target up to this       */
           do {
             *achl4++ = *(--achl2);
           } while ((achl2 > achl1) && (achl4 < achl3));
           if (achl3 > achl4) {
             memset( achl4, 0, achl3 - achl4 );
           }
           m_gen_keys( adsp_hl_clib_1, ACHL_CLIENT_RANDOM_SE, D_ADSL_RCO1, ACHL_WORK_AREA );
           /* copy the keys, this is faster                            */
           memcpy( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.chrc_sig,
                   D_ADSL_RCO1->chrc_sig,
                   sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.chrc_sig) );
           memcpy( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_cl_pkd,
                   D_ADSL_RCO1->dsc_encry_se2cl.chrc_cl_pkd,
                   sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_cl_pkd) );
           memcpy( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_cl_pkd,
                   D_ADSL_RCO1->dsc_encry_cl2se.chrc_cl_pkd,
                   sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_cl_pkd) );
           memcpy( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_orig_pkd,
                   D_ADSL_RCO1->dsc_encry_se2cl.chrc_orig_pkd,
                   sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_orig_pkd) );
           memcpy( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_orig_pkd,
                   D_ADSL_RCO1->dsc_encry_cl2se.chrc_orig_pkd,
                   sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_orig_pkd) );
           /* end of copy                                              */
           /* shorten the keys                                         */
           bol1 = m_prepare_keys( adsp_hl_clib_1, D_ADSL_RCO1 );
           if (bol1 == FALSE) {             /* subroutine reported error */
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 32567;    /* source line no for errors */
         goto ptose92;
           }
           RC4_SetKey( D_ADSL_RCO1->dsc_encry_se2cl.chrc_rc4_state,
                       D_ADSL_RCO1->dsc_encry_se2cl.chrc_cl_pkd,
                       0, D_ADSL_RCO1->imc_used_keylen );
           RC4_SetKey( D_ADSL_RCO1->dsc_encry_cl2se.chrc_rc4_state,
                       D_ADSL_RCO1->dsc_encry_cl2se.chrc_cl_pkd,
                       0, D_ADSL_RCO1->imc_used_keylen );
           memset( ACHL_WORK_SHA1, 0X36, 40 );
           memset( ACHL_WORK_MD5, 0X5C, 48 );
           SHA1_Init( D_ADSL_RCO1->imrc_sha1_state );
           SHA1_Update( D_ADSL_RCO1->imrc_sha1_state, D_ADSL_RCO1->chrc_sig,
                        0, D_ADSL_RCO1->imc_used_keylen );
           SHA1_Update( D_ADSL_RCO1->imrc_sha1_state, ACHL_WORK_SHA1, 0, 40 );
           MD5_Init( D_ADSL_RCO1->imrc_md5_state );
           MD5_Update( D_ADSL_RCO1->imrc_md5_state, D_ADSL_RCO1->chrc_sig,
                       0, D_ADSL_RCO1->imc_used_keylen );
           MD5_Update( D_ADSL_RCO1->imrc_md5_state, ACHL_WORK_MD5, 0, 48 );
           /* send client random to server                             */
//         m_gen_keys( adsp_hl_clib_1, ACHL_CLIENT_RANDOM_CL,
//                     &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1, ACHL_WORK_AREA );
           iml3 = D_RSA_KEY_SIZE;           /* compare size RSA key    */
#ifdef XH_INTERFACE
			ds__hmem dsl_new_struct;
			memset(&dsl_new_struct, 0, sizeof(ds__hmem));
			dsl_new_struct.in__aux_up_version = 1;
			dsl_new_struct.am__aux2 = adsp_hl_clib_1->amc_aux;
			dsl_new_struct.in__flags = 0;
			dsl_new_struct.vp__context = adsp_hl_clib_1->vpc_userfld;
#endif
#ifdef __INSURE__
           // rsa_crypt_raw uses lnum, which causes an Insure-error.
           _Insure_checking_enable(0);
#endif
           iml2 = m_rsa_crypt_raw_big(
#ifdef XH_INTERFACE
                                       &dsl_new_struct,
#endif
									   (unsigned char *) chrl_work_1,
                                       iml1,
                                       (unsigned char *) ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp,
                                       sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.chrc_cert_exp),
                                       (unsigned char *) ADSL_RDPA_F->dsc_rdp_cl_1.achc_cert_key,  /* RSA key */
                                       ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key,  /* length RSA key */
                                       (unsigned char *) ACHL_WORK_AREA,
                                       &iml3 );
#ifdef __INSURE__
           _Insure_checking_enable(1);
#endif
#ifdef XH_INTERFACE
           HMemMgrFree(&dsl_new_struct);
#endif
           if (iml2) goto ptose92;          /* protocol error          */
           if (iml3 == 0) goto ptose92;     /* protocol error          */
           /* shorten the keys                                             */
           bol1 = m_prepare_keys( adsp_hl_clib_1, &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1 );
           if (bol1 == FALSE) {             /* subroutine reported error */
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 32668;    /* source line no for errors */
         goto ptose92;
           }
           if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_keytype
                 == D_ADSL_RCO1->imc_keytype) {
             memcpy( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_rc4_state,
                     D_ADSL_RCO1->dsc_encry_se2cl.chrc_rc4_state,
                     sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_rc4_state) );
             memcpy( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state,
                     D_ADSL_RCO1->dsc_encry_cl2se.chrc_rc4_state,
                     sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state) );
             memcpy( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
                     D_ADSL_RCO1->imrc_sha1_state,
                     sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
             memcpy( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
                     D_ADSL_RCO1->imrc_sha1_state,
                     sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
             memcpy( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
                     D_ADSL_RCO1->imrc_md5_state,
                     sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
             memcpy( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
                     D_ADSL_RCO1->imrc_md5_state,
                     sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
           } else {
             RC4_SetKey( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_rc4_state,
                         ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_cl_pkd,
                         0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_used_keylen );
             RC4_SetKey( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state,
                         ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_cl_pkd,
                         0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_used_keylen );
             SHA1_Init( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state );
             SHA1_Update( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
                          ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.chrc_sig,
                          0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_used_keylen );
             SHA1_Update( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
                          ACHL_WORK_SHA1, 0, 40 );
             MD5_Init( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state );
             MD5_Update( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
                         ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.chrc_sig,
                         0, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_used_keylen );
             MD5_Update( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
                         ACHL_WORK_MD5, 0, 48 );
           }
           switch ( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_keytype) {
             case 1:
               memcpy( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_cl_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
               memcpy( ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_cl_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
               ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_used_keylen = 8;
               break;
             case 2:
               ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_used_keylen = 16;
               break;
             case 4:
             case 8:
               ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_cl_pkd[0] = (char) 0XD1;
               ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_cl_pkd[0] = (char) 0XD1;
               ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imc_used_keylen = 8;
               break;
             default:
//             goto ptose92;                /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 32734;    /* source line no for errors */
         goto ptose92;
           }
           /* send the block to the server                             */
           ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
           ADSL_OA1->achc_lower += 4 + sizeof(ucrs_x224_p01) + 6 + 2 + 8 + iml3 + D_RSA_KEY_PADDING;
           if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
         iml_line_no = __LINE__;
         iml_source_no = 32765;    /* source line no for errors */
         goto ptose96;
           }
           achl1 = ADSL_OA1->achc_lower;       /* get end of block        */
           achl1 -= D_RSA_KEY_PADDING;
           memset( achl1, 0, D_RSA_KEY_PADDING );
           /* send reverse encrypted client random from this client to server */
           achl3 = ACHL_WORK_AREA;
           achl4 = ACHL_WORK_AREA + iml3;
           do {
             *(--achl1) = *achl3++;
           } while (achl3 < achl4);
           iml1 = ADSL_OA1->achc_lower - achl1;  /* length this part      */
           *(--achl1) = 0;
           *(--achl1) = 0;
           achl1 -= 2;
           m_put_le2( achl1, iml1 );        /* output length           */
           *(--achl1) = 0;
           *(--achl1) = 0;
           *(--achl1) = (unsigned char) 0X02;
           *(--achl1) = (unsigned char) 0X01;
           iml1 = ADSL_OA1->achc_lower - achl1;  /* length this part      */
           if (iml1 <= 127) {               /* length in one byte      */
             *(--achl1) = (unsigned char) iml1;
           } else {
             achl1 -= 2;
             m_put_be2( achl1, iml1 );
             *achl1 |= 0X80;                /* length in two bytes     */
           }
           achl1 -= 13;                     /* here is start of block  */
           *achl1 = DEF_CONST_RDP_03;
           *(achl1 + 1) = 0;                /* second byte zero        */
           m_put_be2( achl1 + 2, ADSL_OA1->achc_lower - achl1 );
           memcpy( achl1 + 4,
                   ucrs_x224_p01,
                   sizeof(ucrs_x224_p01) );
           *(achl1 + 4 + sizeof(ucrs_x224_p01)) = 0X64;  /* send data request */
           m_put_be2( achl1 + 8,
                      ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.usc_userid_cl2se );
           m_put_be2( achl1 + 10, D_DISPLAY_CHANNEL );
           *(achl1 + 12) = 0X70;            /* priority / segmentation */
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
           ADSL_GAI1_OUT_G->adsc_next = NULL;
           ADSL_GAI1_OUT_G->achc_ginp_cur = achl1;
           ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
           *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
           ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
#undef ACHL_CLIENT_RANDOM_SE
#undef ACHL_CLIENT_RANDOM_CL
#undef ACHL_CL_RAND_ENCRY
#undef ACHL_WORK_AREA
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
           /* continue communication                                   */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_logon_info_1;  /* logon information 1 */
           goto ptose20;                    /* process next data       */
         case ied_frcl_lic_clrand:          /* New Licence Request/ Client License Info */
         {
           iml2  = D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_len;
           achl1 = D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data;
           // [MS-RDPELE].pdf, 2.2.2.2 Client New License Request (CLIENT_NEW_LICENSE_REQUEST), EncryptedPreMasterSecret:
           // Length of EncryptedPreMasterSecret is not the length of the RSA key.
           // This leads to an error in Windows Server 2012, as the length of a certificate is
           // 0x100 there (JB 29.10.12)
           while (iml2 > D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_len - 8) {  /* Das ist die Länge der Daten, die decrypted werden sollen. Davor stehen 8 Nullen.  */
             if (*achl1) {                  /* data too long, superfluous byte not filled with zero */
         iml_line_no = __LINE__;
         iml_source_no = 32878;    /* source line no for errors */
         goto ptose92;
             }
             iml2--;
             achl1++;
           }
           iml1 = sizeof(chrl_work_1);
           /* encrypt with general key; if there was a special licensing key, we suppressed it */
#ifdef XH_INTERFACE
			ds__hmem dsl_new_struct;
			memset(&dsl_new_struct, 0, sizeof(ds__hmem));
			dsl_new_struct.in__aux_up_version = 1;
			dsl_new_struct.am__aux2 = adsp_hl_clib_1->amc_aux;
			dsl_new_struct.in__flags = 0;
			dsl_new_struct.vp__context = adsp_hl_clib_1->vpc_userfld;
#endif
#ifdef __INSURE__
           // rsa_crypt_raw uses lnum, which causes an Insure-error.
           _Insure_checking_enable(0);
#endif
           iml2 = m_rsa_crypt_raw_big( 
#ifdef XH_INTERFACE
                                       &dsl_new_struct,
#endif			   
		                         	   (unsigned char *) achl1,
                                       iml2,
                                       (unsigned char *) ucrs_rdp_private_key,
                                       sizeof(ucrs_rdp_private_key),
                                       (unsigned char *) ucrs_rdp_cert + D_POS_CERT_PUBLIC_KEY,
                                       D_LEN_CERT_PUBLIC_KEY,
                                       (unsigned char *) chrl_work_1,
                                       &iml1 );
#ifdef __INSURE__
           _Insure_checking_enable(1);
#endif
#ifdef XH_INTERFACE
           HMemMgrFree(&dsl_new_struct);
#endif
           if (iml2) goto ptose92;          /* protocol error          */
           if (iml1 == 0) goto ptose92;     /* protocol error          */
           /* store the premaster (in decrypted, but Big-Endian form)  */
           achl1 = D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data;
           if (iml1 < 48) {                 /* size given in MS-RDPELE 2.2.2.2 */
             iml3 = 48 - iml1;              /* length filled with zeroes */
             memset( achl1, 0, iml3 );
             achl1 += iml3;
             iml1 = 48;
           }
           memcpy( achl1, chrl_work_1, iml1 - (achl1 - D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data) );
           D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_len = iml1;
           /* make licencing keys                                      */
           m_gen_lic_keys( D_ADSL_RCO1->adsc_lic_neg, chrl_work_2 );
           goto ptose40;                    /* send to server          */
       }
       goto ptose96;                        /* program illogic         */
     }
     case ied_fcfp_copy_crlf:               /* copy till <CR><LF> found */
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame;
       if (iml1 > iml_rec) iml1 = iml_rec;
       do {                                 /* loop over input characters */
         chl_w1 = *D_ADSL_RSE1->achc_prot_1++ = *adsl_gai1_inp_1->achc_ginp_cur++;  /* get input */
         D_ADSL_RSE1->imc_pos_inp_frame--;  /* position in frame       */
         if (chl_w1 == CHAR_CR) {           /* carriage-return found   */
           D_ADSL_RSE1->imc_prot_akku = 1;  /* set state CR            */
         } else if (chl_w1 == CHAR_LF) {    /* line-feed found         */
           if (D_ADSL_RSE1->imc_prot_akku != 0) {  /* check state CR   */
             /* found <CR> <LF>                                        */
             /* here ied_frcl_start                                    */
             if (D_ADSL_RSE1->imc_pos_inp_frame == 0) {  /* end of this frame - old client */
               bol1 = m_send_se2cl_const( adsp_hl_clib_1, &dsl_output_area_1, (char *) ucrs_secl_01, sizeof(ucrs_secl_01) );
               D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
               D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_02;
               goto ptose20;                /* process next data       */
             }
             if (D_ADSL_RSE1->imc_pos_inp_frame < (2 + 2 + 4)) {
         iml_line_no = __LINE__;
         iml_source_no = 32969;    /* source line no for errors */
         goto ptose92;
             }
             D_ADSL_RSE1->imc_prot_save1 = -1;  /* first retrieve type */
             D_ADSL_RSE1->imc_prot_count_in = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
             D_ADSL_RSE1->imc_prot_aux1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RSE1->imc_prot_akku = 0;  /* clear value           */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
             goto ptose20;                  /* process next data       */
           }
           D_ADSL_RSE1->imc_prot_akku = 0;  /* reset state CR          */
         } else {                           /* all other characters    */
           D_ADSL_RSE1->imc_prot_akku = 0;  /* reset state CR          */
         }
         iml1--;                            /* character processed     */
       } while (iml1 > 0);
       if (D_ADSL_RSE1->imc_pos_inp_frame > 0) {
         goto ptose20;                      /* needs more data         */
       }
       if (D_ADSL_RSE1->achc_prot_1 != (D_ADSL_RSE1->chrc_prot_1 + 2 + 2 + 4)) {
         iml_line_no = __LINE__;
         iml_source_no = 32991;    /* source line no for errors */
         goto ptose92;
       }
       iml1 = (unsigned char) D_ADSL_RSE1->chrc_prot_1[ 0 + 0 ]
                | ((unsigned char) D_ADSL_RSE1->chrc_prot_1[ 0 + 1 ] << 8);
       if (iml1 != 1) {                     /* type of field invalid   */
         iml_line_no = __LINE__;
         iml_source_no = 32996;    /* source line no for errors */
         goto ptose92;
       }
       iml1 = (unsigned char) D_ADSL_RSE1->chrc_prot_1[ 2 + 0 ]
                | ((unsigned char) D_ADSL_RSE1->chrc_prot_1[ 2 + 1 ] << 8);
       if (iml1 != 8) {                     /* length of field invalid */
         iml_line_no = __LINE__;
         iml_source_no = 33001;    /* source line no for errors */
         goto ptose92;
       }
       iml1 = (unsigned char) D_ADSL_RSE1->chrc_prot_1[ 4 + 0 ]
                | ((unsigned char) D_ADSL_RSE1->chrc_prot_1[ 4 + 1 ] << 8)
                | ((unsigned char) D_ADSL_RSE1->chrc_prot_1[ 4 + 2 ] << 16)
                | ((unsigned char) D_ADSL_RSE1->chrc_prot_1[ 4 + 3 ] << 24);
       bol1 = m_send_se2cl_const( adsp_hl_clib_1, &dsl_output_area_1, (char *) ucrs_secl_02, sizeof(ucrs_secl_02) );
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
       D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_02;
       goto ptose20;                        /* process next data       */
     case ied_fcfp_zero_cmp:                /* compare zeroes          */
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame
                - D_ADSL_RSE1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       do {                                 /* loop over input data    */
         if (*adsl_gai1_inp_1->achc_ginp_cur++) {  /* value not zero   */
         iml_line_no = __LINE__;
         iml_source_no = 33018;    /* source line no for errors */
         goto ptose92;
         }
         D_ADSL_RSE1->imc_pos_inp_frame--;  /* length processed        */
         iml1--;                            /* decrement index         */
       } while (iml1 > 0);
       if (D_ADSL_RSE1->imc_pos_inp_frame > D_ADSL_RSE1->imc_prot_2) {
         goto ptose20;                      /* needs more data         */
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_c_loinf_domna_val:   /* Domain Name String      */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_userna_val;  /* User Name String */
           if (D_ADSL_RCO1->usc_loinf_userna_len) {  /* User Name Length */
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RCO1->usc_loinf_userna_len;  /* number of bytes */
             if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame    */
         iml_line_no = __LINE__;
         iml_source_no = 33032;    /* source line no for errors */
         goto ptose92;
             }
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->awcc_loinf_userna_a) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->usc_loinf_userna_len );
             D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->awcc_loinf_userna_a;  /* User Name */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data normal */
             goto ptose20;                  /* process next data       */
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 33041;    /* source line no for errors */
         goto ptose92;
           }
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_userna_val:  /* User Name String        */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_pwd_val;  /* Password String */
           if (D_ADSL_RCO1->usc_loinf_pwd_len) {  /* Password Length   */
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RCO1->usc_loinf_pwd_len;  /* number of bytes */
             if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame    */
         iml_line_no = __LINE__;
         iml_source_no = 33049;    /* source line no for errors */
         goto ptose92;
             }
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->awcc_loinf_pwd_a) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->usc_loinf_pwd_len );
             D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->awcc_loinf_pwd_a;  /* Password */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data normal */
             goto ptose20;                  /* process next data       */
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 33058;    /* source line no for errors */
         goto ptose92;
           }
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_pwd_val:     /* Password String         */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_altsh_val;  /* Alt Shell String */
           if (D_ADSL_RCO1->usc_loinf_altsh_len) {  /* Alt Shell Length */
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RCO1->usc_loinf_altsh_len;  /* number of bytes */
             if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame    */
         iml_line_no = __LINE__;
         iml_source_no = 33066;    /* source line no for errors */
         goto ptose92;
             }
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->awcc_loinf_altsh_a) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->usc_loinf_altsh_len );
             D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->awcc_loinf_altsh_a;  /* Alt Shell */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data normal */
             goto ptose20;                  /* process next data       */
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 33075;    /* source line no for errors */
         goto ptose92;
           }
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_altsh_val:   /* Alt Shell String        */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_wodir_val;  /* Working Directory String */
           if (D_ADSL_RCO1->usc_loinf_wodir_len) {  /* Working Directory Length */
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RCO1->usc_loinf_wodir_len;  /* number of bytes */
             if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame    */
         iml_line_no = __LINE__;
         iml_source_no = 33083;    /* source line no for errors */
         goto ptose92;
             }
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->awcc_loinf_wodir_a) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->usc_loinf_wodir_len );
             D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->awcc_loinf_wodir_a;  /* Working Directory */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data normal */
             goto ptose20;                  /* process next data       */
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 33092;    /* source line no for errors */
         goto ptose92;
           }
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_wodir_val:   /* Working Directory String */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 33098;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_no_a_par;  /* number of additional parameters */
           goto ptose20;                    /* process next data       */
       }
       M_ERROR_TOSE_ILLOGIC                 /* programm illogic        */
     case ied_fcfp_rdp5_rc4:                /* input RC4 encrypted     */
       /* compute how many to decrypt                                  */
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame
                - D_ADSL_RSE1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       if ((D_ADSL_RCO1->dsc_encry_cl2se.imc_count_sent & (4096 - 1)) == 0){
         if (D_ADSL_RSE1->achc_prot_1 == (char *) D_ADSL_RSE1->ac_temp_buffer) {  /* start of temporary buffer */
           if (D_ADSL_RCO1->dsc_encry_cl2se.imc_count_sent) {
             m_update_keys( D_ADSL_RCO1, &D_ADSL_RCO1->dsc_encry_cl2se, NULL );
           }
         }
       }
       RC4( adsl_gai1_inp_1->achc_ginp_cur, 0, iml1,
            D_ADSL_RSE1->achc_prot_1, 0,
            D_ADSL_RCO1->dsc_encry_cl2se.chrc_rc4_state );
       D_ADSL_RSE1->achc_prot_1 += iml1;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RSE1->imc_pos_inp_frame -= iml1;  /* length processed    */
       if (D_ADSL_RSE1->imc_pos_inp_frame > D_ADSL_RSE1->imc_prot_2) {
         goto ptose20;                      /* needs more data         */
       }
       bol1 = m_check_hash_inp_rdp5( adsp_hl_clib_1,
                                     (char *) D_ADSL_RSE1->ac_temp_buffer,
                                     D_ADSL_RSE1->achc_prot_1 - (char *) D_ADSL_RSE1->ac_temp_buffer );
       if (bol1 == FALSE) {                 /* hash does not match     */
         m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d received from client hash invalid",
                       __LINE__, 33186 );  /* line number for errors  */
         iml_line_no = __LINE__;
         iml_source_no = 33187;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RCO1->dsc_encry_cl2se.imc_count_sent++;  /* count blocks client has sent */
       /* data from client RDP 5 decrypted                             */
       /* make gather with record                                      */
       if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
         memset( &dsl_gai1_start_rec, 0, sizeof(struct dsd_gather_i_1) );
         dsl_gai1_start_rec.achc_ginp_cur = (char *) D_ADSL_RSE1->ac_temp_buffer;
         dsl_gai1_start_rec.achc_ginp_end = D_ADSL_RSE1->achc_prot_1;
         ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
           = ied_trc_cl2se_r5;              /* client to server RDP 5, decrypted */
         ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = &dsl_gai1_start_rec;
         ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RSE1->achc_prot_1 - (char *) D_ADSL_RSE1->ac_temp_buffer;  /* remaining data */
         ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_record - (D_ADSL_RSE1->achc_prot_1 - (char *) D_ADSL_RSE1->ac_temp_buffer);
         ADSL_RDPA_F->dsc_rdptr1.imc_prot1 = D_ADSL_RSE1->imc_prot_4;  /* variable field */
         m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
         D_ADSL_RCO1->imc_len_part = D_ADSL_RSE1->achc_prot_1 - (char *) D_ADSL_RSE1->ac_temp_buffer;  /* length of part */
         ADSL_RDPA_F->dsc_rdptr1.chc_type_disp = 'E';  /* type of displacement */
       }
       m_send_cl2se_rdp5( adsp_hl_clib_1, &dsl_output_area_1,
                          (char *) D_ADSL_RSE1->ac_temp_buffer,
                          D_ADSL_RSE1->achc_prot_1 - (char *) D_ADSL_RSE1->ac_temp_buffer,
                          D_ADSL_RSE1->imc_prot_4 );
       D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_xyz_01;
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_x224_p01:                /* is in x224 header       */
       iml1 = sizeof(ucrs_x224_p01);        /* get length              */
       if (iml1 > (D_ADSL_RSE1->imc_prot_1 + iml_rec)) {
         iml1 = D_ADSL_RSE1->imc_prot_1 + iml_rec;
       }
       iml1 -= D_ADSL_RSE1->imc_prot_1;
       if (memcmp( ucrs_x224_p01 + D_ADSL_RSE1->imc_prot_1,
                   adsl_gai1_inp_1->achc_ginp_cur,
                   iml1 )) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33255;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->imc_prot_1 += iml1;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RSE1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RSE1->imc_prot_1 < sizeof(ucrs_x224_p01)) {
         goto ptose20;                      /* process next data       */
       }
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_mcs_c1;  /* MCS command 1   */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_rec_type:                /* get type of record      */
       D_ADSL_RCO1->chrc_start_rec[0] = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record */
       D_ADSL_RCO1->imc_len_start_rec = 1;  /* length start of record  */
       /* check input RDP5-style                                       */
       if ((((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur) & 0X03) == 0) {
         /* save encrypted                                             */
         D_ADSL_RSE1->imc_prot_3 = ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur) & 0X80;
         /* save number of events                                      */
         D_ADSL_RSE1->imc_prot_4 = (((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur) & 0X3F) >> 2;
         // Can be 0. If 0, length is send later in a second numberEvents.
         // @see [MS-RDPBCGR] 2.2.8.1.2 Client Fast-Path Input Event PDU (TS_FP_INPUT_PDU)
         //if (D_ADSL_RSE1->imc_prot_4 == 0) {  /* no event              */
         //  M_ERROR_TOSE_PROT;              /* protocol error          */
         //}
         /* save flag for block count into hash                        */
         D_ADSL_RSE1->chc_prot_rt03 = ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur) & 0X40;
         adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input         */
         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rdp5_len1;  /* RDP5 input length 1 */
         goto ptose20;                      /* process next data       */
       }
       if (*adsl_gai1_inp_1->achc_ginp_cur != 0X03) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33306;    /* source line no for errors */
         goto ptose92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_byte01;  /* receive byte 01 */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_byte01:                  /* receive byte 01         */
       if (*adsl_gai1_inp_1->achc_ginp_cur) {
         if (   ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur == 0XFF)
             && (ADSL_RDPA_F->boc_scp_hrdpe1)) {  /* protocol HOB MS RDP Ext 1 */
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_hext_ctrl;  /* HOB-RDP-EXT1 control character */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_hext_send;  /* HOB-RDP-EXT1 send to server / SDH */
           goto ptose20;                        /* process next data       */
         }
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33323;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec++ ]
         = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record        */
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_lencons_2;  /* receive len c */
       D_ADSL_RSE1->imc_prot_1 = 0;         /* clear length field      */
       D_ADSL_RSE1->imc_pos_inp_frame = 0;  /* no length frame yet     */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_lencons_2:               /* two bytes length remain */
       if (D_ADSL_RSE1->imc_pos_inp_frame == 0) {  /* no len frame yet */
         D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec++ ]
           = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record      */
       }
       D_ADSL_RSE1->imc_prot_1 <<= 8;
       D_ADSL_RSE1->imc_prot_1
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_lencons_1;  /* receive len c */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_lencons_1:               /* one byte length remains */
       if (D_ADSL_RSE1->imc_pos_inp_frame == 0) {  /* no len frame yet */
         D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec++ ]
           = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record      */
       }
       D_ADSL_RSE1->imc_prot_1 <<= 8;
       D_ADSL_RSE1->imc_prot_1
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
#ifdef TRACEHL1
       printf( "ied_fcfp_lencons_1 received len=%d\n",
               D_ADSL_RSE1->imc_prot_1 );
#endif
       if (D_ADSL_RSE1->imc_pos_inp_frame == 0) {  /* no len frame yet */
         D_ADSL_RCO1->imc_len_record = D_ADSL_RSE1->imc_prot_1;  /* length of record */
         D_ADSL_RCO1->imc_len_part = D_ADSL_RSE1->imc_prot_1;  /* length of part */
         ADSL_RDPA_F->dsc_rdptr1.chc_type_disp = 'R';  /* type of displacement */
         D_ADSL_RSE1->imc_pos_inp_frame = D_ADSL_RSE1->imc_prot_1 - 4;
         if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) {
//         goto ptose92;                    /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33378;    /* source line no for errors */
         goto ptose92;
         }
#ifdef HL_RDPACC_HELP_DEBUG
         D_ADSL_RCO1->imc_debug_reclen = D_ADSL_RSE1->imc_prot_1;
#endif
         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_r4_collect;  /* RDP 4 collect data */
         goto ptose20;                      /* process next data       */
       } else {
         D_ADSL_RSE1->imc_pos_inp_frame -= 2;  /* adjust length remaining */
         if (D_ADSL_RSE1->imc_pos_inp_frame < 0) {
//         goto ptose92;                    /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33391;    /* source line no for errors */
         goto ptose92;
         }
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_start:
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_l1_fi;  /* ASN.1 length field */
           D_ADSL_RSE1->imc_prot_3 = 0;     /* maybe till end of block */
           goto ptose20;                    /* process next data       */
         case ied_frcl_rec_02:
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_x224_mcs)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33402;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_x224mcs;
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_usd1:         /* b2 MC User Data Start   */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - D_ADSL_RSE1->imc_prot_1;
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33413;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data */
           goto ptose20;                    /* process next data       */
         case ied_frcl_rec_05:              /* received block 5        */
         case ied_frcl_rec_06:              /* received block 6        */
         case ied_frcl_cjreq_rec:           /* receive block channel join request */
         case ied_frcl_c_logon_info_1:      /* logon information 1     */
         case ied_frcl_resp_act_pdu_rec:    /* response block active PDU */
         case ied_frcl_rec_xyz_01:
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_x224_p01)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33425;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_x224_p01;  /* is in x224 header */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
//       default:
//         goto ptose96;                    /* program illogic         */
       }
           goto ptose96;                    /* program illogic         */
     case ied_fcfp_r4_collect:              /* RDP 4 collect data      */
       /* check if all data of this frame have been received           */
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* remaining data in frame */
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
       /* start of record                                              */
       if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
         memset( &dsl_gai1_start_rec, 0, sizeof(struct dsd_gather_i_1) );
         dsl_gai1_start_rec.achc_ginp_cur = D_ADSL_RCO1->chrc_start_rec;
         dsl_gai1_start_rec.achc_ginp_end = D_ADSL_RCO1->chrc_start_rec + D_ADSL_RCO1->imc_len_start_rec;
         dsl_gai1_start_rec.adsc_next = adsl_gai1_inp_1;
         ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
           = ied_trc_recv_client;           /* received from client    */
         ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = &dsl_gai1_start_rec;
         ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RCO1->imc_len_record;  /* length of record */
         m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_start:
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_l1_fi;  /* ASN.1 length field */
           D_ADSL_RSE1->imc_prot_3 = 0;     /* maybe till end of block */
           goto ptose20;                    /* process next data       */
         case ied_frcl_rec_02:
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_x224_mcs)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33488;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_x224mcs;
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_usd1:         /* b2 MC User Data Start   */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - D_ADSL_RSE1->imc_prot_1;
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33499;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data */
           goto ptose20;                    /* process next data       */
         case ied_frcl_rec_05:              /* received block 5        */
         case ied_frcl_rec_06:              /* received block 6        */
         case ied_frcl_cjreq_rec:           /* receive block channel join request */
         case ied_frcl_c_logon_info_1:      /* logon information 1     */
         case ied_frcl_resp_act_pdu_rec:    /* response block active PDU */
         case ied_frcl_rec_xyz_01:
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_x224_p01)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33511;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_x224_p01;  /* is in x224 header */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
//       default:
//         goto ptose96;                    /* program illogic         */
       }
           goto ptose96;                    /* program illogic         */
     case ied_fcfp_rdp5_len1:               /* RDP5 input length 1     */
       /* check two bytes len                                          */
       if (((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur) & 0X80) {
         D_ADSL_RSE1->imc_pos_inp_frame
           = (((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++) & 0X7F) << 8;
         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rdp5_len2;  /* RDP5 input length 2 */
         goto ptose20;                        /* process next data       */
       }
       D_ADSL_RCO1->chrc_start_rec[ D_ADSL_RCO1->imc_len_start_rec++ ]
         = *adsl_gai1_inp_1->achc_ginp_cur;  /* start of record        */
       D_ADSL_RCO1->imc_len_record = (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur;  /* length of record */
       D_ADSL_RCO1->imc_len_part = (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur;  /* length of part */
       ADSL_RDPA_F->dsc_rdptr1.chc_type_disp = 'R';  /* type of displacement */
       D_ADSL_RSE1->imc_pos_inp_frame
         = ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur) - 2;
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next character input    */
       /* next is hash                                                 */
       D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_SIZE_HASH;
       if (D_ADSL_RSE1->imc_prot_2 <= 0) {  /* length after hash       */
         iml_line_no = __LINE__;
         iml_source_no = 33542;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->achc_prot_1 = D_ADSL_RSE1->chrc_inp_hash;  /* input hash */
       D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rdp5_inp;  /* RDP5-style input data */
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data  */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_rdp5_len2:               /* RDP5 input length 2     */
       D_ADSL_RSE1->imc_pos_inp_frame
         |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++);
       D_ADSL_RSE1->imc_pos_inp_frame -= 3;
       /* next is hash                                                 */
       D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_SIZE_HASH;
       if (D_ADSL_RSE1->imc_prot_2 <= 0) {  /* length after hash       */
         iml_line_no = __LINE__;
         iml_source_no = 33555;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->achc_prot_1 = D_ADSL_RSE1->chrc_inp_hash;  /* input hash */
       D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rdp5_inp;  /* RDP5-style input data */
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data  */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_mcs_c1:                  /* MCS command 1           */
       switch (*adsl_gai1_inp_1->achc_ginp_cur) {
         case 0X04:                         /* MCS Errect Domain Request */
           if (D_ADSL_RSE1->iec_frcl_bl != ied_frcl_rec_05) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33566;    /* source line no for errors */
         goto ptose92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RSE1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RSE1->imc_pos_inp_frame != 4) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33572;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RSE1->chrc_prot_1;
#ifdef XYZ1
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
             goto ptose92;                  /* protocol error          */
           }
#endif
           D_ADSL_RSE1->imc_prot_2 = 0;     /* copy all bytes          */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           goto ptose20;                    /* process next data       */
//       case 0X20:                         /* MCS end of comm - machine down ???? UUUU */
         case 0X21:                         /* MCS end of comm ???? UUUU */
           if (D_ADSL_RSE1->iec_frcl_bl != ied_frcl_rec_xyz_01) {  /* ????ive block active PDU */
         iml_line_no = __LINE__;
         iml_source_no = 33587;    /* source line no for errors */
         goto ptose92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RSE1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) {
         iml_line_no = __LINE__;
         iml_source_no = 33592;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_end_com;  /* end of communication */
           goto ptose20;                    /* process next data       */
         case 0X28:                         /* MCS Attach User Request */
           if (D_ADSL_RSE1->iec_frcl_bl != ied_frcl_rec_06) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33599;    /* source line no for errors */
         goto ptose92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RSE1->imc_pos_inp_frame--;  /* length constant       */
           if (D_ADSL_RSE1->imc_pos_inp_frame) {  /* more data to follow */
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33605;    /* source line no for errors */
         goto ptose92;
           }
           /* send this block unchanged to server                      */
           ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
           if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
             goto ptose96;                  /* program illogic         */
           }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
           ADSL_GAI1_OUT_G->adsc_next = NULL;
           ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
           memcpy( ADSL_OA1->achc_lower, ucrs_x224_r06_attuser, sizeof(ucrs_x224_r06_attuser) );
           ADSL_OA1->achc_lower += sizeof(ucrs_x224_r06_attuser);
           ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
           *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
           ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
//         D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_06;  /* receive block 6 */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_cjreq_rec;  /* receive block channel join request */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_invalid;  /* invalid data received */
#ifdef TRACEHL1
           if (ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl != ied_fsfp_invalid) {  /* receive record type */
             printf( "after block 6 from client not correct state client\n" );
             goto ptose96;                  /* program illogic         */
           }
#endif
           ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
           goto ptose20;                    /* process next data       */
         case 0X38:                         /* MCS Channel Join Request */
           if (D_ADSL_RSE1->iec_frcl_bl != ied_frcl_cjreq_rec) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33690;    /* source line no for errors */
         goto ptose92;
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RSE1->imc_pos_inp_frame--;  /* length constant       */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33697;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_userid;  /* userid communication follows */
           goto ptose20;                    /* process next data       */
         case 0X64:                         /* MCS Send Data Request   */
           if (D_ADSL_RSE1->iec_frcl_bl == ied_frcl_cjreq_rec) {
             D_ADSL_RSE1->iec_frcl_bl = ied_frcl_clrand_rec;
#ifdef TRACEHL1
             if (   (ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl != ied_fsfp_invalid)  /* receive record type */
                 || (ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl != ied_frse_cjresp_rec)) {  /* receive block channel join response */
               printf( "after block logon information from client not correct state server\n" );
               goto ptose96;                /* program illogic         */
             }
#endif
             if (ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl == ied_frse_cjresp_rec) {  /* receive block channel join response */
               ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl = ied_frse_lic_pr_1_rec;  /* receive block licence protocol */
             }
             if (ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl == ied_fsfp_invalid)  {  /* receive record type */
               ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
             }
           }
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RSE1->imc_pos_inp_frame--;  /* length constant       */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33733;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_userid;  /* userid communication follows */
           goto ptose20;                    /* process next data       */
       }
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33740;    /* source line no for errors */
         goto ptose92;
     case ied_fcfp_userid:                  /* userid communication follows */
       while (TRUE) {
         D_ADSL_RSE1->imc_prot_1 <<= 8;
         D_ADSL_RSE1->imc_prot_1
           |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RSE1->imc_pos_inp_frame--;
         if (D_ADSL_RSE1->imc_pos_inp_frame == D_ADSL_RSE1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto ptose20;                    /* needs more data         */
         }
       }
#ifdef TRACEHL1
       printf( "ied_fcfp_userid found int=%d D_ADSL_RSE1->iec_frcl_bl=%d\n",
               D_ADSL_RSE1->imc_prot_1,
               D_ADSL_RSE1->iec_frcl_bl );
#endif
       if (D_ADSL_RSE1->imc_prot_1 != D_ADSL_RCO1->usc_userid_cl2se) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33760;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
       if (D_ADSL_RSE1->imc_prot_2 < 0) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33765;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->imc_prot_chno = 0;      /* clear value             */
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_chno;  /* channel no follows */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_chno:                    /* channel number follows  */
       while (TRUE) {
         D_ADSL_RSE1->imc_prot_chno <<= 8;
         D_ADSL_RSE1->imc_prot_chno
           |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RSE1->imc_pos_inp_frame--;
         if (D_ADSL_RSE1->imc_pos_inp_frame == D_ADSL_RSE1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto ptose20;                    /* needs more data         */
         }
       }
#ifdef TRACEHL1
       printf( "ied_fcfp_chno found int=%d D_ADSL_RSE1->iec_frcl_bl=%d\n",
               D_ADSL_RSE1->imc_prot_chno,
               D_ADSL_RSE1->iec_frcl_bl );
#endif
//     switch (D_ADSL_RSE1->iec_frcl_bl) {
//     }
       if (D_ADSL_RSE1->iec_frcl_bl == ied_frcl_cjreq_rec) {
         do {
           if (D_ADSL_RSE1->imc_pos_inp_frame) {  /* more data to follow */
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33798;    /* source line no for errors */
         goto ptose92;
           }
           iml1 = -1;                       /* set display channel     */
           if (D_ADSL_RSE1->imc_prot_chno == D_ADSL_RCO1->usc_chno_disp) {  /* channel number display */
             break;
           }
           iml1 = D_ADSL_RCO1->imc_no_virt_ch;  /* number of virtual channels */
           while (iml1) {
#define D_ADSL_VCH (D_ADSL_RCO1->adsrc_vc_1 + (D_ADSL_RCO1->imc_no_virt_ch - iml1))
             /* compare virtual channel no                             */
             if (D_ADSL_RSE1->imc_prot_chno == D_ADSL_VCH->usc_vch_no) {
               break;
             }
#undef D_ADSL_VCH
             iml1--;                        /* number before           */
           }
           if (iml1 > 0) break;             /* channel found           */
           /* channel number control                                   */
           if (D_ADSL_RCO1->dtc_rdpfl_1.ibc_contchno) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33818;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RCO1->usc_chno_cont = (unsigned short int) D_ADSL_RSE1->imc_prot_chno;
           D_ADSL_RCO1->dtc_rdpfl_1.ibc_contchno = 1;
           /* set also for client                                      */
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_chno_cont
             = (unsigned short int) D_ADSL_RSE1->imc_prot_chno;
           ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dtc_rdpfl_1.ibc_contchno = 1;
         } while (FALSE);
         /* send this block unchanged to server                        */
         ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
         if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
           goto ptose96;                    /* program illogic         */
         }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
         ADSL_GAI1_OUT_G->adsc_next = NULL;
         ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
         memcpy( ADSL_OA1->achc_lower, ucrs_x224_cjreq_1, sizeof(ucrs_x224_cjreq_1) );
         ADSL_OA1->achc_lower += sizeof(ucrs_x224_cjreq_1);
         m_put_be2( ADSL_OA1->achc_lower, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
         ADSL_OA1->achc_lower += 2;
         m_put_be2( ADSL_OA1->achc_lower, D_ADSL_RSE1->imc_prot_chno );
         ADSL_OA1->achc_lower += 2;
         ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
         *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
         ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
#ifndef B061002
//         D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_06;  /* receive block 6 */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
//       D_ADSL_RSE1->iec_frcl_bl = ied_frcl_cjreq_rec;  /* receive block channel join request */
#ifdef TRACEHL1
         if (ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl != ied_fcfp_invalid) {  /* receive record type */
           printf( "after block cjreq from client not correct state server\n" );
           goto ptose96;                    /* program illogic         */
         }
#endif
#else
#endif
         ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
         goto ptose20;                      /* process next data       */
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_clrand_rec:          /* receive client random   */
         case ied_frcl_c_logon_info_1:      /* logon information 1     */
         case ied_frcl_resp_act_pdu_rec:    /* response block active PDU */
         case ied_frcl_rec_xyz_01:
           if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33926;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_prio_seg;  /* Priority / Segmentation */
           goto ptose20;                    /* process next data       */
       }
           goto ptose96;                    /* program illogic         */
     case ied_fcfp_prio_seg:                /* Priority / Segmentation */
       if (*adsl_gai1_inp_1->achc_ginp_cur != 0X70) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33935;    /* source line no for errors */
         goto ptose92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RSE1->imc_pos_inp_frame--;
       if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33941;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_mu_len_1;  /* multi length 1 */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_rt02:                    /* record type 2           */
       D_ADSL_RSE1->chc_prot_rt02 = *adsl_gai1_inp_1->achc_ginp_cur++;
#ifdef XYZ1
       adsl_gai1_inp_1->achc_ginp_cur++;
#endif
       D_ADSL_RSE1->imc_pos_inp_frame--;
       if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33953;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rt03;  /* record type 3     */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_rt03:                    /* record type 3           */
#ifdef HL_RDPACC_HELP_DEBUG
     if (ADSL_RDPA_F) {                     /* memory defined          */
       if (ADSL_RDPA_F->boc_help_debug_1) {  /* stop debugger          */
         printf( "xlrdpa1 m_hlclib01() called boc_help_debug_1 set\n" );
         int inh1 = 0;
         inh1++;
       }
     }
#endif
       D_ADSL_RSE1->chc_prot_rt03 = *adsl_gai1_inp_1->achc_ginp_cur++;
#ifdef XYZ1
       if (*adsl_gai1_inp_1->achc_ginp_cur) {  /* contents not zero    */
         goto ptose92;                      /* protocol error          */
       }
       adsl_gai1_inp_1->achc_ginp_cur++;
#endif
       D_ADSL_RSE1->imc_pos_inp_frame--;
       /* two bytes padding follow - to be ignored                     */
       D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;
       if (D_ADSL_RSE1->imc_prot_2 < 0) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 33979;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_padd_1;  /* padding         */
#ifdef NOT_VALID_060924
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rt04;  /* record type 4     */
#endif
       goto ptose20;                        /* process next data       */
#ifdef NOT_VALID_060924
     case ied_fcfp_rt04:                    /* record type 4           */
       D_ADSL_RSE1->chc_prot_rt04 = *adsl_gai1_inp_1->achc_ginp_cur++;
#ifndef B060924
       printf( "l%05d s%05d case ied_fcfp_rt04: D_ADSL_RSE1->chc_prot_rt04 = 0X%02X\n",
           __LINE__, 33991, (unsigned char) D_ADSL_RSE1->chc_prot_rt04 );
#endif
       D_ADSL_RSE1->imc_pos_inp_frame--;
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_padd_1;  /* padding         */
       goto ptose20;                        /* process next data       */
#endif
     case ied_fcfp_padd_1:                  /* padding                 */
       /* compute how many to ignore                                   */
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame
                - D_ADSL_RSE1->imc_prot_2;
       if (iml1 > iml_rec) iml1 = iml_rec;
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RSE1->imc_pos_inp_frame -= iml1;  /* length constant     */
       if (D_ADSL_RSE1->imc_pos_inp_frame > D_ADSL_RSE1->imc_prot_2) {
         goto ptose20;                      /* needs more data         */
       }
#ifdef NOT_VALID_060924
       /* one byte to be ignored                                       */
       adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RSE1->imc_pos_inp_frame--;
#endif
       switch (D_ADSL_RSE1->chc_prot_rt02 & 0XC7) {
         case 0X01:                         /* client random           */
           if (D_ADSL_RSE1->iec_frcl_bl != ied_frcl_clrand_rec) {  /* receive client random */
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34023;    /* source line no for errors */
         goto ptose92;
           }
           if (D_ADSL_RSE1->chc_prot_rt02 & 0X08) {  /* block encrypted */
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34027;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_client_rand;  /* receive client random   */
           goto ptose20;                    /* process next data       */
         case 0X40:                         /* logon information 1     */
           switch (D_ADSL_RSE1->iec_frcl_bl) {
             case ied_frcl_c_logon_info_1:  /* logon information 1     */
               break;
             default:                       /* other values            */
//             goto ptose92;                /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34041;    /* source line no for errors */
         goto ptose92;
           }
           break;
         case 0X00:                         /* response block active PDU */
           switch (D_ADSL_RSE1->iec_frcl_bl) {
             case ied_frcl_resp_act_pdu_rec:  /* response block active PDU */
// new 24.05.07 KB
             case ied_frcl_rec_xyz_01:
               break;
             default:                       /* other values            */
//             goto ptose92;                /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34056;    /* source line no for errors */
         goto ptose92;
           }
           break;
         case 0X80:                         /* SEC_LICENSE_PKT         */
           switch (D_ADSL_RSE1->iec_frcl_bl) {
             case ied_frcl_rec_xyz_01:
             case ied_frcl_resp_act_pdu_rec:  /* response block active PDU */
               break;
             default:                       /* other values            */
//             goto ptose92;                /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34078;    /* source line no for errors */
         goto ptose92;
           }
           break;
         default:
            printf( "padding case %02X received from client iec_frcl_bl=%d iec_fcfp_bl=%d l%d s%d\n",
                    (unsigned char) D_ADSL_RSE1->chc_prot_rt02,
                    ADSL_RDPA_F->dsc_rdp_se_1.iec_frcl_bl,
                    ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl,
                    __LINE__,               /* line number for errors  */
                    34180 );       /* source line no for errors */
           goto ptose96;                    /* program illogic         */
       }
#ifdef TRACEHL1
       printf( "28.12.04 KB - encrypted part follows\n" );
#endif
       if ((D_ADSL_RSE1->chc_prot_rt02 & 0X08) == 0) {  /* block not encrypted */
#ifndef D_BUG_HLJWT_INP1                    /* 17.07.07 KB - input from HOBlink JWT not encrypted */
         iml_line_no = __LINE__;
         iml_source_no = 34095;    /* source line no for errors */
         goto ptose92;
#else
           /* check if all data of this frame have been received       */
           iml1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* remaining data in frame */
           adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather          */
           while (TRUE) {                   /* loop over all gather structures input */
             iml1 -= adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
             if (iml1 <= 0) break;          /* enough data found       */
             adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
             if (adsl_gai1_inp_w2 == NULL) {  /* already end of chain  */
               /* wait for more data                                   */
               goto p_ret_00;               /* check how to return     */
             }
           }
           /* data from client decrypted                               */
           if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
             ADSL_RDPA_F->dsc_rdptr1.iec_tr_command  /* tracer component command */
               = ied_trc_cl2se_decry;       /* client to server, decrypted */
             ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_inp_1;
             ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = D_ADSL_RSE1->imc_pos_inp_frame;  /* remaining data */
             ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_record - D_ADSL_RSE1->imc_pos_inp_frame;
             ADSL_RDPA_F->dsc_rdptr1.usc_vch_no = D_ADSL_RSE1->imc_prot_chno;  /* virtual channel no com */
             m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
             D_ADSL_RCO1->imc_len_part = D_ADSL_RSE1->imc_pos_inp_frame;  /* length of part */
             ADSL_RDPA_F->dsc_rdptr1.chc_type_disp = 'E';  /* type of displacement */
           }
           if (D_ADSL_RSE1->iec_frcl_bl == ied_frcl_c_logon_info_1) {  /* logon information 1 */
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
             if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame    */
         iml_line_no = __LINE__;
         iml_source_no = 34181;    /* source line no for errors */
         goto ptose92;
             }
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore next bytes */
             D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_options;  /* Options */
             goto ptose20;                  /* process next data       */
           }
           if (D_ADSL_RSE1->imc_prot_chno == D_ADSL_RCO1->usc_chno_disp) {  /* channel number display  */
             if ((D_ADSL_RSE1->chc_prot_rt02 & 0X80) == 0) {  /* is not licencing */
               D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_send_from_client;  /* send data to server */
               goto ptose40;                /* process the data        */
             }
             /* unencrypted licensing block from client received       */
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes (preamble header) */
             D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RSE1->imc_prot_1 = 0;   /* clear value             */
             D_ADSL_RSE1->iec_frcl_bl = ied_frcl_lic_01;    /* licencing block to check */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e; /* int little endian (for length) */
             goto ptose20;                  /* process the data        */
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 34223;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rdp4_vch_ulen;  /* virtual channel uncompressed data length */
           goto ptose20;                    /* process next data       */
#endif
       }
       /* next receive the hash of this frame                          */
       D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RSE1->chrc_prot_1;
       D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_SIZE_HASH;
       if (D_ADSL_RSE1->imc_prot_2 <= 0) {  /* shorter than hash length? */
         iml_line_no = __LINE__;
         iml_source_no = 34249;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data  */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_asn1_tag:                /* ASN.1 tag follows       */
       adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RSE1->imc_pos_inp_frame--;
       if (D_ADSL_RSE1->imc_pos_inp_frame < D_ADSL_RSE1->imc_prot_3) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34669;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_l1_fi;  /* ASN.1 length field */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_asn1_l1_fi:              /* ASN.1 length field 1    */
       D_ADSL_RSE1->imc_prot_1
         = *adsl_gai1_inp_1->achc_ginp_cur & 0X7F;
       if (D_ADSL_RSE1->imc_prot_1 == 0) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34678;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->imc_pos_inp_frame--;
       /* compute how many remain after this length                    */
       D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                  - D_ADSL_RSE1->imc_prot_1;
       if (D_ADSL_RSE1->imc_prot_2 < 0) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34686;    /* source line no for errors */
         goto ptose92;
       }
       /* check ASN-1 length in more than one byte                     */
       if (*adsl_gai1_inp_1->achc_ginp_cur & 0X80) {
         if (D_ADSL_RSE1->imc_prot_1 > 4) {
//         goto ptose92;                    /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34692;    /* source line no for errors */
         goto ptose92;
         }
         adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RSE1->imc_prot_1 = 0;        /* length comes to this    */
         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_l1_p2;  /* ASN.1 length part two */
         goto ptose20;                      /* process next data       */
       }
#ifdef TRACEHL1
       printf( "ied_fcfp_asn1_l1_fi found len=%d till=%d D_ADSL_RSE1->iec_frcl_bl=%d\n",
               D_ADSL_RSE1->imc_prot_1,
               D_ADSL_RSE1->imc_prot_2,
               D_ADSL_RSE1->iec_frcl_bl );
#endif
       adsl_gai1_inp_1->achc_ginp_cur++;
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_start:
           if (D_ADSL_RSE1->imc_prot_2) {
             m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d ied_frcl_start found end invalid %d / %d.",
                           __LINE__, 34715,  /* line number for errors */
                           D_ADSL_RSE1->imc_prot_2, D_ADSL_RSE1->imc_pos_inp_frame );
         iml_line_no = __LINE__;
         iml_source_no = 34717;    /* source line no for errors */
         goto ptose92;
           }
           if (D_ADSL_RSE1->imc_pos_inp_frame < sizeof(ucrs_rec_cl_01_cmp1)) {  /* compare received from client first block */
         iml_line_no = __LINE__;
         iml_source_no = 34724;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
           D_ADSL_RSE1->imc_prot_akku = 0;  /* position                */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcscoen:         /* MCS connect encoding    */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_prot_2;  /* save end data */
           /* protocol error 07.08.04 KB ??? */
           if (D_ADSL_RSE1->imc_prot_3 > 0) {
             printf( "ied_frcl_r02_mcscoen found end too early %d\n",
                     D_ADSL_RSE1->imc_prot_3 );
             D_ADSL_RSE1->imc_prot_3 = 0;   /* save end data all block */
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_tag;  /* ASN.1 tag follows */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mc_cids;  /* b2 MC Calling Domain Selector */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_cids:         /* b2 MC Calling Domain Selector */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_ceds:         /* b2 MC Called Domain Selector */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_upwf:         /* b2 MC Upward Flag       */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_tdop:         /* b2 MC Target Domain Parameters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_midp:         /* b2 MC Minimum Domain Parameters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_madp:         /* b2 MC Maximum Domain Parameters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_usd1:         /* b2 MC User Data Start   */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_lencons_2;  /* rec len c */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear length field      */
           goto ptose20;                    /* process next data       */
         default:
           goto ptose96;                    /* program illogic         */
       }
     case ied_fcfp_asn1_l1_p2:              /* ASN.1 length part two   */
       while (TRUE) {
         D_ADSL_RSE1->imc_prot_1 <<= 8;
         D_ADSL_RSE1->imc_prot_1
           |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RSE1->imc_pos_inp_frame--;
         if (D_ADSL_RSE1->imc_pos_inp_frame == D_ADSL_RSE1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto ptose20;                    /* needs more data         */
         }
       }
       /* compute how many remain after this length                    */
       D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                  - D_ADSL_RSE1->imc_prot_1;
       if (D_ADSL_RSE1->imc_prot_2 < D_ADSL_RSE1->imc_prot_3) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34782;    /* source line no for errors */
         goto ptose92;
       }
#ifdef TRACEHL1
       printf( "ied_fcfp_asn1_l1_p2 found len=%d till=%d D_ADSL_RSE1->iec_frcl_bl=%d\n",
               D_ADSL_RSE1->imc_prot_1,
               D_ADSL_RSE1->imc_prot_2,
               D_ADSL_RSE1->iec_frcl_bl );
#endif
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_r02_mcscoen:         /* MCS connect encoding    */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_prot_2;  /* save end data */
           /* protocol error 07.08.04 KB ??? */
           if (D_ADSL_RSE1->imc_prot_3 > 0) {
             printf( "ied_frcl_r02_mcscoen found end too early %d\n",
                     D_ADSL_RSE1->imc_prot_3 );
             D_ADSL_RSE1->imc_prot_3 = 0;    /* save end data all block */
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_asn1_tag;  /* ASN.1 tag follows */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mc_cids;  /* b2 MC Calling Domain Selector */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_cids:         /* b2 MC Calling Domain Selector */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_ceds:         /* b2 MC Called Domain Selector */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_upwf:         /* b2 MC Upward Flag       */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_tdop:         /* b2 MC Target Domain Parameters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_midp:         /* b2 MC Minimum Domain Parameters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_madp:         /* b2 MC Maximum Domain Parameters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mc_usd1:         /* b2 MC User Data Start   */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_lencons_2;  /* rec len c */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear length field      */
           goto ptose20;                    /* process next data       */
//       default:
//         goto ptose96;                    /* program illogic         */
       }
           goto ptose96;                    /* program illogic         */
     case ied_fcfp_mu_len_1:                /* multi length 1          */
       D_ADSL_RSE1->imc_prot_1
         = *adsl_gai1_inp_1->achc_ginp_cur & 0X7F;
       D_ADSL_RSE1->imc_pos_inp_frame--;
       if (*adsl_gai1_inp_1->achc_ginp_cur & 0X80) {  /* second byte follows */
         adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_mu_len_2;  /* multi length 2 follows */
         goto ptose20;                      /* process next data       */
       }
       adsl_gai1_inp_1->achc_ginp_cur++;
       if (D_ADSL_RSE1->imc_prot_1 == 0) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34840;    /* source line no for errors */
         goto ptose92;
       }
       if (D_ADSL_RSE1->imc_pos_inp_frame < D_ADSL_RSE1->imc_prot_1) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34844;    /* source line no for errors */
         goto ptose92;
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_r02_mcud_l1:         /* b2 MC Us-Da length 1    */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - 12;
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34852;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
#ifdef B060907
         case ied_frcl_r02_mcud_dtt:        /* b2 MC Us-Da Desktop Tag */
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_desktop_tag)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34860;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
#endif
         case ied_frcl_r02_fietype:         /* b2 MC Us-Da Record Type */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_clrand_rec:          /* receive client random   */
         case ied_frcl_c_logon_info_1:      /* logon information 1     */
         case ied_frcl_rec_xyz_01:
           /* compute where end of this field                          */
           D_ADSL_RSE1->imc_prot_4
             = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RSE1->imc_prot_1;
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rt02;  /* record type 2 */
           goto ptose20;                    /* process next data       */
//       default:
//         goto ptose96;                    /* program illogic         */
       }
           goto ptose96;                    /* program illogic         */
     case ied_fcfp_mu_len_2:                /* multi length 2          */
       D_ADSL_RSE1->imc_prot_1 <<= 8;       /* shift old value         */
       D_ADSL_RSE1->imc_prot_1
         |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
       D_ADSL_RSE1->imc_pos_inp_frame--;
       if (D_ADSL_RSE1->imc_prot_1 == 0) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34891;    /* source line no for errors */
         goto ptose92;
       }
       if (D_ADSL_RSE1->imc_pos_inp_frame < D_ADSL_RSE1->imc_prot_1) {
//       goto ptose92;                      /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34895;    /* source line no for errors */
         goto ptose92;
       }
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_r02_mcud_l1:         /* b2 MC Us-Da length 1    */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - 12;
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34903;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data  */
           goto ptose20;                    /* process next data       */
#ifdef B060907
         case ied_frcl_r02_mcud_dtt:        /* b2 MC Us-Da Desktop Tag */
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_desktop_tag)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 34911;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
#endif
         case ied_frcl_r02_fietype:         /* b2 MC Us-Da Record Type */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_clrand_rec:          /* receive client random   */
         case ied_frcl_c_logon_info_1:      /* logon information 1     */
         case ied_frcl_resp_act_pdu_rec:    /* response block active PDU */
         case ied_frcl_rec_xyz_01:
           /* compute where end of this field                          */
           D_ADSL_RSE1->imc_prot_4
             = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RSE1->imc_prot_1;
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rt02;  /* record type 2 */
           goto ptose20;                    /* process next data       */
//       default:
//         goto ptose96;                    /* program illogic         */
       }
           goto ptose96;                    /* program illogic         */
     case ied_fcfp_int_lit_e:               /* int little endian       */
       while (TRUE) {
         D_ADSL_RSE1->imc_prot_1
           |= ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++)
                << ((D_ADSL_RSE1->imc_prot_3 - D_ADSL_RSE1->imc_pos_inp_frame)
                      << 3);
         D_ADSL_RSE1->imc_pos_inp_frame--;
         if (D_ADSL_RSE1->imc_pos_inp_frame == D_ADSL_RSE1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto ptose20;                    /* needs more data         */
         }
       }
#ifdef TRACEHL1
       printf( "ied_fcfp_int_lit_e found int=%d/0X%08X D_ADSL_RSE1->iec_frcl_bl=%d\n",
               D_ADSL_RSE1->imc_prot_1,
               D_ADSL_RSE1->imc_prot_1,
               D_ADSL_RSE1->iec_frcl_bl );
#endif
       switch (D_ADSL_RSE1->iec_frcl_bl) {
         case ied_frcl_start:               /* first block from client */
           if (D_ADSL_RSE1->imc_prot_save1 < 0) {  /* first retrieve type */
             D_ADSL_RSE1->imc_prot_save1 = D_ADSL_RSE1->imc_prot_akku;  /* save type */
             D_ADSL_RSE1->imc_prot_count_in = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
             D_ADSL_RSE1->imc_prot_aux1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RSE1->imc_prot_akku = 0;  /* clear value           */
             goto ptose20;                  /* process next data       */
           }
           if (D_ADSL_RSE1->imc_prot_save1 != 1) {  /* check type      */
         iml_line_no = __LINE__;
         iml_source_no = 34965;    /* source line no for errors */
         goto ptose92;
           }
           if (D_ADSL_RSE1->imc_prot_akku != (2 + 2 + 4)) {  /* check length */
         iml_line_no = __LINE__;
         iml_source_no = 34968;    /* source line no for errors */
         goto ptose92;
           }
           if (D_ADSL_RSE1->imc_pos_inp_frame != 4) {  /* check till end of frame */
         iml_line_no = __LINE__;
         iml_source_no = 34971;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_count_in = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           D_ADSL_RSE1->imc_prot_aux1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_akku = 0;  /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_sta_02;  /* start second field */
           goto ptose20;                    /* process next data       */
         case ied_frcl_sta_02:              /* start second field      */
           bol1 = m_send_se2cl_const( adsp_hl_clib_1, &dsl_output_area_1, (char *) ucrs_secl_02, sizeof(ucrs_secl_02) );
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_02;
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_fietype:         /* b2 MC Field Type        */
           D_ADSL_RSE1->imc_prot_4 = D_ADSL_RSE1->imc_prot_1;  /* save field type */
           if ((D_ADSL_RSE1->imc_prot_4 & 0XFF00) != 0XC000) {  /* check value */
         iml_line_no = __LINE__;
         iml_source_no = 34997;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35001;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_fielen;  /* b2 MC Field Length */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_fielen:          /* b2 MC Field Length      */
           if (D_ADSL_RSE1->imc_prot_1 < 4) {  /* check value minimum length field */
         iml_line_no = __LINE__;
         iml_source_no = 35010;    /* source line no for errors */
         goto ptose92;
           }
           /* compute end of this field                                */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - (D_ADSL_RSE1->imc_prot_1 - 4);
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* more than frame?     */
         iml_line_no = __LINE__;
         iml_source_no = 35015;    /* source line no for errors */
         goto ptose92;
           }
           switch (D_ADSL_RSE1->imc_prot_4) {
             case 0XC001:                   /* field user data         */
               D_ADSL_RSE1->imc_prot_4 = D_ADSL_RSE1->imc_prot_2;  /* save end of this field */
#ifdef B060907
               D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
               D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_c01;  /* b2 MC Us-Da const 01 */
               D_ADSL_RSE1->imc_prot_1 = 0;  /* position               */
               goto ptose20;                /* process next data       */
#endif
               /* protocol version                                     */
               D_ADSL_RSE1->achc_prot_1 = (char *) &D_ADSL_RCO1->ucc_prot_vers;
               D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                          - sizeof(D_ADSL_RCO1->ucc_prot_vers);
               if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* more than frame? */
         iml_line_no = __LINE__;
         iml_source_no = 35031;    /* source line no for errors */
         goto ptose92;
               }
               D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
               D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_c01;  /* b2 MC Us-Da const 01 */
               goto ptose20;                /* process next data       */
             case 0XC003:                   /* virtual channels        */
               /* get number of virtual channels                       */
               D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
               if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* more than frame? */
         iml_line_no = __LINE__;
         iml_source_no = 35046;    /* source line no for errors */
         goto ptose92;
               }
               D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RSE1->imc_prot_1 = 0;      /* clear value             */
//             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
               D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_nvc;  /* b2 MC Us-Da no virt ch */
               goto ptose20;                /* process next data       */
           }
           /* first check if CS_ index double                          */
           achl1 = (char *) ADSL_RDPA_F->ac_cs_block_ch;  /* chain GCC client data */
           while (achl1) {
             if (*((unsigned char *) achl1 + sizeof(void *)) == (D_ADSL_RSE1->imc_prot_4 & 0XFF)) {
               iml_line_no = __LINE__;
               iml_source_no = 35176;    /* source line no for errors */
               goto ptose92;
           }
             achl1 = *((char **) achl1);    /* get next in chain       */
           }
           /* save CS_ entry in storage container                      */
           ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
           ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
           achl1 = (char *) m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1,
                                              sizeof(void *)
                                                + D_ADSL_RSE1->imc_prot_1 );
           m_put_le2( achl1 + sizeof(void *), D_ADSL_RSE1->imc_prot_4 );
           m_put_le2( achl1 + sizeof(void *) + sizeof(short int), D_ADSL_RSE1->imc_prot_1 );
           *((void **) achl1) = ADSL_RDPA_F->ac_cs_block_ch;  /* get old chain GCC client data */
           ADSL_RDPA_F->ac_cs_block_ch = achl1;  /* set new chain GCC client data */
           D_ADSL_RSE1->achc_prot_1 = achl1 + sizeof(void *) + 4;
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - (D_ADSL_RSE1->imc_prot_1 - 4);
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_fietype;  /* b2 MC Field Type */
           goto ptose20;                    /* process next data       */
#ifdef B060907
         case ied_frcl_r02_mcud_dtt:        /* b2 MC Us-Da Desktop Tag */
/* what for imc_prot_1 length? 07.08.04 KB */
           /* protocol version                                         */
           D_ADSL_RSE1->achc_prot_1 = (char *) &D_ADSL_RCO1->ucc_prot_vers;
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - sizeof(D_ADSL_RCO1->ucc_prot_vers);
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35078;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           goto ptose20;                    /* process next data       */
#endif
         case ied_frcl_r02_mcud_scw:        /* b2 MC Us-Da scr width   */
           D_ADSL_RCO1->imc_dim_x = D_ADSL_RSE1->imc_prot_1;  /* dimension x pixels */
//         D_ADSL_RCL1->imc_cmp_dim_x = D_ADSL_RSE1->imc_prot_1;  /* dimension x pixels */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35089;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_sch;  /* b2 MC Us-Da scr height */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_sch:        /* b2 MC Us-Da scr height  */
           D_ADSL_RCO1->imc_dim_y = D_ADSL_RSE1->imc_prot_1;  /* dimension y pixels */
//         D_ADSL_RCL1->imc_cmp_dim_y = D_ADSL_RSE1->imc_prot_1;  /* dimension y pixels */
           if (D_ADSL_RSE1->imc_pos_inp_frame <= sizeof(ucrs_r02c02)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35101;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_constant;  /* compare with constant */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_c02;  /* b2 MC Us-Da const 02 */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* position                */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_kbl:        /* b2 MC Us-Da Keyboard La */
           D_ADSL_RCO1->imc_keyboard_layout = D_ADSL_RSE1->imc_prot_1;  /* Keyboard Layout */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35112;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_bun;  /* b2 MC Us-Da Build Numb */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_bun:        /* b2 MC Us-Da Build Numb  */
           D_ADSL_RCO1->imc_build_number = D_ADSL_RSE1->imc_prot_1;  /* dimension y pixels */
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->wcrc_computer_name;
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - sizeof(D_ADSL_RCO1->wcrc_computer_name);
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35126;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_con;  /* b2 MC Us-Da Computer Na */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_kbt:        /* b2 MC Us-Da Keyboard Ty */
           D_ADSL_RCO1->imc_keyboard_type = D_ADSL_RSE1->imc_prot_1;  /* Type of Keyboard / 102 */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35136;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_kbs;  /* b2 MC Us-Da Keyboard ST */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_kbs:        /* b2 MC Us-Da Keyboard ST */
           D_ADSL_RCO1->imc_keyboard_subtype = D_ADSL_RSE1->imc_prot_1;  /* Subtype of Keyboard */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35148;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_nfk;  /* b2 MC Us-Da No Func Key */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_nfk:        /* b2 MC Us-Da No Func Key */
           D_ADSL_RCO1->imc_no_func_keys = D_ADSL_RSE1->imc_prot_1;  /* Number of Function Keys */
#ifdef TRACEHL1
           printf( "08.08.04 target 01 reached\n" );
#endif
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - 64;
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35164;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_ime;  /* b2 MC Us-Da IME Keyb ma */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_cod:        /* b2 MC Us-Da Color Depth */
           D_ADSL_RCO1->imc_cl_coldep = D_ADSL_RSE1->imc_prot_1;  /* client capabilities colour depth */
// to be removed
//         D_ADSL_RCO1->imc_color_depth = D_ADSL_RSE1->imc_prot_1;  /* Bits Color Depth */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35193;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_sup_cod;  /* b2 MC Us-Da supported Color Depth */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_sup_cod:    /* b2 MC Us-Da supported Color Depth */
           D_ADSL_RCO1->usc_cl_supported_color_depth = D_ADSL_RSE1->imc_prot_1;  /* client capabilities */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35204;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_early_cf;  /* b2 MC Us-Da early capability flag */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_early_cf:   /* b2 MC Us-Da early capability flag */
           D_ADSL_RCO1->usc_cl_early_capability_flag = D_ADSL_RSE1->imc_prot_1;  /* client capabilities */
           /* ignore remaining part                                    */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_prot_4;
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_ignore;  /* ignore data */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_fietype;  /* b2 MC Field Type */
           goto ptose20;                    /* process next data       */
#ifdef B060907
         case ied_frcl_r02_mcud_vc1:        /* b2 MC Us-Da virtual ch  */
           if (D_ADSL_RSE1->imc_prot_1 != (D_ADSL_RSE1->imc_pos_inp_frame + 4)) {
             printf( "ied_frcl_r02_mcud_vc1 remaining length invalid\n" );
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35226;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_nvc;  /* b2 MC Us-Da no virt ch */
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
//         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
#endif
         case ied_frcl_r02_mcud_nvc:        /* b2 MC Us-Da no virt ch  */
           D_ADSL_RCO1->imc_no_virt_ch = D_ADSL_RSE1->imc_prot_1;  /* number of virtual channels */
           D_ADSL_RCO1->usc_userid_cl2se = D_ADSL_RCO1->imc_no_virt_ch + 3; /* SM/JB, Malta 13.07.11: User channel is 1001 + userID. Because of that the user-ID has to be minimum 3 + number of virtual channels. */
           if (D_ADSL_RCO1->imc_no_virt_ch == 0) {
             if (D_ADSL_RSE1->imc_pos_inp_frame > 0) {  /* more data to follow */
               D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
               if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35274;    /* source line no for errors */
         goto ptose92;
               }
               D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RSE1->imc_prot_1 = 0;  /* clear value            */
               D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
               D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_fietype;  /* b2 MC Field Type */
               goto ptose20;                /* process next data       */
             }
             goto ptose_send_start;         /* send start to server    */
           }
           if (D_ADSL_RSE1->imc_pos_inp_frame
                 < (D_ADSL_RCO1->imc_no_virt_ch * DEF_LEN_VIRTCH_STA)) {
             m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d ied_frcl_r02_mcud_nvc %d channels - data in record remaining %d.",
                           __LINE__, 35316,  /* line number for errors */
                           D_ADSL_RCO1->imc_no_virt_ch,
                           D_ADSL_RSE1->imc_pos_inp_frame );
         iml_line_no = __LINE__;
         iml_source_no = 35319;    /* source line no for errors */
         goto ptose92;
           }
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->adsrc_vc_1) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->imc_no_virt_ch * sizeof(struct dsd_rdp_vc_1) );
           memset( D_ADSL_RCO1->adsrc_vc_1, 0, D_ADSL_RCO1->imc_no_virt_ch * sizeof(struct dsd_rdp_vc_1) );
           D_ADSL_RSE1->imc_prot_4 = 0;     /* start with first channel */
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->adsrc_vc_1->byrc_name;
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - sizeof(D_ADSL_RCO1->adsrc_vc_1->byrc_name);
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_vcn;  /* b2 MC Us-Da virt ch name */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           goto ptose20;                    /* process next data       */
         case ied_frcl_r02_mcud_vcf:        /* b2 MC Us-Da virt ch fla */
           D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4++ ].imc_flags
             = D_ADSL_RSE1->imc_prot_1;     /* set flags               */
           /* check if was last channel                                */
           if (D_ADSL_RSE1->imc_prot_4 == D_ADSL_RCO1->imc_no_virt_ch) {
             if (D_ADSL_RSE1->imc_pos_inp_frame == 0) {  /* end of frame */
             goto ptose_send_start;         /* send start to server    */
           }
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
             if (D_ADSL_RSE1->imc_prot_2 < 0) {
               iml_line_no = __LINE__;
               iml_source_no = 35560;    /* source line no for errors */
               goto ptose92;
             }
             D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
             D_ADSL_RSE1->imc_prot_1 = 0;   /* clear value             */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
             D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_fietype;  /* b2 MC Field Type */
             goto ptose20;                  /* process next data       */
           }
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->adsrc_vc_1[ D_ADSL_RSE1->imc_prot_4 ].byrc_name;
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
                                      - sizeof(D_ADSL_RCO1->adsrc_vc_1->byrc_name);
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_r02_mcud_vcn;  /* b2 MC Us-Da virt ch name */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           goto ptose20;                    /* process next data       */
         case ied_frcl_client_rand:         /* receive client random   */
           if (D_ADSL_RSE1->imc_prot_1 > (D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RSE1->imc_prot_4)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35457;    /* source line no for errors */
         goto ptose92;
           }
           if (D_ADSL_RSE1->imc_prot_1 > sizeof(D_ADSL_RSE1->chrc_prot_1)) {
//           goto ptose92;                  /* protocol error          */
         iml_line_no = __LINE__;
         iml_source_no = 35464;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->achc_prot_1 = D_ADSL_RSE1->chrc_prot_1;
           D_ADSL_RSE1->imc_prot_2
             = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RSE1->imc_prot_1;  /* number of bytes */
#ifdef XYZ1
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
             goto ptose92;                  /* protocol error          */
           }
#endif
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear position          */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_invers;  /* copy data invers */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_options:     /* Options                 */
           D_ADSL_RCO1->umc_loinf_options = D_ADSL_RSE1->imc_prot_1;  /* Logon Info Options */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 35482;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_domna_len;  /* Domain Name Length */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_domna_len:   /* Domain Name Length      */
           D_ADSL_RCO1->usc_loinf_domna_len = D_ADSL_RSE1->imc_prot_1;  /* Domain Name Length */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 35492;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_userna_len;  /* User Name Length */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_userna_len:  /* User Name Length       */
           D_ADSL_RCO1->usc_loinf_userna_len = D_ADSL_RSE1->imc_prot_1;  /* User Name Length */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 35502;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_pwd_len;  /* Password Length */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_pwd_len:     /* Password Length         */
           D_ADSL_RCO1->usc_loinf_pwd_len = D_ADSL_RSE1->imc_prot_1;  /* Password Length */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 35512;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_altsh_len;  /* Alt Shell Length */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_altsh_len:   /* Alt Shell Length        */
           D_ADSL_RCO1->usc_loinf_altsh_len = D_ADSL_RSE1->imc_prot_1;  /* Alt Shell Length */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 35522;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_wodir_len;  /* Working Directory Length */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_wodir_len:   /* Working Directory Length */
           D_ADSL_RCO1->usc_loinf_wodir_len = D_ADSL_RSE1->imc_prot_1;  /* Working Directory Length */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_domna_val;  /* Domain Name String */
           if (D_ADSL_RCO1->usc_loinf_domna_len) {  /* Domain Name Length */
             D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RCO1->usc_loinf_domna_len;  /* number of bytes */
             if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame    */
         iml_line_no = __LINE__;
         iml_source_no = 35534;    /* source line no for errors */
         goto ptose92;
             }
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->awcc_loinf_domna_a) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RCO1->usc_loinf_domna_len );
             D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->awcc_loinf_domna_a;  /* Domain Name */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data normal */
             goto ptose20;                  /* process next data       */
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 35543;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_zero_cmp;  /* compare zeroes */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_no_a_par:    /* number of additional parameters */
           D_ADSL_RCO1->usc_loinf_no_a_par = D_ADSL_RSE1->imc_prot_1;  /* number of additional parameters */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 35551;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_ineta;  /* INETA */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_ineta:       /* INETA                   */
           if (D_ADSL_RSE1->imc_prot_1 == 0) {  /* length zero         */
         iml_line_no = __LINE__;
         iml_source_no = 35559;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RCO1->usc_loinf_ineta_len = D_ADSL_RSE1->imc_prot_1;  /* INETA Length */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RSE1->imc_prot_1;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 35564;    /* source line no for errors */
         goto ptose92;
           }
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->awcc_loinf_ineta_a) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RSE1->imc_prot_1 );
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->awcc_loinf_ineta_a;  /* INETA */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data normal */
           goto ptose20;                    /* process next data       */
         case ied_frcl_c_loinf_path:        /* Client Path             */
           if (D_ADSL_RSE1->imc_prot_1 == 0) {  /* length zero         */
             if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) {  /* nothing left */
         iml_line_no = __LINE__;
         iml_source_no = 35576;    /* source line no for errors */
         goto ptose92;
             }
             D_ADSL_RCO1->usc_loinf_extra_len = D_ADSL_RSE1->imc_pos_inp_frame;  /* Extra Parameters Length */
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->awcc_loinf_extra_a) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RSE1->imc_pos_inp_frame );
             D_ADSL_RSE1->imc_prot_2 = 0;   /* copy till end of frame  */
             D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->awcc_loinf_extra_a;  /* Extra Parameters */
             D_ADSL_RSE1->iec_frcl_bl = ied_frcl_c_loinf_extra;  /* Extra Parameters */
             D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data normal */
             goto ptose20;                  /* process next data       */
           }
           D_ADSL_RCO1->usc_loinf_path_len = D_ADSL_RSE1->imc_prot_1;  /* Client Path Length */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RSE1->imc_prot_1;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {  /* longer as frame      */
         iml_line_no = __LINE__;
         iml_source_no = 35592;    /* source line no for errors */
         goto ptose92;
           }
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->awcc_loinf_path_a) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, D_ADSL_RSE1->imc_prot_1 );
           D_ADSL_RSE1->achc_prot_1 = (char *) D_ADSL_RCO1->awcc_loinf_path_a;  /* Client Path */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data normal */
           goto ptose20;                    /* process next data       */
         case ied_frcl_rdp4_vch_ulen:       /* virtual channel uncompressed data length */
           D_ADSL_RSE1->umc_vch_ulen = D_ADSL_RSE1->imc_prot_1;  /* virtual channel length uncompressed */
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - sizeof(D_ADSL_RSE1->chrc_vch_segfl);
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35736;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->achc_prot_1 = D_ADSL_RSE1->chrc_vch_segfl;
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           goto ptose20;                    /* process next data       */
         case ied_frcl_lic_01:              /* licencing block to check */
           if ((D_ADSL_RSE1->imc_prot_1 & 0x00007E00) != 0x0200) {
         iml_line_no = __LINE__;
         iml_source_no = 35748;    /* source line no for errors */
         goto ptose92;
           }
           if ((unsigned)(D_ADSL_RSE1->imc_prot_1) >> 16 != D_ADSL_RSE1->imc_pos_inp_frame + 4) {
         iml_line_no = __LINE__;
         iml_source_no = 35751;    /* source line no for errors */
         goto ptose92;
           }
           switch (D_ADSL_RSE1->imc_prot_1 & 0XFF) {
             case 0X12:                     /* LICENSE_INFO            */
             case 0X13:                     /* NEW_LICENSE_REQUEST     */
               if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsc_lic_neg == NULL) {
         iml_line_no = __LINE__;
         iml_source_no = 35757;    /* source line no for errors */
         goto ptose92;
               }
               D_ADSL_RCO1->adsc_lic_neg = ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsc_lic_neg;  /* using same data on both sides */
               D_ADSL_RCO1->adsc_lic_neg->chc_lic_clcertway = (unsigned char) D_ADSL_RSE1->imc_prot_1;  /* type of first client lic. packet after logon info */
               D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers = (unsigned char) (D_ADSL_RSE1->imc_prot_1 >> 8);  /* licensing version and some poorly documented "ExtendedError supported" flag */
               D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
               if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35777;    /* source line no for errors */
         goto ptose92;
               }
               D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
               D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
               D_ADSL_RSE1->iec_frcl_bl = ied_frcl_lic_pkea;  /* parse PreferredKeyExchangeAlg next */
               D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
               goto ptose20;                    /* process next data       */
             case 0X15:                     /* PLATFORM_CHALLENGE_RESPONSE */
               D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_send_from_client;  /* send data to server */
               goto ptose40;           /* send to server          */
             case 0XFF:                     /* ERROR_ALERT             */
               /* licensing data no more needed, free the memory       */
               if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsc_lic_neg) {
                 if (D_ADSL_RCO1->adsc_lic_neg) {
                   if (D_ADSL_RCO1->adsc_lic_neg != ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsc_lic_neg)
                     goto ptose96;     /* program illogic         */
                 } else {
                   D_ADSL_RCO1->adsc_lic_neg = ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsc_lic_neg;
                 }
                 ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.adsc_lic_neg = NULL;
               }
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
         iml_line_no = __LINE__;
         iml_source_no = 35814;    /* source line no for errors */
         goto ptose92;
           }
         iml_line_no = __LINE__;
         iml_source_no = 35816;    /* source line no for errors */
         goto ptose92;
//       default:
//         goto ptose96;                    /* program illogic         */
         case ied_frcl_lic_pkea:            /* PreferredKeyExchangeAlg */
           D_ADSL_RCO1->adsc_lic_neg->imc_lic_pkea = D_ADSL_RSE1->imc_prot_1;
           if (D_ADSL_RCO1->adsc_lic_neg->imc_lic_pkea != 0x1) { /* only alowed value  */
         iml_line_no = __LINE__;
         iml_source_no = 35823;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35827;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_lic_platform;  /* parse PlatformId next */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e;  /* int little endian */
           goto ptose20;                    /* process next data       */
         case ied_frcl_lic_platform:        /* PlatformId              */
           D_ADSL_RCO1->adsc_lic_neg->imc_lic_platform = D_ADSL_RSE1->imc_prot_1;
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 4;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35838;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame
             - sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand);
           D_ADSL_RSE1->achc_prot_1 = D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand;
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_lic_clrand;  /* New Licence Request/ Client License Info */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal; /* copy data normal */
           goto ptose20;                    /* process the data        */
         case ied_frcl_bb_type:
           D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_type = D_ADSL_RSE1->imc_prot_1;
           /* the ms-spec says 0X0002                                  */
           /* the clients say  0X0000                                  */
           if (D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_type & (-1 - 2)) {           /* other bits set          */
         iml_line_no = __LINE__;
         iml_source_no = 35851;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - 2;  /* number of bytes */
           if (D_ADSL_RSE1->imc_prot_2 < 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35855;    /* source line no for errors */
         goto ptose92;
           }
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;  /* here first byte */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear value             */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_bb_len;    /* parse BinaryBlob len next */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_int_lit_e; /* int little endian */
           goto ptose20;                    /* process the data        */
         case ied_frcl_bb_len:
           D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_len = D_ADSL_RSE1->imc_prot_1;
           if (D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_len
                 > (D_ADSL_RSE1->imc_pos_inp_frame - D_ADSL_RSE1->imc_prot_4)) {
         iml_line_no = __LINE__;
         iml_source_no = 35866;    /* source line no for errors */
         goto ptose92;
           }
           iml2 = D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_len;                     /* get length              */
           if (iml2 < D_LEN_CERT_PUBLIC_KEY) iml2 = D_LEN_CERT_PUBLIC_KEY;
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   *((void **) &D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data) = m_aux_stor_alloc( &ADSL_RDPA_F->dsc_stor_sdh_1, iml2 );
           D_ADSL_RSE1->achc_prot_1 = D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data;
           D_ADSL_RSE1->imc_prot_3 = D_ADSL_RSE1->imc_pos_inp_frame;
           D_ADSL_RSE1->imc_prot_2 = D_ADSL_RSE1->imc_pos_inp_frame - iml2;  /* number of bytes */
           D_ADSL_RSE1->imc_prot_1 = 0;     /* clear position          */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_invers; /* copy data invers */
           D_ADSL_RSE1->iec_frcl_bl = ied_frcl_lic_clrand;  /* New Licence Request/ Client License Info */
           goto ptose20;                    /* process next data       */
       }
           goto ptose96;                    /* program illogic         */
     case ied_fcfp_int_big_e:               /* int big endian          */
       while (TRUE) {
         D_ADSL_RSE1->imc_prot_1 <<= 8;
         D_ADSL_RSE1->imc_prot_1
           |= (unsigned char) *adsl_gai1_inp_1->achc_ginp_cur++;
         D_ADSL_RSE1->imc_pos_inp_frame--;
         if (D_ADSL_RSE1->imc_pos_inp_frame == D_ADSL_RSE1->imc_prot_2) break;
         if (adsl_gai1_inp_1->achc_ginp_cur
               >= adsl_gai1_inp_1->achc_ginp_end) {
           goto ptose20;                    /* needs more data         */
         }
       }
#ifdef TRACEHL1
       printf( "ied_fcfp_int_big_e found int=%d D_ADSL_RSE1->iec_frcl_bl=%d\n",
               D_ADSL_RSE1->imc_prot_1,
               D_ADSL_RSE1->iec_frcl_bl );
#endif
       goto ptose96;                        /* program illogic         */
     case ied_fcfp_send_from_client:        /* send data to server     */
       goto ptose40;                        /* process the data        */
     case ied_fcfp_end_com:                 /* end of communication    */
       if ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur != (unsigned char) 0X80) {
         iml_line_no = __LINE__;
         iml_source_no = 35906;    /* source line no for errors */
         goto ptose92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RSE1->imc_pos_inp_frame--;    /* length constant         */
       if (D_ADSL_RSE1->imc_pos_inp_frame != 0) {
         iml_line_no = __LINE__;
         iml_source_no = 35911;    /* source line no for errors */
         goto ptose92;
       }
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_no_session;  /* no more session */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_no_session:              /* no more session         */
       if (   (ADSL_RDPA_F->boc_scp_hrdpe1)  /* protocol HOB MS RDP Ext 1 */
           && ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur == 0X03)) {
         adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input         */
         D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_hext_b2;  /* HOB-RDP-EXT1 byte 2 */
         goto ptose20;                        /* process next data       */
       }
         iml_line_no = __LINE__;
         iml_source_no = 35952;    /* source line no for errors */
         goto ptose92;
     case ied_fcfp_hext_b2:                 /* HOB-RDP-EXT1 byte 2     */
       if ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur != 0XFF) {
         iml_line_no = __LINE__;
         iml_source_no = 35956;    /* source line no for errors */
         goto ptose92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_hext_ctrl;  /* HOB-RDP-EXT1 control character */
       D_ADSL_RSE1->iec_frcl_bl = ied_frcl_hext_send;  /* HOB-RDP-EXT1 send to server / SDH */
       goto ptose20;                        /* process next data       */
     case ied_fcfp_hext_ctrl:               /* HOB-RDP-EXT1 control character */
       D_ADSL_RSE1->chrc_prot_1[ 0 ] = (unsigned char) 0X03;  /* first byte to send */
       D_ADSL_RSE1->chrc_prot_1[ 1 ] = (unsigned char) 0XFF;  /* second byte to send */
       D_ADSL_RSE1->chrc_prot_1[ 2 ] = *adsl_gai1_inp_1->achc_ginp_cur;  /* save the control character */
       switch (*adsl_gai1_inp_1->achc_ginp_cur) {  /* check control character */
         case 0X01:                         /* INETA IPV4              */
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RSE1->achc_prot_1 = D_ADSL_RSE1->chrc_prot_1 + 3;
           D_ADSL_RSE1->imc_pos_inp_frame = 4 + 2;
           D_ADSL_RSE1->imc_prot_2 = 0;     /* copy till end of packet */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           goto ptose20;                    /* process next data       */
         case 0X02:                         /* INETA IPV4              */
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RSE1->achc_prot_1 = D_ADSL_RSE1->chrc_prot_1 + 3;
           D_ADSL_RSE1->imc_pos_inp_frame = 16 + 2;
           D_ADSL_RSE1->imc_prot_2 = 0;     /* copy till end of packet */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data */
           goto ptose20;                    /* process next data       */
         case 0X03:                         /* connect command         */
           adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input       */
           D_ADSL_RSE1->imc_pos_inp_frame = 0;  /* clear number        */
           D_ADSL_RSE1->imc_prot_2 = 4;     /* maximum number of characters */
           D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_hext_l_nhasn;  /* HOB-RDP-EXT1 length NHASN */
           goto ptose20;                    /* process next data       */
       }
         iml_line_no = __LINE__;
         iml_source_no = 35988;    /* source line no for errors */
         goto ptose92;
     case ied_fcfp_hext_l_nhasn:            /* HOB-RDP-EXT1 length NHASN */
       D_ADSL_RSE1->imc_pos_inp_frame <<= 7;       /* shift old value         */
       D_ADSL_RSE1->imc_pos_inp_frame += *adsl_gai1_inp_1->achc_ginp_cur & 0X7F;
       if ((unsigned char) *adsl_gai1_inp_1->achc_ginp_cur & 0X80) {  /* more bit set */
         D_ADSL_RSE1->imc_prot_2--;         /* maximum number of characters */
         if (D_ADSL_RSE1->imc_prot_2 <= 0) {  /* too many digits       */
         iml_line_no = __LINE__;
         iml_source_no = 35995;    /* source line no for errors */
         goto ptose92;
         }
         adsl_gai1_inp_1->achc_ginp_cur++;  /* next byte input         */
         goto ptose20;                      /* process next data       */
       }
       if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) {  /* length too short */
         iml_line_no = __LINE__;
         iml_source_no = 36001;    /* source line no for errors */
         goto ptose92;
       }
       adsl_gai1_inp_1->achc_ginp_cur++;    /* next byte input         */
       achl1 = D_ADSL_RSE1->chrc_prot_1 + 3;  /* output here           */
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* get number output    */
       do {                                 /* loop to calculate space needed for NHASN */
         achl1++;                           /* needs on character      */
         iml1 >>= 7;                        /* remove bits             */
       } while (iml1 > 0);
       iml1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* get number output    */
       iml2 = 0;                            /* clear mor bit           */
       D_ADSL_RSE1->achc_prot_1 = achl1;    /* put following characters here */
       if ((achl1 + iml1) > ((char *) D_ADSL_RSE1->chrc_prot_1 + sizeof(D_ADSL_RSE1->chrc_prot_1))) {
         iml_line_no = __LINE__;
         iml_source_no = 36014;    /* source line no for errors */
         goto ptose92;
       }
       do {                                 /* loop to calculate space needed for NHASN */
         *(--achl1) = (unsigned char) ((iml1 & 0X7F) | iml2);  /* output one digit */
         iml1 >>= 7;                        /* remove bits             */
         iml2 = 0X80;                       /* set more bit            */
       } while (iml1 > 0);
       D_ADSL_RSE1->imc_prot_2 = 0;         /* copy till end of packet */
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_copy_normal;  /* copy data  */
       goto ptose20;                        /* process next data       */
//   default:                               /* other value set         */
//     goto ptose96;                        /* program illogic         */
   }
   goto ptose96;                            /* program illogic         */

// ptose04:                                 /* to server - from client */
// adsl_gai1_inp_1->achc_ginp_cur++;
// goto ptose20;

   ptose_send_start:                        /* send start to server    */
   D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_05;  /* receive block 5     */
   D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_invalid;  /* invalid data received */
   /* start sending to server                                          */
   /* copy all fields to the server                                    */
   memcpy( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1,
           D_ADSL_RCO1,
           sizeof(struct dsd_rdp_co) );
   if (ADSL_RDPA_F->boc_scp_hrdpe1 == FALSE) {  /* not protocol HOB MS RDP Ext 1 */
   /* check if in correct position                                     */
   if (   (ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl != ied_fsfp_invalid)
       || (ADSL_RDPA_F->dsc_rdp_cl_1.iec_frse_bl != ied_frse_start)) {
         iml_line_no = __LINE__;
         iml_source_no = 36063;    /* source line no for errors */
         goto ptose92;
   }
   ADSL_RDPA_F->dsc_rdp_cl_1.iec_fsfp_bl = ied_fsfp_rec_type;  /* receive record type */
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) adsp_hl_clib_1->achc_work_area)
   memset( ADSL_GAI1_OUT_G, 0, sizeof(struct dsd_gather_i_1) );
   ADSL_GAI1_OUT_G->achc_ginp_cur = (char *) ucrs_sese_01;
   ADSL_GAI1_OUT_G->achc_ginp_end = (char *) ucrs_sese_01 + sizeof(ucrs_sese_01);
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
   goto ptose20;                            /* process next data       */

   ptose40:                                 /* send data to server     */
/* 26.09.06 KB - check if output work area too small                   */
#define IML_SEND_LEN_1 (13 + sizeof(ucrs_x224_p01) + sizeof(struct dsd_gather_i_1))
   iml1 = D_ADSL_RSE1->imc_pos_inp_frame;   /* length data encrypted   */
   iml4 = D_SIZE_HASH;                      /* use encryption          */
   bol1 = TRUE;                             /* get input data          */
#define D_ADSL_CL_RCO1 (&ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1)
   switch (D_ADSL_RSE1->iec_frcl_bl) {
     case ied_frcl_c_loinf_extra:           /* Extra Parameters - Logon Info 1 */
       bol1 = FALSE;                        /* do not get input data   */
       iml1 = sizeof(ucrs_logon_info_c1)
            + sizeof(D_ADSL_CL_RCO1->umc_loinf_options)  /* Logon Info Options */
            + 5 * sizeof(unsigned short int)
            + D_ADSL_CL_RCO1->usc_loinf_domna_len  /* Domain Name Length */
            + sizeof(unsigned short int)
            + D_ADSL_CL_RCO1->usc_loinf_userna_len  /* User Name Length */
            + sizeof(unsigned short int)
            + D_ADSL_CL_RCO1->usc_loinf_pwd_len  /* Password Length     */
            + sizeof(unsigned short int)
            + D_ADSL_CL_RCO1->usc_loinf_altsh_len  /* Alt Shell Length  */
            + sizeof(unsigned short int)
            + D_ADSL_CL_RCO1->usc_loinf_wodir_len  /* Working Directory Length */
            + sizeof(unsigned short int)
            + sizeof(unsigned short int)
            + sizeof(unsigned short int)
            + D_ADSL_CL_RCO1->usc_loinf_ineta_len  /* INETA Length      */
            + sizeof(unsigned short int)
            + D_ADSL_CL_RCO1->usc_loinf_path_len  /* Client Path Length */
            + D_ADSL_CL_RCO1->usc_loinf_extra_len;  /* Extra Parameters Length */
       break;
     case ied_frcl_lic_01:                  /* licencing block checked  */
       iml1 += 4;                           /* Licencing Preamble       */
       if (D_ADSL_RSE1->chc_prot_rt02 & 0X08) break;  /* use encryption */
       iml4 = 0;                            /* do not use encryption    */
       break;
     case ied_frcl_lic_clrand:              /* New Licence Request/ Client License Info */
     {
// to-do 09.08.09 KB - better do encryption after check if enough space in output area
// tell Mr. Sommer
       // JB 15.02.11 and 06.06.11: bol1 has to be TRUE, to just copy the rest of the
       // so far non-parsed data, which is the  ClientUserName und ClientMachineName
       // (vgl. [MS-RDPELE] 2.2.2.2 Client New License Request (CLIENT_NEW_LICENSE_REQUEST)),
       // or the license info, Encrypted HWID and MACData in case of a
       // Client License Info. Otherwise non-initialized memory is send.
       bol1 = TRUE;                        /* do not get input data   */
//     printf("---> Lizenzpaket <---\n"); fflush(stdout);
#define IML_PADDED_LCPMSIZE (ADSL_RDPA_F->dsc_rdp_cl_1.imc_len_cert_key + 8)
       /* first encrypt the client random with the server-side keys     */
       iml1 = D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_len;
       iml3 = sizeof(chrl_work_1);
#ifdef XH_INTERFACE
     	ds__hmem dsl_new_struct;
	    memset(&dsl_new_struct, 0, sizeof(ds__hmem));
		dsl_new_struct.in__aux_up_version = 1;
		dsl_new_struct.am__aux2 = adsp_hl_clib_1->amc_aux;
		dsl_new_struct.in__flags = 0;
		dsl_new_struct.vp__context = adsp_hl_clib_1->vpc_userfld;
#endif
#ifdef __INSURE__
       // rsa_crypt_raw uses lnum, which causes an Insure-error.
       _Insure_checking_enable(0);
#endif
       iml2 = m_rsa_crypt_raw_big( 
#ifdef XH_INTERFACE
                                   &dsl_new_struct,
#endif				   
		                           (unsigned char *) D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.achc_bb_data,
                                   iml1,
                                   (unsigned char *) D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_exp,
                                   D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_exp_len,
                                   (unsigned char *) D_ADSL_RCO1->adsc_lic_neg->chrc_lic_cert_key,
                                   D_ADSL_RCO1->adsc_lic_neg->imc_lic_cert_key_len,
                                   (unsigned char *) chrl_work_1,
                                   &iml3 );
#ifdef __INSURE__
       _Insure_checking_enable(1);
#endif
#ifdef XH_INTERFACE
        HMemMgrFree(&dsl_new_struct);
#endif
       if (iml2) goto ptose92;              /* protocol error          */
       if (iml3 == 0) goto ptose92;         /* protocol error          */
#ifdef TRACEHL1_LIC
       printf( "l%05d s%05d re-encrypted licensing premaster.\n",
               __LINE__, 36173 );
       m_console_out( chrl_work_1, iml3 );
#endif
       iml1 = 4                             /* Licencing Preamble      */
            + 4                             /* PreferredKeyExchangeAlg */
            + 4                             /* PlatformId              */
            + 32                            /* ClientRandom            */
            + 2                             /* Binary BLOB, type       */
            + 2                             /* Binary BLOB, length     */
            + IML_PADDED_LCPMSIZE  /* length of the re-encrypted licensing premaster with padding */
            + D_ADSL_RSE1->imc_pos_inp_frame;  /* rest of the data     */
       if (D_ADSL_RSE1->chc_prot_rt02 & 0X08) break;  /* use encryption */
       iml4 = 0;                            /* do not use encryption    */
       break;
   }
   }
   if ((IML_SEND_LEN_1 + iml4 + iml1) > (ADSL_OA1->achc_upper - ADSL_OA1->achc_lower)) {
     if ((IML_SEND_LEN_1 + iml4 + iml1) <= adsp_hl_clib_1->inc_len_work_area) {
       adsp_hl_clib_1->boc_callagain = TRUE;  /* call again this direction */
       goto p_ret_00;                       /* check how to return     */
     }
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d ptose40 encrypt length %d too high",
                   __LINE__, 36210,  /* line number for errors */
                   iml1 + iml4 );
     goto ptose96;                          /* program illogic         */
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     goto ptose96;                          /* program illogic         */
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
   *ADSL_OA1->achc_lower = DEF_CONST_RDP_03;
   *(ADSL_OA1->achc_lower + 1) = 0;            /* second byte zero        */
   memcpy( ADSL_OA1->achc_lower + 4,
           ucrs_x224_p01,
           sizeof(ucrs_x224_p01) );
   *(ADSL_OA1->achc_lower + 4 + sizeof(ucrs_x224_p01)) = 0X64;  /* send data request */
   ADSL_OA1->achc_lower += 4 + sizeof(ucrs_x224_p01) + 1;
   m_put_be2( ADSL_OA1->achc_lower, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
   ADSL_OA1->achc_lower += 2;
   m_put_be2( ADSL_OA1->achc_lower, D_ADSL_RSE1->imc_prot_chno );
   ADSL_OA1->achc_lower += 2;
   *ADSL_OA1->achc_lower++ = 0X70;             /* priority / segmentation */
   if (iml1 <= (127 - 4 - iml4)) {          /* length in one byte      */
     *ADSL_OA1->achc_lower++ = (unsigned char) (iml1 + 4 + iml4);
   } else {
     m_put_be2( ADSL_OA1->achc_lower, iml1 + 4 + iml4 );
     *ADSL_OA1->achc_lower |= 0X80;            /* length in two bytes     */
     ADSL_OA1->achc_lower += 2;
   }
   *ADSL_OA1->achc_lower++ = (unsigned char) (D_ADSL_RSE1->chc_prot_rt02 | iml4);  /* data is / is not encrypted */
   *ADSL_OA1->achc_lower++ = D_ADSL_RSE1->chc_prot_rt03;
   /* two bytes padding zero                                           */
   *ADSL_OA1->achc_lower++ = 0;
   *ADSL_OA1->achc_lower++ = 0;
   /* leave eight bytes for hash if needed                             */
   achl1 = ADSL_OA1->achc_lower + iml4;        /* start output here       */
   switch (D_ADSL_RSE1->iec_frcl_bl) {
     case ied_frcl_c_loinf_extra:           /* Extra Parameters - Logon Info 1 */
       memcpy( achl1,
               ucrs_logon_info_c1,
               sizeof(ucrs_logon_info_c1) );
       achl1 += sizeof(ucrs_logon_info_c1);
       m_put_le4( achl1, D_ADSL_CL_RCO1->umc_loinf_options );
       achl1 += sizeof(D_ADSL_CL_RCO1->umc_loinf_options);
       m_put_le2( achl1, D_ADSL_CL_RCO1->usc_loinf_domna_len );  /* Domain Name Length */
       achl1 += sizeof(unsigned short int);
       m_put_le2( achl1, D_ADSL_CL_RCO1->usc_loinf_userna_len );  /* User Name Length */
       achl1 += sizeof(unsigned short int);
       m_put_le2( achl1, D_ADSL_CL_RCO1->usc_loinf_pwd_len );  /* Password Length */
       achl1 += sizeof(unsigned short int);
       m_put_le2( achl1, D_ADSL_CL_RCO1->usc_loinf_altsh_len );  /* Alt Shell Length */
       achl1 += sizeof(unsigned short int);
       m_put_le2( achl1, D_ADSL_CL_RCO1->usc_loinf_wodir_len );  /* Working Directory Length */
       achl1 += sizeof(unsigned short int);
       iml2 = 0;                            /* bytes to clear          */
       if (D_ADSL_CL_RCO1->usc_loinf_domna_len) {  /* Domain Name Length */
         memcpy( achl1,
                 D_ADSL_CL_RCO1->awcc_loinf_domna_a,
                 D_ADSL_CL_RCO1->usc_loinf_domna_len );
         achl1 += D_ADSL_CL_RCO1->usc_loinf_domna_len;
       }
       iml2 = 2;                            /* bytes to clear          */
       if (D_ADSL_CL_RCO1->usc_loinf_userna_len) {  /* User Name Length */
         memset( achl1, 0, iml2 );          /* clear content           */
         achl1 += iml2;                     /* increment output pointer */
         memcpy( achl1,
                 D_ADSL_CL_RCO1->awcc_loinf_userna_a,
                 D_ADSL_CL_RCO1->usc_loinf_userna_len );
         achl1 += D_ADSL_CL_RCO1->usc_loinf_userna_len;
         iml2 = 0;                          /* bytes to clear          */
       }
       iml2 += 2;                           /* bytes to clear          */
       if (D_ADSL_CL_RCO1->usc_loinf_pwd_len) {  /* Password Length    */
         memset( achl1, 0, iml2 );          /* clear content           */
         achl1 += iml2;                     /* increment output pointer */
         memcpy( achl1,
                 D_ADSL_CL_RCO1->awcc_loinf_pwd_a,
                 D_ADSL_CL_RCO1->usc_loinf_pwd_len );
         achl1 += D_ADSL_CL_RCO1->usc_loinf_pwd_len;
         iml2 = 0;                          /* bytes to clear          */
       }
       iml2 += 2;                           /* bytes to clear          */
       if (D_ADSL_CL_RCO1->usc_loinf_altsh_len) {  /* Alt Shell Length */
         memset( achl1, 0, iml2 );          /* clear content           */
         achl1 += iml2;                     /* increment output pointer */
         memcpy( achl1,
                 D_ADSL_CL_RCO1->awcc_loinf_altsh_a,
                 D_ADSL_CL_RCO1->usc_loinf_altsh_len );
         achl1 += D_ADSL_CL_RCO1->usc_loinf_altsh_len;
         iml2 = 0;                          /* bytes to clear          */
       }
       iml2 += 2;                           /* bytes to clear          */
       if (D_ADSL_CL_RCO1->usc_loinf_wodir_len) {  /* Working Directory Length */
         memset( achl1, 0, iml2 );          /* clear content           */
         achl1 += iml2;                     /* increment output pointer */
         memcpy( achl1,
                 D_ADSL_CL_RCO1->awcc_loinf_wodir_a,
                 D_ADSL_CL_RCO1->usc_loinf_wodir_len );
         achl1 += D_ADSL_CL_RCO1->usc_loinf_wodir_len;
         iml2 = 0;                          /* bytes to clear          */
       }
       iml2 += 2;                           /* bytes to clear          */
       memset( achl1, 0, iml2 );            /* clear content           */
       achl1 += iml2;                       /* increment output pointer */
       m_put_le2( achl1, D_ADSL_CL_RCO1->usc_loinf_no_a_par );  /* number of additional parameters */
       achl1 += sizeof(unsigned short int);
       m_put_le2( achl1, D_ADSL_CL_RCO1->usc_loinf_ineta_len );  /* INETA Length */
       achl1 += sizeof(unsigned short int);
       memcpy( achl1,
               D_ADSL_CL_RCO1->awcc_loinf_ineta_a,
               D_ADSL_CL_RCO1->usc_loinf_ineta_len );
       achl1 += D_ADSL_CL_RCO1->usc_loinf_ineta_len;
       m_put_le2( achl1, D_ADSL_CL_RCO1->usc_loinf_path_len );  /* Client Path Length */
       achl1 += sizeof(unsigned short int);
       memcpy( achl1,
               D_ADSL_CL_RCO1->awcc_loinf_path_a,
               D_ADSL_CL_RCO1->usc_loinf_path_len );
       achl1 += D_ADSL_CL_RCO1->usc_loinf_path_len;
       memcpy( achl1,
               D_ADSL_CL_RCO1->awcc_loinf_extra_a,
               D_ADSL_CL_RCO1->usc_loinf_extra_len );
       achl1 += D_ADSL_CL_RCO1->usc_loinf_extra_len;
       break;
     case ied_frcl_lic_clrand:              /* New Licence Request / Client License Info */
       *achl1++ = D_ADSL_RCO1->adsc_lic_neg->chc_lic_clcertway; /* type, 0x12 or 0x13 */
       *achl1++ = D_ADSL_RCO1->adsc_lic_neg->chc_lic_vers;      /* version 2 or 3, and maybe flag 0x80 */
       m_put_le2( achl1, iml1 );
       achl1 += 2;
       m_put_le4( achl1, D_ADSL_RCO1->adsc_lic_neg->imc_lic_pkea );
       achl1 += 4;
       m_put_le4( achl1, D_ADSL_RCO1->adsc_lic_neg->imc_lic_platform );
       achl1 += 4;
       memcpy( achl1, D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand, sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand) );
       achl1 += sizeof(D_ADSL_RCO1->adsc_lic_neg->chrc_lic_clrand);
       m_put_le2( achl1, D_ADSL_RCO1->adsc_lic_neg->dsc_lic_pms.usc_bb_type);
       achl1 += 2;
       m_put_le2( achl1, IML_PADDED_LCPMSIZE );
       achl1 += 2;
       achl2 = achl1 + IML_PADDED_LCPMSIZE;
       while (iml3) {   /* copy re-encrypted lic. premaster BE -> LE */
         *achl1++ = chrl_work_1[--iml3];
       }
       memset( achl1, 0, achl2 - achl1 );
       achl1 = achl2;
       break;
#undef IML_PADDED_LCPMSIZE
     case ied_frcl_lic_01:                  /* licencing block checked */
       m_put_le4( achl1, D_ADSL_RSE1->imc_prot_1 );  /* lic. preamble from ied_fcfp_copy_normal */
       achl1 += 4;
       break;
   }
   if (iml4) {                              /* encryption is used      */
     if ((ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent & (4096 - 1)) == 0) {
       if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent) {
         m_update_keys( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se, NULL );
       }
     }
     /* generate random                                                */
#define ACHL_WORK_SHA1 ((int *) chrl_work_2)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
     memcpy( ACHL_WORK_SHA1,
             ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_sha1_state) );
     memcpy( ACHL_WORK_MD5,
             ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.imrc_md5_state) );
     m_put_le4( ACHL_WORK_UTIL_01, iml1 );
     SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     if (bol1 == FALSE) {                   /* do not get input data   */
       SHA1_Update( ACHL_WORK_SHA1,
                    ADSL_OA1->achc_lower + D_SIZE_HASH, 0, iml1 );
       RC4( ADSL_OA1->achc_lower + D_SIZE_HASH, 0, iml1, ADSL_OA1->achc_lower + D_SIZE_HASH, 0,
            ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
     } else {                               /* get input data          */
       iml2 = D_ADSL_RSE1->imc_pos_inp_frame;  /* length data encrypted */
       /* encrypt, what was already written */
       SHA1_Update( ACHL_WORK_SHA1,
                    ADSL_OA1->achc_lower + D_SIZE_HASH, 0, iml1 - iml2 );
       RC4( ADSL_OA1->achc_lower + D_SIZE_HASH, 0, iml1 - iml2, ADSL_OA1->achc_lower + D_SIZE_HASH, 0,
            ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
       /* endrypt rest of data. destination = outputarea */
       adsl_gai1_inp_w2 = adsl_gai1_inp_1;  /* get gather              */
       while (TRUE) {                       /* loop over all gather structures input */
         iml3 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
         if (iml3 > iml2) iml3 = iml2;      /* only data in this frame */
         SHA1_Update( ACHL_WORK_SHA1,
                      adsl_gai1_inp_w2->achc_ginp_cur, 0, iml3 );
         RC4( adsl_gai1_inp_w2->achc_ginp_cur, 0, iml3, achl1, 0,
              ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
         iml2 -= iml3;                      /* subtract data processed */
         if (iml2 <= 0) break;              /* all data encrypted      */
         achl1 += iml3;                     /* increment output pointer */
         adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
         if (adsl_gai1_inp_w2 == NULL) {    /* already end of chain    */
           goto ptose96;                    /* program illogic         */
         }
       }
     }
     if (D_ADSL_RSE1->chc_prot_rt03 & 0X08) {  /* flag for block count */
       m_put_le4( ACHL_WORK_UTIL_01, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     }
     SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
     MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
     MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
     memcpy( ADSL_OA1->achc_lower, ACHL_WORK_UTIL_01, D_SIZE_HASH );
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
     ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */
   } else if (bol1) {                       /* needs copying of data   */
     iml2 = D_ADSL_RSE1->imc_pos_inp_frame;  /* length data to copy    */
     adsl_gai1_inp_w2 = adsl_gai1_inp_1;    /* get gather              */
     while (TRUE) {                         /* loop over all gather structures input */
       iml3 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
       if (iml3 > iml2) iml3 = iml2;        /* only data in this frame */
       memcpy( achl1, adsl_gai1_inp_w2->achc_ginp_cur, iml3 );
       iml2 -= iml3;                        /* subtract data processed */
       if (iml2 <= 0) break;                /* all data encrypted      */
       achl1 += iml3;                       /* increment output pointer */
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
       if (adsl_gai1_inp_w2 == NULL) {      /* already end of chain    */
         goto ptose96;                      /* program illogic         */
       }
     }
   }
   ADSL_OA1->achc_lower += iml4 + iml1;
   m_put_be2( ADSL_GAI1_OUT_G->achc_ginp_cur + 2,
              ADSL_OA1->achc_lower - ADSL_GAI1_OUT_G->achc_ginp_cur );
   ADSL_GAI1_OUT_G->achc_ginp_end = ADSL_OA1->achc_lower;
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     goto ptose96;                          /* program illogic         */
   }
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
#undef IML_SEND_LEN_1
#undef D_ADSL_CL_RCO1
   if (D_ADSL_RSE1->iec_frcl_bl == ied_frcl_c_loinf_extra) {  /* Extra Parameters - Logon Info 1 */
     D_ADSL_RSE1->iec_frcl_bl = ied_frcl_resp_act_pdu_rec;  /* response block active PDU */
     D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
     goto ptose20;                          /* process next data       */
   }
   if (D_ADSL_RSE1->iec_frcl_bl == ied_frcl_resp_act_pdu_rec) {  /* response block active PDU */
#ifdef TRACEHL1
     printf( "04.01.05 KB ied_frcl_resp_act_pdu_rec from client processed len=%d/0X%X\n",
             D_ADSL_RCO1->imc_debug_reclen, D_ADSL_RCO1->imc_debug_reclen );
#endif
     /* proceed to end of this block                                   */
     while (TRUE) {                         /* loop over all gather structures input */
       iml1 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       if (iml1 > D_ADSL_RSE1->imc_pos_inp_frame) {
         iml1 = D_ADSL_RSE1->imc_pos_inp_frame;
       }
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RSE1->imc_pos_inp_frame -= iml1;
       if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) break;  /* all data processed */
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next gather */
       if (adsl_gai1_inp_1 == NULL) {       /* already end of chain    */
         goto ptose96;                      /* program illogic         */
       }
     }
#ifdef OLD01
     D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_invalid;  /* invalid data received */
     D_ADSL_RSE1->iec_frcl_bl = ied_frcl_resp_act_pdu_rec;  /* response block active PDU */
#else
     D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_xyz_01;
     D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
#endif
     goto ptose20;                          /* process next data       */
   }
   if (D_ADSL_RSE1->iec_frcl_bl == ied_frcl_rec_xyz_01) {
#ifdef TRACEHL1
     printf( "04.01.05 KB ied_frcl_rec_xyz_01 from client processed len=%d/0X%X\n",
             D_ADSL_RCO1->imc_debug_reclen, D_ADSL_RCO1->imc_debug_reclen );
#endif
     /* proceed to end of this block                                   */
     while (TRUE) {                         /* loop over all gather structures input */
       iml1 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
       if (iml1 > D_ADSL_RSE1->imc_pos_inp_frame) {
         iml1 = D_ADSL_RSE1->imc_pos_inp_frame;
       }
       adsl_gai1_inp_1->achc_ginp_cur += iml1;
       D_ADSL_RSE1->imc_pos_inp_frame -= iml1;
       if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) break;  /* all data processed */
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next gather */
       if (adsl_gai1_inp_1 == NULL) {       /* already end of chain    */
         goto ptose96;                      /* program illogic         */
       }
     }
     D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
     goto ptose20;                          /* process next data       */
   }
   switch (D_ADSL_RSE1->iec_frcl_bl) {
     case ied_frcl_lic_01:                  /* licencing block checked */
     case ied_frcl_lic_clrand:              /* New Licence Request/ Client License Info */
       D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_xyz_01; /* XXX maybe introduce extra states?
         awaiting licensing block of sequence-determined type or 0xFF, except if we got 0xFF => extra handling */
     case ied_frcl_rec_xyz_01:
       /* proceed to end of this block                                 */
       while (TRUE) {                       /* loop over all gather structures input */
         iml1 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
         if (iml1 > D_ADSL_RSE1->imc_pos_inp_frame) {
           iml1 = D_ADSL_RSE1->imc_pos_inp_frame;
         }
         adsl_gai1_inp_1->achc_ginp_cur += iml1;
         D_ADSL_RSE1->imc_pos_inp_frame -= iml1;
         if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) break;  /* all data processed */
         adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next gather */
         if (adsl_gai1_inp_1 == NULL) {     /* already end of chain    */
           goto ptose96;                    /* program illogic         */
         }
       }
       D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
       goto ptose20;                        /* process next data       */
   }
   goto ptose96;                            /* program illogic         */

   ptose_vch_00:                            /* virtual channel data received */
   while (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     if (adsl_gai1_inp_1 == NULL) return;   /* wait for more data      */
   }
   if (D_ADSL_RSE1->imc_pos_inp_frame < (2 + 1)) {
         iml_line_no = __LINE__;
         iml_source_no = 36644;    /* source line no for errors */
         goto ptose92;
   }
   /* trace client to server virtual channel                           */
   ADSL_RDPA_F->dsc_rdptr1.iec_tr_command   /* tracer component command */
     = ied_trc_cl2se_vch;                   /* client to server virtual channel */
   ADSL_RDPA_F->dsc_rdptr1.imc_disp_field = D_ADSL_RCO1->imc_len_part - (D_ADSL_RSE1->imc_pos_inp_frame - 2);
   /* virtual channel segmentation flags                               */
   memcpy( ADSL_RDPA_F->dsc_rdptr1.chrc_vch_segfl, D_ADSL_RSE1->chrc_vch_segfl, sizeof(ADSL_RDPA_F->dsc_rdptr1.chrc_vch_segfl) );
   ADSL_RDPA_F->dsc_rdptr1.usc_vch_no = D_ADSL_RSE1->imc_prot_chno;  /* virtual channel no com */
   ADSL_RDPA_F->dsc_rdptr1.imc_prot1 = D_ADSL_RSE1->umc_vch_ulen;  /* variable field */
   if (*adsl_gai1_inp_1->achc_ginp_cur & 0X20) {  /* data compressed   */
     goto ptose_vch_20;                     /* virtual channel data compressed */
   }
   /* remove two bytes of compression flags                            */
   iml1 = 2;                                /* bytes to remove         */
   D_ADSL_RSE1->imc_pos_inp_frame -= iml1;
   while (TRUE) {
     iml_rec = adsl_gai1_inp_1->achc_ginp_end
                 - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml_rec > iml1) iml_rec = iml1;
     adsl_gai1_inp_1->achc_ginp_cur += iml_rec;
     iml1 -= iml_rec;
     if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) break;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     if (iml1 == 0) break;
   }
   adsl_gai1_inp_w2 = adsl_gai1_inp_1;      /* save input data         */
   iml1 = D_ADSL_RSE1->imc_pos_inp_frame;   /* length of data          */
   goto ptose_vch_40;                       /* send virtual channel to client */

   ptose_vch_20:                            /* virtual channel data compressed */
   if (D_ADSL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) {  /* compression enabled */
     goto ptose_vch_22;                     /* virtual channel compression valid */
   }
   iml1 = D_ADSL_RCO1->imc_no_virt_ch;      /* number of virtual channels */
   while (iml1) {                           /* loop over all virtual channels */
     iml1--;                                /* decrement index         */
     if (D_ADSL_RCO1->adsrc_vc_1[ iml1 ].usc_vch_no == D_ADSL_RSE1->imc_prot_chno) {  /* virtual channel no com */
       if (D_ADSL_RCO1->adsrc_vc_1[ iml1 ].imc_flags & 0X00400000) {
         goto ptose_vch_22;                 /* virtual channel compression valid */
       }
       break;
     }
   }
         iml_line_no = __LINE__;
         iml_source_no = 36794;    /* source line no for errors */
         goto ptose92;

   ptose_vch_22:                            /* virtual channel compression valid */
   /* decompress data                                                  */
   D_ADSL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
// to-do 18.02.12 KB
   /* decompress data                                                  */
   D_ADSL_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
   D_ADSL_RCO1->dsc_cdrf_dec.chrc_header[ 0 ]  /* copy compression header */
     = *(adsl_gai1_inp_1->achc_ginp_cur);   /* address act input-data  */
   /* remove two bytes of compression flags                            */
   iml1 = 2;                                /* bytes to remove         */
   D_ADSL_RSE1->imc_pos_inp_frame -= iml1;
   while (TRUE) {
     iml_rec = adsl_gai1_inp_1->achc_ginp_end
                 - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml_rec > iml1) iml_rec = iml1;
     adsl_gai1_inp_1->achc_ginp_cur += iml_rec;
     iml1 -= iml_rec;
     if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) break;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     if (adsl_gai1_inp_1 == NULL) {         /* already end of chain    */
       M_ERROR_TOSE_ILLOGIC
     }
     if (iml1 == 0) break;
   }
   /* prepare gather of all input data                                 */
#define ADSL_GAI1_S ((struct dsd_gather_i_1 *) chrl_work_2)
   adsl_gai1_w1 = ADSL_GAI1_S;              /* first gather here       */
   while (TRUE) {                           /* loop over input bytes   */
     if (adsl_gai1_inp_1 == NULL) {         /* already end of chain    */
       M_ERROR_TOSE_ILLOGIC
     }
     iml1 = adsl_gai1_inp_1->achc_ginp_end - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml1 > D_ADSL_RSE1->imc_pos_inp_frame) iml1 = D_ADSL_RSE1->imc_pos_inp_frame;  /* remaining data in frame */
     D_ADSL_RSE1->imc_pos_inp_frame -= iml1;  /* compute remaining length compressed data */
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_inp_1->achc_ginp_cur;
     adsl_gai1_w1->achc_ginp_end = adsl_gai1_inp_1->achc_ginp_cur + iml1;
     adsl_gai1_inp_1->achc_ginp_cur += iml1;
     if (adsl_gai1_inp_1->achc_ginp_cur >= adsl_gai1_inp_1->achc_ginp_end) {
       adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;  /* get next in chain */
     }
     if (D_ADSL_RSE1->imc_pos_inp_frame <= 0) break;  /* now last part */
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain gather  */
     adsl_gai1_w1++;                        /* use next gather         */
   }
   adsl_gai1_w1->adsc_next = NULL;          /* end of data             */
   D_ADSL_RCO1->dsc_cdrf_dec.adsc_gai1_in = ADSL_GAI1_S;  /* input data */
#undef ADSL_GAI1_S
   D_ADSL_RCO1->dsc_cdrf_dec.boc_mp_flush = TRUE;  /* end-of-record input */
   dsl_gai1_comp_data.achc_ginp_cur = (char *) (adsl_gai1_w1 + 1);
   D_ADSL_RCO1->dsc_cdrf_dec.achc_out_cur = dsl_gai1_comp_data.achc_ginp_cur;  /* current end of output data */
   D_ADSL_RCO1->dsc_cdrf_dec.achc_out_end = chrl_work_2 + sizeof(chrl_work_2);  /* end of buffer for output data */
   /* decompress data                                              */
   D_ADSL_RCO1->amc_cdr_dec( &D_ADSL_RCO1->dsc_cdrf_dec );
   if (D_ADSL_RCO1->dsc_cdrf_dec.imc_return != DEF_IRET_NORMAL) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d de-compression error %d.",
                   __LINE__, 36864,  /* line number for errors */
                   D_ADSL_RCO1->dsc_cdrf_dec.imc_return );
     goto p_cleanup_00;                 /* do cleanup now          */
   }
   dsl_gai1_comp_data.achc_ginp_end = D_ADSL_RCO1->dsc_cdrf_dec.achc_out_cur;
   iml1 = dsl_gai1_comp_data.achc_ginp_end - dsl_gai1_comp_data.achc_ginp_cur;  /* length of data */
   adsl_gai1_inp_w2 = &dsl_gai1_comp_data;  /* process decompressed data */

   ptose_vch_40:                            /* send virtual channel to server */
   /* trace client to server virtual channel                           */
   if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
     ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_inp_w2;
     ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = iml1;  /* remaining data */
     m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
   }
   /* get pointer to virtual channel structure                         */
   memset( &dsl_rdp_param_vch_1, 0, sizeof(struct dsd_rdp_param_vch_1) );  /* clear RDP parameters virus checking */
   dsl_rdp_param_vch_1.adsc_conf = (struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf;  /* configuration data */
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   memcpy( &dsl_rdp_param_vch_1.dsc_s1, &ADSL_RDPA_F->dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
//   dsl_rdp_param_vch_1.adsc_cb_c = ADSL_RDPA_F->adsc_cb_c;  /* cliprdr flags */
   dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */
   /* virtual channel segmentation flags                               */
   memcpy( dsl_rdp_param_vch_1.chrc_vch_segfl, D_ADSL_RSE1->chrc_vch_segfl, sizeof(dsl_rdp_param_vch_1.chrc_vch_segfl) );
   iml2 = D_ADSL_RCO1->imc_no_virt_ch;      /* number of virtual channels */
   while (iml2) {                           /* loop over all virtual channels */
     iml2--;                                /* decrement index         */
     if (D_ADSL_RCO1->adsrc_vc_1[ iml2 ].usc_vch_no == D_ADSL_RSE1->imc_prot_chno) {  /* virtual channel no com */
       dsl_rdp_param_vch_1.adsc_rdp_vc_1 = &D_ADSL_RCO1->adsrc_vc_1[ iml2 ];  /* RDP virtual channel */
       break;
     }
   }
   if (dsl_rdp_param_vch_1.adsc_rdp_vc_1 == NULL) {
         iml_line_no = __LINE__;
         iml_source_no = 36977;    /* source line no for errors */
         goto ptose92;
   }
   if (dsl_rdp_param_vch_1.adsc_rdp_vc_1->chc_hob_vch) {
     ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
     ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
     memcpy( &dsl_rdp_param_vch_1.dsc_s1, &ADSL_RDPA_F->dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
     dsl_rdp_param_vch_1.ac_chain_send_tose = al_chain_send_tose;  /* chain of buffers to be sent to the server */
     dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */
     dsl_rdp_param_vch_1.adsc_output_area_1 = ADSL_OA1;  /* output of subroutine */
     dsl_rdp_param_vch_1.adsc_gather_i_1_in = adsl_gai1_inp_w2;
     dsl_rdp_param_vch_1.imc_len_vch_input = iml1;  /* remaining data  */
     iel_sdh_ret1 = m_rdp_vch1_rec_tose( &dsl_rdp_param_vch_1 );
     if (iel_sdh_ret1 == ied_sdhr1_fatal_error) {  /* fatal error occured, abend */
       goto p_cleanup_00;                   /* do cleanup now          */
     }
     memcpy( &ADSL_RDPA_F->dsc_s1, &dsl_rdp_param_vch_1.dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
     al_chain_send_tose = dsl_rdp_param_vch_1.ac_chain_send_tose;  /* chain of buffers to be sent to the server */
     if (dsl_rdp_param_vch_1.boc_callrevdir) {  /* call on reverse direction */
       adsp_hl_clib_1->boc_callrevdir = TRUE;  /* set call on reverse direction */
     }
     if (iel_sdh_ret1 == ied_sdhr1_failed) {  /* do not send virtual channel command */
       goto ptose_vch_60;                   /* end of send virtual channel */
     }
   }
   if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < 128) {  /* get new area */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error        */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       goto p_cleanup_20;                   /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     goto ptose96;                          /* program illogic         */
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
   adsl_gai1_out_save = ADSL_GAI1_OUT_G;    /* save start output data  */
#undef ADSL_GAI1_OUT_G
   /* compute where to start output                                    */
   achl_out_1 = ADSL_OA1->achc_lower + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1 + 2 + 4 + D_SIZE_HASH + 4 + 2 + 2;
   achl1 = achl_out_1;                      /* save position start output */
#define D_ADSL_CL_RCO1 (&ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1)
   if (D_ADSL_CL_RCO1->umc_loinf_options & D_LOINFO_COMPR_ENA) goto ptose_vch_44;  /* send virtual channel data compressed */
#undef D_ADSL_CL_RCO1
   memset( achl_out_1 - 2, 0, 2 );          /* clear compression flags */
   iml_out_len = iml1;                      /* set length output       */
   /* do not eat input                                                 */
   achl2 = adsl_gai1_inp_w2->achc_ginp_cur;
   while (TRUE) {
     iml_rec = adsl_gai1_inp_w2->achc_ginp_end - achl2;
     if (iml_rec > iml1) iml_rec = iml1;
     if (iml_rec > (ADSL_OA1->achc_upper - achl_out_1)) iml_rec = ADSL_OA1->achc_upper - achl_out_1;
     memcpy( achl_out_1, achl2, iml_rec );
     achl2 += iml_rec;
     iml1 -= iml_rec;
     achl_out_1 += iml_rec;
     if (iml1 == 0) break;
     if (achl2 >= adsl_gai1_inp_w2->achc_ginp_end) {
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
       if (adsl_gai1_inp_w2 == NULL) {      /* already end of chain    */
         goto ptose96;                      /* program illogic         */
       }
       achl2 = adsl_gai1_inp_w2->achc_ginp_cur;
     }
     if (achl_out_1 < ADSL_OA1->achc_upper) continue;  /* still space in output-area */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;
     /* get new block for more output                                  */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error        */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       goto p_cleanup_20;                   /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
       goto ptose96;                        /* program illogic         */
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
     ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
   }
   goto ptose_vch_48;                       /* output finished         */

   ptose_vch_44:                            /* send virtual channel data compressed */
#define D_ADSL_CL_RCO1 (&ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1)
   iml_compr_inp = iml1;                    /* input to compression    */
   iml_out_len = 0;                         /* clear length output     */
   D_ADSL_RSE1->imc_pos_inp_frame = 0;      /* input is consumed       */
   D_ADSL_CL_RCO1->dsc_cdrf_enc.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   D_ADSL_CL_RCO1->dsc_cdrf_enc.amc_aux = adsp_hl_clib_1->amc_aux;
#define ADSL_GAI1_S ((struct dsd_gather_i_1 *) chrl_work_2)
   adsl_gai1_w1 = ADSL_GAI1_S;              /* first gather here       */
   while (TRUE) {                           /* loop over input bytes   */
     iml1 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
     if (iml1 > iml_compr_inp) iml1 = iml_compr_inp;
     adsl_gai1_w1->achc_ginp_cur = adsl_gai1_inp_w2->achc_ginp_cur;
     adsl_gai1_w1->achc_ginp_end = adsl_gai1_inp_w2->achc_ginp_cur + iml1;
     adsl_gai1_inp_w2->achc_ginp_cur += iml1;
     if (adsl_gai1_inp_w2->achc_ginp_cur >= adsl_gai1_inp_w2->achc_ginp_end) {
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;
     }
     iml_compr_inp -= iml1;                 /* remaining data to compress */
     if (iml_compr_inp <= 0) break;         /* end of data to compress */
     adsl_gai1_w1->adsc_next = adsl_gai1_w1 + 1;  /* set chain gather  */
     adsl_gai1_w1++;                        /* use next gather         */
   }
   adsl_gai1_w1->adsc_next = NULL;          /* end of data             */
   D_ADSL_CL_RCO1->dsc_cdrf_enc.adsc_gai1_in = ADSL_GAI1_S;  /* input data */
#undef ADSL_GAI1_S
   D_ADSL_CL_RCO1->dsc_cdrf_enc.boc_mp_flush = TRUE;  /* end-of-record input */
   D_ADSL_CL_RCO1->dsc_cdrf_enc.achc_out_cur = achl_out_1;  /* current end of output data */
   D_ADSL_CL_RCO1->dsc_cdrf_enc.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
   while (TRUE) {                           /* loop over gather input  */
     D_ADSL_CL_RCO1->amc_cdr_enc( &D_ADSL_CL_RCO1->dsc_cdrf_enc );
     if (D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_return != DEF_IRET_NORMAL) {
       m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d compression error %d.",
                     __LINE__, 37162,  /* line number for errors */
                     D_ADSL_CL_RCO1->dsc_cdrf_enc.imc_return );
       goto p_cleanup_00;                   /* do cleanup now          */
     }
     iml_out_len += D_ADSL_CL_RCO1->dsc_cdrf_enc.achc_out_cur - achl_out_1;
     achl_out_1 = D_ADSL_CL_RCO1->dsc_cdrf_enc.achc_out_cur;  /* set end of output */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;
     if (D_ADSL_CL_RCO1->dsc_cdrf_enc.boc_sr_flush) break;  /* end-of-record output */
     /* get new block for more output                                  */
     memset( &dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea) );  /* acquire additional work area */
     bol1 = (*adsp_hl_clib_1->amc_aux)( adsp_hl_clib_1->vpc_userfld,
                                        DEF_AUX_GET_WORKAREA,  /* get additional work area */
                                        &dsl_aux_get_workarea,
                                        sizeof(struct dsd_aux_get_workarea) );
     if (bol1 == FALSE) {                   /* aux returned error        */
       adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;  /* fatal error occured */
       goto p_cleanup_20;                   /* do cleanup now          */
     }
     ADSL_OA1->achc_lower = dsl_aux_get_workarea.achc_work_area;
     ADSL_OA1->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
     ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
     if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
       goto ptose96;                        /* program illogic         */
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
     ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
     D_ADSL_CL_RCO1->dsc_cdrf_enc.achc_out_cur = achl_out_1;  /* current end of output data */
     D_ADSL_CL_RCO1->dsc_cdrf_enc.achc_out_end = ADSL_OA1->achc_upper;  /* end of buffer for output data */
   }
   *(achl1 - 2) = D_ADSL_CL_RCO1->dsc_cdrf_enc.chrc_header[ 0 ];  /* copy compression header */
   *(achl1 - 1) = 0;                        /* second byte compression header */
#undef D_ADSL_CL_RCO1

   ptose_vch_48:                            /* output finished         */
   ADSL_OA1->achc_lower = ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set end of block */
   /* make header of output                                            */
   achl1 -= 4 + 2 + 2;                      /* length uncompressed, segmentation flags and compression flags */
   m_put_le4( achl1, D_ADSL_RSE1->umc_vch_ulen );
   memcpy( achl1 + 4, D_ADSL_RSE1->chrc_vch_segfl, sizeof(D_ADSL_RSE1->chrc_vch_segfl) );
   iml_out_len += 4 + 2 + 2;                /* add length output       */
   if ((ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent & (4096 - 1)) == 0){
     if (ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent) {
       m_update_keys( &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se, NULL );
     }
   }
// to-do 25.05.11 KB is D_ADSL_RSE1-> correct here ???
   if (D_ADSL_RSE1->chc_prot_rt02 & 0X08) {  /* output encrypted       */
     /* generate random                                                */
#define ACHL_WORK_SHA1 ((int *) chrl_work_2)
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
     adsl_gai1_out_save->achc_ginp_cur = achl1;
     adsl_gai1_inp_w2 = adsl_gai1_out_save;
     iml2 = iml_out_len;                    /* get length output       */
     while (TRUE) {                         /* loop over all gather structures input */
       iml1 = adsl_gai1_inp_w2->achc_ginp_end - adsl_gai1_inp_w2->achc_ginp_cur;
       if (iml1 > iml2) {
         iml1 = iml2;                       /* only data in this frame */
       }
       SHA1_Update( ACHL_WORK_SHA1,
                    adsl_gai1_inp_w2->achc_ginp_cur,
                    0, iml1 );
       RC4( adsl_gai1_inp_w2->achc_ginp_cur, 0, iml1,
            adsl_gai1_inp_w2->achc_ginp_cur, 0,
            ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.chrc_rc4_state );
       iml2 -= iml1;                        /* subtract data processed */
       if (iml2 <= 0) break;                /* all data processed      */
       adsl_gai1_inp_w2 = adsl_gai1_inp_w2->adsc_next;  /* get next gather */
       if (adsl_gai1_inp_w2 == NULL) {      /* already end of chain    */
         goto ptose96;                      /* program illogic         */
       }
     }
// to-do 25.05.11 KB is D_ADSL_RSE1-> correct here ???
     if (D_ADSL_RSE1->chc_prot_rt03 & 0X08) {  /* flag for block count */
       m_put_le4( ACHL_WORK_UTIL_01, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent );
       SHA1_Update( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0, 4 );
     }
     SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
     MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
     MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
     achl1 -= D_SIZE_HASH;                  /* subtract length hash    */
     memcpy( achl1, ACHL_WORK_UTIL_01, D_SIZE_HASH );
     iml_out_len += D_SIZE_HASH;            /* add length hash         */
#undef ACHL_WORK_SHA1
#undef ACHL_WORK_MD5
#undef ACHL_WORK_UTIL_01
   }
   achl1 -= 1 + 2 + 2;                      /* length length, fl2, fl3, padding */
// to-do 25.05.11 KB is D_ADSL_RSE1-> correct here ???
   *(achl1 + 1 + 0) = D_ADSL_RSE1->chc_prot_rt02;
   *(achl1 + 1 + 1) = D_ADSL_RSE1->chc_prot_rt03;
   /* two bytes padding zero                                           */
   *(achl1 + 1 + 2 + 0) = 0;
   *(achl1 + 1 + 2 + 1) = 0;
   iml_out_len += 4;                        /* add length header       */
   *achl1 = (unsigned char) iml_out_len;    /* one byte length         */
   if (iml_out_len >= 0X0080) {             /* length in two bytes     */
     achl1--;                               /* space for second byte   */
     m_put_be2( achl1, iml_out_len );
     *achl1 |= 0X80;                        /* flag length two bytes   */
     iml_out_len += 1;                      /* increment length        */
   }
   achl1 -= 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1;
   iml_out_len += 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1 + 1;
   adsl_gai1_out_save->achc_ginp_cur = achl1;
   *achl1 = DEF_CONST_RDP_03;
   *(achl1 + 1) = 0;                        /* second byte zero        */
   m_put_be2( achl1 + 2, iml_out_len );
   memcpy( achl1 + 4,
           ucrs_x224_p01,
           sizeof(ucrs_x224_p01) );
   *(achl1 + 4 + sizeof(ucrs_x224_p01)) = 0X64;  /* Send Data Indication ???? UUUU 24.05.07 KB */
   m_put_be2( achl1 + 4 + sizeof(ucrs_x224_p01) + 1, ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.usc_userid_cl2se );
   m_put_be2( achl1 + 4 + sizeof(ucrs_x224_p01) + 1 + 2, D_ADSL_RSE1->imc_prot_chno );
   *(achl1 + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2) = 0X70;  /* priority / segmentation */
   ADSL_RDPA_F->dsc_rdp_cl_1.dsc_rdp_co_1.dsc_encry_cl2se.imc_count_sent++;  /* count block sent */

   ptose_vch_60:                            /* end of send virtual channel */
   D_ADSL_RSE1->iec_frcl_bl = ied_frcl_rec_xyz_01;
   D_ADSL_RSE1->iec_fcfp_bl = ied_fcfp_rec_type;  /* receive record type */
   dsl_gai1_comp_data.achc_ginp_cur = NULL;  /* no decompressed data   */
   if (D_ADSL_RSE1->imc_pos_inp_frame == 0) goto ptose20;  /* process next data */
   /* remove all input data                                            */
   while (TRUE) {
     iml_rec = adsl_gai1_inp_1->achc_ginp_end
                 - adsl_gai1_inp_1->achc_ginp_cur;
     if (iml_rec > D_ADSL_RSE1->imc_pos_inp_frame) iml_rec = D_ADSL_RSE1->imc_pos_inp_frame;
     adsl_gai1_inp_1->achc_ginp_cur += iml_rec;
     D_ADSL_RSE1->imc_pos_inp_frame -= iml_rec;
     if (adsl_gai1_inp_1->achc_ginp_cur < adsl_gai1_inp_1->achc_ginp_end) break;
     adsl_gai1_inp_1 = adsl_gai1_inp_1->adsc_next;
     if (D_ADSL_RSE1->imc_pos_inp_frame == 0) break;
   }
   goto ptose20;                            /* process next data       */

   ptose80:                                 /* send to server          */
   /* get pointer to virtual channel structure                         */
   memset( &dsl_rdp_param_vch_1, 0, sizeof(struct dsd_rdp_param_vch_1) );  /* clear RDP parameters virus checking */
   dsl_rdp_param_vch_1.adsc_conf = (struct dsd_rdpvch1_config *) adsp_hl_clib_1->ac_conf;  /* configuration data */
   ADSL_RDPA_F->dsc_stor_sdh_1.amc_aux = adsp_hl_clib_1->amc_aux;
   ADSL_RDPA_F->dsc_stor_sdh_1.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
   memcpy( &dsl_rdp_param_vch_1.dsc_s1, &ADSL_RDPA_F->dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
//   dsl_rdp_param_vch_1.adsc_cb_c = ADSL_RDPA_F->adsc_cb_c;  /* cliprdr flags */
   dsl_rdp_param_vch_1.adsc_stor_sdh_1 = &ADSL_RDPA_F->dsc_stor_sdh_1;  /* storage management */
   dsl_rdp_param_vch_1.ac_chain_send_tose = al_chain_send_tose;  /* chain of buffers to be sent to the server */
   // JB 16.06.11: Included this check, as workarea sometimes is too small and
   // causes a "workarea overflow" in xsrdpvch1.cpp.
   if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < 128) {  /* get new area */
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
   dsl_rdp_param_vch_1.adsc_output_area_1 = ADSL_OA1;  /* output of subroutine */
   iel_sdh_ret1 = m_rdp_vch1_get_tose( &dsl_rdp_param_vch_1 );
   if (iel_sdh_ret1 == ied_sdhr1_fatal_error) {  /* fatal error occured, abend */
     goto p_cleanup_00;                     /* do cleanup now          */
   }
   memcpy( &ADSL_RDPA_F->dsc_s1, &dsl_rdp_param_vch_1.dsc_s1, sizeof(struct dsd_rdp_save_vch_1) );
   al_chain_send_tose = dsl_rdp_param_vch_1.ac_chain_send_tose;  /* chain of buffers to be sent to the server */
   if (dsl_rdp_param_vch_1.boc_callrevdir) {  /* call on reverse direction */
     adsp_hl_clib_1->boc_callrevdir = TRUE;  /* set call on reverse direction */
   }
   if (dsl_rdp_param_vch_1.adsc_sc_vch_out) {  /* send output to virtual channel */
     if (ADSL_RDPA_F->dsc_rdptr1.imc_trace_level) {  /* output of trace record */
       /* trace client to server generated virtual channel             */
       ADSL_RDPA_F->dsc_rdptr1.iec_tr_command   /* tracer component command */
         = ied_trc_cl2se_gen_vch;           /* client to server virtual channel generated */
       ADSL_RDPA_F->dsc_rdptr1.usc_vch_no
         = dsl_rdp_param_vch_1.adsc_sc_vch_out->adsc_rdp_vc_1->usc_vch_no;  /* virtual channel no com */
       adsl_gai1_w1 = dsl_rdp_param_vch_1.adsc_sc_vch_out->adsc_gai1_data;  /* output data */
       ADSL_RDPA_F->dsc_rdptr1.adsc_gather_i_1_in = adsl_gai1_w1;
       iml1 = 0;                            /* clear count             */
       while (adsl_gai1_w1) {               /* loop over input         */
         iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
       }
       ADSL_RDPA_F->dsc_rdptr1.imc_len_trace_input = iml1;  /* remaining data */
       /* virtual channel segmentation flags                           */
       memcpy( ADSL_RDPA_F->dsc_rdptr1.chrc_vch_segfl, dsl_rdp_param_vch_1.adsc_sc_vch_out->chrc_vch_segfl, sizeof(ADSL_RDPA_F->dsc_rdptr1.chrc_vch_segfl) );
       m_hlrdptra1e( &ADSL_RDPA_F->dsc_rdptr1 );
     }
     bol1 = m_send_vch_tose( adsp_hl_clib_1,
                             ADSL_OA1,
                             dsl_rdp_param_vch_1.adsc_sc_vch_out,
                             chrl_work_2 );
     if (bol1 == FALSE) goto p_cleanup_00;  /* do cleanup now          */
     goto ptose80;                          /* check if more to send   */
   }
   goto p_ret_00;                           /* check how to return     */

   ptose92:                                 /* protocol error          */
   m_sdh_printf( adsp_hl_clib_1, "ptose92 - protocoll error received from client iec_frcl_bl=%d iec_fcfp_bl=%d l%05d s%05d",
                 ADSL_RDPA_F->dsc_rdp_se_1.iec_frcl_bl,
                 ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl,
                 iml_line_no,               /* line number for errors  */
                 iml_source_no );           /* source line no for errors */
#ifdef TRACEHL1
   if (adsl_gai1_inp_1) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d ptose92 achl_inp_start=%p achc_ginp_cur=%p achc_ginp_end=%p pos=%04X.",
                   __LINE__, 38173,  /* line number for errors  */
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
#ifdef TRACE_LOOP_1
   while (ADSL_RDPA_F) {
     Sleep( 2000 );
   }
#endif
   if (adsl_gai1_inp_1) {
     adsl_gai1_inp_1->achc_ginp_cur
       = adsl_gai1_inp_1->achc_ginp_end;
   }
   goto p_cleanup_00;                       /* do cleanup now          */

   ptose96:                                 /* program illogic         */
   m_sdh_printf( adsp_hl_clib_1, "ptose96 - program illogic received from client iec_frcl_bl=%d iec_fcfp_bl=%d",
                 ADSL_RDPA_F->dsc_rdp_se_1.iec_frcl_bl,
                 ADSL_RDPA_F->dsc_rdp_se_1.iec_fcfp_bl );
#ifdef D_FFLUSH                             /* 30.05.05 KB - flush stdout */
   fflush( stdout );
#endif                                      /* 30.05.05 KB - flush stdout */
#ifdef TRACE_LOOP_1
   while (ADSL_RDPA_F) {
     Sleep( 2000 );
   }
#endif
   if (adsl_gai1_inp_1) {
     adsl_gai1_inp_1->achc_ginp_cur
       = adsl_gai1_inp_1->achc_ginp_end;
   }
   goto p_cleanup_00;                       /* do cleanup now          */

#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RSE1
#undef D_ADSL_RCO1
#else
   D_ADSL_RSE1 = NULL;
   D_ADSL_RCO1 = NULL;
#endif

   p_ret_00:                                /* check how to return     */
   if (   (adsp_hl_clib_1->boc_eof_client == FALSE)  /* check End-of-File Client */
       && (adsp_hl_clib_1->boc_eof_server == FALSE)) {  /* check End-of-File Server */
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
   m_rdp_vch1_close( &dsl_rdp_param_vch_1 );
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
#define D_ADSL_SE_RCO1 (&ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1)
   if (D_ADSL_SE_RCO1->amc_cdr_dec) {
     D_ADSL_SE_RCO1->dsc_cdrf_dec.imc_func = DEF_IFUNC_END;
     D_ADSL_SE_RCO1->dsc_cdrf_dec.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
     D_ADSL_SE_RCO1->dsc_cdrf_dec.amc_aux = adsp_hl_clib_1->amc_aux;
     D_ADSL_SE_RCO1->amc_cdr_dec( &D_ADSL_SE_RCO1->dsc_cdrf_dec );
   }
   if (D_ADSL_SE_RCO1->amc_cdr_enc) {
     D_ADSL_SE_RCO1->dsc_cdrf_enc.imc_func = DEF_IFUNC_END;
     D_ADSL_SE_RCO1->dsc_cdrf_enc.vpc_userfld = adsp_hl_clib_1->vpc_userfld;
     D_ADSL_SE_RCO1->dsc_cdrf_enc.amc_aux = adsp_hl_clib_1->amc_aux;
     D_ADSL_SE_RCO1->amc_cdr_enc( &D_ADSL_SE_RCO1->dsc_cdrf_enc );
   }
#undef D_ADSL_SE_RCO1
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

/* send block 04 to client                                             */
static BOOL m_send_cl_r04( struct dsd_hl_clib_1 *adsp_hl_clib_1,
     struct dsd_output_area_1 *adsp_output_area_1 ) {
   int        iml1;                         /* working variable        */
// char       *achl1, *achl2;               /* working variables       */
   char       *achl1;                       /* working variable        */
// *M_CHECK_TOSE_DATA;
   struct dsd_gather_i_1 *adsl_gai1_out_st;  /* start output data      */
   struct dsd_gather_i_1 *adsl_gai1_out_1;  /* output data             */
   struct dsd_gather_i_1 *adsl_gai1_out_2;  /* output data             */
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_rdp_server_1 *D_ADSL_RSE1;
// struct dsd_rdp_client_1 *D_ADSL_RCL1;
   struct dsd_rdp_co *D_ADSL_RCO1;  /* RDP communication client */
   struct dsd_output_area_1 *ADSL_OA1;
#endif

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#define ADSL_OA1 adsp_output_area_1
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
#ifndef HL_RDPACC_HELP_DEBUG
#define D_ADSL_RSE1 (&ADSL_RDPA_F->dsc_rdp_se_1)
#define D_ADSL_RCO1 (&D_ADSL_RSE1->dsc_rdp_co_1)
#else
   D_ADSL_RSE1 = &ADSL_RDPA_F->dsc_rdp_se_1;
   D_ADSL_RCO1 = &D_ADSL_RSE1->dsc_rdp_co_1;
   ADSL_OA1 = adsp_output_area_1;
#endif
   /* fill area to send to client                                      */
/* this part already in main program 06.01.05 KB */
   ADSL_OA1->achc_lower = adsp_hl_clib_1->achc_work_area;  /* addr work-area */
   ADSL_OA1->achc_upper = ADSL_OA1->achc_lower + adsp_hl_clib_1->inc_len_work_area;  /* length work-area */
   adsl_gai1_out_2 = NULL;                  /* output data             */
   achl1 = ADSL_OA1->achc_lower;
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d output-area too small",
                   __LINE__, 38847 );  /* line number for errors */
     return FALSE;
   }
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) ADSL_OA1->achc_upper;
   adsl_gai1_out_st = adsl_gai1_out_1;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = achl1;
   *achl1 = DEF_CONST_RDP_03;               /* set block type          */
   *(achl1 + 1) = 0;                        /* second byte zero        */
   achl1 += 4;                              /* after length            */
   memcpy( achl1, ucrs_x224_p01, sizeof(ucrs_x224_p01) );
   achl1 += sizeof(ucrs_x224_p01);
   /* MCS Connect Reply from Server                                    */
   *achl1++ = 0X7F;
   *achl1++ = 0X66;
   achl1 += 3;                              /* after length            */
   memcpy( achl1, ucrs_r04_asn1_1, sizeof(ucrs_r04_asn1_1) );
   achl1 += sizeof(ucrs_r04_asn1_1);
   *achl1++ = 0X04;                         /* ASN-1 tag               */
   achl1 += 3;                              /* after length            */
   memcpy( achl1, ucrs_asn1_prot_id, sizeof(ucrs_asn1_prot_id) );
   achl1 += sizeof(ucrs_asn1_prot_id);
   achl1 += 2;                              /* after length            */
   memcpy( achl1, ucrs_r04_vers_f, sizeof(ucrs_r04_vers_f) );
   achl1 += sizeof(ucrs_r04_vers_f);
   m_put_le2( achl1, 0X0C03 );              /* virtual channel tag     */
   achl1 += 2;                              /* after this field        */
   iml1 = 2 + 2 + (D_ADSL_RCO1->imc_no_virt_ch + 2) * 2;  /* length this sequence */
   if (D_ADSL_RCO1->imc_no_virt_ch & 1) {   /* odd number              */
     iml1 += 2;                             /* add length virtual channel delemiter */
   }
   m_put_le2( achl1, iml1 );                /* length this sequence    */
   achl1 += 2;                              /* after this field        */
   m_put_le2( achl1, D_ADSL_RCO1->usc_chno_disp );  /* virtual channel display */
   achl1 += 2;                              /* after this field        */
   iml1 = D_ADSL_RCO1->imc_no_virt_ch;      /* number of virtual channels */
   m_put_le2( achl1, iml1 );                /* output number of virtual channels */
   achl1 += 2;                              /* after this field        */
   while (iml1) {                           /* loop over all virtual channels */
     m_put_le2( achl1,
                (D_ADSL_RCO1->adsrc_vc_1 + (D_ADSL_RCO1->imc_no_virt_ch - iml1))
                   ->usc_vch_no );
     achl1 += 2;                            /* after this field        */
     iml1--;                                /* decrement number        */
   }
   if (D_ADSL_RCO1->imc_no_virt_ch & 1) {   /* odd number              */
     *achl1++ = 0;
     *achl1++ = 0;
   }
   m_put_le2( achl1, 0X0C02 );              /* encryption tag          */
   achl1 += 2;                              /* after this field        */
   m_put_le2( achl1,
              2 + 2 + 4 * 4
              + sizeof(ADSL_RDPA_F->chrl_server_random)
              + sizeof(ucrs_rdp_pre_cert)
              + sizeof(ucrs_rdp_cert) );
   achl1 += 2;                              /* after this field        */
   m_put_le4( achl1, D_ADSL_RCO1->imc_keytype );  /* keytype           */
   achl1 += 4;                              /* after this field        */
   m_put_le4( achl1, D_ADSL_RCO1->imc_sec_level );  /* security level  */
   achl1 += 4;                              /* after this field        */
   m_put_le4( achl1, sizeof(ADSL_RDPA_F->chrl_server_random) );
   achl1 += 4;                              /* after this field        */
   m_put_le4( achl1, sizeof(ucrs_rdp_pre_cert) + sizeof(ucrs_rdp_cert) );  /* length certificate */
   achl1 += 4;                              /* after this field        */
   adsl_gai1_out_1->achc_ginp_end = achl1;
   /* calculate end if all copied                                      */
   achl1 += sizeof(ADSL_RDPA_F->chrl_server_random)
            + sizeof(ucrs_rdp_pre_cert)
            + sizeof(ucrs_rdp_cert);
   m_put_be2( ADSL_OA1->achc_lower + 2, achl1 - ADSL_OA1->achc_lower );
   m_put_be2( ADSL_OA1->achc_lower + 9 + 1, achl1 - (ADSL_OA1->achc_lower + 9 + 3) );
   *(ADSL_OA1->achc_lower + 9) = (char) 0X82;
   m_put_be2( ADSL_OA1->achc_lower + 0X2F + 1, achl1 - (ADSL_OA1->achc_lower + 0X2F + 3) );
   *(ADSL_OA1->achc_lower + 0X2F) = (char) 0X82;
   m_put_be2( ADSL_OA1->achc_lower + 0X47, achl1 - (ADSL_OA1->achc_lower + 0X47 + 2) );
   *(ADSL_OA1->achc_lower + 0X47) |= 0X80;
   adsl_gai1_out_2 = adsl_gai1_out_1;       /* save this field         */
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d output-area too small",
                   __LINE__, 38955 );  /* line number for errors */
     return FALSE;
   }
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) ADSL_OA1->achc_upper;
   adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = ADSL_RDPA_F->chrl_server_random;
   adsl_gai1_out_1->achc_ginp_end = ADSL_RDPA_F->chrl_server_random
                                    + sizeof(ADSL_RDPA_F->chrl_server_random);
   adsl_gai1_out_2 = adsl_gai1_out_1;       /* save this field         */
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d output-area too small",
                   __LINE__, 38976 );  /* line number for errors */
     return FALSE;
   }
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) ADSL_OA1->achc_upper;
   adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = (char *) ucrs_rdp_pre_cert;
   adsl_gai1_out_1->achc_ginp_end = (char *) ucrs_rdp_pre_cert
                                             + sizeof(ucrs_rdp_pre_cert);

   adsl_gai1_out_2 = adsl_gai1_out_1;       /* save this field         */
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d output-area too small",
                   __LINE__, 38998 );  /* line number for errors */
     return FALSE;
   }
   adsl_gai1_out_1 = (struct dsd_gather_i_1 *) ADSL_OA1->achc_upper;
   adsl_gai1_out_2->adsc_next = adsl_gai1_out_1;
   adsl_gai1_out_1->adsc_next = NULL;
   adsl_gai1_out_1->achc_ginp_cur = (char *) ucrs_rdp_cert;
   adsl_gai1_out_1->achc_ginp_end = (char *) ucrs_rdp_cert
                                             + sizeof(ucrs_rdp_cert);

#ifndef NEW_WSP_1102
   if (adsp_hl_clib_1->adsc_gather_i_1_out) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_cl_r04() not first record output",
                   __LINE__, 39018 );  /* line number for errors */
     return FALSE;
   }
   adsp_hl_clib_1->adsc_gather_i_1_out = adsl_gai1_out_st;
#else
   if (adsp_hl_clib_1->adsc_gai1_out_to_client) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_cl_r04() not first record output",
                   __LINE__, 39025 );  /* line number for errors */
     return FALSE;
   }
   adsp_hl_clib_1->adsc_gai1_out_to_client = adsl_gai1_out_st;  /* output data to client */
#endif
   return TRUE;                             /* all done                */
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RSE1
#undef D_ADSL_RCO1
#undef ADSL_OA1
#undef ADSL_RDPA_F
#endif
} /* end m_send_cl_r04()                                               */

/* generate keys for RDP encryption                                    */
static void m_gen_keys( struct dsd_hl_clib_1 *adsp_hl_clib_1,
     char *achp_client_random,
     struct dsd_rdp_co *adsp_rdp_co,  /* output in RDP communication */
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
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 32 );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, achp_client_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_PRE_HASH + 0, 0 );
   /* make second pre master hash                                      */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_02, 0, sizeof(ucrs_crypt_ini_02) );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 32 );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, achp_client_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_PRE_HASH + 16, 0 );
   /* make third pre master hash                                       */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_03, 0, sizeof(ucrs_crypt_ini_03) );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 24 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 32 );
   SHA1_Final( ACHL_SHA_ARRAY, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, achp_client_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 24 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_PRE_HASH + 32, 0 );
   /* make first master hash                                           */
   SHA1_Init( ACHL_SHA_ARRAY );
   SHA1_Update( ACHL_SHA_ARRAY, (char *) ucrs_crypt_ini_04, 0, sizeof(ucrs_crypt_ini_04) );
   SHA1_Update( ACHL_SHA_ARRAY, ACHL_PRE_HASH, 0, 48 );
   SHA1_Update( ACHL_SHA_ARRAY, achp_client_random, 0, 32 );
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 32 );
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
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 32 );
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
   SHA1_Update( ACHL_SHA_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 32 );
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
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 32 );
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
   MD5_Update( ACHL_MD5_ARRAY, ADSL_RDPA_F->chrl_server_random, 0, 32 );
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
static BOOL m_prepare_keys( struct dsd_hl_clib_1 *adsp_hl_clib_1,
     struct dsd_rdp_co *adsp_rdp_co ) {  /* output in RDP communication */
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
#endif

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
   /* shorten the keys                                                 */
   switch ( adsp_rdp_co->imc_keytype) {
     case 1:
       memcpy( adsp_rdp_co->dsc_encry_se2cl.chrc_cl_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
       memcpy( adsp_rdp_co->dsc_encry_cl2se.chrc_cl_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
       adsp_rdp_co->imc_used_keylen = 8;
       break;
     case 2:
       adsp_rdp_co->imc_used_keylen = 16;
       break;
     case 4:
     case 8:
       adsp_rdp_co->dsc_encry_se2cl.chrc_cl_pkd[0] = (char) 0XD1;
       adsp_rdp_co->dsc_encry_cl2se.chrc_cl_pkd[0] = (char) 0XD1;
       adsp_rdp_co->imc_used_keylen = 8;
       break;
     default:
       return FALSE;                        /* protocol error          */
   }
   return TRUE;                             /* all valid               */
#ifndef HL_RDPACC_HELP_DEBUG
#undef ADSL_RDPA_F
#endif
} /* end m_prepare_keys()                                              */

static void m_update_keys( struct dsd_rdp_co *adsp_rdp_co,
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
                0, adsp_rdp_co->imc_used_keylen );
   SHA1_Update( ACHL_WORK_SHA1, ACHL_CONST_SHA1, 0, 40 );
   SHA1_Update( ACHL_WORK_SHA1, adsp_encry->chrc_cl_pkd,
                0, adsp_rdp_co->imc_used_keylen );
   SHA1_Final( ACHL_WORK_SHA1, ACHL_WORK_UTIL_01, 0 );
   MD5_Init( ACHL_WORK_MD5 );
   MD5_Update( ACHL_WORK_MD5, adsp_encry->chrc_orig_pkd,
               0, adsp_rdp_co->imc_used_keylen );
   MD5_Update( ACHL_WORK_MD5, ACHL_CONST_MD5, 0, 48 );
   MD5_Update( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0, 20 );
   MD5_Final( ACHL_WORK_MD5, ACHL_WORK_UTIL_01, 0 );
   switch ( adsp_rdp_co->imc_keytype) {
     case 1:
       memcpy( adsp_encry->chrc_cl_pkd, ACHL_WORK_UTIL_01, 8 );
       RC4_SetKey( ACHL_WORK_UTIL_02,
                   adsp_encry->chrc_cl_pkd, 0,
                   8 );
       RC4( adsp_encry->chrc_cl_pkd, 0, 8, adsp_encry->chrc_cl_pkd, 0, ACHL_WORK_UTIL_02 );
       memcpy( adsp_encry->chrc_cl_pkd, ucrs_ks_01, sizeof(ucrs_ks_01) );
       break;
     case 2:
       memcpy( adsp_encry->chrc_cl_pkd, ACHL_WORK_UTIL_01, 16 );
       RC4_SetKey( ACHL_WORK_UTIL_02,
                   adsp_encry->chrc_cl_pkd, 0,
                   16 );
       RC4( adsp_encry->chrc_cl_pkd, 0, 16, adsp_encry->chrc_cl_pkd, 0, ACHL_WORK_UTIL_02 );
       break;
     case 4:
     case 8:
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
               adsp_rdp_co->imc_used_keylen );
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


/* check the hash of RDP5-style input                                  */
static BOOL m_check_hash_inp_rdp5( struct dsd_hl_clib_1 *adsp_hl_clib_1,
                                   char *achp_data, int imp_len_data ) {
// int        iml1;                         /* working-variables       */
   int        imrl_sha1_state[ SHA_ARRAY_SIZE ];  /* SHA1 state array  */
   int        imrl_md5_state[ MD5_ARRAY_SIZE ];  /* MD5 state array    */
   char       chrl_work1[20];               /* work-area               */
// int        imrl_sha1_array[ 24 ];
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_rdp_server_1 *D_ADSL_RSE1;
   struct dsd_rdp_co *D_ADSL_RCO1;  /* RDP communication server */
   struct dsd_output_area_1 *ADSL_OA1;
#endif

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#define D_ADSL_RSE1 (&ADSL_RDPA_F->dsc_rdp_se_1)
#define D_ADSL_RCO1 (&D_ADSL_RSE1->dsc_rdp_co_1)
#define ADSL_OA1 adsp_output_area_1
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
   D_ADSL_RSE1 = &ADSL_RDPA_F->dsc_rdp_se_1;
   D_ADSL_RCO1 = &D_ADSL_RSE1->dsc_rdp_co_1;
// ADSL_OA1 = adsp_output_area_1;
#endif
   /* first, do SHA1                                                   */
   memcpy( imrl_sha1_state, D_ADSL_RCO1->imrc_sha1_state, sizeof(D_ADSL_RCO1->imrc_sha1_state) );
   m_put_le4( chrl_work1, imp_len_data );
   SHA1_Update( imrl_sha1_state, chrl_work1, 0, sizeof(int) );
   SHA1_Update( imrl_sha1_state, achp_data, 0, imp_len_data );
   if (D_ADSL_RSE1->chc_prot_rt03) {        /* flag for block count    */
     m_put_le4( chrl_work1, D_ADSL_RCO1->dsc_encry_cl2se.imc_count_sent );
     SHA1_Update( imrl_sha1_state, chrl_work1, 0, sizeof(int) );
   }
   SHA1_Final( imrl_sha1_state, chrl_work1, 0 );
   /* second, do MD5                                                   */
   memcpy( imrl_md5_state, D_ADSL_RCO1->imrc_md5_state, sizeof(D_ADSL_RCO1->imrc_md5_state) );
   MD5_Update( imrl_md5_state, chrl_work1, 0, 20 );
   MD5_Final( imrl_md5_state, chrl_work1, 0 );
   if (!memcmp( chrl_work1, D_ADSL_RSE1->chrc_inp_hash, sizeof(D_ADSL_RSE1->chrc_inp_hash) )) {
     return TRUE;
   }
   m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_check_hash_inp_rdp5() hash invalid",
                 __LINE__, 43376 );  /* line number for errors */
   return FALSE;
#ifdef OLD01
// SHA1_Init( imrl_sha1_array );
// SHA1_Update( imrl_sha1_array, D_ADSL_RCO1->chrc_sig, 0, sizeof(D_ADSL_RCO1->chrc_sig) );
   SHA1_Update( imrl_sha1_array, ACHL_PRE_HASH, 0, 16 * 3 );
   SHA1_Update( imrl_sha1_array, achp_client_random, 0, 32 );
   SHA1_Update( imrl_sha1_array, ADSL_RDPA_F->chrl_server_random, 0, 32 );
   SHA1_Final( imrl_sha1_array, ACHL_SHA_DIG, 0 );
   MD5_Init( ACHL_MD5_ARRAY );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_PRE_HASH, 0, 16 * 3 );
   MD5_Update( ACHL_MD5_ARRAY, ACHL_SHA_DIG, 0, 20 );
   MD5_Final( ACHL_MD5_ARRAY, ACHL_MASTER_H_3, 0 );
   return TRUE;
#endif
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RSE1
#undef D_ADSL_RCO1
#undef ADSL_OA1
#undef ADSL_RDPA_F
#endif
} /* end m_check_hash_inp_rdp5()                                       */

/** send RDP5-style input from client to server                        */
static BOOL m_send_cl2se_rdp5( struct dsd_hl_clib_1 *adsp_hl_clib_1,
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
                   __LINE__, 43449,  /* line number for errors */
                   imp_no_order );
     return FALSE;
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     m_sdh_printf( adsp_hl_clib_1, "xlrdpac1 l%05d s%05d m_send_cl2se_rdp5() output-area too small",
                   __LINE__, 43476 );  /* line number for errors */
     return FALSE;
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   iml1 = 1 + 1 + D_SIZE_HASH + imp_len_data;
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
                   __LINE__, 43518 );  /* line number for errors */
     return FALSE;
   }
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
   iml2 = 0;
   if (imp_no_order <= 15) {
     iml2 = imp_no_order << 2;
   }
   *achl_out++ = (char) (0XC0 | iml2);
   if (iml1 < 128) {                        /* length in one byte      */
     *achl_out++ = (char) iml1;             /* length follows          */
   } else {                                 /* length in two bytes     */
     *achl_out++ = (unsigned char) (0X80 | (iml1 >> 8));  /* length byte one follows */
     *achl_out++ = (unsigned char) iml1;    /* length byte two follows */
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
// adsl_gai1_out_2 = adsl_gai1_out_1;       /* save this field         */
   return TRUE;                             /* all done                */
#ifndef HL_RDPACC_HELP_DEBUG
#undef ADSL_OA1
#undef ADSL_RDPA_F
#endif
} /* end m_send_cl2se_rdp5()                                           */

static BOOL m_send_se2cl_const( struct dsd_hl_clib_1 *adsp_hl_clib_1,
                                struct dsd_output_area_1 *adsp_output_area_1,
                                char *achp_inp, int imp_len_inp ) {
#ifdef HL_RDPACC_HELP_DEBUG
   struct dsd_rdpa_f *ADSL_RDPA_F;
   struct dsd_rdp_server_1 *D_ADSL_RSE1;
   struct dsd_rdp_co *D_ADSL_RCO1;  /* RDP communication client */
   struct dsd_output_area_1 *ADSL_OA1;
#endif

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#define ADSL_OA1 adsp_output_area_1
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
#endif
#ifndef HL_RDPACC_HELP_DEBUG
#define D_ADSL_RSE1 (&ADSL_RDPA_F->dsc_rdp_se_1)
#define D_ADSL_RCO1 (&D_ADSL_RCL1->dsc_rdp_co_1)
#else
   D_ADSL_RSE1 = &ADSL_RDPA_F->dsc_rdp_se_1;
   D_ADSL_RCO1 = &D_ADSL_RSE1->dsc_rdp_co_1;
   ADSL_OA1 = adsp_output_area_1;
#endif
#ifdef TRACEHL1
   printf( "l%05d s%05d m_send_se2cl_const() ADSL_OA1->achc_lower=%p ADSL_OA1->achc_upper=%p\n",
           __LINE__, 44864, ADSL_OA1->achc_lower, ADSL_OA1->achc_upper );
#endif
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     printf( "output-area too small\n" );
     return FALSE;
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   ADSL_GAI1_OUT_G->achc_ginp_cur = achp_inp;
   ADSL_GAI1_OUT_G->achc_ginp_end = achp_inp + imp_len_inp;
   *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
   ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
   return TRUE;
#undef ADSL_GAI1_OUT_G
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RSE1
#undef D_ADSL_RCO1
#undef ADSL_OA1
#undef ADSL_RDPA_F
#endif
} /* end m_send_se2cl_const()                                          */


/* draw bitmap, send to server                                         */

static BOOL m_send_vch_out( struct dsd_hl_clib_1 *adsp_hl_clib_1,
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
   struct dsd_rdp_server_1 *D_ADSL_RSE1;
   struct dsd_rdp_co *D_ADSL_RCO1;  /* RDP communication server */
   struct dsd_output_area_1 *ADSL_OA1;
#endif

#ifndef HL_RDPACC_HELP_DEBUG
#define ADSL_RDPA_F ((struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext)
#define D_ADSL_RSE1 (&ADSL_RDPA_F->dsc_rdp_se_1)
#define D_ADSL_RCO1 (&D_ADSL_RSE1->dsc_rdp_co_1)
#define ADSL_OA1 adsp_output_area_1
#else
   ADSL_RDPA_F = (struct dsd_rdpa_f *) adsp_hl_clib_1->ac_ext;
   D_ADSL_RSE1 = &ADSL_RDPA_F->dsc_rdp_se_1;
   D_ADSL_RCO1 = &D_ADSL_RSE1->dsc_rdp_co_1;
   ADSL_OA1 = adsp_output_area_1;
#endif
   bol_compressed = FALSE;                  /* compress output         */
   if ((ADSL_OA1->achc_upper - ADSL_OA1->achc_lower) < 128) {  /* get new area */
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
   }
   ADSL_OA1->achc_upper -= sizeof(struct dsd_gather_i_1);
   if (ADSL_OA1->achc_upper < ADSL_OA1->achc_lower) {
     return FALSE;                          /* program illogic         */
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
   ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
   adsl_gai1_out_save = ADSL_GAI1_OUT_G;    /* save start output data  */
   /* compute where to start output                                    */
   achl_out_1 = ADSL_OA1->achc_lower + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1 + 2 + 4 + D_SIZE_HASH + 4 + 2 + 2;
#undef ADSL_GAI1_OUT_G
   achl_out_start = achl_out_1;             /* save position start output */
   adsl_gai1_w1 = adsp_sc_vch_out->adsc_gai1_data;  /* output data     */
   iml_out_len = 0;                         /* clear length output     */
   if (bol_compressed) goto psend_vch_08;   /* send virtual channel data compressed */
   memset( achl_out_1 - 2, 0, 2 );          /* clear compression flags */
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
       return FALSE;                        /* program illogic         */
     }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
     ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
   }
   goto psend_vch_20;                       /* output finished         */

   psend_vch_08:                            /* send virtual channel data compressed */
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
                     __LINE__, 61503,  /* line number for errors */
                     D_ADSL_RCO1->dsc_cdrf_enc.imc_return );
       return FALSE;                        /* do cleanup now          */
     }
     iml_out_len += D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur - achl_out_1;
     achl_out_1 = D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur;  /* set end of output */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set current end */
     if (D_ADSL_RCO1->dsc_cdrf_enc.boc_sr_flush) break;  /* end-of-record output */
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
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_client = ADSL_GAI1_OUT_G;  /* output data to client */
     ADSL_OA1->aadsc_gai1_out_to_client = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to client */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
   }
   *(achl_out_start - 2) = D_ADSL_RCO1->dsc_cdrf_enc.chrc_header[ 0 ];  /* copy compression header */
   *(achl_out_start - 1) = 0;               /* second byte compression header */

   psend_vch_20:                            /* output finished         */
   ADSL_OA1->achc_lower = ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set end of block */
   /* make header of output                                            */
   achl_out_start -= 4 + 2 + 2;             /* length uncompressed, segmentation flags and compression flags */
   m_put_le4( achl_out_start, adsp_sc_vch_out->umc_vch_ulen );
   memcpy( achl_out_start + 4, adsp_sc_vch_out->chrc_vch_segfl, sizeof(adsp_sc_vch_out->chrc_vch_segfl) );
   iml_out_len += 4 + 2 + 2;                /* add length output       */
   if ((ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent & (4096 - 1)) == 0){
     if (ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent) {
       m_update_keys( &ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1, &ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl, NULL );
     }
   }
   if (D_ADSL_RCO1->imc_sec_level > 1) {    /* with encryption         */
     /* generate random                                                */
#define ACHL_WORK_SHA1 ((int *) achp_work)
#define ACHL_WORK_MD5 ((int *) ((char *) ((char *) ACHL_WORK_SHA1 + SHA_ARRAY_SIZE * sizeof(int))))
#define ACHL_WORK_UTIL_01 ((char *) ACHL_WORK_MD5 + MD5_ARRAY_SIZE * sizeof(int))
     memcpy( ACHL_WORK_SHA1,
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_sha1_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_sha1_state) );
     memcpy( ACHL_WORK_MD5,
             ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_md5_state,
             sizeof(ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.imrc_md5_state) );
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
            ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.chrc_rc4_state );
       iml2 -= iml1;                        /* subtract data processed */
       if (iml2 <= 0) break;                /* all data processed      */
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next gather     */
       if (adsl_gai1_w1 == NULL) {          /* already end of chain    */
         return FALSE;                      /* program illogic         */
       }
     }
//   if (D_ADSL_RCL1->chc_prot_rt03 & 0X08) {  /* flag for block count */
       m_put_le4( ACHL_WORK_UTIL_01, ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent );
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
     ADSL_RDPA_F->dsc_rdp_se_1.dsc_rdp_co_1.dsc_encry_se2cl.imc_count_sent++;  /* count block sent */
   }
   achl_out_start -= 1 + 2 + 2;             /* length length, fl2, fl3, padding */
// *(achl_out_start + 1 + 0) = D_ADSL_RCL1->chc_prot_rt02;
// *(achl_out_start + 1 + 1) = D_ADSL_RCL1->chc_prot_rt03;
   *(achl_out_start + 1 + 0) = 0;
   *(achl_out_start + 1 + 1) = 0;
   if (D_ADSL_RCO1->imc_sec_level > 1) {    /* with encryption         */
     *(achl_out_start + 1 + 0) = 0X08;
     *(achl_out_start + 1 + 1) = 0X08;
   }
   /* two bytes padding zero                                           */
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
   *(achl_out_start + 4 + sizeof(ucrs_x224_p01)) = 0X68;  /* Send Data Indication */
   m_put_be2( achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1, D_USERID_SE2CL );
   m_put_be2( achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1 + 2, adsp_sc_vch_out->adsc_rdp_vc_1->usc_vch_no );
   *(achl_out_start + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2) = (unsigned char) 0XF0;  /* priority / segmentation */
   return TRUE;                             /* all done                */
#ifndef HL_RDPACC_HELP_DEBUG
#undef D_ADSL_RSE1
#undef D_ADSL_RCO1
#undef ADSL_OA1
#undef ADSL_RDPA_F
#endif
} /* end m_send_vch_out()                                              */

static BOOL m_send_vch_tose( struct dsd_hl_clib_1 *adsp_hl_clib_1,
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
   struct dsd_rdp_co *D_ADSL_RCO1;  /* RDP communication server */
   struct dsd_output_area_1 *ADSL_OA1;
#endif

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
                   __LINE__, 61767);  /* line number for errors */
     return FALSE;                          /* program illogic         */
   }
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
   ADSL_GAI1_OUT_G->adsc_next = NULL;
   *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
   ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
   adsl_gai1_out_save = ADSL_GAI1_OUT_G;    /* save start output data  */
   /* compute where to start output                                    */
   achl_out_1 = ADSL_OA1->achc_lower + 4 + sizeof(ucrs_x224_p01) + 1 + 2 + 2 + 1 + 2 + 4 + D_SIZE_HASH + 4 + 2 + 2;
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
                     __LINE__, 61830);  /* line number for errors */
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
                     __LINE__, 61877,  /* line number for errors */
                     D_ADSL_RCO1->dsc_cdrf_enc.imc_return );
       return FALSE;                        /* do cleanup now          */
     }
     iml_out_len += D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur - achl_out_1;
     achl_out_1 = D_ADSL_RCO1->dsc_cdrf_enc.achc_out_cur;  /* set end of output */
     ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set current end */
     if (D_ADSL_RCO1->dsc_cdrf_enc.boc_sr_flush) break;  /* end-of-record output */
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
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)
     ADSL_GAI1_OUT_G->adsc_next = NULL;
     ADSL_GAI1_OUT_G->achc_ginp_cur = ADSL_OA1->achc_lower;
     *ADSL_OA1->aadsc_gai1_out_to_server = ADSL_GAI1_OUT_G;  /* output data to server */
     ADSL_OA1->aadsc_gai1_out_to_server = &ADSL_GAI1_OUT_G->adsc_next;  /* new chain output data to server */
#undef ADSL_GAI1_OUT_G
     achl_out_1 = ADSL_OA1->achc_lower;     /* here is next output     */
   }
   *(achl_out_start - 2) = D_ADSL_RCO1->dsc_cdrf_enc.chrc_header[ 0 ];  /* copy compression header */
   *(achl_out_start - 1) = 0;               /* second byte compression header */

   psend_vch_20:                            /* output finished         */
   ADSL_OA1->achc_lower = ((struct dsd_gather_i_1 *) ADSL_OA1->achc_upper)->achc_ginp_end = achl_out_1;  /* set end of block */
   /* make header of output                                            */
   achl_out_start -= 4 + 2 + 2;             /* length uncompressed, segmentation flags and compression flags */
   m_put_le4( achl_out_start, adsp_sc_vch_out->umc_vch_ulen );
   memcpy( achl_out_start + 4, adsp_sc_vch_out->chrc_vch_segfl, sizeof(adsp_sc_vch_out->chrc_vch_segfl) );
   iml_out_len += 4 + 2 + 2;                /* add length output       */
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
   achl_out_start -= 1 + 2 + 2;             /* length length, fl2, fl3, padding */
// *(achl_out_start + 1 + 0) = D_ADSL_RCL1->chc_prot_rt02;
// *(achl_out_start + 1 + 1) = D_ADSL_RCL1->chc_prot_rt03;
// 25.04.12 KB - send virtual channel always encrypted to server
   {
     *(achl_out_start + 1 + 0) = 0X08;
     *(achl_out_start + 1 + 1) = 0X08;
   }
   /* two bytes padding zero                                           */
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
static int m_sdh_printf( struct dsd_hl_clib_1 *adsp_hl_clib_1, char *achptext, ... ) {
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
static void m_sdh_console_out( struct dsd_hl_clib_1 *adsp_hl_clib_1,
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

static char * m_ret_t_ied_fcfp_bl( ied_fcfp_bl iel_fcfp_bl ) {
   switch (iel_fcfp_bl) {
     case ied_fcfp_invalid:                 /* invalid data received   */
       return "ied_fcfp_invalid";
     case ied_fcfp_constant:                /* is in constant          */
       return "ied_fcfp_constant";
     case ied_fcfp_x224_p01:                /* is in x224 header       */
       return "ied_fcfp_x224_p01";
     case ied_fcfp_ignore:                  /* ignore data             */
       return "ied_fcfp_ignore";
     case ied_fcfp_copy_normal:             /* copy data normal        */
       return "ied_fcfp_copy_normal";
     case ied_fcfp_copy_invers:             /* copy data invers        */
       return "ied_fcfp_copy_invers";
     case ied_fcfp_rdp5_rc4:                /* input RC4 encrypted     */
       return "ied_fcfp_rdp5_rc4";
     case ied_fcfp_rec_type:                /* receive record type     */
       return "ied_fcfp_rec_type";
     case ied_fcfp_byte01:                  /* receive byte 01         */
       return "ied_fcfp_byte01";
     case ied_fcfp_lencons_2:               /* two bytes length remain */
       return "ied_fcfp_lencons_2";
     case ied_fcfp_lencons_1:               /* one byte length remains */
       return "ied_fcfp_lencons_1";
     case ied_fcfp_r4_collect:              /* RDP 4 collect data      */
       return "ied_fcfp_r4_collect";
     case ied_fcfp_rdp5_len1:               /* RDP5 input length 1     */
       return "ied_fcfp_rdp5_len1";
     case ied_fcfp_rdp5_len2:               /* RDP5 input length 2     */
       return "ied_fcfp_rdp5_len2";
     case ied_fcfp_mcs_c1:                  /* x224 MCS command 1      */
       return "ied_fcfp_mcs_c1";
     case ied_fcfp_userid:                  /* userid communication    */
       return "ied_fcfp_userid";
     case ied_fcfp_chno:                    /* receive channel no      */
       return "ied_fcfp_chno";
     case ied_fcfp_prio_seg:                /* Priority / Segmentation */
       return "ied_fcfp_prio_seg";
     case ied_fcfp_rt02:                    /* record type 2           */
       return "ied_fcfp_rt02";
     case ied_fcfp_rt03:                    /* record type 3           */
       return "ied_fcfp_rt03";
     case ied_fcfp_padd_1:                  /* padding                 */
       return "ied_fcfp_padd_1";
     case ied_fcfp_asn1_tag:                /* ASN.1 tag follows       */
       return "ied_fcfp_asn1_tag";
     case ied_fcfp_asn1_l1_fi:              /* ASN.1 length field      */
       return "ied_fcfp_asn1_l1_fi";
     case ied_fcfp_asn1_l1_p2:              /* ASN.1 length part two   */
       return "ied_fcfp_asn1_l1_p2";
     case ied_fcfp_mu_len_1:                /* multi length 1          */
       return "ied_fcfp_mu_len_1";
     case ied_fcfp_mu_len_2:                /* multi length 2          */
       return "ied_fcfp_mu_len_2";
     case ied_fcfp_int_lit_e:               /* int little endian       */
       return "ied_fcfp_int_lit_e";
     case ied_fcfp_int_big_e:               /* int big endian          */
       return "ied_fcfp_int_big_e";
     case ied_fcfp_send_from_client:        /* send data to server     */
       return "ied_fcfp_send_from_client";
     case ied_fcfp_end_com:                 /* end of communication    */
       return "ied_fcfp_end_com";
     case ied_fcfp_no_session:              /* no more session         */
       return "ied_fcfp_no_session";
   }
   return "-undef-";
}  /* end m_ret_t_ied_fcfp_bl()                                        */

static char * m_ret_t_ied_fsfp_bl( ied_fsfp_bl iel_fsfp_bl ) {
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
     case ied_fsfp_r4_collect:              /* RDP 4 collect data      */
       return "ied_fsfp_r4_collect";
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
     case ied_fsfp_r5_collect:              /* RDP 5 collect data      */
       return "ied_fsfp_r5_collect";
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

static char * m_ret_t_ied_frcl_bl( ied_frcl_bl iel_frcl_bl ) {
   switch (iel_frcl_bl) {
     case ied_frcl_start:                   /* start of communication  */
       return "ied_frcl_start";
     case ied_frcl_rec_02:                  /* receive block 2         */
       return "ied_frcl_rec_02";
     case ied_frcl_r02_x224mcs:             /* proc bl 2 X.224 MCS     */
       return "ied_frcl_r02_x224mcs";
     case ied_frcl_r02_mcscoen:             /* b2 MCS connect encoding */
       return "ied_frcl_r02_mcscoen";
     case ied_frcl_r02_mc_cids:             /* b2 MC Calling Domain Selector */
       return "ied_frcl_r02_mc_cids";
     case ied_frcl_r02_mc_ceds:             /* b2 MC Called Domain Selector */
       return "ied_frcl_r02_mc_ceds";
     case ied_frcl_r02_mc_upwf:             /* b2 MC Upward Flag       */
       return "ied_frcl_r02_mc_upwf";
     case ied_frcl_r02_mc_tdop:             /* b2 MC Target Domain Parameters */
       return "ied_frcl_r02_mc_tdop";
     case ied_frcl_r02_mc_midp:             /* b2 MC Minimum Domain Parameters */
       return "ied_frcl_r02_mc_midp";
     case ied_frcl_r02_mc_madp:             /* b2 MC Maximum Domain Parameters */
       return "ied_frcl_r02_mc_madp";
     case ied_frcl_r02_mc_usd1:             /* b2 MC User Data Start   */
       return "ied_frcl_r02_mc_usd1";
     case ied_frcl_r02_mcud_l1:             /* b2 MC Us-Da length 1    */
       return "ied_frcl_r02_mcud_l1";
     case ied_frcl_r02_fietype:             /* b2 MC Field Type        */
       return "ied_frcl_r02_fietype";
     case ied_frcl_r02_fielen:              /* b2 MC Field Length      */
       return "ied_frcl_r02_fielen";
     case ied_frcl_r02_mcud_c01:            /* b2 MC Us-Da const 01    */
       return "ied_frcl_r02_mcud_c01";
     case ied_frcl_r02_mcud_scw:            /* b2 MC Us-Da scr width   */
       return "ied_frcl_r02_mcud_scw";
     case ied_frcl_r02_mcud_sch:            /* b2 MC Us-Da scr height  */
       return "ied_frcl_r02_mcud_sch";
     case ied_frcl_r02_mcud_c02:            /* b2 MC Us-Da const 02    */
       return "ied_frcl_r02_mcud_c02";
     case ied_frcl_r02_mcud_kbl:            /* b2 MC Us-Da Keyboard La */
       return "ied_frcl_r02_mcud_kbl";
     case ied_frcl_r02_mcud_bun:            /* b2 MC Us-Da Build Numb  */
       return "ied_frcl_r02_mcud_bun";
     case ied_frcl_r02_mcud_con:            /* b2 MC Us-Da Computer Na */
       return "ied_frcl_r02_mcud_con";
     case ied_frcl_r02_mcud_kbt:            /* b2 MC Us-Da Keyboard Ty */
       return "ied_frcl_r02_mcud_kbt";
     case ied_frcl_r02_mcud_kbs:            /* b2 MC Us-Da Keyboard ST */
       return "ied_frcl_r02_mcud_kbs";
     case ied_frcl_r02_mcud_nfk:            /* b2 MC Us-Da No Func Key */
       return "ied_frcl_r02_mcud_nfk";
     case ied_frcl_r02_mcud_ime:            /* b2 MC Us-Da IME Keyb ma */
       return "ied_frcl_r02_mcud_ime";
     case ied_frcl_r02_mcud_c03:            /* b2 MC Us-Da const 03    */
       return "ied_frcl_r02_mcud_c03";
     case ied_frcl_r02_mcud_pv1:            /* b2 MC Us-Da protocol ve */
       return "ied_frcl_r02_mcud_pv1";
     case ied_frcl_r02_mcud_cod:            /* b2 MC Us-Da Color Depth */
       return "ied_frcl_r02_mcud_cod";
     case ied_frcl_r02_mcud_sup_cod:        /* b2 MC Us-Da supported Color Depth */
       return "ied_frcl_r02_mcud_sup_cod";
     case ied_frcl_r02_mcud_early_cf:       /* b2 MC Us-Da early capability flag */
       return "ied_frcl_r02_mcud_early_cf";
     case ied_frcl_r02_mcud_nvc:            /* b2 MC Us-Da no virt ch  */
       return "ied_frcl_r02_mcud_nvc";
     case ied_frcl_r02_mcud_vcn:            /* b2 MC Us-Da virt ch nam */
       return "ied_frcl_r02_mcud_vcn";
     case ied_frcl_r02_mcud_vcf:            /* b2 MC Us-Da virt ch fla */
       return "ied_frcl_r02_mcud_vcf";
     case ied_frcl_rdp5_inp:                /* RDP5-style input data   */
       return "ied_frcl_rdp5_inp";
     case ied_frcl_rec_05:                  /* receive block 5         */
       return "ied_frcl_rec_05";
     case ied_frcl_rec_06:                  /* receive block 6         */
       return "ied_frcl_rec_06";
     case ied_frcl_cjreq_rec:               /* receive block channel join request */
       return "ied_frcl_cjreq_rec";
     case ied_frcl_clrand_rec:   /* ??? */  /* receive client random   */
       return "ied_frcl_clrand_rec";
     case ied_frcl_client_rand:             /* receive client random   */
       return "ied_frcl_client_rand";
     case ied_frcl_c_logon_info_1:          /* logon information 1     */
       return "ied_frcl_c_logon_info_1";
     case ied_frcl_c_loinf_options:         /* Options                 */
       return "ied_frcl_c_loinf_options";
     case ied_frcl_c_loinf_domna_len:       /* Domain Name Length      */
       return "ied_frcl_c_loinf_domna_len";
     case ied_frcl_c_loinf_userna_len:      /* User Name Length        */
       return "ied_frcl_c_loinf_userna_len";
     case ied_frcl_c_loinf_pwd_len:         /* Password Length         */
       return "ied_frcl_c_loinf_pwd_len";
     case ied_frcl_c_loinf_altsh_len:       /* Alt Shell Length        */
       return "ied_frcl_c_loinf_altsh_len";
     case ied_frcl_c_loinf_wodir_len:       /* Working Directory Length */
       return "ied_frcl_c_loinf_wodir_len";
     case ied_frcl_c_loinf_domna_val:       /* Domain Name String      */
       return "ied_frcl_c_loinf_domna_val";
     case ied_frcl_c_loinf_userna_val:      /* User Name String        */
       return "ied_frcl_c_loinf_userna_val";
     case ied_frcl_c_loinf_pwd_val:         /* Password String         */
       return "ied_frcl_c_loinf_pwd_val";
     case ied_frcl_c_loinf_altsh_val:        /* Alt Shell String        */
       return "ied_frcl_c_loinf_altsh_val";
     case ied_frcl_c_loinf_wodir_val:       /* Working Directory String */
       return "ied_frcl_c_loinf_wodir_val";
     case ied_frcl_c_loinf_no_a_par:        /* number of additional parameters */
       return "ied_frcl_c_loinf_no_a_par";
     case ied_frcl_c_loinf_ineta:           /* INETA                   */
       return "ied_frcl_c_loinf_ineta";
     case ied_frcl_c_loinf_path:            /* Client Path             */
       return "ied_frcl_c_loinf_path";
     case ied_frcl_c_loinf_extra:           /* Extra Parameters        */
       return "ied_frcl_c_loinf_extra";
     case ied_frcl_lic_01:                  /* licencing block to check */
       return "ied_frcl_lic_01";
     case ied_frcl_lic_clrand:              /* New Licence Request / Client License Info */
       return "ied_frcl_lic_clrand";
     case ied_frcl_resp_act_pdu_rec:        /* response block active PDU */
       return "ied_frcl_resp_act_pdu_rec";
     case ied_frcl_rdp4_vch_ulen:           /* virtual channel uncompressed data length */
       return "ied_frcl_rdp4_vch_ulen";
     case ied_frcl_rec_xyz_01:              /* ?????nse block active PDU */
       return "ied_frcl_rec_xyz_01";
   }
   return "-undef-";
}  /* end m_ret_t_ied_frcl_bl()                                        */

static char * m_ret_t_ied_frse_bl( ied_frse_bl iel_frse_bl ) {
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
     case ied_frse_r04_keytype:             /* block 4 security keytype */
       return "ied_frse_r04_keytype";
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
     case ied_frse_r5_pdu_ord_buf:          /* RDP 5 PDU order buffer  */
       return "ied_frse_r5_pdu_ord_buf";
     case ied_frse_r5_pdu_primord:          /* RDP 5 PDU primary order */
       return "ied_frse_r5_pdu_primord";
     case ied_frse_r5_pdu_apply_order:      /* RDP 5 PDU apply order   */
       return "ied_frse_r5_pdu_apply_order";
     case ied_frse_r5_ign_single_unic:      /* ignore one single Unicode character */
       return "ied_frse_r5_ign_single_unic";
     case ied_frse_ordsec_brush_header:     /* secondary order brush header */
       return "ied_frse_ordsec_brush_header";
     case ied_frse_ordsec_brush_data:       /* secondary order brush data */
       return "ied_frse_ordsec_brush_data";
     case ied_frse_ordsec_cache_glyph:      /* secondary order cache glyph */
       return "ied_frse_ordsec_cache_glyph";
     case ied_frse_xyz_end_pdu:             /* end of PDU              */
       return "ied_frse_xyz_end_pdu";
     case ied_frse_xyz_end_order:           /* end of order            */
       return "ied_frse_xyz_end_order";
     case ied_frse_hrdpext1_01:             /* HOB-RDP-EXT1 data       */
       return "ied_frse_hrdpext1_01";
     case ied_ad_inv_user_x:                /* userid invalid - not fo */
       return "ied_ad_inv_user_x";
     case ied_ad_inv_password_x:            /* password invalid        */
       return "ied_ad_inv_password_x";
   }
   return "-undef-";
}  /* end m_ret_t_ied_frse_bl()                                        */
