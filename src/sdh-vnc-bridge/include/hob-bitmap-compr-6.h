/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-bitmap-compr-6.h                                |*/
/*| -------------                                                     |*/
/*|  HOB Header file for RDP 6.0 Bitmap Compression                   |*/
/*|  SM 27.02.10                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC all platforms                                                |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef DEF_HL_HOB_BITMAP_COMPR_6_H__
#define DEF_HL_HOB_BITMAP_COMPR_6_H__

#ifdef WIN32
#include <windows.h>
#else
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hob-hunix01.h"
#endif

#include <hob-bitmap-compr-1.h>

/* Reserved size is a gather structure. */
#define BITMAP_COMPR_6_RESERVED_SIZE			sizeof(dsd_gather_i_1)
/* Header size for RDP6 compression. */
#define _BITMAP_COMPR_6_HEADER_SIZE           1

/* Maximum size of a compressed plane. */
#define _BITMAP_COMPR_6_MAX_COMPR_PLANE(w, h, compression_flags) ((((w) + (((compression_flags) & dsd_bitmap_compr_6::FLAG_NO_UNCOMPRESSED) != 0 ? (((w)+15-1)/15) : 0)) * (h)))
/* Number of "extra long run 47" entries for the specified run count. */
#define _BITMAP_COMPR_6_MAX_COMPR_FIXED_LR2(run) (((run)+15)/47)
/* Number of "extra long run 31" entries for the specified run count. */
#define _BITMAP_COMPR_6_MAX_COMPR_FIXED_LR1(run) ((((run)+15)-_BITMAP_COMPR_6_MAX_COMPR_FIXED_LR2((run))*47)/31)
/* Number of "short run" entries for the specified run count. */
#define _BITMAP_COMPR_6_MAX_COMPR_FIXED_SR(run) (((((run)+0)+14)-_BITMAP_COMPR_6_MAX_COMPR_FIXED_LR2(run)*47-_BITMAP_COMPR_6_MAX_COMPR_FIXED_LR1(run)*31)/15)
/* Number of bytes used to encode the specified run count. */
#define _BITMAP_COMPR_6_MAX_COMPR_FIXED_RLE(run) (_BITMAP_COMPR_6_MAX_COMPR_FIXED_LR2(run) + _BITMAP_COMPR_6_MAX_COMPR_FIXED_LR1(run) + _BITMAP_COMPR_6_MAX_COMPR_FIXED_SR(run))
/* Fixed value: Size of the first line in bytes (value assumed to be non-zero). */
#define _BITMAP_COMPR_6_MAX_COMPR_FIXED_LINE0(w) ((w) <= 3 ? ((w)+1) : (2 + _BITMAP_COMPR_6_MAX_COMPR_FIXED_RLE((w)-15-1)))
/* Fixed value: Size of the plane in bytes. */
#define _BITMAP_COMPR_6_MAX_COMPR_FIXED(w, h, compression_flags) (_BITMAP_COMPR_6_MAX_COMPR_FIXED_LINE0(w) + ((_BITMAP_COMPR_6_MAX_COMPR_FIXED_RLE(w)) * ((h)-1)))

/* Number of large color planes (subsampling). */
#define _BITMAP_COMPR_6_PLANES_NOSS(compression_flags) ((((compression_flags) & dsd_bitmap_compr_6::FLAG_SUBSAMPLING) != 0) ? 1 : 3)
/* Number of small color planes (subsampling). */
#define _BITMAP_COMPR_6_PLANES_SS(compression_flags) ((((compression_flags) & dsd_bitmap_compr_6::FLAG_SUBSAMPLING) != 0) ? 2 : 0)

/* Maximum output size of an image. */
#define _BITMAP_COMPR_6_MAX_COMPR_SIZE(w, h, compression_flags) \
	(((((compression_flags) & dsd_bitmap_compr_6::FLAG_HAS_ALPHA) != 0) \
		? ((_BITMAP_COMPR_6_PLANES_NOSS(compression_flags)+1) * _BITMAP_COMPR_6_MAX_COMPR_PLANE(w, h, compression_flags)) \
		: (_BITMAP_COMPR_6_PLANES_NOSS(compression_flags) * _BITMAP_COMPR_6_MAX_COMPR_PLANE(w, h, compression_flags)) \
		+ ((((compression_flags) & dsd_bitmap_compr_6::FLAG_SKIP_ALPHA) != 0) ? 0 : _BITMAP_COMPR_6_MAX_COMPR_FIXED(w, h, compression_flags))) \
		+ _BITMAP_COMPR_6_PLANES_SS(compression_flags) * _BITMAP_COMPR_6_MAX_COMPR_PLANE(((w)+1)>>1, ((h)+1)>>1, compression_flags))

/* Maximum output size of an image (including header). */
#define BITMAP_COMPR_6_MAX_OUT(w, h, compression_flags)  (_BITMAP_COMPR_6_HEADER_SIZE + _BITMAP_COMPR_6_MAX_COMPR_SIZE(w, h, compression_flags))
/* Maximum buffer size needed for output. */
#define BITMAP_COMPR_6_MAX_SIZE(w, h, compression_flags)	(BITMAP_COMPR_6_MAX_OUT(w, h, compression_flags) + BITMAP_COMPR_6_RESERVED_SIZE)
/* Maximum output size of an image. */
#define BITMAP_COMPR_1_MAX_OUT(w, h, bypp)  ((w) * (h) * (bypp))
/* Maximum buffer size needed for output. */
#define BITMAP_COMPR_1_MAX_SIZE(w, h, bypp)	(BITMAP_COMPR_1_MAX_OUT(w, h, bypp) + BITMAP_COMPR_6_RESERVED_SIZE)
/* Maximum number of pixels that can be compressed at once. */
#define BITMAP_COMPR_6_MAX_PIXELS	8192

/**
 * Indicates that the bitmap is RLE compressed.
 */
#define BITMAP_COMPR_6_RLE_COMPRESSED_FLAG	0x10
#define BITMAP_COMPR_6_NO_ALPHA_FLAG			0x20
#define BITMAP_COMPR_6_COLOR_SUBSAMPLING_FLAG 0x08

#define BITMAP_COMPR_6_WRITE_OUTPUT				1
#define BITMAP_COMPR_6_WRITE_RLE_SEGMENT		1
#define BITMAP_COMPR_6_WRITE_RESERVED			1
#define BITMAP_COMPR_6_DEBUG_COMPRESS			0
#define BITMAP_COMPR_6_VERIFY_COMPRESS			0
#define BITMAP_COMPR_6_HOB_STYLE					0
#define BITMAP_COMPR_6_ALPHA_UNCOMPRESSED		0
#define BITMAP_COMPR_6_NO_UNCOMPRESSED		   1

#if BITMAP_COMPR_6_HOB_STYLE
#define CALC_CHANGE(run_count) (3 - im_run_count)
#else
#define CALC_CHANGE(run_count) 2
#endif

struct dsd_bitmap_compr_6 :  public dsd_bitmap_compr_1 {
   enum {
      FLAG_HAS_ALPHA = 0x1,
      FLAG_SKIP_ALPHA = 0x2,
      FLAG_SKIP_ALPHA_UNCOMPRESSED = 0x4,
      FLAG_SUBSAMPLING = 0x8,
      FLAG_GRAY_COLOR = 0x10,
#if BITMAP_COMPR_6_NO_UNCOMPRESSED
      FLAG_NO_UNCOMPRESSED = 0x20
#endif      
   };

   int inc_compression_flags;
	int inc_cll;
};

extern "C" BOOL m_bitmap_compr_6( struct dsd_bitmap_compr_1 * );

#endif /*!DEF_HL_HOB_BITMAP_COMPR_6_H__*/
