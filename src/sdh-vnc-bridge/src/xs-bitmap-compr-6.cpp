/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-bitmap-compr-6                                   |*/
/*| -------------                                                     |*/
/*|  RDP 6.0 bitmap compression                                       |*/
/*|  SM 15.02.11                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/




/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include "hob-bitmap-compr-6.h"
#include <hob/util/hob-tk-types.h>
#include <stdexcept>
#undef min
#undef max

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
#define BITMAP_COMPR_6_COCGY						1

#define BITMAP_COMPR_6_USE_RUN_COUNTER			1
#ifndef BITMAP_COMPR_6_USE_SSE2
#define BITMAP_COMPR_6_USE_SSE2					0
#endif
#define BITMAP_COMPR_6_USE_COMPRESS_LINE		1

#define BITMAP_COMPR_6_USE_SSE2_ALIGNED		0

#define min(a, b) ((a) < (b) ? (a) : (b))
#if BITMAP_COMPR_6_USE_SSE2
#include <emmintrin.h>
#endif

#if HOB_UNIX
#include <strings.h>
#endif

#if BITMAP_COMPR_6_HOB_STYLE
#define CALC_CHANGE(run_count) (3 - im_run_count)
#else
#define CALC_CHANGE(run_count) 2
#endif

//typedef int pint_t;
typedef unsigned int pint_t;

class c_simple_writer {
	char* ach_cur;
	char* ach_stop;
	char* ach_start;
	char* ach_end;
   struct dsd_bitmap_compr_1* adsc_bmc1;

public:
	c_simple_writer(struct dsd_bitmap_compr_1* adsp_bmc1)
      : ach_cur(adsp_bmc1->achc_wa_free_start), ach_stop(adsp_bmc1->achc_wa_free_end),
      ach_start(adsp_bmc1->achc_wa_free_start), ach_end(adsp_bmc1->achc_wa_free_end),
      adsc_bmc1(adsp_bmc1)
	{}

	int get_position() const {
		return (int)(this->ach_cur - this->ach_start);
	}

	bool write_byte(char ch_cur) {
#if !BITMAP_COMPR_6_WRITE_RESERVED
		if(this->ach_cur >= this->ach_stop)
			return false;
#endif
#if BITMAP_COMPR_6_WRITE_OUTPUT
		*this->ach_cur++ = ch_cur;
#else
		this->ach_cur++;
#endif
		return true;
	}

	bool write_bytes(unsigned char ch_val, int in_count) {
#if !BITMAP_COMPR_6_WRITE_RESERVED
		if(this->ach_cur+in_count > this->ach_stop)
			return false;
#endif
		memset(this->ach_cur, ch_val, in_count);
		this->ach_cur += in_count;
		//this->im_position++;
		return true;
	}

	/* Writes bytes at the current position. */
	bool write(char* auc_data, int in_count) {
#if !BITMAP_COMPR_6_WRITE_RESERVED
		if(this->ach_cur+in_count > this->ach_stop)
			return false;
#endif
		memcpy(this->ach_cur, auc_data, in_count);
		this->ach_cur += in_count;
		return true;
	}

	bool copy_memory(int im_pos, int in_bytes) {
#if !BITMAP_COMPR_6_WRITE_RESERVED
		if(this->ach_cur+in_bytes > this->ach_stop)
			return false;
#endif
		memcpy(this->ach_cur, this->ach_start + im_pos, in_bytes);
		this->ach_cur += in_bytes;
		return true;
	}

	bool skip(int in_bytes) {
		char* ach_cur = this->ach_cur + in_bytes;
		if(ach_cur > this->ach_stop)
			return false;
		this->ach_cur = ach_cur;
		//this->im_position += in_bytes;
		return true;
	}

	bool reserve(int in_bytes) {
		return (this->ach_cur + in_bytes <= this->ach_stop);
	}

	void seek(int im_pos) {
		this->ach_cur += im_pos - this->get_position();
	}

	void set_stop(int im_pos) {
		this->ach_stop = this->ach_start + im_pos;
		if(this->ach_stop > this->ach_end)
			this->ach_stop = this->ach_end;
	}

	void done() {
      this->adsc_bmc1->adsc_gai1_out->achc_ginp_end = this->ach_cur;
      this->adsc_bmc1->achc_wa_free_start = this->ach_cur;
	}
};

class c_gather_writer {
	/* Bitmap compression object. */
	struct dsd_bitmap_compr_1* adsc_bmc1;
	/* The current gather. */
	struct dsd_gather_i_1 *adsc_gai1_last;
	/* Absolute start position of the current gather. */
	int im_position_abs;
	/* Start of the current gather. */
	char* ach_start;
	/* End of the current gather. */
	char* ach_end;
	/* Position in the current gather. */
	char* ach_cur;
	/* Stop position in the currrent gather. */
	char* ach_stop;
	/* Absolute stop position. */
	int im_position_stop;

	BOOL m_next_gather()
	{
		int im_available = this->im_position_stop-this->get_position();
		if(im_available <= 0)
			return FALSE;
		struct dsd_gather_i_1 * ads_ginp_new = this->adsc_gai1_last->adsc_next;
		if(ads_ginp_new == NULL) {
			this->adsc_gai1_last->achc_ginp_end = this->ach_cur;
			BOOL bol1 = adsc_bmc1->amc_get_workarea( adsc_bmc1 );
			if (bol1 == FALSE)
				return FALSE;
			adsc_bmc1->achc_wa_free_end -= sizeof(struct dsd_gather_i_1);
			if(adsc_bmc1->achc_wa_free_start >= adsc_bmc1->achc_wa_free_end)
				return FALSE;
			ads_ginp_new = ((struct dsd_gather_i_1 *) adsc_bmc1->achc_wa_free_end);
			ads_ginp_new->adsc_next = NULL;
			ads_ginp_new->achc_ginp_cur = adsc_bmc1->achc_wa_free_start;
			ads_ginp_new->achc_ginp_end = adsc_bmc1->achc_wa_free_end;
			this->adsc_gai1_last->adsc_next = ads_ginp_new;
		}
		this->adsc_gai1_last = ads_ginp_new;
		this->im_position_abs += (int)(this->ach_cur - this->ach_start);
		this->ach_start = ads_ginp_new->achc_ginp_cur;
		this->ach_cur = ads_ginp_new->achc_ginp_cur;
		this->ach_end = ads_ginp_new->achc_ginp_end;
		this->ach_stop = ads_ginp_new->achc_ginp_end;
		int in_chunk_size = (int)(this->ach_end - this->ach_start);
		if(in_chunk_size > im_available)
			this->ach_stop = this->ach_start + im_available;
		return TRUE;
	}
public:
	c_gather_writer(struct dsd_bitmap_compr_1* adsp_bmc1)
		: adsc_bmc1(adsp_bmc1), adsc_gai1_last(adsp_bmc1->adsc_gai1_out), im_position_abs(0),
		  ach_start(adsc_gai1_last->achc_ginp_cur), ach_end(adsc_gai1_last->achc_ginp_end),
		  ach_cur(ach_start), ach_stop(ach_end), im_position_stop(0x7fffffff)
	{}

	/* Get the absolute position in the stream. */
	int get_position() const {
		return this->im_position_abs + (int)(this->ach_cur - this->ach_start);
	}

	/* Writes a single byte. */
	bool write_byte(char ch_cur) {
		if(this->ach_cur >= this->ach_stop && !this->m_next_gather())
			return false;
#if BITMAP_COMPR_6_WRITE_OUTPUT
		*this->ach_cur++ = ch_cur;
#else
		this->ach_cur++;
#endif
		return true;
	}

	/* Writes a value multiple times at the current position. */
	bool write_bytes(unsigned char ch_val, int in_count) {
		while(in_count > 0) {
			if(this->ach_cur >= this->ach_stop && !this->m_next_gather())
				return false;
			int in_rest = min((int)(this->ach_stop - this->ach_cur), in_count);
			memset(this->ach_cur, ch_val, in_rest);
			this->ach_cur += in_rest;
			in_count -= in_rest;
		}
		return true;
	}

	/* Writes bytes at the current position. */
	bool write(char* auc_data, int in_count) {
		while(in_count > 0) {
			if(this->ach_cur >= this->ach_stop && !this->m_next_gather())
				return false;
			int in_rest = min((int)(this->ach_stop - this->ach_cur), in_count);
			memcpy(this->ach_cur, auc_data, in_rest);
			auc_data += in_rest;
			this->ach_cur += in_rest;
			in_count -= in_rest;
		}
		return true;
	}

	/* Copies memory within the data stream. */
	bool copy_memory(int im_pos, int in_bytes) {
		/* Run to the segment that contains the start position. */
		dsd_gather_i_1 *adsc_gai1_cur = this->adsc_bmc1->adsc_gai1_out;
		int im_src_pos = 0;
		while(adsc_gai1_cur != NULL) {
			int im_gather_len = (int)(adsc_gai1_cur->achc_ginp_end-adsc_gai1_cur->achc_ginp_cur);
			if(im_src_pos+im_gather_len > im_pos)
				break;
			im_src_pos += im_gather_len;
			adsc_gai1_cur = adsc_gai1_cur->adsc_next;
		}
		if(adsc_gai1_cur == NULL)
			return false;
		char* ach_src = adsc_gai1_cur->achc_ginp_cur + (im_pos-im_src_pos);
		int in_rest = min((int)(adsc_gai1_cur->achc_ginp_end - ach_src), in_bytes);
		if(!this->write(ach_src, in_rest))
			return false;
		in_bytes -= in_rest;
		/* More segments to read? */
		while(in_bytes > 0) {
			adsc_gai1_cur = adsc_gai1_cur->adsc_next;
			if(adsc_gai1_cur == NULL)
				return false;
			char* ach_src = adsc_gai1_cur->achc_ginp_cur;
			int in_rest = min((int)(adsc_gai1_cur->achc_ginp_end - ach_src), in_bytes);
			if(!this->write(ach_src, in_rest))
				return false;
			in_bytes -= in_rest;
		}
		return true;
	}

	/* Skips the specified length. */
	bool skip(int in_count) {
		while(in_count > 0) {
			if(this->ach_cur >= this->ach_stop && !this->m_next_gather())
				return false;
			int in_rest = min((int)(this->ach_stop - this->ach_cur), in_count);
			this->ach_cur += in_rest;
			in_count -= in_rest;
		}
		return true;
	}

	/* Ensures that the stream can write the specified number of bytes. */
	bool reserve(int in_bytes) {
		if(this->ach_cur+in_bytes <= this->ach_stop)
			return true;
		return (this->get_position() + in_bytes <= this->im_position_stop);
	}

	/* Seeks to an absolute position. */
	void seek(int im_pos) {
		/* Is position before current gather? */
		if(im_pos < this->im_position_abs) {
			/* Reset to the beginning. */
			struct dsd_gather_i_1* ads_ginp_new = this->adsc_bmc1->adsc_gai1_out;
			this->adsc_gai1_last = ads_ginp_new;  /* last output data    */
			this->im_position_abs = 0;
			this->ach_start = adsc_gai1_last->achc_ginp_cur;
			this->ach_end = adsc_gai1_last->achc_ginp_end;
			this->ach_cur = this->ach_start;
			this->ach_stop = this->ach_end;
			int in_chunk_size = (int)(this->ach_end - this->ach_start);
			int im_available = this->im_position_stop-this->get_position();
			if(in_chunk_size > im_available)
				this->ach_stop = this->ach_start + im_available;
		}
		/* Is inside current gather, but before the current position? */
		int im_delta = im_pos - this->get_position();
		if(im_delta < 0) {
			this->ach_cur += im_delta;
			return;
		}
		/* Skip forward. */
		this->skip(im_delta);
	}

	/* Sets an absolute stop position. */
	void set_stop(int im_pos) {
		this->im_position_stop = im_pos;
		int in_rest = (int)(im_pos - this->im_position_abs);
		this->ach_stop = this->ach_start + in_rest;
		if(this->ach_stop > this->ach_end)
			this->ach_stop = this->ach_end;
	}

	/* Does some commit stuff. */
	void done() {
		this->adsc_gai1_last->achc_ginp_end = this->ach_cur;
      this->adsc_bmc1->achc_wa_free_start = this->ach_cur;
   }
};

template<int IM_STEP, class WRITER> static bool copy_uncompressed_plane(unsigned char* axxl_src, int im_width, int im_pad_bytes, int im_scanline, int im_height, WRITER& rds_w) {
   int in_size = (im_width + im_pad_bytes) * im_height;
   if(!rds_w.reserve(in_size))
      return FALSE;
	while(--im_height >= 0) {
		if(IM_STEP != 1) {
			unsigned char* auc_cur = axxl_src;
			unsigned char* axxl_end = auc_cur + (im_width * IM_STEP);
			while(auc_cur < axxl_end) {
				if(!rds_w.write_byte(*auc_cur))
					return false;
				auc_cur += IM_STEP;
			}
		}
		else {
			rds_w.write((char*)axxl_src, im_width);
		}
		rds_w.write_bytes(0, im_pad_bytes);
		axxl_src += im_scanline;
	}
	return true;
}

#if BITMAP_COMPR_6_DEBUG_COMPRESS
template<class WRITER> static void check_byte(WRITER& rds_w) {
}

template<int IM_STEP> static void dump_line(const unsigned char* auc_src, int im_width) {
	unsigned char ucr_line[4096];
	for(int im_i=0; im_i<im_width; im_i++) {
		ucr_line[im_i] = auc_src[0];
		auc_src += IM_STEP;
	}
	m_console_out((char*)ucr_line, im_width);
}

template<int IM_STEP> static void dump_line(const unsigned char* auc_src, int im_prev_line, int im_width) {
	unsigned char ucr_line[4096];
	for(int im_i=0; im_i<im_width; im_i++) {
		ucr_line[im_i] = ((auc_src[0]) - (auc_src[0-im_prev_line]));
		auc_src += IM_STEP;
	}
	m_console_out((char*)ucr_line, im_width);
}
#endif /*BITMAP_COMPR_6_DEBUG_COMPRESS*/

template<int IM_STEP, class WRITER, bool BO_FIRST_LINE> struct s_copy_raw;
/*	static const unsigned char* copy_raw(const unsigned char* auc_src_raw, int im_count, c_gather_writer& rds_w, int im_prev_line);
};*/

template<int IM_STEP, class WRITER> struct s_copy_raw<IM_STEP, WRITER, true> {
	static const unsigned char* copy_raw(const unsigned char* auc_src_raw, const unsigned char* auc_src_end,
		pint_t im_count, WRITER& rds_w, int im_prev_line)
	{
		const unsigned char* auc_src_raw_end = auc_src_raw + im_count * IM_STEP;
#if BITMAP_COMPR_6_WRITE_OUTPUT
		if(auc_src_end > auc_src_raw_end)
			auc_src_end = auc_src_raw_end;
		while(auc_src_raw < auc_src_end) {
			if(!rds_w.write_byte((char)*auc_src_raw))
				return NULL;
#if BITMAP_COMPR_6_VERIFY_COMPRESS
			check_byte(rds_w);
#endif
			auc_src_raw += IM_STEP;
		}
		while(auc_src_raw < auc_src_raw_end) {
			if(!rds_w.write_byte(0))
				return NULL;
#if BITMAP_COMPR_6_VERIFY_COMPRESS
			check_byte(rds_w);
#endif
			auc_src_raw += IM_STEP;
		}
		return auc_src_raw;
#else
		if(!rds_w.skip(im_count))
			return NULL;
		return auc_src_raw_end;
#endif
	}
};

template<int IM_STEP, class WRITER> struct s_copy_raw<IM_STEP, WRITER, false> {
static const unsigned char* copy_raw(const unsigned char* auc_src_raw, const unsigned char* auc_src_end,
	pint_t im_count, WRITER& rds_w, int im_prev_line) {
	const unsigned char* auc_src_raw_end = auc_src_raw + im_count * IM_STEP;
#if BITMAP_COMPR_6_WRITE_OUTPUT
	if(auc_src_end > auc_src_raw_end)
		auc_src_end = auc_src_raw_end;
	while(auc_src_raw < auc_src_end) {
      unsigned char ch_delta = auc_src_raw[0] - auc_src_raw[0-im_prev_line];
      if(ch_delta >= 0x80) {
			ch_delta = (0x100 - ch_delta);
			ch_delta <<= 1;
			ch_delta--;
		}
		else {
			ch_delta <<= 1;
		}
		if(!rds_w.write_byte((char)ch_delta))
         return NULL;
#if BITMAP_COMPR_6_VERIFY_COMPRESS
		check_byte(rds_w);
#endif
		auc_src_raw += IM_STEP;
	}
	while(auc_src_raw < auc_src_raw_end) {
		if(!rds_w.write_byte(0))
			return NULL;
#if BITMAP_COMPR_6_VERIFY_COMPRESS
		check_byte(rds_w);
#endif
		auc_src_raw += IM_STEP;
	}
	return auc_src_raw;
#else
	if(!rds_w.skip(im_count))
      return NULL;
	return auc_src_raw_end;
#endif
}
};

int ins_raw_counter = 0;
int ins_run_counter = 0;

template<int IM_STEP, class WRITER, bool BO_FIRST_LINE> static bool write_rle_segment(
	WRITER& rds_w, pint_t im_run_count, pint_t im_raw_count,
	const unsigned char* auc_src_raw, const unsigned char* auc_src_end, int im_prev_line)
{
#if 0
	ins_raw_counter += im_raw_count;
	ins_run_counter += im_run_count;
	if(true)
		return true;
#endif

#if BITMAP_COMPR_6_WRITE_RLE_SEGMENT
	if(im_raw_count > 0) {
		while((im_raw_count & ~0xf) != 0) {
#if BITMAP_COMPR_6_DEBUG_COMPRESS
			printf("   run=%d raw=%d auc_src_raw=%p\n", 0, 0xf, auc_src_raw);
#endif
#if BITMAP_COMPR_6_WRITE_OUTPUT
#if BITMAP_COMPR_6_WRITE_RESERVED
			if(!rds_w.reserve(1 + 0xf))
				return false;
#endif
			if(!rds_w.write_byte((char)0xf0))
            return false;
#if BITMAP_COMPR_6_VERIFY_COMPRESS
			check_byte(rds_w);
#endif
			auc_src_raw = s_copy_raw<IM_STEP, WRITER, BO_FIRST_LINE>::copy_raw(auc_src_raw, auc_src_end, 0xf, rds_w, im_prev_line);
         if(auc_src_raw == NULL)
            return false;
#endif
			im_raw_count -= 0xf;
		}
		if((im_run_count & ~0xf) == 0)
			goto LBL_SIMPLE;
		pint_t im_rest = 0xf;
		im_run_count -= 0xf;
		if(im_run_count < 3) {
			const int im_change = CALC_CHANGE(im_run_count);
			im_rest -= im_change;
			im_run_count += im_change;
		}
#if BITMAP_COMPR_6_DEBUG_COMPRESS
		printf("   run=%d raw=%d auc_src_raw=%p\n", im_rest, im_raw_count, auc_src_raw);
#endif
#if BITMAP_COMPR_6_WRITE_OUTPUT
#if BITMAP_COMPR_6_WRITE_RESERVED
		if(!rds_w.reserve(1 + im_raw_count))
			return false;
#endif
		if(!rds_w.write_byte((char)((im_raw_count<<4) | im_rest)))
         return false;
#if BITMAP_COMPR_6_VERIFY_COMPRESS
		check_byte(rds_w);
#endif
		auc_src_raw = s_copy_raw<IM_STEP, WRITER, BO_FIRST_LINE>::copy_raw(auc_src_raw, auc_src_end, im_raw_count, rds_w, im_prev_line);
      if(auc_src_raw == NULL)
         return false;
#endif
		im_raw_count = 0;
	}
	/* Is extra long (2.2.2.5.1.2) - im_run_count >= 32 ? */
	while((im_run_count & ~0x1f) != 0) {
		im_run_count -= 32;
		pint_t im_rest = im_run_count;
		if((im_rest & ~0xf) != 0)
			im_rest = 0xf;
		im_run_count -= im_rest;
		if(im_run_count > 0 && im_run_count < 3) {
			const pint_t im_change = CALC_CHANGE(im_run_count);
			im_rest -= im_change;
			im_run_count += im_change;
		}
#if BITMAP_COMPR_6_DEBUG_COMPRESS
		printf("   run=%d raw=%d auc_src_raw=%p\n", 2, im_rest, auc_src_raw);
#endif
#if BITMAP_COMPR_6_WRITE_OUTPUT
#if BITMAP_COMPR_6_WRITE_RESERVED
		if(!rds_w.reserve(1))
			return false;
#endif
		if(!rds_w.write_byte((char)((im_rest<<4) | 0x2)))
         return false;
#if BITMAP_COMPR_6_VERIFY_COMPRESS
		check_byte(rds_w);
#endif
#endif
		if(im_run_count == 0)
			return true;
	}
	/* Is extra long (2.2.2.5.1.2) - im_run_count >= 16 ? */
	if((im_run_count & ~0xf) != 0) {
		im_run_count -= 16;
		pint_t im_rest = im_run_count;
		im_run_count -= im_rest;
		if(im_run_count > 0 && im_run_count < 3) {
			const int im_change = CALC_CHANGE(im_run_count);
			im_rest -= im_change;
			im_run_count += im_change;
		}
#if BITMAP_COMPR_6_DEBUG_COMPRESS
		printf("   run=%d raw=%d auc_src_raw=%p\n", 1, im_rest, auc_src_raw);
#endif
#if BITMAP_COMPR_6_WRITE_OUTPUT
#if BITMAP_COMPR_6_WRITE_RESERVED
		if(!rds_w.reserve(1))
			return false;
#endif
		if(!rds_w.write_byte((char)((im_rest<<4) | 0x1)))
         return false;
#if BITMAP_COMPR_6_VERIFY_COMPRESS
		check_byte(rds_w);
#endif
#endif
		if(im_run_count == 0)
			return true;
	}
LBL_SIMPLE:
#if BITMAP_COMPR_6_DEBUG_COMPRESS
	printf("   run=%d raw=%d auc_src_raw=%p\n", im_run_count, im_raw_count, auc_src_raw);
#endif
#if BITMAP_COMPR_6_WRITE_OUTPUT
#if BITMAP_COMPR_6_WRITE_RESERVED
	if(!rds_w.reserve(1 + im_raw_count))
		return false;
#endif
	if(!rds_w.write_byte((char)((im_raw_count<<4) | im_run_count)))
      return false;
#if BITMAP_COMPR_6_VERIFY_COMPRESS
	check_byte(rds_w);
#endif
	auc_src_raw = s_copy_raw<IM_STEP, WRITER, BO_FIRST_LINE>::copy_raw(auc_src_raw, auc_src_end, im_raw_count, rds_w, im_prev_line);
   if(auc_src_raw == NULL)
      return false;
#endif
#if BITMAP_COMPR_6_DEBUG_COMPRESS
	printf("   end auc_src_raw=%p\n", auc_src_raw);
#endif
#else
	//printf("im_raw_count=%d im_run_count=%d\n", im_raw_count, im_run_count);
	if(im_raw_count > 0) {
		while((im_raw_count & ~0xf) != 0) {
			if(!rds_w.skip(1 + 0xf))
				return false;
			im_raw_count -= 0xf;
		}
		if((im_run_count & ~0xf) == 0)
			goto LBL_SIMPLE;
		im_run_count -= 0xf;
		if(im_run_count < 3)
			im_run_count += CALC_CHANGE(im_run_count);
		if(!rds_w.skip(1 + im_raw_count))
			return false;
		im_raw_count = 0;
	}
	/* Is extra long (2.2.2.5.1.2) - im_run_count >= 32 ? */
	while((im_run_count & ~0x1f) != 0) {
		im_run_count -= 32;
		pint_t im_rest = im_run_count;
		if((im_rest & ~0xf) != 0)
			im_rest = 0xf;
		im_run_count -= im_rest;
		if(im_run_count > 0 && im_run_count < 3) {
			const int im_change = CALC_CHANGE(im_run_count);
			im_rest -= im_change;
			im_run_count += im_change;
		}
		if(!rds_w.skip(1))
			return false;
		if(im_run_count == 0)
			return true;
	}
	/* Is extra long (2.2.2.5.1.2) - im_run_count >= 16 ? */
	if((im_run_count & ~0xf) != 0) {
		im_run_count -= 16;
		pint_t im_rest = im_run_count;
		//if((im_rest & ~0xf) != 0)
		//	im_rest = 0xf;
		im_run_count -= im_rest;
		if(im_run_count > 0 && im_run_count < 3) {
			const pint_t im_change = CALC_CHANGE(im_run_count);
			im_rest -= im_change;
			im_run_count += im_change;
		}
		if(!rds_w.skip(1))
			return false;
		if(im_run_count == 0)
			return true;
	}
LBL_SIMPLE:
	if(!rds_w.skip(1 + im_raw_count))
		return false;
#endif
	return true;
}

#if BITMAP_COMPR_6_USE_SSE2
template<int IM_STEP> struct s_read_sse2 {
	static __ALWAYSINLINE __m128i read(const unsigned char* auc_src, const unsigned char* auc_srcend) {
		return _mm_set_epi8 (
			auc_src[IM_STEP*15],
			auc_src[IM_STEP*14],
			auc_src[IM_STEP*13],
			auc_src[IM_STEP*12],
			auc_src[IM_STEP*11],
			auc_src[IM_STEP*10],
			auc_src[IM_STEP*9],
			auc_src[IM_STEP*8],
			auc_src[IM_STEP*7],
			auc_src[IM_STEP*6],
			auc_src[IM_STEP*5],
			auc_src[IM_STEP*4],
			auc_src[IM_STEP*3],
			auc_src[IM_STEP*2],
			auc_src[IM_STEP*1],
			auc_src[IM_STEP*0]);
	}
};

template<> struct s_read_sse2<1> {
	static __ALWAYSINLINE __m128i read(const unsigned char* auc_src, const unsigned char* auc_srcend) {
#if BITMAP_COMPR_6_USE_SSE2_ALIGNED
		return _mm_load_si128((__m128i*)auc_src);
#else
		return _mm_loadu_si128((__m128i*)auc_src);
#endif
	}
};

#if 0
template<> struct s_read_sse2<4> {
	static __m128i read(const unsigned char* auc_src, const unsigned char* auc_srcend) {
#if 0
		__m128i sK[4];
		sK[0] = _mm_loadu_si128((__m128i*)auc_src);
		sK[1] = _mm_loadu_si128((__m128i*)(auc_src+16));
		sK[2] = _mm_loadu_si128((__m128i*)(auc_src+32));
		sK[3] = _mm_loadu_si128((__m128i*)(auc_src+48));

		__m128i sU1 = _mm_unpacklo_epi8(sK[0], sK[1]);
		__m128i sU2 = _mm_unpackhi_epi8(sK[0], sK[1]);
		__m128i sU1V2 = _mm_unpacklo_epi8(sU1, sU2);
		__m128i sU2V2 = _mm_unpackhi_epi8(sU1, sU2);
		__m128i sV1W2 = _mm_unpacklo_epi8(sU1V2, sU2V2);
		//__m128i sV2W2 = _mm_unpackhi_epi8(sU1V2, sU2V2);
		
		__m128i sU3 = _mm_unpacklo_epi8(sK[2], sK[3]);
		__m128i sU4 = _mm_unpackhi_epi8(sK[2], sK[3]);
		__m128i sU3V2 = _mm_unpacklo_epi8(sU3, sU4);
		__m128i sU4V2 = _mm_unpackhi_epi8(sU3, sU4);
		__m128i sV3W2 = _mm_unpacklo_epi8(sU3V2, sU4V2);
		//__m128i sV4W2 = _mm_unpackhi_epi8(sU3V2, sU4V2);

		__m128i sP = _mm_unpacklo_epi64(sV1W2, sV3W2);
		//sP[1] = _mm_unpackhi_epi64(sV1W2, sV3W2);
		//sP[2] = _mm_unpacklo_epi64(sV2W2, sV4W2);
		//sP[3] = _mm_unpackhi_epi64(sV2W2, sV4W2);
		return sP;
#endif
	}
};
#endif
#endif /*BITMAP_COMPR_6_USE_SSE2*/

typedef unsigned int pixel_t;
//typedef unsigned char pixel_t;

template<int IM_STEP, class WRITER, bool BO_FIRST_LINE> static bool compress_rle_line(
	const unsigned char* auc_srcline, const unsigned char* auc_srcline_end, pint_t im_width, int im_prev_delta, pint_t im_pad_bytes, WRITER& rds_w)
{
#if BITMAP_COMPR_6_USE_RUN_COUNTER
	pint_t im_run_count = 0;
#else
	const unsigned char* auc_run_start = auc_src;
#endif
	pint_t im_raw_count = 0;
	pixel_t uc_color_last = 0;
	const unsigned char* auc_src = auc_srcline;
#if BITMAP_COMPR_6_USE_SSE2
	const unsigned char* auc_srcline_sse_end = auc_src + ((im_width & ~0xf) * IM_STEP);
	__m128i mm_last = _mm_setzero_si128();
LBL_SSE_NEXT1:
	while(auc_src < auc_srcline_sse_end) {
		__m128i mm_src = s_read_sse2<IM_STEP>::read(auc_src, auc_srcline_sse_end);
		if(!BO_FIRST_LINE) {
			__m128i mm_prev = s_read_sse2<IM_STEP>::read(auc_src+im_prev_delta, auc_srcline_sse_end+im_prev_delta);
			mm_src = _mm_sub_epi8(mm_src, mm_prev);
		}
		__m128i mm_src2 = _mm_slli_si128(mm_src, 1);
		mm_src2 = _mm_or_si128(mm_src2, mm_last);
		__m128i mm_cmp = _mm_cmpeq_epi8(mm_src, mm_src2);
		int in_bitmask = (~_mm_movemask_epi8(mm_cmp))&0xffff;
		unsigned long um_bitpos_max = 16;
LBL_SSE_NEXT2:
		do {
#if HOB_WINDOWS
			unsigned long um_bitpos;
			unsigned char uc_result =_BitScanForward(&um_bitpos, (unsigned long)in_bitmask);
			if(uc_result == 0) {
#else
			int in_bitpos = ffs((int)in_bitmask);
			if(in_bitpos == 0) {
#endif
				auc_src += um_bitpos_max * IM_STEP;
				im_run_count += um_bitpos_max;
				mm_last = _mm_srli_si128(mm_src, 15);
				goto LBL_SSE_NEXT1;
			}
#if HOB_WINDOWS
			auc_src += (um_bitpos+1) * IM_STEP;
			im_run_count += um_bitpos;
			in_bitmask >>= um_bitpos+1;
			um_bitpos_max -= um_bitpos+1;
#else
			auc_src += in_bitpos * IM_STEP;
			im_run_count += (in_bitpos-1);
			in_bitmask >>= in_bitpos;
			um_bitpos_max -= in_bitpos;
#endif
			//printf("im_run_count=%d im_raw_count=%d srcpos=%d\n", im_run_count, im_raw_count, (auc_src-auc_srcline)/IM_STEP);
			if(im_run_count >= 3) {
				const unsigned char* auc_raw = auc_src - (im_raw_count + im_run_count + 1) * IM_STEP;
				if(!write_rle_segment<IM_STEP, WRITER, BO_FIRST_LINE>(rds_w, im_run_count, im_raw_count, auc_raw, auc_srcline_sse_end, -im_prev_delta))
					return false;
				im_run_count = 0;
				im_raw_count = 1;
				goto LBL_SSE_NEXT2;
			}
			im_raw_count += im_run_count;
			im_raw_count++;
			im_run_count = 0;
			goto LBL_SSE_NEXT2;
		} while(true);
	}
	//printf("SSE2 done im_run_count=%d im_raw_count=%d srcpos=%d\n", im_run_count, im_raw_count, (auc_src-auc_srcline)/IM_STEP);
	if(auc_src != auc_srcline)
		uc_color_last = BO_FIRST_LINE ? (auc_src[-IM_STEP]) : (auc_src[-IM_STEP] - auc_src[im_prev_delta-IM_STEP]);
#endif /*BITMAP_COMPR_6_USE_SSE2*/
LBL_NEXT1:
	while(auc_src < auc_srcline_end) {
		//printf("hallo");
		pixel_t uc_cur = BO_FIRST_LINE ? auc_src[0] : (auc_src[0] - auc_src[im_prev_delta]);
		if(uc_cur == uc_color_last) {
			auc_src += IM_STEP;
#if BITMAP_COMPR_6_USE_RUN_COUNTER
			im_run_count++;
#endif
			goto LBL_NEXT1;
		}
		//printf("im_run_count=%d im_raw_count=%d srcpos=%d\n", im_run_count, im_raw_count, (auc_src-auc_srcline)/IM_STEP);
		uc_color_last = uc_cur;
#if !BITMAP_COMPR_6_USE_RUN_COUNTER
		pint_t im_run_count = ((unsigned int)(auc_src - auc_run_start)) / IM_STEP;
#endif
		if(im_run_count >= 3) {
#if BITMAP_COMPR_6_USE_RUN_COUNTER
			const unsigned char* auc_raw = auc_src - (im_raw_count + im_run_count) * IM_STEP;
#else
			const unsigned char* auc_raw = auc_run_start-im_raw_count;
#endif
			if(!write_rle_segment<IM_STEP, WRITER, BO_FIRST_LINE>(rds_w, im_run_count, im_raw_count, auc_raw, auc_srcline_end, -im_prev_delta))
				return false;
#if BITMAP_COMPR_6_USE_RUN_COUNTER
			im_run_count = 0;
#endif
			im_raw_count = 1;
			auc_src += IM_STEP;
#if !BITMAP_COMPR_6_USE_RUN_COUNTER
			auc_run_start = auc_src;
#endif
			goto LBL_NEXT1;
		}
		im_raw_count += im_run_count;
		im_raw_count++;
#if BITMAP_COMPR_6_USE_RUN_COUNTER
		im_run_count = 0;
#endif
		auc_src += IM_STEP;
#if !BITMAP_COMPR_6_USE_RUN_COUNTER
		auc_run_start = auc_src;
#endif
		goto LBL_NEXT1;
	}
#if BITMAP_COMPR_6_USE_RUN_COUNTER
	im_run_count += im_pad_bytes;
	if(im_run_count < 3) {
		im_raw_count += im_run_count;
		im_run_count = 0;
	}
	auc_src += im_pad_bytes * IM_STEP;
	const unsigned char* auc_raw = auc_src - ((im_raw_count + im_run_count) * IM_STEP);
#else
	auc_src += im_pad_bytes * IM_STEP;
	pint_t im_run_count = (auc_src - auc_run_start) / IM_STEP;
	const unsigned char* auc_raw = auc_run_start-im_raw_count;
#endif
	if(!write_rle_segment<IM_STEP, WRITER, BO_FIRST_LINE>(rds_w, im_run_count, im_raw_count, auc_raw, auc_srcline_end, -im_prev_delta))
		return false;
	return true;
}

template<int IM_STEP, class WRITER> static int compress_rle_plane(
	const unsigned char* auc_src, pint_t im_width, pint_t im_pad_bytes, int im_scanline, pint_t im_height,
	WRITER& rds_w)
{

	/* Is invalid height? */
	if(im_height <= 0)
		return 0;
	const int im_dstpos_in = rds_w.get_position();
	/* Multiply width by output step. */
	const pint_t im_width_step = im_width * IM_STEP;
	const unsigned char* auc_srcline = auc_src;
	{
#if BITMAP_COMPR_6_USE_COMPRESS_LINE
		if(!compress_rle_line<IM_STEP, WRITER, true>(auc_src, auc_src + im_width_step, im_width, 0, im_pad_bytes, rds_w))
			return -1;
#else
		pint_t im_run_count = 0;
		pint_t im_raw_count = 0;
		pixel_t uc_color_last = 0;
#if BITMAP_COMPR_6_DEBUG_COMPRESS
		printf("line%d: im_raw_start=%p end=%p\n",
			0, auc_src, (auc_src+im_width_step));
		dump_line<IM_STEP>(auc_src, im_width);
#endif
		const unsigned char* const auc_srcline_end = auc_srcline + im_width_step;
LBL_NEXT0:
		while(auc_src < auc_srcline_end) {
			pixel_t uc_cur = auc_src[0];
			if(uc_cur == uc_color_last) {
				auc_src += IM_STEP;
				im_run_count++;
				goto LBL_NEXT0;
			}
			uc_color_last = uc_cur;
			if(im_run_count >= 3) {
				const unsigned char* auc_raw = auc_src - (im_raw_count + im_run_count) * IM_STEP;
				if(!write_rle_segment<IM_STEP, WRITER, true>(rds_w, im_run_count, im_raw_count, auc_raw, auc_srcline_end, 0))
					return -1;
				im_raw_count = 0;
			}
			else {
				im_raw_count += im_run_count;
			}
			im_run_count = 0;
			im_raw_count++;
			auc_src += IM_STEP;
			goto LBL_NEXT0;
		}
		im_run_count += im_pad_bytes;
		if(im_run_count < 3) {
			im_raw_count += im_run_count;
			im_run_count = 0;
		}
		auc_src += im_pad_bytes * IM_STEP;
		const unsigned char* auc_raw = auc_src - (im_raw_count + im_run_count) * IM_STEP;
		if(!write_rle_segment<IM_STEP, WRITER, true>(rds_w, im_run_count, im_raw_count, auc_raw, auc_srcline_end, 0))
			return -1;
#endif
		auc_src = auc_srcline + im_scanline;
	}

	const unsigned char* auc_srcline_prev = auc_srcline;
	int im_prev_delta = (int)(auc_srcline_prev-auc_src);
	//if(BO_TOP_DOWN)
	//	im_srcpos = im_cur_line - im_width_step;
	
	pint_t im_h = 0;
	while(++im_h < im_height) {
		auc_srcline = auc_src;

#if BITMAP_COMPR_6_USE_COMPRESS_LINE
		if(!compress_rle_line<IM_STEP, WRITER, false>(auc_src, auc_src + im_width_step, im_width, im_prev_delta, im_pad_bytes, rds_w))
			return -1;
#else
#if BITMAP_COMPR_6_USE_RUN_COUNTER
		pint_t im_run_count = 0;
#else
		const unsigned char* auc_run_start = auc_src;
#endif
		pint_t im_raw_count = 0;
		pixel_t uc_color_last = 0;
		const unsigned char* const auc_srcline_end = auc_src + im_width_step;
#if BITMAP_COMPR_6_DEBUG_COMPRESS
		printf("line%d: im_raw_start=%p end=%p\n",
			im_h, auc_src, (auc_src+im_width_step));
		dump_line<IM_STEP>(auc_src, -im_prev_delta, im_width);
#endif
#if BITMAP_COMPR_6_USE_SSE2
		__m128i mm_last = _mm_setzero_si128();
#endif
LBL_NEXT1:
		while(auc_src < auc_srcline_end) {
#if BITMAP_COMPR_6_USE_SSE2
			__m128i mm_src = s_read_sse2<IM_STEP>::read(auc_src, auc_srcline_end);
			__m128i mm_prev = s_read_sse2<IM_STEP>::read(auc_src+im_prev_delta, auc_srcline_end+im_prev_delta);
			__m128i mm_sub = _mm_sub_epi8(mm_src, mm_prev);
			__m128i mm_sub2 = _mm_slli_si128(mm_sub, 1);
			mm_sub2 = _mm_or_si128 (mm_sub2, mm_last);
			__m128i mm_cmp = _mm_cmpeq_epi8(mm_sub, mm_sub2);
			int in_bitmask = (~_mm_movemask_epi8(mm_cmp))&0xffff;
			unsigned long um_bitpos_max = 16;
LBL_NEXT2:
			do {
#if HOB_WINDOWS
				unsigned long um_bitpos;
				unsigned char uc_result =_BitScanForward(&um_bitpos, (unsigned long)in_bitmask);
				if(uc_result == 0) {
#else
				int in_bitpos = ffs((int)in_bitmask);
				if(in_bitpos == 0) {
#endif
					auc_src += um_bitpos_max * IM_STEP;
					im_run_count += um_bitpos_max;
					mm_last = _mm_srli_si128(mm_sub, 15);
					goto LBL_NEXT1;
				}
#if HOB_WINDOWS
				auc_src += um_bitpos * IM_STEP;
				im_run_count += um_bitpos;
				in_bitmask >>= um_bitpos+1;
				um_bitpos_max -= um_bitpos+1;
#else
				auc_src += (in_bitpos-1) * IM_STEP;
				im_run_count += (in_bitpos-1);
				in_bitmask >>= in_bitpos;
				um_bitpos_max -= in_bitpos;
#endif
				//printf("im_run_count=%d im_raw_count=%d srcpos=%d\n", im_run_count, im_raw_count, (auc_src-auc_srcline)/IM_STEP);
				if(im_run_count >= 3) {
					const unsigned char* auc_raw = auc_src - (im_raw_count + im_run_count) * IM_STEP;
					if(!write_rle_segment<IM_STEP, WRITER, false>(rds_w, im_run_count, im_raw_count, auc_raw, auc_srcline_end, -im_prev_delta))
						return -1;
					im_run_count = 0;
					im_raw_count = 1;
					auc_src += IM_STEP;
					goto LBL_NEXT2;
				}
				im_raw_count += im_run_count;
				im_raw_count++;
				im_run_count = 0;
				auc_src += IM_STEP;
				goto LBL_NEXT2;
			} while(true);
#else						
			//printf("hallo");
			pixel_t uc_cur = auc_src[0] - auc_src[im_prev_delta];
			if(uc_cur == uc_color_last) {
				auc_src += IM_STEP;
#if BITMAP_COMPR_6_USE_RUN_COUNTER
				im_run_count++;
#endif
				goto LBL_NEXT1;
			}
			//printf("im_run_count=%d im_raw_count=%d srcpos=%d\n", im_run_count, im_raw_count, (auc_src-auc_srcline)/IM_STEP);
			uc_color_last = uc_cur;
#if !BITMAP_COMPR_6_USE_RUN_COUNTER
			pint_t im_run_count = ((unsigned int)(auc_src - auc_run_start)) / IM_STEP;
#endif
			if(im_run_count >= 3) {
#if BITMAP_COMPR_6_USE_RUN_COUNTER
				const unsigned char* auc_raw = auc_src - (im_raw_count + im_run_count) * IM_STEP;
#else
				const unsigned char* auc_raw = auc_run_start-im_raw_count;
#endif
				if(!write_rle_segment<IM_STEP, WRITER, false>(rds_w, im_run_count, im_raw_count, auc_raw, auc_srcline_end, -im_prev_delta))
					return -1;
#if BITMAP_COMPR_6_USE_RUN_COUNTER
				im_run_count = 0;
#endif
				im_raw_count = 1;
				auc_src += IM_STEP;
#if !BITMAP_COMPR_6_USE_RUN_COUNTER
				auc_run_start = auc_src;
#endif
				goto LBL_NEXT1;
			}
			im_raw_count += im_run_count;
			im_raw_count++;
#if BITMAP_COMPR_6_USE_RUN_COUNTER
			im_run_count = 0;
#endif
			auc_src += IM_STEP;
#if !BITMAP_COMPR_6_USE_RUN_COUNTER
			auc_run_start = auc_src;
#endif
			goto LBL_NEXT1;
#endif
		}
#if BITMAP_COMPR_6_USE_RUN_COUNTER
		im_run_count += im_pad_bytes;
		if(im_run_count < 3) {
			im_raw_count += im_run_count;
			im_run_count = 0;
		}
		auc_src += im_pad_bytes * IM_STEP;
		const unsigned char* auc_raw = auc_src - ((im_raw_count + im_run_count) * IM_STEP);
#else
		auc_src += im_pad_bytes * IM_STEP;
		pint_t im_run_count = (auc_src - auc_run_start) / IM_STEP;
		const unsigned char* auc_raw = auc_run_start-im_raw_count;
#endif
		if(!write_rle_segment<IM_STEP, WRITER, false>(rds_w, im_run_count, im_raw_count, auc_raw, auc_srcline_end, -im_prev_delta))
			return -1;
#endif
		//im_h++;
		auc_srcline_prev = auc_srcline;
		auc_src = auc_srcline + im_scanline;
		//if(BO_TOP_DOWN)
		//	im_srcpos = im_cur_line - im_width_step;
	}
	return (rds_w.get_position() - im_dstpos_in);
}

template<class WRITER> static int compress_rle_plane_fixed(
	unsigned char uc_value, pint_t im_width, pint_t im_pad_bytes, int im_scanline, pint_t im_height,
	WRITER& rds_w)
{
	/* Is invalid height? */
	if(im_height <= 0)
		return 0;
	const int im_dstpos_in = rds_w.get_position();
	pint_t im_run_count = im_width + im_pad_bytes;
	pint_t im_raw_count = 0;
	if(uc_value != 0) {
		im_raw_count = 1;
		im_run_count--;
	}
	if(im_run_count < 3) {
		im_raw_count += im_run_count;
		im_run_count = 0;
	}
	const unsigned char* auc_raw = &uc_value;
	if(!write_rle_segment<1, WRITER, true>(rds_w, im_run_count, im_raw_count, auc_raw, auc_raw+im_raw_count, 0))
		return -1;

	pint_t im_h = 0;
	im_run_count = im_width + im_pad_bytes;
	while(++im_h < im_height) {
		if(!write_rle_segment<1, WRITER, false>(rds_w, im_run_count, 0, auc_raw, auc_raw, 0))
			return -1;
	}
	return (rds_w.get_position() - im_dstpos_in);
}

void m_console_out( char *achp_buff, int implength );

/*static inline void __attribute__((hot)) rgb2cocgy_mmx(const unsigned char* auc_src, const int in_cll,
	unsigned char* auc_dst_y, unsigned char* auc_dst_co, unsigned char* auc_dst_cg);
*/

#if BITMAP_COMPR_6_USE_SSE2
struct s_write_sse2_direct {
	unsigned char* auc_dst;

	s_write_sse2_direct(unsigned char* auc_dst) : auc_dst(auc_dst) {
	}

	void write(int in_out) {
		*this->auc_dst++ = (unsigned char)in_out;
	}

	void write(__m128i mm_out) {
		_mm_storeu_si128((__m128i*)this->auc_dst, mm_out);
		this->auc_dst += 16;
	}
};

struct s_write_sse2_padded {
	unsigned char* auc_dst;
	unsigned char* auc_end;
	int im_width;
	int im_pad;

	s_write_sse2_padded(unsigned char* auc_dst, int im_width, int im_pad)
		: auc_dst(auc_dst), auc_end(auc_dst+im_width), im_width(im_width), im_pad(im_pad)
	{}

	void check_pad() {
		if(this->auc_dst < this->auc_end)
			return;
		this->auc_dst = this->auc_end + im_pad;
		this->auc_end = this->auc_dst + this->im_width;
	}

	void increment_dst(int im_bytes) {
		this->auc_dst += im_bytes;
		this->check_pad();
	}

	void write(int in_out) {
		*this->auc_dst++ = (unsigned char)in_out;
		this->check_pad();
	}

#if 0
	static void memcpy(unsigned char* auc_dst, unsigned char* auc_src, int in_len) {
		unsigned char* auc_srcend = auc_src + in_len;
		while(auc_src < auc_srcend) {
			*auc_dst++ = *auc_src++; 
		}
	}
#endif

	void write(__m128i mm_out) {
#if 1
		int im_dst_rest = this->auc_end-this->auc_dst;
		if(im_dst_rest >= 16 || this->im_pad == 0) {
			_mm_storeu_si128((__m128i*)this->auc_dst, mm_out);
			this->increment_dst(16);
			return;
		}
		__m128i mm_temp;
		_mm_storeu_si128((__m128i*)&mm_temp, mm_out);
		unsigned char* auc_src = (unsigned char*)&mm_temp;
		unsigned char* auc_srcend = auc_src + 16;
		do {
			int in_copy = std::min(im_dst_rest, (int)(auc_srcend-auc_src)); 
			memcpy(this->auc_dst, auc_src, in_copy);
			this->increment_dst(in_copy);
			auc_src += in_copy;
		} while(auc_src < auc_srcend);
#endif
	}
};

template<int IM_RED_INDEX, int IM_GREEN_INDEX, int IM_BLUE_INDEX, class SSE_WRITER>
static inline void rgb2cocgy_mmx(
	const __m128i (&sK)[4],
	const int in_cll,
	SSE_WRITER& rds_dst_y, SSE_WRITER& rds_dst_co, SSE_WRITER& rds_dst_cg)
{
#if 0
	auc_src = (const unsigned char*)(((size_t)(auc_src + 15)) & ~0xf);
	auc_dst = (unsigned char*)(((size_t)(auc_dst + 15)) & ~0xf);
#endif
	//m_console_out((char*)auc_src, 16);
	//_mm_prefetch((const char*)auc_src, _MM_HINT_T0); 
	// We need to fetch and blit out our k before we write over it with UV data.
	__m128i sU1 = _mm_unpacklo_epi8(sK[0], sK[1]);
	__m128i sU2 = _mm_unpackhi_epi8(sK[0], sK[1]);
	__m128i sU1V2 = _mm_unpacklo_epi8(sU1, sU2);
	__m128i sU2V2 = _mm_unpackhi_epi8(sU1, sU2);
	__m128i sV1W2 = _mm_unpacklo_epi8(sU1V2, sU2V2);
	__m128i sV2W2 = _mm_unpackhi_epi8(sU1V2, sU2V2);
	
	__m128i sU3 = _mm_unpacklo_epi8(sK[2], sK[3]);
	__m128i sU4 = _mm_unpackhi_epi8(sK[2], sK[3]);
	__m128i sU3V2 = _mm_unpacklo_epi8(sU3, sU4);
	__m128i sU4V2 = _mm_unpackhi_epi8(sU3, sU4);
	__m128i sV3W2 = _mm_unpacklo_epi8(sU3V2, sU4V2);
	__m128i sV4W2 = _mm_unpackhi_epi8(sU3V2, sU4V2);

	__m128i sP[4];
	sP[0] = _mm_unpacklo_epi64(sV1W2, sV3W2);
	sP[1] = _mm_unpackhi_epi64(sV1W2, sV3W2);
	sP[2] = _mm_unpacklo_epi64(sV2W2, sV4W2);
	sP[3] = _mm_unpackhi_epi64(sV2W2, sV4W2);

	// Y - (r >> 2) + (g >> 1) + (b >> 2)
	const __m128i sShiftMask1 = _mm_set_epi32(0x7f7f7f7f, 0x7f7f7f7f, 0x7f7f7f7f, 0x7f7f7f7f);
	const __m128i sShiftMask2 = _mm_set_epi32(0x3f3f3f3f, 0x3f3f3f3f, 0x3f3f3f3f, 0x3f3f3f3f);
	{
		__m128i sY = _mm_add_epi8(
			_mm_add_epi8(
				_mm_and_si128(_mm_srli_epi64(sP[IM_RED_INDEX], 2), sShiftMask2),	// (r >> 2)
				_mm_and_si128(_mm_srli_epi64(sP[IM_GREEN_INDEX], 1), sShiftMask1)), // (g >> 1)
				_mm_and_si128(_mm_srli_epi64(sP[IM_BLUE_INDEX], 2), sShiftMask2)	// (b >> 2)
		);
		rds_dst_y.write(sY);
	}

	const __m128i sNull = _mm_setzero_si128();
	const __m128i sRed1 = _mm_unpacklo_epi8(sP[IM_RED_INDEX], sNull);
	const __m128i sBlue1 = _mm_unpacklo_epi8(sP[IM_BLUE_INDEX], sNull);
	// Part1: Co = (r - b) >> cll
	__m128i sCo1 = _mm_srli_epi16(_mm_sub_epi16(sRed1, sBlue1), in_cll);
	const __m128i sRed2 = _mm_unpackhi_epi8(sP[IM_RED_INDEX], sNull);
	const __m128i sBlue2 = _mm_unpackhi_epi8(sP[IM_BLUE_INDEX], sNull);
	// Part2: Co = (r - b) >> cll
	__m128i sCo2 = _mm_srli_epi16(_mm_sub_epi16(sRed2, sBlue2), in_cll);
	__m128i sCg1Red = _mm_srli_epi16(sRed1, 1);
	__m128i sCg2Red = _mm_srli_epi16(sRed2, 1);
	const int IN_PACK_MASK = 0x00ff00ff;
	const __m128i sPackMask = _mm_set_epi32(IN_PACK_MASK, IN_PACK_MASK, IN_PACK_MASK, IN_PACK_MASK);
	{
		__m128i sCo = _mm_packus_epi16(_mm_and_si128(sCo1, sPackMask), _mm_and_si128(sCo2, sPackMask));
		rds_dst_co.write(sCo);
	}

#if 1
	// Cg - Part
	__m128i sGreen1 = _mm_unpacklo_epi8(sP[IM_GREEN_INDEX], sNull);
	__m128i sCg1 = _mm_sub_epi16(sGreen1, _mm_srli_epi16(sBlue1, 1));
	sCg1 = _mm_sub_epi16(sCg1, sCg1Red);
	sCg1 = _mm_srli_epi16(sCg1, in_cll);
	
	__m128i sGreen2 = _mm_unpackhi_epi8(sP[IM_GREEN_INDEX], sNull);
	__m128i sCg2 = _mm_sub_epi16(sGreen2, _mm_srli_epi16(sBlue2, 1));
	//__m128i sCg2Red = _mm_srli_epi16(sRed2, 1);
	sCg2 = _mm_sub_epi16(sCg2, sCg2Red);
	sCg2 = _mm_srli_epi16(sCg2, in_cll);

	sCg1 = _mm_and_si128(sCg1, sPackMask);
	sCg2 = _mm_and_si128(sCg2, sPackMask);
	{
		__m128i sCg = _mm_packus_epi16(sCg1, sCg2);
		rds_dst_cg.write(sCg);
	}
#else
		// Cg - Part
	__m128i sGreen1 = _mm_unpacklo_epi8(sP[IM_GREEN_INDEX], sNull);
	// Part1: Cg = (im_green - (im_blue >> 1) - (im_red >> 1)) >> in_cll;
	__m128i sCg1 = _mm_srli_epi16(
		_mm_sub_epi16(
			_mm_sub_epi16(_mm_unpacklo_epi8(sP[IM_GREEN_INDEX], sNull), _mm_srli_epi16(sBlue1, 1)),	// (im_green - (im_blue >> 1))
			_mm_srli_epi16(sRed1, 1)),	// (im_red >> 1)
			in_cll	// >> in_cll
	);
	
	__m128i sGreen2 = _mm_unpackhi_epi8(sP[IM_GREEN_INDEX], sNull);
	__m128i sCg2 = _mm_srli_epi16(
		_mm_sub_epi16(
			_mm_sub_epi16(sGreen2, _mm_srli_epi16(sBlue2, 1)),	// (im_green - (im_blue >> 1))
			_mm_srli_epi16(sRed2, 1)),	// (im_red >> 1)
			in_cll	// >> in_cll
	);

	{
		__m128i sCg = _mm_packus_epi16(_mm_and_si128(sCg1, sPackMask), _mm_and_si128(sCg2, sPackMask));
		rds_dst_cg.write(sCg);
	}
#endif
	//_mm_storeu_si128((__m128i*)(auc_dst+48), sP4);
}

template<int IM_RED_INDEX, int IM_GREEN_INDEX, int IM_BLUE_INDEX> static inline void rgb2cocgy_mmx(
	const unsigned char* auc_src, const int in_cll,
	unsigned char* auc_dst_y, unsigned char* auc_dst_co, unsigned char* auc_dst_cg)
{
#if 0
	auc_src = (const unsigned char*)(((size_t)(auc_src + 15)) & ~0xf);
	auc_dst = (unsigned char*)(((size_t)(auc_dst + 15)) & ~0xf);
#endif
	//m_console_out((char*)auc_src, 16);
	//_mm_prefetch((const char*)auc_src, _MM_HINT_T0); 
	// We need to fetch and blit out our k before we write over it with UV data.
	__m128i sK1 = _mm_loadu_si128((__m128i*)auc_src);
	__m128i sK2 = _mm_loadu_si128((__m128i*)(auc_src+16));
	__m128i sK3 = _mm_loadu_si128((__m128i*)(auc_src+32));
	__m128i sK4 = _mm_loadu_si128((__m128i*)(auc_src+48));
	
	rgb2cocgy_mmx<IM_RED_INDEX, IM_GREEN_INDEX, IM_BLUE_INDEX, s_write_sse2_direct>(
		sK1, sK2, sK3, sK4, in_cll, auc_dst_y, auc_dst_co, auc_dst_cg,
		s_write_sse2_direct());
}

#define FILL_MMX(in_i) \
		if(true && auc_cur+16 <= auc_srcline_end) { \
			sK[in_i] = _mm_loadu_si128((__m128i*)auc_cur); \
			auc_cur += 16; \
		} \
		else { \
			/*uint32_t inr_pix[4];*/ \
			for(int in_p=0; in_p<4; in_p++) { \
				if(auc_cur == auc_srcline_end) { \
					auc_src += im_scanline; \
					auc_srcline_end += im_scanline; \
					auc_cur = auc_src; \
					im_h++; \
				} \
				/*inr_pix[in_p] = *((uint32_t*)auc_cur);*/ \
				((uint32_t*)&sK[in_i])[in_p] = *((uint32_t*)auc_cur); \
				auc_cur += 4; \
			} \
			/*sK[in_i] = _mm_loadu_si128((__m128i*)inr_pix);*/ \
		}
#endif /*BITMAP_COMPR_6_USE_SSE2*/

template<int IM_STEP, int IM_RED_INDEX, int IM_GREEN_INDEX, int IM_BLUE_INDEX> static void rgb2cocgy(
	const unsigned char* auc_src, int im_width, int im_height, int im_scanline,
	int in_cll, unsigned char* auc_dst_y, unsigned char* auc_dst_co, unsigned char* auc_dst_cg)
{
	const unsigned char* auc_src_old = auc_src;
	unsigned char* auc_dst_y_old = auc_dst_y;
	unsigned char* auc_dst_co_old = auc_dst_co;
	unsigned char* auc_dst_cg_old = auc_dst_cg;

	const int im_width_step = im_width * IM_STEP;
	int im_h = 0;
#if BITMAP_COMPR_6_USE_SSE2
	int in_mmx_pixels = (im_width * im_height) >> 4;
	const unsigned char* auc_cur = auc_src; 
	const unsigned char* auc_srcline_end = auc_src + im_width_step;
	register __m128i sK[4];
#if BITMAP_COMPR_6_USE_SSE2_ALIGNED
	int iml_aligned_width = HOB_PAD_INTEGER(im_width, 16);
	s_write_sse2_padded dsl_sse2_y(auc_dst_y, im_width, iml_aligned_width-im_width);
	s_write_sse2_padded dsl_sse2_co(auc_dst_co, im_width, iml_aligned_width-im_width);
	s_write_sse2_padded dsl_sse2_cg(auc_dst_cg, im_width, iml_aligned_width-im_width);
#else
	s_write_sse2_direct dsl_sse2_y(auc_dst_y);
	s_write_sse2_direct dsl_sse2_co(auc_dst_co);
	s_write_sse2_direct dsl_sse2_cg(auc_dst_cg);
#endif
	while(in_mmx_pixels > 0) {

#if 1
		FILL_MMX(0);
		FILL_MMX(1);
		FILL_MMX(2);
		FILL_MMX(3);
#else
		sK[0] = _mm_loadu_si128((__m128i*)auc_cur);
		sK[1] = _mm_loadu_si128((__m128i*)(auc_cur+16));
		sK[2] = _mm_loadu_si128((__m128i*)(auc_cur+32));
		sK[3] = _mm_loadu_si128((__m128i*)(auc_cur+48));
		auc_cur += 64;
#endif
		rgb2cocgy_mmx<IM_RED_INDEX, IM_GREEN_INDEX, IM_BLUE_INDEX>(
			sK, in_cll, dsl_sse2_y, dsl_sse2_co, dsl_sse2_cg);
		in_mmx_pixels--;
		if(auc_cur == auc_srcline_end) {
			auc_src += im_scanline;
			auc_srcline_end += im_scanline;
			auc_cur = auc_src;
			im_h++;
		}
	}
	/* Convert the rest of pixels (0-15 pixels). */
	while(im_h++ < im_height) {
		while(auc_cur < auc_srcline_end) {
			int im_red = auc_cur[IM_RED_INDEX];
			int im_green = auc_cur[IM_GREEN_INDEX];
			int im_blue = auc_cur[IM_BLUE_INDEX];
			// Y
			dsl_sse2_y.write((im_red >> 2) + (im_green >> 1) + (im_blue >> 2));
			//*auc_dst_y++ = (im_red >> 2) + (im_green >> 1) + (im_blue >> 2);
			// Co
			dsl_sse2_co.write((im_red - im_blue) >> in_cll);
			// Cg
			dsl_sse2_cg.write((-(im_red >> 1) + im_green - (im_blue >> 1)) >> in_cll);
			//*auc_dst_cg++ = (-(im_red >> 1) + im_green - (im_blue >> 1)) >> in_cll;
			auc_cur += IM_STEP;
		}
		auc_src += im_scanline;
		auc_cur = auc_src; 
		auc_srcline_end = auc_src + im_width_step;
	}
#if 0
	auc_src = auc_src_old; 
	auc_dst_y = auc_dst_y_old;
	auc_dst_co = auc_dst_co_old;
	auc_dst_cg = auc_dst_cg_old;
	im_h = 0;

	while(++im_h <= im_height) {
		auc_cur = auc_src; 
		auc_srcline_end = auc_src + im_width_step;
		int im_x = 0;
		//printf("h=%d auc_cur=%p\n", im_h-1, auc_cur);
		//m_console_out((char*)auc_cur, 16*4);
		while(auc_cur < auc_srcline_end) {
			int im_red = auc_cur[IM_RED_INDEX];
			int im_green = auc_cur[IM_GREEN_INDEX];
			int im_blue = auc_cur[IM_BLUE_INDEX];
			// Y
			unsigned char ch_y = (im_red >> 2) + (im_green >> 1) + (im_blue >> 2);
			// Co
			unsigned char ch_co = (im_red - im_blue) >> in_cll;
			// Cg
			unsigned char ch_cg = (-(im_red >> 1) + im_green - (im_blue >> 1)) >> in_cll;

			if(ch_y != *auc_dst_y || ch_co != *auc_dst_co || ch_cg != *auc_dst_cg)
				return;
			auc_dst_y++;
			auc_dst_co++;
			auc_dst_cg++;
			auc_cur += IM_STEP;
			im_x++;
		}
		auc_src += im_scanline;
	}
#endif
#else
	while(++im_h <= im_height) {
		const unsigned char* auc_cur = auc_src; 
		const unsigned char* const auc_srcline_end = auc_src + im_width_step;
#if 0
#if 0
		unsigned char ucr_srctest[64];
		//unsigned char* auc_pad_src = (unsigned char*)(((size_t)(ucr_srctest + 15)) & ~0xf);
		unsigned char* auc_pad_src = ucr_srctest;
		for(int in_i=0, in_pix=0; in_i<64; in_i+=4) {
			auc_pad_src[in_i+0] = 0x00 + in_pix;
			auc_pad_src[in_i+1] = 0x40 + in_pix;
			auc_pad_src[in_i+2] = 0x80 + in_pix;
			auc_pad_src[in_i+3] = 0xA0 + in_pix;
			in_pix++;
		}
/*
		for(int in_i=0, in_pix=0; in_i<64; in_i+=4) {
			auc_pad_src[in_i+IM_RED_INDEX] = 0xe2;
			auc_pad_src[in_i+IM_GREEN_INDEX] = 0xe2;
			auc_pad_src[in_i+IM_BLUE_INDEX] = 0xe3;
			in_pix++;
		}*/
		
		rgb2cocgy_mmx(auc_pad_src, in_cll, auc_dst_y, auc_dst_co, auc_dst_cg);
#endif
		unsigned char* auc_dst_y_orig = auc_dst_y;
		unsigned char* auc_dst_co_orig = auc_dst_co;
		unsigned char* auc_dst_cg_orig = auc_dst_cg; 
		while(auc_cur < auc_srcline_end) {
			rgb2cocgy_mmx(auc_cur, in_cll, auc_dst_y, auc_dst_co, auc_dst_cg);
			auc_cur += 64;
			auc_dst_y += 16;
			auc_dst_co += 16;
			auc_dst_cg += 16;
		}
#if 1
		auc_cur = auc_src;
		auc_dst_y = auc_dst_y_orig;
		auc_dst_co = auc_dst_co_orig;
		auc_dst_cg = auc_dst_cg_orig;
		while(auc_cur < auc_srcline_end) {
			int im_red = auc_cur[IM_RED_INDEX];
			int im_green = auc_cur[IM_GREEN_INDEX];
			int im_blue = auc_cur[IM_BLUE_INDEX];
			// Y
			unsigned char ch_y = (im_red >> 2) + (im_green >> 1) + (im_blue >> 2);
			// Co
			unsigned char ch_co = (im_red - im_blue) >> in_cll;
			// Cg
			unsigned char ch_cg = (-(im_red >> 1) + im_green - (im_blue >> 1)) >> in_cll;

			if(ch_y != *auc_dst_y || ch_co != *auc_dst_co || ch_cg != *auc_dst_cg)
				return;
			auc_dst_y++;
			auc_dst_co++;
			auc_dst_cg++;
			auc_cur += IM_STEP;
		}
#endif
#else
		while(auc_cur < auc_srcline_end) {
			int im_red = auc_cur[IM_RED_INDEX];
			int im_green = auc_cur[IM_GREEN_INDEX];
			int im_blue = auc_cur[IM_BLUE_INDEX];
			// Y
			*auc_dst_y++ = (im_red >> 2) + (im_green >> 1) + (im_blue >> 2);
			// Co
			*auc_dst_co++ = (im_red - im_blue) >> in_cll;
			// Cg
			*auc_dst_cg++ = (-(im_red >> 1) + im_green - (im_blue >> 1)) >> in_cll;
			auc_cur += IM_STEP;
		}
#endif
		auc_src += im_scanline;
	}
#endif
}

template<int IM_STEP, int IM_RED_INDEX, int IM_GREEN_INDEX, int IM_BLUE_INDEX> static void rgb2cocgy2(
	const unsigned char* auc_src, int im_width, int im_height, int im_scanline,
	const int in_cll, unsigned char* auc_dst)
{
	const int im_width_step = im_width * IM_STEP;
	int im_h = 0;
	while(++im_h <= im_height) {
		const unsigned char* auc_cur = auc_src; 
		const unsigned char* const auc_srcline_end = auc_src + im_width_step;
#define RGB2COCGY(src, dst) { \
		int im_red = src[IM_RED_INDEX]; \
		int im_green = src[IM_GREEN_INDEX]; \
		int im_blue = src[IM_BLUE_INDEX]; \
		*dst++ = (im_red >> 2) + (im_green >> 1) + (im_blue >> 2); \
		*dst++ = (im_red - im_blue) >> in_cll; \
		*dst++ = (-(im_red >> 1) + im_green - (im_blue >> 1)) >> in_cll; \
		src += IM_STEP; } \

#define GET_R(src) ((int)(src[IM_RED_INDEX]))
#define GET_G(src) ((int)(src[IM_GREEN_INDEX]))
#define GET_B(src) ((int)(src[IM_BLUE_INDEX]))
#define _RGB2COCGY(src, dst) { \
		*dst++ = (GET_R(src) >> 2) + (GET_G(src) >> 1) + (GET_B(src) >> 2); \
		*dst++ = (GET_R(src) - GET_B(src)) >> in_cll; \
		*dst++ = (-(GET_R(src) >> 1) + GET_G(src) - (GET_B(src) >> 1)) >> in_cll; \
		src += IM_STEP; } \

#undef _RGB2COCGY
#define _RGB2COCGY(src, dst) { \
		int im_co = (GET_R(src) >> 2) + (GET_G(src) >> 1) + (GET_B(src) >> 2); \
		int im_cg = (GET_R(src) - GET_B(src)) >> in_cll; \
		int im_y = (-(GET_R(src) >> 1) + GET_G(src) - (GET_B(src) >> 1)) >> in_cll; \
		*dst++ = im_co; \
		*dst++ = im_cg; \
		*dst++ = im_y; \
		src += IM_STEP; } \

#if 0
		unsigned char ucr_srctest[64];
		//unsigned char* auc_pad_src = (unsigned char*)(((size_t)(ucr_srctest + 15)) & ~0xf);
		unsigned char* auc_pad_src = ucr_srctest;
		for(int in_i=0, in_pix=0; in_i<64; in_i+=4) {
			auc_pad_src[in_i+0] = 0x00 + in_pix;
			auc_pad_src[in_i+1] = 0x40 + in_pix;
			auc_pad_src[in_i+2] = 0x80 + in_pix;
			auc_pad_src[in_i+3] = 0xA0 + in_pix;
			in_pix++;
		}

		rgb2cocgy_mmx(auc_pad_src, auc_dst, in_cll);
		while(true && auc_cur < auc_srcline_end) {
			rgb2cocgy_mmx(auc_cur, auc_dst, in_cll);
			auc_cur += 64;
			auc_dst += 64;
		}
#endif
		while(auc_cur < auc_srcline_end) {
#if 1
			RGB2COCGY(auc_cur, auc_dst);
			/*RGB2COCGY(auc_cur, auc_dst);
			RGB2COCGY(auc_cur, auc_dst);
			RGB2COCGY(auc_cur, auc_dst);
			RGB2COCGY(auc_cur, auc_dst);
			RGB2COCGY(auc_cur, auc_dst);
			RGB2COCGY(auc_cur, auc_dst);
			RGB2COCGY(auc_cur, auc_dst);*/
#else
#if 1
			if(IM_STEP != 4) {
				int im_red = auc_cur[IM_RED_INDEX];
				int im_green = auc_cur[IM_GREEN_INDEX];
				int im_blue = auc_cur[IM_BLUE_INDEX];
				auc_cur += IM_STEP;
				// Y
				*auc_dst++ = (im_red >> 2) + (im_green >> 1) + (im_blue >> 2);
				// Co
				*auc_dst++ = (im_red - im_blue) >> in_cll;
				// Cg
				*auc_dst++ = (-(im_red >> 1) + im_green - (im_blue >> 1)) >> in_cll;
			}
			else {
				struct s_rgba {
					unsigned char chr_pix[4];
				};
				/*uint32_t um_pix = *((uint32_t*)auc_cur);
				int im_red = ((unsigned char*)&um_pix)[IM_RED_INDEX];
				int im_green = ((unsigned char*)&um_pix)[IM_GREEN_INDEX];
				int im_blue = ((unsigned char*)&um_pix)[IM_BLUE_INDEX];*/
				struct s_rgba ds_rgba = *((s_rgba*)auc_cur);
				int im_red = ds_rgba.chr_pix[IM_RED_INDEX];
				int im_green = ds_rgba.chr_pix[IM_GREEN_INDEX];
				int im_blue = ds_rgba.chr_pix[IM_BLUE_INDEX];
				/*
				const int IM_SWAP = 0;
				int im_red = (unsigned char)(um_pix >> (IM_SWAP+(IM_RED_INDEX*8)));
				int im_green = (unsigned char)(um_pix >> (IM_SWAP+(IM_GREEN_INDEX*8)));
				int im_blue = (unsigned char)(um_pix >> (IM_SWAP+(IM_BLUE_INDEX*8)));*/
				auc_cur += IM_STEP;
				// Y
				*auc_dst++ = (im_red >> 2) + (im_green >> 1) + (im_blue >> 2);
				// Co
				*auc_dst++ = (im_red - im_blue) >> in_cll;
				// Cg
				*auc_dst++ = (-(im_red >> 1) + im_green - (im_blue >> 1)) >> in_cll;
			}
#endif
#endif
		}
		auc_src += im_scanline;
	}
}

template<int IM_STEP, class WRITER> static BOOL m_bitmap_compr_6_rgb(struct dsd_bitmap_compr_6* adsp_bmc6, WRITER& ds_w) {
	int im_header_pos = ds_w.get_position();
	char ch_flags = 0;
	if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_SKIP_ALPHA) != 0)
		ch_flags |= BITMAP_COMPR_6_NO_ALPHA_FLAG;
#if BITMAP_COMPR_6_WRITE_RESERVED
	if(!ds_w.reserve(1))
		return FALSE;
#endif
	if(!ds_w.write_byte(BITMAP_COMPR_6_RLE_COMPRESSED_FLAG | ch_flags))
		return FALSE;
	int im_plane_size = adsp_bmc6->imc_bitmap_width * adsp_bmc6->imc_bitmap_height;
	int im_planes = ((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) != 0) ? 3 : 4;
	int im_uncompressed_size = im_plane_size * im_planes;
#if BITMAP_COMPR_6_NO_UNCOMPRESSED
   if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_NO_UNCOMPRESSED) == 0)
      ds_w.set_stop(ds_w.get_position() + im_uncompressed_size);
#else
   ds_w.set_stop(ds_w.get_position() + im_uncompressed_size);
#endif
   
	int iml_disp_nl = adsp_bmc6->imc_dim_x;      /* displacement next line  */
   int iml_save_fill = 0;                       /* save number of fill     */
   int iml_cur_line = adsp_bmc6->imc_dest_bottom;  /* current line         */
	int iml_dst_width = (adsp_bmc6->imc_dest_right - adsp_bmc6->imc_dest_left) + 1;
	int iml_dst_height = (adsp_bmc6->imc_dest_bottom - adsp_bmc6->imc_dest_top) + 1;
	int iml_pad_bytes = adsp_bmc6->imc_bitmap_width - iml_dst_width;
	int iml_scanline =  -(iml_disp_nl * IM_STEP);

	unsigned char* auc_cur = ((unsigned char*)adsp_bmc6->ac_screen_buffer) + ((iml_cur_line * iml_disp_nl + adsp_bmc6->imc_dest_left) * IM_STEP);
	int im_planeout_start;
	int im_count;
#ifdef _DEBUG
	if(false)
		goto LBL_UNCOMPRESSED;
#endif
	if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
		// Alpha plane
		if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_HAS_ALPHA) != 0)
			im_count = compress_rle_plane<IM_STEP>(auc_cur + 3, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w);
		else
			im_count = compress_rle_plane_fixed(0xff, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w);
		if(im_count < 0)
			goto LBL_UNCOMPRESSED;
	}
	im_planeout_start = ds_w.get_position();
	// Red plane
	im_count = compress_rle_plane<IM_STEP>(auc_cur + 2, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w);
   //printf("compress_rle_plane: red=%d\n", im_count);
   if(im_count < 0)
		goto LBL_UNCOMPRESSED;
	if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_GRAY_COLOR) != 0) {
		int im_planeout_size = ds_w.get_position() - im_planeout_start;
		//printf("im_planeout_size=%d\n", im_planeout_size);
		/* Is enough space left to save two more planes? */
		if(!ds_w.reserve(im_planeout_size<<1))
			return FALSE;
		if(!ds_w.copy_memory(im_planeout_start, im_planeout_size))
			return FALSE;
		if(!ds_w.copy_memory(im_planeout_start, im_planeout_size))
			return FALSE;
		return TRUE;
	}
   // Green plane
	im_count = compress_rle_plane<IM_STEP>(auc_cur + 1, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w);
   //printf("compress_rle_plane: green=%d\n", im_count);
   if(im_count < 0)
		goto LBL_UNCOMPRESSED;
	// Blue plane
	im_count = compress_rle_plane<IM_STEP>(auc_cur + 0, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w);
   //printf("compress_rle_plane: blue=%d\n", im_count);
   if(im_count < 0)
		goto LBL_UNCOMPRESSED;
	return TRUE;
LBL_UNCOMPRESSED:
#if BITMAP_COMPR_6_NO_UNCOMPRESSED
   if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_NO_UNCOMPRESSED) != 0)
      return FALSE;
#endif
	ds_w.seek(im_header_pos);
#if BITMAP_COMPR_6_ALPHA_UNCOMPRESSED
	ch_flags = 0;
	if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_SKIP_ALPHA_UNCOMPRESSED) != 0)
		ch_flags |= BITMAP_COMPR_6_NO_ALPHA_FLAG;
	im_planes = ((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) != 0) ? 3 : 4;
	im_uncompressed_size = im_plane_size * im_planes;
#endif
	ds_w.set_stop(im_header_pos+1+im_uncompressed_size);
   if(!ds_w.reserve(1+im_uncompressed_size))
	   return FALSE;
	if(!ds_w.write_byte(ch_flags))
		return FALSE;
	if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
		// Alpha plane
		if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_HAS_ALPHA) != 0) {
			if(!copy_uncompressed_plane<IM_STEP>(auc_cur + 3, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w))
				return FALSE;
		}
		else {
			if(!ds_w.write_bytes(0xff, im_plane_size))
				return FALSE;
		}
	}
	// Red plane
   if(!copy_uncompressed_plane<IM_STEP>(auc_cur + 2, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w))
		return FALSE;
   // Green plane
	if(!copy_uncompressed_plane<IM_STEP>(auc_cur + 1, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w))
		return FALSE;
	// Blue plane
	if(!copy_uncompressed_plane<IM_STEP>(auc_cur + 0, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w))
		return FALSE;
	return TRUE;
}

template<int IM_STEP, class WRITER> static BOOL m_bitmap_compr_6_cocgy(struct dsd_bitmap_compr_6* adsp_bmc6, WRITER& ds_w) {
	int im_header_pos = ds_w.get_position();
	char ch_flags = adsp_bmc6->inc_cll;
	if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_SKIP_ALPHA) != 0)
		ch_flags |= BITMAP_COMPR_6_NO_ALPHA_FLAG;
	int iml_plane_size = adsp_bmc6->imc_bitmap_width * adsp_bmc6->imc_bitmap_height;
	/* Is source image too large? */
	if(iml_plane_size > BITMAP_COMPR_6_MAX_PIXELS)
		return FALSE;
#if BITMAP_COMPR_6_WRITE_RESERVED
	if(!ds_w.reserve(1))
		return FALSE;
#endif
	if(!ds_w.write_byte(BITMAP_COMPR_6_RLE_COMPRESSED_FLAG | ch_flags))
		return FALSE;
	int im_planes = ((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) != 0) ? 3 : 4;
	int im_uncompressed_size = iml_plane_size * im_planes;
#if BITMAP_COMPR_6_NO_UNCOMPRESSED
   if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_NO_UNCOMPRESSED) == 0)
      ds_w.set_stop(ds_w.get_position() + im_uncompressed_size);
#else
   ds_w.set_stop(ds_w.get_position() + im_uncompressed_size);
#endif

	int iml_disp_nl = adsp_bmc6->imc_dim_x;      /* displacement next line  */
   int iml_cur_line = adsp_bmc6->imc_dest_bottom;  /* current line         */
	int iml_dst_width = (adsp_bmc6->imc_dest_right - adsp_bmc6->imc_dest_left) + 1;
	int iml_dst_height = (adsp_bmc6->imc_dest_bottom - adsp_bmc6->imc_dest_top) + 1;
	int iml_pad_bytes = adsp_bmc6->imc_bitmap_width - iml_dst_width;
	int iml_scanline = -(iml_disp_nl * IM_STEP);

#define BITMAP_COMPR_6_RGB2COGY2	0
#define BITMAP_COMPR_6_FUNC_RGB2COGY	rgb2cocgy2
#if BITMAP_COMPR_6_RGB2COGY2
	unsigned char ucr_cocgy[BITMAP_COMPR_6_MAX_PIXELS*3];
	unsigned char* auc_y = ucr_cocgy;
	unsigned char* auc_co = ucr_cocgy + 1;
	unsigned char* auc_cg = ucr_cocgy + 2;
	const int IM_COCGY_STEP = 3;
#else
	__ALIGN(16) unsigned char ucr_cocgy[BITMAP_COMPR_6_MAX_PIXELS*3];
#if BITMAP_COMPR_6_USE_SSE2_ALIGNED
   int iml_aligned_scanline = HOB_PAD_INTEGER(iml_dst_width, 16);
#else
   int iml_aligned_scanline = iml_dst_width;
#endif
   int iml_aligned_planesize = iml_aligned_scanline * iml_dst_height;
	unsigned char* auc_y = ucr_cocgy;
	unsigned char* auc_co = auc_y + iml_aligned_planesize;
	unsigned char* auc_cg = auc_co + iml_aligned_planesize;
	const int IM_COCGY_STEP = 1;
#endif

	unsigned char* auc_src = ((unsigned char*)adsp_bmc6->ac_screen_buffer)
		+ ((adsp_bmc6->imc_dest_bottom * iml_disp_nl + adsp_bmc6->imc_dest_left) * IM_STEP);
	unsigned char* auc_alpha = auc_src + 3;
#if 1
	if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
#if BITMAP_COMPR_6_RGB2COGY2
		rgb2cocgy2<IM_STEP, 2, 1, 0>(auc_src, iml_dst_width, iml_dst_height, iml_scanline,
			adsp_bmc6->inc_cll, ucr_cocgy);
#else
		rgb2cocgy<IM_STEP, 2, 1, 0>(auc_src, iml_dst_width, iml_dst_height, iml_scanline,
			adsp_bmc6->inc_cll, auc_y, auc_co, auc_cg);
#endif
	}
	else {
#if BITMAP_COMPR_6_RGB2COGY2
		rgb2cocgy2<IM_STEP, 0, 1, 2>(auc_src, iml_dst_width, iml_dst_height, iml_scanline,
			adsp_bmc6->inc_cll, ucr_cocgy);
#else
		rgb2cocgy<IM_STEP, 0, 1, 2>(auc_src, iml_dst_width, iml_dst_height, iml_scanline,
			adsp_bmc6->inc_cll, auc_y, auc_co, auc_cg);
#endif
	}
#endif
#if 0
	if(ucr_cocgy[0] == ucr_cocgy[1])
		return TRUE;
	if(ucr_cocgy[0] != ucr_cocgy[1])
		return TRUE;
#endif
   //printf("m_bitmap_compr_6_cocgy ch_flags=%02X adsp_bmc6->bo_skip_alpha=%d\n", ch_flags, adsp_bmc6->bo_skip_alpha);
	int im_count;
#ifdef _DEBUG
	if(false)
		goto LBL_UNCOMPRESSED;
#endif
	int iml_scanline_ss;
	if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
		// Alpha plane
		if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_HAS_ALPHA) != 0)
			im_count = compress_rle_plane<IM_STEP>(auc_alpha, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w);
		else
			im_count = compress_rle_plane_fixed(0xff, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w);
		if(im_count < 0)
			goto LBL_UNCOMPRESSED;
	}
#if BITMAP_COMPR_6_USE_SSE2_ALIGNED
	iml_scanline_ss = iml_aligned_scanline;
#else
	iml_scanline_ss = iml_dst_width;
#endif
	// Y plane
	im_count = compress_rle_plane<IM_COCGY_STEP>(auc_y, iml_dst_width, iml_pad_bytes, iml_scanline_ss, iml_dst_height, ds_w);
	//printf("compress_rle_plane: red=%d\n", im_count);
	if(im_count < 0)
		goto LBL_UNCOMPRESSED;
	// Co plane
	im_count = compress_rle_plane<IM_COCGY_STEP>(auc_co, iml_dst_width, iml_pad_bytes, iml_scanline_ss, iml_dst_height, ds_w);
	//printf("compress_rle_plane: green=%d\n", im_count);
	if(im_count < 0)
		goto LBL_UNCOMPRESSED;
	// Cg plane
	im_count = compress_rle_plane<IM_COCGY_STEP>(auc_cg, iml_dst_width, iml_pad_bytes, iml_scanline_ss, iml_dst_height, ds_w);
	//printf("compress_rle_plane: blue=%d\n", im_count);
	if(im_count < 0)
		goto LBL_UNCOMPRESSED;
	return TRUE;
LBL_UNCOMPRESSED:
#if BITMAP_COMPR_6_NO_UNCOMPRESSED
   if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_NO_UNCOMPRESSED) != 0)
      return FALSE;
#endif
   ds_w.seek(im_header_pos);
#if BITMAP_COMPR_6_ALPHA_UNCOMPRESSED
   char ch_old_flags = ch_flags;
   ch_flags = adsp_bmc6->inc_cll;
	if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_SKIP_ALPHA_UNCOMPRESSED) != 0)
		ch_flags |= BITMAP_COMPR_6_NO_ALPHA_FLAG;
	im_planes = ((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) != 0) ? 3 : 4;
	im_uncompressed_size = iml_plane_size * im_planes;
   ds_w.set_stop(im_header_pos+1+im_uncompressed_size);
#endif
	if(!ds_w.reserve(1+im_uncompressed_size))
		return FALSE;
	if(!ds_w.write_byte(ch_flags))
		return FALSE;
#if BITMAP_COMPR_6_ALPHA_UNCOMPRESSED
   if(ch_old_flags != ch_flags) {
      if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
#if BITMAP_COMPR_6_RGB2COGY2
			rgb2cocgy2<IM_STEP, 2, 1, 0>(auc_src, iml_dst_width, iml_dst_height, iml_scanline,
            adsp_bmc6->inc_cll, ucr_cocgy);
#else
			rgb2cocgy<IM_STEP, 2, 1, 0>(auc_src, iml_dst_width, iml_dst_height, iml_scanline,
            adsp_bmc6->inc_cll, auc_y, auc_co, auc_cg);
#endif
		}
      else {
#if BITMAP_COMPR_6_RGB2COGY2
         rgb2cocgy2<IM_STEP, 0, 1, 2>(auc_src, iml_dst_width, iml_dst_height, iml_scanline,
            adsp_bmc6->inc_cll, ucr_cocgy);
#else
         rgb2cocgy<IM_STEP, 0, 1, 2>(auc_src, iml_dst_width, iml_dst_height, iml_scanline,
            adsp_bmc6->inc_cll, auc_y, auc_co, auc_cg);
#endif
      }
   }
#endif
	if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
		// Alpha plane
		if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_HAS_ALPHA) != 0) {
			if(!copy_uncompressed_plane<IM_STEP>(auc_alpha, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w))
				return FALSE;
		}
		else {
			if(!ds_w.write_bytes(0xff, iml_plane_size))
				return FALSE;
		}
	}
	// Y plane
   if(!copy_uncompressed_plane<IM_COCGY_STEP>(auc_y, iml_dst_width, iml_pad_bytes, iml_scanline_ss, iml_dst_height, ds_w))
		return FALSE;
   // Co plane
	if(!copy_uncompressed_plane<IM_COCGY_STEP>(auc_co, iml_dst_width, iml_pad_bytes, iml_scanline_ss, iml_dst_height, ds_w))
		return FALSE;
	// Cg plane
	if(!copy_uncompressed_plane<IM_COCGY_STEP>(auc_cg, iml_dst_width, iml_pad_bytes, iml_scanline_ss, iml_dst_height, ds_w))
		return FALSE;
   return TRUE;
}

struct s_cocgy {
	int imc_cg;
	int imc_co;
	int imc_y;
public:
	s_cocgy(int im_red, int im_green, int im_blue) {
		this->imc_cg = (-(im_red >> 1) + im_green - (im_blue >> 1));
		this->imc_co = (im_red - im_blue);
		this->imc_y = (im_red >> 2) + (im_green >> 1) + (im_blue >> 2);
	}
};

template<int IM_STEP, int IM_RED_INDEX, int IM_GREEN_INDEX, int IM_BLUE_INDEX> static void rgb2cocgyss(
	const unsigned char* auc_src, int im_width, int im_pad_pix, int im_scanline, int im_height,
	int in_cll, unsigned char* auc_dst_co, unsigned char* auc_dst_cg, unsigned char* auc_dst_y)
{
#define MAKE_COCGY(varname, src) s_cocgy varname((src)[IM_RED_INDEX], (src)[IM_GREEN_INDEX], (src)[IM_BLUE_INDEX])
	//printf("rgb2cocgyss: im_width=%d im_height=%d\n", im_width, im_height);
	const int im_width_step2 = (im_width & ~0x1) * IM_STEP;
	const int im_width_step = im_width * IM_STEP;
	const int im_pad_pix2 = ((im_width+im_pad_pix+1)>>1) - ((im_width+1)>>1);
	int im_h = 0;
	while(++im_h <= (im_height>>1)) {
		const unsigned char* auc_srcline1 = auc_src; 
		const unsigned char* auc_srcline2 = auc_src + im_scanline;
		const unsigned char* const auc_srcline1_end = auc_src + (im_width_step2 & ~0x1);
		unsigned char* auc_dstline_y1 = auc_dst_y;
		unsigned char* auc_dstline_y2 = auc_dst_y + (im_width + im_pad_pix);
		while(auc_srcline1 < auc_srcline1_end) {
			MAKE_COCGY(ds_col1, auc_srcline1);
			*auc_dstline_y1++ = (unsigned char)ds_col1.imc_y;
			auc_srcline1 += IM_STEP;
			MAKE_COCGY(ds_col2, auc_srcline1);
			ds_col1.imc_cg += ds_col2.imc_cg; 
			ds_col1.imc_co += ds_col2.imc_co; 
			*auc_dstline_y1++ = (unsigned char)ds_col2.imc_y;
			auc_srcline1 += IM_STEP;
			MAKE_COCGY(ds_col3, auc_srcline2);
			ds_col1.imc_cg += ds_col3.imc_cg; 
			ds_col1.imc_co += ds_col3.imc_co; 
			*auc_dstline_y2++ = (unsigned char)ds_col3.imc_y;
			auc_srcline2 += IM_STEP;
			MAKE_COCGY(ds_col4, auc_srcline2);
			ds_col1.imc_cg += ds_col4.imc_cg; 
			ds_col1.imc_co += ds_col4.imc_co; 
			*auc_dstline_y2++ = (unsigned char)ds_col4.imc_y;
			auc_srcline2 += IM_STEP;
		
			*auc_dst_co++ = ds_col1.imc_co >> (2 + in_cll);
			*auc_dst_cg++ = ds_col1.imc_cg >> (2 + in_cll);
		}
		if(auc_srcline1 < auc_src + im_width_step) {
			MAKE_COCGY(ds_col1, auc_srcline1);
			*auc_dstline_y1++ = (unsigned char)ds_col1.imc_y;
			MAKE_COCGY(ds_col3, auc_srcline2);
			ds_col1.imc_cg += ds_col3.imc_cg; 
			ds_col1.imc_co += ds_col3.imc_co; 
			*auc_dstline_y2++ = (unsigned char)ds_col3.imc_y;
			
			*auc_dst_co++ = ds_col1.imc_co >> (1 + in_cll);
			*auc_dst_cg++ = ds_col1.imc_cg >> (1 + in_cll);
		}
		auc_dst_y += (im_width + im_pad_pix) << 1;
		for(int im_i=0; im_i<im_pad_pix2; im_i++) {
			*auc_dst_co++ = 0;
			*auc_dst_cg++ = 0;
		}
		auc_src += (im_scanline * 2);
		//printf("   auc_dstline_y1=%p\n", auc_dstline_y1);
		//printf("   auc_dstline_y2=%p\n", auc_dstline_y2);
	}
	if((im_height & 0x1) != 0) {
		const unsigned char* auc_srcline1 = auc_src; 
		const unsigned char* const auc_srcline1_end = auc_src + (im_width_step2 & ~0x1);
		unsigned char* auc_dstline_y1 = auc_dst_y;
		while(auc_srcline1 < auc_srcline1_end) {
			MAKE_COCGY(ds_col1, auc_srcline1);
			*auc_dstline_y1++ = (unsigned char)ds_col1.imc_y;
			auc_srcline1 += IM_STEP;
			MAKE_COCGY(ds_col2, auc_srcline1);
			ds_col1.imc_cg += ds_col2.imc_cg; 
			ds_col1.imc_co += ds_col2.imc_co; 
			*auc_dstline_y1++ = (unsigned char)ds_col2.imc_y;
			auc_srcline1 += IM_STEP;
			
			*auc_dst_co++ = ds_col1.imc_co >> (1 + in_cll);
			*auc_dst_cg++ = ds_col1.imc_cg >> (1 + in_cll);
		}
		if(auc_srcline1 < auc_src + im_width_step) {
			MAKE_COCGY(ds_col1, auc_srcline1);
			*auc_dstline_y1++ = (unsigned char)ds_col1.imc_y;
			
			*auc_dst_co++ = ds_col1.imc_co >> (1 + in_cll);
			*auc_dst_cg++ = ds_col1.imc_cg >> (1 + in_cll);
		}
		for(int im_i=0; im_i<im_pad_pix2; im_i++) {
			*auc_dst_co++ = 0;
			*auc_dst_cg++ = 0;
		}
	}
	//printf("auc_dst_y=%p\n", auc_dst_y);
#undef MAKE_COCGY
}

template<int IM_STEP, class WRITER> static BOOL m_bitmap_compr_6_cocgyss(struct dsd_bitmap_compr_6* adsp_bmc6, WRITER& ds_w) {
	int im_header_pos = ds_w.get_position();
	char ch_flags = BITMAP_COMPR_6_COLOR_SUBSAMPLING_FLAG | adsp_bmc6->inc_cll;
	if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_SKIP_ALPHA) != 0)
		ch_flags |= BITMAP_COMPR_6_NO_ALPHA_FLAG;
#if BITMAP_COMPR_6_WRITE_RESERVED
	if(!ds_w.reserve(1))
		return FALSE;
#endif
	if(!ds_w.write_byte(BITMAP_COMPR_6_RLE_COMPRESSED_FLAG | ch_flags))
		return FALSE;

	int iml_disp_nl = adsp_bmc6->imc_dim_x;      /* displacement next line  */
   int iml_dst_width = (adsp_bmc6->imc_dest_right - adsp_bmc6->imc_dest_left) + 1;
	int iml_dst_height = (adsp_bmc6->imc_dest_bottom - adsp_bmc6->imc_dest_top) + 1;
	int iml_pad_bytes = adsp_bmc6->imc_bitmap_width - iml_dst_width;
	int iml_scanline =  -(iml_disp_nl * IM_STEP);

	int im_dst_width_ss = (iml_dst_width + 1) >> 1;
	int im_dst_height_ss = (iml_dst_height + 1) >> 1;
	int im_bitmap_width_ss = (adsp_bmc6->imc_bitmap_width + 1) >> 1;
	int im_bitmap_height_ss = (adsp_bmc6->imc_bitmap_height + 1) >> 1;

	int iml_plane_size = adsp_bmc6->imc_bitmap_width * adsp_bmc6->imc_bitmap_height;
	int iml_plane_size_ss = im_bitmap_width_ss * im_bitmap_height_ss;
	int im_planes = ((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) != 0) ? 1 : 2;
	int im_uncompressed_size = (iml_plane_size * im_planes) + (iml_plane_size_ss << 1);
#if BITMAP_COMPR_6_NO_UNCOMPRESSED
   if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_NO_UNCOMPRESSED) == 0)
      ds_w.set_stop(ds_w.get_position() + im_uncompressed_size);
#else
   ds_w.set_stop(ds_w.get_position() + im_uncompressed_size);
#endif

	unsigned char ucr_cocgy[BITMAP_COMPR_6_MAX_PIXELS+(BITMAP_COMPR_6_MAX_PIXELS/4)*2];
	unsigned char* auc_y = ucr_cocgy;
	unsigned char* auc_co = auc_y + iml_plane_size;
	unsigned char* auc_cg = auc_co + iml_plane_size_ss;
	/* Is source image too large? */
	if(auc_cg + iml_plane_size_ss > ucr_cocgy+sizeof(ucr_cocgy))
		return FALSE;
   
	unsigned char* auc_src = ((unsigned char*)adsp_bmc6->ac_screen_buffer)
		+ ((adsp_bmc6->imc_dest_bottom * iml_disp_nl + adsp_bmc6->imc_dest_left) * IM_STEP);
   unsigned char* auc_alpha = auc_src + 3;
	if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
		rgb2cocgyss<IM_STEP, 2, 1, 0>(auc_src, iml_dst_width, iml_pad_bytes, iml_scanline,
			iml_dst_height, adsp_bmc6->inc_cll, auc_co, auc_cg, auc_y);
	}
	else {
		rgb2cocgyss<IM_STEP, 0, 1, 2>(auc_src, iml_dst_width, iml_pad_bytes, iml_scanline,
			iml_dst_height, adsp_bmc6->inc_cll, auc_co, auc_cg, auc_y);
	}
	int iml_pad_bytes_ss = im_bitmap_width_ss - im_dst_width_ss;

#ifdef _DEBUG
	if(false) {
		ds_w.skip(2*256+128);
		ds_w.seek(256+1);
		goto LBL_UNCOMPRESSED;
	}
#endif
	int im_count;
	if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
		// Alpha plane
		if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_HAS_ALPHA) != 0)
			im_count = compress_rle_plane<IM_STEP>(auc_alpha, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w);
		else
			im_count = compress_rle_plane_fixed(0xff, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w);
		if(im_count < 0)
			goto LBL_UNCOMPRESSED;
	}
	// Y plane
	im_count = compress_rle_plane<1>(auc_y, iml_dst_width, iml_pad_bytes, adsp_bmc6->imc_bitmap_width, iml_dst_height, ds_w);
	//printf("compress_rle_plane: red=%d\n", im_count);
	if(im_count < 0)
		goto LBL_UNCOMPRESSED;
	// Co plane
	im_count = compress_rle_plane<1>(auc_co, im_dst_width_ss, iml_pad_bytes_ss, im_bitmap_width_ss, im_dst_height_ss, ds_w);
	//printf("compress_rle_plane: green=%d\n", im_count);
	if(im_count < 0)
		goto LBL_UNCOMPRESSED;
	// Cg plane
	im_count = compress_rle_plane<1>(auc_cg, im_dst_width_ss, iml_pad_bytes_ss, im_bitmap_width_ss, im_dst_height_ss, ds_w);
	//printf("compress_rle_plane: blue=%d\n", im_count);
	if(im_count < 0)
		goto LBL_UNCOMPRESSED;
	return TRUE;
LBL_UNCOMPRESSED:
#if BITMAP_COMPR_6_NO_UNCOMPRESSED
   if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_NO_UNCOMPRESSED) != 0)
      return FALSE;
#endif
	ds_w.seek(im_header_pos);
#if BITMAP_COMPR_6_ALPHA_UNCOMPRESSED
   char ch_old_flags = ch_flags;
	ch_flags = BITMAP_COMPR_6_COLOR_SUBSAMPLING_FLAG | adsp_bmc6->inc_cll;
	if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_SKIP_ALPHA_UNCOMPRESSED) != 0)
		ch_flags |= BITMAP_COMPR_6_NO_ALPHA_FLAG;
	im_planes = ((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) != 0) ? 1 : 2;
	im_uncompressed_size = (iml_plane_size * im_planes) + (iml_plane_size_ss << 1);
   ds_w.set_stop(im_header_pos+1+im_uncompressed_size);
#endif
	if(!ds_w.reserve(1+im_uncompressed_size))
		return false;
	if(!ds_w.write_byte(ch_flags))
		return FALSE;
#if BITMAP_COMPR_6_ALPHA_UNCOMPRESSED
   if(ch_old_flags != ch_flags) {
      if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
         rgb2cocgyss<IM_STEP, 2, 1, 0>(auc_src, iml_dst_width, iml_pad_bytes, iml_scanline,
            iml_dst_height, adsp_bmc6->inc_cll, auc_co, auc_cg, auc_y);
      }
      else {
         rgb2cocgyss<IM_STEP, 0, 1, 2>(auc_src, iml_dst_width, iml_pad_bytes, iml_scanline,
            iml_dst_height, adsp_bmc6->inc_cll, auc_co, auc_cg, auc_y);
      }
   }
#endif      
	if((ch_flags & BITMAP_COMPR_6_NO_ALPHA_FLAG) == 0) {
		// Alpha plane
		if((adsp_bmc6->inc_compression_flags & dsd_bitmap_compr_6::FLAG_HAS_ALPHA) != 0) {
			if(!copy_uncompressed_plane<IM_STEP>(auc_alpha, iml_dst_width, iml_pad_bytes, iml_scanline, iml_dst_height, ds_w))
				return FALSE;
		}
		else {
			if(!ds_w.write_bytes(0xff, iml_plane_size))
				return FALSE;
		}
	}
	// Y plane
   if(!copy_uncompressed_plane<1>(auc_y, iml_dst_width, iml_pad_bytes, adsp_bmc6->imc_bitmap_width, iml_dst_height, ds_w))
		return FALSE;
   // Co plane
	if(!copy_uncompressed_plane<1>(auc_co, im_dst_width_ss, iml_pad_bytes_ss, im_bitmap_width_ss, im_dst_height_ss, ds_w))
		return FALSE;
	// Cg plane
	if(!copy_uncompressed_plane<1>(auc_cg, im_dst_width_ss, iml_pad_bytes_ss, im_bitmap_width_ss, im_dst_height_ss, ds_w))
		return FALSE;
	return TRUE;
}

static BOOL m_bitmap_compr_6_simple(struct dsd_bitmap_compr_6* adsp_bmc1) {
	if ((int)(adsp_bmc1->achc_wa_free_end - adsp_bmc1->achc_wa_free_start) <= (int)sizeof(struct dsd_gather_i_1))
		return FALSE;
	struct dsd_gather_i_1 * achc_ginp_cur = ((struct dsd_gather_i_1 *) adsp_bmc1->achc_wa_free_end) - 1;
	adsp_bmc1->achc_wa_free_end -= sizeof(struct dsd_gather_i_1);
	adsp_bmc1->adsc_gai1_out = achc_ginp_cur;  /* output data         */
	c_simple_writer ds_w(adsp_bmc1);
#if BITMAP_COMPR_6_COCGY
	if(adsp_bmc1->inc_cll != 0) {
		if((adsp_bmc1->inc_compression_flags & dsd_bitmap_compr_6::FLAG_SUBSAMPLING) != 0) {
			if(!m_bitmap_compr_6_cocgyss<4>(adsp_bmc1, ds_w))
				return FALSE;
		}
		else {
			if(!m_bitmap_compr_6_cocgy<4>(adsp_bmc1, ds_w))
				return FALSE;
		}
	}
	else {
#endif
		if(!m_bitmap_compr_6_rgb<4>(adsp_bmc1, ds_w))
			return FALSE;
#if BITMAP_COMPR_6_COCGY
	}
#endif
	achc_ginp_cur->adsc_next = NULL;
	achc_ginp_cur->achc_ginp_cur = adsp_bmc1->achc_wa_free_start;
	ds_w.done();
	return TRUE;
}

static BOOL m_bitmap_compr_6_gathered(struct dsd_bitmap_compr_6* adsp_bmc1) {
	//printf("m_bitmap_compr_6: rest=%d\n", (int)(adsp_bmc1->achc_wa_free_end - adsp_bmc1->achc_wa_free_start));
	if ((int)(adsp_bmc1->achc_wa_free_end - adsp_bmc1->achc_wa_free_start) <= (int)sizeof(struct dsd_gather_i_1)) {
		BOOL bol1 = adsp_bmc1->amc_get_workarea( adsp_bmc1 );
		if (bol1 == FALSE) return FALSE;       /* error occured           */
		if ((int)(adsp_bmc1->achc_wa_free_end - adsp_bmc1->achc_wa_free_start) <= (int)sizeof(struct dsd_gather_i_1)) {
			return FALSE;
		}
   }
	struct dsd_gather_i_1 * achc_ginp_cur = ((struct dsd_gather_i_1 *) adsp_bmc1->achc_wa_free_end) - 1;
   adsp_bmc1->achc_wa_free_end -= sizeof(struct dsd_gather_i_1);
	achc_ginp_cur->adsc_next = NULL;
	achc_ginp_cur->achc_ginp_cur = adsp_bmc1->achc_wa_free_start;
	achc_ginp_cur->achc_ginp_end = adsp_bmc1->achc_wa_free_end;
   adsp_bmc1->adsc_gai1_out = achc_ginp_cur;  /* output data         */
	c_gather_writer ds_w(adsp_bmc1);
#if BITMAP_COMPR_6_COCGY
	if(adsp_bmc1->inc_cll != 0) {
		if((adsp_bmc1->inc_compression_flags & dsd_bitmap_compr_6::FLAG_SUBSAMPLING) != 0) {
			if(!m_bitmap_compr_6_cocgyss<4>(adsp_bmc1, ds_w))
				return FALSE;
		}
		else {
			if(!m_bitmap_compr_6_cocgy<4>(adsp_bmc1, ds_w))
				return FALSE;
		}
	}
	else {
#endif
		if(!m_bitmap_compr_6_rgb<4>(adsp_bmc1, ds_w))
			return FALSE;
#if BITMAP_COMPR_6_COCGY
	}
#endif
	ds_w.done();
	//achc_ginp_cur->achc_ginp_end = ds_w.done();
	return TRUE;
}

extern "C" BOOL m_bitmap_compr_6(struct dsd_bitmap_compr_1* adsp_bmc1) {
	if (adsp_bmc1->amc_get_workarea == NULL)
		return m_bitmap_compr_6_simple(static_cast<dsd_bitmap_compr_6*>(adsp_bmc1));
	return m_bitmap_compr_6_gathered(static_cast<dsd_bitmap_compr_6*>(adsp_bmc1));
}
