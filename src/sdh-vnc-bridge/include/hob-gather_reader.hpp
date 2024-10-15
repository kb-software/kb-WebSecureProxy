#pragma once
#ifndef __HOB_GATHER_READER__
#define __HOB_GATHER_READER__

// +--------------------------------------------------------------------+
// |                                                                    |
// | PROGRAM NAME: hob-gather_reader.hpp                                |
// | -------------                                                      |
// |  Simple reader, which takes a dsd_gather_i_1 and allows to read    |
// |  data by moving the cur-pointer (read_xx) or to peek data, which   |
// |  does not move the cur-pointer (peek_xx). The reader also allows   |
// |  to hand a number of valid bytes, even if the gather-queue is much |
// |  longer.                                                           |
// |  Johannes Bauer 02.12.2011                                         |
// |                                                                    |
// | COPYRIGHT:                                                         |
// | ----------                                                         |
// |  Copyright (C) HOB Germany 2011                                    |
// |                                                                    |
// +--------------------------------------------------------------------+

/* NECESSARY INCLUDES:
HOB_RDPACC_ALLOW_THROW not set: 
normal windows/unix includes

/* HOB_RDPACC_ALLOW_THROW set: 

normal windows/unix includes
#include <hob-throw_error.hpp>

*/

// DEFINES, WHICH CAN BE SET BEFORE INCLUDING THIS FILE:
// HOB_RDPACC_ALLOW_THROW set this define, if you want the called function to throw a C++-error instead of returning false, 
//                       if there is not enough data to read (dsd_gather_reader) or no memory to write (dsd_gather_writer) 

#define CAST_POINTDIFF_TO_INT(POINTDIFF) ((int) (POINTDIFF))

// +------------------------------+
// | Definition of dsd_gather_i_1 |
// +------------------------------+

#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 {                     /* gather input data       */
   struct dsd_gather_i_1 *adsc_next;        /* next in chain           */
   char *     achc_ginp_cur;                /* current position        */
   char *     achc_ginp_end;                /* end of input data       */
};
#endif

//   __              _   _             __              _        _              _   _            _   _ 
//  / _|_  _ _ _  __| |_(_)___ _ _    / _|___ _ _   __| |___ __| |   __ _ __ _| |_| |_  ___ _ _(_) / |
// |  _| || | ' \/ _|  _| / _ \ ' \  |  _/ _ \ '_| / _` (_-</ _` |  / _` / _` |  _| ' \/ -_) '_| | | |
// |_|  \_,_|_||_\__|\__|_\___/_||_| |_| \___/_|   \__,_/__/\__,_|__\__, \__,_|\__|_||_\___|_|_|_|_|_|
//                                                             |___|___/                   |___|___| 

inline static int m_gather_count(dsd_gather_i_1* adsp_gather){
   int inl = 0;
   while(true){
      if(adsp_gather == NULL)
         return inl;
      inl += CAST_POINTDIFF_TO_INT(adsp_gather->achc_ginp_end - adsp_gather->achc_ginp_cur);
      adsp_gather = adsp_gather->adsc_next;
   }
}

inline static bool m_gather_is_empty(dsd_gather_i_1* adsp_gather){
   while(adsp_gather != NULL){
      if(adsp_gather->achc_ginp_end > adsp_gather->achc_ginp_cur)
         return false;
      adsp_gather = adsp_gather->adsc_next;
   }
   return true;
}

inline static dsd_gather_i_1* m_gather_clear(dsd_gather_i_1* adsp_gather){
   while(true){
      if(adsp_gather == NULL)
         return NULL;
      if(adsp_gather->achc_ginp_end > adsp_gather->achc_ginp_cur)
         return adsp_gather;
      adsp_gather = adsp_gather->adsc_next;
   }
}

inline static dsd_gather_i_1* m_gather_clear(dsd_gather_i_1** aadsp_gather){
   if(aadsp_gather == NULL)
      return NULL;
   while(true){
      if((*aadsp_gather) == NULL)
         return NULL;
      if((*aadsp_gather)->achc_ginp_end > (*aadsp_gather)->achc_ginp_cur)
         return *aadsp_gather;
      *aadsp_gather = (*aadsp_gather)->adsc_next;
   }
}

inline static bool m_gather_skip(dsd_gather_i_1* adsp_gather, int inp_num){
   while(inp_num > 0){
      if(adsp_gather == NULL)
         return false;
      int inl_skip_now = CAST_POINTDIFF_TO_INT(adsp_gather->achc_ginp_end - adsp_gather->achc_ginp_cur);
      if(inl_skip_now > inp_num)
         inl_skip_now = inp_num;
      adsp_gather->achc_ginp_cur += inl_skip_now;
      inp_num -= inl_skip_now;
      adsp_gather = adsp_gather->adsc_next;
   }
   return true; 
}

///////////////////////////////////////////////////////////////////////////////////////////
//      _         _                 _   _                                   _            //
//   __| |___  __| |     __ _  __ _| |_| |__   ___ _ __  _ __ ___  __ _  __| | ___ _ __  //
//  / _` / __|/ _` |    / _` |/ _` | __| '_ \ / _ \ '__|| '__/ _ \/ _` |/ _` |/ _ \ '__| //
// | (_| \__ \ (_| |   | (_| | (_| | |_| | | |  __/ |   | | |  __/ (_| | (_| |  __/ |    //
//  \__,_|___/\__,_|____\__, |\__,_|\__|_| |_|\___|_|___|_|  \___|\__,_|\__,_|\___|_|    //
//                |_____|___/                      |_____|                               //
///////////////////////////////////////////////////////////////////////////////////////////

#ifdef HOB_RDPACC_ALLOW_THROW
#define RETURN_VALUE_IF_NOTHROW 
#define ENSURE(NUM_BYTES)  if(this->inc_bytes_left < (NUM_BYTES)) \
                              THROW_HOB_ERROR("Read out of bounds: this->in_bytes_left=0x%x NUM_BYTES=0x%x", this->inc_bytes_left, NUM_BYTES);
#else
#define RETURN_VALUE_IF_NOTHROW , bool* abop_error
#define ENSURE(NUM_BYTES) if(this->inc_bytes_left < (NUM_BYTES)) return false;
#endif

class dsd_gather_reader {
   dsd_gather_i_1* adsc_gather;
   int inc_bytes_left; 

private:

   // call ENSURE() before, as there is no check!
   inline char get_byte(){ 
      this->inc_bytes_left -= 1;
      return *(this->clear()->achc_ginp_cur++);
   }
   // call ENSURE() before, as there is no check!
   inline int get_byte_as_int(){ 
      this->inc_bytes_left -= 1;
      return ((int)*(this->clear()->achc_ginp_cur++)) & 0xff;
   }

public:

   inline dsd_gather_i_1* clear(){
      this->adsc_gather = m_gather_clear(this->adsc_gather);
      return this->adsc_gather;
   }

   inline dsd_gather_reader(dsd_gather_i_1* adsp_gather) 
    : adsc_gather(adsp_gather), 
      inc_bytes_left(m_gather_count(adsp_gather)) 
   {
   }

   inline dsd_gather_reader(dsd_gather_i_1* adsp_gather, int inp_bytes RETURN_VALUE_IF_NOTHROW) 
    : adsc_gather(adsp_gather), 
      inc_bytes_left(inp_bytes) 
   {
#ifdef HOB_RDPACC_ALLOW_THROW
      if(m_gather_count(adsp_gather) < inp_bytes)
         THROW_HOB_ERROR("Read out of bounds: m_gather_count(ads_gather)=0x%x in_bytes=0x%x", m_gather_count(adsp_gather), inp_bytes);
#else
      *abop_error = m_gather_count(adsp_gather) >= inp_bytes;
#endif
   }

   inline dsd_gather_reader(dsd_gather_reader* adsp_reader, int inp_bytes RETURN_VALUE_IF_NOTHROW) 
    : adsc_gather(adsp_reader->adsc_gather), 
      inc_bytes_left(inp_bytes) 
   {
#ifdef HOB_RDPACC_ALLOW_THROW
      if(adsp_reader->inc_bytes_left < inp_bytes)
         THROW_HOB_ERROR("Read out of bounds: m_gather_count(ads_gather)=0x%x in_bytes=0x%x", m_gather_count(this->adsc_gather), inp_bytes);
#else
      *abop_error = adsp_reader->inc_bytes_left >= inp_bytes;
#endif
      adsp_reader->inc_bytes_left -= inp_bytes;
   }

// Use this macro, if you want to use the Constructor above in an invironment, which also uses the define HOB_RDPACC_ALLOW_THROW
#ifdef HOB_RDPACC_ALLOW_THROW
#define DSD_GATHER_READER(SUBREADER, OLD_READER, REQU_BYTES) dsd_gather_reader SUBREADER(OLD_READER, REQU_BYTES);
#else
#define DSD_GATHER_READER(SUBREADER, OLD_READER, REQU_BYTES)      \
   bool bol_ret;                                                   \
   dsd_gather_reader SUBREADER(OLD_READER, REQU_BYTES, &bol_ret); \
   if(bol_ret == false)                                            \
      return false;                                  
#endif

   inline int get_bytes_left(){
      return this->inc_bytes_left;
   }

#if !(defined B140825)
   // Ticket 34373
   // daviladd: 
   //    The following two functions are needed to solve error during compilation
   //    of xl-rdps-rfbc-3.cpp with dsd_input and dsd_input_dec due to gcc being
   //    more restrictive than MS compiler regarding "goto(s)" and the initialization
   //    of this variables. 

  inline void m_copy_input_gather(dsd_gather_i_1* adsp_gather)
   {
	   this->adsc_gather = adsp_gather;
	   this->inc_bytes_left = m_gather_count(adsp_gather);
   }

  inline void m_copy_gather_reader(dsd_gather_reader* adsp_reader, int inp_bytes RETURN_VALUE_IF_NOTHROW)
  {
      this->adsc_gather = adsp_reader->adsc_gather;
	  this->inc_bytes_left = inp_bytes;

    #ifdef HOB_RDPACC_ALLOW_THROW
	   if(adsp_reader->inc_bytes_left < inp_bytes)
			 THROW_HOB_ERROR("Read out of bounds: m_gather_count(ads_gather)=0x%x in_bytes=0x%x", m_gather_count(this->adsc_gather), inp_bytes);
	#else
		  *abop_error = adsp_reader->inc_bytes_left >= inp_bytes;
	#endif
		  adsp_reader->inc_bytes_left -= inp_bytes;
  }
#endif 

   // Function does not move cur-pointer or change number of bytes
   inline void get_max_contiguous_bytes(int* ainp_number, char** aachp_mem){
      if(this->inc_bytes_left == 0){
         *ainp_number = 0;
         *aachp_mem = NULL;
         return;
      }
      dsd_gather_i_1* adsl_gather = this->clear();
      int inl_num = CAST_POINTDIFF_TO_INT(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
      if(inl_num > this->inc_bytes_left)
         inl_num = this->inc_bytes_left;
      *ainp_number = inl_num;
      *aachp_mem = adsl_gather->achc_ginp_cur;
      return;
   }

   bool is_available(int inp_num_requ){
      return this->inc_bytes_left >= inp_num_requ;
   }

   dsd_gather_i_1* get_gather(){
      return this->adsc_gather;
   }

   bool copy_to(char* achp_dest, int inp_num){
      ENSURE(inp_num);
      while(inp_num > 0){
         dsd_gather_i_1* adsl_gather = this->clear();
         int inl_copy_now = CAST_POINTDIFF_TO_INT(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
         if(inl_copy_now > inp_num)
            inl_copy_now = inp_num;

         memcpy(achp_dest, adsl_gather->achc_ginp_cur, inl_copy_now);
         achp_dest += inl_copy_now;
         inp_num -= inl_copy_now;
         this->inc_bytes_left -= inl_copy_now; 
         this->adsc_gather->achc_ginp_cur += inl_copy_now;
      }
      return true;
   }

   bool peek_data(char* ach_dest, int in_off, int in_num){
      ENSURE(in_off + in_num);

      // First, search for offset
      dsd_gather_i_1* ads_gather = this->clear();
      while(CAST_POINTDIFF_TO_INT(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur) <= in_off){
         in_off -= CAST_POINTDIFF_TO_INT(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
         ads_gather = ads_gather->adsc_next;
      }

      // Copy bytes in gather, where offset starts
      int in_copy_now = CAST_POINTDIFF_TO_INT(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur) - in_off;
      if(in_copy_now > in_num)
         in_copy_now = in_num;
      memcpy(ach_dest, ads_gather->achc_ginp_cur + in_off, in_copy_now);
      in_num -= in_copy_now;
      if(in_num == 0)
         return true; 
      ach_dest += in_copy_now;
      ads_gather = ads_gather->adsc_next;
      
      // Still data needed
      while(in_num > 0){
         in_copy_now = CAST_POINTDIFF_TO_INT(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
         if(in_copy_now > in_num)
            in_copy_now = in_num;

         memcpy(ach_dest, ads_gather->achc_ginp_cur, in_copy_now);
         in_num -= in_copy_now;
         ach_dest += in_copy_now;
         ads_gather = ads_gather->adsc_next;
      }
      return true;
   }

   bool memcomp(const char* achp_compare_with, int inp_num, int* ainp_result){
      ENSURE(inp_num);
      while(inp_num > 0){
         dsd_gather_i_1* adsl_gather = this->clear();
         int inl_compare_now = CAST_POINTDIFF_TO_INT(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
         if(inl_compare_now > inp_num)
            inl_compare_now = inp_num;
         int inl_res = memcmp(adsl_gather->achc_ginp_cur, achp_compare_with, inl_compare_now);
         adsl_gather->achc_ginp_cur += inl_compare_now;
         achp_compare_with += inl_compare_now;
         this->inc_bytes_left -= inl_compare_now;
         inp_num -= inl_compare_now; 
         if(inl_res == 0)
            continue;      // keep comparing if the same
         *ainp_result = inl_res;
         this->skip(inp_num);
      }
      *ainp_result = 0;
      return true; 
   }
      
   inline bool other_gather_takes_data(dsd_gather_i_1* adsp_other_gather, int inp_max_len, int* ainp_bytes_taken){
      if(inp_max_len == 0){
         *ainp_bytes_taken = 0;
         return true;
      }

      if(inp_max_len > this->inc_bytes_left)
         inp_max_len = this->inc_bytes_left;

      // Get next gather with data
      dsd_gather_i_1* adsl_gather = this->clear();

      // Find out sum of bytes to give to other gather
      int inl_available = CAST_POINTDIFF_TO_INT(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
      if(inl_available < inp_max_len)
         inp_max_len = inl_available;

      // set other gather
      adsp_other_gather->achc_ginp_cur = adsl_gather->achc_ginp_cur;
      adsp_other_gather->achc_ginp_end = adsl_gather->achc_ginp_cur + inp_max_len; 
      adsp_other_gather->adsc_next = NULL;

      // Skip bytes here
      adsl_gather->achc_ginp_cur += inp_max_len;
      this->inc_bytes_left -= inp_max_len; 
      *ainp_bytes_taken = inp_max_len;
      return true;
   }

   inline bool empty(){
      return this->inc_bytes_left == 0;
   }

   inline void add_front(dsd_gather_i_1* adsp_gather){
      if(adsp_gather == NULL)
         return;
      dsd_gather_i_1* adsl_gather_orig = adsp_gather; 

      dsd_gather_i_1* adsl_gather_end;
      while(adsp_gather != NULL){
         this->inc_bytes_left += CAST_POINTDIFF_TO_INT(adsp_gather->achc_ginp_end - adsp_gather->achc_ginp_cur);
         adsl_gather_end = adsp_gather;
         adsp_gather = adsp_gather->adsc_next;
      }

      adsl_gather_end->adsc_next = this->adsc_gather;
      this->adsc_gather = adsl_gather_orig; 
   }

   inline void remove_first_gather(){
      if(this->adsc_gather == NULL)
         return;
      this->inc_bytes_left -= CAST_POINTDIFF_TO_INT(this->adsc_gather->achc_ginp_end - this->adsc_gather->achc_ginp_cur);
      this->adsc_gather = this->adsc_gather->adsc_next;
   }

   inline bool read_8(int* ainp_result){
      ENSURE(1);
      *ainp_result = this->get_byte_as_int();
      return true;
   }

   inline bool read_8(char* achp_result){
      ENSURE(1);
      *achp_result = this->get_byte();
      return true;
   }

   inline bool read_8(unsigned char* auchp_result){
      ENSURE(1);
      *auchp_result = this->get_byte();
      return true;
   }

   inline bool read_8_signed(int* ainp_result){
      ENSURE(1);
      *ainp_result = this->get_byte();
      return true;
   }


   inline bool peek_8(unsigned char* uchp_result){
      ENSURE(1);
      *uchp_result = *(this->clear()->achc_ginp_cur);
      return true; 
   }

   inline bool peek_8(int* ainp_result){
      ENSURE(1);
      *ainp_result = ((int)*(this->clear()->achc_ginp_cur)) & 0xff;
      return true; 
   }

   inline bool peek_8(int* ainp_result, int inp_offset){
      ENSURE(1 + inp_offset);

      dsd_gather_i_1* adsl_gather = this->clear();
      while(inp_offset >= (int)(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur)){
         inp_offset -= (int)(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
         adsl_gather = adsl_gather->adsc_next;
      }

      *ainp_result = ((int)*(adsl_gather->achc_ginp_cur + inp_offset)) & 0xff;
      return true; 
   }

   inline bool peek_8(unsigned char* aucp_result, int inp_offset){
      ENSURE(1 + inp_offset);

      dsd_gather_i_1* adsl_gather = this->clear();
      while(inp_offset >= (int)(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur)){
         inp_offset -= (int)(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
         adsl_gather = adsl_gather->adsc_next;
      }

      *aucp_result = ((int)*(adsl_gather->achc_ginp_cur + inp_offset)) & 0xff;
      return true; 
   }

   inline bool read_16_le(int* ainp_result){
      ENSURE(2);
      // First check the normal case: 2 bytes directly available
      dsd_gather_i_1* adsl_gather = this->adsc_gather;
      if(adsl_gather->achc_ginp_cur + 2 <= adsl_gather->achc_ginp_end){
         *ainp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) << 0) | 
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) << 8);
         adsl_gather->achc_ginp_cur += 2;
         this->inc_bytes_left -= 2;
         return true;
      }
      // Not 2 bytes left in actual gather
      *ainp_result = this->get_byte_as_int() | (this->get_byte_as_int() << 8);
      return true;
   }

   inline bool read_16_le(short* aisp_result){
      ENSURE(2);
      // First check the normal case: 2 bytes directly available
      dsd_gather_i_1* adsl_gather = this->adsc_gather;
      if(adsl_gather->achc_ginp_cur + 2 <= adsl_gather->achc_ginp_end){
         *aisp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) << 0) | 
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) << 8);
         adsl_gather->achc_ginp_cur += 2;
         this->inc_bytes_left -= 2;
         return true;
      }
      // Not 2 bytes left in actual gather
      *aisp_result = this->get_byte_as_int() | (this->get_byte_as_int() << 8);
      return true;
   }

   inline bool peek_16_be(int* ainp_result){
      ENSURE(2);
      // First check the normal case: 2 bytes directly available
      dsd_gather_i_1* adsl_gather = this->clear();
      if(adsl_gather->achc_ginp_cur + 2 <= adsl_gather->achc_ginp_end){
         *ainp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) << 8) | 
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) << 0);
         return true;
      }
      // Not 2 bytes left in actual gather
      *ainp_result = (((int) *adsl_gather->achc_ginp_cur) & 0xff) << 8;
      adsl_gather = adsl_gather->adsc_next;
      while(adsl_gather->achc_ginp_cur >= adsl_gather->achc_ginp_end)
         adsl_gather = adsl_gather->adsc_next;
      *ainp_result |= ((int) *adsl_gather->achc_ginp_cur) & 0xff;
      return true;
   }

   inline bool peek_16_le(int* ainp_result){
      ENSURE(2);
      // First check the normal case: 2 bytes directly available
      dsd_gather_i_1* adsl_gather = this->clear();
      if(adsl_gather->achc_ginp_cur + 2 <= adsl_gather->achc_ginp_end){
         *ainp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) << 0) | 
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) << 8);
         return true;
      }
      // Not 2 bytes left in actual gather
      *ainp_result = (((int) *adsl_gather->achc_ginp_cur) & 0xff);
      adsl_gather = adsl_gather->adsc_next;
      while(adsl_gather->achc_ginp_cur >= adsl_gather->achc_ginp_end)
         adsl_gather = adsl_gather->adsc_next;
      *ainp_result |= (((int) *adsl_gather->achc_ginp_cur) & 0xff) << 8;
      return true;
   }

   inline bool read_16_be(int* ainp_result){
      ENSURE(2);
      // First check the normal case: 2 bytes directly available
      dsd_gather_i_1* adsl_gather = this->adsc_gather;
      if(adsl_gather->achc_ginp_cur + 2 <= adsl_gather->achc_ginp_end){
         *ainp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) << 8) | 
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) << 0);
         adsl_gather->achc_ginp_cur += 2;
         this->inc_bytes_left -= 2;
         return true;
      }
      // Not 2 bytes left in actual gather
      *ainp_result = (this->get_byte_as_int() << 8) | this->get_byte_as_int();
      return true;
   }

   inline bool read_16_be(short* aisp_result){
      ENSURE(2);
      // First check the normal case: 2 bytes directly available
      dsd_gather_i_1* adsl_gather = this->clear();
      if(adsl_gather->achc_ginp_cur + 2 <= adsl_gather->achc_ginp_end){
         *aisp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) << 8) | 
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) << 0);
         adsl_gather->achc_ginp_cur += 2;
         this->inc_bytes_left -= 2;
         return true;
      }
      // Not 2 bytes left in actual gather
      *aisp_result = (this->get_byte_as_int() << 8) | this->get_byte_as_int();
      return true;
   }

   inline bool read_16_be(unsigned short* aisp_result){
      return read_16_be((short*) aisp_result);
   }

   inline bool read_24_le(int* ainp_result){
      ENSURE(3);
      dsd_gather_i_1* adsl_gather = this->clear();
      if(adsl_gather->achc_ginp_cur + 3 <= adsl_gather->achc_ginp_end){
         *ainp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) <<  0) |
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) <<  8) |
                        (((int) *(adsl_gather->achc_ginp_cur + 2) & 0xff) << 16);
         adsl_gather->achc_ginp_cur += 3;
         this->inc_bytes_left -= 3;
         return true; 
       }
      *ainp_result = (this->get_byte_as_int() <<  0) | 
                     (this->get_byte_as_int() <<  8) |
                     (this->get_byte_as_int() << 16);
      return true;
   }

   inline bool read_24_be(int* ainp_result){
      ENSURE(3);
      dsd_gather_i_1* adsl_gather = this->clear();
      if(adsl_gather->achc_ginp_cur + 3 <= adsl_gather->achc_ginp_end){
         *ainp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) << 16) |
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) <<  8) |
                        (((int) *(adsl_gather->achc_ginp_cur + 2) & 0xff) <<  0);
         adsl_gather->achc_ginp_cur += 3;
         this->inc_bytes_left -= 3;
         return true; 
       }
      *ainp_result = (this->get_byte_as_int() << 16) | 
                     (this->get_byte_as_int() <<  8) |
                     (this->get_byte_as_int() <<  0);
      return true;
   }

   inline bool read_32_le(int* ainp_result){
      ENSURE(4);
      // First check the normal case: 4 bytes directly available 
      dsd_gather_i_1* adsl_gather = this->clear();
      if(adsl_gather->achc_ginp_cur + 4 <= adsl_gather->achc_ginp_end){
         *ainp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) <<  0) |
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) <<  8) |
                        (((int) *(adsl_gather->achc_ginp_cur + 2) & 0xff) << 16) |
                        (((int) *(adsl_gather->achc_ginp_cur + 3) & 0xff) << 24);
         adsl_gather->achc_ginp_cur += 4;
         this->inc_bytes_left -= 4;
         return true; 
       }
      *ainp_result = (this->get_byte_as_int() <<  0) | 
                     (this->get_byte_as_int() <<  8) |
                     (this->get_byte_as_int() << 16) |
                     (this->get_byte_as_int() << 24);
      return true;
   }

   inline bool read_32_be(int* ainp_result){
      ENSURE(4);
      // First check the normal case: 4 bytes directly available 
      dsd_gather_i_1* adsl_gather = this->clear();
      if(adsl_gather->achc_ginp_cur + 4 <= adsl_gather->achc_ginp_end){
         *ainp_result = (((int) *(adsl_gather->achc_ginp_cur + 0) & 0xff) << 24) |
                        (((int) *(adsl_gather->achc_ginp_cur + 1) & 0xff) << 16) |
                        (((int) *(adsl_gather->achc_ginp_cur + 2) & 0xff) <<  8) |
                        (((int) *(adsl_gather->achc_ginp_cur + 3) & 0xff) <<  0);
         adsl_gather->achc_ginp_cur += 4;
         this->inc_bytes_left -= 4;
         return true; 
       }
      *ainp_result = (this->get_byte_as_int() << 24) | 
                     (this->get_byte_as_int() << 16) |
                     (this->get_byte_as_int() <<  8) |
                     (this->get_byte_as_int() <<  0);
      return true;
   }
   inline bool read_32_be(unsigned int* aunp_result){
      return read_32_be((int*) aunp_result);
   }

   inline bool read_hasn1(int* ainp_result){
      *ainp_result = 0;
      int inl_shift = 0;

      while(true){
         ENSURE(1);
         int inl_byte = this->get_byte_as_int();
         *ainp_result |= (inl_byte & 0x7F) << inl_shift;
         if((inl_byte & 0x80) == 0)
            return true;
         inl_shift += 7;
      }
   }

   inline bool peek_hasn1(int* ainp_result, int* ainp_off){
      *ainp_result = 0;
      int inl_shift = 0;

      while(true){
         int inl_byte;
         this->peek_8(&inl_byte, *ainp_off);
         (*ainp_off)++;

         *ainp_result |= (inl_byte & 0x7F) << inl_shift;
         if((inl_byte & 0x80) == 0)
            return true;
         inl_shift += 7;
      }
   }

   inline bool try_peek_hasn1(int* ainp_result, int* ainp_off){
      *ainp_result = 0;
      int inl_shift = 0;

      // Check, if offset is available
      if((*ainp_off) >= this->get_bytes_left())
         return false;

      // Get first byte
      dsd_gather_i_1* adsl_gather = this->clear();
      int inl_offset = *ainp_off; 
      while(inl_offset >= (int)(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur)){
         inl_offset -= (int)(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
         adsl_gather = adsl_gather->adsc_next;
      }
      char* achl_cur = adsl_gather->achc_ginp_cur + inl_offset;
      
      // Now read hasn1
      while(true){

         // evaluate this byte
         int inl_byte = (*achl_cur) & 0xff;
         *ainp_result |= (inl_byte & 0x7F) << inl_shift;
         (*ainp_off)++;
         if((inl_byte & 0x80) == 0)
            return true;
         inl_shift += 7;

         // Check, if one byte more is available
         if((*ainp_off) >= this->get_bytes_left())
            return false;
         
         // get next byte
         achl_cur++;
         while(achl_cur >= adsl_gather->achc_ginp_end){
            adsl_gather = adsl_gather->adsc_next;
            if(adsl_gather == NULL)
#ifdef HOB_RDPACC_ALLOW_THROW
               THROW_HOB_ERROR("Error in dsd_gather_reader! Not enough bytes available!");
#else
               return false;
#endif
            achl_cur = adsl_gather->achc_ginp_cur;
         }

      }
   }


   void skip_rest(){
      while(this->inc_bytes_left > 0){
         dsd_gather_i_1* adsl_gather = this->clear();
         int inl_skip_now = CAST_POINTDIFF_TO_INT(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
         if(inl_skip_now > this->inc_bytes_left)
            inl_skip_now = this->inc_bytes_left;
         adsl_gather->achc_ginp_cur += inl_skip_now;
         this->inc_bytes_left -= inl_skip_now; 
      }
   }

   bool skip(int inp_skip){
      if(inp_skip == 0)
         return true;
      ENSURE(inp_skip);
      while(inp_skip > 0){
         dsd_gather_i_1* adsl_gather = this->clear();
         int inl_skip_now = CAST_POINTDIFF_TO_INT(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
         if(inl_skip_now > inp_skip)
            inl_skip_now = inp_skip;

         adsl_gather->achc_ginp_cur += inl_skip_now;
         inp_skip -= inl_skip_now;
         this->inc_bytes_left -= inl_skip_now; 
      }
      return true;
   }

   // This function calls back for every peece of memory, but takes care for the length!
   typedef bool (* amd_gather_reader_callback)(void *avop_userfld, char* achp_cur, char* achp_end);
   bool callback_for_mem(amd_gather_reader_callback amp_gather_reader_callback, void* avop_userfld){
      int inl_rest_bytes = this->inc_bytes_left;
      dsd_gather_i_1* adsl_gather = this->clear();
      while(true){
         int inl_callback_now = CAST_POINTDIFF_TO_INT(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
         if(inl_callback_now >= inl_rest_bytes){
            return amp_gather_reader_callback(avop_userfld, adsl_gather->achc_ginp_cur, adsl_gather->achc_ginp_cur + inl_rest_bytes); 
         }
         if(!amp_gather_reader_callback(avop_userfld, adsl_gather->achc_ginp_cur, adsl_gather->achc_ginp_end))
            return false; 
         inl_rest_bytes -= inl_callback_now; 
         adsl_gather = adsl_gather->adsc_next;
      }
   }

   //void dump(){
   //   dsd_gather_i_1* ads_gather = this->ads_gather;
   //   while(ads_gather != NULL){
   //      m_console_out(ads_gather->achc_ginp_cur, (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur));
   //      ads_gather = ads_gather->adsc_next;
   //   }
   //}


};

#undef RETURN_VALUE_IF_NOTHROW
#undef ENSURE

//             _ _                                                 
// __ __ ___ _(_) |_ ___   ___ _ _    _ __  ___ _ __  ___ _ _ _  _ 
// \ V  V / '_| |  _/ -_) / _ \ ' \  | '  \/ -_) '  \/ _ \ '_| || |
//  \_/\_/|_| |_|\__\___| \___/_||_| |_|_|_\___|_|_|_\___/_|  \_, |
//                                                            |__/ 

static inline void write_32_le(char* achp_pointer, int inp_val){
   *(achp_pointer++) = (char) inp_val;
   *(achp_pointer++) = (char) (inp_val >>  8);
   *(achp_pointer++) = (char) (inp_val >> 16);
   *(achp_pointer++) = (char) (inp_val >> 24);
}

static inline void write_16_le(char* achp_pointer, int inp_val){
   *(achp_pointer++) = (char) inp_val;
   *(achp_pointer++) = (char) (inp_val >> 8);
}

static inline void write_8(char* achp_pointer, int inp_val){
   *achp_pointer = inp_val;
}

static inline int read_32_le(char* achp_pointer){
   return ((((int) *(achp_pointer + 0)) <<  0) & 0x000000ff) | 
          ((((int) *(achp_pointer + 1)) <<  8) & 0x0000ff00) |
          ((((int) *(achp_pointer + 2)) << 16) & 0x00ff0000) |
          ((((int) *(achp_pointer + 3)) << 24) & 0xff000000);
}

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

static inline void write_8(char** aachp_pointer, char chp_val){
   *(*aachp_pointer)++ = chp_val;     
}

static inline void write_16_be(char** aachp_pointer, unsigned short usp_val){
   *(*aachp_pointer)++ = ((usp_val) >>  8);     
   *(*aachp_pointer)++ = ((usp_val) >>  0);     
}

static inline void write_16_le(char** aachp_pointer, unsigned short usp_val){
   *(*aachp_pointer)++ = ((usp_val) >>  0);     
   *(*aachp_pointer)++ = ((usp_val) >>  8);     
}

static inline void write_24_be(char** aachp_pointer, int inp_val){
   *(*aachp_pointer)++ = ((inp_val) >> 16);     
   *(*aachp_pointer)++ = ((inp_val) >>  8);     
   *(*aachp_pointer)++ = ((inp_val) >>  0);     
}

static inline void write_24_le(char** aachp_pointer, int inp_val){
   *(*aachp_pointer)++ = ((inp_val) >>  0);     
   *(*aachp_pointer)++ = ((inp_val) >>  8);     
   *(*aachp_pointer)++ = ((inp_val) >> 16);     
}

static inline void write_32_be(char** aachp_pointer, unsigned unp_val){
   *(*aachp_pointer)++ = ((unp_val) >> 24);     
   *(*aachp_pointer)++ = ((unp_val) >> 16);     
   *(*aachp_pointer)++ = ((unp_val) >>  8);     
   *(*aachp_pointer)++ = ((unp_val) >>  0);     
}

static inline void write_32_le(char** aachp_pointer, unsigned unp_val){
   *(*aachp_pointer)++ = ((unp_val) >>  0);     
   *(*aachp_pointer)++ = ((unp_val) >>  8);     
   *(*aachp_pointer)++ = ((unp_val) >> 16);     
   *(*aachp_pointer)++ = ((unp_val) >> 24);     
}

static inline void write_64_le(char** aachp_pointer, HL_LONGLONG ilp_val){
   *(*aachp_pointer)++ = (char)((ilp_val) >>  0);     
   *(*aachp_pointer)++ = (char)((ilp_val) >>  8);     
   *(*aachp_pointer)++ = (char)((ilp_val) >> 16);     
   *(*aachp_pointer)++ = (char)((ilp_val) >> 24);     
   *(*aachp_pointer)++ = (char)((ilp_val) >> 32);     
   *(*aachp_pointer)++ = (char)((ilp_val) >> 40);     
   *(*aachp_pointer)++ = (char)((ilp_val) >> 48);     
   *(*aachp_pointer)++ = (char)((ilp_val) >> 56);     
}

static inline void write_hasn1(char** aachp_pointer, unsigned int inp_val){
   while(true){
      int inl_byte = inp_val & 0x7f;
      inp_val >>= 7;

      if(inp_val == 0){
         *(*aachp_pointer)++ = inl_byte;
         return; 
      }
      *(*aachp_pointer)++ = inl_byte | 0x80;
   }
}

#undef CAST_POINTDIFF_TO_INT
#endif
