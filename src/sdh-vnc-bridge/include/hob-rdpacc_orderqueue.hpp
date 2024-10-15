#pragma once
#ifndef __HOB_RDPACC_ORDERQUEUE_TO_CLIENT__
#define __HOB_RDPACC_ORDERQUEUE_TO_CLIENT__

/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-rdpacc_orderqueue.hpp                           |*/
/*| -------------                                                     |*/
/*|  Creates queue of dsd_sc_co1 commands for RDP-Accelerator         |*/
/*|  Also allows to keep track of used workareas or other resources   |*/
/*|  Requires an i_workarea_provider to require workareas             |*/
/*|  Johannes Bauer 02.12.2011                                        |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

// possible defines: 
// HOB_RDPACC_ALLOW_THROW set this define, if you want the orderqueue to throw an C++-error, if there is no memory. Otherwise, NULL is returned.

// KEEP_TRACK_OF_USED_WORKAREAS set this define, if the orderqueue should take care for the workareas, it uses and release them
//                              when free_resources_and_workareas() is called. 
//                              -> Don't use this define in a server-data-hook (as the WSP takes care for the workareas)
//                              -> Use this define especially in a multi-threading-environment, when building the orderqueue and processing it
//                                 is done by different threads. 

/* NECESSARY INCLUDES:

// normal windows/unix includes
#ifndef HL_UNIX
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/sem.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <hob-unix01.h>
#endif

// RDPACC-server includes: 
#include "hob-cdrdef1.h"
#include "hmd5.h"
#include "hsha.h"
#include "hrc4cons.h"
#include <hob-avl03.h>

#pragma warning(disable:4005)
#include <hob-rdpserver1.h>
#pragma warning(default:4005)

// other includes: 
#include <hob/util/hob-tk-queue.hpp>

if HOB_RDPACC_ALLOW_THROW is set:
#include <hob-throw_error.hpp>

*/

#ifdef HOB_RDPACC_ALLOW_THROW
#define RETURN_NULL_OR_THROW(MESSAGE, ...) {THROW_HOB_ERROR(MESSAGE, __VA_ARGS__);}
#define RETURN_NULL_IF_NULL_AND_NO_THROW(POINTER)
#else
#define RETURN_NULL_OR_THROW(MESSAGE, ...) return NULL;
#define RETURN_NULL_IF_NULL_AND_NO_THROW(POINTER) if(POINTER == NULL) return NULL;
#endif

// +------------------------------+
// | Interface i_workareaprovider |
// +------------------------------+

#ifndef __HOB_I_WORKAREA_PROVIDER__
#define __HOB_I_WORKAREA_PROVIDER__
class i_workareaprovider {
public:
   virtual bool get_workarea(char** aach_work_area, int* ain_len_work_area) = 0;
#ifdef KEEP_TRACK_OF_USED_WORKAREAS
   virtual void release_workarea(char* ach_wa_to_free) = 0;
#endif
   virtual ~i_workareaprovider(){};
};
#endif

// +-------------------------------------------+
// | Non-existing commands in hob-rdpserver1.h |
// +-------------------------------------------+

struct dsd_sc_order_end_session{};
struct dsd_sc_order_end_shutdown{};
struct dsd_sc_order_end_shutdown_deny{};
struct dsd_sc_order_clearbounds{};

struct dsd_sc_order_new_font{
   dsd_font* adsc_font;
};

struct dsd_sc_order_delete_font{
   dsd_font* dsc_font;
};

// +-----------------------------------------------------------+
// | Mapping from order-struct to corresponding ied_sc_command |
// +-----------------------------------------------------------+

inline static ied_sc_command get_rdpacc_order_id(dsd_d_act_pdu*)                 {return ied_scc_d_act_pdu;}
inline static ied_sc_command get_rdpacc_order_id(dsd_change_screen*)             {return ied_scc_change_screen;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_draw_sc*)                {return ied_scc_draw_sc;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_vch_out*)                {return ied_scc_vch_out;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_end_session*)      {return ied_scc_end_session;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_end_shutdown*)     {return ied_scc_end_shutdown;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_scrblt*)           {return ied_scc_order_scrblt;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_mpoi_system*)            {return ied_scc_mpoi_system;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_mpoi_position*)          {return ied_scc_mpoi_position;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_mpoi_color*)             {return ied_scc_mpoi_color;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_mpoi_cached*)            {return ied_scc_mpoi_cached;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_mpoi_pointer*)           {return ied_scc_mpoi_pointer;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_error_info*)             {return ied_scc_error_info;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_end_shutdown_deny*){return ied_scc_order_shutdown_deny;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_setbounds*)        {return ied_scc_order_setbounds;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_clearbounds*)      {return ied_scc_order_clearbounds;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_patblt*)           {return ied_scc_order_patblt;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_opaquerect*)       {return ied_scc_order_opaquerect;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_memblt*)           {return ied_scc_order_memblt;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_mem3blt*)          {return ied_scc_order_mem3blt;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_lineto*)           {return ied_scc_order_lineto;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_savebitmap*)       {return ied_scc_order_savebitmap;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_drawstring*)       {return ied_scc_order_drawstring;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_polygonsc*)        {return ied_scc_order_polygonsc;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_polygoncb*)        {return ied_scc_order_polygoncb;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_polyline*)         {return ied_scc_order_polyline;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_ellipsesc*)        {return ied_scc_order_ellipsesc;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_ellipsecb*)        {return ied_scc_order_ellipsecb;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_cachebitmap*)      {return ied_scc_order_cachebitmap;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_cachebrush*)       {return ied_scc_order_cachebrush;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_createoffbitmap*)  {return ied_scc_order_createoffbitmap;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_switchsurface*)    {return ied_scc_order_switchsurface;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_framemarker*)      {return ied_scc_order_framemarker;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_new_font*)         {return ied_scc_order_new_font;}
inline static ied_sc_command get_rdpacc_order_id(dsd_sc_order_delete_font*)      {return ied_scc_order_delete_font;}


// +------------------------------+
// | Structures to free resources |
// +------------------------------+

typedef void (*amd_free_resource)(void* avo_userfld_1, void* avo_userfld_2);

struct dsd_free_resource {
   dsd_free_resource* adsc_next;
   amd_free_resource  amc_free_resource_callback;
   void*              avo_userfld_1;
   void*              avo_userfld_2;
   dsd_free_resource(amd_free_resource  amc_free_resource_callback, void* avo_userfld_1, void* avo_userfld_2)
    : adsc_next(NULL), amc_free_resource_callback(amc_free_resource_callback), 
      avo_userfld_1(avo_userfld_1), avo_userfld_2(avo_userfld_2)
   {}
};

// +-----------------------------+
// | class dsd_rdpacc_orderqueue |
// +-----------------------------+

#ifdef KEEP_TRACK_OF_USED_WORKAREAS
struct dsd_orderqueue_workarea {
   dsd_orderqueue_workarea* adsc_next;
};
typedef hob::util::dsd_hob_queue<dsd_orderqueue_workarea> dsd_ord_wa_queue;
#endif
typedef hob::util::dsd_hob_queue<dsd_sc_co1>    dsd_sc_co_queue;
typedef hob::util::dsd_hob_queue<dsd_free_resource> dsd_free_resource_queue;

class dsd_rdpacc_orderqueue {
   i_workareaprovider* ads_workareaprovider;
#ifdef KEEP_TRACK_OF_USED_WORKAREAS
   dsd_ord_wa_queue ds_workarea_queue;
#endif
   dsd_sc_co_queue ds_sc_co_queue;
   dsd_free_resource_queue ds_free_queue;
   char *ach_act_workarea;
   int in_len_act_workarea;

public:  

   inline dsd_rdpacc_orderqueue(i_workareaprovider* ads_workareaprovider)
      : ads_workareaprovider(ads_workareaprovider),
        ds_sc_co_queue(),
        ach_act_workarea(NULL),
        in_len_act_workarea(0)
   {
   }


   inline dsd_sc_co1* release_orders(){
      return this->ds_sc_co_queue.release();
   }
   inline dsd_sc_co1* get_orders(){
      return this->ds_sc_co_queue.get_first();
   }

   inline bool is_empty(){
      return this->ds_sc_co_queue.is_empty();
   }

   inline bool has_orders(){
      return !this->ds_sc_co_queue.is_empty();
   }

   inline dsd_free_resource* release_free_res(){
      return this->ds_free_queue.release();
   }

   inline void clear(){
      this->ds_sc_co_queue.clear();
#ifdef KEEP_TRACK_OF_USED_WORKAREAS
      this->ds_workarea_queue.clear();
#endif
      this->ach_act_workarea = NULL;
      this->in_len_act_workarea = 0;
      this->ds_free_queue.clear();
   }

   inline void move_to(dsd_rdpacc_orderqueue* ads_other){
      this->ds_sc_co_queue.move_to(&ads_other->ds_sc_co_queue);
#ifdef KEEP_TRACK_OF_USED_WORKAREAS
      this->ds_workarea_queue.move_to(&ads_other->ds_workarea_queue);
      this->ach_act_workarea = NULL;
      this->in_len_act_workarea = 0;
#endif
      this->ds_free_queue.move_to(&ads_other->ds_free_queue);
   }

   inline char* get_memory(int in_bytes){
      if(this->in_len_act_workarea < in_bytes){
         if(this->ads_workareaprovider->get_workarea(&this->ach_act_workarea, &this->in_len_act_workarea) == false){
            RETURN_NULL_OR_THROW("hob-rdpacc_orderqueue, function get_memory: workareaprovider returned false.") 
         }
#ifdef KEEP_TRACK_OF_USED_WORKAREAS
         dsd_orderqueue_workarea* ads_new_workarea = (dsd_orderqueue_workarea*) this->ach_act_workarea;
         this->ach_act_workarea += sizeof(dsd_orderqueue_workarea);
         this->in_len_act_workarea -= sizeof(dsd_orderqueue_workarea);
         ads_new_workarea->adsc_next = NULL;
         this->ds_workarea_queue.add(ads_new_workarea);
#endif
         if(this->in_len_act_workarea < in_bytes){
            RETURN_NULL_OR_THROW("hob-rdpacc_orderqueue, function get_memory: workareaprovider returned workarea, which is too small. Sizeof workarea: 0x%i, needed 0x%i", this->in_len_act_workarea, in_bytes) 
         }
      }
      char* ach_ret = this->ach_act_workarea;
      this->ach_act_workarea += in_bytes;
      this->in_len_act_workarea -= in_bytes;
      //memset(ach_ret, 0, in_bytes);
      return ach_ret;
   }

   template<typename T> T* new_command(dsd_sc_co1* ads_new_co){
      ads_new_co->adsc_next = NULL;
      ads_new_co->iec_sc_command = get_rdpacc_order_id((T*) NULL);

      // Put command in queue
      this->ds_sc_co_queue.add(ads_new_co);

      // Return structure after command
      return (T*) (ads_new_co + 1);
   }

   template<typename T> T* new_command(int in_addbytes = 0){
      int in_size_needed = sizeof(dsd_sc_co1) + sizeof(T) + in_addbytes;
      dsd_sc_co1* ads_new_co = (dsd_sc_co1*) this->get_memory(in_size_needed);
      RETURN_NULL_IF_NULL_AND_NO_THROW(ads_new_co);
      return this->new_command<T>(ads_new_co);
   }

   template<typename T> T* new_command(int inl_addbytes_min, int inl_addbytes_max, int* ainl_addbytes_ret){
      int inl_size_needed = sizeof(dsd_sc_co1) + sizeof(T) + inl_addbytes_min;
      dsd_sc_co1* ads_new_co = (dsd_sc_co1*) this->get_memory(inl_size_needed);
      RETURN_NULL_IF_NULL_AND_NO_THROW(ads_new_co);

      if(inl_addbytes_max <= inl_addbytes_min){
         *ainl_addbytes_ret = inl_addbytes_min;
         return this->new_command<T>(ads_new_co);
      } 

      // Now get more space on SAME workarea
      int inl_get_more_space = this->in_len_act_workarea;
      if((inl_addbytes_min + inl_get_more_space) > inl_addbytes_max)
         inl_get_more_space = inl_addbytes_max - inl_addbytes_min;
      this->in_len_act_workarea -= inl_get_more_space;
      this->ach_act_workarea += inl_get_more_space;
      
      // Return length of addbytes
      *ainl_addbytes_ret = inl_addbytes_min + inl_get_more_space;
      return this->new_command<T>(ads_new_co);
   }

   template<typename T> T* new_command(amd_free_resource amc_free_resource_callback, void* avo_userfld_1, void* avo_userfld_2, int in_addbytes = 0){
      dsd_free_resource* ads_free_resource = (dsd_free_resource*) this->get_memory(sizeof(dsd_free_resource));
      RETURN_NULL_IF_NULL_AND_NO_THROW(ads_free_resource);
      new (ads_free_resource) dsd_free_resource(amc_free_resource_callback, avo_userfld_1, avo_userfld_2);
      this->ds_free_queue.add(ads_free_resource);
      return this->new_command<T>(in_addbytes);
   }

   // This is an important function for Server-Data-Hooks!
   // Call this function before you leave the Server-Data-Hook,
   // as the workareas are released afterwards. 
   inline void dont_use_act_workarea_any_more(){
      this->ach_act_workarea = NULL;
      this->in_len_act_workarea = 0;
   }

   inline void free_resources(){
      dsd_free_resource* ads_resource = this->ds_free_queue.release();

      while(ads_resource != NULL){
         dsd_free_resource* ads_res_free = ads_resource;
         ads_resource = ads_resource->adsc_next;
         ads_res_free->amc_free_resource_callback(ads_res_free->avo_userfld_1, ads_res_free->avo_userfld_2);
      }
   }

#ifdef KEEP_TRACK_OF_USED_WORKAREAS
   inline void free_resources_and_workareas(){
      // Note: free resources before freeing workareas, as dsd_free_resource are on workareas!
      this->free_resources();

      dsd_orderqueue_workarea* ads_workarea = this->ds_workarea_queue.release();
      while(ads_workarea != NULL){
         dsd_orderqueue_workarea* ads_wa_to_free = ads_workarea;
         ads_workarea = ads_workarea->adsc_next;
         this->ads_workareaprovider->release_workarea((char*) ads_wa_to_free);
      }
   }

#endif

   // ---------------------------
   // Functions to be linked in C
   // ---------------------------

   inline void* new_command(ied_sc_command ie_command, int in_needed_bytes){
      // Get memory
      int in_size_needed = sizeof(dsd_sc_co1) + in_needed_bytes;
      dsd_sc_co1* ads_new_co = (dsd_sc_co1*) this->get_memory(in_size_needed);
      RETURN_NULL_IF_NULL_AND_NO_THROW(ads_new_co);

      // Put command in queue
      ads_new_co->adsc_next = NULL;
      ads_new_co->iec_sc_command = ie_command;
      this->ds_sc_co_queue.add(ads_new_co);

      // Return memory after command
      return (void*) (ads_new_co + 1);
   }
}; // class dsd_rdpacc_orderqueue

// +--------------------------------------+
// | Functions to help in RDP-Accelerator |
// +--------------------------------------+

// rop-codes
// ---------

inline static ied_sc_rop2_operation get_rdp_rop2(int in_rop3){
   int in_rop2 = ((in_rop3 & 0x30) >> 2) | ((in_rop3 & 0x3));
   switch(in_rop2){
      case 0x0: return ied_scc_r2_black;        break; // 0    RDP:0x1
      case 0x1: return ied_scc_r2_notmergepen;  break; // DPon RDP:0x2
      case 0x2: return ied_scc_r2_masknotpen;   break; // DPna RDP:0x3
      case 0x3: return ied_scc_r2_notcopypen;   break; // Pn   RDP:0x4
      case 0x4: return ied_scc_r2_maskpennot;   break; // PDna RDP:0x5
      case 0x5: return ied_scc_r2_not;          break; // Dn   RDP:0x6
      case 0x6: return ied_scc_r2_xorpen;       break; // DPx  RDP:0x7
      case 0x7: return ied_scc_r2_notmaskpen;   break; // DPan RDP:0x8
      case 0x8: return ied_scc_r2_maskpen;      break; // DPa  RDP:0x9
      case 0x9: return ied_scc_r2_notxorpen;    break; // DPon RDP:0xa
      case 0xa: return ied_scc_r2_nop;          break; // D    RDP:0xb
      case 0xb: return ied_scc_r2_mergenotpen;  break; // DPno RDP:0xc
      case 0xc: return ied_scc_r2_copypen;      break; // P    RDP:0xd
      case 0xd: return ied_scc_r2_mergepennot;  break; // PDno RDP:0xe
      case 0xe: return ied_scc_r2_mergepen;     break; // PDo  RDP:0xf
      case 0xf: return ied_scc_r2_white;        break; // 1    RDP:0x10
      default: 
         return ied_scc_r2_black;
   }
}

// Colors for RDP-Accelerator
// --------------------------
typedef unsigned int (* amd_get_rdpcolor)(unsigned char uc_red, unsigned int uc_green, unsigned int uc_blue);

inline static unsigned int get_rdpcolor_15(unsigned char uc_red, unsigned int uc_green, unsigned int uc_blue){
   return ((uc_red & 0xf8) << 7) | ((uc_green & 0xf8) << 2) | ((uc_blue & 0xf8) >> 3);
}

inline static unsigned int get_rdpcolor_16(unsigned char uc_red, unsigned int uc_green, unsigned int uc_blue){
   return ((uc_red & 0xf8) << 8) | ((uc_green & 0xfc) << 3) | ((uc_blue & 0xff) >> 3);
}

inline static unsigned get_rdpcolor_24(unsigned char uc_red, unsigned int uc_green, unsigned int uc_blue){
   return ((uc_red & 0xff) >> 0) | ((uc_green & 0xff) << 8) | ((uc_blue & 0xff) << 16);
}

inline static unsigned get_color_24(unsigned char uc_red, unsigned int uc_green, unsigned int uc_blue){
   return ((uc_red & 0xff) << 16) | ((uc_green & 0xff) << 8) | ((uc_blue & 0xff) >> 0);
}

inline static amd_get_rdpcolor get_rdpcolor_func(int in_colordeph){
   switch(in_colordeph){
      case 15:
         return &get_rdpcolor_15; 
      case 16:
         return &get_rdpcolor_16;
      case 24:
      case 32:
      default:
         return &get_rdpcolor_24;
   }
}

inline static amd_get_rdpcolor get_color_func(int in_colordeph){
   switch(in_colordeph){
      case 15:
         return &get_rdpcolor_15; 
      case 16:
         return &get_rdpcolor_16;
      case 24:
      case 32:
      default:
         return &get_color_24;
   }
}

inline static unsigned get_rdpcolor(int in_colordeph, unsigned char uc_red, unsigned int uc_green, unsigned int uc_blue){
   switch(in_colordeph) {
      case 15:
         return get_rdpcolor_15(uc_red, uc_green, uc_blue);
      case 16:
         return get_rdpcolor_16(uc_red, uc_green, uc_blue);
      case 24:
         return get_rdpcolor_24(uc_red, uc_green, uc_blue);
      case 32:
         return get_rdpcolor_24(uc_red, uc_green, uc_blue) | 0xFF000000;
      default:
         return 0;
   }
}

inline static unsigned get_color(int in_colordeph, unsigned char uc_red, unsigned int uc_green, unsigned int uc_blue){
   switch(in_colordeph) {
      case 15:
         return get_rdpcolor_15(uc_red, uc_green, uc_blue);
      case 16:
         return get_rdpcolor_16(uc_red, uc_green, uc_blue);
      case 24:
         return get_color_24(uc_red, uc_green, uc_blue);
      case 32:
         return get_color_24(uc_red, uc_green, uc_blue) | 0xFF000000;
      default:
         return 0;
   }
}

#undef RETURN_NULL_OR_THROW
#undef RETURN_NULL_IF_NULL_AND_NO_THROW

// +--------------------------+
// | Dummy i_workareaprovider |
// +--------------------------+

typedef BOOL ( * amd_get_workarea )( void *, int, void *, int );

class dsd_dummy_workareaprovider : public i_workareaprovider {
   amd_get_workarea amc_aux;  // Helper routine pointer
   void* avo_userfld;
public:

   dsd_dummy_workareaprovider(amd_get_workarea amc_aux, void* avo_userfld)
    : amc_aux(amc_aux), 
      avo_userfld(avo_userfld)
   {}

   bool get_workarea(char** aach_work_area, int* ain_len_work_area){
      struct dsd_aux_get_workarea dsl_aux_get_workarea;
      memset (&dsl_aux_get_workarea, 0, sizeof(struct dsd_aux_get_workarea));   
      BOOL bo = this->amc_aux( this->avo_userfld, DEF_AUX_GET_WORKAREA, &dsl_aux_get_workarea, sizeof(struct dsd_aux_get_workarea));
      if(bo == FALSE) 
         return false;
      *aach_work_area = dsl_aux_get_workarea.achc_work_area;
      *ain_len_work_area = dsl_aux_get_workarea.imc_len_work_area;
      return true;
   }
};


#endif