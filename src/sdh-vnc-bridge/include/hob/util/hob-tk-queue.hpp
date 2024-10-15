#pragma once
#ifndef __HOB_HOB_QUEUE__
#define __HOB_HOB_QUEUE__

namespace hob {
namespace util {


template<typename T> class dsd_hob_queue {
   T* adsc_first;
   T* adsc_last;
public:
   dsd_hob_queue() : adsc_first(NULL), adsc_last(NULL) {}
   dsd_hob_queue(T* adsp_first, T* adsp_last)
    : adsc_first(adsp_first),
      adsc_last(adsp_last)
   {}
   dsd_hob_queue(T* adsp_first)
    : adsc_first(adsp_first),
      adsc_last(adsp_first)
   {
      if(adsc_last) {
         while(this->adsc_last->adsc_next)
            this->adsc_last = this->adsc_last->adsc_next; 
      }   
   }
   dsd_hob_queue(dsd_hob_queue& rdsp_other)
    : adsc_first(rdsp_other.adsc_first),
      adsc_last(rdsp_other.adsc_last)
   {
      rdsp_other.clear();
   }
   void reset(T* adsp_first, T* adsp_last) {
      this->adsc_first = adsp_first; 
      this->adsc_last  = adsp_last;
   }
   void reset(dsd_hob_queue& rdsp_other) {
      this->adsc_first = rdsp_other.adsc_first; 
      this->adsc_last  = rdsp_other.adsc_last; 
   }
   void add(T* adsp_first_add){
      // No element given?
      if(adsp_first_add == NULL)
         return;

      // Put at end of queue
      if(this->adsc_first == NULL){
         // First element in queue
         this->adsc_first = adsp_first_add;
      } else {
         // There were other elements before
         this->adsc_last->adsc_next = adsp_first_add;
      }

      // Search for last gather
      while(adsp_first_add->adsc_next != NULL){
         adsp_first_add = adsp_first_add->adsc_next;
      }
      this->adsc_last = adsp_first_add; 
   }

   void add(T* adsp_first_add, T* adsp_last_add){
      // No element given?
      if(adsp_first_add == NULL)
         return;

      // Put at end of queue
      if(this->adsc_first == NULL){
         // First element in queue
         this->adsc_first = adsp_first_add;
         this->adsc_last  = adsp_last_add;
         return; 
      }
      this->adsc_last->adsc_next = adsp_first_add;
      this->adsc_last = adsp_last_add; 
   }

   void add_front(T* adsp_first_add){
      // No element given?
      if(adsp_first_add == NULL)
         return;

      // Remember old first element
      T* adsl_old_first = this->adsc_first;

      // Put at beginning of queue
      this->adsc_first = adsp_first_add;

      // Search for alst gather
      while(adsp_first_add->adsc_next != NULL){
         adsp_first_add = adsp_first_add->adsc_next;
      }
      
      adsp_first_add->adsc_next = adsl_old_first;
      if(this->adsc_last == NULL)
         this->adsc_last = adsp_first_add; 
   }

   bool is_empty(){
      return (this->adsc_first == NULL);
   }

   T* get_first() const {
      return this->adsc_first;
   }

   T* get_last() const {
      return this->adsc_last;
   }

   T* remove_first(){
      if(this->adsc_first == NULL)
         return NULL;
      T* adsl_ret = this->adsc_first;
      this->adsc_first = this->adsc_first->adsc_next;
      if(this->adsc_first == NULL)
         this->adsc_last = NULL;
      adsl_ret->adsc_next = NULL;
      return adsl_ret;
   }

   T* release(){
      T* adsl_ret = this->adsc_first;
      this->adsc_first = NULL;
      this->adsc_last = NULL;
      return adsl_ret; 
   }
   
   void clear(){
      this->adsc_first = NULL;
      this->adsc_last = NULL;
   }

   // move everything to other queue
   void move_to(dsd_hob_queue<T>* adsp_other){
      if(this->is_empty())
         return; // nothing to copy

      T* adsl_rem_last = this->get_last();
      if(adsp_other->is_empty()){
         adsp_other->adsc_first = this->release();
      } else {
         adsp_other->adsc_last->adsc_next = this->release();
      }
      adsp_other->adsc_last = adsl_rem_last;
   }

   bool empty(){
      return (this->adsc_first == NULL);
   }
};

template<typename T1, typename T2> class dsd_double_hob_queue {
   dsd_hob_queue<T1> dsc_queue_1;
   dsd_hob_queue<T2> dsc_queue_2;

public:   
   void add(T1* adsp_t1_add, T2* adsp_t2_add){
      this->dsc_queue_1.add(adsp_t1_add);
      this->dsc_queue_2.add(adsp_t2_add);
   }

   void move_to(dsd_double_hob_queue<T1, T2>* adsp_other){
      this->dsc_queue_1.move_to(adsp_other->get_queue_1());
      this->dsc_queue_2.move_to(adsp_other->get_queue_2());
   }

   T1* release_queue_1(){
      return this->dsc_queue_1.release();
   }

   T2* release_queue_2(){
      return this->dsc_queue_2.release();
   }

   dsd_hob_queue<T1>* get_queue_1(){
      return &this->dsc_queue_1;
   }

   dsd_hob_queue<T2>* get_queue_2(){
      return &this->dsc_queue_2;
   }

   void clear(){
      this->dsc_queue_1.clear();
      this->dsc_queue_2.clear();
   }

   bool is_empty(){
      return this->dsc_queue_1.is_empty() && this->dsc_queue_2.is_empty();
   }
};

} // namespace util
} // namespace hob

#endif