#ifndef __HOB_DSD_BUFFER_HPP__
#define __HOB_DSD_BUFFER_HPP__

/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-dsd_rdpacc_vector.hpp                           |*/
/*| -------------                                                     |*/
/*|  dsd_rdpacc_vector.hpp reserves memory for SIZE objects of type   |*/
/*|  T on the stack. Taken from an idea from Stefan Martin, which     |*/
/*|  uses malloc and free.                                            |*/
/*|  Johannes Bauer 02.12.2011                                        |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/* Necessary defines (only if HOB_RDPACC_ALLOW_THROW is set):

#include <hob-throw_error.hpp>

*/

typedef bool (*amd_get_memory) (void* avo_usrfld, char** aach_memory, int inl_size);
typedef bool (*amd_free_memory)(void* avo_usrfld, void*  avol_memory, int inl_size);

template<typename T, int SIZE> class dsd_rdpacc_vector {
private:
	T dscr_stack[SIZE];
	T* adsc_data;
   int inc_act_size; 
	
	dsd_rdpacc_vector(const dsd_rdpacc_vector&);
	dsd_rdpacc_vector& operator=(const dsd_rdpacc_vector&);

public:
   
   void init(){
      this->adsc_data = dscr_stack;
      this->inc_act_size = SIZE;
   }

   int get_act_size(){
      return this->inc_act_size;
   }

   dsd_rdpacc_vector() : adsc_data(dscr_stack), inc_act_size(SIZE) {}

#ifdef HOB_RDPACC_ALLOW_THROW
	/* Use a buffer of the specified size. */
	dsd_rdpacc_vector(int inl_length, amd_get_memory amc_get_memory, void* avo_usrfld)
		: adsc_data(dscr_stack), inc_act_size(SIZE){
      // Return, if size is big enough
      if(inl_length <= SIZE)
         return;
      // get more memory
      if(!amc_get_memory(avo_usrfld, &this->adsc_data, sizeof(T) * inl_length))
         THROW_HOB_ERROR("dsd_rdpacc_vector: amc_get_memory did not return memory for %i elements.", inl_length);
      inc_act_size = inl_length; 
   }
#else
	/* Use a buffer of the specified size. */
	dsd_rdpacc_vector(int inl_length, amd_get_memory amc_get_memory, void* avo_usrfld, bool* abol_ret)
		: adsc_data(dscr_stack), inc_act_size(SIZE) {
      // Return, if size is big enough
      if(inl_length <= SIZE)
         return;
      // get more memory
      *abol_ret = amc_get_memory(avo_usrfld, &this->adsc_data, sizeof(T) * inl_length) == true;
      if(*abol_ret)
         inc_act_size = inl_length;
   }
#endif



   bool close(amd_free_memory amd_free_memory, void* avo_usrfld, bool bol_zero_mem = false){

      if(bol_zero_mem){
         memset(this->dscr_stack, 0, SIZE);
      }
      
      if(this->adsc_data == this->dscr_stack)
         return true; 

      if(bol_zero_mem){
         memset(this->adsc_data, 0, this->inc_act_size);
      }
      
      // Delete memory
      if(!amd_free_memory(avo_usrfld, this->adsc_data, sizeof(T) * this->inc_act_size)){
#ifdef HOB_RDPACC_ALLOW_THROW
         THROW_HOB_ERROR("dsd_rdpacc_vector: amc_free_memory returned false.");
#endif
         return false; 
      }
      return true; 
   }

	// Destroys the buffer. */
	~dsd_rdpacc_vector(){
#ifdef HOB_RDPACC_ALLOW_THROW
		if(this->adsc_data != this->dscr_stack)
         THROW_HOB_ERROR("dsd_rdpacc_vector: this->adsc_data=%p this->dscr_stack=%p", this->adsc_data, this->dscr_stack);
#endif
	}

   bool reset(int inl_length, amd_get_memory amc_get_memory, amd_free_memory amd_free_memory, void* avo_usrfld){

      // Do we already have exact length?
      if(inl_length == this->inc_act_size)
         return true;

      // Free old memory if necessary
      if(this->adsc_data != this->dscr_stack){
         if(!amd_free_memory(avo_usrfld, this->adsc_data, sizeof(T) * this->inc_act_size)){
#ifdef HOB_RDPACC_ALLOW_THROW
            THROW_HOB_ERROR("dsd_rdpacc_vector: amc_free_memory returned false.");
#endif
            return false;
         }
      }

      // Check, if SIZE is big enough
      if(inl_length <= SIZE){
         this->adsc_data = this->dscr_stack;
         this->inc_act_size = SIZE; 
         return true;
      }

      // Now get memory
      if(!amc_get_memory(avo_usrfld, (char**)(&this->adsc_data), sizeof(T) * inl_length)){
#ifdef HOB_RDPACC_ALLOW_THROW
         THROW_HOB_ERROR("dsd_rdpacc_vector: amc_get_memory did not return memory for %i elements.", inl_length);
#endif
         return false; 
      }
      this->inc_act_size = inl_length; 
      return true;
   }
	
   bool ensure_elements(int inl_length, amd_get_memory amc_get_memory, amd_free_memory amd_free_memory, void* avo_usrfld, bool bol_copy = false){
      if(inl_length <= this->inc_act_size)
         return true; 
		T* adsl_olddata = this->adsc_data;

      // Get new memory
      if(!amc_get_memory(avo_usrfld, (char**)(&this->adsc_data), sizeof(T) * inl_length)){
#ifdef HOB_RDPACC_ALLOW_THROW
         THROW_HOB_ERROR("dsd_rdpacc_vector: amc_get_memory did not return memory for %i elements.", inl_length);
#endif
         return false; 
      }

      // Copy
      if(bol_copy){
         memcpy(this->adsc_data, adsl_olddata, sizeof(T) * this->inc_act_size);
      }

      // Delete old memory
      if(adsl_olddata != this->dscr_stack){
         if(!amd_free_memory(avo_usrfld, adsl_olddata, sizeof(T) * this->inc_act_size)){
#ifdef HOB_RDPACC_ALLOW_THROW
            THROW_HOB_ERROR("dsd_rdpacc_vector: amc_free_memory returned false.");
#endif
            return false; 
         }
      }

      // Use new memory
      this->inc_act_size = inl_length; 
      return true; 
   }

   bool init_and_copyfrom(dsd_rdpacc_vector<T, SIZE>* adsl_src, amd_get_memory amc_get_memory, void* avol_usrfld){
      this->inc_act_size = adsl_src->inc_act_size;
      if(this->inc_act_size <= SIZE){
         this->adsc_data = this->dscr_stack;
      } else {
         if(!amc_get_memory(avol_usrfld, (char**)(&this->adsc_data), sizeof(T) * this->inc_act_size)){
#ifdef HOB_RDPACC_ALLOW_THROW
            THROW_HOB_ERROR("dsd_rdpacc_vector: amc_get_memory did not return memory for %i elements.", inl_length);
#endif
            return false; 
         }
      }
      memcpy(this->adsc_data, adsl_src->adsc_data, this->inc_act_size);
      return true; 
   }

	T* get_data(){
		return adsc_data;
	}

	T* operator*(){
		return adsc_data;
	}
};

#endif // __HOB_DSD_BUFFER_HPP__
