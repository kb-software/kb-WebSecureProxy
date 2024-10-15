#ifndef HOBTHREADS
#ifndef __ccdoc__
#define HOBTHREADS 1
#endif
/*****************************************************************************/
/* Project: hcthread                                                         */
/* Source: hob-thread.hpp                                                    */
/* Description: definiton of class dsd_hcthread: Creating and manipulating   */
/* strings for multiple operating systems.                                   */
/*                                                                           */
/* Copyright 1998, 2005 HOB GmbH & Co. KG Germany                                  */
/*                                                                           */
/* Created by: AC                                                            */
/* Creation Date: ??.??.1998?                                                */
/*                                                                           */
/* Operating system(architecture): Multiple                                  */
/*                                                                           */
/* Compile with: Depends                                                     */
/*                                                                           */
/* Additional requirements:                                                  */
/* Unix: set HL_UNIXSTRICT for UNIX-type thread functions, otherwise, the    */
/* thread method is declared without linkage modifier                        */
/* Win32: Compile with multithreaded runtime                                 */
/*                                                                           */
/* Additional Libraries:                                                     */
/* Unix: librt => link with -lrt                                             */
/*                                                                           */
/* Changed by:                                                               */
/* THO 20.07.2005 getThreadId, HCTHREADV1, dsd_hcthread                      */
/* changed to hob-thread.hpp (coding standards!!!)                           */
/*****************************************************************************/
/**
 * @pkg hcthread2
 */
/**
 * Creating and manipulating threads for multiple operating systems.
 * @version 2005/07/20.
 * @author AC, THO
 * @pkgdoc hcthread2
 */
//#define CUTRC 1                               // Trace variable

#ifndef __ccdoc__
// include necessary headers
#if defined WIN32 || WIN64
    #include <process.h>
#ifndef _INC_WINDOWS
#include <windows.h>
#define _INC_WINDOWS
#endif
#endif

#ifdef OS2
    #define INCL_DOSPROCESS
    #include <os2.h>
#endif

#ifdef HL_UNIX
    #include <pthread.h>
    #include <sched.h>
    #include <errno.h>
    #include <unistd.h>
#endif

#ifdef IBMOS400
#define _MULTI_THREADED
    #include <time.h>
    struct timespec
    {
       time_t tv_sec;
       long   tv_nsec;
    };
    #include <pthread.h>
  #ifdef CUTRC
    #include <unistd.h>
  #endif
#endif
#include <stdio.h>
#include <stdlib.h>

#ifdef CUTRC
// Used for test purposes only
  #ifdef HL_UNIX
    #define Sleep( x ) usleep( x * 1000 )
  #endif

  #ifdef OS2
    #define Sleep( x ) DosSleep( x )
  #endif
  #ifdef IBMOS400
    #define Sleep( x ) sleep( x )
  #endif
#endif
#endif //__ccdoc__

// Define standard macros
#ifdef HL_UNIX
/** Type for thread handle. */
   #define hthread_t2 pthread_t
#ifdef HL_UNIXSTRICT
/** Type for thread function for use in calling application. */
   #define htfunc1_t extern "C" void *
#else
/** Type for thread function for use in calling application. */
   #define htfunc1_t void *
#endif
/** Type for thread function without linkage specifier. */
   #define htfunc2_t void *
/** Type for thread function with linkage specifier. */
   #define htfunc3_t void *
/** Cast to minimize warnings */
   #define htfunc_cast (void*(*)(void*))
/** Return from thread function. */
   #define htreturn return 0
/** Value of an invalid thread ID. */
   #define INVALID_THREADID 0
#endif
#ifdef IBMOS400
/** Type for thread handle. */
   #define hthread_t2 pthread_t
/** Type for thread function for use in calling application. */
   #define htfunc1_t void *
/** Type for thread function without linkage specifier. */
   #define htfunc2_t void *
/** Type for thread function with linkage specifier. */
   #define htfunc3_t void *
/** Cast to minimize warnings */
   #define htfunc_cast
/** Return from thread function. */
   #define htreturn return 0
/** Value of an invalid thread ID. */
   #define INVALID_THREADID 0
#endif
#ifdef OS2
/** Type for thread handle. */
   #define hthread_t2 unsigned long
/** Type for thread function for use in calling application. */
   #define htfunc1_t void _Optlink
/** Type for thread function without linkage specifier. */
   #define htfunc2_t void
/** Type for thread function with linkage specifier. */
   #define htfunc3_t void _Optlink
/** Cast to minimize warnings */
   #define htfunc_cast
/** Return from thread function. */
   #define htreturn return
/** Value of an invalid thread ID. */
   #define INVALID_THREADID 0
#endif
#if defined WIN32 || WIN64
#ifdef HCTHREADV1
/** Type for thread handle. */
   #define hthread_t2 unsigned long
#ifdef VAC
/** Type for thread function for use in calling application. */
   #define htfunc1_t void _Optlink
/** Type for thread function with linkage specifier. */
   #define htfunc3_t void _Optlink
#else
/** Type for thread function for use in calling application. */
   #define htfunc1_t void
/** Type for thread function with linkage specifier. */
   #define htfunc3_t void
#endif
/** Type for thread function without linkage specifier. */
   #define htfunc2_t void
/** Cast to minimize warnings */
   #define htfunc_cast
/** Return from thread function. */
   #define htreturn return
/** Value of an invalid thread ID. */
   #define INVALID_THREADID 0
#else
/** Type for thread handle. */
   #define hthread_t2 HANDLE
/** Type for thread function for use in calling application. */
   #define htfunc1_t unsigned _stdcall
/** Type for thread function without linkage specifier. */
   #define htfunc2_t unsigned
/** Type for thread function with linkage specifier. */
   #define htfunc3_t unsigned _stdcall
/** Cast to minimize warnings */
   #define htfunc_cast
/** Return from thread function. */
   #define htreturn return 0
/** Value of an invalid thread ID. */
   #define INVALID_THREADID 0
#endif
#endif

// Return codes
/** An error occured. */
#define HT_ERROR -1
/** Everything is ok. */
#define HT_OK 0
/** Function not implemented. */
#define HT_NFUNC 0

#ifndef __ccdoc__
#define MIN_PRIO 1
#define MAX_PRIO 5
#define HL_DEFAULT_PRIO 0
#endif

/**
 * Create and manipulate threads,
 */
class dsd_hcthread
{
 public:
/** Thread state enumeration. */
      enum ied_threadstate{ied_stopped = 0,
                           ied_suspended = 1,
                           ied_running = 2};

/** Last error number. */
      unsigned int  ulc_lasterror;

 private:
/** Thread priority table */
     int imrc_prio[MAX_PRIO - MIN_PRIO + 1];

/** "Handle" to the new thread. */
      hthread_t2 dsc_hthread;
/** Pointer to thread function. */
      htfunc2_t amc_start(void*);
/** Thread state. */
      int imc_state;
/** Argument list for new thread. */
      void* avoc_parameter;
/** Initial thread stack size, in bytes. */
      unsigned int  ulc_stack;
/** Pointer to exit code. */
#if defined WIN32 || WIN64
      DWORD        * aulc_exitcode;
#else
      unsigned int * aulc_exitcode;
#endif
/** Exit code. */
      unsigned int  ulc_exit;
/** Thread priority level. */
      int imc_priority;
/** Thread's previous suspend count. */
      unsigned int  ulc_suscount;
/** Thread id. */
      unsigned int umc_id;

 public:
     /********** Constructors **************/
/**
 * Constructor. Call mc_create to start thread.
 */
      dsd_hcthread(void)
      {
         imc_state = ied_stopped;
         imc_priority = 0;
         ulc_lasterror = 0;
         umc_id = INVALID_THREADID;
      };
/**
 * Constructor. Starts a new thread.
 * @param amp_start thread start address.
 * @param avop_parameter thread arguments.
 * @param ulp_stack stack size.
 * @param imp_priority thread priority.between 0 and 5.
 */
      inline dsd_hcthread(htfunc3_t amp_start(void *),
                          void  *avop_parameter = 0,
                          unsigned int ulp_stack = 0,
                          int imp_priority = 0);

       /** functions **/
/**
 * Create the thread.
 * @param amp_start thread start address.
 * @param avop_parameter thread arguments.
 * @param ulp_stack stack size.
 * @param imp_priority thread priority.between 0 and 5.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
      int inline mc_create(htfunc3_t amp_start(void *),
                           void *avop_parameter = 0,
                           unsigned int ulp_stack = 0,
                           int imp_priority = 0);
/**
 * Forcibly end thread execution.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
      int inline mc_exit();
/**
 * Return thread priority.
 * @return Thread priority. Between 0 and 5. HT_ERROR if an error occurred, check ulc_lasterror for error code.
 */
      int inline mc_getpriority();
/**
 * Get thread exit code.
 * @return Exit code. HT_ERROR if an error occurred, check ulc_lasterror for error code.
 * Since the value of HT_ERROR may be the exit code of the thread, make sure to check
 * ulc_lasterror. If it is zero, HT_ERROR really is the threads return code.
 */
      unsigned int inline mc_getexitcode();
/**
 * Change thread priority.
 * @param imp_priority new thread priority. Between 0 and 5.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
      int inline mc_setpriority(int imp_priority);
/**
 * Resume a suspended thread.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
	  int inline mc_resume();
/**
 * Suspend (temporarily stop execution of) a thread.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
      int inline mc_suspend();
/**
 * Get thread ID.
 * @return Thread ID. INVALID_THREADID if an error occurred, check ulc_lasterror for error code.
 */
      unsigned int inline mc_getthreadid();

    /**
     * Return thread handle.
     * @return Thread handle.
     */
      hthread_t2 mc_geththread() {return dsc_hthread;};
    /**
     * Return stack size.
     * @return Stack size.
     */
      unsigned int mc_getstack() {return ulc_stack;};
    /**
     * Return exit code.
     * @return Exit code.
     */
      unsigned int mc_getlexitcode() {return ulc_exit;};
    /**
     * Return address of exit code.
     * @return Address of exit code.
     */
#if defined WIN32 || WIN64
      DWORD       * mc_getaexitcode() {return aulc_exitcode;};
#else
      unsigned int* mc_getaexitcode() {return aulc_exitcode;};
#endif
    /**
     * Return thread priority.
     * @return Thread priority.
     */
      int mc_getlastpriority() {return imc_priority;};
    /**
     * Return suspend count.
     * @return Suspend count.
     */
      unsigned int mc_getsuscount() {return ulc_suscount;};
    /**
     * Return thread arguments.
     * @return Thread arguments.
     */
      void* mc_getparameter() {return avoc_parameter;};

 private:
    /**
     * Create the 5 level priority table.
     */
      void mc_createprios()
      {
#if defined WIN32 || WIN64
         imrc_prio[0] = THREAD_PRIORITY_LOWEST;
         imrc_prio[1] = THREAD_PRIORITY_BELOW_NORMAL;
         imrc_prio[2] = THREAD_PRIORITY_NORMAL;
         imrc_prio[3] = THREAD_PRIORITY_ABOVE_NORMAL;
         imrc_prio[4] = THREAD_PRIORITY_HIGHEST;
#endif
#ifdef HL_UNIX
#ifdef _POSIX_PRIORITY_SCHEDULING
         struct sched_param ds_params;    // schduling parameters
         int im_policy;                   // scheduling policy
         int im_rc;                       // return code

         im_rc = pthread_getschedparam(dsc_hthread, &im_policy, &ds_params);
         if(im_rc)
         {
            im_policy = SCHED_OTHER;    // on error assume SCHED_OTHER
         }
         imrc_prio[0] = sched_get_priority_min(im_policy);
         if(imrc_prio[0] == -1)         // error use default values
#endif
         {
            imrc_prio[0] = -20;
            imrc_prio[1] = -10;
            imrc_prio[2] = 0;
            imrc_prio[3] = 10;
            imrc_prio[4] = 20;
         }
#ifdef _POSIX_PRIORITY_SCHEDULING
         else
         {
            imrc_prio[4] = sched_get_priority_max(im_policy);
            imrc_prio[2] = imrc_prio[0] + ((imrc_prio[4] - imrc_prio[0]) / 2);
            imrc_prio[1] = imrc_prio[0] + ((imrc_prio[2] - imrc_prio[0]) / 2);
            imrc_prio[3] = imrc_prio[2] + ((imrc_prio[4] - imrc_prio[2]) / 2);
         }
#endif
#endif
      };
}; // class dsd_hcthread

/**
 * Constructor. Call mc_create to start thread
 * @param amp_start thread start address.
 * @param avop_parameter thread arguments.
 * @param ulp_stack stack size.
 * @param imp_priority thread priority.between 0 and 5.
 */
dsd_hcthread::dsd_hcthread(htfunc3_t amp_start(void*),
                           void* avop_parameter,
                           unsigned int ulp_stack,
                           int imp_priority)
{
#ifdef CUTRC
   printf("Constructor 2\n");
#endif
   imc_state = ied_stopped;
   umc_id = INVALID_THREADID;
   mc_create(amp_start, avop_parameter, ulp_stack, imp_priority);
} // dsd_hcthread::dsd_hcthread(htfunc3_t, void*, unsigned int, int)

/**
 * Create the thread.
 * @param amp_start thread start address.
 * @param avop_parameter thread arguments.
 * @param ulp_stack stack size.
 * @param imp_priority thread priority.between 0 and 5.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
int dsd_hcthread::mc_create(htfunc3_t amp_start(void*),
                            void *avop_parameter,
                            unsigned int ulp_stack,
                            int imp_priority)
{
#if defined WIN32 || WIN64
   int im_suspended  = 0; // set to CREATE_SUSPENDED if priority has to be changed

   ulc_lasterror = 0;
#ifdef VAC
   dsc_hthread = _beginthread(amp_start ,NULL, ulp_stack, avop_parameter );
#elif defined HCTHREADV1
   dsc_hthread = (hthread_t2)(_beginthread(amp_start,
                                           ulp_stack,
                                           avop_parameter));
#else
   if(imp_priority != 0)
   {
      im_suspended = CREATE_SUSPENDED;
   }
   dsc_hthread = (HANDLE)_beginthreadex(NULL,
                                        ulp_stack,
                                        amp_start,
                                        avop_parameter,
                                        im_suspended,
                                        &umc_id);
#endif
   this->avoc_parameter = avop_parameter;
   this->ulc_stack = ulp_stack;
#ifdef HCTHREADV1
   if(dsc_hthread == -1)
#else
   if(dsc_hthread == 0)
#endif
   {
      ulc_lasterror = GetLastError();
#ifdef CUTRC
      printf("beginthread error: %ld.\n", ulc_lasterror);
#endif
      imc_priority = 0;
      imc_state = ied_stopped;
      return HT_ERROR;
   }
   else
   {
#ifndef HCTHREADV1
#ifndef VAC
      if(im_suspended != 0)
      {
         mc_setpriority(imp_priority);
         mc_resume();
      }
#endif
#endif
      imc_state = ied_running;
#ifdef CUTRC
      printf("beginthread OK: ied_running\n");
      Sleep( 700 );
#endif
      return HT_OK;
   }
#endif
#ifdef OS2
   dsc_hthread = _beginthread(amp_start, 0, ulp_stack, avop_parameter);
   this->avoc_parameter = avop_parameter;
   this->ulc_stack = ulp_stack;
   ulc_lasterror = dsc_hthread;
   if(dsc_hthread == -1)
    {
#ifdef CUTRC
      printf("beginthread error\n");
#endif
      imc_state = ied_stopped;
      return HT_ERROR;
   }
   else
   {
#ifdef CUTRC
      printf("beginthread OK: ied_running\n");
      Sleep( 700 );
#endif
      imc_state = ied_running;
      return HT_OK;
   }
#endif
#ifdef HL_UNIX
   int im_rc;               // function return code
   pthread_attr_t ds_attr;  // thread attrib struct
   pthread_attr_t* ads_attr = NULL; // pointer to structure above
   sched_param ds_priority; // schedule parameter

#ifdef TRACEHL1
   printf( "hob-thread.hpp-l%05d-T pthread_create() dsd_hcthread::mc_create()\n",
           __LINE__ );
#endif
   if(!pthread_attr_init(&ds_attr))
   {
        ads_attr = &ds_attr;
        if((imp_priority >= MIN_PRIO) && (imp_priority <= MAX_PRIO))
        {
             mc_createprios();
             pthread_attr_getschedparam(ads_attr, &ds_priority);
             ds_priority.sched_priority = imrc_prio[imp_priority - 1];
             pthread_attr_setschedparam(ads_attr, &ds_priority);
        }
        if (pthread_attr_setstacksize(ads_attr, ulp_stack) != 0)
            pthread_attr_setstacksize(ads_attr, 0); // stack is to small, set system default stack size value AG 25.01.06
        pthread_attr_getstacksize(ads_attr, (size_t*)&ulc_stack);
   }
   im_rc = pthread_create(&dsc_hthread, ads_attr, amp_start, avop_parameter);
#ifdef TRACEHL1
   printf( "hob-thread.hpp-l%05d-T pthread_create() returned %d errno %d.\n",
           __LINE__, im_rc, errno );
#endif
   if(ads_attr != NULL)
        pthread_attr_destroy(ads_attr);
   if(im_rc)
   {
       ulc_lasterror = im_rc;
       imc_state = ied_stopped;
#ifdef CUTRC
       printf("pthread_create FALSE\n");
#endif
       return HT_ERROR;
   }
   else
   {
       ulc_lasterror = 0;
       imc_priority = imp_priority;
       this->avoc_parameter = avop_parameter;
       imc_state = ied_running;
#ifdef CUTRC
       printf("pthread_create OK: ied_running\n");
#endif
       return HT_OK;
   }
#endif
#ifdef IBMOS400
   ulc_lasterror = pthread_create(&dsc_hthread,
                                  NULL,
                                  amp_start,
                                  avop_parameter);
   if(ulc_lasterror)
   {
       imc_state = ied_stopped;
#ifdef CUTRC
       printf("pthread_create FALSE: %ld\n", ulc_lasterror);
#endif
       return HT_ERROR;
   }
   else
   {
       this->avoc_parameter = avop_parameter;
       imc_state = ied_running;
#ifdef CUTRC
       printf("pthread_create OK: ied_running\n");
#endif
       return HT_OK;
    }
#endif
} // dsd_hcthread::mc_create(htfunc3_t, void*, unsigned int)

/**
 * Forcibly end thread execution.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
int dsd_hcthread::mc_exit()
{
#if defined WIN32 || WIN64
   ulc_lasterror = 0;
   if((TerminateThread((HANDLE)dsc_hthread, ulc_exit)) == FALSE)
   {
      ulc_lasterror = GetLastError();
#ifdef CUTRC
      printf("TerminateThread ERROR: %ld\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
   else
   {
      imc_state = ied_stopped;
      this->ulc_exit = ulc_exit;
#ifdef CUTRC
      printf("TerminateThread OK ied_stopped: EXITCODE: %d\n", ulc_exit);
#endif
      return HT_OK;
   }
#endif
#ifdef OS2
   ulc_lasterror = DosKillThread(dsc_hthread);
   if(ulc_lasterror == 0)
   {
      imc_state = ied_stopped;
#ifdef CUTRC
      printf("DosKillThread OK: ied_stopped\n");
#endif
      return HT_OK;
   }
   else
   {
#ifdef CUTRC
      printf("DosExit ERROR: %d\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
#endif
#ifdef HL_UNIX
   int  il_rc;

   il_rc = pthread_cancel(dsc_hthread);
   if(il_rc)
   {
      ulc_lasterror = errno;
#ifdef CUTRC
      printf("TerminateThread ERROR: %ld\n", il_rc);
#endif
      return HT_ERROR;
   }
   else
   {
      imc_state = ied_stopped;
      ulc_lasterror = 0;
#ifdef CUTRC
      printf("TerminateThread OK ied_stopped\n");
#endif
      return HT_OK;
   }
#endif
#ifdef IBMOS400
   ulc_lasterror = pthread_cancel(dsc_hthread);
   if (ulc_lasterror)
   {
#ifdef CUTRC
      printf("TerminateThread ERROR: %ld\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
   else
   {
      imc_state = ied_stopped;
#ifdef CUTRC
      printf("TerminateThread OK ied_stopped rc: %ld\n", ulc_lasterror);
#endif
      return HT_OK;
    }
#endif
} // dsd_hcthread::mc_exit()

/**
 * Return thread priority.
 * @return Thread priority. Between 0 and 5. HT_ERROR if an error occurred, check ulc_lasterror for error code.
 */
int dsd_hcthread::mc_getpriority()
{
#if defined WIN32 || WIN64
   int iml_index;           // index to priority array
   int iml_prio;            //Windows Thread priority

   ulc_lasterror = 0;

   iml_prio = GetThreadPriority((HANDLE)dsc_hthread);
   if(imc_priority == THREAD_PRIORITY_ERROR_RETURN)
   {
      ulc_lasterror = GetLastError();
#ifdef CUTRC
      printf("GetThreadPriority ERROR: %ld\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
   else
   {
#ifdef CUTRC
      printf("GetThreadPriority OK: %d\n", imc_priority);
#endif
      if(imc_priority == 0)
      {
         mc_createprios();
      }
      for(iml_index = MIN_PRIO; iml_index <= MAX_PRIO; iml_index++)
      {
         if(iml_prio == imrc_prio[iml_index - 1])
         {
            imc_priority = iml_index;
            break;
         }
      }
      if(iml_index > MAX_PRIO)
      {
         return HT_ERROR;
      }
      return imc_priority;
   }
#endif
#ifdef OS2
   return HT_NFUNC;
#endif
#ifdef HL_UNIX
   struct sched_param ds_params;    // schduling parameters
   int im_policy;                   // scheduling policy
   int im_rc;                       // return code
   int iml_index;                   // index to priority array

   im_rc = pthread_getschedparam(dsc_hthread, &im_policy, &ds_params);
   if(im_rc != 0 )
   {
      ulc_lasterror = im_rc;
      return HT_ERROR;
   }
   if(imc_priority == 0)
   {
      mc_createprios();
   }
   for(iml_index = MIN_PRIO; iml_index <= MAX_PRIO; iml_index++)
   {
      if(ds_params.sched_priority <= imrc_prio[iml_index - 1])
      {
         imc_priority = iml_index;
         break;
      }
   }
   if(iml_index > MAX_PRIO)
   {
      return HT_ERROR;
   }
   return imc_priority;
#endif
#ifdef IBMOS400
   return HT_NFUNC;
#endif
} // dsd_hcthread::mc_getpriority()

/**
 * Change thread priority.
 * @param imc_priority new thread priority.between 0 and 5.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
int dsd_hcthread::mc_setpriority(int imp_priority)
{
#if defined WIN32 || WIN64
   ulc_lasterror = 0;

   if(imp_priority == 0)
   {
      return HT_OK;
   }
   if((imp_priority < 1) || (imp_priority > 5))
   {
      ulc_lasterror = 87;   // Invalid parameter
      return HT_ERROR;
   }
   if(imc_priority == 0)
   {
      mc_createprios();
   }
   if((SetThreadPriority((HANDLE)dsc_hthread, imrc_prio[imp_priority-1]))
         == TRUE)
   {
#ifdef CUTRC
      printf("SetThreadPriority OK: %d\n", imp_priority);
#endif
      imc_priority = imp_priority;
      return HT_OK;
   }
   else
   {
      ulc_lasterror = GetLastError();
#ifdef CUTRC
      printf("SetThreadPriority ERROR: %ld\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
#endif
#ifdef OS2
   ulc_lasterror = DosSetPriority(PRTYS_THREAD, 0, imp_priority, dsc_hthread);
   if(ulc_lasterror == 0)
   {
#ifdef CUTRC
      printf("DosSetPriorityOK: %d\n", imp_priority);
#endif
      imc_priority = imp_priority;
      return HT_OK;
   }
   else
   {
#ifdef CUTRC
      printf("DosSetPriority ERROR: %ld\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
#endif
#ifdef HL_UNIX
   struct sched_param ds_params;    // schduling parameters
   int im_policy;                   // scheduling policy
   int im_rc;                       // return code

   ulc_lasterror = 0;

   if(imp_priority == 0)
   {
      return HT_OK;
   }
   if((imp_priority < 1) || (imp_priority > 5))
   {
      ulc_lasterror = 87;   // Invalid parameter
      return HT_ERROR;
   }
   if(imc_priority == 0)
   {
      mc_createprios();
   }
   im_rc = pthread_getschedparam(dsc_hthread, &im_policy, &ds_params);
   if(im_rc != 0 )
   {
      ulc_lasterror = im_rc;
      return HT_ERROR;
   }
   ds_params.sched_priority = imrc_prio[imp_priority-1];
   im_rc = pthread_setschedparam(dsc_hthread, im_policy, &ds_params);
   if(im_rc != 0 )
   {
      ulc_lasterror = im_rc;
      return HT_ERROR;
   }
   imc_priority = imp_priority;
   return HT_OK;
#endif
#ifdef IBMOS400
   return HT_NFUNC;
#endif
} // dsd_hcthread::mc_setpriority(int imp_priority)

/**
 * Get thread exit code.
 * @return Exit code. HT_ERROR if an error occurred, check ulc_lasterror for error code.
 * Since the value of HT_ERROR may be the exit code of the thread, make sure to check
 * ulc_lasterror. If it is zero, HT_ERROR really is the threads return code.
 */
unsigned int dsd_hcthread::mc_getexitcode()
{
#if defined WIN32 || WIN64
   ulc_lasterror = 0;
   if(GetExitCodeThread((HANDLE)dsc_hthread, aulc_exitcode) == TRUE)
   {
      if(*aulc_exitcode == STILL_ACTIVE)
      {
#ifdef CUTRC
         printf("GetExitCodeThread Active OK: %ld\n", *aulc_exitcode);
#endif
         imc_state = ied_running;
      }
      else
      {
#ifdef CUTRC
         printf("GetExitCodeThread OK: %ld\n", *aulc_exitcode);
#endif
         imc_state = ied_stopped;
      }
      return *aulc_exitcode;
   }
   else
   {
      ulc_lasterror = GetLastError();
#ifdef CUTRC
      printf("GetExitCodeThread ERROR: %ld\n", ulc_lasterror);
#endif
      return (unsigned int)HT_ERROR;
   }
#endif
#ifdef OS2
   return (unsigned int)HT_NFUNC;
#endif
#ifdef HL_UNIX
   return (unsigned int)HT_NFUNC;
#endif
#ifdef IBMOS400
   return (unsigned int)HT_NFUNC;
#endif
} // dsd_hcthread::mc_getexitcode()

/**
 * Resume a suspended thread.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
int dsd_hcthread::mc_resume()
{
#if defined WIN32 || WIN64
   ulc_lasterror = 0;

   ulc_suscount = ResumeThread((HANDLE)dsc_hthread);
   if(ulc_suscount == 0xFFFFFFFF)
   {
      ulc_lasterror = GetLastError();
#ifdef CUTRC
      printf("ResumeThread ERROR: %ld\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
   else
   {
      imc_state = ied_running;
#ifdef CUTRC
      printf("ResumeThread OK: ied_running: %d\n", ulc_suscount);
#endif
      return HT_OK;
   }
#endif
#ifdef OS2
   ulc_lasterror = DosResumeThread(dsc_hthread);
   if(ulc_lasterror == 0)
   {
      imc_state = ied_running;
#ifdef CUTRC
      printf("DosResumeThread OK ied_running\n");
#endif
      return HT_OK;
   }
   else
   {
#ifdef CUTRC
      printf("DosResumeThread ERROR: %ld\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
#endif
#ifdef HL_UNIX
   return HT_NFUNC;
#endif
#ifdef IBMOS400
   return HT_NFUNC;
#endif
} // dsd_hcthread::mc_resume()

/**
 * Suspend (temporarily stop execution of) a thread.
 * @return HT_OK if successful otherwise HTERROR. Check ulc_lasterror for system error code.
 */
int dsd_hcthread::mc_suspend()
{
#if defined WIN32 || WIN64
   ulc_lasterror = 0;

   ulc_suscount = SuspendThread((HANDLE)dsc_hthread);
   if(ulc_suscount == 0xFFFFFFFF)
   {
      ulc_lasterror = GetLastError();
#ifdef CUTRC
      printf("SuspendThread ERROR: %ld\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
   else
   {
      imc_state = ied_suspended;
#ifdef CUTRC
      printf("SuspendThread OK: ied_stopped: %ld\n", ulc_suscount);
#endif
      return HT_OK;
   }
#endif
#ifdef OS2
   ulc_lasterror = DosSuspendThread(dsc_hthread);
   if(ulc_lasterror == 0)
   {
      imc_state = ied_suspended;
#ifdef CUTRC
      printf("DosSuspendThread OK: ied_stopped\n");
#endif
      return HT_OK;
   }
   else
   {
#ifdef CUTRC
      printf("DosSuspendThread ERROR: %ld\n", ulc_lasterror);
#endif
      return HT_ERROR;
   }
#endif
#ifdef HL_UNIX
   return HT_NFUNC;
#endif
#ifdef IBMOS400
   return HT_NFUNC;
#endif
} // dsd_hcthread::mc_suspend()

/**
 * Get thread ID.
 * @return Thread ID. INVALID_THREADID if an error occurred, check ulc_lasterror for error code.
 */
unsigned int dsd_hcthread::mc_getthreadid()
{
#if defined WIN32 || WIN64
#ifdef HCTHREADV1
   unsigned int (FAR __stdcall *aml_getid)(hthread_t2);
   HMODULE iml_lib;

   ulc_lasterror = 0;
   if(umc_id == INVALID_THREADID)
   {
      iml_lib = LoadLibrary("Kernel32.dll");
      if(iml_lib != NULL)
      {
         aml_getid =
          (unsigned int (FAR __stdcall*)(hthread_t2))GetProcAddress(iml_lib,
                                                               "GetThreadId");
         if(aml_getid != NULL)
         {
            umc_id = aml_getid(dsc_hthread);
            if(umc_id == INVALID_THREADID)
            {
               ulc_lasterror = GetLastError();;
            }
         }
         else
         {
            ulc_lasterror = GetLastError();;
         }
         FreeLibrary(iml_lib);
      }
      else
      {
         ulc_lasterror = GetLastError();;
      }
   }
#endif
   return umc_id;
#endif
#ifdef OS2
   return dsc_hthread;
#endif
#ifdef HL_UNIX
// 27.07.15 KB - nonsense
#ifdef XYZ1
#ifndef HL_LINUX
#define HL_THRID m_gettid()
#include <sys/thr.h>
extern "C" pid_t m_gettid( void );
#else
#define HL_THRID syscall( __NR_gettid )
#endif
#ifndef HL_LINUX
/** get the thread id                                                  */
extern "C" pid_t m_gettid( void ) {
// to-do 27.07.15 KB - should be unsigned int
   long int iml_pwtid;

   thr_self( &iml_pwtid );
// iml_pwtid = 999;
   return (pid_t) iml_pwtid;
} /* end m_gettid()                                                    */
#endif
#endif
#ifdef B150727
   return (unsigned int) dsc_hthread;
#endif
   return 0;  /* invalid anyway */
#endif
#ifdef IBMOS400
   return dsc_hthread;
#endif
} // dsd_hcthread::mc_getthreadid()
#endif
