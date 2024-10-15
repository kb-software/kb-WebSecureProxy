#ifndef COMP_HOB_XSLHCLA1
#define COMP_HOB_XSLHCLA1
#ifdef WIN32
class dsd_hcla_event_1 {                    /* class for events        */
#ifdef B141228
   private:
#endif
   public:
     HANDLE   dsc_heve_1;                   /* event handle            */

#ifdef B141228
   public:
#endif
     inline int m_create( int *aimp_ext_error ) {
       dsc_heve_1 = CreateEvent( NULL, FALSE, FALSE, NULL );
       if (dsc_heve_1 == NULL) {
         *aimp_ext_error = GetLastError();  /* get error code from OS  */
         return -1;                         /* return with error       */
       }
       return 0;
     }

     inline int m_wait( int *aimp_ext_error ) {
       DWORD  dwl_rc;                       /* return code             */

       dwl_rc = WaitForSingleObject( dsc_heve_1, INFINITE );
       if (dwl_rc == WAIT_OBJECT_0) return 0;
       *aimp_ext_error = GetLastError();    /* get error code from OS  */
       return dwl_rc;                       /* error occured           */
     }

     inline int m_wait_msec( int imp_waitmsec, int *aimp_ext_error ) {
       DWORD  dwl_rc;                       /* return code             */

       dwl_rc = WaitForSingleObject( dsc_heve_1, imp_waitmsec );
       if (dwl_rc == WAIT_OBJECT_0) return 0;
       *aimp_ext_error = GetLastError();    /* get error code from OS  */
       return dwl_rc;                       /* error occured           */
     }

#ifdef XYZ1
     inline APIRET waitsec( UNSIG_MED ulp1 ) {  /* wait in seconds         */
       sleep( ulp1 );
       return 0;
     }
#endif

     inline int m_post( int *aimp_ext_error ) {  /* post event         */
       BOOL   bol_rc;                       /* return code             */

       bol_rc = SetEvent( dsc_heve_1 );
       if (bol_rc) return 0;                /* no error                */
       *aimp_ext_error = GetLastError();    /* get error code from OS  */
       return -1;                           /* error occured           */
     }

     inline int m_close( int *aimp_ext_error ) {  /* close event handle */
       BOOL   bol_rc;                       /* return code             */

       bol_rc = CloseHandle( dsc_heve_1 );
       if (bol_rc) return 0;                /* no error                */
       *aimp_ext_error = GetLastError();    /* get error code from OS  */
       return -1;                           /* error occured           */
     }
};

class dsd_hcla_critsect_1 {                 /* class for critical sect */
   private:
     CRITICAL_SECTION dsc_critsect_1;       /* critical section        */

   public:
     inline int m_create() {
       InitializeCriticalSection( &dsc_critsect_1 );
       return 0;
     }

     inline int m_enter() {
       EnterCriticalSection( &dsc_critsect_1 );
       return 0;
     }

     inline int m_leave() {
       LeaveCriticalSection( &dsc_critsect_1 );
       return 0;
     }

     inline int m_close() {
       DeleteCriticalSection( &dsc_critsect_1 );
       return 0;
     }
};

#ifdef XYZ1
class clepoch1 {                            /* class for timers        */
   public:
     inline UNSIG_MED gettime() {
       struct timeval dutimeval;
       gettimeofday( &dutimeval, 0 );
       return (UNSIG_MED) dutimeval.tv_sec;
     }
};
#endif
#endif
#ifdef HL_UNIX
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

#ifdef HL_MACOS
#ifndef __MACOS_GETTIME_WORKAROUND__
#define __MACOS_GETTIME_WORKAROUND__
#define CLOCK_REALTIME 0
/**
This serves as a workaround for the lack of clock_gettime on MAC OS X.

As it uses gettimeofday, it is only accurate on a usec scale.
*/
inline int clock_gettime(int, struct timespec *adsp_result ){
    struct timeval now;
    int rv = gettimeofday(&now, NULL);
    if (rv) return rv;
    adsp_result->tv_sec  = now.tv_sec;
    adsp_result->tv_nsec = now.tv_usec * 1000;
    return 0;
}

#endif // !__MACOS_GETTIME_WORKAROUND__
#endif //HL_MACOS

class dsd_hcla_event_1 {                    /* class for events        */
private:
    pthread_mutex_t ds_mutex;
    pthread_cond_t ds_cond;
    int im_counter;
#ifdef HL_COND_BC
    int im_waiters; // to do: if implemenation of pthread_cond_broadcast() needed
#endif
public:
    inline int m_create( int *aimp_ext_error ) {
        int    inl1;
        im_counter = 0;
#ifdef HL_COND_BC
        im_waiters = 0;
#endif
        if ((inl1 = pthread_cond_init(&ds_cond, NULL)) != 0)
        {
            if (aimp_ext_error)
                *aimp_ext_error = inl1;
            return -1;
        }
        if ((inl1 = pthread_mutex_init(&ds_mutex, NULL)) != 0)
        {
            if (aimp_ext_error)
                *aimp_ext_error = inl1;
            pthread_cond_destroy(&ds_cond);
            return -1;
        }
        return 0;
    }

    inline int m_wait( int *aimp_ext_error ) {
        int    inl1;
        if ((inl1 = pthread_mutex_lock(&ds_mutex)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            return -1;
        }
#ifdef HL_COND_BC
        ++ im_waiters;
#endif
        for (;;)
        {
            if (im_counter > 0)
            {
                -- im_counter;
#ifdef HL_COND_BC
                -- im_waiters;
#endif
                if ((inl1 = pthread_mutex_unlock(&ds_mutex)) != 0)
                {
                    if (aimp_ext_error != NULL)
                        *aimp_ext_error = inl1;
                    return -1;
                }
                return 0;
            }
            if ((inl1 = pthread_cond_wait(&ds_cond, &ds_mutex)) != 0)
            {
                if (inl1 == EINTR) //for linux
                    continue;
                if (aimp_ext_error != NULL)
                    *aimp_ext_error = inl1;
#ifdef HL_COND_BC
                  -- im_waiters;
#endif
                pthread_mutex_unlock(&ds_mutex);
                return -1;
            }
            if (im_counter <= 0) // maybe EINTR
                continue;
            break;
        }
        -- im_counter;
#ifdef HL_COND_BC
        -- im_waiters;
#endif
        if ((inl1 = pthread_mutex_unlock(&ds_mutex)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            return -1;
        }
        return 0;
    }

    inline int m_wait_msec( int imp_waitmsec, int *aimp_ext_error ) {
        int    inl1;
        struct timespec dsl_timespec;

        if (imp_waitmsec < 0)
             return m_wait(aimp_ext_error);
        	
        clock_gettime(CLOCK_REALTIME, &dsl_timespec);
        dsl_timespec.tv_sec += imp_waitmsec / 1000;
        dsl_timespec.tv_nsec += (imp_waitmsec%1000) * 1000000;
        dsl_timespec.tv_sec += dsl_timespec.tv_nsec/1000000000;
        dsl_timespec.tv_nsec %= 1000000000;
        if ((inl1 = pthread_mutex_lock(&ds_mutex)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            return -1;
        }
#ifdef HL_COND_BC
        ++ im_waiters;
#endif
        for (;;)
        {
            if (im_counter > 0)
            {
                -- im_counter;
#ifdef HL_COND_BC
                -- im_waiters;
#endif
                if ((inl1 = pthread_mutex_unlock(&ds_mutex)) != 0)
                {
                    if (aimp_ext_error != NULL)
                        *aimp_ext_error = inl1;

                    return -1;
                }
                return 0;
            }

            if ((inl1 = pthread_cond_timedwait(&ds_cond, &ds_mutex, &dsl_timespec)) != 0)
            {
                if (inl1 == EINTR) // inl1 == EINTR for linux
                    continue;
                if (inl1 != ETIMEDOUT) // error
                {
                    if (aimp_ext_error != NULL)
                        *aimp_ext_error = inl1;
                    pthread_mutex_unlock(&ds_mutex);
#ifdef HL_COND_BC
                    -- im_waiters;
#endif
                    return -1;
                }
                else // ETIMEDOUT
                {
                    if (aimp_ext_error != NULL)
                        *aimp_ext_error = inl1;
                    break;
                }
            }
            if (im_counter <= 0) //maybe EINTR
                continue;
            -- im_counter;
            break;
        }
#ifdef HL_COND_BC
        -- im_waiters;
#endif
        if ((inl1 = pthread_mutex_unlock(&ds_mutex)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            return -1;
        }
        return 0;
    }

#ifdef XYZ1
    inline APIRET waitsec( UNSIG_MED ulp1 ) {  /* wait in seconds         */
        sleep( ulp1 );
        return 0;
    }
#endif

    inline int m_post( int *aimp_ext_error ) {  /* post event         */
        int    inl1;
        if ((inl1 = pthread_mutex_lock(&ds_mutex)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            return -1;
        }
        if ((inl1 = pthread_cond_signal(&ds_cond)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            pthread_mutex_unlock(&ds_mutex);
            return -1;
        }
        ++ im_counter;
        if ((inl1 = pthread_mutex_unlock(&ds_mutex)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            return -1;
        }
        return 0;
    }
#ifdef HL_COND_BC
    inline int m_post_all( int *aimp_ext_error ) {  /* post event         */
        int    inl1;
        if ((inl1 = pthread_mutex_lock(&ds_mutex)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            return -1;
        }
        if ((inl1 = pthread_cond_broadcast(&ds_cond)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            pthread_mutex_unlock(&ds_mutex);
            return -1;
        }
        im_counter += im_waiters;
        //++ im_counter;
        if ((inl1 = pthread_mutex_unlock(&ds_mutex)) != 0)
        {
            if (aimp_ext_error != NULL)
                *aimp_ext_error = inl1;
            return -1;
        }
        return 0;
    }
#endif
    inline int m_close( int *aimp_ext_error ) {  /* close event handle */
        int    inl1;

        if ((inl1 = pthread_mutex_destroy(&ds_mutex)) != 0)
        {
            if (aimp_ext_error)
                *aimp_ext_error = inl1;
        }
        if ((inl1 = pthread_cond_destroy(&ds_cond)) != 0)
        {
            if (aimp_ext_error)
                *aimp_ext_error = inl1;
            return -1;
        }
        return inl1;
    }
};

#ifdef HL_FREEBSD
// FreeBSD needs an initialization of the pthread_mutex_t
// Other UNIX based systems so far seem fine
#define HL_PTHREAD_INIT_VAL 0
#else
#define HL_PTHREAD_INIT_VAL
#endif

class dsd_hcla_critsect_1 {                 /* class for critical sect */
   private:
     pthread_mutex_t dsc_hcla_critsect_1;

   public:
     dsd_hcla_critsect_1(void) : 
         dsc_hcla_critsect_1(HL_PTHREAD_INIT_VAL){}

     inline int m_create() {
  return pthread_mutex_init( &dsc_hcla_critsect_1 , NULL );
     }
     inline int m_enter() {
  return pthread_mutex_lock( &dsc_hcla_critsect_1 );
     }
     inline int m_leave() {
  return pthread_mutex_unlock( &dsc_hcla_critsect_1 );
     }
     inline int m_close() {
      return pthread_mutex_destroy(&dsc_hcla_critsect_1);
     }
};

#ifdef XYZ1
class clepoch1 {                            /* class for timers        */
   public:
     inline UNSIG_MED gettime() {
       struct timeval dutimeval;
       gettimeofday( &dutimeval, 0 );
       return (UNSIG_MED) dutimeval.tv_sec;
     }
};
#endif
#endif
#endif //COMP_HOB_XSLHCLA1
