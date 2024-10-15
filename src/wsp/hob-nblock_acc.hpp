// to-do 17.09.11 KB remove entries ads_thread->dsr_tcpconn[im_index] when NULL
// to-do 17.09.11 KB + CloseHandle when Windows
#ifndef __HOB_NON_BLOCKING_ACCEPTOR
#define __HOB_NON_BLOCKING_ACCEPTOR

#ifdef B090124
#ifdef _DEBUG
#if defined(WIN32) || defined(WIN64)
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#endif
#endif

/*****************************************************************************/
/* Project: non-blocking accept                                              */
/* Source: hob-nblock_acc.hpp                                                */
/* Description: header containing non-blocking accept definition             */
/*                                                                           */
/* Copyright 2007 HOB GmbH & Co. KG                                          */
/* Copyright 2011 HOB Germany                                                */
/*                                                                           */
/* Created by: AG                                                            */
/* Creation Date: 14.05.2007                                                 */
/*                                                                           */
/* Operating system(architecture): Win32(X86)                                */
/*                                                                           */
/* Compile with: Visual Studio .Net C++                                      */
/*                                                                           */
/* Additional requirements: calling source must have windows.h and winsock2.h*/
/*                                                                           */
/*****************************************************************************/
/**
 * @pkg nblock_acc
 */
/**
 * Non blocking TCP/IP Accept for Win32.
 * @version 2007/05/14.
 * @author AG
 * @pkgdoc nblock_acc
 */
#if defined(WIN32) || defined(WIN64)

#ifdef B090124
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <process.h>
#endif

//#define TRACE
#ifndef BOOL
#ifndef __ccdoc__
   #define BOOL int
#endif
#endif


// Defines
/** Maximum number of connections one thread can handle. */
#define NBACC_MAXCONN (WSA_MAXIMUM_WAIT_EVENTS-1)
/** Error location flag: startacc. */
#define NBACC_ERRORAT_STARTACC 1
/** Error location flag: stopacc. */
#define NBACC_ERRORAT_STOPACC 2
/** Error location flag: accthread. */
#define NBACC_ERRORAT_ACCTHREAD 3
/** Error location flag: close socket. */
#define NBACC_ERRORAT_CLOSE 4
/** Error location flag: accept */
#define NBACC_ERRORAT_ACCEPT 5
/** Error location flag: accept socket */
#define NBACC_ERRORAT_ACCEPT_SOCK 6

// Error numbers:
/** Error: No error. */
#define NBACC_ERROR_NONE 0
/** Error: startup called twice. */
#define NBACC_ERROR_ALREADYRUNNING (-1000)
/** Error: Unable to create thread. */
#define NBACC_ERROR_NOTHREAD (-1001)
/** Error: Illegal parameter (=null) */
#define NBACC_ERROR_NULLPARAM (-1002)
/** Error: No more addresses to connect to. */
#define NBACC_ERROR_NOADDRESS (-1003)
// End of defines

// Classes and structures

class dsd_nblock_acc;     // forward declaration

/**
 * This structure contains the set of callback routines used to inform
 * the calling programm about network events ( and errors).
 */
typedef struct dsd_acccallback
{
   void (*am_acceptcallback)( dsd_nblock_acc *, void *, int, struct sockaddr *, int );  // Accept callback function.
   void (*am_errorcallback)( dsd_nblock_acc *, void *, char *, int, int ); // Error callback function.
} dsd_acccallback_t;
/** Pointer to a callback structure. */
typedef dsd_acccallback_t* dsd_acccallback_p;

/**
 * This class implements an interface for performing nonblocking accept
 * operations on multiple connections. Each instance maps to one
 * listener.
 */
class dsd_nblock_acc
{
   BOOL       boc_fix;                      /* do not free memory      */
// type definitions
   /** Type for TCP connection handle. */
   typedef SOCKET dsd_tcphandle;
   /** Type for event handle. */
   typedef HANDLE dsd_eventtype;
   /** Thread handle type. */
   typedef uintptr_t dsd_threadhandle;

#ifdef B110917
/**
 * Structure for list of stopped connections.
 * The wait thread looks through this list and deletes all connection
 * listed here.
 */
typedef struct dsd_stopped
{
   struct dsd_stopped* ads_next;   // Next element in chain.
   class dsd_nblock_acc* ads_stopped; // Stopped connection.
   BOOL bo_close;                  // Socket has to be closed by wait thread.
} dsd_stopped_t;
/** Pointer to a stopped connection structure. */
typedef dsd_stopped_t* dsd_stopped_p;
#endif
/**
 * This structure defines an element of a TCP/IP wait thread.chain.
 */
typedef struct dsd_tcpthread
{
   struct dsd_tcpthread* ads_next;   // Next element in chain.
   dsd_threadhandle ds_threadhandle; // The thread handle.
   class dsd_nblock_acc* dsr_tcpconn[NBACC_MAXCONN]; // Array of connections handled by thread
   dsd_eventtype dsr_waitevent[NBACC_MAXCONN+1];  // Array of events handled by thread.
#ifdef B110918
   int im_concount;                  // Number of active connections.
#else
   volatile int im_concount;         // Number of active connections.
#endif
#ifdef B110917
   dsd_stopped_p ads_stopchain;      // Anchor for chain of stopped connections.
#endif
   BOOL bo_cleanup;                  // If this is set, the thread  cleans up and stops executing.
   CRITICAL_SECTION ds_thrcritsect;
   dsd_tcpthread()  {
       ads_next = NULL;
       ds_threadhandle = NULL;
       memset(&dsr_tcpconn, 0, sizeof(dsr_tcpconn));
       memset(&dsr_waitevent, 0, sizeof(dsr_waitevent));
       im_concount = 0;
#ifdef B110917
       ads_stopchain = 0;
#endif
       bo_cleanup = FALSE;
       InitializeCriticalSection(&ds_thrcritsect);
   };
   ~dsd_tcpthread() { DeleteCriticalSection(&ds_thrcritsect); };
} dsd_tcpthread_t;
/** Pointer to a wait thread structure. */
typedef dsd_tcpthread_t* dsd_tcpthread_p;



// static members
/** Anchor for tcp threads. */
   static dsd_tcpthread_p ads_thranc;
/** Critical section for safe access to ressources. */
   static CRITICAL_SECTION ds_critsect;
/**
 * Create a new TCP work thread.
 * @return address of the thread structure for the newly created thread.
 */
   static inline dsd_tcpthread_p mc_createnewthread();
/**
 * TCP/IP wait thread.
 * @param ads_parm pointer to corresponding thread structure.
 */
   static inline void mc_accthread(void*);

public:
/**
 * Initiate dsd_nblock_acc.
 * @return TRUE if successful, otherwise FALSE.
 */
   static inline int mc_startup();
/**
 * Cleanup everything.
 * @return TRUE if successful, otherwise FALSE.
 */
   static inline int mc_shutdown();
/**
 * Create a new listener instance.
 * @param ds_sock socket used.
 * @param ads_callback structure containing the necessary callback functions.
 * @param ads_usrfld pointer to user data.
 * @return pointer to the newly created dsd_nblock_acc object, NULL if an error occurred.
 */
   static inline dsd_nblock_acc* mc_startlisten(dsd_tcphandle ds_sock,
                                          dsd_acccallback_p ads_callback,
                                          void* ads_usrfld);
   inline int mc_startlisten_fix(dsd_tcphandle ds_sock,
                                 dsd_acccallback_p ads_callback,
                                 void* ads_usrfld);
// instance members
/** Last error code (OS dependent). */
   int im_error;
/**
 * Stop processing this connection.
 * @param bo_close close the underlying socket.
 * @param bo_thread delete connection from thread.
 * @return TRUE if successful, otherwise FALSE.
 */
   inline void mc_stoplistener(BOOL bo_close,
                   BOOL bo_thread = TRUE);
   inline int  mc_stoplistener_fix( void );
/**
 * Called, when ACCEPTOR should start accepting again.
 * @return TRUE if successful, otherwise FALSE.
 */
   inline int mc_resume();                           // start accepting again

private:
/**
 * Non-blocking accept
 * @param dsp_addr optional out pointer to a buffer that receives the address of the connecting entity
 * @param aimp_addrlen optional in/out pointer to an integer that contains the length of dsp_addr
 * @return returns a value of type SOCKET that is a descriptor for the new socket or INVALID_SOCKET if error occurs
 */
   inline int mc_accept_sock();
/** Structure with callback methods. */
   dsd_acccallback_p ads_callback;
/** Socket to work with. */
   dsd_tcphandle ds_sock;
/** User specific data. */
   void* ads_usrfld;
/** Corresponding thread object. */
   dsd_tcpthread_p ads_thread;
/** Event used with this connection. */
   dsd_eventtype ds_event;
/** Receive allowed. */
   BOOL bo_accept;
/** Receive data available. */
   BOOL bo_data;
};// class dsd_nonblock_acc
// End of classes and structures

int dsd_nblock_acc::mc_startup()
{
#ifdef TRACE
   printf("mc_startup\n");
#endif
   if(ads_thranc != NULL)
   {
      return NBACC_ERROR_ALREADYRUNNING;
   }
   InitializeCriticalSection(&ds_critsect);
   ads_thranc = mc_createnewthread();
   if(ads_thranc == NULL)
   {
      DeleteCriticalSection(&ds_critsect);
      return NBACC_ERROR_NOTHREAD;
   }
   return NBACC_ERROR_NONE;
} // int class dsd_nblock_acc::mc_startup()

int dsd_nblock_acc::mc_shutdown()
{
   dsd_tcpthread_p ads_thrcur;            // current thread object
   dsd_tcpthread_p ads_thrnext;           // next thread object

#ifdef TRACE
   printf("m_shutdown\n");
#endif
   EnterCriticalSection(&ds_critsect);
   ads_thrcur = ads_thranc;
   ads_thranc = NULL;
   while(ads_thrcur)
   {
      ads_thrnext = ads_thrcur->ads_next;
      ads_thrcur->bo_cleanup = TRUE;
      SetEvent(ads_thrcur->dsr_waitevent[0]); // Tell thread to cleanup.
      ads_thrcur = ads_thrnext;
   }
   LeaveCriticalSection(&ds_critsect);
   DeleteCriticalSection(&ds_critsect);
   return TRUE;
} // int class dsd_nblock_acc::mc_shutdown()

dsd_nblock_acc* dsd_nblock_acc::mc_startlisten(dsd_tcphandle ds_sock,
                                      dsd_acccallback_p ads_callback,
                                      void* ads_usrfld)
{
   dsd_nblock_acc* ads_newcon;               // new connection object
   dsd_tcpthread_p ads_thrcur;            // current thread object
   dsd_tcpthread_p ads_thrlast;           // last thread in chain
#ifdef TRACE
   printf("mc_startlisten\n");
#endif
   if(ds_sock == INVALID_SOCKET ||
      !ads_callback ||
      !ads_usrfld ||
      !ads_callback->am_acceptcallback ||
      !ads_callback->am_errorcallback)
   {
#ifdef TRACE
      printf("Parameter is null\n");
#endif
      return NULL;
   }

   bool bo_listener;
   int im_optlen;
   bo_listener = false;
   im_optlen = sizeof(bool);
   if (getsockopt(ds_sock, SOL_SOCKET, SO_ACCEPTCONN, (char*)&bo_listener, &im_optlen) != 0)
   {
#ifdef TRACE
      printf("Error getsockopt()\n");
#endif
      return NULL;
   }
   if (bo_listener == false)
   {
#ifdef TRACE
      printf("Socket is not a listener socket\n");
#endif
      return NULL;
   }

   ads_newcon = new dsd_nblock_acc();
   if(!ads_newcon)
   {
#ifdef TRACE
      printf("Unable to allocate memory for new connection object\n");
#endif
      return NULL;
   }
   // Init connection object
#ifndef B110917
   ads_newcon->boc_fix = FALSE;             /* do not free memory      */
#endif
   ads_newcon->bo_data = FALSE;
   ads_newcon->bo_accept = TRUE;
   ads_newcon->ds_sock = ds_sock;
   ads_newcon->ads_callback = ads_callback;
   ads_newcon->ads_usrfld = ads_usrfld;
   ads_newcon->im_error = 0;
   ads_newcon->ds_event = CreateEvent(NULL, TRUE, FALSE, NULL);
   if(ads_newcon->ds_event == NULL)
   {
#ifdef TRACE
      printf("Unable to create event for new connection object\n");
#endif
      delete ads_newcon;
      return NULL;
   }
   if(WSAEventSelect(ds_sock,
                     ads_newcon->ds_event,
                     FD_ACCEPT))
   {
#ifdef TRACE
      printf("Unable to set socket for non-blocking operation: %d\n", WSAGetLastError());
#endif
      CloseHandle(ads_newcon->ds_event);
      delete ads_newcon;
      return NULL;
   }
   // now find a thread to handle this connection
   EnterCriticalSection(&ds_critsect);
   ads_thrlast = ads_thrcur = ads_thranc;
   while(ads_thrcur)
   {
      if(ads_thrcur->im_concount < NBACC_MAXCONN)
      {
         break;
      }
      ads_thrlast = ads_thrcur;
      ads_thrcur = ads_thrcur->ads_next;
   }
   if(!ads_thrcur)    // no more space in threads, create new one
   {
      LeaveCriticalSection(&ds_critsect);
      ads_thrcur = mc_createnewthread();
      if(!ads_thrcur)
      {
#ifdef TRACE
         printf("Unable to start a thread for this connection\n");
#endif
         CloseHandle(ads_newcon->ds_event);
         delete ads_newcon;
         return NULL;
      }
      EnterCriticalSection(&ds_critsect);
      if(!ads_thranc)
      {
        ads_thranc = ads_thrcur;
      }
      else
      {
         ads_thrlast = ads_thranc;
         while(ads_thrlast)
         {
            if(!ads_thrlast->ads_next)
            {
               ads_thrlast->ads_next  = ads_thrcur;
               break;
            }
            ads_thrlast = ads_thrlast->ads_next;
         }
      }
   }
   ads_newcon->ads_thread = ads_thrcur;
   ads_thrcur->dsr_tcpconn[ads_thrcur->im_concount] = ads_newcon;
   ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1] =
                                                     ads_newcon->ds_event;
   ads_thrcur->im_concount++;
   LeaveCriticalSection(&ds_critsect);
   if(!SetEvent(ads_thrcur->dsr_waitevent[0])) // Tell thread to handle this connection
   {
      if(ads_callback->am_errorcallback != NULL)
      {
         ads_newcon->im_error = GetLastError();
         ads_callback->am_errorcallback(ads_newcon,
                                        ads_usrfld,
                                        "Unable to set event for new connection",
                                        ads_newcon->im_error,
                                        NBACC_ERRORAT_STARTACC);
      }
#ifdef TRACE
      printf("Unable to set event for new connection.\n");
#endif
   }
   return ads_newcon;
} // dsd_nblock_acc* dsd_nblock_acc::mc_startlisten(dsd_tcphandle, dsd_tcpcallback_p, void*)

int dsd_nblock_acc::mc_startlisten_fix(dsd_tcphandle ds_sock,
                                      dsd_acccallback_p ads_callback,
                                      void* ads_usrfld)
{
   dsd_tcpthread_p ads_thrcur;            // current thread object
   dsd_tcpthread_p ads_thrlast;           // last thread in chain
#ifdef TRACE
   printf("mc_startlisten_fix\n");
#endif
   if(ds_sock == INVALID_SOCKET ||
      !ads_callback ||
      !ads_usrfld ||
      !ads_callback->am_acceptcallback ||
      !ads_callback->am_errorcallback)
   {
#ifdef TRACE
      printf("Parameter is null\n");
#endif
      return NULL;
   }

   bool bo_listener;
   int im_optlen;
   bo_listener = false;
   im_optlen = sizeof(bool);
   if (getsockopt(ds_sock, SOL_SOCKET, SO_ACCEPTCONN, (char*)&bo_listener, &im_optlen) != 0)
   {
#ifdef TRACE
      printf("Error getsockopt()\n");
#endif
      return NULL;
   }
   if (bo_listener == false)
   {
#ifdef TRACE
      printf("Socket is not a listener socket\n");
#endif
      return NULL;
   }

   // Init connection object
#ifndef B110917
   this->boc_fix = TRUE;                    /* do not free memory      */
#endif
   this->bo_data = FALSE;
   this->bo_accept = TRUE;
   this->ds_sock = ds_sock;
   this->ads_callback = ads_callback;
   this->ads_usrfld = ads_usrfld;
   this->im_error = 0;
   this->ds_event = CreateEvent(NULL, TRUE, FALSE, NULL);
   if(this->ds_event == NULL)
   {
#ifdef TRACE
      printf("Unable to create event for new connection object\n");
#endif
      return -1;
   }
   if(WSAEventSelect(ds_sock,
                     this->ds_event,
                     FD_ACCEPT))
   {
#ifdef TRACE
      printf("Unable to set socket for non-blocking operation: %d\n", WSAGetLastError());
#endif
      CloseHandle(this->ds_event);
      return -1;
   }
   // now find a thread to handle this connection
   EnterCriticalSection(&ds_critsect);
   ads_thrlast = ads_thrcur = ads_thranc;
   while(ads_thrcur)
   {
      if(ads_thrcur->im_concount < NBACC_MAXCONN)
      {
         break;
      }
      ads_thrlast = ads_thrcur;
      ads_thrcur = ads_thrcur->ads_next;
   }
   if(!ads_thrcur)    // no more space in threads, create new one
   {
      LeaveCriticalSection(&ds_critsect);
      ads_thrcur = mc_createnewthread();
      if(!ads_thrcur)
      {
#ifdef TRACE
         printf("Unable to start a thread for this connection\n");
#endif
         CloseHandle(this->ds_event);
         return -1;
      }
      EnterCriticalSection(&ds_critsect);
      if(!ads_thranc)
      {
        ads_thranc = ads_thrcur;
      }
      else
      {
         ads_thrlast = ads_thranc;
         while(ads_thrlast)
         {
            if(!ads_thrlast->ads_next)
            {
               ads_thrlast->ads_next  = ads_thrcur;
               break;
            }
            ads_thrlast = ads_thrlast->ads_next;
         }
      }
   }
   this->ads_thread = ads_thrcur;
   ads_thrcur->dsr_tcpconn[ads_thrcur->im_concount] = this;
   ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1] =
                                                     this->ds_event;
   ads_thrcur->im_concount++;
   LeaveCriticalSection(&ds_critsect);
   if(!SetEvent(ads_thrcur->dsr_waitevent[0])) // Tell thread to handle this connection
   {
      if(ads_callback->am_errorcallback != NULL)
      {
         this->im_error = GetLastError();
         ads_callback->am_errorcallback(this,
                                        ads_usrfld,
                                        "Unable to set event for new connection",
                                        this->im_error,
                                        NBACC_ERRORAT_STARTACC);
      }
#ifdef TRACE
      printf("Unable to set event for new connection.\n");
#endif
   }
   return 0;
} // dsd_nblock_acc* dsd_nblock_acc::mc_startlisten_fix(dsd_tcphandle, dsd_tcpcallback_p, void*)

#ifdef B110917
void dsd_nblock_acc::mc_stoplistener(BOOL bo_close, BOOL bo_thread)
{
   dsd_stopped_p ads_stop;       // new Element for stopped list
   dsd_stopped_p ads_stopnext;   // pointer to find place for new element

#ifdef TRACE
   printf("mc_stoplistener\n");
#endif
   bo_accept = false;
   if(bo_thread)
   {
      EnterCriticalSection(&ds_critsect);
      ads_stop = new dsd_stopped_t;
      ads_stop->ads_next = NULL;
      ads_stop->ads_stopped = this;
      ads_stop->bo_close = bo_close;

      ads_stopnext = ads_thread->ads_stopchain;
      if(ads_stopnext == NULL)
      {
         ads_thread->ads_stopchain = ads_stop;
      }
      else
      {
         while(ads_stopnext->ads_next != NULL)
         {
            ads_stopnext = ads_stopnext->ads_next;
         }
         ads_stopnext->ads_next = ads_stop;
      }
      LeaveCriticalSection(&ds_critsect);
      if(!SetEvent(ads_thread->dsr_waitevent[0])) // Tell thread to handle this connection
      {
         if(ads_callback->am_errorcallback != NULL)
         {
            im_error = GetLastError();
            ads_callback->am_errorcallback(this,
                                           ads_usrfld,
                                           "Unable to set event for stopped connection",
                                           im_error,
                                           NBACC_ERRORAT_STOPACC);
         }
#ifdef TRACE
         printf("Unable to set event for stopped connection.\n");
#endif
      }
   }
   else if(bo_close)
   {
      closesocket(ds_sock);
   }
} // void dsd_nblock_acc::mc_stoplistener(BOOL bo_close, BOOL bo_thread)
#endif
#ifndef B110917
void dsd_nblock_acc::mc_stoplistener( BOOL bop_close, BOOL bop_thread ) {
   int        iml1;                         /* working variable        */

   iml1 = 0;                                /* clear index             */
   EnterCriticalSection(&ds_critsect);
   while (iml1 < this->ads_thread->im_concount) {  /* loop over all classes */
     if (this == this->ads_thread->dsr_tcpconn[ iml1 ]) {  /* element found */
       this->ads_thread->dsr_tcpconn[ iml1 ] = NULL;  /* clear pointer to element */
       break;
     }
     iml1++;                                /* increment index         */
   }
   LeaveCriticalSection(&ds_critsect);
   if (bop_close) {
// to-do 17.09.11 KB check return-code
      closesocket(ds_sock);
   }
   if (this->boc_fix == FALSE) {            /* do not free memory      */
     delete this;
   }
} /* end dsd_nblock_acc::mc_stoplistener()                             */
#endif

int dsd_nblock_acc::mc_stoplistener_fix( void ) {
#ifdef B110917
// to-do 08.08.11 KB
#else
   int        iml1;                         /* working variable        */

   iml1 = 0;                                /* clear index             */
   EnterCriticalSection(&ds_critsect);
   while (iml1 < this->ads_thread->im_concount) {  /* loop over all classes */
     if (this == this->ads_thread->dsr_tcpconn[ iml1 ]) {  /* element found */
       this->ads_thread->dsr_tcpconn[ iml1 ] = NULL;  /* clear pointer to element */
       break;
     }
     iml1++;                                /* increment index         */
   }
   LeaveCriticalSection(&ds_critsect);
// to-do 17.09.11 KB check return-code
   closesocket( ds_sock );
#endif
   return 0;
}

int dsd_nblock_acc::mc_resume()
{
   EnterCriticalSection(&ads_thread->ds_thrcritsect);
#ifdef TRACE
   printf("mc_accept: bo_data: %d, ds_event %d\n", bo_data, ds_event);
#endif
   bo_accept = TRUE;
   LeaveCriticalSection(&ads_thread->ds_thrcritsect);
#ifdef TRACE
      printf("Set Event\n");
#endif
      if(!SetEvent(ds_event))
      {
         if(ads_callback->am_errorcallback != NULL)
         {
            im_error = GetLastError();
            ads_callback->am_errorcallback(this,
                                           ads_usrfld,
                                           "Unable to set event for accept",
                                           im_error,
                                           NBACC_ERRORAT_ACCEPT);
         }
#ifdef TRACE
         printf("Unable to set event for accept.\n");
#endif
      }
   return TRUE;
} // int dsd_nblock_acc::mc_resume();

int dsd_nblock_acc::mc_accept_sock()
{
#ifdef TRACE
   printf("mc_accept\n");
#endif
    int im_error;
    SOCKET dsl_sockret;
   struct sockaddr_storage dsl_soa_accept;
   int        iml_len_soa;
    //do
    //{
   memset( &dsl_soa_accept, 0, sizeof(struct sockaddr_storage) );
   iml_len_soa = sizeof(struct sockaddr_storage);
    if (INVALID_SOCKET == (dsl_sockret = accept( ds_sock, (sockaddr *) &dsl_soa_accept, &iml_len_soa )))
    {
         im_error = WSAGetLastError();
#ifdef TRACE
         printf("Accept failed: %d.\n", im_error );
#endif
         if(im_error != WSAEWOULDBLOCK &&
         im_error != WSAENOTCONN)
         {
            if(ads_callback->am_errorcallback != NULL)
            {
               this->im_error = im_error;
               ads_callback->am_errorcallback(this,
                                              ads_usrfld,
                                              "Accept failed",
                                              im_error,
                                              NBACC_ERRORAT_ACCEPT);
            }
            return -1;
         }
        return 1;
    }
#ifdef TRACE
    else
        printf("Accept OK. Sock: %d\n", dsl_sockret);
#endif
//  EnterCriticalSection(&ads_thread->ds_thrcritsect);
    ads_callback->am_acceptcallback( this, ads_usrfld, dsl_sockret, (sockaddr *) &dsl_soa_accept, iml_len_soa );
//  LeaveCriticalSection(&ads_thread->ds_thrcritsect);
    //} while (bo_accept);
    return 0;
} // SOCKET dsd_nblock_acc::mc_accept_sock()

dsd_nblock_acc::dsd_tcpthread_p dsd_nblock_acc::mc_createnewthread()
{
   dsd_tcpthread_p ads_newthread;

   ads_newthread = new dsd_tcpthread_t;
   if(!ads_newthread)
   {
#ifdef TRACE
      printf("Unable to allocate memory for new TCP/IP thread structure\n");
#endif
      return 0;
   }
   ads_newthread->dsr_waitevent[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
   if(ads_newthread->dsr_waitevent[0] == NULL)
   {
#ifdef TRACE
      printf("Unable to create event for new TCP/IP thread\n");
#endif
      delete ads_newthread;
      return 0;
   }
   ads_newthread->ds_threadhandle = _beginthread(mc_accthread,
                                                 0,
                                                 (void*)ads_newthread);
   if(ads_newthread->ds_threadhandle < 0)
   {
#ifdef TRACE
      printf("Unable to start new TCP/IP thread: %d\n", errno);
#endif
      CloseHandle(ads_newthread->dsr_waitevent[0]);
      delete ads_newthread;
      return 0;
   }
#ifdef TRACE
      printf("New thread started.\n");
#endif
   return ads_newthread;
} // dsd_tcpthread_p dsd_nblock_acc::mc_createnewthread()

void dsd_nblock_acc::mc_accthread(void* ads_parm)
{
   DWORD um_waitret;    // return code from wait
   dsd_tcpthread_p ads_thread; // thread structure
   int im_error;        // error codes
   WSANETWORKEVENTS ds_nwevents; // network event structure
   int im_index;        // loop index
   int im_conn;         // index of connection notified
#ifdef B110917
   dsd_stopped_p ads_stop; // pointer to a stopped connection
#endif
#ifndef B110917
   BOOL       bol1;                         /* working variable        */
   class dsd_nblock_acc *adsl_nblock_acc_w1;  /* working variable */
#endif

   ads_thread = (dsd_tcpthread_p)ads_parm;
#ifdef TRACE
   printf("TCP/IP thread started\n");
#endif
   do
   {
#ifdef TRACE
      printf("Wait for %d events\n", ads_thread->im_concount + 1);
#endif
      um_waitret = WSAWaitForMultipleEvents(
                      ads_thread->im_concount + 1,
                      ads_thread->dsr_waitevent,
                      FALSE,
                      INFINITE,
                      FALSE);
      if(ads_thread->bo_cleanup)
      {
         printf("WSAWaitForMultipleEvents failed\n");
         break;
      }
      if(um_waitret == WSA_WAIT_FAILED)
      {
         Sleep(500);
         continue;
      }
      if(um_waitret == WSA_WAIT_EVENT_0)
      {
#ifdef TRACE
         printf("Reset event 0 \n");
#endif
         if(!ResetEvent(ads_thread->dsr_waitevent[0]))
         {
            printf("Reset event failed\n");
         }
#ifdef B110917
         EnterCriticalSection(&ds_critsect);
         ads_stop = ads_thread->ads_stopchain;
         while(ads_stop != NULL)
         {
#ifdef TRACE
            printf("Stopped listeners found\n");
#endif
            for(im_index = 0; im_index < ads_thread->im_concount; im_index++)
            {
               if(ads_thread->dsr_tcpconn[im_index] == ads_stop->ads_stopped)
               {
#ifdef TRACE
                  printf("Close Event handle\n");
#endif
                  if(ads_stop->bo_close)
                  {
                     closesocket(ads_thread->dsr_tcpconn[im_index]->ds_sock);
                  }
                  ads_thread->dsr_tcpconn[im_index]->bo_data = FALSE;
                  CloseHandle(ads_thread->dsr_waitevent[im_index+1]);
                  ads_thread->im_concount--;
                  if(im_index < ads_thread->im_concount)
                  {
#ifdef TRACE
                     printf("Remove emtpy event\n");
#endif
                     memmove(&ads_thread->dsr_tcpconn[im_index],
                             &ads_thread->dsr_tcpconn[im_index + 1],
                             (ads_thread->im_concount - im_index) *
                             sizeof(class dsd_nblock_acc*));
                     memmove(&ads_thread->dsr_waitevent[im_index + 1],
                             &ads_thread->dsr_waitevent[im_index + 2],
                             (ads_thread->im_concount - im_index) *
                              sizeof(dsd_eventtype));
                  }
                  break;
               }
            }
            ads_thread->ads_stopchain = ads_stop->ads_next;
#ifdef TRACE
            printf("Delete stop entries\n");
#endif
            delete ads_stop->ads_stopped;
            delete ads_stop;
            ads_stop = ads_thread->ads_stopchain;
         }
         LeaveCriticalSection(&ds_critsect);
#endif
      }
      else
      {
#ifdef TRACE
         printf("Event posted was: %d\n", um_waitret - WSA_WAIT_EVENT_0);
#endif
#ifndef B110918
#define IML_NO_EVENT (um_waitret - WSA_WAIT_EVENT_0 - 1)
         if (   (IML_NO_EVENT >= 0)
             && (IML_NO_EVENT < ads_thread->im_concount)) {
           adsl_nblock_acc_w1 = ads_thread->dsr_tcpconn[ IML_NO_EVENT ];
           if (adsl_nblock_acc_w1 == NULL) {  /* the entry has been deleted */
             bol1 = CloseHandle( ads_thread->dsr_waitevent[ IML_NO_EVENT + 1 ] );
// to-do 18.09.11 KB check return code
             EnterCriticalSection(&ds_critsect);
             ads_thread->im_concount--;
#define IML_OLD_EVENTS (ads_thread->im_concount - IML_NO_EVENT)
             if (IML_OLD_EVENTS > 0) {
               memmove( &ads_thread->dsr_waitevent[ IML_NO_EVENT + 1 ],
                        &ads_thread->dsr_waitevent[ IML_NO_EVENT + 1 + 1 ],
                        IML_OLD_EVENTS * sizeof(HANDLE) );
               memmove( &ads_thread->dsr_tcpconn[ IML_NO_EVENT ],
                        &ads_thread->dsr_tcpconn[ IML_NO_EVENT + 1 ],
                        IML_OLD_EVENTS * sizeof(void *) );
             }
#undef IML_OLD_EVENTS
             LeaveCriticalSection(&ds_critsect);
           }
         }
#undef IML_NO_EVENT
#endif
// to-do 18.09.11 KB use um_waitret to identify entry
         for(im_conn = 0; im_conn < ads_thread->im_concount; im_conn++)
         {
// to-do 18.09.11 KB the following statement is superflous
            im_index = WSAWaitForMultipleEvents(
                          1,
                          &ads_thread->dsr_waitevent[im_conn + 1],
                          TRUE,
                          0,
                          FALSE);
            if ((im_index != WSA_WAIT_FAILED) && (im_index != WSA_WAIT_TIMEOUT))
            {
#ifdef TRACE
               printf("Reset event: %d:%d; Index: %d\n", im_conn + 1, ads_thread->dsr_waitevent[im_conn + 1], im_index);
#endif
               im_error = WSAEnumNetworkEvents(
                     ads_thread->dsr_tcpconn[im_conn]->ds_sock,
                     ads_thread->dsr_waitevent[im_conn + 1],
                     &ds_nwevents);
               if(im_error)
               {
#ifdef TRACE
                  printf("WSAEnumNetworkEvents failed: %d.\n", WSAGetLastError());
#endif
                  if(ads_thread->dsr_tcpconn[im_conn]->
                         ads_callback->am_errorcallback
                        != NULL)
                  {
                     ads_thread->dsr_tcpconn[im_conn]->
                        ads_callback->am_errorcallback
                        (ads_thread->dsr_tcpconn[im_conn],
                         ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                         "WSAEnumNetworkEvents failed",
                         WSAGetLastError(),
                         NBACC_ERRORAT_ACCTHREAD);
                  }
              }
              else
              {
#ifdef TRACE
                  printf("WSAEnumNetworkEvents: %d.\n", ds_nwevents.lNetworkEvents);
#endif
                  if((ds_nwevents.lNetworkEvents & FD_ACCEPT) != 0) // Incomming Connection
                  {
                     im_error = ds_nwevents.iErrorCode[FD_ACCEPT_BIT];
#ifdef TRACE
                     printf("Accept comming. im_error = %d\n", im_error);
#endif
                     if(im_error)
                     {
                        if(ads_thread->dsr_tcpconn[im_conn]->
                           ads_callback->am_errorcallback
                           != NULL)
                        {
                           ads_thread->dsr_tcpconn[im_conn]->
                           ads_callback->am_errorcallback
                              (ads_thread->dsr_tcpconn[im_conn],
                               ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                               "Accept failed",
                               im_error,
                               NBACC_ERRORAT_ACCEPT);
                        }
                        if(ads_thread->dsr_tcpconn[im_conn]->im_error == 0)
                           ads_thread->dsr_tcpconn[im_conn]->im_error =
                              im_error;
                     }
                     else
                     {
                        if(!ads_thread->dsr_tcpconn[im_conn]->bo_accept)
                        {
                           ads_thread->dsr_tcpconn[im_conn]->bo_data = TRUE;
#ifdef TRACE
                           printf("bo_data = true.\n");
#endif
                        }
                        else
                        {
                           ads_thread->dsr_tcpconn[im_conn]->mc_accept_sock();
                        }
                     }
                  }
                  else if(ads_thread->dsr_tcpconn[im_conn]->bo_accept &&
                          ads_thread->dsr_tcpconn[im_conn]->bo_data)
                  {
                          ads_thread->dsr_tcpconn[im_conn]->mc_accept_sock();
                  }
               }
            }
            else if(im_index == WSA_WAIT_FAILED) // Wait failed
            {
               if(ads_thread->dsr_tcpconn[im_conn]->
                      ads_callback->am_errorcallback
                     != NULL)
               {
                  ads_thread->dsr_tcpconn[im_conn]->
                     ads_callback->am_errorcallback
                     (ads_thread->dsr_tcpconn[im_conn],
                      ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                      "WSAWaitForMultipleEvents failed",
                      WSAGetLastError(),
                      NBACC_ERRORAT_ACCTHREAD);
               }
            }
         }
      }
   }while(TRUE);
#ifdef TRACE
   printf("ACCthread ended. clean up.\n");
#endif
// clean up
   for(im_index = 0; im_index < ads_thread->im_concount; im_index++)
   {
#ifdef B110917
      if(ads_thread->dsr_tcpconn[im_index] != NULL)
      {
         ads_thread->dsr_tcpconn[im_index]->mc_stoplistener(FALSE, FALSE);
         delete ads_thread->dsr_tcpconn[im_index];
      }
      CloseHandle(ads_thread->dsr_waitevent[im_index + 1]);
#endif
#ifndef B110917
      adsl_nblock_acc_w1 = ads_thread->dsr_tcpconn[im_index];
      if (adsl_nblock_acc_w1 != NULL) {
        adsl_nblock_acc_w1->mc_stoplistener( TRUE, FALSE );
      }
#endif
   }
   CloseHandle(ads_thread->dsr_waitevent[0]);
   delete ads_thread;
} // void dsd_nblock_acc::mc_accthread(void*)

#else // LINUX/UNIX
#ifdef B110807
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stropts.h>
#include <poll.h>
#include <unistd.h>

#include <fcntl.h>

#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string.h>

//#define TRACE
#ifndef __ccdoc__
#ifndef BOOL
   #define BOOL int
#endif
#ifndef TRUE
   #define TRUE 1
#endif
#ifndef FALSE
   #define FALSE 0
#endif
#ifndef NULL
   #define NULL 0
#endif
#ifndef INFTIM
   #define INFTIM -1
#endif
#endif
#endif


// Defines
/** Maximum number of connections one thread can handle. */
#define NBACC_MAXCONN 63
/** Error location flag: startacc. */
#define NBACC_ERRORAT_STARTACC 1
/** Error location flag: stopacc. */
#define NBACC_ERRORAT_STOPACC 2
/** Error location flag: accthread. */
#define NBACC_ERRORAT_ACCTHREAD 3
/** Error location flag: close socket. */
#define NBACC_ERRORAT_CLOSE 4
/** Error location flag: accept */
#define NBACC_ERRORAT_ACCEPT 5
/** Error location flag: accept socket */
#define NBACC_ERRORAT_ACCEPT_SOCK 6

// Error numbers:
/** Error: No error. */
#define NBACC_ERROR_NONE 0
/** Error: startup called twice. */
#define NBACC_ERROR_ALREADYRUNNING (-1000)
/** Error: Unable to create thread. */
#define NBACC_ERROR_NOTHREAD (-1001)
/** Error: Illegal parameter (=null) */
#define NBACC_ERROR_NULLPARAM (-1002)
/** Error: No more addresses to connect to. */
#define NBACC_ERROR_NOADDRESS (-1003)
// End of defines

// Classes and structures

class dsd_nblock_acc;     // forward declaration

/**
 * This structure contains the set of callback routines used to inform
 * the calling programm about network events ( and errors).
 */
typedef struct dsd_acccallback
{
   //int (*am_acceptcallback)(dsd_nblock_acc*, void*, int); // Accept callback function.
   void (*am_acceptcallback)( dsd_nblock_acc *, void *, int, struct sockaddr *, int );  // Accept callback function.
   void (*am_errorcallback)(dsd_nblock_acc*, void*, char*, int, int); // Error callback function.
} dsd_acccallback_t;
/** Pointer to a callback structure. */
typedef dsd_acccallback_t* dsd_acccallback_p;
/** Thread handle type. */
typedef pthread_t dsd_threadhandle;
/**
 * This class implements an interface for performing nonblocking accept
 * operations on multiple connections. Each instance maps to one
 * listener.
 */
class dsd_nblock_acc
{
   BOOL       boc_fix;                      /* do not free memory      */
// type definitions
   /** Type for TCP connection handle. */
   typedef int dsd_tcphandle;
   /** Type for event handle. */
   typedef struct pollfd* dsd_eventtype;

#ifdef B110917
/**
 * Structure for list of stopped connections.
 * The wait thread looks through this list and deletes all connection
 * listed here.
 */
typedef struct dsd_stopped
{
   struct dsd_stopped* ads_next;   // Next element in chain.
   class dsd_nblock_acc* ads_stopped; // Stopped connection.
   BOOL bo_close;                  // Socket has to be closed by wait thread.
} dsd_stopped_t;
public:
/** Pointer to a stopped connection structure. */
typedef dsd_stopped_t* dsd_stopped_p;
#endif
private:
/**
 * This structure defines an element of a TCP/IP wait thread.chain.
 */
typedef struct dsd_tcpthread
{
   struct dsd_tcpthread* ads_next;   // Next element in chain.
   dsd_threadhandle ds_threadhandle; // The thread handle.
   class dsd_nblock_acc* dsr_tcpconn[NBACC_MAXCONN+1]; // Array of connections handled by thread
   struct pollfd dsr_waitevent[NBACC_MAXCONN+1];  // Array of events handled by thread.
#ifndef B110918
   int im_concount;                  // Number of active connections.
#else
   volatile int im_concount;         // Number of active connections.
#endif
#ifdef B110917
   dsd_stopped_p ads_stopchain;      // Anchor for chain of stopped connections.
#endif
   BOOL bo_cleanup;                  // If this is set, the thread  cleans up and stops executing.
   int imr_pipefd[2];                                // descriptor for eventpipe
   pthread_mutex_t ds_thrcritsect;
   dsd_tcpthread()  {
       ads_next = NULL;
       ds_threadhandle = (dsd_threadhandle)NULL;
       memset(&dsr_tcpconn, 0, sizeof(dsr_tcpconn));
       memset(&dsr_waitevent, 0, sizeof(dsr_waitevent));
       im_concount = 0;
#ifdef B110917
       ads_stopchain = 0;
#endif
       bo_cleanup = FALSE;
       pthread_mutex_init(&ds_thrcritsect, NULL);
   };
   ~dsd_tcpthread() { pthread_mutex_destroy(&ds_thrcritsect); };
} dsd_tcpthread_t;
/** Pointer to a wait thread structure. */
typedef dsd_tcpthread_t* dsd_tcpthread_p;



// static members
/** Anchor for tcp threads. */
   static dsd_tcpthread_p ads_thranc;
/** Critical section for safe access to ressources. */
   static pthread_mutex_t ds_critsect;
/**
 * Create a new TCP work thread.
 * @return address of the thread structure for the newly created thread.
 */
   static inline dsd_tcpthread_p mc_createnewthread();
/**
 * TCP/IP wait thread.
 * @param ads_parm pointer to corresponding thread structure.
 */
   static inline void* mc_accthread(void*);

public:
/**
 * Initiate dsd_nblock_acc.
 * @return TRUE if successful, otherwise FALSE.
 */
   static inline int mc_startup();
/**
 * Cleanup everything.
 * @return TRUE if successful, otherwise FALSE.
 */
   static inline int mc_shutdown();
/**
 * Create a new listener instance.
 * @param ds_sock socket used.
 * @param ads_callback structure containing the necessary callback functions.
 * @param ads_usrfld pointer to user data.
 * @return pointer to the newly created dsd_nblock_acc object, NULL if an error occurred.
 */
   static inline dsd_nblock_acc* mc_startlisten(dsd_tcphandle ds_sock,
                                          dsd_acccallback_p ads_callback,
                                          void* ads_usrfld);
   inline int mc_startlisten_fix(dsd_tcphandle ds_sock,
                                 dsd_acccallback_p ads_callback,
                                 void* ads_usrfld);
// instance members
/** Last error code (OS dependent). */
   int im_error;
/**
 * Stop processing this connection.
 * @param bo_close close the underlying socket.
 * @param bo_thread delete connection from thread.
 * @return TRUE if successful, otherwise FALSE.
 */
   inline void mc_stoplistener(BOOL bo_close,
                   BOOL bo_thread = TRUE);
   inline int  mc_stoplistener_fix( void );
/**
 * Called, when ACCEPTOR should start accepting again.
 * @return TRUE if successful, otherwise FALSE.
 */
   inline int mc_resume();                           // start accepting again

   /* give socket to the outside                                       */
   inline int mc_get_socket( void ) {
     return this->ds_sock;
   }

private:
/**
 * Non-blocking accept
 * @param dsp_addr optional out pointer to a buffer that receives the address of the connecting entity
 * @param aimp_addrlen optional in/out pointer to an integer that contains the length of dsp_addr
 * @return returns a value of type SOCKET that is a descriptor for the new socket or INVALID_SOCKET if error occurs
 */
   inline int mc_accept_sock();
/** Structure with callback methods. */
   dsd_acccallback_p ads_callback;
/** Socket to work with. */
   dsd_tcphandle ds_sock;
/** User specific data. */
   void* ads_usrfld;
/** Corresponding thread object. */
   dsd_tcpthread_p ads_thread;
/** Event used with this connection. */
   dsd_eventtype ds_event;
/** Receive allowed. */
   BOOL bo_accept;
/** Receive data available. */
   BOOL bo_data;
};// class dsd_nonblock_acc
// End of classes and structures

int dsd_nblock_acc::mc_startup()
{
#ifdef TRACE
   printf("mc_startup\n");
#endif
   if(ads_thranc != NULL)
   {
      return NBACC_ERROR_ALREADYRUNNING;
   }
   ads_thranc = mc_createnewthread();
   if(ads_thranc == NULL)
   {
      return NBACC_ERROR_NOTHREAD;
   }
   pthread_mutex_init(&ds_critsect, NULL);
   return NBACC_ERROR_NONE;
} // int class dsd_nblock_acc::mc_startup()

int dsd_nblock_acc::mc_shutdown()
{
   dsd_tcpthread_p ads_thrcur;            // current thread object
   dsd_tcpthread_p ads_thrnext;           // next thread object

#ifdef TRACE
   printf("m_shutdown\n");
#endif
   pthread_mutex_lock(&ds_critsect);
   ads_thrcur = ads_thranc;
   ads_thranc = NULL;
   while(ads_thrcur)
   {
      ads_thrnext = ads_thrcur->ads_next;
      ads_thrcur->bo_cleanup = TRUE;
      write(ads_thrcur->imr_pipefd[1], &ads_thrcur, sizeof(ads_thrcur)); // Tell thread to cleanup.
      ads_thrcur = ads_thrnext;
   }
   pthread_mutex_unlock(&ds_critsect);
   pthread_mutex_destroy(&ds_critsect);
   return TRUE;
} // int class dsd_nblock_acc::mc_shutdown()

dsd_nblock_acc* dsd_nblock_acc::mc_startlisten(dsd_tcphandle ds_sock,
                                      dsd_acccallback_p ads_callback,
                                      void* ads_usrfld)
{
   dsd_nblock_acc* ads_newcon;               // new connection object
   dsd_tcpthread_p ads_thrcur;            // current thread object
   dsd_tcpthread_p ads_thrlast;           // last thread in chain
#ifdef TRACE
   printf("mc_startlisten\n");
#endif

   if(ds_sock == -1 ||
      !ads_callback ||
      !ads_usrfld ||
      !ads_callback->am_acceptcallback ||
      !ads_callback->am_errorcallback)
   {
#ifdef TRACE
      printf("Parameter is null\n");
#endif
      return NULL;
   }

   /*bool bo_listener;
   socklen_t im_optlen;
   bo_listener = false;
   im_optlen = sizeof(bool);
   if (getsockopt(ds_sock, SOL_SOCKET, SO_ACCEPTCONN, (char*)&bo_listener, &im_optlen) != 0)
   {
#ifdef TRACE
      printf("Error getsockopt()\n");
#endif
      return NULL;
   }
   if (bo_listener == false)
   {
#ifdef TRACE
      printf("Socket is not a listener socket\n");
#endif
      return NULL;
   }*/

   ads_newcon = new dsd_nblock_acc();
   if(!ads_newcon)
   {
#ifdef TRACE
      printf("Unable to allocate memory for new connection object\n");
#endif
      return NULL;
   }
   // Init connection object
#ifndef B110917
   ads_newcon->boc_fix = FALSE;             /* do not free memory      */
#endif
   ads_newcon->bo_data = FALSE;
   ads_newcon->bo_accept = TRUE;
   ads_newcon->ds_sock = ds_sock;
   ads_newcon->ads_callback = ads_callback;
   ads_newcon->ads_usrfld = ads_usrfld;
   ads_newcon->im_error = 0;

   if (fcntl(ds_sock, F_SETFL, O_NONBLOCK) != 0) //Set socket to non-blocking mode
   {
#ifdef TRACE
      printf("Unable to set socket for non-blocking operation: %d\n", errno);
#endif
      delete ads_newcon;
      return NULL;
   }
   // now find a thread to handle this connection
   pthread_mutex_lock(&ds_critsect);
   ads_thrlast = ads_thrcur = ads_thranc;
   while(ads_thrcur)
   {
      if(ads_thrcur->im_concount < NBACC_MAXCONN)
      {
         break;
      }
      ads_thrlast = ads_thrcur;
      ads_thrcur = ads_thrcur->ads_next;
   }
   if(!ads_thrcur)    // no more space in threads, create new one
   {
      pthread_mutex_unlock(&ds_critsect);
      ads_thrcur = mc_createnewthread();
      if(!ads_thrcur)
      {
#ifdef TRACE
         printf("Unable to start a thread for this connection\n");
#endif
         delete ads_newcon;
         return NULL;
      }
      pthread_mutex_lock(&ds_critsect);
      if(!ads_thranc)
      {
        ads_thranc = ads_thrcur;
      }
      else
      {
         ads_thrlast = ads_thranc;
         while(ads_thrlast)
         {
            if(!ads_thrlast->ads_next)
            {
               ads_thrlast->ads_next  = ads_thrcur;
               break;
            }
            ads_thrlast = ads_thrlast->ads_next;
         }
      }
   }
   ads_newcon->ads_thread = ads_thrcur;
   ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].fd =
                                                     ads_newcon->ds_sock;
   ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].events =
                                                     POLLIN;
   ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].revents = 0;
// to-do 18.09.11 KB the following statement is a bug or superflous
// since the elements in the array may be moved
   ads_newcon->ds_event = &ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1];
   ads_thrcur->dsr_tcpconn[ads_thrcur->im_concount + 1] = ads_newcon;
   ads_thrcur->im_concount++;
   pthread_mutex_unlock(&ds_critsect);
   write(ads_thrcur->imr_pipefd[1], &ads_thrcur, sizeof(ads_thrcur)); // Tell thread to handle this connection
#ifdef TRACE
   printf("pipe event fired in m_startconn()\n");
#endif
   return ads_newcon;
} // dsd_nblock_acc* dsd_nblock_acc::mc_startlisten(dsd_tcphandle, dsd_tcpcallback_p, void*)

int dsd_nblock_acc::mc_startlisten_fix( dsd_tcphandle ds_sock,
                                        dsd_acccallback_p ads_callback,
                                        void* ads_usrfld)
{
   dsd_tcpthread_p ads_thrcur;            // current thread object
   dsd_tcpthread_p ads_thrlast;           // last thread in chain
#ifdef TRACE
   printf("mc_startlisten\n");
#endif

   if(ds_sock == -1 ||
      !ads_callback ||
      !ads_usrfld ||
      !ads_callback->am_acceptcallback ||
      !ads_callback->am_errorcallback)
   {
#ifdef TRACE
      printf("Parameter is null\n");
#endif
      return -1;
   }

   /*bool bo_listener;
   socklen_t im_optlen;
   bo_listener = false;
   im_optlen = sizeof(bool);
   if (getsockopt(ds_sock, SOL_SOCKET, SO_ACCEPTCONN, (char*)&bo_listener, &im_optlen) != 0)
   {
#ifdef TRACE
      printf("Error getsockopt()\n");
#endif
      return NULL;
   }
   if (bo_listener == false)
   {
#ifdef TRACE
      printf("Socket is not a listener socket\n");
#endif
      return NULL;
   }*/

   // Init connection object
#ifndef B110917
   this->boc_fix = TRUE;                    /* do not free memory      */
#endif
   this->bo_data = FALSE;
   this->bo_accept = TRUE;
   this->ds_sock = ds_sock;
   this->ads_callback = ads_callback;
   this->ads_usrfld = ads_usrfld;
   this->im_error = 0;

   if (fcntl(ds_sock, F_SETFL, O_NONBLOCK) != 0) //Set socket to non-blocking mode
   {
#ifdef TRACE
      printf("Unable to set socket for non-blocking operation: %d\n", errno);
#endif
      return -1;
   }
   // now find a thread to handle this connection
   pthread_mutex_lock(&ds_critsect);
   ads_thrlast = ads_thrcur = ads_thranc;
   while(ads_thrcur)
   {
      if(ads_thrcur->im_concount < NBACC_MAXCONN)
      {
         break;
      }
      ads_thrlast = ads_thrcur;
      ads_thrcur = ads_thrcur->ads_next;
   }
   if(!ads_thrcur)    // no more space in threads, create new one
   {
      pthread_mutex_unlock(&ds_critsect);
      ads_thrcur = mc_createnewthread();
      if(!ads_thrcur)
      {
#ifdef TRACE
         printf("Unable to start a thread for this connection\n");
#endif
         return -1;
      }
      pthread_mutex_lock(&ds_critsect);
      if(!ads_thranc)
      {
        ads_thranc = ads_thrcur;
      }
      else
      {
         ads_thrlast = ads_thranc;
         while(ads_thrlast)
         {
            if(!ads_thrlast->ads_next)
            {
               ads_thrlast->ads_next  = ads_thrcur;
               break;
            }
            ads_thrlast = ads_thrlast->ads_next;
         }
      }
   }
   this->ads_thread = ads_thrcur;
   ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].fd =
                                                     this->ds_sock;
   ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].events =
                                                     POLLIN;
   ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].revents = 0;
   this->ds_event = &ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1];
#ifndef B120327
   ads_thrcur->dsr_tcpconn[ads_thrcur->im_concount + 1] = this;
#else
   ads_thrcur->dsr_tcpconn[ads_thrcur->im_concount] = this;
#endif
   ads_thrcur->im_concount++;
   pthread_mutex_unlock(&ds_critsect);
   write(ads_thrcur->imr_pipefd[1], &ads_thrcur, sizeof(ads_thrcur)); // Tell thread to handle this connection
#ifdef TRACE
   printf("pipe event fired in m_startconn()\n");
#endif
   return 0;
} // dsd_nblock_acc* dsd_nblock_acc::mc_startlisten_fix(dsd_tcphandle, dsd_tcpcallback_p, void*)

#ifdef B110917
void dsd_nblock_acc::mc_stoplistener(BOOL bo_close, BOOL bo_thread)
{
   dsd_stopped_p ads_stop;       // new Element for stopped list
   dsd_stopped_p ads_stopnext;   // pointer to find place for new element

#ifdef TRACE
   printf("mc_stoplistener\n");
#endif
   bo_accept = false;

   if(bo_thread)
   {
      pthread_mutex_lock(&ds_critsect);
      ads_stop = new dsd_stopped_t;
      ads_stop->ads_next = NULL;
      ads_stop->ads_stopped = this;
      ads_stop->bo_close = bo_close;

      ads_stopnext = ads_thread->ads_stopchain;
      if(ads_stopnext == NULL)
      {
         ads_thread->ads_stopchain = ads_stop;
      }
      else
      {
         while(ads_stopnext->ads_next != NULL)
         {
            ads_stopnext = ads_stopnext->ads_next;
         }
         ads_stopnext->ads_next = ads_stop;
      }
      pthread_mutex_unlock(&ds_critsect);
      write(ads_thread->imr_pipefd[1], &ads_thread, sizeof(ads_thread)); // Tell thread to handle this connection
   }
   else if(bo_close)
   {
#ifdef TRACE
   printf("Close socket: %d\n", bo_close);
#endif
      close(ds_sock);
   }
} // void dsd_nblock_acc::mc_stoplistener(BOOL bo_close, BOOL bo_thread)
#endif
#ifndef B110917
void dsd_nblock_acc::mc_stoplistener( BOOL bop_close, BOOL bop_thread ) {
   int        iml1;                         /* working variable        */

   iml1 = 0;                                /* clear index             */
   pthread_mutex_lock(&ds_critsect);
   while (iml1 < this->ads_thread->im_concount) {  /* loop over all classes */
     if (this == this->ads_thread->dsr_tcpconn[ iml1 ]) {  /* element found */
       this->ads_thread->dsr_tcpconn[ iml1 ] = NULL;  /* clear pointer to element */
       break;
     }
     iml1++;                                /* increment index         */
   }
   pthread_mutex_unlock(&ds_critsect);
   if (bop_close) {
// to-do 17.09.11 KB check return-code
      close(ds_sock);
   }
   if (this->boc_fix == FALSE) {            /* do not free memory      */
     delete this;
   }
} /* end dsd_nblock_acc::mc_stoplistener()                             */
#endif

int dsd_nblock_acc::mc_stoplistener_fix( void ) {
#ifdef B110917
// to-do 08.08.11 KB
#else
   int        iml1;                         /* working variable        */

   iml1 = 0;                                /* clear index             */
   pthread_mutex_lock(&ds_critsect);
   while (iml1 < this->ads_thread->im_concount + 1) {  /* loop over all classes */
     if (this == this->ads_thread->dsr_tcpconn[ iml1 ]) {  /* element found */
       this->ads_thread->dsr_tcpconn[ iml1 ] = NULL;  /* clear pointer to element */
       break;
     }
     iml1++;                                /* increment index         */
   }
   pthread_mutex_unlock(&ds_critsect);

   iml1 = close( ds_sock );
   if (    iml1 != 0
        && ads_callback
        && ads_callback->am_errorcallback != NULL ) {
      	im_error = errno;
	ads_callback->am_errorcallback(this,
					ads_usrfld,
					"Unable to close socket",
					im_error,
					NBACC_ERRORAT_CLOSE);
   }
//end AK

#endif
// inception 01.06.2012
   write(this->ads_thread->imr_pipefd[1], &(this->ads_thread), sizeof(this->ads_thread)); // Tell thread to handle this connection
// end inception 01.06.2012
   return 0;
}

int dsd_nblock_acc::mc_resume()
{
   pthread_mutex_lock(&ads_thread->ds_thrcritsect);
#ifdef TRACE
   printf("mc_accept: bo_data: %d, ds_event %d\n", bo_data, ds_event);
#endif
   bo_accept = TRUE;
   pthread_mutex_unlock(&ads_thread->ds_thrcritsect);
#ifdef TRACE
      printf("Set Event\n");
#endif
      if(write(ads_thread->imr_pipefd[1],
         &ads_thread, sizeof(ads_thread)) < 0)
      {
         if(ads_callback->am_errorcallback != NULL)
         {
            im_error = errno;
            ads_callback->am_errorcallback(this,
                                           ads_usrfld,
                                           "Unable to set event for accept",
                                           im_error,
                                           NBACC_ERRORAT_ACCEPT);
         }
#ifdef TRACE
         printf("Unable to set event for accept.\n");
#endif
      }
   return TRUE;
} // int dsd_nblock_acc::mc_resume();

int dsd_nblock_acc::mc_accept_sock()
{
#ifdef TRACE
   printf("mc_accept\n");
#endif
    int im_error;
    int dsl_sockret;
    struct sockaddr_storage dsl_soa_accept;
#ifdef HL_HPUX
   int        iml_len_soa;
#else
   socklen_t        iml_len_soa;
#endif
    //do
    //{
    memset( &dsl_soa_accept, 0, sizeof(struct sockaddr_storage) );
    iml_len_soa = sizeof(struct sockaddr_storage);
    if (-1 == (dsl_sockret = accept(ds_sock, (sockaddr *) &dsl_soa_accept, &iml_len_soa)))
    {
         im_error = errno;
#ifdef TRACE
         printf("Accept failed: %d.\n", im_error );
#endif
         if(im_error != EWOULDBLOCK &&
         im_error != ENOTCONN)
         {
            if(ads_callback->am_errorcallback != NULL)
            {
               this->im_error = im_error;
               ads_callback->am_errorcallback(this,
                                              ads_usrfld,
                                              "Accept failed",
                                              im_error,
                                              NBACC_ERRORAT_ACCEPT);
            }
            return -1;
         }
        return 1;
    }
#ifdef TRACE
    else
        printf("Accept OK. Sock: %d\n", dsl_sockret);
#endif
    /* pthread_mutex_lock(&ads_thread->ds_thrcritsect);
    bo_accept = ads_callback->am_acceptcallback(this,
                                           ads_usrfld,
                                           dsl_sockret);
    pthread_mutex_unlock(&ads_thread->ds_thrcritsect); */
    ads_callback->am_acceptcallback( this, ads_usrfld, dsl_sockret, (sockaddr *) &dsl_soa_accept, iml_len_soa );
    //} while (bo_accept);
    return 0;
} // SOCKET dsd_nblock_acc::mc_accept_sock()

dsd_nblock_acc::dsd_tcpthread_p dsd_nblock_acc::mc_createnewthread()
{
   dsd_tcpthread_p ads_newthread;

   ads_newthread = new dsd_tcpthread_t;
   if(!ads_newthread)
   {
#ifdef TRACE
      printf("Unable to allocate memory for new TCP/IP thread structure\n");
#endif
      return 0;
   }
      if(pipe(ads_newthread->imr_pipefd) < 0)
   {
#ifdef TRACE
      printf("Unable to create pipes for new TCP/IP thread\n");
#endif
      delete ads_newthread;
      return 0;
   }
   ads_newthread->dsr_waitevent[0].fd = ads_newthread->imr_pipefd[0];
   ads_newthread->dsr_waitevent[0].events = POLLIN;
   ads_newthread->dsr_waitevent[0].revents = 0;
   if(pthread_create(&(ads_newthread->ds_threadhandle),
                     NULL,
                     mc_accthread,
                     (void*)ads_newthread))
   {
      printf("Unable to start new TCP/IP thread.\n");
      close(ads_newthread->imr_pipefd[0]);
      close(ads_newthread->imr_pipefd[1]);
      delete ads_newthread;
      return 0;
   }
#ifdef TRACE
      printf("New thread started.\n");
#endif
   return ads_newthread;
} // dsd_tcpthread_p dsd_nblock_acc::mc_createnewthread()

void* dsd_nblock_acc::mc_accthread(void* ads_parm)
{
   int im_waitret;    // return code from wait
   dsd_tcpthread_p ads_thread; // thread structure
   int im_index;        // loop index
   int im_conn;         // index of connection notified
#ifdef B110917
   dsd_stopped_p ads_stop; // pointer to a stopped connection
#endif
   dsd_tcpthread_p ads_dummy;  // buffer to clear notification pipe
   //struct t_call ds_tcall;  // get address from connect here
#ifndef B110917
   class dsd_nblock_acc *adsl_nblock_acc_w1;  /* working variable */
#endif

   ads_thread = (dsd_tcpthread_p)ads_parm;
#ifdef TRACE
   printf("TCP/IP thread started\n");
#endif
   do
   {
#ifdef TRACE
      printf("Wait for %d events\n", ads_thread->im_concount + 1);
#endif
      im_waitret = poll(ads_thread->dsr_waitevent,
                        ads_thread->im_concount + 1,
                        INFTIM);
      if(ads_thread->bo_cleanup)
      {
         printf("Cleanup requested\n");
         break;
      }
#ifdef TRACE
      printf("poll returned with %d\n", im_waitret);
#endif
      if(im_waitret <= 0)
      {
         printf("Poll error %d or nothing received? %d\n", errno, im_waitret);
         sleep(1);
         continue;
      }
      im_conn = 0;
      do
      {
         if(ads_thread->dsr_waitevent[im_conn].revents != 0)
         {
#ifdef TRACE
            printf("Event: %d: %d\n", im_conn, ads_thread->dsr_waitevent[im_conn].revents);
#endif
            im_waitret--;
#ifndef B110918
            if (im_conn > 0) {              /* real connection         */
#ifdef KB_ORG
              adsl_nblock_acc_w1 = ads_thread->dsr_tcpconn[ im_conn - 1 ];
#else //AK
              adsl_nblock_acc_w1 = ads_thread->dsr_tcpconn[ im_conn ];
#endif
              if (adsl_nblock_acc_w1 == NULL) {  /* connection deleted */
                 printf("remove connection %d\n", im_conn);
                 pthread_mutex_lock(&dsd_nblock_acc::ds_critsect);
#ifdef TJ_B170801
                 ads_thread->im_concount--;
#endif
#ifdef KB_ORG
#define IML_OLD_EVENTS (ads_thread->im_concount - (im_conn - 1))
                 if (IML_OLD_EVENTS > 0) {
                   memmove( &ads_thread->dsr_tcpconn[ im_conn - 1 ],
                            &ads_thread->dsr_tcpconn[ im_conn - 1 + 1],
                            IML_OLD_EVENTS *  sizeof(class dsd_tcpcomp *) );
                   memmove( &ads_thread->dsr_waitevent[ im_conn - 1 ],
                            &ads_thread->dsr_waitevent[ im_conn - 1 + 1],
                            IML_OLD_EVENTS * sizeof(struct pollfd) );
                 }
#undef IML_OLD_EVENTS
#else //AK
#define IML_OLD_EVENTS (ads_thread->im_concount - (im_conn))
                 if (IML_OLD_EVENTS > 0) {
                   memmove( &ads_thread->dsr_tcpconn[ im_conn ],
                            &ads_thread->dsr_tcpconn[ im_conn + 1],
                            IML_OLD_EVENTS *  sizeof(class dsd_tcpcomp *) );
                   memmove( &ads_thread->dsr_waitevent[ im_conn ],
                            &ads_thread->dsr_waitevent[ im_conn + 1],
                            IML_OLD_EVENTS * sizeof(struct pollfd) );
                 }
#undef IML_OLD_EVENTS
#endif
#ifndef TJ_B170801
                 ads_thread->im_concount--;
#endif
                 pthread_mutex_unlock(&dsd_nblock_acc::ds_critsect);
              }
            }
#endif
#ifdef TRACE_POLLEVENTS
            if ( ads_thread->dsr_waitevent[im_conn].revents == (POLLHUP) ) {
		printf( "POLLHUP received on connection %d\n", im_conn );
            }
            if ( ads_thread->dsr_waitevent[im_conn].revents == (POLLNVAL) ) {
		printf( "POLLNVAL received on connection %d\n", im_conn );
            }
            if ( ads_thread->dsr_waitevent[0].revents == POLLIN ) {
                printf( "data received on pipe\n" );
                /*read( ads_thread->dsr_waitevent[0].fd,
                      &ads_dummy, sizeof(ads_dummy) );
		*/
            }
#endif
// end TRACE POLLEVENTS
            if((ads_thread->dsr_waitevent[im_conn].revents &
               (POLLIN | POLLERR)) != 0)
            {
               if(im_conn == 0) // control event fired
               {
                  read(ads_thread->dsr_waitevent[0].fd,
                       &ads_dummy, sizeof(ads_dummy));
#ifdef TRACE
                  printf("event read from pipe in m_tcpthread()\n");
#endif

#ifdef B110917
                  pthread_mutex_lock(&dsd_nblock_acc::ds_critsect);
                  ads_stop = ads_thread->ads_stopchain;
                  while(ads_stop != NULL)
                  {
#ifdef TRACE
                     printf("Stopped connections found\n");
#endif
                     for(im_index = 1; im_index <= ads_thread->im_concount; im_index++)
                     {
                        if(ads_thread->dsr_tcpconn[im_index] == ads_stop->ads_stopped)
                        {
#ifdef TRACE
                           printf("Close Event handle\n");
#endif
                           if(ads_stop->bo_close)
                           {
                              close(ads_thread->dsr_tcpconn[im_index]->ds_sock);
                           }
                           if(ads_thread->dsr_waitevent[im_index].revents != 0)
                           {
                              im_waitret--;
                           }
                           ads_thread->dsr_tcpconn[im_index]->bo_data = FALSE;
                           if(im_index < ads_thread->im_concount)
                           {
#ifdef TRACE
                              printf("Remove emtpy event\n");
#endif
                              memmove(&ads_thread->dsr_tcpconn[im_index],
                                      &ads_thread->dsr_tcpconn[im_index + 1],
                                      (ads_thread->im_concount - im_index) *
                                       sizeof(class dsd_tcpcomp*));
                              memmove(&ads_thread->dsr_waitevent[im_index],
                                      &ads_thread->dsr_waitevent[im_index + 1],
                                      (ads_thread->im_concount - im_index) *
                                       sizeof(struct pollfd));
                           }
                           ads_thread->im_concount--;
                           break;
                        }
                     }
                     ads_thread->ads_stopchain = ads_stop->ads_next;
#ifdef TRACE
                     printf("Delete stop entries\n");
#endif
                     delete ads_stop->ads_stopped;
                     delete ads_stop;
                     ads_stop = ads_thread->ads_stopchain;
                  }
                  pthread_mutex_unlock(&dsd_nblock_acc::ds_critsect);
#endif
// Now look for connections which need to be handled and set events right
                  for(im_index = 1;
                      im_index <= ads_thread->im_concount;
                      im_index++)
                  {
                     ads_thread->dsr_waitevent[im_index].events = 0;
//inception 01.06.2012
		     if ( ads_thread->dsr_tcpconn[im_index] == NULL ) {
                       printf("remove2 connection %d\n", im_index);
                       pthread_mutex_lock(&dsd_nblock_acc::ds_critsect);
#ifdef B131010
#define IML_OLD_EVENTS (ads_thread->im_concount - (im_conn))
#else
#define IML_OLD_EVENTS (ads_thread->im_concount - im_index)
#endif
                       if (IML_OLD_EVENTS > 0) {
                         memmove( &ads_thread->dsr_tcpconn[ im_index ],
                                  &ads_thread->dsr_tcpconn[ im_index + 1],
                                 IML_OLD_EVENTS *  sizeof(class dsd_tcpcomp *) );
                         memmove( &ads_thread->dsr_waitevent[ im_index ],
                                  &ads_thread->dsr_waitevent[ im_index + 1],
                                  IML_OLD_EVENTS * sizeof(struct pollfd) );
                       }
#undef IML_OLD_EVENTS
                       ads_thread->im_concount--;
                       pthread_mutex_unlock(&dsd_nblock_acc::ds_critsect);

                     } else { // end 01.06.2012
                        if(ads_thread->dsr_tcpconn[im_index]->bo_accept &&
                          ads_thread->dsr_tcpconn[im_index]->bo_data)
                       {
                          ads_thread->dsr_tcpconn[im_index]->mc_accept_sock();
                       }
                       if(!(ads_thread->dsr_tcpconn[im_index]->bo_data))
                       {
                          ads_thread->dsr_waitevent[im_index].events |= POLLIN;
                       }
                     }
                  }
               }
               else             // receive data, means not the control event
               {
               	  if(ads_thread->dsr_tcpconn[im_conn]->bo_accept)
                  {
                     ads_thread->dsr_tcpconn[im_conn]->mc_accept_sock();
                  }
                  else
                  {
                     ads_thread->dsr_tcpconn[im_conn]->bo_data = TRUE;
                  }
               }
            }
            if(im_conn > 0)
            {
               ads_thread->dsr_waitevent[im_conn].revents = 0;
               ads_thread->dsr_waitevent[im_conn].events = 0;
               if(   (ads_thread->dsr_tcpconn[im_conn] ) //(valgrind problem)
                  && (ads_thread->dsr_tcpconn[im_conn]->bo_data == FALSE) )
               {
                  ads_thread->dsr_waitevent[im_conn].events |= POLLIN;
               }
            }
         }
         im_conn++;
      }while(im_waitret > 0 && im_conn <= ads_thread->im_concount);
   }while(TRUE);
#ifdef TRACE
   printf("TCPthread ended. clean up.\n");
#endif
// clean up
#ifdef B110917
   for(im_index = 0; im_index < ads_thread->im_concount; im_index++)
   {
      if(ads_thread->dsr_tcpconn[im_index] != NULL)
      {
         ads_thread->dsr_tcpconn[im_index]->mc_stoplistener(FALSE, FALSE);
         delete ads_thread->dsr_tcpconn[im_index];
      }
   }
#endif
#ifdef B131010
#ifndef B110917
   for(im_index = 0; im_index < ads_thread->im_concount; im_index++)
   {
      adsl_nblock_acc_w1 = ads_thread->dsr_tcpconn[im_index];
      if (adsl_nblock_acc_w1 != NULL) {
        adsl_nblock_acc_w1->mc_stoplistener( TRUE, FALSE );
      }
   }
#endif
#endif
#ifndef B131010
   for(im_index = 1; im_index <= ads_thread->im_concount; im_index++)
   {
      adsl_nblock_acc_w1 = ads_thread->dsr_tcpconn[im_index];
      if (adsl_nblock_acc_w1 != NULL) {
        adsl_nblock_acc_w1->mc_stoplistener( TRUE, FALSE );
      }
   }
#endif
   close(ads_thread->imr_pipefd[0]);
   close(ads_thread->imr_pipefd[1]);
   delete ads_thread;
   return NULL;
	
} // void dsd_nblock_acc::mc_accthread(void*)

#endif

#endif //__HOB_NON_BLOCKING_ACCEPTOR
