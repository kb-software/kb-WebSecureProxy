// temporary start 19.04.12 KB
/*
  changes needed 20.11.12 KB
  1. callback-routine amc_free_target_ineta has been removed
  2. am_conncallback has two more parameters
  3. m_startco_mh() has one more parameter
  4. use new error numbers of connect callback routine,
     result of multiple connect()
*/
#define TCPCOMP_ERR_BASE              70000
#define TCPCOMP_ERR_CANCELLED         (TCPCOMP_ERR_BASE + 0)
//#define TCPCOMP_ERR_CONN_REFUSED      (TCPCOMP_ERR_BASE + 1)
//#define TCPCOMP_ERR_CONN_TIMEOUT      (TCPCOMP_ERR_BASE + 2)
#define TCPCOMP_ERR_CONN_ALL_REFUSED  (TCPCOMP_ERR_BASE + 3)
#define TCPCOMP_ERR_CONN_ALL_TIMEOUT  (TCPCOMP_ERR_BASE + 4)
#define TCPCOMP_ERR_CONN_ALL_RF_TO    (TCPCOMP_ERR_BASE + 5)
/**
 * AKre
 * DEBUG_POLL_TIME is a switcher for
 * 1) debugging the time in a POLL loop
 * 2) getting all callback routines in a POLL
 *   a) how much callbacks were called
 *   b) which callback was called
 *
 * currently only for windows implemented
 */
//#define DEBUG_POLL_TIME
//#define DEBUG_TCPCOMP_300614 //for debugging linux problem with hanging sessions in m_end_session

#define DEBUG_TCPCOMP_120314_10
// temporary end   19.04.12 KB
#ifdef DEBUG_TCPCOMP_120314_01
#define DEBUG_TCPCOMP_120314_02
//#define DEBUG_TCPCOMP_120314_03
//#define DEBUG_TCPCOMP_120314_04
#define DEBUG_TCPCOMP_120314_05
#define DEBUG_TCPCOMP_120314_06
#define DEBUG_TCPCOMP_120314_07
#define DEBUG_TCPCOMP_120314_08
#define DEBUG_TCPCOMP_120314_09
#define DEBUG_TCPCOMP_120314_10
#endif

/*
 * AKre 23.07.2012: switcher for a deferred release of
 * a connection after 2 minutes
 * if defined then we will delete a connection not until 2 mins
 * otherwise we will delete the conncection directly
 *
 * NOTE: this switcher is regulating both the windows and unix part
 * because it´s before '#if defined(WIN32) || defined(WIN64) ...'
 */

//#define DEF_RELEASE
#ifdef DEF_RELEASE
#include <time.h>
#endif

#ifdef WIN32
#define HL_WIN
#endif

#ifdef WIN64
#define HL_WIN
#endif

#ifdef HL_UNIX
#ifdef TRACEHL1
#define TRACE                               /* 11.08.11 KB             */
#define TRACEHL_POLL_01                     /* 11.08.11 KB             */
#endif
//#define NEW_KB_110811                       /* problems with bo_connot */
//#define WAIT_RECV_KB_110813                 /* problems with bo_recv   */
#endif
#ifdef TO_DO
// 19.06.11 KB
// void dsd_tcpcomp::mc_set_nodelay() call error callback
// also all other setsockopt()
// 13.08.11 KB
// serious errors: m_hl1_printf(), goes to log if configured
// am_conncallback( ) with sockaddr
// 11.09.11 KB
// Unix Socket
// 15.09.11 KB
// Unix: dsl_sockaddr can be rebuild with m_set_connect_p1()
//       dsc_soa_connect not needed, vasts memory
#endif
#define TRACE_090801_01
//#define TRACE
#ifdef HL_WIN
#ifndef TCPCOMP
#ifndef __ccdoc__
#define TCPCOMP
#endif
/*****************************************************************************/
/* Project: TCPCOMP                                                          */
/* Source: itcpco1.hpp                                                       */
/* Description: header containing TCPCOMP definition                         */
/*                                                                           */
/* Copyright 2005 HOB GmbH & Co. KG                                          */
/*                                                                           */
/* Created by: THO                                                           */
/* Creation Date: 26.01.2005                                                 */
/*                                                                           */
/* Operating system(architecture): Win32(X86)                                */
/*                                                                           */
/* Compile with: Visual Studio .Net C++                                      */
/*                                                                           */
/* Additional requirements:                                                  */
/* following header files must be included in main file    in the order below*/
/* winsock2.h, Ws2tcpip.h, windows.h, stdio.h, process.h, hob-netw-01.h      */
/* hob-tcpco1.hpp, hltabaw2.h                                                */
/*                                                                           */
/*                                                                           */
/* Changed by:                                                               */
/*                                                                           */
/* 1. AG 13.07.2006 dsd_tcpcomp::m_recv()                                    */
/*    bo_data state is ignored, it means that ds_event is being allways set  */
/* 2. AG 13.07.2006 class dsd_tcpthread                                      */
/*    critical section ds_thrcritsect is added for every dsd_tcpthread object*/
/*    this cr.sect. should be used for among the data whithin a thread       */
/*    not among the data in all threads;                                     */
/*    constructor and destructor are added to struct dsd_tcpthread;          */
/*    memset of dsd_tcpthread after successfuly init is comment out;         */
/*    the synchronisation of dsd_tcpcomp::bo_recv is changed to be used with */
/*    dsd_tcpthread::ds_thrcritsect                                          */
/*****************************************************************************/
/**
 * @pkg tcpcomp
 */
/**
 * Non blocking TCP/IP for Win32.
 * @version 2005/01/26.
 * @author THO
 * @pkgdoc tcpcomp
 */

//define TRACE
#ifndef BOOL
#ifndef __ccdoc__
#define BOOL int
#endif
#endif


/**
 * gather structure definition for dsd_tcpcomp::m_send_gather()
 */
#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 { /* gather input data       */
    struct dsd_gather_i_1 *adsc_next; /* next in chain           */
    char * achc_ginp_cur; /* current position        */
    char * achc_ginp_end; /* end of input data       */
};
#endif

#ifdef DEF_TC_OWN_NS
namespace ns_tcpcomp_mh {
#endif

#ifndef DEF_SEND_WSASEND
#define DEF_SEND_WSASEND 32 // default size for array of WSABUF structures for WSASend()
#endif
// Defines
    /** Maximum number of connections one thread can handle. */
#define TCPCOMP_MAXCONN (WSA_MAXIMUM_WAIT_EVENTS-1)
    /** Error location flag: stopconn. */
#define ERRORAT_STOPCONN 1
    /** Error location flag: connect. */
#define ERRORAT_CONNECT 2
    /** Error location flag: recv. */
#define ERRORAT_RECV 3
    /** Error location flag: send. */
#define ERRORAT_SEND 4
    /** Error location flag: tcpthread. */
#define ERRORAT_TCPTHREAD 5
    /** Error location flag: close socket. */
#ifndef ERRORAT_CLOSE
#define ERRORAT_CLOSE 6
#endif
    /** Error location flag: startconn. */
#define ERRORAT_STARTCONN 7
#define ERRORAT_SETEVENT  8
#define ERRORAT_SO        9

// Error numbers:
    /** Error: No error. */
#define TCPCOMP_ERROR_NONE 0
    /** Error: startup called twice. */
#define TCPCOMP_ERROR_ALREADYRUNNING (-1000)
    /** Error: Unable to create thread. */
#define TCPCOMP_ERROR_NOTHREAD (-1001)
    /** Error: Illegal parameter (=null) */
#define TCPCOMP_ERROR_NULLPARAM (-1002)
    /** Error: No more addresses to connect to. */
#define TCPCOMP_ERROR_NOADDRESS (-1003)
// End of defines

// Classes and structures
    /** Type for TCP connection handle. */
    typedef SOCKET dsd_tcphandle;
    /** Thread handle type. */
    typedef uintptr_t dsd_threadhandle;
    /** Type for event handle. */
    typedef HANDLE dsd_eventtype;

    extern "C" int m_hl1_printf( char *aptext, ... );
    extern "C" int m_hlnew_printf( int, char *, ... );

    class dsd_tcpcomp; // forward declaration

    /**
     * This structure contains the set of callback routines used to inform
     * the calling programm about network events ( and errors).
     */
    typedef struct dsd_tcpcallback {
        void (*am_connerrcallback)(dsd_tcpcomp *, void *, struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_current_index, int imp_total_index, int imp_errno ); /* connect failed function */
        void (*am_conncallback)( dsd_tcpcomp *, void *, struct dsd_target_ineta_1 *adsp_server_ineta, void * ap_free_ti1, struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_error ); /* connect callback function */
        void (*am_sendcallback)( dsd_tcpcomp *, void * ); /* send callback function */
        int (*am_getrecvbuf)( dsd_tcpcomp *, void *, void **, char **, int ** ); /* get receive buffer callback function */
        int (*am_recvcallback)( dsd_tcpcomp *, void *, void * ); /* receive callback function */
        void (*am_errorcallback)( dsd_tcpcomp *, void *, char *, int, int ); /* error callback function */
        void (*amc_cleanup)( dsd_tcpcomp *, void * ); /* cleanup callback function */
        int (*amc_get_random_number)( int ); /* get random number       */
#ifdef B121120
        void (*amc_free_target_ineta)( dsd_tcpcomp *, void *, const struct dsd_target_ineta_1 * ); /* free target INETA */
#endif
    }dsd_tcpcallback_t;
    /** Pointer to a callback structure. */
    typedef dsd_tcpcallback_t* dsd_tcpcallback_p;

// 23.07.2007 AG begin
#ifdef DEF_M_STOPCONN_CB
    /**
     * Helper class implementation needed for the current thread identification
     * m_stopconn() can call a given callback function
     * it can happen the calling user waits for the callback on the same thread
     */
    typedef class dsd_thr_ident
    {
    private:
#if defined(WIN32) || defined(WIN64)
        typedef DWORD type_thr_id_t;
#else
        typedef pthread_t type_thr_id_t; // isn't tested jet
#endif
        type_thr_id_t ds_thr_id;
        inline type_thr_id_t m_get_thr_id()
        {
#if defined(WIN32) || defined(WIN64)
            return GetCurrentThreadId();
#else // pthread library: UNIX/LINUX
            return pthread_self(); // isn't tested jet
#endif //defined(WIN32) || defined(WIN64)
        }
    public:
        inline void m_init() { // called at the entry point of the new thread
            ds_thr_id = m_get_thr_id();
        }
        inline bool m_isthesame() {
            if (ds_thr_id == m_get_thr_id())
            return true;
            return false;
        }
    }dsd_thr_ident_t;
#endif // DEF_M_STOPCONN_CB
// 23.07.2007 AG end

    /**
     * Structure for list of stopped connections.
     * The wait thread looks through this list and deletes all connection
     * listed here.
     */
    typedef struct dsd_stopped
    {
        struct dsd_stopped* ads_next; // Next element in chain.
        class dsd_tcpcomp* ads_stopped;// Stopped connection.
        BOOL bo_close;// Socket has to be closed by wait thread.
#ifdef DEF_M_STOPCONN_CB
        void (*am_closeconncallback)(void*); // Connection close callback function
        void* avo_usrfld;// user field, the callback will be called with it as parameter
#endif
    }dsd_stopped_t;
    /** Pointer to a stopped connection structure. */
    typedef dsd_stopped_t* dsd_stopped_p;

#ifdef DEF_RELEASE
    /**
     * Structure for a list with sessions which have to be
     * deferred deleted.
     * The wait thread looks through this list and
     * deletes session after 2 minutes.
     * Due to KB we should not delete the session directly
     *
     * The corresponding switcher is #ifdef DEF_RELEASE
     *
     */
     typedef struct dsd_def_release {
        struct dsd_def_release* adsc_next;      /* Next element in chain */
        class dsd_tcpcomp*      adsc_cur_ses;   /* sored session which has to be deleted*/
        int                     in_timestamp;   /* time in seconds */
    }dsd_def_release_t;
    /* Pointer to a released session*/
     typedef dsd_def_release_t* dsd_def_release_p;
#endif

    typedef void (*md_at_thr_start)(int); // TCPCOMP Start thread callback function declaration


    /**
     * This structure defines an element of a TCP/IP wait thread.chain.
     */
    typedef struct dsd_tcpthread
    {
        struct dsd_tcpthread* ads_next; // Next element in chain.
        dsd_threadhandle ds_threadhandle;// The thread handle.
        class dsd_tcpcomp* dsr_tcpconn[TCPCOMP_MAXCONN];// Array of connections handled by thread
        dsd_eventtype dsr_waitevent[TCPCOMP_MAXCONN+1];// Array of events handled by thread.
        int im_concount;// Number of active connections.
        dsd_stopped_p ads_stopchain;// Anchor for chain of stopped connections.
        BOOL bo_cleanup;// If this is set, the thread  cleans up and stops executing.
        // AG 13.07.2006 begin
        CRITICAL_SECTION ds_thrcritsect;
        static md_at_thr_start amc_at_thread_start;// start thread callback function address,
                                                   // called at new tcpcomp thread start
                                                   // if was set at m_startup()
#ifdef DEBUG_POLL_TIME
#define MAX_CB_CALLED 20
        //static int  ins_active_threads =0 ;                 /* number of active threads*/
        int  in_cb_called;                      /* number of callback methods in array     */
        void *av_last_callbacks[MAX_CB_CALLED]; /* array of the last used callback methods */
#endif
#ifdef DEF_RELEASE
       dsd_def_release_p ads_def_rel;  /* Anchor for chain of connections to be deleted */
#endif

        dsd_tcpthread() {
            ads_next = NULL;
            ds_threadhandle = NULL;
            memset(&dsr_tcpconn, 0, sizeof(dsr_tcpconn));
            memset(&dsr_waitevent, 0, sizeof(dsr_waitevent));
            im_concount = 0;
            ads_stopchain = 0;
            bo_cleanup = FALSE;
#ifdef DEF_RELEASE
            ads_def_rel = 0;
#endif
            InitializeCriticalSection(&ds_thrcritsect);
        };
        ~dsd_tcpthread() {DeleteCriticalSection(&ds_thrcritsect);};
        // AG 13.07.2006 end
// 23.07.2007 AG begin
#ifdef DEF_M_STOPCONN_CB
        dsd_thr_ident_t ds_thr_ident;
#endif
// 23.07.2007 AG end
    }dsd_tcpthread_t;
    /** Pointer to a wait thread structure. */
    typedef dsd_tcpthread_t* dsd_tcpthread_p;

    /**
     * This class implements an interface for performing nonblocking TCP/IP
     * operations on multiple connections. Each instance maps to one
     * TCP/IP connection.
     */
    class dsd_tcpcomp
    {
// static members
        /** Anchor for tcp threads. */
        static dsd_tcpthread_p ads_thranc;
        /** Critical section for safe access to ressources. */
        static CRITICAL_SECTION ds_critsect;
        /**
         * Create a new TCP work thread.
         * @return address of the thread structure for the newly created thread.
         */
        static inline dsd_tcpthread_p m_createnewthread();
        /**
         * TCP/IP wait thread.
         * @param ads_parm pointer to corresponding thread structure.
         */
        static inline void m_tcpthread(void*);

    public:
        /**
         * Initiate dsd_tcpcomp.
         * @param amp_at_thread_start optional parameter - callback address of function which is called after a new thread was created
         * @return TRUE if successful, otherwise FALSE.
         */
        static inline int m_startup(md_at_thr_start amp_at_thread_start = NULL);
        /**
         * Cleanup everything.
         * @return TRUE if successful, otherwise FALSE.
         */
        static inline int m_shutdown();
        /**
         * Create a new conection.
         * @param ds_sock socket used.
         * @param ads_callback structure containing the necessary callback functions.
         * @param ads_usrfld pointer to user data.
         * @return pointer to the newly created tcpcomp object, NULL if an error occurred.
         */
        static inline dsd_tcpcomp* m_startconn(dsd_tcphandle ds_sock,
                dsd_tcpcallback_p ads_callback,
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
        inline void m_stopconn(BOOL bo_close,
                BOOL bo_thread = TRUE
#ifdef DEF_M_STOPCONN_CB
                ,
                void (*am_closeconncallback)(void*) = NULL, // Connection close callback function
                void* avo_usrfld = NULL// user field, the callback will be called with it as parameter
#endif
        );
        inline int m_startco_fb( int, dsd_tcpcallback_p, void * );
        inline int m_startco_bind_conn_fix( dsd_tcpcallback_p, void *, struct sockaddr *, int, struct sockaddr *, int );
        inline void m_end_session( void );

        /**
         * Non-blocking connect.
         * @param str_ip ipadress to connect.
         * @param str_port ip port to conect.
         * @return TRUE if successful, otherwise FALSE.
         */
        inline int m_connect(char* str_ip = NULL,
                char* str_port = NULL);
        /**
         * Called, when TCPCOMP should start receiving again.
         * @return TRUE if successful, otherwise FALSE.
         */
        inline int m_recv(); // start receiving again
        /**
         * Non-blocking send.
         * @param ach_data address of data to send.
         * @param im_len length of data to send.
         * @return number of bytes send, if < im_len => blocked, -1 = error,
         */
        inline int m_send(char *ach_data, int im_len);

        /**
         * Non-blocking WSASend
         * @param ads_gatherinp pointer to the input gather chain
         * @param aads_gatherout pointer to the pointer gather - output parameter
         * @param aimp_rc 0 ok, -1  error
         * if *aads_gatherout is equal NULL all of data was sent if not NULL
         * the first gather wich is incomplete sent
         * @return number of bytes send, if < im_len => blocked
         */
        inline int m_send_gather(dsd_gather_i_1 *ads_gatherinp, dsd_gather_i_1** aads_gatherout, int* aimp_rc = NULL);
        /**
         * Application wants to be notified when send is possible again.
         */
        inline void m_sendnotify();

        /**
         * Starting connection: bind if needed execute non blocking connect till any first was successfuly or all failed
         * @param adsp_callback
         * @param vpp_userfld
         * @param adsp_target_ineta
         * @param adsp_bind_ineta
         */
        inline int m_startco_mh( dsd_tcpcallback_p adsp_callback, void * vpp_userfld,
                const struct dsd_bind_ineta_1* adsp_bind_ineta,
                const struct dsd_target_ineta_1* adsp_target_ineta,
#ifndef B121120
                const void * ap_free_ti1,
#endif
                unsigned short usp_port,
                BOOL bop_round_robin = FALSE );

        /**
         * disable/enable the Naegle Algorithm
         */
        inline void dsd_tcpcomp::mc_set_nodelay(int imp_optval);
        /**
         * set size of the TCP send buffer
         */
        inline void dsd_tcpcomp::mc_set_sndbuf( int imp_sndbuf );
        /**
         * set Socket Option SO_KEEPALIVE
         */
        inline void dsd_tcpcomp::mc_set_keepalive ( int imp_optval );
        /**
         * set size of the TCP receive buffer
         */
        inline void dsd_tcpcomp::mc_set_rcvbuf( int imp_rcvbuf );
        /**
         * return the TCP socket
         */
#ifdef XYZ1
        inline int dsd_tcpcomp::mc_getsocket( void );
#endif
        inline int dsd_tcpcomp::mc_getsocket( void ) {
            return ds_sock;
        } /* end dsd_tcpcomp::mc_getsocket()                                */

    private:
        /**
         * Receive data.
         */
        inline BOOL m_recvdata();
#ifndef B120324
        inline void dsd_tcpcomp::mc_int_close( void );
#endif
        inline void dsd_tcpcomp::mc_remove_entry( int imp_conn );
#ifdef DEF_RELEASE
        inline void dsd_tcpcomp::mc_set_ref_conn ( int inl_conn );
        inline int  dsd_tcpcomp::mc_get_time     ( void );
#endif
        /** Structure with callback methods. */
        dsd_tcpcallback_p ads_callback;
        /** Socket to work with. */
        dsd_tcphandle ds_sock;
        /** User specific data. */
        void* ads_usrfld;
        const void* aps_free_ti1;
        /** Corresponding thread object. */
        dsd_tcpthread_p ads_thread;
        /** Event used with this connection. */
        dsd_eventtype ds_event;
#ifdef B120316
        /** Notify that send is possible. */
        BOOL bo_sendnot;
        /** Data could be send. */
        BOOL bo_sendok;
#else
        /** Notify that send is possible. */
        volatile BOOL bo_sendnot;
        /** Data could be send. */
        volatile BOOL bo_sendok;
#endif
        /** Receive allowed. */
        BOOL bo_recv;
        /** Receive data available. */
        BOOL bo_data;
        /** FD_CLOSE network event occured. */
        BOOL bo_fd_close; // AG 14.04.2008
        BOOL boc_storage; /* storage has been acquired */
        BOOL boc_end; /* end has been set        */
#ifdef DEBUG_TCPCOMP_120314_02
        int   imc_debug_01;
#endif
#ifdef DEBUG_TCPCOMP_120314_03
        int   imrc_trace_01[ 8 ];
#endif
#ifdef DEBUG_TCPCOMP_120314_05
        int   imc_trace_01;
#endif
#ifdef DEBUG_TCPCOMP_120314_06
        int   imc_trace_02_a;
        int   imc_trace_02_b;
#endif
#ifdef DEBUG_TCPCOMP_120314_07
        BOOL  boc_trace_sendok;
#endif
#ifdef DEBUG_TCPCOMP_120314_08
        BOOL  boc_trace_sendnot;
#endif
#ifdef DEBUG_TCPCOMP_120314_09
        BOOL  boc_dummy;
        void * aboc_1_sendok;
        void * aboc_1_sendnot;
        void * aboc_2_sendok;
        void * aboc_2_sendnot;
#endif
        /** Output from getaddressinfo. */
        struct addrinfo* ads_findsock;
        /** Current addressinfo used for running connect attempt. */
        struct addrinfo* ads_findcur;

        /** Current dsd_target_ineta_1 used for running connect attempt. */
        const dsd_target_ineta_1* ads_target_ineta;
        /** Current dsd_bind_ineta_1 used for bind before running connect attempt. */
        const dsd_bind_ineta_1* ads_bind_ineta;
        /** Port nummer for connect*/
        unsigned short us_port;
        /** Current ineta number */
        int im_ineta_curno;
        /** */
        BOOL bo_mhconnect; // multihomed connect mode
#ifndef B110924
        sockaddr_storage dsc_soa_connect;
#endif
        /**
         * Non-blocking connect.
         * @return TRUE if successful, otherwise FALSE.
         */
        inline int m_connect_mh(sockaddr_storage* adsp_sockaddr, socklen_t dsp_len);

        inline SOCKET ms_socket(unsigned short usp_family, const dsd_bind_ineta_1* adsp_bind_ineta);
    }; // class dsd_tcpcomp
// End of classes and structures

    int dsd_tcpcomp::m_startup(md_at_thr_start amp_at_thread_start)
    {
#ifdef TRACE
        printf("m_startup\n");
#endif
        if(ads_thranc != NULL)
        {
            return TCPCOMP_ERROR_ALREADYRUNNING;
        }
        InitializeCriticalSection(&ds_critsect);
        ads_thranc = m_createnewthread();
        if(ads_thranc == NULL)
        {
            DeleteCriticalSection(&ds_critsect);
            return TCPCOMP_ERROR_NOTHREAD;
        }
        dsd_tcpthread_t::amc_at_thread_start = amp_at_thread_start;
        return TCPCOMP_ERROR_NONE;
    } // int class dsd_tcpcomp::m_startup()

    int dsd_tcpcomp::m_shutdown()
    {
        dsd_tcpthread_p ads_thrcur; // current thread object
        dsd_tcpthread_p ads_thrnext;// next thread object
        dsd_threadhandle dsl_thrhandle;// local thread handle variable for waiting for terminated thread

#ifdef TRACE
        printf("m_shutdown\n");
#endif
        EnterCriticalSection(&ds_critsect);
        ads_thrcur = ads_thranc;
        ads_thranc = NULL;
        while(ads_thrcur)
        {
            ads_thrnext = ads_thrcur->ads_next;
            dsl_thrhandle = ads_thrcur->ds_threadhandle;
            ads_thrcur->bo_cleanup = TRUE;
            SetEvent(ads_thrcur->dsr_waitevent[0]); // Tell thread to cleanup.
            WaitForSingleObject((HANDLE)dsl_thrhandle, 5000);// wait max 5 sec for thread termination
            ads_thrcur = ads_thrnext;
        }
        LeaveCriticalSection(&ds_critsect);
        DeleteCriticalSection(&ds_critsect);
        return TRUE;
    } // int class dsd_tcpcomp::m_shutdown()

    dsd_tcpcomp* dsd_tcpcomp::m_startconn(dsd_tcphandle ds_sock,
            dsd_tcpcallback_p ads_callback,
            void* ads_usrfld)
    {
        dsd_tcpcomp* ads_newcon; // new connection object
        dsd_tcpthread_p ads_thrcur;// current thread object
        dsd_tcpthread_p ads_thrlast;// last thread in chain

#ifdef TRACE
        printf("m_startconn\n");
#endif
        if(ds_sock == INVALID_SOCKET ||
                !ads_callback ||
                !ads_usrfld ||
                !ads_callback->am_getrecvbuf ||
                !ads_callback->am_recvcallback )
        {
#ifdef TRACE
            printf("Parameter is null\n");
#endif
            return NULL;
        }

        ads_newcon = new dsd_tcpcomp();
        if(!ads_newcon)
        {
#ifdef TRACE
            printf("Unable to allocate memory for new connection object\n");
#endif
            return NULL;
        }
        // Init connection object
        ads_newcon->boc_storage = TRUE; /* storage has been acquired */
        ads_newcon->boc_end = FALSE; /* end has not been set    */
        ads_newcon->bo_sendnot = FALSE;
        ads_newcon->bo_data = FALSE;
        ads_newcon->bo_sendok = FALSE;
        ads_newcon->bo_recv = FALSE;
        ads_newcon->bo_fd_close = FALSE; // AG 14.04.2008
        ads_newcon->bo_mhconnect = FALSE; //AK 17.11.2011
        ads_newcon->ds_sock = ds_sock;
        ads_newcon->ads_callback = ads_callback;
        ads_newcon->ads_usrfld = ads_usrfld;
        ads_newcon->aps_free_ti1 = NULL;
        ads_newcon->im_error = 0;
        ads_newcon->ads_findsock = NULL;
        ads_newcon->ads_findcur = NULL;
#ifdef DEBUG_TCPCOMP_120314_02
        ads_newcon->imc_debug_01 = 0;
#endif
#ifdef DEBUG_TCPCOMP_120314_03
        memset( ads_newcon->imrc_trace_01, 0, sizeof(ads_newcon->imrc_trace_01) );
#endif
#ifdef DEBUG_TCPCOMP_120314_05
        ads_newcon->imc_trace_01 = 0;
#endif
// 25.03.12 KB - should be WSACreateEvent()
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
                        FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE))
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
            if(ads_thrcur->im_concount < TCPCOMP_MAXCONN)
            {
                break;
            }
            ads_thrlast = ads_thrcur;
            ads_thrcur = ads_thrcur->ads_next;
        }
        if(!ads_thrcur) // no more space in threads, create new one
        {
            LeaveCriticalSection(&ds_critsect);
            ads_thrcur = m_createnewthread();
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
                        ads_thrlast->ads_next = ads_thrcur;
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
                        ERRORAT_STARTCONN);
            }
#ifdef TRACE
            printf("Unable to set event for new connection.\n");
#endif
        }
        return ads_newcon;
    } // dsd_tcpcomp* dsd_tcpcomp::m_startconn(dsd_tcphandle, dsd_tcpcallback_p, void*)

    int dsd_tcpcomp::m_startco_fb( int imp_socket, dsd_tcpcallback_p adsp_callback, void * vpp_userfld ) {
        dsd_tcpthread_p ads_thrcur; // current thread object
        dsd_tcpthread_p ads_thrlast;// last thread in chain

#ifdef TRACEHL1
        m_hl1_printf( "hob-tcpco1-l%05d-T dsd_tcpcomp::m_startco_fb this=%p vpp_userfld=%p.",
                __LINE__, this, vpp_userfld);
#endif
#ifdef TRACE
        printf( "hob-tcpco1.hpp l%05d m_startco_fb this=%p\n", __LINE__, this );
#endif
        if (imp_socket == INVALID_SOCKET ||
                !adsp_callback ||
                !adsp_callback->am_getrecvbuf ||
                !adsp_callback->am_recvcallback) {
#ifdef TRACE
            printf("Parameter is null\n");
#endif
            return 1;
        }

        // Init connection object
        this->boc_storage = FALSE; /* storage has not been acquired */
        this->boc_end = FALSE; /* end has not been set    */
        this->bo_sendnot = FALSE;
        this->bo_data = FALSE;
        this->bo_sendok = FALSE;
        this->bo_recv = FALSE;
        this->bo_fd_close = FALSE; // AG 14.04.2008
        this->bo_mhconnect = FALSE; // AK 17.11.2011
        this->ds_sock = imp_socket;
        this->ads_callback = adsp_callback;
        this->ads_usrfld = vpp_userfld;
        this->aps_free_ti1 = NULL;
        this->im_error = 0;
        this->ads_findsock = NULL;
        this->ads_findcur = NULL;
#ifdef DEBUG_TCPCOMP_120314_02
        this->imc_debug_01 = 0;
#endif
#ifdef DEBUG_TCPCOMP_120314_03
        memset( this->imrc_trace_01, 0, sizeof(this->imrc_trace_01) );
#endif
#ifdef DEBUG_TCPCOMP_120314_05
        this->imc_trace_01 = 0;
#endif
        this->ads_target_ineta = NULL;
        this->ads_bind_ineta = NULL;
// 25.03.12 KB - should be WSACreateEvent()
        this->ds_event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if(this->ds_event == NULL)
        {
#ifdef TRACE
            printf("Unable to create event for new connection object\n");
#endif
            return 2;
        }
        if (WSAEventSelect( ds_sock,
                        this->ds_event,
                        FD_READ | FD_WRITE /*AK| FD_CONNECT*/ | FD_CLOSE ))
        {
#ifdef TRACE
            printf("Unable to set socket for non-blocking operation: %d\n", WSAGetLastError());
#endif
            CloseHandle(this->ds_event);
            return 3;
        }
        // now find a thread to handle this connection
        EnterCriticalSection(&ds_critsect);
        ads_thrlast = ads_thrcur = ads_thranc;
        while(ads_thrcur)
        {
            if(ads_thrcur->im_concount < TCPCOMP_MAXCONN)
            {
                break;
            }
            ads_thrlast = ads_thrcur;
            ads_thrcur = ads_thrcur->ads_next;
        }
        if(!ads_thrcur) // no more space in threads, create new one
        {
            LeaveCriticalSection(&ds_critsect);
            ads_thrcur = m_createnewthread();
            if(!ads_thrcur)
            {
#ifdef TRACE
                printf("Unable to start a thread for this connection\n");
#endif
                CloseHandle(this->ds_event);
                return 4;
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
                        ads_thrlast->ads_next = ads_thrcur;
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
#ifdef TRACE
        printf( "hob-tcpco1.hpp l%05d m_startco_fb() ads_thrcur=%p im_concount=%d\n",
                __LINE__, ads_thrcur, ads_thrcur->im_concount );
#endif
        if(!SetEvent(ads_thrcur->dsr_waitevent[0])) // Tell thread to handle this connection
        {
            if(ads_callback->am_errorcallback != NULL)
            {
                this->im_error = GetLastError();
                adsp_callback->am_errorcallback(this,
                        vpp_userfld,
                        "Unable to set event for new connection",
                        this->im_error,
                        ERRORAT_STARTCONN );
            }
#ifdef TRACE
            printf("Unable to set event for new connection.\n");
#endif
        }
        return 0;
    } /* end dsd_tcpcomp::m_startco_fb()                                   */

    int dsd_tcpcomp::m_startco_bind_conn_fix( dsd_tcpcallback_p adsp_callback, void * vpp_userfld,
            struct sockaddr *adsp_bind, socklen_t iml_len_bind,
            struct sockaddr *adsp_connect, socklen_t iml_len_connect ) {
        int iml_rc; /* return code             */
        dsd_tcpthread_p ads_thrcur; // current thread object
        dsd_tcpthread_p ads_thrlast;// last thread in chain

#ifdef TRACEHL1
        m_hl1_printf( "hob-tcpco1-l%05d-T dsd_tcpcomp::m_startco_bind_conn_fix this=%p vpp_userfld=%p.",
                __LINE__, this, vpp_userfld);
#endif
#ifdef TRACE
        printf( "hob-tcpco1.hpp l%05d m_startco_bind_conn_fix this=%p\n", __LINE__, this );
#endif
        if (!adsp_callback ||
                !adsp_callback->am_getrecvbuf ||
                !adsp_callback->am_recvcallback) {
#ifdef TRACE
            printf("Parameter is null\n");
#endif
            return 1;
        }

        // Init connection object
        this->boc_storage = FALSE; /* storage has not been acquired */
        this->boc_end = FALSE; /* end has not been set    */
        this->bo_sendnot = FALSE;
        this->bo_data = FALSE;
        this->bo_sendok = FALSE;
        this->bo_recv = FALSE;
        this->bo_fd_close = FALSE; // AG 14.04.2008
        this->bo_mhconnect = FALSE; //AK 18.11.2011
// this->ds_sock = imp_socket;
        this->ads_callback = adsp_callback;
        this->ads_usrfld = vpp_userfld;
        this->aps_free_ti1 = NULL;
        this->im_error = 0;
        this->ads_findsock = NULL;
        this->ads_findcur = NULL;
        this->ads_target_ineta = NULL;
        this->ads_bind_ineta = NULL;

        this->ds_sock = socket( adsp_connect->sa_family, SOCK_STREAM, IPPROTO_TCP );
        if (this->ds_sock < 0) {
        }

// 25.03.12 KB - should be WSACreateEvent()
        this->ds_event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if(this->ds_event == NULL)
        {
#ifdef TRACE
            printf("Unable to create event for new connection object\n");
#endif
            return 2;
        }
        if (WSAEventSelect( ds_sock,
                        this->ds_event,
                        FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE ))
        {
#ifdef TRACE
            printf("Unable to set socket for non-blocking operation: %d\n", WSAGetLastError());
#endif
            CloseHandle(this->ds_event);
            return 3;
        }
        // now find a thread to handle this connection
        EnterCriticalSection(&ds_critsect);
        ads_thrlast = ads_thrcur = ads_thranc;
        while(ads_thrcur)
        {
            if(ads_thrcur->im_concount < TCPCOMP_MAXCONN)
            {
                break;
            }
            ads_thrlast = ads_thrcur;
            ads_thrcur = ads_thrcur->ads_next;
        }
        if(!ads_thrcur) // no more space in threads, create new one
        {
            LeaveCriticalSection(&ds_critsect);
            ads_thrcur = m_createnewthread();
            if(!ads_thrcur)
            {
#ifdef TRACE
                printf("Unable to start a thread for this connection\n");
#endif
                CloseHandle(this->ds_event);
                return 4;
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
                        ads_thrlast->ads_next = ads_thrcur;
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
#ifdef TRACE
        printf( "hob-tcpco1.hpp l%05d m_startco_fb() ads_thrcur=%p im_concount=%d\n",
                __LINE__, ads_thrcur, ads_thrcur->im_concount );
#endif
        if(!SetEvent(ads_thrcur->dsr_waitevent[0])) // Tell thread to handle this connection
        {
            if(ads_callback->am_errorcallback != NULL)
            {
                this->im_error = GetLastError();
                adsp_callback->am_errorcallback(this,
                        vpp_userfld,
                        "Unable to set event for new connection",
                        this->im_error,
                        ERRORAT_STARTCONN );
            }
#ifdef TRACE
            printf("Unable to set event for new connection.\n");
#endif
        }
        if (iml_len_bind > 0) {
            iml_rc = bind( this->ds_sock, adsp_bind, iml_len_bind );
// to-do 24.09.11 KB check return code
        }
        memcpy( &this->dsc_soa_connect, adsp_connect, iml_len_connect );
        iml_rc = connect( this->ds_sock, adsp_connect, iml_len_connect );
// to-do 24.09.11 KB check return code
        return 0;
    } /* end dsd_tcpcomp::m_startco_bind_conn_fix()                        */

    void dsd_tcpcomp::m_stopconn(BOOL bo_close, BOOL bo_thread
#ifdef DEF_M_STOPCONN_CB
            ,
            void (*am_closeconncallback)(void*), // Connection close callback function
            void* avo_usrfld// user field, the callback will be called with it as parameter
#endif
    )
    {
        dsd_stopped_p ads_stop; // new Element for stopped list
        dsd_stopped_p ads_stopnext;// pointer to find place for new element
#ifdef DEF_M_STOPCONN_CB
        bool bo_thesamethr;
        bo_thesamethr = false;
#endif
#ifdef TRACE
        printf("m_stopconn\n");
#endif
        bo_recv = false;
        bo_sendnot = false;
        if(ads_findsock)
        {
            freeaddrinfo(ads_findsock);
            ads_findsock = 0;
        }
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
#ifdef DEF_M_STOPCONN_CB
            bo_thesamethr = ads_thread->ds_thr_ident.m_isthesame();
            if (bo_thesamethr == false && am_closeconncallback) {
                ads_stop->am_closeconncallback = am_closeconncallback;
                ads_stop->avo_usrfld = avo_usrfld;
            } else {
                ads_stop->am_closeconncallback = NULL;
                ads_stop->avo_usrfld = NULL;
            }
#endif
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
                            ERRORAT_STOPCONN);
                }
#ifdef TRACE
                printf("Unable to set event for stopped connection.\n");
#endif
            }
#ifdef DEF_M_STOPCONN_CB
            if (am_closeconncallback && bo_thesamethr)
            am_closeconncallback(avo_usrfld);
#endif
        }
        else if(bo_close)
        {
            closesocket(ds_sock);
        }
    } // void dsd_tcpcomp::m_stopconn(BOOL bo_close, BOOL bo_thread)

    void dsd_tcpcomp::m_end_session( void ) {
        BOOL bol1; /* working-variable        */
        DWORD dwl_error; /* for error               */
        dsd_tcpcallback_p adsl_callback;

#ifdef TRACEHL1
        m_hl1_printf( "hob-tcpco1-l%05d-T dsd_tcpcomp::m_end_session this=%p.",
                __LINE__, this);
#endif
#ifdef TRACE
        printf( "l%05d dsd_tcpcomp::m_end_session\n", __LINE__ );
#endif
        adsl_callback = this->ads_callback;
        if (adsl_callback == NULL) return;
        boc_end = TRUE; /* end has been set        */
#ifndef B120324
        this->mc_int_close();               /* close the socket        */
#endif
// bol1 = WSASetEvent( ds_event );
        bol1 = SetEvent( ds_event );
        if (bol1 == FALSE) {
// to-do 24.03.12 KB - after SetEvent GetLastError is set, not WSAGetLastError
            dwl_error = WSAGetLastError();
#ifdef TRACE
            printf( "l%05d m_end_session WSASetEvent error %d\n", __LINE__, dwl_error );
#endif
            if (adsl_callback->am_errorcallback != NULL) {
                adsl_callback->am_errorcallback( this, this->ads_usrfld,
                        "Error SetEvent()",
                        dwl_error,
                        ERRORAT_SETEVENT );
            }
        }
    } /* end dsd_tcpcomp::m_end_session()                                  */

    int dsd_tcpcomp::m_connect( char* str_ip, char* str_port ) {
        int im_error; // error code
        struct addrinfo ds_sohint;// input for getaddressinfo

#ifdef TRACE
        printf( "l%05d m_connect\n", __LINE__ );
#endif
        if(ads_findsock != NULL) // check next address
        {
            ads_findcur = ads_findcur->ai_next;
            if(ads_findcur == NULL)
            {
                freeaddrinfo(ads_findsock);
                ads_findsock = NULL;
#ifdef TRACE
                printf("No more addresses\n");
#endif
                if(ads_callback->am_errorcallback != NULL)
                {
                    this->im_error = TCPCOMP_ERROR_NOADDRESS;
                    ads_callback->am_errorcallback(this,
                            ads_usrfld,
                            "No more addresses to connect",
                            TCPCOMP_ERROR_NOADDRESS,
                            ERRORAT_CONNECT);
                }
                return FALSE;
            }
        }
        else // find first address
        {
            memset((void*)&ds_sohint, 0, sizeof(struct addrinfo));
            ds_sohint.ai_family = PF_INET;
            ds_sohint.ai_socktype = SOCK_STREAM;
            ds_sohint.ai_protocol = IPPROTO_TCP;
            im_error = getaddrinfo(str_ip, str_port,&ds_sohint, &ads_findsock);
            if( im_error )
            {
#ifdef TRACE
                printf("getaddrinfo failed for %s: %d.\n\n", str_ip, im_error);
#endif
                if(ads_callback->am_errorcallback != NULL)
                {
                    this->im_error = im_error;
                    ads_callback->am_errorcallback(this,
                            ads_usrfld,
                            "getaddrinfo failed",
                            im_error,
                            ERRORAT_CONNECT);
                }
                return FALSE;
            }
            ads_findcur = ads_findsock;
        }
        im_error = connect(ds_sock,
                ads_findcur->ai_addr,
                (int)(ads_findcur->ai_addrlen));
        if( !im_error )
        {
#ifdef TRACE
            printf("Connect doesn't return with WSAEWOULDBLOCK. Strange\n");
#endif
        }
        else
        {
            im_error = WSAGetLastError();
            if( im_error != WSAEWOULDBLOCK )
            {
#ifdef TRACE
                printf("Connect failed: %d.\n\n", im_error );
#endif
                freeaddrinfo(ads_findsock);
                ads_findsock = NULL;
                if(ads_callback->am_errorcallback != NULL)
                {
                    this->im_error = im_error;
                    ads_callback->am_errorcallback(this,
                            ads_usrfld,
                            "Connect failed",
                            im_error,
                            ERRORAT_CONNECT);
                }
                return FALSE;
            }
        }
        return TRUE;
    } // int dsd_tcpcomp::m_connect(char* str_ip, char* str_port)

    int dsd_tcpcomp::m_recv()
    {
#ifndef B111206
        dsd_tcpcallback_p adsl_callback;
#endif
// EnterCriticalSection(&ads_thread->ds_thrcritsect); // AG 13.07.2006
#ifdef TRACE
        printf("l%05d m_recv: bo_data: %d, ds_event %d\n", __LINE__, bo_data, ds_event );
#endif
//   EnterCriticalSection(&ds_critsect);            // AG 13.07.2006
        bo_recv = TRUE;
//   LeaveCriticalSection(&ds_critsect);            // AG 13.07.2006
// LeaveCriticalSection(&ads_thread->ds_thrcritsect);  // AG 13.07.2006
//   if(bo_data)                         // AG 13.07.2006
//   {                                   // AG 13.07.2006
#ifdef TRACE
        printf( "l%05d Set Event\n", __LINE__ );
#endif
        if(!SetEvent(ds_event))
        {
#ifdef B111206
            if(ads_callback->am_errorcallback != NULL)
            {
                im_error = GetLastError();
                ads_callback->am_errorcallback(this,
                        ads_usrfld,
                        "Unable to set event for receive",
                        im_error,
                        ERRORAT_RECV);
            }
#else
            adsl_callback = this->ads_callback;
            if (   (adsl_callback)
                && (adsl_callback->am_errorcallback)) {
                im_error = GetLastError();
                adsl_callback->am_errorcallback(this,
                        ads_usrfld,
                        "Unable to set event for receive",
                        im_error,
                        ERRORAT_RECV);
            }
#endif
#ifdef TRACE
            printf( "l%05d Unable to set event for receive.\n", __LINE__ );
#endif
        }
//   }                                  // AG 13.07.2006
        return TRUE;
    } // int dsd_tcpcomp::m_recv();

    int dsd_tcpcomp::m_send(char *ach_data, int im_len)
    {
        int im_error; // error code
        int im_sendcnt;// number of bytes sent with one send
        int im_send;// total number of bytes
        dsd_tcpcallback_p adsl_callback;

#ifdef TRACE
        printf("m_send to %d: %d bytes. bo_data = %d\n", ds_sock, im_len, bo_data);
#endif
        im_send = 0; // nothing send yet
#ifndef B120316
        bo_sendok = FALSE;
#endif
        do
        {
#ifdef B120316
            bo_sendok = FALSE;
#endif
            im_sendcnt = send(ds_sock, ach_data, im_len - im_send, 0);
            if( im_sendcnt == SOCKET_ERROR )
            {
                im_error = WSAGetLastError();
#ifdef TRACE
                printf("Send failed: %d.\n", im_error );
#endif
                if(im_error != WSAEWOULDBLOCK &&
                        im_error != WSAENOTCONN)
                {
                    adsl_callback = ads_callback;
                    if(adsl_callback && adsl_callback->am_errorcallback != NULL)
                    {
                        this->im_error = im_error;
                        adsl_callback->am_errorcallback(this,
                                ads_usrfld,
                                "Send failed",
                                im_error,
                                ERRORAT_SEND);
                    }
                    im_send = -1;
                }
                break;
            }
#ifdef B120316
            bo_sendok = TRUE;
#endif
            im_send += im_sendcnt;
            ach_data += im_sendcnt;
        }while(im_send < im_len);
#ifdef TRACE
        printf("m_send OK. Len: %d\n", im_send);
#endif
        return im_send;
    } // int dsd_tcpcomp::m_send(char *ach_data, int im_len)

    int dsd_tcpcomp::m_send_gather(dsd_gather_i_1 *ads_gatherinp, dsd_gather_i_1** aads_gatherout, int* aimp_rc)
    {
        int im_error; // error code
        int im_sendcnt;// number of bytes sent with one send
        int im_send;// total number of bytes per WSASend()
        int im_len;// total number of bytes to send per WSASend()
        WSABUF dsrl_wsabuf[DEF_SEND_WSASEND];// buffer for WSASend()
        int iml_bufcnt;// buffer's counter for WSASend()
        DWORD dwl_sent;// number of bytes sent by WSASend()
        int iml_sent;// number of bytes counter
        int iml_senttotal;// total number of bytes sent per m_send_gather
        int iml_cur_ele;// current position index
        dsd_gather_i_1 *adsl_gatheriter;// working variable
        dsd_gather_i_1 *adsl_gathercnt;// working variable
        dsd_tcpcallback_p adsl_callback;

#ifdef DEBUG_TCPCOMP_120314_03
#define ADSL_CONN this
        EnterCriticalSection( &ds_critsect );
        memmove( ADSL_CONN->imrc_trace_01,
                 ADSL_CONN->imrc_trace_01 + 1,
                 sizeof(ADSL_CONN->imrc_trace_01) - sizeof(ADSL_CONN->imrc_trace_01[0]) );
        ADSL_CONN->imrc_trace_01[ sizeof(ADSL_CONN->imrc_trace_01) / sizeof(ADSL_CONN->imrc_trace_01[0]) - 1 ] = __LINE__;
        LeaveCriticalSection( &ds_critsect );
#undef ADSL_CONN
#endif
#ifdef DEBUG_TCPCOMP_120314_05
        this->imc_trace_01 = __LINE__;
#endif
        if (aimp_rc)// AG 07.10.2008
        *aimp_rc = 0;// AG 07.10.2008
        iml_senttotal = 0;
        adsl_gatheriter = ads_gatherinp;
        while (adsl_gatheriter)
        {
            adsl_gathercnt = adsl_gatheriter;
            iml_cur_ele = 0;
            im_len = 0;
            iml_bufcnt = 0;
            while (adsl_gatheriter && iml_bufcnt < DEF_SEND_WSASEND)
            {
                dsrl_wsabuf[iml_bufcnt].buf = adsl_gatheriter->achc_ginp_cur;
                im_len += dsrl_wsabuf[iml_bufcnt].len = adsl_gatheriter->achc_ginp_end - adsl_gatheriter->achc_ginp_cur;
                adsl_gatheriter = adsl_gatheriter->adsc_next;
                ++ iml_bufcnt;
            }
#ifdef TRACE
            printf("m_send_gather to %d: %d bytes. bo_data = %d\n", ds_sock, im_len, bo_data);
#endif
            im_send = 0; // nothing send yet
#ifndef B120316
            bo_sendok = FALSE;
#endif
            do
            {
                iml_sent = 0;
#ifdef B120316
                bo_sendok = FALSE;
#endif
                im_sendcnt = WSASend(ds_sock, &dsrl_wsabuf[iml_cur_ele], iml_bufcnt, &dwl_sent, 0, NULL, NULL);
                if( im_sendcnt == SOCKET_ERROR )
                {
                    iml_senttotal += im_send; // AG 07.10.2008
                    im_error = WSAGetLastError();
#ifdef TRACE
                    printf("Send failed: %d.\n", im_error );
#endif
                    if (    im_error != WSAEWOULDBLOCK
                         && im_error != WSAENOTCONN    )
                    {
                        adsl_callback = ads_callback;
                        if(adsl_callback && adsl_callback->am_errorcallback != NULL)
                        {
                            this->im_error = im_error;
                            adsl_callback->am_errorcallback(this,
                                    ads_usrfld,
                                    "Send failed",
                                    im_error,
                                    ERRORAT_SEND);
                        }
                        if (aimp_rc) {     // AG 07.10.2008
                            *aimp_rc = -1; // AG 07.10.2008
                        }
                    }
                    break;
                }

                // iml_cur_ele = 0; // AG  14.04.2008
                while (iml_sent < dwl_sent)
                {
                    if ((dwl_sent - iml_sent) >= (adsl_gathercnt->achc_ginp_end - adsl_gathercnt->achc_ginp_cur)) // AG 14.04.2008 ">" replaced thru the ">="
                    {
                        iml_sent += (adsl_gathercnt->achc_ginp_end - adsl_gathercnt->achc_ginp_cur);
                        adsl_gathercnt->achc_ginp_cur = adsl_gathercnt->achc_ginp_end;
                        adsl_gathercnt = adsl_gathercnt->adsc_next; // AG 14.04.2008
                        -- iml_bufcnt;// AG 14.04.2008
                        ++ iml_cur_ele;// AG 14.04.2008
                    }
                    else
                    {
                        adsl_gathercnt->achc_ginp_cur += (dwl_sent - iml_sent);
                        iml_sent += (dwl_sent - iml_sent);
                        dsrl_wsabuf[iml_cur_ele].buf = adsl_gatheriter->achc_ginp_cur; // AG 14.04.2008
                        dsrl_wsabuf[iml_cur_ele].len = adsl_gathercnt->achc_ginp_end - adsl_gathercnt->achc_ginp_cur;// AG 14.04.2008
                    }
                    // ++ iml_cur_ele; // AG 14.04.2008
                    // adsl_gathercnt = adsl_gathercnt->adsc_next; // AG 14.04.2008
                }
                // iml_bufcnt -= iml_cur_ele; // AG 14.04.2008

#ifdef B120316
                bo_sendok = TRUE;
#endif
                im_send += dwl_sent;
            }while(im_send < im_len);
            if (im_sendcnt == SOCKET_ERROR)
            break;
            iml_senttotal += im_send;
#ifdef TRACE
            printf("m_send_gather OK. Len: %d\n", im_send);
#endif
        }
#ifdef DEBUG_TCPCOMP_120314_03
#define ADSL_CONN this
        EnterCriticalSection( &ds_critsect );
        memmove( ADSL_CONN->imrc_trace_01,
                 ADSL_CONN->imrc_trace_01 + 1,
                 sizeof(ADSL_CONN->imrc_trace_01) - sizeof(ADSL_CONN->imrc_trace_01[0]) );
        ADSL_CONN->imrc_trace_01[ sizeof(ADSL_CONN->imrc_trace_01) / sizeof(ADSL_CONN->imrc_trace_01[0]) - 1 ] = __LINE__;
        LeaveCriticalSection( &ds_critsect );
#undef ADSL_CONN
#endif
#ifdef DEBUG_TCPCOMP_120314_05
        this->imc_trace_01 = __LINE__;
#endif
#ifdef TRACE
        printf("m_send_gather OK. total Len: %d\n", iml_senttotal);
#endif

        *aads_gatherout = adsl_gathercnt;
        return iml_senttotal;
    } // int dsd_tcpcomp::m_send_gather(dsd_gather_i_1 *ads_gatherinp, dsd_gather_i_1** aads_gatherout, int* aimp_rc)

    void dsd_tcpcomp::m_sendnotify()
    {
#ifdef TRACE
        printf("m_sendnotitfy\n");
#endif
#ifdef DEBUG_TCPCOMP_120314_05
        this->imc_trace_01 = __LINE__;
#endif
        bo_sendnot = TRUE;
#ifdef DEBUG_TCPCOMP_120314_07
        boc_trace_sendok = bo_sendok;
#endif
#ifdef DEBUG_TCPCOMP_120314_09
        if (this->ads_bind_ineta) {
          this->boc_dummy = TRUE;
        }
        this->aboc_1_sendok = (void *) &this->bo_sendok;
        this->aboc_1_sendnot = (void *) &this->bo_sendnot;
#endif
#ifdef DEBUG_TCPCOMP_120314_10
        EnterCriticalSection( &ds_critsect );
        LeaveCriticalSection( &ds_critsect );
#endif
        if(bo_sendok)
        {
#ifdef DEBUG_TCPCOMP_120314_02
            this->imc_debug_01++;
#endif
#ifdef DEBUG_TCPCOMP_120314_03
            EnterCriticalSection( &ds_critsect );
            memmove( this->imrc_trace_01,
                     this->imrc_trace_01 + 1,
                     sizeof(this->imrc_trace_01) - sizeof(this->imrc_trace_01[0]) );
            this->imrc_trace_01[ sizeof(this->imrc_trace_01) / sizeof(this->imrc_trace_01[0]) - 1 ] = __LINE__;
            LeaveCriticalSection( &ds_critsect );
#endif
#ifdef DEBUG_TCPCOMP_120314_05
            this->imc_trace_01 = __LINE__;
#endif
#ifdef TRACE
            printf("Set Event\n");
#endif
            if(!SetEvent(ds_event))
            {
                dsd_tcpcallback_p adsl_callback;
                adsl_callback = this->ads_callback;
                if (   (adsl_callback)
                    && (adsl_callback->am_errorcallback)) {
                    im_error = GetLastError();
                    adsl_callback->am_errorcallback(this,
                                ads_usrfld,
                                "Unable to set event for stopped send",
                                im_error,
                                ERRORAT_SEND);
                }
#ifdef TRACE
                printf("Unable to set event for send.\n");
#endif
            }
#ifdef DEBUG_TCPCOMP_120314_05
            this->imc_trace_01 = __LINE__;
#endif
        }
    } // void dsd_tcpcomp::m_sendnotify()

    dsd_tcpthread_p dsd_tcpcomp::m_createnewthread()
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

        // memset(ads_newthread, 0, sizeof(dsd_tcpthread_t)); // AG 13.07.2006
        ads_newthread->dsr_waitevent[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
        if(ads_newthread->dsr_waitevent[0] == NULL)
        {
#ifdef TRACE
            printf("Unable to create event for new TCP/IP thread\n");
#endif
            delete ads_newthread;
            return 0;
        }
        ads_newthread->ds_threadhandle = _beginthread(m_tcpthread,
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
    } // dsd_tcpthread_p dsd_tcpcomp::m_createnewthread()

    void dsd_tcpcomp::m_tcpthread(void* ads_parm) {
        BOOL bol_remove_entry; /* has to remove entry     */
        BOOL bol_save_1; /* save value              */
        BOOL bol_ret; /* return code             */
        DWORD um_waitret; // return code from wait
        dsd_tcpthread_p ads_thread;// thread structure
        int im_error;// error codes
        WSANETWORKEVENTS ds_nwevents;// network event structure
        int im_index;// loop index
        int im_conn;// index of connection notified
        dsd_stopped_p ads_stop;// pointer to a stopped connection
        dsd_tcpcallback_p adsl_callback;
#ifdef DEF_RELEASE
        int               inl_time;     /* time for deferred release       */
        dsd_def_release_p adsl_def_rel; /* pointer to a deleted connection */
#endif
#ifdef DEBUG_POLL_TIME
        HL_LONGLONG ill_eyecather;
        HL_LONGLONG ill_time;
        HL_LONGLONG ill_now;
        HL_LONGLONG ill_freq;
        HL_LONGLONG ill_freq_thousandth;
        HL_LONGLONG ill_t_max;
#endif
        ads_thread = (dsd_tcpthread_p)ads_parm;
        if (dsd_tcpthread_t::amc_at_thread_start)
        dsd_tcpthread_t::amc_at_thread_start(GetCurrentThreadId());
// 23.07.2007 AG begin
#ifdef DEF_M_STOPCONN_CB
        ads_thread->ds_thr_ident.m_init();
#endif
#ifdef TRACE
        printf("TCP/IP thread started\n");
#endif
#ifdef DEBUG_POLL_TIME

        memcpy( &ill_eyecather, "TCPCOMP1", sizeof(HL_LONGLONG) );
        ill_time = 0;
        ill_freq = 0;
        QueryPerformanceFrequency( (LARGE_INTEGER *) &ill_freq );
        ill_freq_thousandth = ill_freq / 1000;
        ill_t_max = 0;
        ads_thread->in_cb_called = 0;
#endif

        do {

#ifdef DEBUG_POLL_TIME
            if ( *((HL_LONGLONG *) &ill_time) > 0 ) {
                bol_ret = QueryPerformanceCounter((LARGE_INTEGER*)&ill_now);
//              printf( "Time in TCP Thread between WaitForMultipleEvents in %lld micro-sec\n", (((ill_now - ill_time) * 1000000) / ill_freq) );
                ill_now -= ill_time;
                if (ill_now > ill_t_max) ill_t_max = ill_now;

                /*  AK 14.05.2012:
                    print out the adresses of the called callback routines in case that the duration
                    in current poll time was longer than 1 millisecond */
                if ( ill_now > ill_freq_thousandth ) { //greater than 1 millisecond
                    m_hlnew_printf(123, "DEBUG_POLL_TIME: %d callback methods called (ill_now: %lld - micro-sec: %lld)", ads_thread->in_cb_called, ill_now, ill_now * 1000000 / ill_freq );
                    for ( int inl_1 = 0; inl_1 < ads_thread->in_cb_called; inl_1++ ) {
                        m_hlnew_printf( 123, "   Address %d of callback routine called %p", inl_1, ads_thread->av_last_callbacks[inl_1] );
                    }
                    m_hlnew_printf(123, "DEBUG_POLL_TIME end" );
                }
                memset( ads_thread->av_last_callbacks, 0, sizeof(void*) * MAX_CB_CALLED );  //reset ads_thread->av_last_callbacks
                ads_thread->in_cb_called = 0;
            }
#endif

#ifdef TRACE
            printf("Wait for %d events\n", ads_thread->im_concount + 1);
#endif
            bol_remove_entry = FALSE; /* reset has to remove entry */

            um_waitret = WSAWaitForMultipleEvents(
                    ads_thread->im_concount + 1,
                    ads_thread->dsr_waitevent,
                    FALSE,
                    INFINITE,
                    FALSE);

#ifdef DEBUG_POLL_TIME
            QueryPerformanceCounter((LARGE_INTEGER*)&ill_time);
#endif

            if(ads_thread->bo_cleanup) {
                printf("WSAWaitForMultipleEvents failed\n");
                break;
            }
            if(um_waitret == WSA_WAIT_FAILED) {
#ifdef TRACE_090801_01
                m_hl1_printf( "hob-tcpco1-l%05d-W WSA_WAIT_FAILED", __LINE__ );
#endif
                Sleep(500);
                continue;
            }
            if (um_waitret >= WSA_WAIT_EVENT_0) {
#ifdef TRACE
                printf( "l%05d Reset event \n", __LINE__ );
#endif
#ifdef DEBUG_TCPCOMP_120314_04
                Sleep( 2 );
#endif
                if(!ResetEvent(ads_thread->dsr_waitevent[ um_waitret - WSA_WAIT_EVENT_0 ])) {
                    printf( "l%05d Reset event failed\n", __LINE__ );
                }
            }
            if (um_waitret == WSA_WAIT_EVENT_0) {
// to-do 24.03.12 KB - critical section should not include closesocket and CloseHandle
// to-do 24.03.12 KB - check error after closesocket and CloseHandle
                EnterCriticalSection(&ds_critsect);
                ads_stop = ads_thread->ads_stopchain;
                while (ads_stop != NULL) {
#ifdef TRACE
                    printf("Stopped connections found\n");
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
#ifndef B120324
                                ads_thread->dsr_tcpconn[im_index]->mc_int_close();
#else
                                closesocket(ads_thread->dsr_tcpconn[im_index]->ds_sock);
#endif
                            }
                            ads_thread->dsr_tcpconn[im_index]->bo_data = FALSE;
                            ads_thread->dsr_tcpconn[im_index]->bo_sendok = FALSE;
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
                                        sizeof(class dsd_tcpcomp*));
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
#ifdef DEF_M_STOPCONN_CB
                    if (ads_stop->am_closeconncallback)
                    ads_stop->am_closeconncallback(ads_stop->avo_usrfld);
#endif
                    if (ads_stop->ads_stopped->boc_storage)
                    delete ads_stop->ads_stopped;
                    delete ads_stop;
                    ads_stop = ads_thread->ads_stopchain;
                }
                LeaveCriticalSection(&ds_critsect);
            }
            else
            {
#ifdef TRACE
                printf("Event posted was: %d\n", um_waitret - WSA_WAIT_EVENT_0);
#endif
//       for(im_conn = 0; im_conn < ads_thread->im_concount; im_conn++)
//       {
//          im_index = WSAWaitForMultipleEvents(
//                        1,
//                        &ads_thread->dsr_waitevent[im_conn + 1],
//                        TRUE,
//                        0,
//                        FALSE);
//          if ((im_index != WSA_WAIT_FAILED) && (im_index != WSA_WAIT_TIMEOUT))
                im_conn = um_waitret - WSA_WAIT_EVENT_0 - 1;
                if (im_conn >= 0)
                {
#ifdef DEBUG_TCPCOMP_120314_03
#define ADSL_CONN ads_thread->dsr_tcpconn[im_conn]
                    EnterCriticalSection( &ds_critsect );
                    memmove( ADSL_CONN->imrc_trace_01,
                             ADSL_CONN->imrc_trace_01 + 1,
                             sizeof(ADSL_CONN->imrc_trace_01) - sizeof(ADSL_CONN->imrc_trace_01[0]) );
                    ADSL_CONN->imrc_trace_01[ sizeof(ADSL_CONN->imrc_trace_01) / sizeof(ADSL_CONN->imrc_trace_01[0]) - 1 ] = __LINE__;
                    LeaveCriticalSection( &ds_critsect );
#undef ADSL_CONN
#endif
#ifdef DEBUG_TCPCOMP_120314_05
                   ads_thread->dsr_tcpconn[im_conn]->imc_trace_01 = __LINE__;
#endif
#ifdef TRACE
                    im_index = 0;
                    printf("WSAEnumNetworkEvents() event: %d:%d; Index: %d\n", im_conn + 1, ads_thread->dsr_waitevent[im_conn + 1], im_index);
#endif
                    adsl_callback = ads_thread->dsr_tcpconn[im_conn]->ads_callback;

                    //if boc_end is set, then remove_entry has the highest priority
                    //therefore we use the function mc_remove_entry
                    if (ads_thread->dsr_tcpconn[im_conn]->boc_end) { /* end has been set */
                        ads_thread->dsr_tcpconn[im_conn]->mc_remove_entry(im_conn);
                        continue;
                    }
                    im_error = WSAEnumNetworkEvents(
                            ads_thread->dsr_tcpconn[im_conn]->ds_sock,
                            ads_thread->dsr_waitevent[im_conn + 1],
                            &ds_nwevents);
                    if(im_error)
                    {
#ifdef TRACE
                        printf("WSAEnumNetworkEvents failed: %d.\n", WSAGetLastError());
#endif
                        if (adsl_callback != NULL && adsl_callback->am_errorcallback != NULL) {
#ifdef DEBUG_POLL_TIME
                            ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_errorcallback;
                            ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                            adsl_callback->am_errorcallback
                            (ads_thread->dsr_tcpconn[im_conn],
                                    ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                    "WSAEnumNetworkEvents failed",
                                    WSAGetLastError(),
                                    ERRORAT_TCPTHREAD);
                        }
                    } else {
#ifdef TRACE
                        printf("WSAEnumNetworkEvents: %d.\n", ds_nwevents.lNetworkEvents);
#endif


                        if((ds_nwevents.lNetworkEvents & FD_CONNECT) != 0) // Connect occurred
                        {
                            im_error = ds_nwevents.iErrorCode[FD_CONNECT_BIT];
                            switch (ads_thread->dsr_tcpconn[im_conn]->bo_mhconnect) {
                                case FALSE:
                                if (im_error) { /* reported error          */
                                    bol_remove_entry = TRUE; /* set has to remove entry */
                                    if (adsl_callback != NULL && adsl_callback->am_errorcallback != NULL) {
                                        ads_thread->dsr_tcpconn[im_conn]->im_error = im_error;
                                        /* adsl_callback->am_errorcallback(ads_thread->dsr_tcpconn[im_conn],
                                         ads_thread->dsr_tcpconn[im_conn]->ads_usrfld, "Connect error",
                                         im_error, ERRORAT_CONNECT); */
#ifdef DEBUG_POLL_TIME
                                        ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_connerrcallback;
                                        ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                                        adsl_callback->am_connerrcallback(ads_thread->dsr_tcpconn[im_conn],
                                                ads_thread->dsr_tcpconn[im_conn]->ads_usrfld, NULL, 0, 0, 0, im_error);
                                    }
                                }
                                else if (adsl_callback != NULL && adsl_callback->am_conncallback != NULL) {
                                    /* adsl_callback->am_conncallback(ads_thread->dsr_tcpconn[im_conn],
                                     ads_thread->dsr_tcpconn[im_conn]->ads_usrfld, im_error); */
#ifdef DEBUG_POLL_TIME
                                    ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_conncallback;
                                    ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
#ifdef B121120
                                    adsl_callback->am_conncallback(ads_thread->dsr_tcpconn[im_conn],
                                            ads_thread->dsr_tcpconn[im_conn]->ads_usrfld, NULL, 0, 0 );
#else
                                    adsl_callback->am_conncallback(ads_thread->dsr_tcpconn[im_conn],
                                        ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                        (struct dsd_target_ineta_1*) &ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta,
                                        (void*) ads_thread->dsr_tcpconn[im_conn]->aps_free_ti1,
                                        NULL, 0, 0 );
#endif
                                }
                                if (ads_thread->dsr_tcpconn[im_conn]->ads_findsock) {
                                    freeaddrinfo( ads_thread->dsr_tcpconn[im_conn]->ads_findsock);
                                    ads_thread->dsr_tcpconn[im_conn]->ads_findsock = NULL;
                                }
#ifdef B121120
                                if (       (adsl_callback != NULL)
                                        && (adsl_callback->amc_free_target_ineta)
                                        && (ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta)) {
#ifdef DEBUG_POLL_TIME
                                    ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->amc_free_target_ineta;
                                    ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                                    adsl_callback->amc_free_target_ineta(ads_thread->dsr_tcpconn[im_conn],
                                            ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                            ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta);
                                    ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta = NULL; /* do not free twice */
                                }
#endif
                                break;
                                case TRUE:
                                {
                                    sockaddr_storage dsl_sockaddr;
                                    socklen_t dsl_len;
                                    int iml_ineta_curno;
                                    iml_ineta_curno = ads_thread->dsr_tcpconn[im_conn]->im_ineta_curno - 1;
                                    ads_thread->dsr_tcpconn[im_conn]->im_error = im_error;
                                    m_set_connect_p1(&dsl_sockaddr, (socklen_t*)&dsl_len,
                                            (dsd_target_ineta_1*)ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta, iml_ineta_curno);
                                    if (im_error) { /* reported error          */
                                        /* if (adsl_callback->am_errorcallback != NULL) {
                                         ads_thread->dsr_tcpconn[im_conn]->im_error = im_error;
                                         adsl_callback->am_errorcallback(ads_thread->dsr_tcpconn[im_conn],
                                         ads_thread->dsr_tcpconn[im_conn]->ads_usrfld, "Connect error",
                                         im_error, ERRORAT_CONNECT);
                                         } */
                                        if (adsl_callback != NULL && adsl_callback->am_connerrcallback != NULL) {
#ifdef DEBUG_POLL_TIME
                                            ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_connerrcallback;
                                            ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                                            adsl_callback->am_connerrcallback(ads_thread->dsr_tcpconn[im_conn], ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                                    (struct sockaddr *) &dsl_sockaddr, dsl_len, iml_ineta_curno, ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta->imc_no_ineta,
                                                    im_error);
                                        }
                                        if (    (ads_thread->dsr_tcpconn[im_conn]->im_ineta_curno ==
                                                 ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta->imc_no_ineta) //?
                                             && (adsl_callback != NULL)
                                             && (adsl_callback->am_conncallback != NULL) ) {
                                            // due to KBinfo from 23.01.2012, tcpcomp should also call
                                            // connect callback method if connect failes!
#ifdef DEBUG_POLL_TIME
                                            ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_conncallback;
                                            ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
#ifdef B121120
                                            adsl_callback->am_conncallback(ads_thread->dsr_tcpconn[im_conn],
                                                    ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                                    (struct sockaddr *) &dsl_sockaddr, dsl_len, im_error );
#else
                                            adsl_callback->am_conncallback(ads_thread->dsr_tcpconn[im_conn],
                                                    ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                                    (struct dsd_target_ineta_1*) &ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta,
                                                    (void*) ads_thread->dsr_tcpconn[im_conn]->aps_free_ti1,
                                                    (struct sockaddr *) &dsl_sockaddr, dsl_len, im_error );
#endif

                                        }
                                        if (ads_thread->dsr_tcpconn[im_conn]->im_ineta_curno == ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta->imc_no_ineta) {
                                            bol_remove_entry = TRUE; /* set has to remove entry */
                                            break;
                                        }
                                        else {
                                            closesocket(ads_thread->dsr_tcpconn[im_conn]->ds_sock);
                                            ads_thread->dsr_tcpconn[im_conn]->ds_sock = INVALID_SOCKET;
#ifdef B121120
                                            if (ads_thread->dsr_tcpconn[im_conn]->m_startco_mh(NULL, NULL, NULL, NULL, 0) != 0)
#else
                                            if (ads_thread->dsr_tcpconn[im_conn]->m_startco_mh(NULL, NULL, NULL, NULL, NULL, 0) != 0)
#endif
                                            bol_remove_entry = TRUE; /* set has to remove entry */
                                            break;
                                        }

                                    }
                                    if (adsl_callback != NULL && adsl_callback->am_conncallback != NULL) {
#ifdef DEBUG_POLL_TIME
                                        ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_conncallback;
                                        ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
#ifndef B131125
// 25.11.13 KB - TCP port is missing in struct sockaddr
                                        if (dsl_sockaddr.ss_family == AF_INET) {
                                          ((struct sockaddr_in *) &dsl_sockaddr)->sin_port = htons( ads_thread->dsr_tcpconn[im_conn]->us_port );
                                        } else if (dsl_sockaddr.ss_family == AF_INET6) {
                                          ((struct sockaddr_in6 *) &dsl_sockaddr)->sin6_port = htons( ads_thread->dsr_tcpconn[im_conn]->us_port );
                                        }
#endif
                                        adsl_callback->am_conncallback(ads_thread->dsr_tcpconn[im_conn],
                                                ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
#ifndef B121120
                                                (struct dsd_target_ineta_1*) &ads_thread->dsr_tcpconn[im_conn]->ads_target_ineta,
                                                (void*) ads_thread->dsr_tcpconn[im_conn]->aps_free_ti1,
#endif
                                                (struct sockaddr *) &dsl_sockaddr, dsl_len, 0 );
                                    }
                                }
                                break;
                            }
                        }
                        if((ds_nwevents.lNetworkEvents & FD_WRITE) != 0) // Send allowed
                        {
#ifdef DEBUG_TCPCOMP_120314_03
#define ADSL_CONN ads_thread->dsr_tcpconn[im_conn]
                            EnterCriticalSection( &ds_critsect );
                            memmove( ADSL_CONN->imrc_trace_01,
                                     ADSL_CONN->imrc_trace_01 + 1,
                                     sizeof(ADSL_CONN->imrc_trace_01) - sizeof(ADSL_CONN->imrc_trace_01[0]) );
                            ADSL_CONN->imrc_trace_01[ sizeof(ADSL_CONN->imrc_trace_01) / sizeof(ADSL_CONN->imrc_trace_01[0]) - 1 ] = __LINE__;
                            LeaveCriticalSection( &ds_critsect );
#undef ADSL_CONN
#endif
#ifdef DEBUG_TCPCOMP_120314_05
                            ads_thread->dsr_tcpconn[im_conn]->imc_trace_01 = __LINE__;
#endif
                            im_error = ds_nwevents.iErrorCode[FD_WRITE_BIT];
                            if ( im_error ) {
                                if (    adsl_callback                   != NULL
                                     && adsl_callback->am_errorcallback != NULL ) {
#ifdef DEBUG_POLL_TIME
                                    ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_errorcallback;
                                    ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                                    adsl_callback->am_errorcallback( ads_thread->dsr_tcpconn[im_conn],
                                                         ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                                         "Send error", im_error, ERRORAT_SEND );
                                }
                                if(ads_thread->dsr_tcpconn[im_conn]->im_error == 0)
                                {
                                    ads_thread->dsr_tcpconn[im_conn]->im_error =
                                    im_error;
#ifdef DEBUG_POLL_TIME
                                    ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_recvcallback;
                                    ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                                    adsl_callback->am_recvcallback(
                                            ads_thread->dsr_tcpconn[im_conn],
                                            ads_thread->dsr_tcpconn[im_conn]->
                                            ads_usrfld,
                                            NULL);
                                }
                            }
                            else
                            {
                                ads_thread->dsr_tcpconn[im_conn]->bo_sendok = TRUE;
#ifdef DEBUG_TCPCOMP_120314_03
#define ADSL_CONN ads_thread->dsr_tcpconn[im_conn]
                                EnterCriticalSection( &ds_critsect );
                                memmove( ADSL_CONN->imrc_trace_01,
                                         ADSL_CONN->imrc_trace_01 + 1,
                                         sizeof(ADSL_CONN->imrc_trace_01) - sizeof(ADSL_CONN->imrc_trace_01[0]) );
                                ADSL_CONN->imrc_trace_01[ sizeof(ADSL_CONN->imrc_trace_01) / sizeof(ADSL_CONN->imrc_trace_01[0]) - 1 ] = __LINE__;
                                LeaveCriticalSection( &ds_critsect );
#undef ADSL_CONN
#endif
#ifdef DEBUG_TCPCOMP_120314_06
#ifdef DEBUG_TCPCOMP_120314_05
                                ads_thread->dsr_tcpconn[im_conn]->imc_trace_02_a = ads_thread->dsr_tcpconn[im_conn]->imc_trace_01;
#endif
                                ads_thread->dsr_tcpconn[im_conn]->imc_trace_02_b = __LINE__;
#endif
#ifdef DEBUG_TCPCOMP_120314_05
                                ads_thread->dsr_tcpconn[im_conn]->imc_trace_01 = __LINE__;
#endif
#ifdef DEBUG_TCPCOMP_120314_08
                                ads_thread->dsr_tcpconn[im_conn]->boc_trace_sendnot = ads_thread->dsr_tcpconn[im_conn]->bo_sendnot;
#endif
#ifdef DEBUG_TCPCOMP_120314_09
#define ADSL_CONN ads_thread->dsr_tcpconn[im_conn]
                                if (ADSL_CONN->ads_bind_ineta) {
                                  ADSL_CONN->boc_dummy = TRUE;
                                }
                                ADSL_CONN->aboc_2_sendok = (void *) &ADSL_CONN->bo_sendok;
                                ADSL_CONN->aboc_2_sendnot = (void *) &ADSL_CONN->bo_sendnot;
#undef ADSL_CONN
#endif
#ifdef DEBUG_TCPCOMP_120314_10
                                EnterCriticalSection( &ds_critsect );
                                LeaveCriticalSection( &ds_critsect );
#endif
#ifdef B120316
                                if(ads_thread->dsr_tcpconn[im_conn]->bo_sendnot)
                                {
                                    ads_thread->dsr_tcpconn[im_conn]->bo_sendnot =
                                    FALSE;
                                    adsl_callback->am_sendcallback
                                    (ads_thread->dsr_tcpconn[im_conn],
                                            ads_thread->dsr_tcpconn[im_conn]->ads_usrfld);
#ifdef TRACE
                                    printf("return from send.\n");
#endif
#ifdef DEBUG_TCPCOMP_120314_03
#define ADSL_CONN ads_thread->dsr_tcpconn[im_conn]
                                    EnterCriticalSection( &ds_critsect );
                                    memmove( ADSL_CONN->imrc_trace_01,
                                             ADSL_CONN->imrc_trace_01 + 1,
                                             sizeof(ADSL_CONN->imrc_trace_01) - sizeof(ADSL_CONN->imrc_trace_01[0]) );
                                    ADSL_CONN->imrc_trace_01[ sizeof(ADSL_CONN->imrc_trace_01) / sizeof(ADSL_CONN->imrc_trace_01[0]) - 1 ] = __LINE__;
                                    LeaveCriticalSection( &ds_critsect );
#undef ADSL_CONN
#endif
#ifdef DEBUG_TCPCOMP_120314_05
                                    ads_thread->dsr_tcpconn[im_conn]->imc_trace_01 = __LINE__;
#endif
                                }
#endif
                            }
                        }

                        if (    ads_thread->dsr_tcpconn[im_conn]->bo_sendnot
                             && ads_thread->dsr_tcpconn[im_conn]->bo_sendok )
                        {
#ifdef DEBUG_TCPCOMP_120314_03
#define ADSL_CONN ads_thread->dsr_tcpconn[im_conn]
                            EnterCriticalSection( &ds_critsect );
                            memmove( ADSL_CONN->imrc_trace_01,
                                     ADSL_CONN->imrc_trace_01 + 1,
                                     sizeof(ADSL_CONN->imrc_trace_01) - sizeof(ADSL_CONN->imrc_trace_01[0]) );
                            ADSL_CONN->imrc_trace_01[ sizeof(ADSL_CONN->imrc_trace_01) / sizeof(ADSL_CONN->imrc_trace_01[0]) - 1 ] = __LINE__;
                            LeaveCriticalSection( &ds_critsect );
#undef ADSL_CONN
#endif
#ifdef DEBUG_TCPCOMP_120314_05
                            ads_thread->dsr_tcpconn[im_conn]->imc_trace_01 = __LINE__;
#endif
                            ads_thread->dsr_tcpconn[im_conn]->bo_sendnot = FALSE;
#ifdef DEBUG_POLL_TIME
                            ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_sendcallback;
                            ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                            adsl_callback->am_sendcallback( ads_thread->dsr_tcpconn[im_conn],
                                                            ads_thread->dsr_tcpconn[im_conn]->ads_usrfld );
#ifdef DEBUG_TCPCOMP_120314_03
#define ADSL_CONN ads_thread->dsr_tcpconn[im_conn]
                            EnterCriticalSection( &ds_critsect );
                            memmove( ADSL_CONN->imrc_trace_01,
                                     ADSL_CONN->imrc_trace_01 + 1,
                                     sizeof(ADSL_CONN->imrc_trace_01) - sizeof(ADSL_CONN->imrc_trace_01[0]) );
                            ADSL_CONN->imrc_trace_01[ sizeof(ADSL_CONN->imrc_trace_01) / sizeof(ADSL_CONN->imrc_trace_01[0]) - 1 ] = __LINE__;
                            LeaveCriticalSection( &ds_critsect );
#undef ADSL_CONN
#endif
#ifdef DEBUG_TCPCOMP_120314_05
                            ads_thread->dsr_tcpconn[im_conn]->imc_trace_01 = __LINE__;
#endif
                        }
                        if((ds_nwevents.lNetworkEvents & FD_READ) != 0) // Data available
                        {
                            im_error = ds_nwevents.iErrorCode[FD_READ_BIT];
                            if(im_error)
                            {
                                bol_remove_entry = TRUE; /* set has to remove entry */
                                if ( (adsl_callback != NULL) && (adsl_callback->am_errorcallback != NULL)) {
#ifdef DEBUG_POLL_TIME
                                    ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_errorcallback;
                                    ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                                    adsl_callback->am_errorcallback
                                    (ads_thread->dsr_tcpconn[im_conn],
                                            ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                            "Receive error",
                                            im_error,
                                            ERRORAT_RECV);
                                }
                                if(ads_thread->dsr_tcpconn[im_conn]->im_error == 0)
                                {
                                    ads_thread->dsr_tcpconn[im_conn]->im_error =
                                    im_error;
#ifdef DEBUG_POLL_TIME
                                    ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_recvcallback;
                                    ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                                    adsl_callback->am_recvcallback(
                                            ads_thread->dsr_tcpconn[im_conn],
                                            ads_thread->dsr_tcpconn[im_conn]->
                                            ads_usrfld,
                                            NULL);
                                }
                            }
                            else
                            {
                                if(!ads_thread->dsr_tcpconn[im_conn]->bo_recv)
                                {
                                    ads_thread->dsr_tcpconn[im_conn]->bo_data = TRUE;
#ifdef TRACE
                                    printf("bo_data = true.\n");
#endif
                                }
                                else
                                {
                                    bol_ret = ads_thread->dsr_tcpconn[im_conn]->m_recvdata();
                                    if (bol_ret) {
                                        bol_remove_entry = TRUE; /* set has to remove entry */
                                    }
                                }
                            }
                        }
                        else if(ads_thread->dsr_tcpconn[im_conn]->bo_recv &&
                                (ads_thread->dsr_tcpconn[im_conn]->bo_fd_close || // AG 14.04.2008
                                        ads_thread->dsr_tcpconn[im_conn]->bo_data)
                        )// AG 14.04.2008
                        {
                            bol_ret = ads_thread->dsr_tcpconn[im_conn]->m_recvdata();
                            if (bol_ret) {
                                bol_remove_entry = TRUE; /* set has to remove entry */
                            }
                        }
                        if((ds_nwevents.lNetworkEvents & FD_CLOSE) != 0) // Connection closed
                        {
                            im_error = ds_nwevents.iErrorCode[FD_CLOSE_BIT];
#ifdef TRACE
                            printf("Close coming. im_error = %d\n", im_error);
#endif
                            if(im_error)
                            {
                                if ( (adsl_callback != NULL) && (adsl_callback->am_errorcallback != NULL)) {
#ifdef DEBUG_POLL_TIME
                                    ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_errorcallback;
                                    ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                                    adsl_callback->am_errorcallback
                                    (ads_thread->dsr_tcpconn[im_conn],
                                            ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                            "Connection closed",
                                            im_error,
                                            ERRORAT_CLOSE);
                                }
                                if(ads_thread->dsr_tcpconn[im_conn]->im_error == 0)
                                {
                                    ads_thread->dsr_tcpconn[im_conn]->im_error =
                                    im_error;
#ifdef DEBUG_POLL_TIME
                                    ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_recvcallback;
                                    ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                                    adsl_callback->am_recvcallback(
                                            ads_thread->dsr_tcpconn[im_conn],
                                            ads_thread->dsr_tcpconn[im_conn]->
                                            ads_usrfld,
                                            NULL);
                                }
                                bol_remove_entry = TRUE; /* set has to remove entry */
                            }
                            else
                            {
                                ads_thread->dsr_tcpconn[im_conn]->bo_fd_close = TRUE; // AG 14.04.2008
                                if(ads_thread->dsr_tcpconn[im_conn]->bo_recv)
                                {
                                    bol_ret = ads_thread->dsr_tcpconn[im_conn]->m_recvdata();
                                    if (bol_ret) {
                                        bol_remove_entry = TRUE; /* set has to remove entry */
                                    }
                                }
#ifdef DEF_RELEASE
                                adsl_def_rel = ads_thread->ads_def_rel;

                                inl_time = ads_thread->dsr_tcpconn[im_conn]->mc_get_time();
                                while ( (adsl_def_rel != NULL) &&                      //delete session after 2 mins
                                       ((inl_time - adsl_def_rel->in_timestamp) > 120 ) ) {
                                    ads_thread->ads_def_rel = adsl_def_rel->adsc_next; //go to next in chain
                                    delete adsl_def_rel->adsc_cur_ses;                 //deferred delete of session
                                    delete adsl_def_rel;                               //delete whole chain
                                    adsl_def_rel = ads_thread->ads_def_rel;            //go to next in chain
                                }
#endif
                                /* else
                                 {
                                 adsl_callback->am_recvcallback(
                                 ads_thread->dsr_tcpconn[im_conn],
                                 ads_thread->dsr_tcpconn[im_conn]->
                                 ads_usrfld,
                                 NULL);
                                 }*/ // AG 14.04.2008
                            }
                        }

                        //use the function mc_remove_entry
                        if (bol_remove_entry) { /* end has been set */
                            ads_thread->dsr_tcpconn[im_conn]->mc_remove_entry(im_conn);
                        }
                    }
                }
#ifdef XYZ1
                else if (im_index == WSA_WAIT_FAILED) { // Wait failed
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
                                ERRORAT_TCPTHREAD);
                    }
                }
#endif
//       }
            }
        }while (TRUE);
#ifdef TRACE
        printf("TCPthread ended. clean up.\n");
#endif

// clean up
        for(im_index = 0; im_index < ads_thread->im_concount; im_index++)
        {
            if(ads_thread->dsr_tcpconn[im_index] != NULL)
            {
                ads_thread->dsr_tcpconn[im_index]->m_stopconn(TRUE, FALSE);
                if (ads_thread->dsr_tcpconn[im_index]->boc_storage)
                delete ads_thread->dsr_tcpconn[im_index];
            }
            CloseHandle(ads_thread->dsr_waitevent[im_index + 1]);
        }
        CloseHandle(ads_thread->dsr_waitevent[0]);
        delete ads_thread;
    } // void dsd_tcpcomp::m_tcpthread(void*)

    BOOL dsd_tcpcomp::m_recvdata()
    {
        void* avo_handle; // handle to receive buffer
        char* ach_buffer;// receive buffer
        int* aim_datalen;// length of data received
        int im_bufferlen;// maximum length to receive
        int im_received;// number of bytes received with one recv.
        int im_error;// error code
        BOOL bol_recv_2;
        BOOL bol_remove_entry; /* has to remove entry     */
        dsd_tcpcallback_p adsl_callback;

#ifdef TRACE
        printf( "l%05d m_recvdata from %d\n", __LINE__, ds_sock);
#endif
        bol_remove_entry = FALSE; /* reset has to remove entry */
        adsl_callback = ads_callback;
        if ( adsl_callback == NULL ) {
            return FALSE;
        }
        // get receive buffer from application
#ifdef DEBUG_POLL_TIME
        ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_getrecvbuf;
        ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
        im_bufferlen = adsl_callback->am_getrecvbuf(this,
                ads_usrfld,
                &avo_handle,
                &ach_buffer,
                &aim_datalen);
#ifdef TRACE
        printf( "l%05d m_recvdata m_getrecvbuf() returned %d\n", __LINE__, im_bufferlen );
#endif
		if ( im_bufferlen <= 0 ) // no buffer available
        {
#ifdef TRACE
            printf( "l%05d bufferlen <= 0\n", __LINE__ );
#endif
            return FALSE;
        }
        if (avo_handle == NULL ||
                ach_buffer == NULL ||
                aim_datalen == NULL)
        {
#ifdef TRACE
            printf( "l%05d m_getrecvbuf() returned invalid values\n", __LINE__ );
#endif
            if(adsl_callback->am_errorcallback != NULL)
            {
                this->im_error = TCPCOMP_ERROR_NULLPARAM;
#ifdef DEBUG_POLL_TIME
                ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_errorcallback;
                ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                adsl_callback->am_errorcallback(this,
                        ads_usrfld,
                        "Invalid paramter value (NULL)",
                        TCPCOMP_ERROR_NULLPARAM,
                        ERRORAT_RECV);
            }
            return FALSE;
        }

        // now receive
        do {
            bo_data = FALSE;
            im_received = recv( ds_sock, ach_buffer, im_bufferlen, 0);
            if(im_received == 0) // Connection ended
            {
                *aim_datalen = -1;
                bol_remove_entry = TRUE; /* set has to remove entry */
                break;
            }
            if(im_received == SOCKET_ERROR)
            {
                im_error = WSAGetLastError();
                if(im_error == WSAEWOULDBLOCK)
                {
                    *aim_datalen = 0;
                    break;
                }
                else
                {
                    bol_remove_entry = TRUE; /* set has to remove entry */
                    if(adsl_callback->am_errorcallback != NULL)
                    {
                        this->im_error = im_error;
#ifdef DEBUG_POLL_TIME
                        ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_errorcallback;
                        ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
                        adsl_callback->am_errorcallback(this,
                                ads_usrfld,
                                "Receive error",
                                im_error,
                                ERRORAT_RECV);
                    }
                    if(im_bufferlen < sizeof(int))
                    {
                        *aim_datalen = -2;
                        *ach_buffer = (char)0xFF;
                    }
                    else
                    {
                        *aim_datalen = -4;
                        *(int*)ach_buffer = im_error;
                    }
                    break;
                }
            }
            *aim_datalen = im_received;
//    break;
        }while (FALSE);
        // call application
//   EnterCriticalSection(&ds_critsect);            // AG 13.07.2006
// EnterCriticalSection(&ads_thread->ds_thrcritsect);  // AG 13.07.2006
        bo_recv = FALSE;
#ifdef DEBUG_POLL_TIME
        ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->am_recvcallback;
        ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
        bol_recv_2 = adsl_callback->am_recvcallback( this,
                ads_usrfld,
                avo_handle );
#ifdef TRACE
        printf( "l%05d m_recvdata m_recvcallback() returned %d\n", __LINE__, bol_recv_2 );
#endif
        if (bol_recv_2) bo_recv = TRUE;
//   LeaveCriticalSection(&ds_critsect);            // AG 13.07.2006
// LeaveCriticalSection(&ads_thread->ds_thrcritsect);  // AG 13.07.2006
#ifdef TRACE
        printf( "l%05d m_recvdata OK\n", __LINE__ );
#endif
        return bol_remove_entry;
    } // BOOL dsd_tcpcomp::m_recvdata()

    SOCKET dsd_tcpcomp::ms_socket(unsigned short usp_family, const dsd_bind_ineta_1* adsp_bind_ineta) {
        SOCKET dsl_sock;
        int iml_ret;
        dsl_sock = socket(usp_family, SOCK_STREAM, IPPROTO_TCP);

        if(dsl_sock == INVALID_SOCKET) {
            im_error = GetLastError();
            if (ads_callback->am_errorcallback)
            ads_callback->am_errorcallback(this, ads_usrfld,
                    "Unable to create socket for new connection",
                    im_error, ERRORAT_STARTCONN );
#ifdef TRACE
            printf("%s:%d %s Error socket(): %d.\n\n", __FILE__, __LINE__, __FUNCTION__, WSAGetLastError());
#endif
            return dsl_sock;
        }
        if (adsp_bind_ineta) {
            if (usp_family == AF_INET)
            iml_ret = bind(dsl_sock, (const sockaddr* )&adsp_bind_ineta->dsc_soai4, sizeof(adsp_bind_ineta->dsc_soai4));
            else if (usp_family == AF_INET6)
            iml_ret = bind(dsl_sock, (const sockaddr* )&adsp_bind_ineta->dsc_soai6, sizeof(adsp_bind_ineta->dsc_soai6));
            if (iml_ret != 0)
            {
                im_error = GetLastError();
                if (ads_callback->am_errorcallback)
                ads_callback->am_errorcallback(this, ads_usrfld,
                        "Unable to bind socket",
                        im_error, ERRORAT_STARTCONN );
#ifdef TRACE
                printf("%s:%d %s Error bind(): %d.\n\n", __FILE__, __LINE__, __FUNCTION__, WSAGetLastError());
#endif
                closesocket(dsl_sock);
                return INVALID_SOCKET;
            }
        }
        return dsl_sock;

    }

    int dsd_tcpcomp::m_startco_mh( dsd_tcpcallback_p adsp_callback, void * vpp_userfld,
            const dsd_bind_ineta_1* adsp_bind_ineta,
            const dsd_target_ineta_1* adsp_target_ineta,
#ifndef B121120
            const void * ap_free_ti1,
#endif
            unsigned short usp_port, BOOL bop_round_robin ) {
        dsd_tcpthread_p ads_thrcur; // current thread object
        dsd_tcpthread_p ads_thrlast;// last thread in chain

        int iml_ret, im_conn;
        const dsd_bind_ineta_1* adsl_bind;
        sockaddr_storage dsl_sockaddr;
        socklen_t dsl_len;

#ifdef TRACEHL1
        m_hl1_printf( "hob-tcpco1-l%05d-T dsd_tcpcomp::m_startco_mh this=%p vpp_userfld=%p.",
                __LINE__, this, vpp_userfld);
#endif
#ifdef TRACE
        printf( "hob-tcpco1.hpp l%05d m_startco_mh this=%p\n", __LINE__, this );
#endif
        if (ads_thread == NULL) // the tcpcomp instanse is not on tcpcomp thread
        {
            if (!adsp_callback ||
                    !adsp_callback->am_conncallback ||
                    !adsp_callback->amc_cleanup ||
                    !adsp_callback->am_getrecvbuf ||
                    !adsp_callback->am_recvcallback ||
                    !adsp_target_ineta || adsp_target_ineta->imc_len_mem == 0) {
#ifdef TRACE
                printf("Parameter is null\n");
#endif
                return 1;
            }

            // Init connection object
            this->boc_storage = FALSE; /* storage has not been acquired */
            this->boc_end = FALSE; /* end has not been set    */
            this->bo_sendnot = FALSE;
            this->bo_data = FALSE;
            this->bo_sendok = FALSE;
            this->bo_recv = FALSE;
            this->bo_fd_close = FALSE; // AG 14.04.2008
            this->ads_callback = adsp_callback;
            this->ads_usrfld = vpp_userfld;
            this->aps_free_ti1 = ap_free_ti1;
            this->im_error = 0;
            this->ads_findsock = NULL;
            this->ads_findcur = NULL;

            im_ineta_curno = 0;
            us_port = usp_port;
            bo_mhconnect = TRUE;
            ads_target_ineta = adsp_target_ineta;

        }
        while (true) {
            while (im_ineta_curno < ads_target_ineta->imc_no_ineta) {

                memset(&dsl_sockaddr, 0, sizeof(sockaddr_storage));
                m_set_connect_p1(&dsl_sockaddr, (socklen_t*)&dsl_len, (dsd_target_ineta_1*)ads_target_ineta, im_ineta_curno ++);

                adsl_bind = NULL;
                if (adsp_bind_ineta && adsp_bind_ineta->boc_bind_needed) {
                    if (dsl_sockaddr.ss_family == AF_INET && adsp_bind_ineta->boc_ipv4)
                    adsl_bind = adsp_bind_ineta;
                    else if (dsl_sockaddr.ss_family == AF_INET6 && adsp_bind_ineta->boc_ipv6)
                    adsl_bind = adsp_bind_ineta;
                }

                if ((this->ds_sock = ms_socket(dsl_sockaddr.ss_family, adsl_bind)) != INVALID_SOCKET)
                break;

            }
            if (this->ds_sock == INVALID_SOCKET) {
#ifdef TRACE
                printf("Unable to create socket for new connection object\n");
#endif
                return 2;
            }
            if (this->ds_event == NULL) // test
// 25.03.12 KB - should be WSACreateEvent()
            this->ds_event = CreateEvent(NULL, TRUE, FALSE, NULL);
            if(this->ds_event == NULL)
            {
#ifdef TRACE
                printf("Unable to create event for new connection object\n");
#endif
                closesocket(this->ds_sock);
                this->ds_sock = INVALID_SOCKET;
                return 3;
            }
            if (WSAEventSelect( this->ds_sock,
                            this->ds_event,
                            FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE ))
            {
#ifdef TRACE
                printf("Unable to set socket for non-blocking operation: %d\n", WSAGetLastError());
#endif
                CloseHandle(this->ds_event);
                closesocket(this->ds_sock);
                this->ds_sock = INVALID_SOCKET;
                return 4;
            }
            break;

        }

        if (ads_thread == NULL) // the tcpcomp instanse is not on tcpcomp thread
        {
            // now find a thread to handle this connection
            EnterCriticalSection(&ds_critsect);
            ads_thrlast = ads_thrcur = ads_thranc;
            while(ads_thrcur)
            {
                if(ads_thrcur->im_concount < TCPCOMP_MAXCONN)
                {
                    break;
                }
                ads_thrlast = ads_thrcur;
                ads_thrcur = ads_thrcur->ads_next;
            }
            if(!ads_thrcur) // no more space in threads, create new one
            {
                LeaveCriticalSection(&ds_critsect);
                ads_thrcur = m_createnewthread();
                if(!ads_thrcur)
                {
#ifdef TRACE
                    printf("Unable to start a thread for this connection\n");
#endif
                    CloseHandle(this->ds_event);
                    closesocket(this->ds_sock);
                    this->ds_sock = INVALID_SOCKET;
                    return 5;
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
                            ads_thrlast->ads_next = ads_thrcur;
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
#ifdef TRACE
            printf( "hob-tcpco1.hpp l%05d m_startco_fb() ads_thrcur=%p im_concount=%d\n",
                    __LINE__, ads_thrcur, ads_thrcur->im_concount );
#endif

            if(!SetEvent(ads_thread->dsr_waitevent[0])) // Tell thread to handle this connection
            {
                if(ads_callback->am_errorcallback != NULL) {
                    this->im_error = GetLastError();
                    adsp_callback->am_errorcallback(this, vpp_userfld,
                            "Unable to set event for new connection",
                            this->im_error, ERRORAT_STARTCONN );
                }
#ifdef TRACE
                printf("Unable to set event for new connection.\n");
#endif
            }
        }
        if ((iml_ret = m_connect_mh(&dsl_sockaddr, dsl_len)) == TRUE)
        return 0;

#ifdef TRACE
        printf("Error connect() on the new connection object %d\n", im_error);
#endif
        if (im_ineta_curno < ads_target_ineta->imc_no_ineta) {
            closesocket(ds_sock);
            ds_sock = INVALID_SOCKET;
#ifdef B121120
            iml_ret = m_startco_mh( NULL, NULL, NULL, NULL, us_port, FALSE );
#else
            iml_ret = m_startco_mh( NULL, NULL, NULL, NULL, NULL, us_port, FALSE );
#endif
        }
        else
        iml_ret = -1;

        if (iml_ret != 0 && adsp_callback != NULL) {
            BOOL bol_save_1;
            dsd_tcpcallback_t* adsl_callback;
            EnterCriticalSection(&ds_critsect);
            for (im_conn = 0; im_conn < ads_thread->im_concount; ++ im_conn)
            {
                if (ads_thread->dsr_tcpconn[im_conn] == this)
                break;
            }

            adsl_callback = ads_callback;
#ifdef TRACE
            printf( "hob-tcpco1.hpp l%05d remove entry\n", __LINE__ );
#endif
            ads_callback = NULL;
            closesocket(ds_sock);
            CloseHandle(ds_event);
            bol_save_1 = boc_storage; /* save value */
#ifdef B121120
            if ( (adsl_callback->amc_free_target_ineta)
                    && (ads_target_ineta))
            adsl_callback->amc_free_target_ineta(this, ads_usrfld, ads_target_ineta);
#endif
            if (adsl_callback->amc_cleanup)
            adsl_callback->amc_cleanup(this, ads_usrfld );
            if (bol_save_1)
            delete this;

            ads_thread->im_concount--;
#ifdef TRACE
            printf( "hob-tcpco1.hpp l%05d dsd_tcpcomp::m_tcpthread() ads_thread=%p im_concount=%d\n",
                    __LINE__, ads_thread, ads_thread->im_concount );
#endif
            if (im_conn < ads_thread->im_concount) {
#ifdef TRACE
                printf( "l%05d Remove empty event\n", __LINE__ );
#endif
                memmove(&ads_thread->dsr_tcpconn[im_conn],
                        &ads_thread->dsr_tcpconn[im_conn + 1],
                        (ads_thread->im_concount - im_conn) *
                        sizeof(class dsd_tcpcomp*));
                memmove(&ads_thread->dsr_waitevent[im_conn + 1],
                        &ads_thread->dsr_waitevent[im_conn + 2],
                        (ads_thread->im_concount - im_conn) *
                        sizeof(dsd_eventtype));
            }
            LeaveCriticalSection(&ds_critsect);

        }

        return iml_ret;

    } /* end int dsd_tcpcomp::m_startco_mh()                                            */

    int dsd_tcpcomp::m_connect_mh(sockaddr_storage* adsp_sockaddr, socklen_t dsp_len)
    {
        int iml_error;
        if (adsp_sockaddr->ss_family == AF_INET)
        ((sockaddr_in*)adsp_sockaddr)->sin_port = htons(us_port);
        else
        ((sockaddr_in6*)adsp_sockaddr)->sin6_port = htons(us_port);

        iml_error = connect(ds_sock, (const sockaddr*) adsp_sockaddr, dsp_len);
        if( !iml_error ) {
#ifdef TRACE
            printf("Connect doesn't return with WSAEWOULDBLOCK. Strange\n");
#endif
        }
        else {
            iml_error = WSAGetLastError();
            if( iml_error != WSAEWOULDBLOCK )
            {
#ifdef TRACE
                printf("Connect failed: %d.\n\n", iml_error );
#endif
                /*
                 if(ads_callback->am_errorcallback != NULL)
                 {
                 im_error = iml_error;
                 ads_callback->am_errorcallback(this, ads_usrfld,
                 "Connect failed", iml_error, ERRORAT_CONNECT);
                 } */
                if (ads_callback->am_connerrcallback != NULL) {
                    sockaddr_storage dsl_sockaddr;
                    socklen_t dsl_len;
                    int iml_ineta_curno;
                    im_error = iml_error;
                    iml_ineta_curno = im_ineta_curno - 1;
                    m_set_connect_p1( &dsl_sockaddr, (socklen_t*)&dsl_len,
                            (dsd_target_ineta_1*)ads_target_ineta,
                            iml_ineta_curno);
                    ads_callback->am_connerrcallback( this, ads_usrfld,
                            (struct sockaddr *) &dsl_sockaddr, dsl_len,
                            iml_ineta_curno, ads_target_ineta->imc_no_ineta,
                            iml_error);
                }
                return FALSE;
            }
        }
        return TRUE;
    }

    void dsd_tcpcomp::mc_set_nodelay(int imp_optval)
    {
        int iml_rc; /* return value            */
        dsd_tcpcallback_p   adsl_callback;

        adsl_callback = this->ads_callback;

        /* disable the Naegle Algorithm                                     */
        iml_rc = setsockopt( ds_sock, IPPROTO_TCP, TCP_NODELAY, (const char *) &imp_optval, sizeof(int) );
        if (iml_rc != 0) { /* error occured           */

#ifdef TRACE
            printf( "hob-tcpco1.hpp %05d setsockopt() returned %d error %d.",
                    __LINE__, iml_rc, WSAGetLastError() );
#endif
            if (  adsl_callback != NULL &&
                  adsl_callback->am_errorcallback != NULL) {
                adsl_callback->am_errorcallback( this, this->ads_usrfld,
                                                 "Error setsockopt()",
                                                 WSAGetLastError(),
                                                 ERRORAT_SO );
            }
        }
    }

    void dsd_tcpcomp::mc_set_sndbuf( int imp_sndbuf ) {
        int iml_rc; /* return value            */
        dsd_tcpcallback_p   adsl_callback;

        adsl_callback = this->ads_callback;

        /* set send buffer                                                  */
        iml_rc = setsockopt( ds_sock, SOL_SOCKET, SO_SNDBUF, (const char *) &imp_sndbuf, sizeof(int) );
        if (iml_rc != 0) { /* error occured           */
#ifdef TRACE
            printf( "hob-tcpco1.hpp %05d setsockopt() returned %d error %d.",
                    __LINE__, iml_rc, WSAGetLastError() );
#endif
            if (  adsl_callback != NULL &&
                  adsl_callback->am_errorcallback != NULL) {
                adsl_callback->am_errorcallback( this, this->ads_usrfld,
                                                 "Error setsockopt()",
                                                 WSAGetLastError(),
                                                 ERRORAT_SO );
            }
        }
    }

    void dsd_tcpcomp::mc_set_rcvbuf( int imp_rcvbuf ) {
        int iml_rc; /* return value            */
        dsd_tcpcallback_p   adsl_callback;

        adsl_callback = this->ads_callback;

        /* set send buffer                                                  */
        iml_rc = setsockopt( ds_sock, SOL_SOCKET, SO_RCVBUF, (const char *) &imp_rcvbuf, sizeof(int) );
        if (iml_rc != 0) { /* error occured           */
#ifdef TRACE
            printf( "hob-tcpco1.hpp %05d setsockopt() returned %d error %d.",
                    __LINE__, iml_rc, WSAGetLastError() );
#endif
            if (  adsl_callback != NULL &&
                  adsl_callback->am_errorcallback != NULL) {
                adsl_callback->am_errorcallback( this, this->ads_usrfld,
                                                 "Error setsockopt()",
                                                 WSAGetLastError(),
                                                 ERRORAT_SO );
            }
        }
    }

    void dsd_tcpcomp::mc_set_keepalive ( int imp_optval ) {
        int                 iml_rc_so;
        dsd_tcpcallback_p   adsl_callback;

        adsl_callback = this->ads_callback;

        iml_rc_so = setsockopt( ds_sock, SOL_SOCKET,
                                SO_KEEPALIVE, (const char*) &imp_optval,
                                sizeof(int) );
        if (iml_rc_so != 0) {
#ifdef TRACE
            printf( "%05d setsockopt() returned %d error %d.",
                     __LINE__, iml_rc_so, WSAGetLastError() );
#endif
            if (   adsl_callback != NULL &&
                   adsl_callback->am_errorcallback != NULL) {
                adsl_callback->am_errorcallback( this, this->ads_usrfld,
                                                 "Error setsockopt()",
                                                 WSAGetLastError(),
                                                 ERRORAT_SO );
            }
        }
    }

#ifndef B120324
    inline void dsd_tcpcomp::mc_int_close( void ) {
      int iml_rc;                           /* return value            */
      dsd_tcphandle dsl_temp_sock;

      EnterCriticalSection( &ds_critsect );
      dsl_temp_sock = this->ds_sock;        /* save socket             */
      this->ds_sock = INVALID_SOCKET;       /* mark socket invalid     */
      LeaveCriticalSection(&ds_critsect);
      if (dsl_temp_sock == INVALID_SOCKET) return;
      iml_rc = closesocket( dsl_temp_sock );
      if (iml_rc == 0) return;              /* no error occured        */
// to-do display error message
    }
#endif

    /**
     * private method dsd_tcpcomp::mc_remove_entry
     *  remove given connection from tcpcomp list, means
     *   -> close socket
     *   -> delete event
     *   -> free resources
     * NOTE: this function get called from tcpcomp-thread
     *
     * @author      Alexander Kretzschmar
     * @param[in]   int     inp_conn        connection index
     * @return      nothing
    */
    inline void dsd_tcpcomp::mc_remove_entry( int imp_conn )
    {
        BOOL              bol_free;
        dsd_tcpcallback_p adsl_callback;
        dsd_tcpthread_p   adsl_thread;

#ifdef TRACE
        printf( "hob-tcpco1.hpp l%05d remove entry\n", __LINE__ );
#endif

        adsl_thread = this->ads_thread;
#define ADSL_CUR_SESSION (adsl_thread->dsr_tcpconn[imp_conn])
#define ADSL_CUR_EVENT (adsl_thread->dsr_waitevent[imp_conn+1])

        /* reset callback methods */
        adsl_callback = ADSL_CUR_SESSION ->ads_callback;
        ADSL_CUR_SESSION->ads_callback = NULL;

        /* close socket and event */
#ifndef B120324
        ADSL_CUR_SESSION ->mc_int_close();
#else
        closesocket(ADSL_CUR_SESSION->ds_sock);
#endif
        CloseHandle(ADSL_CUR_EVENT);

        /* should we delete the memory also? */
        bol_free = ADSL_CUR_SESSION->boc_storage;

#ifdef B121120
        /* free ineta and call cleanup */
        if (    (adsl_callback != NULL)
             && (adsl_callback->amc_free_target_ineta)
             && (ADSL_CUR_SESSION->ads_target_ineta) ) {
#ifdef DEBUG_POLL_TIME
            ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->amc_free_target_ineta;
            ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
            adsl_callback->amc_free_target_ineta( ADSL_CUR_SESSION,
                                                  ADSL_CUR_SESSION->ads_usrfld,
                                                  ADSL_CUR_SESSION->ads_target_ineta );
        }
#endif
        if (    (adsl_callback != NULL)
             && (adsl_callback->amc_cleanup) ) {
#ifdef DEBUG_POLL_TIME
            ads_thread->av_last_callbacks[ads_thread->in_cb_called] = (void*) adsl_callback->amc_cleanup;
            ads_thread->in_cb_called = (ads_thread->in_cb_called == MAX_CB_CALLED) ? 0 : ads_thread->in_cb_called + 1;
#endif
            adsl_callback->amc_cleanup( ADSL_CUR_SESSION, ADSL_CUR_SESSION->ads_usrfld );
        }

        /* delete this connection if needed */
        if ( bol_free ) {
#ifdef DEF_RELEASE
            mc_set_ref_conn( imp_conn ); /* store connection in chain */
#else
            delete ADSL_CUR_SESSION;
#endif
        }

        /* move session and events */
        EnterCriticalSection(&ds_critsect);
        adsl_thread->im_concount--;
#ifdef TRACE
        printf( "hob-tcpco1.hpp l%05d dsd_tcpcomp::mc_remove_entry() ads_thread=%p im_concount=%d\n",
                __LINE__, adsl_thread, adsl_thread->im_concount );
#endif
        if ( imp_conn < adsl_thread->im_concount ) {
#ifdef TRACE
            printf( "l%05d Remove empty event\n", __LINE__ );
#endif
            memmove( &ADSL_CUR_SESSION,
                     &adsl_thread->dsr_tcpconn[imp_conn + 1],
                     (adsl_thread->im_concount - imp_conn) * sizeof(class dsd_tcpcomp*) );
            memmove( &ADSL_CUR_EVENT,
                     &adsl_thread->dsr_waitevent[imp_conn + 2],
                     (adsl_thread->im_concount - imp_conn) * sizeof(dsd_eventtype) );
        }
        LeaveCriticalSection(&ds_critsect);
#undef ADSL_CUR_SESSION
#undef ADSL_CUR_EVENT
    } /* end of dsd_tcpcomp::mc_remove_entry */

#ifdef DEF_RELEASE
    /**
     * private method dsd_tcpcomp::mc_set_ref_conn
     * -- set referred connection --
     * stores given conncetion in chain together with
     * the current timestamp in order to do a
     * deferred release.
     * NOTE: this function get called from tcpcomp-thread
     *
     * @author      Alexander Kretzschmar
     * @param[in]   int     inl_conn        connection index
     * @return      nothing
    */
    inline void dsd_tcpcomp::mc_set_ref_conn(int inl_conn) {

        dsd_tcpthread_p   adsl_thread;
        BOOL              bol_ret;

#ifdef TRACE
        printf( "hob-tcpco1.hpp l%05d mc_set_ref_conn\n", __LINE__ );
#endif

        adsl_thread = this->ads_thread;
        bol_ret     = this->boc_storage;

        if (bol_ret == TRUE ||
            bol_ret == FALSE) {  /* boc_storage could be not only true and false, but also
                                  * a negative number, which means that we have an invalid
                                  * session and in that case adsl_thread->ads_def_rel is
                                  * not defined
                                  */

            EnterCriticalSection(&ds_critsect);
            dsd_def_release_p adsl_new_rel;
            dsd_def_release_p adsl_def_release;

            adsl_new_rel               = new dsd_def_release_t;
            adsl_new_rel->adsc_next    = NULL;
            adsl_new_rel->adsc_cur_ses = adsl_thread->dsr_tcpconn[inl_conn];
            adsl_new_rel->in_timestamp = mc_get_time();

            adsl_def_release = ads_thread->ads_def_rel;
            if ( adsl_def_release == NULL ) {
                ads_thread->ads_def_rel = adsl_new_rel;
            } else {
                while ( adsl_def_release->adsc_next != NULL ) {
                    adsl_def_release = adsl_def_release->adsc_next;
                }
                adsl_def_release->adsc_next = adsl_new_rel;
            }
            LeaveCriticalSection(&ds_critsect);
        }



    } /* end of dsd_tcpcomp::mc_set_rel_conn*/

    /**
     * private method dsd_tcpcomp::mc_get_time
     * returns the current time in seconds
     *
     * NOTE: Although not defined, this is almost always a integral value holding
     * the number of seconds since 00:00, Jan 1 1970 UTC, corresponding to POSIX time.
     *
     * @author      Alexander Kretzschmar
     * @param[in]   nothing
     * @return      time in seconds
    */

    inline int dsd_tcpcomp::mc_get_time() {

        time_t      inl_time;

#ifdef TRACE
        printf( "hob-tcpco1.hpp l%05d mc_get_time\n", __LINE__ );
#endif

        //tm*         atim_now;
        inl_time =  time ( NULL );
        //atim_now =  localtime( &inl_time );

        //int inl_sum = atim_now->tm_hour*100 + atim_now->tm_min;
        return inl_time;
    } /* end of dsd_tcpcomp::mc_get_time */
#endif

#ifdef DEF_TC_OWN_NS
}
#endif

#endif // TCPCOMP
#else // end of Windows Implementation - begin linux/unix
#ifndef TCPCOMP
#ifndef __ccdoc__
#define TCPCOMP
#endif
//#define TRACE
/*****************************************************************************/
/* Project: TCPCOMP                                                          */
/* Source: ntcpco1.hpp                                                       */
/* Description: header containing TCPCOMP definition                         */
/*                                                                           */
/* Copyright 2005 HOB GmbH & Co. KG                                          */
/*                                                                           */
/* Created by: THO                                                           */
/* Creation Date: 26.01.2005                                                 */
/*                                                                           */
/* Update:                                                                   */
/* 2012/3/13: AK: Added macros for add and delete POLLIN                     */
/*                deleted unneeded bo_recv                                   */
/*                                                                           */
/* Operating system(architecture): Unix                                      */
/*                                                                           */
/* Compile with: C++ compiler                                                */
/*                                                                           */
/*                                                                           */
/* Changed by:                                                               */
/*                                                                           */
/*****************************************************************************/
/**
 * @pkg tcpcomp
 */
/**
 * Non blocking TCP/IP for Unix.
 * @version 2005/01/26.
 * @author THO
 * @pkgdoc tcpcomp
 */

#ifndef HL_LINUX
//#ifdef B110811
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/uio.h>
#include <limits.h>
#endif

//define TRACE
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
#ifndef SOCKET
#define SOCKET int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#endif

#ifdef DEF_EPOLL
#include <sys/epoll.h>
#include <sys/utsname.h>
//#include "hob-refcnt.hpp"
#define DEF_TCPC_ADDNEW     0
#define DEF_TCPC_DEL        1
#define DEF_TCPC_RECV       2
#define DEF_TCPC_SENDNOTIFY 3
/** Maximum number of connections one thread can handle. */
//#define TCPCOMP_MAXCONN_EPOLL     1023
#ifndef MAKEKERNELVERSIONNUMBER
#define MAKEKERNELVERSIONNUMBER(ver, maj, min) (unsigned int) ((ver << 16) & 0x00FF0000) | \
                                                        ((maj <<  8) & 0x0000FF00) | \
                                                        (min & 0x000000FF)
#endif

#include <iostream>
#include "hob-xslhcla1.hpp"

using namespace std;

#ifndef BOOL
#define BOOL int
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif



// small blocks placed on the large boundaries
typedef struct dsd_chunk
{
    union {
        struct dsd_chunk* adsc_next; // if not used then points to the next free chunk
        int imc_counter;// if active used for counter
    };
    dsd_hcla_critsect_1 dsc_lock; // chunk lock object
    BOOL boc_valid;// status
}chunk_t;

// saves the large blocks used for debug (memory leaks)
typedef struct dsd_boundaries
{
    dsd_boundaries* adsc_next;
    chunk_t* adsc_chunks;

}boundaries_t;

// reference conter storage
class dsd_cntstor
{
    static boundaries_t* adsc_anchor; // all of allocated boundaries chain
    static chunk_t* adsc_nextfree;// next free chunk
    static dsd_hcla_critsect_1 dsc_storlock;// storage lock object
public:
    static chunk_t* mc_getnextfree();// returns the free reference conter chunk
    static void mc_release(chunk_t* adsp_forrel);// release the chunk after the conters lost the last reference
    static void mc_init();// initialize conter storage object
    static void mc_shutdown();// clean up of conter storage object
    dsd_cntstor();
    virtual ~dsd_cntstor() = 0;// is not instantiatable
};

// reference counter object
class dsd_refcnt
{
    void* avoc_content; // protected object
    chunk_t* adsc_counter;// reference counter tracking struct (global data)
    int imc_flags;// local data

    void* operator new(size_t);// prevent dynamically creation - empty
    void* operator new(size_t, void*);// prevent dynamically creation - defined need to use intern
    void* operator new[](size_t);// prevent dynamically creation - empty
public:

    dsd_refcnt();
    dsd_refcnt(const dsd_refcnt& );// copy constructor
    //dsd_refcnt(const dsd_refcnt&, int);     // construct and set flags
    dsd_refcnt(void* avop_content);// construct with an object
    dsd_refcnt& operator = (dsd_refcnt& );// assignment operator by ref counter object
    dsd_refcnt& operator = (void* );// assignment operator by the protected object
    ~dsd_refcnt();

    void* mc_getobj();// get the content - protected object
    void mc_invalidate();// set status to invalid
    BOOL mc_isvalid();// checks the status

    void mc_destruct_stackless();// call the destructor for objects wich were not created on stack
                                 // used for destruction of received objects
                                 // is equal to: obj = NULL;
    void mc_prevent_destruct();// prevent destruction of an object thru the destructor
                               // used for sending objects
    void mc_setflags(int);
    int mc_getflags();
};

#endif

#define DEF_ADD_EVENT(x,y) ((x) |= (y))
#define DEF_RM_EVENT(x,y)  ((x) = ((x) &~(y)))
#define DEF_IS_SET(x,y)    (((x) & (y))==(y))

//#include <hob-netw-01.h>

/**
 * gather structure definition for dsd_tcpcomp::m_send_gather()
 */
#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 { /* gather input data       */
    struct dsd_gather_i_1 *adsc_next; /* next in chain           */
    char * achc_ginp_cur; /* current position        */
    char * achc_ginp_end; /* end of input data       */
};
#endif

#ifndef B150812
#ifndef HL_SOLARIS
#define DEF_POLL_CONN (POLLIN | POLLOUT)
#else
#define DEF_POLL_CONN POLLIN
#endif
#endif
// Defines
/** Maximum number of connections one thread can handle. */
#define TCPCOMP_MAXCONN 63
/** Error location flag: stopconn. */
#define ERRORAT_STOPCONN 1
/** Error location flag: connect. */
#define ERRORAT_CONNECT 2
/** Error location flag: recv. */
#define ERRORAT_RECV 3
/** Error location flag: send. */
#define ERRORAT_SEND 4
/** Error location flag: tcpthread. */
#define ERRORAT_TCPTHREAD 5
/** Error location flag: close socket. */
#define ERRORAT_CLOSE 6
/** Error location flag: startconn. */
#define ERRORAT_STARTCONN 7
/** Error location flag: accept */
#define ERRORAT_ACCEPT 8
#define ERRORAT_SO     9
// Error numbers:
/**  Error: No error. */
#define TCPCOMP_ERROR_NONE 0
/** Error: startup called twice. */
#define TCPCOMP_ERROR_ALREADYRUNNING (-1000)
/** Error: Unable to create thread. */
#define TCPCOMP_ERROR_NOTHREAD (-1001)
/** Error: Illegal parameter (=null) */
#define TCPCOMP_ERROR_NULLPARAM (-1002)
/** Error: No more addresses to connect to.*/
#define TCPCOMP_ERROR_NOADDRESS (-1003)
// End of defines

// Classes and structures
/** Type for TCP connection handle. */
typedef int dsd_tcphandle;
/** Type thread handle. */
typedef pthread_t dsd_threadhandle;
/** Type for event handle. */
typedef struct pollfd* dsd_eventtype;

#ifndef __ccdoc__
extern "C" {
static void* m_starttcpthread(void*); // tcp/ip wait thread method
#ifdef DEF_EPOLL
        void* m_estarttcpthread(void*); // tcp/ip wait thread method
#endif
}
#endif

extern "C" int m_hlnew_printf( int, char *, ... );

class dsd_tcpcomp;
// forward declaration

/**
 * This structure contains the set of callback routines used to inform
 * the calling programm about network events ( and errors).
 */
typedef struct dsd_tcpcallback {
    void (*am_connerrcallback)(dsd_tcpcomp *, void *, struct sockaddr *adsp_soa,
            socklen_t imp_len_soa, int imp_current_index, int imp_total_index,
            int imp_errno); /* connect failed function */
#ifdef B121120
    void (*am_conncallback)(dsd_tcpcomp *, void *, struct sockaddr *adsp_soa,
            socklen_t imp_len_soa, int imp_error); /* connect callback function */
#else
    void (*am_conncallback)( dsd_tcpcomp *, void *, struct dsd_target_ineta_1 *adsp_server_ineta, void * ap_free_ti1, struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_error ); /* connect callback function */
#endif
    void (*am_sendcallback)(dsd_tcpcomp *, void *); /* send callback function */
    int (*am_getrecvbuf)(dsd_tcpcomp *, void *, void **, char **, int **); /* get receive buffer callback function */
    int (*am_recvcallback)(dsd_tcpcomp *, void *, void *); /* receive callback function */
    void (*am_errorcallback)(dsd_tcpcomp *, void *, char *, int, int); /* error callback function */
    void (*amc_cleanup)(dsd_tcpcomp *, void *); /* cleanup callback function */
    int (*amc_get_random_number)(int); /* get random number       */
#ifdef B121120
    void (*amc_free_target_ineta)(dsd_tcpcomp *, void *,
            const struct dsd_target_ineta_1 *); /* free target INETA */
#endif
} dsd_tcpcallback_t;
typedef dsd_tcpcallback_t* dsd_tcpcallback_p;

/**
 * Structure for list of stopped connections.
 */
typedef struct dsd_stopped {
    struct dsd_stopped* ads_next; // next element
    class dsd_tcpcomp* ads_stopped; // stopped connection
    BOOL bo_close; // close socket
} dsd_stopped_t;
typedef dsd_stopped_t* dsd_stopped_p;


#ifdef DEF_RELEASE
/**
 * Structure for a list with sessions which have to be
 * deferred deleted.
 * The wait thread looks through this list and
 * deletes the session after 2 mins.
 * Due to KB we should not delete the session directly
 *
 * The corresponding switcher is #ifdef DEF_RELEASE
 *
 */
typedef struct dsd_def_release {
    struct dsd_def_release* adsc_next;    /* Next element in chain */
    class dsd_tcpcomp*      adsc_cur_ses; /* stored session which has to be deleted */
    int                     in_timestamp; /* time in seconds */
}dsd_def_release_t;
/* Pointer to a released session */
typedef dsd_def_release_t* dsd_def_release_p;
#endif

typedef void (*md_at_thr_start)(int); // TCPCOMP Start thread callback function declaration

/**
 * This structure defines an element of a TCP/IP wait thread.chain.
 */
typedef struct dsd_tcpthread {
    struct dsd_tcpthread* ads_next; // next in chain

    dsd_threadhandle ds_threadhandle; // handle for this thread

    class dsd_tcpcomp* dsr_tcpconn[TCPCOMP_MAXCONN + 1]; // array of connection
    struct pollfd dsr_waitevent[TCPCOMP_MAXCONN + 1]; // array of corresponding poll structures
    int im_concount; // number of active connections
    dsd_stopped_p ads_stopchain; // chain of stopped connections
    BOOL bo_cleanup; // cleanup all
    int imr_pipefd[2]; // descriptor for eventpipe
    // AG 10.10.2006 begin
    pthread_mutex_t ds_thrcritsect;
    static md_at_thr_start amc_at_thread_start; // start thread callback function address,
                                                // called at new tcpcomp thread start
                                                // if was set at m_startup()
#ifdef DEF_RELEASE
    dsd_def_release_p ads_def_rel;  /* Anchor for chain of connections to be deleted */
#endif
    inline dsd_tcpthread();
    inline ~dsd_tcpthread();
    // AG 10.10.2006 end
} dsd_tcpthread_t;
typedef dsd_tcpthread_t* dsd_tcpthread_p;

dsd_tcpthread::dsd_tcpthread() {
    ads_next = NULL;
    ds_threadhandle = (dsd_threadhandle) NULL;
    memset( &dsr_tcpconn, 0, sizeof(dsr_tcpconn) );
    memset( &dsr_waitevent, 0, sizeof(dsr_waitevent) );
    im_concount = 0;
    ads_stopchain = 0;
    bo_cleanup = FALSE;
#ifdef DEF_RELEASE
    ads_def_rel = 0;
#endif
    pthread_mutex_init( &ds_thrcritsect, NULL );
}

dsd_tcpthread::~dsd_tcpthread() {
    pthread_mutex_destroy( &ds_thrcritsect );
}

#ifdef DEF_EPOLL
/**
 * This structure defines an element of a TCP/IP wait thread.chain.
 */
typedef struct dsd_etcpthread
{
    dsd_threadhandle ds_threadhandle; // handle for this thread
    int imc_epoll_fd;
    //class dsd_tcpcomp* dsr_tcpconn[TCPCOMP_MAXCONN+1];// array of connection
    struct epoll_event dsr_waitevent[TCPCOMP_MAXCONN+1];// array of corresponding poll structures
    BOOL bo_cleanup;// cleanup all
    int imr_pipefd[2];// descriptor for eventpipe
    static md_at_thr_start amc_at_thread_start;// start thread callback function address,
                                               // called at new tcpcomp thread start
                                               // if was set at m_startup()
    inline dsd_etcpthread();
    inline ~dsd_etcpthread();
}dsd_etcpthread_t;
typedef dsd_etcpthread_t* dsd_etcpthread_p;

dsd_etcpthread::dsd_etcpthread() {
    ds_threadhandle = (dsd_threadhandle)NULL;
    memset(&dsr_waitevent, 0, sizeof(dsr_waitevent));
    bo_cleanup = FALSE;
}

dsd_etcpthread::~dsd_etcpthread() {

}

#endif // DEF_EPOLL
/**
 * This class implements an interface for performing nonblocking TCP/IP
 * operations on multiple connections. Each instance maps to one
 * TCP/IP connection.
 */
class dsd_tcpcomp {
// static members
    /** Anchor for tcp threads. */
    static dsd_tcpthread_p ads_thranc;

    /**
     * Create a new TCP work thread.
     * @return address of the thread structure for the newly created thread.
     */
    inline static dsd_tcpthread_p m_createnewthread();
#ifdef DEF_EPOLL
    static dsd_etcpthread_p adsc_ethranc;
    static dsd_etcpthread_p mc_ecreatenewthread();
    static unsigned int umsc_minreqver_2_5_66;
#endif
#ifndef B130420
private:
    /** Socket to work with. */
    dsd_tcphandle ds_sock;
#endif
public:
    /** Mutex for safe access to ressources. */
    static pthread_mutex_t ds_critsect;
    /**
     * Initialise dsd_tcpcomp.
     * @param amp_at_thread_start optional parameter - callback address of function which is called after a new thread was created
     * @return TRUE if successful, otherwise FALSE.
     */
    inline static int m_startup(md_at_thr_start amp_at_thread_start = NULL);
    /**
     * Cleanup everything.
     * @return TRUE if successful, otherwise FALSE.
     */
    inline static int m_shutdown();
    /**
     * Create a new conection.
     * @param ds_sock socket used.
     * @param ads_callback structure containing the necessary callback functions.
     * @param ads_usrfld pointer to user data.
     * @return pointer to the newly created tcpcomp object, NULL if an error occurred.
     */
    inline static dsd_tcpcomp* m_startconn(dsd_tcphandle ds_sock,
            dsd_tcpcallback_p ads_callback, void* ads_usrfld);
// instance members
    /** Last error occurred (OS dependent). */
    int im_error;
    /**
     * Stop processing this connection.
     * @param bo_close close the underlying socket.
     * @param bo_thread delete connection from thread.
     * @return TRUE if successful, otherwise FALSE.
     */
    inline void m_stopconn(BOOL bo_close, BOOL bo_thread = TRUE);

    inline int m_startco_fb(int, dsd_tcpcallback_p, void *);
    inline int m_startco_bind_conn_fix(dsd_tcpcallback_p, void *,
            struct sockaddr *, socklen_t, struct sockaddr *, socklen_t);
    inline void m_end_session(void);
    /**
     * Non-blocking connect.
     * @param str_ip ipadress to connect.
     * @param str_port ip port to conect.
     * @return TRUE if successful, otherwise FALSE.
     */
    inline int m_connect(char* str_ip = NULL, char* str_port = NULL);
    /**
     * Called, when TCPCOMP should start receiving again.
     * @return TRUE if successful, otherwise FALSE.
     */
    inline int m_recv();
    /**
     * Non-blocking send.
     * @param ach_data address of data to send.
     * @param im_len length of data to send.
     * @return number of bytes send, if < im_len => blocked, -1 = error,
     */
    inline int m_send(char *ach_data, int im_len);

    /**
     * Non-blocking writev test
     * @param ads_gatherinp pointer to the input gather chain
     * @param aads_gatherout pointer to the pointer gather - output parameter
     * @param aimp_rc 0 ok, -1 error
     * if *aads_gatherout is equal NULL all of data was sent if not NULL
     * the first gather wich is incomplete sent
     * @return number of bytes send, if < im_len => blocked
     */
    inline int m_send_gather(dsd_gather_i_1 *ads_gatherinp,
            dsd_gather_i_1** aads_gatherout, int* aimp_rc = NULL);
    /*
     * Application wants to be notified when send is possible again.
     */
    inline void m_sendnotify();
    /**
     * Starting connection: bind if needed execute non blocking connect till any first was successfuly or all failed
     * @param adsp_callback
     * @param vpp_userfld
     * @param adsp_target_ineta
     * @param adsp_bind_ineta
     */
    inline int m_startco_mh(dsd_tcpcallback_p adsp_callback, void * vpp_userfld,
            const struct dsd_bind_ineta_1* adsp_bind_ineta,
            const struct dsd_target_ineta_1* adsp_target_ineta,
#ifndef B121121
            const void * ap_free_ti1,
#endif
            unsigned short usp_port, BOOL bop_round_robin = FALSE);
    /**
     *  disable/enable the Naegle Algorithm
     */
    inline void mc_set_nodelay(int imp_optval);
    /**
     * set size of the TCP send buffer
     */
    inline void mc_set_sndbuf(int imp_sndbuf);
    /**
     * set size of the TCP receive buffer
     */
    inline void mc_set_rcvbuf(int imp_rcvbuf);
    /**
     * set Socket Option SO_KEEPALIVE
     */
    inline void mc_set_keepalive ( int imp_optval );

#ifndef B130420
    inline int mc_getsocket( void ) {
      return ds_sock;
    } /* end dsd_tcpcomp::mc_getsocket()                               */
#endif

    inline static void m_tcpthread(void*);
#ifdef DEF_EPOLL
    static int mc_estartup(md_at_thr_start amp_at_thread_start = NULL);
    static int mc_eshutdown();
    static dsd_tcpcomp* mc_estartconn(dsd_tcphandle ds_sock,
            dsd_tcpcallback_p ads_callback,
            void* ads_usrfld);
    void mc_estopconn(BOOL bo_close, BOOL bo_thread = TRUE);
    int mc_estartco_fb( int, dsd_tcpcallback_p, void * );
    void mc_eend_session( void );
    int mc_econnect(char* str_ip = NULL, char* str_port = NULL);
    int mc_erecv();
    int mc_esend(char *ach_data, int im_len);
    void mc_esendnotify();
    int mc_estartco_mh(dsd_tcpcallback_p adsp_callback, void* vpp_userfld,
            const struct dsd_target_ineta_1* adsp_target_ineta,
            const struct dsd_bind_ineta_1* adsp_bind_ineta,
            unsigned short usp_port, BOOL bop_round_robin = FALSE );
    static void mc_etcpthread(void*);
#endif
private:
    inline BOOL mc_connect_notify(int imp_events);
    /**
     * Receive data.
     */
    inline bool m_recvdata();
#ifdef DEF_RELEASE
    inline void mc_set_ref_conn ( int inl_conn );
    inline int  mc_get_time     ( void );
#endif

    /** Structure with callback methods. */
    dsd_tcpcallback_p ads_callback;
#ifdef B130420
    /** Socket to work with. */
    dsd_tcphandle ds_sock;
#endif
    /** User specific data. */
    void* ads_usrfld;
    const void* aps_free_ti1;
    /** Corresponding thread object. */
    dsd_tcpthread_p ads_thread;
    /** Notify that send is possible. */
    BOOL bo_sendnot;
    /** Data could be send. */
    BOOL bo_sendok;
    /** Receive allowed. */
    BOOL bo_recv;
    /** Receive data available. */
    BOOL bo_data;BOOL boc_storage; /* storage has been acquired */
    BOOL boc_end; /* end has been set        */

    /** Notify that connect has happend. */
    BOOL bo_connot;
#ifdef NEW_KB_110811                        /* problems with bo_connot */
    BOOL boc_do_connect; /* connect needs to be done */
#endif
    /** The socket is a listener. */
    //BOOL bo_listener;
    /** Pointer to address array. */
    //struct nd_addrlist* ads_findsock;
    struct addrinfo* ads_findsock;
    /** Current address. */
    //struct netbuf* ads_findcur;
    struct addrinfo* ads_findcur;
    /** Current dsd_target_ineta_1 used for running connect attempt. */
    const dsd_target_ineta_1* adsc_target_ineta;
    const dsd_bind_ineta_1* adsc_bind_ineta;
    /** Port nummer for connect*/
    unsigned short usc_port;
    /** Current ineta number */
    int imc_ineta_curno;
    /** */
    BOOL boc_mhconnect; // multihomed connect mode
#ifndef B110915
    sockaddr_storage dsc_soa_connect;
#endif
    /**
     * Non-blocking connect.
     * @return TRUE if successful, otherwise FALSE.
     */
    inline int m_connect_mh(sockaddr_storage* adsp_sockaddr, socklen_t dsp_len);
    inline SOCKET ms_socket(unsigned short usp_family,
            const dsd_bind_ineta_1* adsp_bind_ineta);
#ifdef DEF_EPOLL
    int mc_econnect_mh(sockaddr_storage* adsp_sockaddr, socklen_t dsp_len);
    BOOL mc_econnect_notify(int imp_events);
    dsd_etcpthread_p adsc_ethread;
    dsd_refcnt dsc_refcnt; // reference conter object
    static BOOL boc_epoll;// epoll function set used
    /**
     * remove entry
     * 1. param epoll descriptor
     * 2. current position on event array
     * 3. the size of current event array
     * 2. and 3. used for invalidate the event cache
     */
    void mc_eremove_entry(int, int, int);
    int mc_esend_notification(int imp_cmd);
#endif
};
// class dsd_tcpcomp
// End of classes and structures

dsd_tcpcomp* dsd_tcpcomp::m_startconn(dsd_tcphandle ds_sock,
        dsd_tcpcallback_p ads_callback, void* ads_usrfld) {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return dsd_tcpcomp::mc_estartconn(ds_sock, ads_callback, ads_usrfld);
#endif
    dsd_tcpcomp* ads_newcon; // new connection object
    dsd_tcpthread_p ads_thrcur; // current thread object
    dsd_tcpthread_p ads_thrlast; // last thread in chain

#ifdef TRACE
    m_hlnew_printf(123, "m_startconn\n");
#endif
    if ( ds_sock == -1 || !ads_callback || !ads_usrfld
            || !ads_callback->am_getrecvbuf
            || !ads_callback->am_recvcallback ) {
#ifdef TRACE
        m_hlnew_printf(123, "Parameter is null\n");
#endif
        return NULL;
    }

    ads_newcon = new dsd_tcpcomp();
    if ( !ads_newcon ) {
#ifdef TRACE
        m_hlnew_printf(123, "Unable to allocate memory for new connection object\n");
#endif
        return NULL;
    }
    // Init connection object
    ads_newcon->boc_storage = TRUE; /* storage has been acquired */
    ads_newcon->boc_end = FALSE; /* end has not been set    */
    ads_newcon->bo_sendnot = FALSE;
    ads_newcon->bo_data = FALSE;
    ads_newcon->bo_sendok = TRUE;
    ads_newcon->bo_recv = FALSE;
    ads_newcon->boc_mhconnect = FALSE; //AK 18.11.11
    //ads_newcon->bo_connot = FALSE;
    if ( ads_callback->am_conncallback != NULL )
        ads_newcon->bo_connot = TRUE;
    else
        ads_newcon->bo_connot = FALSE;
#ifdef NEW_KB_110811                        /* problems with bo_connot */
    ads_newcon->boc_do_connect = FALSE; /* connect needs to be done */
#endif
    ads_newcon->ds_sock = ds_sock;
    ads_newcon->ads_callback = ads_callback;
    ads_newcon->ads_usrfld = ads_usrfld;
    ads_newcon->aps_free_ti1 = NULL;
    ads_newcon->im_error = 0;
    ads_newcon->ads_findsock = 0;
    ads_newcon->ads_findcur = 0;

    if ( fcntl( ds_sock, F_SETFL, O_NONBLOCK ) != 0 ) //Set socket to non-blocking mode
            {
#ifdef TRACE
        m_hlnew_printf(123, "Unable to set socket for non-blocking operation: %d\n", errno);
#endif
        delete ads_newcon;
        return NULL;
    }
    // now find a thread to handle this connection
    pthread_mutex_lock( &ds_critsect );
    ads_thrlast = ads_thrcur = ads_thranc;
    while ( ads_thrcur ) {
        if ( ads_thrcur->im_concount < TCPCOMP_MAXCONN ) {
            break;
        }
        ads_thrlast = ads_thrcur;
        ads_thrcur = ads_thrcur->ads_next;
    }
    if ( !ads_thrcur ) // no more space in threads, create new one
    {
        pthread_mutex_unlock( &ds_critsect );
        ads_thrcur = m_createnewthread();
        if ( !ads_thrcur ) {
#ifdef TRACE
            m_hlnew_printf(123, "Unable to start a thread for this connection\n");
#endif
            delete ads_newcon;
            return NULL;
        }
        pthread_mutex_lock( &ds_critsect );
        if ( !ads_thranc ) {
            ads_thranc = ads_thrcur;
        } else {
            ads_thrlast = ads_thranc;
            while ( ads_thrlast ) {
                if ( !ads_thrlast->ads_next ) {
                    ads_thrlast->ads_next = ads_thrcur;
                    break;
                }
                ads_thrlast = ads_thrlast->ads_next;
            }
        }
    }
    ads_newcon->ads_thread = ads_thrcur;
    ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].fd =
            ads_newcon->ds_sock;
#ifdef B150812
    ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].events = POLLIN
#ifndef HL_SOLARIS
            | POLLOUT
#endif
            ;
#endif
#ifndef B150812
    ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].events = DEF_POLL_CONN;
#endif
    ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].revents = 0;
    ads_thrcur->dsr_tcpconn[ads_thrcur->im_concount + 1] = ads_newcon;
    ads_thrcur->im_concount++;
    pthread_mutex_unlock( &ds_critsect );
    write( ads_thrcur->imr_pipefd[1], &ads_thrcur, sizeof(ads_thrcur) ); // Tell thread to handle this connection
#ifdef TRACE
            m_hlnew_printf(123, "pipe event fired in m_startconn()\n");
#endif
    return ads_newcon;
} // dsd_tcpcomp* dsd_tcpcomp::m_startconn(dsd_tcphandle, dsd_tcpcallback_p, void*)

int dsd_tcpcomp::m_startup(md_at_thr_start amp_at_thread_start) {
#ifdef DEF_EPOLL
    // to switch to epoll need the version 2.5.66
    if (dsd_tcpcomp::boc_epoll == FALSE && ads_thranc == NULL)
    {
        struct utsname dsl_utsname;
        unsigned int uml_ver, uml_maj, uml_min;
        char *achl_rel, chl_cur;
        if (uname(&dsl_utsname) == 0) {
            achl_rel = &dsl_utsname.release[0];
            while ((chl_cur = *achl_rel) != '\0') {
                if (chl_cur < '0' || chl_cur > '9')
                *achl_rel = ' ';
                ++ achl_rel;
            }
            if (sscanf(&dsl_utsname.release[0], "%d %d %d", &uml_ver, &uml_maj, &uml_min) == 3) {
                uml_ver = MAKEKERNELVERSIONNUMBER(uml_ver, uml_maj, uml_min);
                if (uml_ver >= umsc_minreqver_2_5_66) {
                    dsd_tcpcomp::boc_epoll = TRUE;
#ifdef TRACE
                    m_hlnew_printf(123, "TCPCOMP switched to epoll processing\n");
#endif
                }
            }
        }
    }
    if (dsd_tcpcomp::boc_epoll == TRUE)
    return dsd_tcpcomp::mc_estartup(amp_at_thread_start);
#endif
#ifdef TRACE
    m_hlnew_printf(123, "m_startup\n");
#endif
    if ( ads_thranc != NULL ) {
        return TCPCOMP_ERROR_ALREADYRUNNING;
    }
    ads_thranc = m_createnewthread();
    if ( ads_thranc == NULL ) {
        return TCPCOMP_ERROR_NOTHREAD;
    }
    pthread_mutex_init( &ds_critsect, NULL );
    dsd_tcpthread_t::amc_at_thread_start = amp_at_thread_start;
    return TCPCOMP_ERROR_NONE;
} // int class dsd_tcpcomp::m_startup()


/**
 * public functon dsd_tcpcomp::m_startco_fb
 *  add an existing socket to existing tcpcomp memory
 *  No connection callback is needed in that case!!!
 *
*/
int dsd_tcpcomp::m_startco_fb(int imp_socket, dsd_tcpcallback_p adsp_callback,
        void * vpp_userfld) {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return dsd_tcpcomp::mc_estartco_fb(imp_socket, adsp_callback, vpp_userfld);
#endif
    dsd_tcpthread_p ads_thrcur; // current thread object
    dsd_tcpthread_p ads_thrlast; // last thread in chain

#ifdef TRACE
    m_hlnew_printf(123,  "hob-tcpco1.hpp l%05d m_startco_fb this=%p\n", __LINE__, this );
#endif
    if ( imp_socket == -1 || !adsp_callback || !adsp_callback->am_getrecvbuf
            || !adsp_callback->am_recvcallback ) {
#ifdef TRACE
        m_hlnew_printf(123, "Parameter is null\n");
#endif
        return 1;
    }

    // Init connection object
    this->boc_storage = FALSE;    /* storage has not been acquired */
    this->boc_end = FALSE;        /* end has not been set    */
    this->bo_sendnot = FALSE;
    this->bo_data = FALSE;
    this->bo_sendok = TRUE;
    this->bo_recv = FALSE;
    this->boc_mhconnect = FALSE;  //AK 18.11.11
    this->bo_connot = FALSE;      //AK set bo_connot to FALSE (instead of TRUE)
#ifdef NEW_KB_110811              /* problems with bo_connot */
    this->boc_do_connect = FALSE; /* connect needs to be done */
#endif
    this->ds_sock = imp_socket;
    this->ads_callback = adsp_callback;
    this->ads_usrfld = vpp_userfld;
    this->aps_free_ti1 = NULL;
    this->im_error = 0;
    this->ads_findsock = NULL;
    this->ads_findcur = NULL;

    if ( fcntl( ds_sock, F_SETFL, O_NONBLOCK ) != 0 ) //Set socket to non-blocking mode
    {
#ifdef TRACE
        m_hlnew_printf(123, "Unable to set socket to non-blocking operation: %d\n", errno);
#endif
        return 3;
    }
    // now find a thread to handle this connection
    pthread_mutex_lock( &ds_critsect );
    ads_thrlast = ads_thrcur = ads_thranc;
    while ( ads_thrcur ) {
        if ( ads_thrcur->im_concount < TCPCOMP_MAXCONN ) {
            break;
        }
        ads_thrlast = ads_thrcur;
        ads_thrcur = ads_thrcur->ads_next;
    }
    if ( !ads_thrcur ) // no more space in threads, create new one
    {
        pthread_mutex_unlock( &ds_critsect );
        ads_thrcur = m_createnewthread();
        if ( !ads_thrcur ) {
#ifdef TRACE
            m_hlnew_printf(123, "Unable to start a thread for this connection\n");
#endif
            return 4;
        }
        pthread_mutex_lock( &ds_critsect );
        if ( !ads_thranc ) {
            ads_thranc = ads_thrcur;
        } else {
            ads_thrlast = ads_thranc;
            while ( ads_thrlast ) {
                if ( !ads_thrlast->ads_next ) {
                    ads_thrlast->ads_next = ads_thrcur;
                    break;
                }
                ads_thrlast = ads_thrlast->ads_next;
            }
        }
    }
    this->ads_thread = ads_thrcur;
    ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].fd = this->ds_sock;
#ifdef B150812
    ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].events = POLLIN
#ifndef HL_SOLARIS
            | POLLOUT
#endif
            ;
#endif
#ifndef B150812
    ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].events = DEF_POLL_CONN;
#endif
    ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].revents = 0;
    ads_thrcur->dsr_tcpconn[ads_thrcur->im_concount + 1] = this;
    ads_thrcur->im_concount++;
    pthread_mutex_unlock( &ds_critsect );
#ifdef TRACE
    m_hlnew_printf(123,  "hob-tcpco1.hpp l%05d m_startco_fb() ads_thrcur=%p im_concount=%d\n",
            __LINE__, ads_thrcur, ads_thrcur->im_concount );
#endif
    write( ads_thrcur->imr_pipefd[1], &ads_thrcur, sizeof(ads_thrcur) ); // Tell thread to handle this connection
    //sleep(3);
#ifdef TRACE
    m_hlnew_printf(123, "pipe event fired in m_startconn()\n");
#endif
    return 0;
} /* end dsd_tcpcomp::m_startco_fb()                                   */

int dsd_tcpcomp::m_startco_bind_conn_fix(dsd_tcpcallback_p adsp_callback,
        void * vpp_userfld, struct sockaddr *adsp_bind, socklen_t iml_len_bind,
        struct sockaddr *adsp_connect, socklen_t iml_len_connect) {

        int iml_rc; /* return code             */
        dsd_tcpthread_p ads_thrcur; // current thread object
        dsd_tcpthread_p ads_thrlast;// last thread in chain

#ifdef TRACE
        m_hlnew_printf(123,  "hob-tcpco1.hpp l%05d m_startco_bind_conn_fix this=%p\n", __LINE__, this );
#endif
        if (!adsp_callback ||
                !adsp_callback->am_getrecvbuf ||
                !adsp_callback->am_recvcallback) {
#ifdef TRACE
            m_hlnew_printf(123, "Parameter is null\n");
#endif
            return 1;
        }

        // Init connection object
        this->boc_storage = FALSE; /* storage has not been acquired */
        this->boc_end = FALSE; /* end has not been set    */
        this->bo_sendnot = FALSE;
        this->bo_data = FALSE;
        this->bo_sendok = FALSE;
        this->bo_recv = FALSE;
        this->bo_connot = TRUE;
        this->boc_mhconnect = FALSE; //AK 18.11.2011
        // this->ds_sock = imp_socket;
        this->ads_callback = adsp_callback;
        this->ads_usrfld = vpp_userfld;
        this->aps_free_ti1 = NULL;
        this->im_error = 0;
        this->ads_findsock = NULL;
        this->ads_findcur = NULL;

        this->ds_sock = socket ( adsp_connect->sa_family, SOCK_STREAM, IPPROTO_TCP );

        if ( fcntl( ds_sock, F_SETFL, O_NONBLOCK ) != 0 ) //Set socket to non-blocking mod
        {
#ifdef TRACE
        m_hlnew_printf(123, "Unable to set socket to non-blocking operation: %d\n", errno);
#endif
        return 3;
        }
        // now find a thread to handle this connection
        pthread_mutex_lock( &ds_critsect );
        ads_thrlast = ads_thrcur = ads_thranc;
        while(ads_thrcur)
        {
            if(ads_thrcur->im_concount < TCPCOMP_MAXCONN)
            {
                break;
            }
            ads_thrlast = ads_thrcur;
            ads_thrcur = ads_thrcur->ads_next;
        }
        if(!ads_thrcur) // no more space in threads, create new one
        {
            pthread_mutex_unlock( &ds_critsect );
            ads_thrcur = m_createnewthread();
            if(!ads_thrcur)
            {
#ifdef TRACE
                m_hlnew_printf(123, "Unable to start a thread for this connection\n");
#endif
                return 4;
            }
            pthread_mutex_lock( &ds_critsect );
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
                        ads_thrlast->ads_next = ads_thrcur;
                        break;
                    }
                    ads_thrlast = ads_thrlast->ads_next;
                }
            }
        }
        this->ads_thread = ads_thrcur;
        ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1 ].fd = this->ds_sock;
#ifdef B150812
        ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1 ].events = POLLIN
#ifndef HL_SOLARIS
            | POLLOUT
#endif
            ;
#endif
#ifndef B150812
        ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].events = DEF_POLL_CONN;
#endif
        ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].revents = 0;
        ads_thrcur->dsr_tcpconn[ads_thrcur->im_concount + 1] = this;
        ads_thrcur->im_concount++;
        pthread_mutex_unlock( &ds_critsect );
#ifdef TRACE
        m_hlnew_printf(123, "hob-tcpco1.hpp l%05d m_startco_bind_conn_fix() ads_thrcur=%p im_concount=%d\n",
                __LINE__, ads_thrcur, ads_thrcur->im_concount );
#endif
        write( ads_thrcur->imr_pipefd[1], &ads_thrcur, sizeof(ads_thrcur) ); // Tell thread to handle this

        if (iml_len_bind > 0) {
            iml_rc = bind( this->ds_sock, adsp_bind, iml_len_bind );
			if ( iml_rc != 0 ) {
#ifdef TRACE
                m_hlnew_printf(123, "Unable to bind to socket\n");
#endif
                return 5;

			}
        }
        memcpy( &this->dsc_soa_connect, adsp_connect, iml_len_connect );
        iml_rc = connect( this->ds_sock, adsp_connect, iml_len_connect );
		if ( iml_rc == 0 ) {

        } else {
            iml_rc = errno;
            if ( iml_rc != EWOULDBLOCK && iml_rc != EINPROGRESS ) {
#ifdef TRACE
                m_hlnew_printf(123, "Connect failed: %d \n", iml_rc);
#endif
                bo_connot = FALSE;
                if ( adsp_callback->am_errorcallback != NULL ) {
                    this->im_error = im_error;
                    adsp_callback->am_errorcallback( this, ads_usrfld,
                        (char*)"Connect failed", iml_rc, ERRORAT_CONNECT );
                }
				return 6;
			}

		}
    return 0;
} /* end dsd_tcpcomp::m_startco_bind_conn_fix()                        */

int dsd_tcpcomp::m_shutdown() {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return dsd_tcpcomp::mc_eshutdown();
#endif
    dsd_tcpthread_p ads_thrcur; // current thread object
    dsd_tcpthread_p ads_thrnext; // next thread object

#ifdef TRACE
    m_hlnew_printf(123, "m_shutdown\n");
#endif
    pthread_mutex_lock( &ds_critsect );
    ads_thrcur = ads_thranc;
    ads_thranc = NULL;
    while ( ads_thrcur ) {
        ads_thrnext = ads_thrcur->ads_next;
        ads_thrcur->bo_cleanup = TRUE;
        write( ads_thrcur->imr_pipefd[1], &ads_thrcur, sizeof(ads_thrcur) ); // Tell thread to cleanup.
        ads_thrcur = ads_thrnext;
    }
    pthread_mutex_unlock( &ds_critsect );
    pthread_mutex_destroy( &ds_critsect );
    return TRUE;
} // int class dsd_tcpcomp::m_shutdown()

void dsd_tcpcomp::m_stopconn(BOOL bo_close, BOOL bo_thread) {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return mc_estopconn(bo_close, bo_thread);
#endif
    dsd_stopped_p ads_stop; // new Element for stopped list
    dsd_stopped_p ads_stopnext; // pointer to find place for new element
#ifdef TRACE
    dsd_tcphandle ds_closesock; // socket to close
#endif

#ifdef TRACE
    m_hlnew_printf(123, "m_stopconn\n");
#endif
    bo_recv = false;
    //DEF_RM_EVENT(ads_thread->dsr_waitevent[ads_thread->im_concount].events, POLLIN);
    bo_sendnot = false;
    if ( ads_findsock ) {
        freeaddrinfo( ads_findsock );
        ads_findsock = 0;
    }
    if ( bo_thread ) {
        pthread_mutex_lock( &ds_critsect );
        ads_stop = new dsd_stopped_t;
        ads_stop->ads_next = NULL;
        ads_stop->ads_stopped = this;
        ads_stop->bo_close = bo_close;

        ads_stopnext = ads_thread->ads_stopchain;
        if ( ads_stopnext == NULL ) {
            ads_thread->ads_stopchain = ads_stop;
        } else {
            while ( ads_stopnext->ads_next != NULL ) {
                ads_stopnext = ads_stopnext->ads_next;
            }
            ads_stopnext->ads_next = ads_stop;
        }
        pthread_mutex_unlock( &ds_critsect );
        write( ads_thread->imr_pipefd[1], &ads_thread, sizeof(ads_thread) ); // Tell thread to handle this connection
    } else if ( bo_close ) {
#ifdef TRACE
        m_hlnew_printf(123, "Close socket: %d\n", ds_closesock);
#endif
        close( ds_sock );
    }
} // void dsd_tcpcomp::m_stopconn(BOOL bo_close, BOOL bo_thread)

void dsd_tcpcomp::m_end_session(void) {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return mc_eend_session();
#endif
    dsd_tcpcallback_p adsl_callback;

#ifdef TRACE
    m_hlnew_printf(123, "l%05d dsd_tcpcomp::m_end_session\n", __LINE__ );
#endif
    adsl_callback = this->ads_callback;
    if ( adsl_callback == NULL )
        return;
    boc_end = TRUE; /* end has been set        */
    write( ads_thread->imr_pipefd[1], &ads_thread, sizeof(ads_thread) ); // Tell thread to handle this connection
} /* end dsd_tcpcomp::m_end_session()                                  */

int dsd_tcpcomp::m_connect(char* str_ip, char* str_port) {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return mc_econnect(str_ip, str_port);
#endif
    int im_error; // error code
    //struct t_call ds_tcall;            // save current address here
    //struct nd_hostserv ds_sohint;      // input for getbyname //AG
    //struct netconfig* ads_netconf;     // netconfig structure //AG
    struct addrinfo ds_sohint; // input for getaddressinfo

#ifdef TRACE
    m_hlnew_printf(123, "m_connect\n");
#endif
    if ( ads_findsock != NULL ) // check next address
    {
        ads_findcur = ads_findcur->ai_next;
        if ( ads_findcur == NULL ) {
            freeaddrinfo( ads_findsock );
            ads_findsock = NULL;
#ifdef TRACE
            m_hlnew_printf(123, "No more addresses\n");
#endif
            if ( ads_callback->am_errorcallback != NULL ) {
                this->im_error = TCPCOMP_ERROR_NOADDRESS;
                ads_callback->am_errorcallback( this, ads_usrfld,
                        (char*)"No more addresses to connect", TCPCOMP_ERROR_NOADDRESS,
                        ERRORAT_CONNECT );
            }
            return FALSE;
        }
    } else // find first address
    {
        memset( (void*) &ds_sohint, 0, sizeof(struct addrinfo) );
        ds_sohint.ai_family = PF_INET;
        ds_sohint.ai_socktype = SOCK_STREAM;
        ds_sohint.ai_protocol = IPPROTO_TCP;
        im_error = getaddrinfo( str_ip, str_port, &ds_sohint, &ads_findsock );
        if ( im_error ) {
#ifdef TRACE
            m_hlnew_printf(123, "getaddrinfo failed for %s: %d.\n\n", str_ip, im_error);
#endif
            if ( ads_callback->am_errorcallback != NULL ) {
                this->im_error = im_error;
                ads_callback->am_errorcallback( this, ads_usrfld,
                        (char*)"getaddrinfo failed", im_error, ERRORAT_CONNECT );
            }
            return FALSE;
        }
        ads_findcur = ads_findsock;
    }
#ifdef TRACE
    m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::m_connect call connect()\n",
            __LINE__ );
#endif
    im_error = connect( ds_sock, ads_findcur->ai_addr,
            (int) (ads_findcur->ai_addrlen) );
    if ( im_error == 0 ) {
#ifdef TRACE
        m_hlnew_printf(123, "Connect doesn't return with EWOULDBLOCK. Strange\n");
#endif
    } else {
        im_error = errno;
        if ( im_error != EWOULDBLOCK && im_error != EINPROGRESS ) {
#ifdef TRACE
            m_hlnew_printf(123, "Connect failed: %d.\n\n", im_error );
#endif
            bo_connot = FALSE;
            freeaddrinfo( ads_findsock );
            ads_findsock = NULL;
            if ( ads_callback->am_errorcallback != NULL ) {
                this->im_error = im_error;
                ads_callback->am_errorcallback( this, ads_usrfld,
                        (char*)"Connect failed", im_error, ERRORAT_CONNECT );
            }
            return FALSE;
        }
    }
#ifdef TRACE
    m_hlnew_printf(123, "Connect OK\n");
#endif
    return TRUE;
} // int dsd_tcpcomp::m_connect(char* str_ip, char* str_port)

int dsd_tcpcomp::m_recv() {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return mc_erecv();
#endif
#ifdef WAIT_RECV_KB_110813                  /* problems with bo_recv   */
#ifdef TRACE
    m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::m_recv this=%p before sleep( 1 )\n",
            __LINE__, this );
#endif
    sleep( 1 );
#endif
#ifdef TRACE
    m_hlnew_printf(123, "m_recv: bo_data: %d\n", bo_data);
#endif
    //pthread_mutex_lock(&dsd_tcpcomp::ds_critsect); //AG
    //pthread_mutex_lock(&ads_thread->ds_thrcritsect); //AG
    bo_recv = TRUE;
    //DEF_ADD_EVENT(ads_thread->dsr_waitevent[ads_thread->im_concount].events, POLLIN);
    //pthread_mutex_unlock(&dsd_tcpcomp::ds_critsect); //AG
    //pthread_mutex_unlock(&ads_thread->ds_thrcritsect); //AG
//   if(bo_data)
//   {
#ifdef TRACE
    m_hlnew_printf(123, "Set Event\n");
#endif
    if ( write( ads_thread->imr_pipefd[1], &ads_thread, sizeof(ads_thread) )
            < 0 ) {
        if ( ads_callback->am_errorcallback != NULL ) {
            im_error = errno;
            ads_callback->am_errorcallback( this, ads_usrfld,
                    (char*)"Unable to set event for receive", im_error, ERRORAT_RECV );
        }
#ifdef TRACE
        m_hlnew_printf(123, "Unable to set event for receive.\n");
#endif
    }
#ifdef TRACE
    m_hlnew_printf(123, "pipe event fired in m_recv()\n");
#endif
//   }
    return TRUE;
} // int dsd_tcpcomp::m_recv();

int dsd_tcpcomp::m_send(char *ach_data, int im_len) {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return mc_esend(ach_data, im_len);
#endif
    int im_error; // error code
    int im_sendcnt; // number of bytes sent with one send
    int im_send; // total number of bytes
    dsd_tcpcallback_p adsl_callback;

#ifdef TRACE
    m_hlnew_printf(123, "m_send to %d: %d bytes. bo_data = %d\n", ds_sock, im_len, bo_data);
#endif
    im_send = 0; // nothing send yet
    do {
        bo_sendok = FALSE;
        im_sendcnt = send( ds_sock, ach_data, im_len - im_send, 0 );
        if ( im_sendcnt < 0 ) {
            im_error = errno;
#ifdef TRACE
            m_hlnew_printf(123, "Send failed in m_send: %d.\n", im_error );
#endif
            if ( im_error != EWOULDBLOCK && im_error != ENOTCONN
                    && im_error != EPIPE ) {
                adsl_callback = ads_callback;
                if ( adsl_callback && ads_callback->am_errorcallback != NULL ) {
                    this->im_error = im_error;
                    adsl_callback->am_errorcallback( this, ads_usrfld,
                            (char*)"Send failed in m_send", im_error, ERRORAT_SEND );
                }
                im_send = -1;
            }
            break;
        }
        bo_sendok = TRUE;
        im_send += im_sendcnt;
        ach_data += im_sendcnt;
    } while ( im_send < im_len );
#ifdef TRACE
    m_hlnew_printf(123, "m_send OK. Len: %d\n", im_send);
#endif
    if ( bo_sendok == FALSE ) {
        if ( write( ads_thread->imr_pipefd[1], &ads_thread, sizeof(ads_thread) )
                < 0 ) {
            adsl_callback = ads_callback;
            if ( adsl_callback && ads_callback->am_errorcallback != NULL ) {
                im_error = errno;
                adsl_callback->am_errorcallback( this, ads_usrfld,
                        (char*)"Unable to set event for stopped send", im_error,
                        ERRORAT_SEND );
            }
#ifdef TRACE
            m_hlnew_printf(123, "Unable to set event for send.\n");
#endif
        }
    }
    return im_send;
} // int dsd_tcpcomp::m_send(char *ach_data, int im_len)

int dsd_tcpcomp::m_send_gather(dsd_gather_i_1 *ads_gatherinp,
        dsd_gather_i_1** aads_gatherout, int* aimp_rc) {
    int im_error; // error code
    int im_sendcnt; // number of bytes sent with one send
    int im_send; // total number of bytes per WSASend()
    int im_len; // total number of bytes to send per WSASend()
    iovec dsrl_iovecbuf[IOV_MAX]; // buffer for writev
    int iml_bufcnt; // buffer's counter for WSASend()
    //DWORD dwl_sent;                          // number of bytes sent by WSASend()
    int iml_sent; // number of bytes counter
    int iml_senttotal; // total number of bytes sent per m_send_gather
    int iml_cur_ele; // current position index
    dsd_gather_i_1 *adsl_gatheriter; // working variable
    dsd_gather_i_1 *adsl_gathercnt; // working variable
    dsd_tcpcallback_p adsl_callback;

    if ( aimp_rc ) // AG 07.10.2008
        *aimp_rc = 0; // AG 07.10.2008
    iml_senttotal = 0;
    adsl_gatheriter = ads_gatherinp;
    while ( adsl_gatheriter ) {
        adsl_gathercnt = adsl_gatheriter;
        iml_cur_ele = 0;
        im_len = 0;
        iml_bufcnt = 0;
        while ( adsl_gatheriter && iml_bufcnt < IOV_MAX ) {
            dsrl_iovecbuf[iml_bufcnt].iov_base = adsl_gatheriter->achc_ginp_cur;
            im_len += dsrl_iovecbuf[iml_bufcnt].iov_len =
                    adsl_gatheriter->achc_ginp_end
                            - adsl_gatheriter->achc_ginp_cur;
            adsl_gatheriter = adsl_gatheriter->adsc_next;
            ++iml_bufcnt;
        }
#ifdef TRACE
        m_hlnew_printf(123, "m_send_gather to %d: %d bytes. bo_data = %d\n", ds_sock, im_len, bo_data);
#endif
        im_send = 0; // nothing send yet
        do {
            iml_sent = 0;
            bo_sendok = FALSE;
            im_sendcnt = writev( ds_sock, &dsrl_iovecbuf[iml_cur_ele],
                    iml_bufcnt );
            if ( im_sendcnt == -1 ) {
                iml_senttotal += im_send; // AG 07.10.2008
                im_error = errno;
#ifdef TRACE
                m_hlnew_printf(123, "Send failed in m_send_gather: %d.\n", im_error );
#endif
                if ( im_error != EWOULDBLOCK && im_error != ENOTCONN
                        && im_error != EPIPE ) {
                    adsl_callback = ads_callback;
                    if ( adsl_callback && ads_callback->am_errorcallback != NULL ) {
                        this->im_error = im_error;
                        adsl_callback->am_errorcallback( this, ads_usrfld,
                                (char*)"Send failed in m_send_gather", im_error, ERRORAT_SEND );
                    }
                    if ( aimp_rc ) // AG 07.10.2008
                        *aimp_rc = -1; // AG 07.10.2008
                }
                break;
            }

            // iml_cur_ele = 0; // AG 14.04.2008
            while ( iml_sent < im_sendcnt ) {
                // if ((im_sendcnt - iml_sent) > (adsl_gathercnt->achc_ginp_end - adsl_gathercnt->achc_ginp_cur))
                if ( (im_sendcnt - iml_sent)
                        >= (adsl_gathercnt->achc_ginp_end
                                - adsl_gathercnt->achc_ginp_cur) ) // AG 14.04.2008 ">" replaced thru the ">="
                        {
                    iml_sent += (adsl_gathercnt->achc_ginp_end
                            - adsl_gathercnt->achc_ginp_cur);
                    adsl_gathercnt->achc_ginp_cur =
                            adsl_gathercnt->achc_ginp_end;
                    adsl_gathercnt = adsl_gathercnt->adsc_next; // AG 14.04.2008
                    --iml_bufcnt; // AG 14.04.2008
                    ++iml_cur_ele; // AG 14.04.2008
                } else {
                    adsl_gathercnt->achc_ginp_cur += (im_sendcnt - iml_sent);
                    iml_sent += (im_sendcnt - iml_sent);
#ifdef KB_ORG
                    dsrl_iovecbuf[iml_cur_ele].iov_base =
                            adsl_gatheriter->achc_ginp_cur; // AG 14.04.2008
#else //AK 13.06.2012
		    dsrl_iovecbuf[iml_cur_ele].iov_base =
                            adsl_gathercnt->achc_ginp_cur;
#endif
                    dsrl_iovecbuf[iml_cur_ele].iov_len =
                            adsl_gathercnt->achc_ginp_end
                                    - adsl_gathercnt->achc_ginp_cur; // AG 14.04.2008
                }
                // ++ iml_cur_ele; // AG 14.04.2008
                // adsl_gathercnt = adsl_gathercnt->adsc_next; // AG 14.04.2008
            }
            // iml_bufcnt -= iml_cur_ele; // AG 14.04.2008
            bo_sendok = TRUE;
            im_send += im_sendcnt;
        } while ( im_send < im_len );
        if ( im_sendcnt == -1 )
            break;
        iml_senttotal += im_send;
#ifdef TRACE
        m_hlnew_printf(123, "m_send_gather OK. Len: %d\n", im_send);
#endif
    }
#ifdef TRACE
    m_hlnew_printf(123, "m_send_gather OK. total Len: %d\n", iml_senttotal);
#endif
    if ( bo_sendok == FALSE ) {
        if ( write( ads_thread->imr_pipefd[1], &ads_thread, sizeof(ads_thread) )
                < 0 ) {
            adsl_callback = ads_callback;
            if ( adsl_callback && ads_callback->am_errorcallback != NULL ) {
                im_error = errno;
                adsl_callback->am_errorcallback( this, ads_usrfld,
                        (char*)"Unable to set event for stopped send", im_error,
                        ERRORAT_SEND );
            }
        }
    }
    *aads_gatherout = adsl_gathercnt;
    return iml_senttotal;
} // int dsd_tcpcomp::m_send_gather(dsd_gather_i_1 *ads_gatherinp, dsd_gather_i_1** aads_gatherout, int* aimp_rc)

void dsd_tcpcomp::m_sendnotify() {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return mc_esendnotify();
#endif
#ifdef TRACE
    m_hlnew_printf(123, "m_sendnotitfy\n");
#endif
    bo_sendnot = TRUE;
    if ( bo_sendok ) {
#ifdef TRACE
        m_hlnew_printf(123, "Set Event\n");
#endif
        if ( write( ads_thread->imr_pipefd[1], &ads_thread, sizeof(ads_thread) )
                < 0 ) {
            if ( ads_callback->am_errorcallback != NULL ) {
                im_error = errno;
                ads_callback->am_errorcallback( this, ads_usrfld,
                        (char*)"Unable to set event for stopped send", im_error,
                        ERRORAT_SEND );
            }
#ifdef TRACE
            m_hlnew_printf(123, "Unable to set event for send.\n");
#endif
        }
    }
} // void dsd_tcpcomp::m_sendnotify()

dsd_tcpthread_p dsd_tcpcomp::m_createnewthread() {
    dsd_tcpthread_p ads_newthread;

    ads_newthread = new dsd_tcpthread_t;
    if ( !ads_newthread ) {
#ifdef TRACE
        m_hlnew_printf(123, "Unable to allocate memory for new TCP/IP thread structure\n");
#endif
        return 0;
    }

    //memset(ads_newthread, 0, sizeof(dsd_tcpthread_t)); //AG 10.10.2006
    if ( pipe( ads_newthread->imr_pipefd ) < 0 ) {
#ifdef TRACE
        m_hlnew_printf(123, "Unable to create pipes for new TCP/IP thread\n");
#endif
        delete ads_newthread;
        return 0;
    }
    ads_newthread->dsr_waitevent[0].fd = ads_newthread->imr_pipefd[0];
    ads_newthread->dsr_waitevent[0].events = POLLIN;
    ads_newthread->dsr_waitevent[0].revents = 0;
    if ( pthread_create( &(ads_newthread->ds_threadhandle), NULL,
            m_starttcpthread, (void*) ads_newthread ) ) {
        printf( "Unable to start new TCP/IP thread.\n" );
        close( ads_newthread->imr_pipefd[0] );
        close( ads_newthread->imr_pipefd[1] );
        delete ads_newthread;
        return 0;
    }
#ifdef TRACE
    m_hlnew_printf(123, "New thread started.\n");
#endif
    return ads_newthread;
} // dsd_tcpthread_p dsd_tcpcomp::m_createnewthread()

bool dsd_tcpcomp::m_recvdata() {
    void* avo_handle; // handle to receive buffer
    char* ach_buffer; // receive buffer
    int* aim_datalen; // length of data received
    int im_bufferlen; // maximum length to receive
    int im_received; // number of bytes received with one recv.
    int im_error; // error code
    int im_flags; // flags fÁù®Áù®Áù®Áù®Áù®Áù®Áù®Áù®Áù®r t_recv or from t_look
    BOOL bol_recv_2;
    BOOL bol_remove_entry; /* has to remove entry     */

#ifdef TRACE
    m_hlnew_printf(123, "m_recvdata from %d\n", ds_sock);
#endif
    bol_remove_entry = FALSE; /* reset has to remove entry */
    // get receive buffer from application
    im_bufferlen = ads_callback->am_getrecvbuf( this, ads_usrfld, &avo_handle,
            &ach_buffer, &aim_datalen );

    if ( im_bufferlen <= 0 ) // no buffer available
    {
#ifdef TRACE
        m_hlnew_printf(123, "bufferlen <= 0\n");
#endif
        return false;
    }
    if ( avo_handle == NULL || ach_buffer == NULL || aim_datalen == NULL ) {
        if ( ads_callback->am_errorcallback != NULL ) {
            this->im_error = TCPCOMP_ERROR_NULLPARAM;
            ads_callback->am_errorcallback( this, ads_usrfld,
                    (char*)"Invalid paramter value (NULL)", TCPCOMP_ERROR_NULLPARAM,
                    ERRORAT_RECV );
        }
        return false;
    }

    // now receive
    do {
        bo_data = FALSE;
        im_flags = 0;
        im_received = recv( ds_sock, ach_buffer, im_bufferlen, 0 );
        if ( im_received == 0 ) // Connection ended
                {
            *aim_datalen = -1;
            bol_remove_entry = TRUE; /* set has to remove entry */
            break;
        }
        if ( im_received < 0 ) {
            im_error = errno;
            if ( im_error == EWOULDBLOCK ) {
                *aim_datalen = 0;
                break;
            } else {
                bol_remove_entry = TRUE; /* set has to remove entry */
                if ( ads_callback->am_errorcallback != NULL ) {
                    this->im_error = im_error;
                    ads_callback->am_errorcallback( this, ads_usrfld,
                            (char*)"Receive error", im_error, ERRORAT_RECV );
                }
                if ( im_bufferlen < (int) sizeof(int) ) {
                    *aim_datalen = -2;
                    *ach_buffer = (char) 0xFF;
                } else {
                    *aim_datalen = -4;
                    *(int*) ach_buffer = im_error;
                }
                break;
            }
        }
        *aim_datalen = im_received;
        break;
#ifdef KB_ORG_266
    } while ( TRUE );
#else
    } while ( FALSE );
#endif
#ifdef TRACE
    m_hlnew_printf(123, "m_recvdata OK\n");
#endif
    // call application
    //pthread_mutex_lock(&dsd_tcpcomp::ds_critsect); //AG
    // thread_mutex_lock(&ads_thread->ds_thrcritsect); //AG
    bo_recv = FALSE;
    //DEF_RM_EVENT(ads_thread->dsr_waitevent[ads_thread->im_concount].events, POLLIN);
    bol_recv_2 = ads_callback->am_recvcallback( this, ads_usrfld, avo_handle );
    //pthread_mutex_unlock(&dsd_tcpcomp::ds_critsect); //AG
    //pthread_mutex_unlock(&ads_thread->ds_thrcritsect); //AG

#ifdef TRACE
    m_hlnew_printf(123, "l%05d m_recvdata m_recvcallback() returned %d\n", __LINE__, bol_recv_2 );
#endif
    if ( bol_recv_2 ) {
        bo_recv = TRUE;
        //DEF_ADD_EVENT(ads_thread->dsr_waitevent[ads_thread->im_concount].events, POLLIN);
   }
#ifdef TRACE
    m_hlnew_printf(123, "l%05d m_recvdata OK\n", __LINE__ );
#endif
    return bol_remove_entry;
} // void dsd_tcpcomp::m_recvdata()

#ifdef B170711
BOOL dsd_tcpcomp::mc_connect_notify(int imp_events) {
    BOOL bol_connected;
    BOOL bol_remove_entry;
    int iml_error;
#ifndef B110915
    socklen_t iml_soa_len;
#endif

    bol_connected = FALSE;
    bol_remove_entry = FALSE;

#ifdef TRACE
    m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::mc_connect_notify( imp_events=%d ) boc_mhconnect=%d.\n",
            __LINE__, imp_events, boc_mhconnect );
#endif
#ifdef HL_LINUX
    if ( (imp_events & (POLLERR | POLLNVAL)) != 0 ) {
        iml_error =  boc_mhconnect ? 0:1;
    } else {
        iml_error = 0;
    }
#endif
#ifdef HL_FREEBSD
    iml_error = 0;
#ifdef B150817
    if (   (boc_mhconnect)
        && (imp_events & (POLLIN | POLLHUP))) {
      iml_error = 1;
    }
#endif
    if (   (boc_mhconnect)
        && (imp_events & (POLLERR | POLLNVAL | POLLHUP))) {
      iml_error = 1;
    }
#endif

// to-do 15.09.11 KB switch for BOOL makes no sense
    switch ( boc_mhconnect ) {
        case FALSE:
#ifndef B110915
            iml_soa_len = 0;
            switch ( this->dsc_soa_connect.ss_family ) {
                case AF_INET: /* IPV4                    */
                    iml_soa_len = sizeof(struct sockaddr_in);
                    break;
                case AF_INET6: /* IPV6                    */
                    iml_soa_len = sizeof(struct sockaddr_in6);
                    break;
            }
#ifdef TRACE
            m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::mc_connect_notify() dsc_soa_connect.ss_family=%d iml_soa_len=%d.\n",
                    __LINE__, this->dsc_soa_connect.ss_family, iml_soa_len );
#endif
#endif
            if ( iml_error ) { /* reported error          */
                bol_remove_entry = TRUE; /* set has to remove entry */
                if ( ads_callback->am_errorcallback != NULL ) {
                    im_error = iml_error;
#ifdef B110915
                    ads_callback->am_connerrcallback(this, ads_usrfld, NULL, 0, 0, 0, iml_error);
#else
                    ads_callback->am_connerrcallback( this, ads_usrfld,
                            (struct sockaddr *) &this->dsc_soa_connect,
                            iml_soa_len, this->imc_ineta_curno,
                            adsc_target_ineta->imc_no_ineta, iml_error );
#endif
                }
            } else if ( ads_callback->am_conncallback != NULL ) {
#ifdef TRACE
#ifdef B110813
                m_hlnew_printf(123, "NON-multihomed connect\n");
#else
                m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::mc_connect_notify() call am_conncallback\n",
                        __LINE__ );
#endif
#endif
#ifdef B110915
                ads_callback->am_conncallback(this, ads_usrfld, NULL, 0, 0 );
#else
                ads_callback->am_conncallback( this, ads_usrfld,
#ifndef B121120
                        (struct dsd_target_ineta_1*)&adsc_target_ineta, (void*)aps_free_ti1,
#endif
                        (struct sockaddr *) &this->dsc_soa_connect, iml_soa_len,
                        0 );
#endif
            }
            if ( ads_findsock ) {
                freeaddrinfo( ads_findsock );
                ads_findsock = NULL;
            }
            if ( bol_remove_entry == FALSE )
                bol_connected = TRUE;
            break;

        case TRUE: {
#ifdef B110915
            sockaddr_storage dsl_sockaddr;
            socklen_t dsl_len;
#endif
            int iml_ineta_curno;
            iml_ineta_curno = imc_ineta_curno - 1;
#ifdef B150818
#ifdef B110915
            m_set_connect_p1(&dsl_sockaddr, (socklen_t*)&dsl_len,
                    (dsd_target_ineta_1*)adsc_target_ineta,
                    iml_ineta_curno);
#else
            m_set_connect_p1( &this->dsc_soa_connect, &iml_soa_len,
                              (dsd_target_ineta_1 *) adsc_target_ineta, iml_ineta_curno );
#endif
#endif
#ifndef B150818
            iml_soa_len = 0;
            switch ( this->dsc_soa_connect.ss_family ) {
                case AF_INET: /* IPV4                    */
                    iml_soa_len = sizeof(struct sockaddr_in);
                    break;
                case AF_INET6: /* IPV6                    */
                    iml_soa_len = sizeof(struct sockaddr_in6);
                    break;
            }
#endif
            if ( iml_error == 0 ) {
                int iml_errno;
                int iml_reconnerr;
#ifdef TRACE
                m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::mc_connect_notify call connect()\n",
                        __LINE__ );
#endif
#ifdef B110915
                iml_reconnerr = connect(ds_sock,
                        (sockaddr*)&dsl_sockaddr,
                        (socklen_t)dsl_len);
#else
                iml_reconnerr = connect( ds_sock,
                                         (struct sockaddr *) &this->dsc_soa_connect,
                                         iml_soa_len );
#endif
                iml_errno = errno;
#ifdef TRACE
                m_hlnew_printf(123, "iml_reconnerr %d errno %d: %s\n", iml_reconnerr, iml_errno, strerror(iml_errno));
#endif
                if ( iml_reconnerr != -1 ) {
                    /* connect successful */

                    // MJ test connection callback was missing?!
                    //if ( ads_callback->am_conncallback != NULL ) {
                    //    ads_callback->am_conncallback( this, ads_usrfld,
                    //                                   (struct sockaddr *) &this->dsc_soa_connect,
                    //                                   iml_soa_len, 0 );
                    // }
                    // bol_connected = TRUE;
                    // end MJ

                    break;
                } else if ( iml_errno == EINPROGRESS || iml_errno == EALREADY ) {
                    break;
                } else if ( iml_errno != EISCONN ) {
                    iml_error = iml_errno;
                }
            }
			socklen_t dsl_paramlen = sizeof(iml_error);
			int iml_rc;
			iml_rc = getsockopt(this->ds_sock, SOL_SOCKET, SO_ERROR, 
			           &iml_error, &dsl_paramlen);
			if (iml_rc) {
#ifdef TRACE
                m_hlnew_printf(123, "hob-tcpco1.hpp %05d getsockopt() returned %d error %d.",
                __LINE__, iml_rc, errno);
#endif
			}
			im_error = iml_error;
            if ( iml_error ) { /* reported error          */
                if ( ads_callback->am_connerrcallback != NULL ) {
#ifdef B110915
                    ads_callback->am_connerrcallback(this, ads_usrfld,
                            (struct sockaddr *) &dsl_sockaddr, dsl_len,
                            iml_ineta_curno,
                            adsc_target_ineta->imc_no_ineta, iml_error);
#else
                    ads_callback->am_connerrcallback( this, ads_usrfld,
                            (struct sockaddr *) &this->dsc_soa_connect,
                            iml_soa_len, iml_ineta_curno,
                            adsc_target_ineta->imc_no_ineta, iml_error );
#endif
                }
#ifndef B150817
#ifdef TRACE
                m_hlnew_printf(123, "hob-tcpco1.hpp l%05d try next target or end - close this->ds_sock=%d.",
                                    __LINE__, this->ds_sock );
#endif
                close( this->ds_sock );
                this->ds_sock = INVALID_SOCKET;
#endif
                if ( imc_ineta_curno == adsc_target_ineta->imc_no_ineta ) {
                    bol_remove_entry = TRUE; /* set has to remove entry */
                    break;
                } else {
#ifdef B150817
                    close( ds_sock );
                    ds_sock = INVALID_SOCKET;
#endif
#ifdef B121121
                    if ( m_startco_mh( NULL, NULL, NULL, NULL, 0, FALSE ) != 0 )
#else
                    if ( m_startco_mh( NULL, NULL, NULL, NULL, NULL, 0, FALSE ) != 0 )
#endif
                        bol_remove_entry = TRUE; /* set has to remove entry */
                    break;
                }

            }
            if ( ads_callback->am_conncallback != NULL ) {
#ifdef TRACE
                m_hlnew_printf(123, "NON multihomed connect\n");
#endif
#ifdef B110915
                ads_callback->am_conncallback( this, ads_usrfld,
                        (struct sockaddr *) &dsl_sockaddr, dsl_len, 0 );
#else
                ads_callback->am_conncallback( this, ads_usrfld,
#ifndef B121120
                        (struct dsd_target_ineta_1*) &adsc_target_ineta,
                        (void*) aps_free_ti1,
#endif
                        (struct sockaddr *) &this->dsc_soa_connect, iml_soa_len,
                        0 );
#endif
            }
            bol_connected = TRUE;
        }
        break;
    }
    if ( bol_connected == TRUE )
        bo_connot = FALSE;
    return bol_remove_entry;
}
#endif //#ifdef B170711
#ifndef B170711
BOOL dsd_tcpcomp::mc_connect_notify(int imp_events) {
    int iml_error;                   // error code
    int iml_rc;                      // return code
    socklen_t iml_soa_len;           // length of socket address
    socklen_t iml_sock_len;          // length of socket option

#ifdef TRACE
    m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::mc_connect_notify( imp_events=%d ) boc_mhconnect=%d.\n",
            __LINE__, imp_events, boc_mhconnect );
#endif

    // check if connect was successful
    // see man pages for connect() - EINPROGRESS/non-blocking connect
    iml_sock_len = sizeof (int);
    iml_rc = getsockopt(this->ds_sock, SOL_SOCKET, SO_ERROR, 
           &iml_error, &iml_sock_len);
    if (iml_rc) {  // getsockopt() failed
#ifdef TRACE
        m_hlnew_printf(123, "hob-tcpco1.hpp %05d getsockopt() returned %d error %d.",
            __LINE__, iml_rc, errno);
#endif
        iml_error = errno;
    } else { // getsockopt succeeded
        switch ( iml_error ) {
            case ( 0 ): // connect successful
                // connect error in case of POLLERR, POLLNVAL            
                iml_error = ( imp_events & ( POLLERR | POLLNVAL ) ) != 0 ;
                break;
            case ( EINPROGRESS ):  // connect still in progress
#ifdef TRACE
                m_hlnew_printf(123, "hob-tcpco1.hpp %05d connect still in progress.",
                    __LINE__);
#endif 
                // connect error in case of POLLERR, POLLNVAL            
                iml_error = ( imp_events & ( POLLERR | POLLNVAL ) ) != 0 ;
                if ( !iml_error ) {
                    // wait for connect to complete
                    return FALSE;
                }
                break;
            default:
                break; 
        }
    }
    
    iml_soa_len = 0;
    switch ( this->dsc_soa_connect.ss_family ) {
        case AF_INET: /* IPV4                    */
            iml_soa_len = sizeof(struct sockaddr_in);
            break;
        case AF_INET6: /* IPV6                    */
            iml_soa_len = sizeof(struct sockaddr_in6);
            break;
    }

#ifdef TRACE
        m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::mc_connect_notify() dsc_soa_connect.ss_family=%d iml_soa_len=%d.\n",
                __LINE__, this->dsc_soa_connect.ss_family, iml_soa_len );
#endif
    
    if ( boc_mhconnect == FALSE ) {  // non-multihomed connect             
        
        if ( ads_findsock ) {
            freeaddrinfo( ads_findsock );
            ads_findsock = NULL;
        }
        
        if ( iml_error ) { // connect failed!
            im_error = iml_error;
            if ( ads_callback->am_errorcallback != NULL ) {
                ads_callback->am_connerrcallback( this, ads_usrfld,
                        (struct sockaddr *) &this->dsc_soa_connect,
                        iml_soa_len, 0, 1, iml_error );
            }
            return TRUE;  /* set has to remove entry */
        }
        // connect successful!
        if ( ads_callback->am_conncallback != NULL ) {
#ifdef TRACE
            m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::mc_connect_notify() call am_conncallback\n",
                    __LINE__ );
#endif
            ads_callback->am_conncallback( this, ads_usrfld,
                    (struct dsd_target_ineta_1*)&adsc_target_ineta, (void*)aps_free_ti1,
                    (struct sockaddr *) &this->dsc_soa_connect, iml_soa_len, 0 );
        }
        bo_connot = FALSE;
        return FALSE;
    }
    
    //multihomed connect
    
    if ( iml_error ) { /* reported error          */
        im_error = iml_error;
        if ( ads_callback->am_connerrcallback != NULL ) {
            ads_callback->am_connerrcallback( this, ads_usrfld,
                    (struct sockaddr *) &this->dsc_soa_connect,
                    iml_soa_len, ( imc_ineta_curno - 1),
                    adsc_target_ineta->imc_no_ineta, iml_error );
        }
#ifdef TRACE
        m_hlnew_printf(123, "hob-tcpco1.hpp l%05d try next target or end - close this->ds_sock=%d.",
                            __LINE__, this->ds_sock );
#endif
        close( this->ds_sock );
        this->ds_sock = INVALID_SOCKET;
        
        if ( imc_ineta_curno < adsc_target_ineta->imc_no_ineta ) {
            // return TRUE when m_startco_mh() fails
            return ( m_startco_mh( NULL, NULL, NULL, NULL, NULL, 0, FALSE ) != 0 );            
        }
        return TRUE;
    }
    
    //multihomed connect sucessful!
    if ( ads_callback->am_conncallback != NULL ) {
#ifdef TRACE
        m_hlnew_printf(123, "multihomed connect\n");
#endif
        ads_callback->am_conncallback( this, ads_usrfld,
                (struct dsd_target_ineta_1*) &adsc_target_ineta,
                (void*) aps_free_ti1,
                (struct sockaddr *) &this->dsc_soa_connect, iml_soa_len,
                0 );
    }
    bo_connot = FALSE;
    return FALSE;
}
#endif // ifndef B170711

/**
 * TCP/IP wait thread.
 * @param ads_parm pointer to corresponding thread structure.
 */
void dsd_tcpcomp::m_tcpthread(void* ads_parm) {
    BOOL bol_remove_entry; /* has to remove entry     */
    BOOL bol_save_1; /* save value              */
    BOOL bol_ret; /* return code             */
    int im_waitret; // return code from wait
    dsd_tcpthread_p ads_thread; // thread structure
    int im_index; // loop index
    int im_conn; // index of connection notified
    dsd_stopped_p ads_stop; // pointer to a stopped connection
    dsd_tcpthread_p ads_dummy; // buffer to clear notification pipe
    dsd_tcpcallback_p adsl_callback;
#ifdef DEF_RELEASE
    int inl_time;
    dsd_def_release_p adsl_def_rel; /* pointer to a deleted connection */
#endif

    ads_thread = (dsd_tcpthread_p) ads_parm;
    if ( dsd_tcpthread_t::amc_at_thread_start )
        dsd_tcpthread_t::amc_at_thread_start( 0 );
#ifdef TRACE
    m_hlnew_printf(123, "TCP/IP thread started\n");
#endif
    int iml_concount;
    do {
#ifdef XYZ1
#ifdef TRACE
        //m_hlnew_printf(123, "Wait for %d events\n", ads_thread->im_concount + 1);
        m_hlnew_printf(123, "Wait for %d events\n", iml_concount);
#endif
#endif
        bol_remove_entry = FALSE; /* reset has to remove entry */
        iml_concount = ads_thread->im_concount;
#ifdef TRACE
        //m_hlnew_printf(123, "Wait for %d events\n", ads_thread->im_concount + 1);
        m_hlnew_printf(123, "Wait for %d events\n", iml_concount);
#endif
#ifdef TRACEHL_POLL_01                      /* 11.08.11 KB             */
        for (int iml_i2 = 0; iml_i2 < iml_concount + 1; ++ iml_i2) {
            m_hlnew_printf(123, "hob-tcpco1-l%05d-T loop index=%d socket=0X%08X events=0X%08X.\n",
                    __LINE__, iml_i2,
                    ads_thread->dsr_waitevent[iml_i2].fd,
                    ads_thread->dsr_waitevent[iml_i2].events );
        }
#endif

        im_waitret = poll( ads_thread->dsr_waitevent, iml_concount + 1, -1/*INFTIM*/);

#ifdef TRACE
        for (int iml_ii = 0; iml_ii < iml_concount + 1; ++ iml_ii) {
            m_hlnew_printf(123, "index %d events 0x%x revents 0x%x\n", iml_ii,
                    ads_thread->dsr_waitevent[iml_ii].events, ads_thread->dsr_waitevent[iml_ii].revents);
        }
        m_hlnew_printf(123, "TRACEEND-------------------\n");
#endif
#ifdef TRACE
        if ( ads_thread->bo_cleanup ) {
            m_hlnew_printf(123, "Cleanup requested\n" );
            break;
        }
#endif
#ifdef TRACE
        m_hlnew_printf(123, "poll returned with %d\n", im_waitret);
        if ( im_waitret <= 0 ) {
            m_hlnew_printf(123, "Poll error %d or nothing received? %d\n", errno,
                    im_waitret );
            sleep( 1 );
            continue;
        }
#endif

        im_conn = 0;
        do {
            if ( ads_thread->dsr_waitevent[im_conn].revents != 0 ) {
#ifdef TRACE
#ifdef B110813
                m_hlnew_printf(123, "Event: %d: %d\n", im_conn, ads_thread->dsr_waitevent[im_conn].revents);
#else
                m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::m_tcpthread Event: %d: %d\n",
                        __LINE__, im_conn, ads_thread->dsr_waitevent[im_conn].revents);
#endif
#endif
                im_waitret--;
                if ( (ads_thread->dsr_waitevent[im_conn].revents
                        & (POLLIN | POLLERR | POLLNVAL)) != 0 ) {
                    if ( im_conn == 0 ) {
                        /* control event fired */
                        read( ads_thread->dsr_waitevent[0].fd, &ads_dummy, sizeof(ads_dummy) );
#ifdef TRACE
#ifdef B110813
                        m_hlnew_printf(123, "event read from pipe in m_tcpthread()\n");
#else
                        m_hlnew_printf(123,  "hob-tcpco1-l%05d-T dsd_tcpcomp::m_tcpthread event read from pipe iml_concount=%d.\n",
                                __LINE__, iml_concount );
#endif
#endif

                        pthread_mutex_lock( &dsd_tcpcomp::ds_critsect );
                        ads_stop = ads_thread->ads_stopchain;
                        while ( ads_stop != NULL ) {
#ifdef TRACE
                            m_hlnew_printf(123, "Stopped connections found\n");
#endif
                            for ( im_index = 1; im_index <= iml_concount;
                                    im_index++ ) {
                                if ( ads_thread->dsr_tcpconn[im_index]
                                        == ads_stop->ads_stopped ) {
#ifdef TRACE
                                    m_hlnew_printf(123, "Close Event handle\n");
#endif
                                    if ( ads_stop->bo_close ) {
                                        close(
                                                ads_thread->dsr_tcpconn[im_index]->ds_sock );
										ads_thread->dsr_tcpconn[im_index]->ds_sock = INVALID_SOCKET;
                                    }
                                    if ( ads_thread->dsr_waitevent[im_index].revents
                                            != 0 )
                                        im_waitret--;
                                    ads_thread->dsr_tcpconn[im_index]->bo_data =
                                            FALSE;
                                    ads_thread->dsr_tcpconn[im_index]->bo_sendok =
                                            FALSE;
                                    if ( im_index
                                            < iml_concount/*ads_thread->im_concount*/) {
#ifdef TRACE
                                        m_hlnew_printf(123, "Remove emtpy event\n");
#endif
                                        memmove(
                                                &ads_thread->dsr_tcpconn[im_index],
                                                &ads_thread->dsr_tcpconn[im_index
                                                        + 1],
                                                (ads_thread->im_concount
                                                        - im_index)
                                                        * sizeof(class dsd_tcpcomp*) );
                                        memmove(
                                                &ads_thread->dsr_waitevent[im_index],
                                                &ads_thread->dsr_waitevent[im_index
                                                        + 1],
                                                (ads_thread->im_concount
                                                        - im_index)
                                                        * sizeof(struct pollfd) );
                                    }
                                    ads_thread->im_concount--;
                                    iml_concount = ads_thread->im_concount;
                                    break;
                                }
                            }
                            ads_thread->ads_stopchain = ads_stop->ads_next;
#ifdef TRACE
                            m_hlnew_printf(123, "Delete stop entries\n");
#endif
                            if ( ads_stop->ads_stopped->boc_storage )
                                delete ads_stop->ads_stopped;
                            delete ads_stop;
                            ads_stop = ads_thread->ads_stopchain;
                        }
                        pthread_mutex_unlock( &dsd_tcpcomp::ds_critsect );
                        // Now look for connections which need to be handled and set events right
#ifdef TRACE
                        m_hlnew_printf(123,  "hob-tcpco1-l%05d-T before loop iml_concount=%d ads_thread->im_concount=%d.\n",
                                __LINE__, iml_concount, ads_thread->im_concount );
#endif
#ifndef B110813
// to-do 13.08.11 KB new element might have been added
                        iml_concount = ads_thread->im_concount;
#endif
                        for ( im_index = 1; im_index <= iml_concount/*ads_thread->im_concount*/; im_index++ ) {
#ifdef TRACE
                            m_hlnew_printf(123,  "hob-tcpco1-l%05d-T loop im_index=%d bo_connot=%d \n",
                                    __LINE__, im_index,
                                    ads_thread->dsr_tcpconn[im_index]->bo_connot);
                                    //ads_thread->dsr_tcpconn[im_index]->bo_recv );
#endif
                            bol_remove_entry = FALSE;
#ifdef B170711
                            if ( (ads_thread->dsr_tcpconn[im_index]->bo_connot == TRUE) ) {
#endif
#ifndef B170711
                            // do not wait for connect when TCPCOMP session ended
                            if ( (ads_thread->dsr_tcpconn[im_index]->bo_connot) && (!ads_thread->dsr_tcpconn[im_index]->boc_end) ) {
#endif
                                //if ((ads_thread->dsr_waitevent[im_index].revents & (POLLIN | POLLERR | POLLNVAL)) != 0)
                                //continue;
                                //bol_remove_entry = ms_connect_notify(ads_thread, adsl_callback, im_index);
                                //else
#ifdef B110813
#ifdef NEW_KB_110811                        /* problems with bo_connot */
                                if (ads_thread->dsr_tcpconn[im_index]->boc_do_connect == FALSE) { /* connect needs not to be done */
                                    ads_thread->dsr_tcpconn[im_index]->bo_connot = FALSE;
                                    ads_thread->dsr_waitevent[im_index].events = POLLIN;
                                    ads_thread->dsr_tcpconn[im_index]->bo_recv = TRUE;
                                    //DEF_ADD_EVENT(ads_thread->dsr_waitevent[im_index].events, POLLIN);
                                }
#endif
#endif
                                continue;
                            }
#ifndef B110813_XXX
//#ifdef NEW_KB_110811                        /* problems with bo_connot */
                            if ( ads_thread->dsr_tcpconn[im_index]->bo_recv ) {
                                ads_thread->dsr_waitevent[im_index].events |= POLLIN;
                            }
                            /*if ( (ads_thread->dsr_waitevent[im_index].revents & POLLIN) != 0 ) {
                                DEF_ADD_EVENT(ads_thread->dsr_waitevent[im_index].events, POLLIN);	
                            }*/
//#endif
#endif
                            adsl_callback = ads_thread->dsr_tcpconn[im_index]->ads_callback;
                            /* MJ why is this in comments? */
                            //if (ads_thread->dsr_tcpconn[im_index]->bo_connot == FALSE)
                            {
                                if ( ads_thread->dsr_tcpconn[im_index]->boc_end )  { /* end has been set */
                                    bol_remove_entry = TRUE; /* set has to remove entry */
                                }

                                ads_thread->dsr_waitevent[im_index].events = 0;
                                if (    ads_thread->dsr_tcpconn[im_index]->bo_sendnot
                                     && ads_thread->dsr_tcpconn[im_index]->bo_sendok  ) {
#ifdef TRACE
			            m_hlnew_printf(123, "calling sendcallback on socket at index %d\n",
                                            im_index );
#endif
                                    ads_thread->dsr_tcpconn[im_index]->bo_sendnot = FALSE;
                                    ads_thread->dsr_tcpconn[im_index]->ads_callback->am_sendcallback(
                                            ads_thread->dsr_tcpconn[im_index],
                                            ads_thread->dsr_tcpconn[im_index]->ads_usrfld );
                                }
                                if (    ads_thread->dsr_tcpconn[im_index]->bo_recv
                                //if ( ((ads_thread->dsr_waitevent[im_index].revents & POLLIN) != 0)
                                        && ads_thread->dsr_tcpconn[im_index]->bo_data ) {
                                    bol_ret = ads_thread->dsr_tcpconn[im_index]->m_recvdata();
                                    if ( bol_ret ) {
                                        bol_remove_entry = TRUE; /* set has to remove entry */
                                    }
                                }
                                if ( ads_thread->dsr_tcpconn[im_index]->bo_data == FALSE ) {
                                    ads_thread->dsr_waitevent[im_index].events |= POLLIN;
                                }
                                if ( ads_thread->dsr_tcpconn[im_index]->bo_sendok == FALSE ) {
#ifdef TRACE
			            m_hlnew_printf(123, "adding POLLOUT event to socket at index %d\n",
                                            im_index );
#endif
                                    ads_thread->dsr_waitevent[im_index].events |= POLLOUT;
                                }
#ifdef DEF_RELEASE
                                adsl_def_rel = ads_thread->ads_def_rel;
                                inl_time     = ads_thread->dsr_tcpconn[im_index]->mc_get_time();

                                while ( (adsl_def_rel != NULL) &&             /*delete session after 2 mins*/
                                        ((inl_time - adsl_def_rel->in_timestamp) > 120) ) {
                                    ads_thread->ads_def_rel = adsl_def_rel->adsc_next; /* go to next in chain        */
                                    delete adsl_def_rel->adsc_cur_ses;                 /* deferred delete of session */
                                    delete adsl_def_rel;                               /* delete whole chain         */
                                    adsl_def_rel = ads_thread->ads_def_rel;            /* go to next in chain        */
                                }
#endif
                            }

                            if ( bol_remove_entry ) { /* set has to remove entry */
#ifdef TRACE
                                m_hlnew_printf(123, "hob-tcpco1.hpp l%05d remove entry\n", __LINE__ );
#endif
                                ads_thread->dsr_tcpconn[im_index]->ads_callback = NULL;
                                close( ads_thread->dsr_tcpconn[im_index]->ds_sock );
								ads_thread->dsr_tcpconn[im_index]->ds_sock = INVALID_SOCKET;
                                bol_save_1 = ads_thread->dsr_tcpconn[im_index]->boc_storage; /* save value */
#ifdef B121120
                                if (    (adsl_callback->amc_free_target_ineta)
                                     && (ads_thread->dsr_tcpconn[im_index]->adsc_target_ineta) )
                                    adsl_callback->amc_free_target_ineta(
                                            ads_thread->dsr_tcpconn[im_index],
                                            ads_thread->dsr_tcpconn[im_index]->ads_usrfld,
                                            (struct dsd_target_ineta_1 *) ads_thread->dsr_tcpconn[im_index]->adsc_target_ineta );
#endif
                                if ( adsl_callback->amc_cleanup ) {
                                    adsl_callback->amc_cleanup(
                                            ads_thread->dsr_tcpconn[im_index],
                                            ads_thread->dsr_tcpconn[im_index]->ads_usrfld );
                                }
                                if ( bol_save_1 ) {
#ifdef DEF_RELEASE
                                    ads_thread->dsr_tcpconn[im_index]->mc_set_ref_conn( im_index );
#else
                                    delete ads_thread->dsr_tcpconn[im_index];
#endif
                                }
                                pthread_mutex_lock( &dsd_tcpcomp::ds_critsect );

                                if ( im_index < ads_thread->im_concount ) {
#ifdef TRACE
                                    m_hlnew_printf(123, "l%05d Remove empty event\n", __LINE__ );
#endif
                                    memmove( &ads_thread->dsr_tcpconn[im_index],
                                             &ads_thread->dsr_tcpconn[im_index + 1],
                                            (ads_thread->im_concount - im_index) * sizeof(class dsd_tcpcomp*) );
                                    memmove( &ads_thread->dsr_waitevent[im_index],
                                             &ads_thread->dsr_waitevent[im_index + 1],
                                            (ads_thread->im_concount - im_index) * sizeof(struct pollfd) );
                                }
                                ads_thread->im_concount--;
                                iml_concount = ads_thread->im_concount;
#ifdef TRACE
                                m_hlnew_printf(123, "hob-tcpco1.hpp l%05d dsd_tcpcomp::m_tcpthread() ads_thread=%p im_concount=%d\n",
                                        __LINE__, ads_thread, ads_thread->im_concount );
#endif
                                pthread_mutex_unlock(
                                        &dsd_tcpcomp::ds_critsect );
                            }
                        }
                    } // if(im_conn == 0) // control event fired
                    else // receive data
                    {
                        bol_remove_entry = FALSE;
                        adsl_callback =
                                ads_thread->dsr_tcpconn[im_conn]->ads_callback;
#ifdef TRACE
                        m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::m_tcpthread im_conn=%d adsl_callback=%p bo_connot=%d \n",
                                __LINE__, im_conn, adsl_callback,
                                ads_thread->dsr_tcpconn[im_conn]->bo_connot);
                                //ads_thread->dsr_tcpconn[im_conn]->bo_recv );
#endif
                        if ( ads_thread->dsr_tcpconn[im_conn]->bo_connot == TRUE ) {
                            if ( (ads_thread->dsr_waitevent[im_conn].revents
                                    & (POLLERR | POLLIN)) != 0 )
#ifndef B150818
                              {
#endif
#ifdef XYZ1
#ifndef B150812
                              {
#ifdef FORKEDIT
                              }
#endif
#ifdef TRACE
                                m_hlnew_printf(123, "hob-tcpco1.hpp l%05d try next target - close ...->ds_sock=%d.",
                                                    __LINE__, ads_thread->dsr_tcpconn[im_conn]->ds_sock );
#endif
                                close( ads_thread->dsr_tcpconn[im_conn]->ds_sock );
                                ads_thread->dsr_tcpconn[im_conn]->ds_sock = INVALID_SOCKET;
#endif
#endif
                                bol_remove_entry =
                                        ads_thread->dsr_tcpconn[im_conn]->mc_connect_notify(
                                                ads_thread->dsr_waitevent[im_conn].revents );
#ifndef B150812
                                if (bol_remove_entry == FALSE) {
#ifdef TRACE
                                  m_hlnew_printf(123, "hob-tcpco1.hpp l%05d tried next target - old content.fd=%d.",
                                                      __LINE__, ads_thread->dsr_waitevent[im_conn].fd );
                                  m_hlnew_printf(123, "hob-tcpco1.hpp l%05d tried next target - copy ...->ds_sock=%d.",
                                                      __LINE__, ads_thread->dsr_tcpconn[im_conn]->ds_sock );
#endif
                                  ads_thread->dsr_waitevent[im_conn].fd = ads_thread->dsr_tcpconn[im_conn]->ds_sock;
                                  ads_thread->dsr_waitevent[im_conn].events = DEF_POLL_CONN;
                                }
                              }
#endif
                        }
                        if ( ads_thread->dsr_tcpconn[im_conn]->bo_connot
                                == FALSE ) {
                            if ( ads_thread->dsr_tcpconn[im_conn]->bo_recv ) {
                            //if ( (ads_thread->dsr_waitevent[im_conn].revents & POLLIN) != 0 ) {
#ifdef TRACE
                                m_hlnew_printf(123, "hob-tcpco1.hpp l%05d poll returned recv event\n", __LINE__ );
#endif
                                bol_ret =
                                        ads_thread->dsr_tcpconn[im_conn]->m_recvdata();
                                if ( bol_ret )
                                    bol_remove_entry = TRUE; /* set has to remove entry */
                            } else {
#ifdef TRACE
                                m_hlnew_printf(123, "hob-tcpco1.hpp l%05d poll returned recv event, but we should not receive more data\n", __LINE__ );
#endif
                                ads_thread->dsr_tcpconn[im_conn]->bo_data = TRUE;
                            }
#ifdef DEF_RELEASE
                            adsl_def_rel = ads_thread->ads_def_rel;
                            inl_time     = ads_thread->dsr_tcpconn[im_conn]->mc_get_time();

                            while ( (adsl_def_rel != NULL) &&          /* delete session after 2 mins */
                                    ((inl_time - adsl_def_rel->in_timestamp) > 120) ) {
                                ads_thread->ads_def_rel = adsl_def_rel->adsc_next; /* go to next in chain        */
                                delete adsl_def_rel->adsc_cur_ses;                 /* deferred delete of session */
                                delete adsl_def_rel;                               /* delete whole chain         */
                                adsl_def_rel = ads_thread->ads_def_rel;            /* go to next in chain        */
                            }
#endif
                        }
                        if ( bol_remove_entry ) { /* set has to remove entry */
#ifdef TRACE
                            m_hlnew_printf(123, "hob-tcpco1.hpp l%05d remove entry\n", __LINE__ );
#endif
                            ads_thread->dsr_tcpconn[im_conn]->ads_callback =
                                    NULL;
                            if (ads_thread->dsr_tcpconn[im_conn]->ds_sock != INVALID_SOCKET) {
                              close( ads_thread->dsr_tcpconn[im_conn]->ds_sock );
                              ads_thread->dsr_tcpconn[im_conn]->ds_sock = INVALID_SOCKET;
                            }
#ifndef B150817
                            if (ads_thread->dsr_tcpconn[im_conn]->bo_connot) {
                                    if ( adsl_callback->am_conncallback != NULL ) {
										int iml_connerr = ads_thread->dsr_tcpconn[im_conn]->im_error;
										if ( iml_connerr == 0) { //no 0 in conncallback at this time
										    iml_connerr = 1; 
										}
                                        adsl_callback->am_conncallback(
                                                ads_thread->dsr_tcpconn[im_conn],
                                                ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                                (struct dsd_target_ineta_1*)&ads_thread->dsr_tcpconn[im_conn]->adsc_target_ineta,
                                                (void*)ads_thread->dsr_tcpconn[im_conn]->aps_free_ti1,
                                                NULL, 0,
                                                iml_connerr );
                                    }
                            }
#endif
                            bol_save_1 =
                                    ads_thread->dsr_tcpconn[im_conn]->boc_storage; /* save value */
#ifdef B121120
                            if (    (adsl_callback->amc_free_target_ineta)
                                 && (ads_thread->dsr_tcpconn[im_conn]->adsc_target_ineta) )
                                adsl_callback->amc_free_target_ineta(
                                        ads_thread->dsr_tcpconn[im_conn],
                                        ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
                                        (struct dsd_target_ineta_1 *) ads_thread->dsr_tcpconn[im_conn]->adsc_target_ineta );
#endif
                            if ( adsl_callback->amc_cleanup ) {
                                adsl_callback->amc_cleanup(
                                        ads_thread->dsr_tcpconn[im_conn],
                                        ads_thread->dsr_tcpconn[im_conn]->ads_usrfld );
                            }
                            if ( bol_save_1 ) {
#ifdef DEF_RELEASE
                                ads_thread->dsr_tcpconn[im_conn]->mc_set_ref_conn( im_conn );
#else
                                delete ads_thread->dsr_tcpconn[im_conn];
#endif
                            }
                            pthread_mutex_lock( &dsd_tcpcomp::ds_critsect );

                            --iml_concount;
                            if ( im_conn < ads_thread->im_concount ) {
#ifdef TRACE
                                m_hlnew_printf(123, "l%05d Remove empty event\n", __LINE__ );
#endif
                                memmove( &ads_thread->dsr_tcpconn[im_conn],
                                         &ads_thread->dsr_tcpconn[im_conn + 1],
                                         (ads_thread->im_concount - im_conn) * sizeof(class dsd_tcpcomp*) );
                                memmove( &ads_thread->dsr_waitevent[im_conn],
                                         &ads_thread->dsr_waitevent[im_conn + 1],
                                         (ads_thread->im_concount - im_conn) * sizeof(struct pollfd) );
                            }
                            ads_thread->im_concount--;
                            //iml_concount = ads_thread->im_concount;
#ifdef TRACE
                            m_hlnew_printf(123, "hob-tcpco1.hpp l%05d dsd_tcpcomp::m_tcpthread() ads_thread=%p im_concount=%d\n",
                                    __LINE__, ads_thread, ads_thread->im_concount );
#endif
                            pthread_mutex_unlock( &dsd_tcpcomp::ds_critsect );
                            ++im_conn;
                            continue;
                        }
                    }

                } // end of if((ads_thread->dsr_waitevent[im_conn].revents & (POLLIN | POLLERR)) != 0)
                if ( im_conn > 0 ) {
                    if ( (ads_thread->dsr_waitevent[im_conn].revents & (POLLOUT | POLLHUP)) == POLLOUT ) {
#ifndef HL_SOLARIS
#ifdef NEW_KB_110811                        /* problems with bo_connot */
//#ifdef B110813
                        if (ads_thread->dsr_tcpconn[im_conn]->boc_do_connect == FALSE) { /* connect needs not to be done */
                            ads_thread->dsr_tcpconn[im_conn]->bo_connot = FALSE;
                        }
//#endif
#endif
                        if ( ads_thread->dsr_tcpconn[im_conn]->bo_connot != FALSE )
                        {
                            adsl_callback = ads_thread->dsr_tcpconn[im_conn]->ads_callback;
#ifdef TRACE
                            m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::m_tcpthread() CONNECT NOTIFY POLLOUT\n",
                                    __LINE__ );
#endif
                            ads_thread->dsr_tcpconn[im_conn]->bo_connot = FALSE;
#ifndef B110915
                            socklen_t iml_soa_len;
                            iml_soa_len = 0;
                            switch ( ads_thread->dsr_tcpconn[im_conn]->dsc_soa_connect.ss_family ) {
                                case AF_INET: /* IPV4                   */
                                    iml_soa_len = sizeof(struct sockaddr_in);
                                    break;
                                case AF_INET6: /* IPV6                  */
                                    iml_soa_len = sizeof(struct sockaddr_in6);
                                    break;
                            }
#ifdef TRACE
                            m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::m_tcpthread() dsc_soa_connect.ss_family=%d iml_soa_len=%d.\n",
                                    __LINE__, ads_thread->dsr_tcpconn[im_conn]->dsc_soa_connect.ss_family, iml_soa_len );
#endif
#endif
                            /* MJ why not call mc_connect_notify? */

                            switch ( ads_thread->dsr_tcpconn[im_conn]->boc_mhconnect ) {
                                case FALSE:

                                    if ( adsl_callback->am_conncallback != NULL ) {
#ifdef B110915
// to-do 13.08.11 KB pass sockaddr-storage of connect as done in Windows
                                        adsl_callback->am_conncallback(ads_thread->dsr_tcpconn[im_conn],
                                                ads_thread->dsr_tcpconn[im_conn]->ads_usrfld, NULL, 0, 0 );
#else
#define ADSL_TCPCO_G ads_thread->dsr_tcpconn[im_conn]
                                        adsl_callback->am_conncallback(
                                                ADSL_TCPCO_G,
                                                ADSL_TCPCO_G->ads_usrfld,
#ifndef B121120
                                                (struct dsd_target_ineta_1*) &ADSL_TCPCO_G->adsc_target_ineta,
                                                (void*)ADSL_TCPCO_G->aps_free_ti1,
#endif
                                                (struct sockaddr *) &ADSL_TCPCO_G->dsc_soa_connect,
                                                iml_soa_len, 0 );
#undef ADSL_TCPCO_G
#endif
                                    }
                                    if ( ads_thread->dsr_tcpconn[im_conn]->ads_findsock ) {
                                        freeaddrinfo( ads_thread->dsr_tcpconn[im_conn]->ads_findsock );
                                        ads_thread->dsr_tcpconn[im_conn]->ads_findsock = NULL;
                                    }
                                    break;
                                case TRUE: {
//#ifdef B110915
                                    sockaddr_storage dsl_sockaddr;
                                    socklen_t dsl_len;
//#endif
                                    int iml_ineta_curno;
                                    iml_ineta_curno = ads_thread->dsr_tcpconn[im_conn]->imc_ineta_curno - 1;
                                    ads_thread->dsr_tcpconn[im_conn]->im_error = 1;
//#ifdef B110915
                                    m_set_connect_p1(
                                            &dsl_sockaddr,
                                            (socklen_t*) &dsl_len,
                                            (dsd_target_ineta_1*) ads_thread->dsr_tcpconn[im_conn]->adsc_target_ineta,
                                            iml_ineta_curno );
#ifndef TJ_B170810
                                    switch ( dsl_sockaddr.ss_family ) {
                                        case ( AF_INET ):
                                            ( (struct sockaddr_in *) &dsl_sockaddr )->sin_port = ( (struct sockaddr_in *) &ads_thread->dsr_tcpconn[im_conn]->dsc_soa_connect )->sin_port;
                                            break;
                                        case ( AF_INET6 ):
                                            ( (struct sockaddr_in6 *) &dsl_sockaddr )->sin6_port = ( (struct sockaddr_in6 *) &ads_thread->dsr_tcpconn[im_conn]->dsc_soa_connect )->sin6_port;
                                            break;
                                        default:
                                            break;
                                    }
#endif

                                    if ( adsl_callback->am_conncallback != NULL ) {
                                        adsl_callback->am_conncallback(
                                                ads_thread->dsr_tcpconn[im_conn],
                                                ads_thread->dsr_tcpconn[im_conn]->ads_usrfld,
#ifndef B121120
                                                (struct dsd_target_ineta_1*)&ads_thread->dsr_tcpconn[im_conn]->adsc_target_ineta,
                                                (void*)ads_thread->dsr_tcpconn[im_conn]->aps_free_ti1,
#endif
                                                (struct sockaddr *) &dsl_sockaddr,
                                                dsl_len, 0 );
                                    }
//#else
//#endif
                                }
                                break;
                            }
                        }
#endif
#ifdef TRACE
			m_hlnew_printf(123, "POLLOUT event received on socket at index %d, sendnotify is '%s'\n",
                                im_conn, (ads_thread->dsr_tcpconn[im_conn]->bo_sendnot?"TRUE":"FALSE") );
#endif
                        ads_thread->dsr_tcpconn[im_conn]->bo_sendok = TRUE;
                        if ( ads_thread->dsr_tcpconn[im_conn]->bo_sendnot ) {
                            ads_thread->dsr_tcpconn[im_conn]->bo_sendnot = FALSE;
                            ads_thread->dsr_tcpconn[im_conn]->ads_callback->am_sendcallback(
                                    ads_thread->dsr_tcpconn[im_conn],
                                    ads_thread->dsr_tcpconn[im_conn]->ads_usrfld );
#ifdef TRACE
                            m_hlnew_printf(123, "return from send.\n");
#endif
                        }
                    }

                    if ( ads_thread->dsr_tcpconn[im_conn]->bo_connot == FALSE ) {
                        ads_thread->dsr_waitevent[im_conn].revents = 0;
                        ads_thread->dsr_waitevent[im_conn].events = 0;
			if ( ads_thread->dsr_tcpconn[im_conn]->bo_data == FALSE ) {
                            ads_thread->dsr_waitevent[im_conn].events |= POLLIN;
                        }
                        if ( ads_thread->dsr_tcpconn[im_conn]->bo_sendok
                                == FALSE
#ifdef HL_SOLARIS
                        && im_conn && ads_thread->dsr_tcpconn[im_conn]->bo_connot == FALSE
#endif
                        )
                            ads_thread->dsr_waitevent[im_conn].events |=
                                    POLLOUT;
#ifdef B150817
                    } else {
                        ads_thread->dsr_waitevent[im_conn].revents = 0;
                        ads_thread->dsr_waitevent[im_conn].events = 0;
                        ads_thread->dsr_waitevent[im_conn].events |= POLLOUT;
#endif
                    }
                }
            } // end of if(ads_thread->dsr_waitevent[im_conn].revents != 0)
            im_conn++;
        } while ( im_waitret > 0 && im_conn <= iml_concount/*ads_thread->im_concount*/);
    } while ( TRUE );
#ifdef TRACE
    m_hlnew_printf(123, "TCPthread ended. clean up.\n");
#endif
// clean up
    for ( im_index = 1; im_index <= ads_thread->im_concount; im_index++ ) {
        if ( ads_thread->dsr_tcpconn[im_index] != NULL ) {
            ads_thread->dsr_tcpconn[im_index]->m_stopconn( FALSE, FALSE );
            if ( ads_thread->dsr_tcpconn[im_index]->boc_storage )
                delete ads_thread->dsr_tcpconn[im_index];
        }
    }
    close( ads_thread->imr_pipefd[0] );
    close( ads_thread->imr_pipefd[1] );
    delete ads_thread;
    return;
} // void m_tcpthread(void*)

static void* m_starttcpthread(void* adsp_param) {
    dsd_tcpcomp::m_tcpthread( adsp_param );
    return NULL;
}

SOCKET dsd_tcpcomp::ms_socket(unsigned short usp_family,
        const dsd_bind_ineta_1* adsp_bind_ineta) {
    SOCKET dsl_sock;
    int iml_ret;
    dsl_sock = socket( usp_family, SOCK_STREAM, IPPROTO_TCP );

    if ( dsl_sock == -1 ) {
        im_error = errno;
        if ( ads_callback->am_errorcallback )
            ads_callback->am_errorcallback( this, ads_usrfld,
                    (char*)"Unable to create socket for new connection", im_error,
                    ERRORAT_STARTCONN );
#ifdef TRACE
        m_hlnew_printf(123, "%s:%d %s Error socket(): %d.\n\n", __FILE__, __LINE__, __FUNCTION__, errno);
#endif
        return dsl_sock;
    }
    if ( adsp_bind_ineta ) {
        if ( usp_family == AF_INET )
            iml_ret = bind( dsl_sock,
                    (const sockaddr*) &adsp_bind_ineta->dsc_soai4,
                    sizeof(adsp_bind_ineta->dsc_soai4) );
        else if ( usp_family == AF_INET6 )
            iml_ret = bind( dsl_sock,
                    (const sockaddr*) &adsp_bind_ineta->dsc_soai6,
                    sizeof(adsp_bind_ineta->dsc_soai6) );
        if ( iml_ret != 0 ) {
            im_error = errno;
            if ( ads_callback->am_errorcallback )
                ads_callback->am_errorcallback( this, ads_usrfld,
                        (char*)"Unable to bind socket", im_error, ERRORAT_STARTCONN );
#ifdef TRACE
            m_hlnew_printf(123, "%s:%d %s Error bind(): %d.\n\n", __FILE__, __LINE__, __FUNCTION__, errno);
            m_hlnew_printf(123, "%s\n", strerror(errno));
#endif
            close( dsl_sock );
            return -1;
        }
    }
    return dsl_sock;

}

int dsd_tcpcomp::m_startco_mh(dsd_tcpcallback_p adsp_callback,
        void * vpp_userfld, const dsd_bind_ineta_1* adsp_bind_ineta,
#ifdef B121121
        const dsd_target_ineta_1* adsp_target_ineta, unsigned short usp_port,
#else
        const dsd_target_ineta_1* adsp_target_ineta,
        const void * ap_free_ti1,
        unsigned short usp_port,
#endif
        BOOL bop_round_robin) {
#ifdef DEF_EPOLL
    if (dsd_tcpcomp::boc_epoll)
    return mc_estartco_mh(adsp_callback, vpp_userfld, adsp_target_ineta, adsp_bind_ineta, usp_port);
#endif
    dsd_tcpthread_p ads_thrcur; // current thread object
    dsd_tcpthread_p ads_thrlast; // last thread in chain

    int iml_ret, im_conn;
    const dsd_bind_ineta_1* adsl_bind;
#ifdef B110921
    sockaddr_storage dsl_sockaddr;
#endif
    socklen_t dsl_len;

    im_conn = 0;

#ifdef TRACE
    m_hlnew_printf(123, "hob-tcpco1.hpp l%05d m_startco_mh this=%p\n", __LINE__, this );
#endif
    if ( ads_callback == NULL ) // the tcpcomp instanse is not on tcpcomp thread
    {
        if (    !adsp_callback
             || !adsp_callback->am_conncallback
             || !adsp_callback->amc_cleanup
             || !adsp_callback->am_getrecvbuf
             || !adsp_callback->am_recvcallback
             || !adsp_target_ineta
             || adsp_target_ineta->imc_len_mem == 0 ) {
#ifdef TRACE
            m_hlnew_printf(123, "Parameter is null\n");
#endif
            return 1;
        }

        // Init connection object
        this->boc_storage = FALSE; /* storage has not been acquired */
        this->boc_end = FALSE; /* end has not been set    */
        this->bo_sendnot = FALSE;
        this->bo_data = FALSE;
        this->bo_sendok = FALSE;
        this->bo_recv = FALSE;
        //this->bo_fd_close = FALSE; // AG 14.04.2008
        if ( adsp_callback->am_conncallback != NULL )
            this->bo_connot = TRUE;
        else
            this->bo_connot = FALSE;
#ifdef NEW_KB_110811                        /* problems with bo_connot */
        this->boc_do_connect = FALSE; /* connect needs to be done */
#endif
        this->ads_callback = adsp_callback;
        this->ads_usrfld = vpp_userfld;
        this->aps_free_ti1 = ap_free_ti1;
        this->im_error = 0;
        this->ads_findsock = NULL;
        this->ads_findcur = NULL;

        imc_ineta_curno = 0;
        usc_port = usp_port;
        boc_mhconnect = TRUE;
        adsc_target_ineta = adsp_target_ineta;
#ifndef B150817
        this->adsc_bind_ineta = adsp_bind_ineta;
#endif

    }
    while ( true ) {
        while ( imc_ineta_curno < adsc_target_ineta->imc_no_ineta ) {

#ifdef B110921
            memset(&dsl_sockaddr, 0, sizeof(sockaddr_storage));
            m_set_connect_p1(&dsl_sockaddr, (socklen_t*)&dsl_len, (dsd_target_ineta_1*)adsc_target_ineta, imc_ineta_curno ++);
#else
            memset( &this->dsc_soa_connect, 0, sizeof(sockaddr_storage) );
            m_set_connect_p1( &this->dsc_soa_connect, (socklen_t*) &dsl_len,
                              (dsd_target_ineta_1*) adsc_target_ineta,
                              imc_ineta_curno++ );
#endif
#ifdef B150817
            adsl_bind = NULL;
            if ( adsp_bind_ineta && adsp_bind_ineta->boc_bind_needed ) {
#ifdef B110921
                if (dsl_sockaddr.ss_family == AF_INET && adsp_bind_ineta->boc_ipv4)
                adsl_bind = adsp_bind_ineta;
                else if (dsl_sockaddr.ss_family == AF_INET6 && adsp_bind_ineta->boc_ipv6)
                adsl_bind = adsp_bind_ineta;
#else
                if (    this->dsc_soa_connect.ss_family == AF_INET
                     && adsp_bind_ineta->boc_ipv4 ) {
                    adsl_bind = adsp_bind_ineta;
                } else if (    this->dsc_soa_connect.ss_family == AF_INET6
                            && adsp_bind_ineta->boc_ipv6 ) {
                    adsl_bind = adsp_bind_ineta;
                }
#endif
            }
#endif
#ifndef B150817
            adsl_bind = NULL;
            if ( this->adsc_bind_ineta && this->adsc_bind_ineta->boc_bind_needed ) {
                if (    this->dsc_soa_connect.ss_family == AF_INET
                     && this->adsc_bind_ineta->boc_ipv4 ) {
                    adsl_bind = this->adsc_bind_ineta;
                } else if (    this->dsc_soa_connect.ss_family == AF_INET6
                            && this->adsc_bind_ineta->boc_ipv6 ) {
                    adsl_bind = this->adsc_bind_ineta;
                }
            }
#endif

#ifdef B110921
            if ((this->ds_sock = ms_socket(dsl_sockaddr.ss_family, adsl_bind)) != INVALID_SOCKET)
            break;
#else
            if ( (this->ds_sock = ms_socket( this->dsc_soa_connect.ss_family,
                    adsl_bind )) != INVALID_SOCKET )
                break;
#endif
#ifdef TRACE
            m_hlnew_printf(123, "hob-tcpco1.hpp l%05d after ms_socket() this->ds_sock=%d.", __LINE__, this->ds_sock );
#endif

        }
        if ( this->ds_sock == INVALID_SOCKET ) {
#ifdef TRACE
            m_hlnew_printf(123, "Unable to create socket for new connection object\n");
#endif
            return 2;
        }
        if ( fcntl( ds_sock, F_SETFL, O_NONBLOCK ) != 0 ) //Set socket to non-blocking mode
                {
#ifdef TRACE
            m_hlnew_printf(123, "Unable to set socket to non-blocking operation: %d\n", errno);
#endif
            close( this->ds_sock );
            this->ds_sock = INVALID_SOCKET;
            return 3;
        }
        break;

    }

#ifdef B110921
    if ((iml_ret = m_connect_mh(&dsl_sockaddr, dsl_len)) == TRUE)
#else
    if ( (iml_ret = m_connect_mh( &this->dsc_soa_connect, dsl_len )) != FALSE )
#endif
    {
        if ( ads_thread == NULL ) // the tcpcomp instanse is not on tcpcomp thread
        {
            // now find a thread to handle this connection
            pthread_mutex_lock( &dsd_tcpcomp::ds_critsect );
            ads_thrlast = ads_thrcur = ads_thranc;
            while ( ads_thrcur ) {
                if ( ads_thrcur->im_concount < TCPCOMP_MAXCONN ) {
                    break;
                }
                ads_thrlast = ads_thrcur;
                ads_thrcur = ads_thrcur->ads_next;
            }
            if ( !ads_thrcur ) // no more space in threads, create new one
            {
                pthread_mutex_unlock( &dsd_tcpcomp::ds_critsect );
                ads_thrcur = m_createnewthread();
                if ( !ads_thrcur ) {
#ifdef TRACE
                    m_hlnew_printf(123, "Unable to start a thread for this connection\n");
#endif
                    close( this->ds_sock );
                    this->ds_sock = INVALID_SOCKET;
                    return 5;
                }
                pthread_mutex_lock( &dsd_tcpcomp::ds_critsect );
                if ( !ads_thranc ) {
                    ads_thranc = ads_thrcur;
                } else {
                    ads_thrlast = ads_thranc;
                    while ( ads_thrlast ) {
                        if ( !ads_thrlast->ads_next ) {
                            ads_thrlast->ads_next = ads_thrcur;
                            break;
                        }
                        ads_thrlast = ads_thrlast->ads_next;
                    }
                }
            }
            this->ads_thread = ads_thrcur;
            //im_conn = ads_thrcur->im_concount;
            ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].fd =
                    this->ds_sock;
#ifdef B150812
            ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].events =
                 POLLIN
#ifndef HL_SOLARIS
                 | POLLOUT
#endif
                 ;
#endif
#ifndef B150812
            ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].events = DEF_POLL_CONN;
#endif
            ads_thrcur->dsr_waitevent[ads_thrcur->im_concount + 1].revents = 0;
            ads_thrcur->dsr_tcpconn[ads_thrcur->im_concount + 1] = this;
            ads_thrcur->im_concount++;
            pthread_mutex_unlock( &dsd_tcpcomp::ds_critsect );
#ifdef TRACE
            m_hlnew_printf(123, "hob-tcpco1.hpp l%05d m_startco_mh() ads_thrcur=%p im_concount=%d\n",
                    __LINE__, ads_thrcur, ads_thrcur->im_concount );
#endif

            write( ads_thrcur->imr_pipefd[1], &ads_thrcur, sizeof(ads_thrcur) ); // Tell thread to handle this connection
        } else // must be allready on the thread
        { // processing on tcpcomp thread - send event is not needed
            ads_thrcur = this->ads_thread;
            pthread_mutex_lock( &dsd_tcpcomp::ds_critsect );
            for ( im_conn = 1; im_conn <= ads_thread->im_concount; ++im_conn ) {
                if ( ads_thread->dsr_tcpconn[im_conn] == this )
                    break;
            }
            ads_thrcur->dsr_waitevent[im_conn].fd = ds_sock;
#ifdef B150812
            ads_thrcur->dsr_waitevent[im_conn].events = POLLIN
#ifndef HL_SOLARIS
                    | POLLOUT
#endif
                    ;
#endif
#ifndef B150812
            ads_thrcur->dsr_waitevent[im_conn].events = DEF_POLL_CONN;
#endif
            ads_thrcur->dsr_waitevent[im_conn].revents = 0;
            pthread_mutex_unlock( &dsd_tcpcomp::ds_critsect );
        }
        return 0;
    }

#ifdef TRACE
    m_hlnew_printf(123, "Error connect() on the new connection object %d\n", im_error);
#endif
    if ( imc_ineta_curno < adsc_target_ineta->imc_no_ineta ) {
#ifdef TRACE
        m_hlnew_printf(123, "close sock %d\n", ds_sock);
#endif
        if ( close( ds_sock ) == -1 ) {
#ifdef TRACE
            m_hlnew_printf(123, "error close on sock %d\n", ds_sock);
#endif
        }
#ifdef B121121
        iml_ret = m_startco_mh( NULL, NULL, NULL, NULL, usc_port, FALSE );
#else
        iml_ret = m_startco_mh( NULL, NULL, NULL, NULL, NULL, usc_port, FALSE );
#endif
    } else
        iml_ret = -1;

    if ( iml_ret != 0 && adsp_callback != NULL ) {
        BOOL bol_save_1;
        dsd_tcpcallback_t* adsl_callback;
        pthread_mutex_lock( &dsd_tcpcomp::ds_critsect );
#ifndef V150930
        if ( ads_thread ) {
#endif
        for ( im_conn = 1; im_conn <= ads_thread->im_concount; ++im_conn ) {
            if ( ads_thread->dsr_tcpconn[im_conn] == this )
                break;
        }
#ifndef V150930
        }
#endif
        adsl_callback = ads_callback;
#ifdef TRACE
        m_hlnew_printf(123, "hob-tcpco1.hpp l%05d remove entry\n", __LINE__ );
#endif
        ads_callback = NULL;
        close( ds_sock );
        bol_save_1 = boc_storage; /* save value */
#ifdef B121120
        if ( (adsl_callback->amc_free_target_ineta) && (adsc_target_ineta) )
            adsl_callback->amc_free_target_ineta( this, ads_usrfld,
                    (struct dsd_target_ineta_1 *) adsc_target_ineta );
#endif
        if ( adsl_callback->amc_cleanup )
            adsl_callback->amc_cleanup( this, ads_usrfld );

        if ( bol_save_1 )
            delete this;
#ifndef V150930
        if ( ads_thread ) {
#endif
        if ( im_conn <= ads_thread->im_concount ) // found on thread
                {
            ads_thread->im_concount--;
#ifdef TRACE
            m_hlnew_printf(123, "hob-tcpco1.hpp l%05d dsd_tcpcomp::m_tcpthread() ads_thread=%p im_concount=%d\n",
                    __LINE__, ads_thread, ads_thread->im_concount );
#endif
            if ( im_conn < ads_thread->im_concount ) {
#ifdef TRACE
                m_hlnew_printf(123, "l%05d Remove empty event\n", __LINE__ );
#endif
                memmove(
                        &ads_thread->dsr_tcpconn[im_conn],
                        &ads_thread->dsr_tcpconn[im_conn + 1],
                        (ads_thread->im_concount - im_conn)
                                * sizeof(class dsd_tcpcomp*) );
                memmove(
                        &ads_thread->dsr_waitevent[im_conn],
                        &ads_thread->dsr_waitevent[im_conn + 1],
                        (ads_thread->im_concount - im_conn)
                                * sizeof(struct pollfd) );
            }
        }
#ifndef V150930
        }
#endif
        pthread_mutex_unlock( &dsd_tcpcomp::ds_critsect );
    }
    return iml_ret;

} /* end int dsd_tcpcomp::m_startco_mh()                                            */

int dsd_tcpcomp::m_connect_mh(sockaddr_storage* adsp_sockaddr,
        socklen_t dsp_len) {
    int iml_error;
    if ( adsp_sockaddr->ss_family == AF_INET )
        ((sockaddr_in*) adsp_sockaddr)->sin_port = htons( usc_port );
    else
        ((sockaddr_in6*) adsp_sockaddr)->sin6_port = htons( usc_port );
#ifdef TRACE
#ifdef B110813
    m_hlnew_printf(123, "try connect on %d\n", ds_sock);
#else
    m_hlnew_printf(123,  "hob-tcpco1-l%05d-T dsd_tcpcomp::m_connect_mh call connect() ds_sock=%d bo_connot=%d adsp_sockaddr=%p dsp_len=%d.\n",
            __LINE__, ds_sock, bo_connot, adsp_sockaddr, dsp_len );
#endif
#endif
#ifndef B110921
#ifdef XYZ1
    memcpy( &this->dsc_soa_connect, adsp_sockaddr, dsp_len );
#endif
#endif
    iml_error = connect( ds_sock, (const sockaddr*) adsp_sockaddr, dsp_len );
#ifdef TRACE
#ifdef B110813
    m_hlnew_printf(123, "connect on %d returns with %d errno %d\n", ds_sock, iml_error , errno);
#else
    m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::m_connect_mh() connect on %d returns with %d errno %d.\n",
            __LINE__, ds_sock, iml_error, errno );
#endif
#endif
    if ( !iml_error ) {
#ifdef TRACE
        m_hlnew_printf(123, "Connect doesn't return with WSAEWOULDBLOCK. \n");
#endif
    } else {
        iml_error = errno;
        if ( iml_error != EWOULDBLOCK && iml_error != EINPROGRESS ) {
#ifdef TRACE
#ifdef B110813
            m_hlnew_printf(123, "Connect failed: %d.\n\n", iml_error );
#else
            m_hlnew_printf(123, "hob-tcpco1-l%05d-T dsd_tcpcomp::m_connect_mh() connect failed: %d.\n",
                    __LINE__, iml_error );
#endif
#endif
            /*
             if(ads_callback->am_errorcallback != NULL)
             {
             im_error = iml_error;
             ads_callback->am_errorcallback(this, ads_usrfld,
             "Connect failed", iml_error, ERRORAT_CONNECT);
             } */
            if ( ads_callback->am_connerrcallback != NULL ) {
                sockaddr_storage dsl_sockaddr;
                socklen_t dsl_len;
                int iml_ineta_curno;
                im_error = iml_error;
                iml_ineta_curno = imc_ineta_curno - 1;
                m_set_connect_p1( &dsl_sockaddr, (socklen_t*) &dsl_len,
                        (dsd_target_ineta_1*) adsc_target_ineta,
                        iml_ineta_curno );
                ads_callback->am_connerrcallback( this, ads_usrfld,
                        (struct sockaddr *) &dsl_sockaddr, dsl_len,
                        iml_ineta_curno, adsc_target_ineta->imc_no_ineta,
                        iml_error );
            }
            return FALSE;
        }
    }
    return TRUE;
}

void dsd_tcpcomp::mc_set_nodelay(int imp_optval) {
    int iml_rc; /* return value            */
    dsd_tcpcallback_p   adsl_callback;

    adsl_callback = this->ads_callback;

    /* disable the Naegle Algorithm                 */
    iml_rc = setsockopt( ds_sock, IPPROTO_TCP, TCP_NODELAY,
            (const char *) &imp_optval, sizeof(int) );
    if ( iml_rc != 0 ) { /* error occured           */
#ifdef TRACE
        m_hlnew_printf(123, "hob-tcpco1.hpp %05d setsockopt() returned %d error %d.",
                __LINE__, iml_rc, errno);
#endif
    if (  adsl_callback != NULL &&
              adsl_callback->am_errorcallback != NULL) {
            adsl_callback->am_errorcallback( this, this->ads_usrfld,
                                             "Error setsockopt()",
                                             errno,
                                             ERRORAT_SO );
        }
    }
}

void dsd_tcpcomp::mc_set_sndbuf(int imp_sndbuf) {
    int iml_rc; /* return value            */
    dsd_tcpcallback_p   adsl_callback;

    adsl_callback = this->ads_callback;

    /* set send buffer                                                  */
    iml_rc = setsockopt( ds_sock, SOL_SOCKET, SO_SNDBUF,
            (const char *) &imp_sndbuf, sizeof(int) );
    if ( iml_rc != 0 ) { /* error occured           */
#ifdef TRACE
        m_hlnew_printf(123, "hob-tcpco1.hpp %05d setsockopt() returned %d error %d.",
                __LINE__, iml_rc, errno );
#endif
    if (  adsl_callback != NULL &&
              adsl_callback->am_errorcallback != NULL) {
            adsl_callback->am_errorcallback( this, this->ads_usrfld,
                                             "Error setsockopt()",
                                             errno,
                                             ERRORAT_SO );
        }
    }
}

void dsd_tcpcomp::mc_set_rcvbuf(int imp_rcvbuf) {
    int iml_rc; /* return value            */
    dsd_tcpcallback_p   adsl_callback;

    adsl_callback = this->ads_callback;

    /* set send buffer                                                  */
    iml_rc = setsockopt( ds_sock, SOL_SOCKET, SO_RCVBUF,
            (const char *) &imp_rcvbuf, sizeof(int) );
    if ( iml_rc != 0 ) { /* error occured           */
#ifdef TRACE
        m_hlnew_printf(123, "hob-tcpco1.hpp %05d setsockopt() returned %d error %d.",
                __LINE__, iml_rc, errno );
#endif
    if (  adsl_callback != NULL &&
              adsl_callback->am_errorcallback != NULL) {
            adsl_callback->am_errorcallback( this, this->ads_usrfld,
                                             "Error setsockopt()",
                                             errno,
                                             ERRORAT_SO );
        }
    }
}

void dsd_tcpcomp::mc_set_keepalive ( int imp_optval ) {
    int iml_rc_so;
    dsd_tcpcallback_p   adsl_callback;

    adsl_callback = this->ads_callback;
    iml_rc_so = setsockopt( ds_sock, SOL_SOCKET,
                            SO_KEEPALIVE, (const char*) &imp_optval,
                            sizeof(int) );
    if (iml_rc_so != 0) {
#ifdef TRACE
        m_hlnew_printf(123, "%05d setsockopt() returned %d error %d.",
                 __LINE__, iml_rc_so, errno );
#endif
    if (  adsl_callback != NULL &&
              adsl_callback->am_errorcallback != NULL) {
            adsl_callback->am_errorcallback( this, this->ads_usrfld,
                                             "Error setsockopt()",
                                             errno,
                                             ERRORAT_SO );
        }
    }
}

#ifdef DEF_RELEASE
/**
 * private methode dsd_tcpcomp::mc_set_ref_conn
 *  --set referred connection--
 * stores given connection in chain togehter with
 * the current timestamp in order to do a
 * deferred release.
 * NOTE: this function is called from tcpcomp-thread
 *
 * @author     Alexander Kretzschmar
 * @param[in]  int          inl_conn   current connection number
 * @param[out] nothing
 */
inline void dsd_tcpcomp::mc_set_ref_conn(int inl_conn) {

    dsd_tcpthread_p   adsl_thread;
    BOOL              bol_ret;

#ifdef TRACE
   m_hlnew_printf(123, "hob-tcpco1.hpp l%05d mc_set_ref_conn\n", __LINE__ );
#endif

   adsl_thread = this->ads_thread;
   bol_ret     = this->boc_storage;

   if (bol_ret == FALSE || bol_ret == TRUE) { /* bol_ret could not only be true or false, but also
                                               * a negative number, which means that we have an invalid
                                               * session and in that case adsl_thread->ads_def_rel is
                                               * not defined
                                               */
       pthread_mutex_lock( &dsd_tcpcomp::ds_critsect );
       dsd_def_release_p adsl_new_rel;
       dsd_def_release_p adsl_def_release;

       adsl_new_rel                = new dsd_def_release_t;
       adsl_new_rel->adsc_next     = NULL;
       adsl_new_rel->adsc_cur_ses  = adsl_thread->dsr_tcpconn[inl_conn];
       adsl_new_rel->in_timestamp  = mc_get_time();

       adsl_def_release            = ads_thread->ads_def_rel;
       if ( adsl_def_release == NULL ) {
           ads_thread->ads_def_rel = adsl_new_rel;
       } else {
           while ( adsl_def_release->adsc_next != NULL ) {
                   adsl_def_release = adsl_def_release->adsc_next;
               }
           adsl_def_release->adsc_next = adsl_new_rel;
       }
       pthread_mutex_unlock( &dsd_tcpcomp::ds_critsect );
   }
} /* end of dsd_tcpcomp::mc_set_ref_conn */
/**
 * private method dsd_tcpcomp::mc_get_time
 * returns the current time in seconds
 *
 * NOTE: Although not defined, this is almost always a integral value holding
 * the number of seconds since 00:00, Jan 1 1970 UTC, corresponding to POSIX time.
 *
 * @author     Alexander Kretzschmar
 * @param[in]  nothing
 * @param[out] time in seconds
 */
inline int dsd_tcpcomp::mc_get_time() {

    time_t inl_time;

#ifdef TRACE
    m_hlnew_printf(123, "hob-tcpco1.hpp l%05d mc_get_time\n", __LINE__ );
#endif

    inl_time = time ( NULL );

    return inl_time;
} /* end of dsd_tcpcomp::mc_get_time */
#endif //DEF_RELEASE

#ifdef XYZ1
int dsd_tcpcomp::mc_getsocket( void ) {
    return ds_sock;
} /* end dsd_tcpcomp::mc_getsocket()                                   */
#endif

#endif // TCPCOMP
#endif // end of linux/unix Implementation
