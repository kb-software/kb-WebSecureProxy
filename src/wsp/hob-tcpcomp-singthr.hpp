/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| FILE NAME: hob-tcpcomp-singthr.hpp                                |*/
/*| ----------                                                        |*/
/*|  Header-File for single-thread TCPCOMP                            |*/
/*|    for Windows and Unix and C++ programs (contains class)         |*/
/*|  11.05.10 KB                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/**
  this header file needs the following include statements
  in the calling C++ program:
    #include <poll.h>
    #include <sys/socket.h>
    #include <hob-unix01.h>
    #include <hob-netw-01.h>
  not complete 14.06.10 KB
*/

#ifdef HL_UNIX
#define D_INCL_UNIX_SOCKET

#ifndef HL_SOLARIS
#ifndef HL_HPUX
#define MSGHDR_CONTROL_AVAILABLE 1
#endif
#endif
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

/** Error location flag: stopconn. */
#define ERRORAT_STOPCONN 1
#define ERRORAT_ENDSESSION 1
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

// Error numbers:
/** Error: No error. */
#define TCPCOMP_ERROR_NONE 0

#ifndef HL_UNIX
typedef void ( * amd_tcpco_cb_posted )( WSAEVENT dsp_event_posted, void * vpp_uf_posted );
//typedef struct dsd_lib_wsm_1 * ( * amd_wsm_cb_posted )( void * );  /* when handle is posted */
//typedef void ( * amd_wsm_reg_handle )( void *vpp_userfld, WSAEVENT **aadsp_event, WSAEVENT dsp_event_passed, amd_wsm_cb_posted amp_wsm_cb_posted, void *vpp_uf_posted );
//typedef void ( * amd_wsm_unreg_handle )( void *vpp_userfld, WSAEVENT **aadsp_event );
#endif
#ifdef HL_UNIX
typedef void ( * amd_poll_compl) ( struct dsd_sithr_poll_1 * );

struct dsd_sithr_poll_1 {                   /* single thread poll structure */
   struct pollfd *adsc_pollfd;              /* address of poll structure */
   amd_poll_compl amc_p_compl_poll;         /* callback event POLL     */
};
#endif

/*+-------------------------------------------------------------------+*/
/*| non-blocking accept.                                              |*/
/*+-------------------------------------------------------------------+*/

/**
  from hob-nblock_acc.hpp
*/

class dsd_nblock_acc;     // forward declaration

#ifdef B100604
extern "C" class dsd_nblock_acc * m_nblock_acc_startlisten( int imp_socket,
                                                            struct dsd_acccallback *adsp_callback,
                                                            void * vpp_userfld );
#endif

/**
 * This structure contains the set of callback routines used to inform
 * the calling programm about network events (and errors).
 */
struct dsd_acccallback {
   void (*amc_acceptcallback)( class dsd_nblock_acc *, void *, int, struct sockaddr *, int );  // Accept callback function.
   void (*amc_errorcallback)( class dsd_nblock_acc *, void *, char *, int, int );  // Error callback function.
};

class dsd_nblock_acc {
   public:
#ifdef HL_UNIX
     struct dsd_sithr_poll_1 dsc_sithr_poll_1;  /* single thread poll structure */
#endif
#ifndef HL_UNIX
     int        imc_socket;                 /* socket used             */
     WSAEVENT   dsc_event;                  /* handle for event        */
#endif
     struct dsd_acccallback *adsc_callback;
     void *   vpc_userfld;
     static class dsd_nblock_acc * mc_startlisten( int imp_socket,
                                                   struct dsd_acccallback *adsp_callback,
                                                   void * vpp_userfld );
     int mc_startlisten_fix( int imp_socket,
                             struct dsd_acccallback *adsp_callback,
                             void * vpp_userfld );
     int mc_stoplistener_fix( void );
};

#ifdef B100604
class dsd_nblock_acc * dsd_nblock_acc::mc_startlisten( int imp_socket,
                                                       struct dsd_acccallback *adsp_callback,
                                                       void * vpp_userfld ) {
   return m_nblock_acc_startlisten( imp_socket, adsp_callback, vpp_userfld );

} /* end dsd_nblock_acc::mc_startlisten()                              */
#endif

/*+-------------------------------------------------------------------+*/
/*| TCPCOMP - non-blocking TCP connection.                            |*/
/*+-------------------------------------------------------------------+*/

class dsd_tcpcomp;     // forward declaration

/**
 * This structure contains the set of callback routines used to inform
 * the calling programm about network events (and errors).
 */
struct dsd_tcpcallback {
   void (*amc_connerrcallback)( class dsd_tcpcomp *, void *, struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_current_index, int imp_total_index, int imp_errno );  /* connect failed function */
   void (*amc_conncallback)( class dsd_tcpcomp *, void *, struct dsd_target_ineta_1 *, void *, struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_error );  /* connect callback function */
   void (*amc_sendcallback)( class dsd_tcpcomp *, void * );  /* send callback function */
   int (*amc_getrecvbuf)( class dsd_tcpcomp *, void *, void **, char **, int ** );  /* get receive buffer callback function */
   int (*amc_recvcallback)( class dsd_tcpcomp *, void *, void * );  /* receive callback function */
   void (*amc_errorcallback)( class dsd_tcpcomp *, void *, char *, int, int );  /* error callback function */
   void (*amc_cleanup)( class dsd_tcpcomp *, void * );  /* cleanup callback function */
   int (*amc_get_random_number)( int );     /* get random number       */
};

/**
 * This class implements an interface for performing nonblocking TCP/IP
 * operations on multiple connections. Each instance maps to one
 * TCP/IP connection.
 */
class dsd_tcpcomp {
   public:
#ifdef HL_UNIX
     struct dsd_sithr_poll_1 dsc_sithr_poll_1;  /* single thread poll structure */
#endif
#ifndef HL_UNIX
// to-do 14.01.13 KB - make private - but problems
     WSAEVENT dsc_event;                    /* handle for event        */
     int      imc_socket;                   /* TCP socket of connection */
#endif
     struct dsd_tcpcallback *adsc_callback;
     void *   vpc_userfld;
     /* values for connect()                                           */
     struct dsd_target_ineta_1 *adsc_target_ineta;
     const void * ac_free_ti1;
     struct dsd_bind_ineta_1 *adsc_bind_ineta;
     unsigned short usc_port;
     BOOL     boc_round_robin;
     int      imc_conn_no;                  /* number of connect       */
     BOOL     boc_cb_active;                /* callback routine is active */
     BOOL     boc_do_close;                 /* do close                */
#ifdef D_INCL_UNIX_SOCKET
     BOOL     boc_unix_socket;              /* is Unix socket          */
#endif
#ifndef HL_UNIX
     BOOL     boc_send_blocked;             /* send is blocked         */
     BOOL     boc_send_event;               /* event send not blocked has occured */
     BOOL     boc_recv_blocked;             /* receive is blocked      */
     BOOL     boc_recv_event;               /* event receive not blocked has occured */
#endif
     HL_LONGLONG ilc_used_round_robin;      /* used bits round robin   */
     socklen_t imc_len_soa_conn;
     struct sockaddr_storage dsc_soa_conn;
#ifdef D_INCL_UNIX_SOCKET
#ifndef MSGHDR_CONTROL_AVAILABLE
     int      imc_msg_fd;                   /* file-descriptor received */
#endif
     struct msghdr dsc_msghdr;              /* last received message structure */
#endif
/**
 * Initiate dsd_tcpcomp.
 * @param amp_at_thread_start optional parameter - callback address of function which is called after a new thread was created
 * @return TRUE if successful, otherwise FALSE.
 */
// static inline int m_startup(md_at_thr_start amp_at_thread_start = NULL);
/**
 * Cleanup everything.
 * @return TRUE if successful, otherwise FALSE.
 */
// static inline int m_shutdown();
/**
 * Create a new conection.
 * @param ds_sock socket used.
 * @param ads_callback structure containing the necessary callback functions.
 * @param ads_usrfld pointer to user data.
 * @return pointer to the newly created tcpcomp object, NULL if an error occurred.
 */
#ifdef XYZ1
   static inline dsd_tcpcomp* m_startconn(dsd_tcphandle ds_sock,
                                          dsd_tcpcallback_p ads_callback,
                                          void* ads_usrfld);
#endif
/**
 * Starting connection: bind if needed execute non blocking connect till any first was successfuly or all failed
 * @param adsp_callback
 * @param vpp_userfld
 * @param adsp_target_ineta
 * @param adsp_bind_ineta
 */
     int m_startco_mh( struct dsd_tcpcallback *,
                       void * vpp_userfld,
                       const struct dsd_bind_ineta_1 *adsp_bind_ineta,
                       const struct dsd_target_ineta_1 *adsp_target_ineta,
                       const void * ap_free_ti1,
                       unsigned short usp_port,
                       BOOL bop_round_robin = FALSE );
// instance members
#ifdef XYZ1
/** Last error code (OS dependent). */
   int im_error;
#endif
/**
 * Stop processing this connection.
 * @param bo_close close the underlying socket.
 * @param bo_thread delete connection from thread.
 * @return TRUE if successful, otherwise FALSE.
 */
#ifdef XYZ1
   inline void m_stopconn(BOOL bo_close,
                   BOOL bo_thread = TRUE
#ifdef DEF_M_STOPCONN_CB
                   ,
                   void (*am_closeconncallback)(void*) = NULL, // Connection close callback function
                   void* avo_usrfld = NULL                    // user field, the callback will be called with it as parameter
#endif
                       );
#endif
     int m_startco_fb( int, struct dsd_tcpcallback *, void * );
#ifdef D_INCL_UNIX_SOCKET
     int m_startco_unix_socket_fix( int, struct dsd_tcpcallback *, void * );
#endif
     void m_end_session( void );

/**
 * Non-blocking connect.
 * @param str_ip ipadress to connect.
 * @param str_port ip port to conect.
 * @return TRUE if successful, otherwise FALSE.
 */
#ifdef XYZ1
   inline int m_connect(char* str_ip = NULL,
                        char* str_port = NULL);
#endif
/**
 * Called, when TCPCOMP should start receiving again.
 * @return TRUE if successful, otherwise FALSE.
 */
     int m_recv( void );                    /* start receiving again */
/**
 * Non-blocking send.
 * @param ach_data address of data to send.
 * @param im_len length of data to send.
 * @return number of bytes send, if < im_len => blocked, -1 = error,
 */
   int m_send(char *ach_data, int im_len);


/**
 * Non-blocking WSASend
 * @param ads_gatherinp pointer to the input gather chain
 * @param aads_gatherout pointer to the pointer gather - output parameter
 * @param aimp_rc 0 ok, -1  error
 * if *aads_gatherout is equal NULL all of data was sent if not NULL
 * the first gather wich is incomplete sent
 * @return number of bytes send, if < im_len => blocked
 */
     int m_send_gather( struct dsd_gather_i_1 *adsp_gai1_inp,
                        struct dsd_gather_i_1 **aadsp_gai1_out, int *aimp_rc = NULL );
/**
 * Application wants to be notified when send is possible again.
 */
     void m_sendnotify( void );

#ifdef D_INCL_UNIX_SOCKET
/** retrieve file-descriptor passed with last message received over Unix socket connection */
     int m_get_unix_socket_fd( void );
#endif

/**
 * Starting connection: bind if needed execute non blocking connect till any first was successfuly or all failed
 * @param adsp_callback
 * @param vpp_userfld
 * @param adsp_target_ineta
 * @param adsp_bind_ineta
 */
#ifdef XYZ1
   inline int m_startco_mh( dsd_tcpcallback_p adsp_callback, void * vpp_userfld,
	   const struct dsd_target_ineta_1* adsp_target_ineta, const struct dsd_bind_ineta_1* adsp_bind_ineta,
	   unsigned short usp_port);
#endif

/**
* disable/enable the Naegle Algorithm
*/
#ifdef XYZ1
   inline void dsd_tcpcomp::mc_set_nodelay(int imp_optval);
#endif

#ifndef HL_UNIX
   inline int mc_getsocket( void ) {
     return 0;  // to-do temporary 14.01.13 KB
   } /* end dsd_tcpcomp::mc_getsocket()                                */
#endif
#ifdef HL_UNIX
   inline int mc_getsocket( void ) {
     return this->dsc_sithr_poll_1.adsc_pollfd->fd;
   } /* end dsd_tcpcomp::mc_getsocket()                                */
#endif
// private:
#ifndef HL_UNIX
     void m_event_send( void );
     void m_event_recv( void );

     /* internal process end of connection                             */
     void m_int_end( int imp_reason );
#endif
};
